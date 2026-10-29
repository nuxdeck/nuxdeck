// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/client"
)

const (
	logsPath          = "/api/v1/logs/stream"
	defaultTail       = 100
	maxTail           = 10000
	defaultRetryBase  = time.Second
	defaultRetryMax   = 30 * time.Second
	defaultIdle       = time.Second
	maxRefusalBodyLen = 64 << 10
)

// logsOptions controls one logs invocation. The timing fields exist so tests can run fast.
type logsOptions struct {
	Follow    bool
	Tail      int
	Grep      string
	Since     time.Duration
	RetryBase time.Duration
	RetryMax  time.Duration
	Idle      time.Duration
}

// logFrame is one WebSocket text frame; type decides which fields are set.
type logFrame struct {
	Type    string `json:"type"`
	Ts      int64  `json:"ts"`
	Stream  string `json:"stream"`
	Text    string `json:"text"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

// errStreamIdle ends a non-follow read once the replay has gone quiet.
var errStreamIdle = errors.New("stream idle")

func (a *app) logs(ctx context.Context, args []string) error {
	var s shared
	var o logsOptions
	fs := a.newFlagSet("logs", "logs TARGET [-f] [flags]",
		"Shows the recent output of a container or a systemd journal unit, then follows it with -f.\n"+
			"TARGET is a container name or ID, container:ID, or journal:HOST:UNIT where HOST is a hostname or ID.\n"+
			"Without -f, nux prints the last --tail lines and exits when the output goes quiet.")
	s.register(fs, true)
	fs.BoolVar(&o.Follow, "f", false, "follow the log, reconnecting with backoff until interrupted")
	fs.IntVar(&o.Tail, "tail", defaultTail, "lines to replay first, 0 to 10000")
	fs.StringVar(&o.Grep, "grep", "", "only lines containing this text")
	var since string
	fs.StringVar(&since, "since", "", "only lines newer than this age, for example 10m")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	if o.Tail < 0 || o.Tail > maxTail {
		return errcode.New(errcode.CLIArg002, "--tail must be from 0 to %d", maxTail)
	}
	if since != "" {
		d, err := time.ParseDuration(since)
		if err != nil || d <= 0 {
			return errcode.New(errcode.CLIArg002, "--since must be a positive duration such as 10m, got %q", since)
		}
		o.Since = d
	}
	if len(o.Grep) > 256 {
		return errcode.New(errcode.CLIArg002, "--grep is limited to 256 characters")
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	target, err := resolveTarget(ctx, c, pos[0])
	if err != nil {
		return err
	}
	return a.streamLogs(ctx, c, target, s.Output == "json", o)
}

// resolveTarget turns a name, ID or prefixed target into the container: or journal: form the API takes.
func resolveTarget(ctx context.Context, c *conn, raw string) (string, error) {
	kind, rest, prefixed := strings.Cut(raw, ":")
	if prefixed && kind == "journal" {
		host, unit, ok := strings.Cut(rest, ":")
		if !ok || host == "" || unit == "" {
			return "", errcode.New(errcode.CLIArg002, "journal target must be journal:HOST:UNIT")
		}
		id, err := resolveHost(ctx, c, host)
		if err != nil {
			return "", err
		}
		return "journal:" + id + ":" + unit, nil
	}
	if prefixed && kind == "container" {
		raw = rest
	}
	cts, err := allContainers(ctx, c)
	if err != nil {
		return "", err
	}
	var matches []client.Container
	for _, ct := range cts {
		if ct.Id == raw || ct.Name == raw {
			matches = append(matches, ct)
		}
	}
	switch len(matches) {
	case 0:
		return "", errcode.New(errcode.APINF001, "no running container matches %q", raw)
	case 1:
		return "container:" + matches[0].Id, nil
	}
	return "", ambiguous("container", raw, containerNames(matches))
}

func resolveHost(ctx context.Context, c *conn, raw string) (string, error) {
	hosts, err := allHosts(ctx, c)
	if err != nil {
		return "", err
	}
	var matches []client.Host
	for _, h := range hosts {
		if h.Id == raw || h.Hostname == raw {
			matches = append(matches, h)
		}
	}
	switch len(matches) {
	case 0:
		return "", errcode.New(errcode.APINF001, "no host matches %q", raw)
	case 1:
		return matches[0].Id, nil
	}
	names := make([]string, 0, len(matches))
	for _, h := range matches {
		names = append(names, h.Hostname+" ("+h.Id+")")
	}
	return "", ambiguous("host", raw, names)
}

func containerNames(cts []client.Container) []string {
	out := make([]string, 0, len(cts))
	for _, ct := range cts {
		out = append(out, ct.Name+" ("+ct.Id+")")
	}
	return out
}

func ambiguous(kind, raw string, candidates []string) error {
	return errcode.New(errcode.CLIArg004, "%q matches %d %ss: %s; use the ID", raw, len(candidates), kind, strings.Join(candidates, ", "))
}

// streamLogs prints frames until interrupted (follow) or until the replay goes quiet. Transient
// failures reconnect with exponential backoff and jitter; refusals such as 403 or 404 stop at once.
// Reconnects ask for no replay, so lines already shown are not repeated.
func (a *app) streamLogs(ctx context.Context, c *conn, target string, rawJSON bool, o logsOptions) error {
	o = o.withDefaults()
	tail := o.Tail
	delay := o.RetryBase
	for {
		err := a.streamOnce(ctx, c, target, tail, rawJSON, o)
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errStreamIdle):
			return nil
		case !transient(err):
			return err
		case !o.Follow:
			return err
		}
		_, _ = fmt.Fprintf(a.env.Stderr, "nux: log stream interrupted (%v); reconnecting in about %s\n", err, delay.Round(time.Millisecond))
		if !sleepJittered(ctx, delay) {
			return nil
		}
		delay = min(delay*2, o.RetryMax)
		tail = 0
	}
}

func (o logsOptions) withDefaults() logsOptions {
	if o.RetryBase <= 0 {
		o.RetryBase = defaultRetryBase
	}
	if o.RetryMax <= 0 {
		o.RetryMax = defaultRetryMax
	}
	if o.Idle <= 0 {
		o.Idle = defaultIdle
	}
	return o
}

// transient reports whether a failed attempt is worth retrying. Auth, permission, not-found
// and validation refusals are final.
func transient(err error) bool {
	var api *APIError
	if errors.As(err, &api) {
		switch api.Status {
		case http.StatusConflict, http.StatusTooManyRequests:
			return true
		}
		return api.Status >= 500
	}
	return true
}

// sleepJittered waits for a random duration in [d/2, d] and reports false if ctx ends first.
func sleepJittered(ctx context.Context, d time.Duration) bool {
	half := d / 2
	wait := half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // jitter spreads retries; it is not security-sensitive
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// streamOnce runs one WebSocket session. It returns nil when the caller stopped it, errStreamIdle
// when a non-follow replay went quiet, or an error describing why the session ended.
func (a *app) streamOnce(ctx context.Context, c *conn, target string, tail int, rawJSON bool, o logsOptions) error {
	u, err := logsURL(c.server, target, tail, o.Grep)
	if err != nil {
		return err
	}
	ws, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPClient: c.stream,
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + c.token}},
	})
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRefusalBodyLen))
			_ = resp.Body.Close()
			if refusal := responseError(resp.StatusCode, body); refusal != nil {
				return refusal
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		return transportError(err)
	}
	defer func() { _ = ws.CloseNow() }()

	var since time.Time
	if o.Since > 0 {
		since = time.Now().Add(-o.Since)
	}
	for {
		readCtx, cancel := ctx, context.CancelFunc(func() {})
		if !o.Follow {
			readCtx, cancel = context.WithTimeout(ctx, o.Idle)
		}
		_, data, err := ws.Read(readCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				_ = ws.Close(websocket.StatusNormalClosure, "")
				return nil
			}
			if !o.Follow && errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				_ = ws.Close(websocket.StatusNormalClosure, "")
				return errStreamIdle
			}
			return transportError(err)
		}
		done, err := a.handleFrame(data, rawJSON, since, o.Follow)
		if err != nil || done {
			_ = ws.Close(websocket.StatusNormalClosure, "")
			return err
		}
	}
}

// handleFrame prints one frame. It returns done when the server ended the stream and nux should not reconnect.
func (a *app) handleFrame(data []byte, rawJSON bool, since time.Time, follow bool) (bool, error) {
	var f logFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return false, errcode.Wrap(errcode.APIInt001, "nuxd sent an unreadable log frame", err)
	}
	switch f.Type {
	case "line":
		if !since.IsZero() && time.UnixMilli(f.Ts).Before(since) {
			return false, nil
		}
		if rawJSON {
			_, err := fmt.Fprintln(a.env.Stdout, string(data))
			return false, err
		}
		_, err := fmt.Fprintf(a.env.Stdout, "%s %-6s %s\n", time.UnixMilli(f.Ts).UTC().Format(time.RFC3339Nano), f.Stream, f.Text)
		return false, err
	case "notice":
		_, _ = fmt.Fprintf(a.env.Stderr, "nux: notice: %s\n", f.Message)
		return false, nil
	case "end":
		_, _ = fmt.Fprintf(a.env.Stderr, "nux: stream ended: %s\n", f.Reason)
		if !follow {
			return true, nil
		}
		return true, transportError(errors.New("stream ended by server: " + f.Reason))
	}
	return false, nil
}

// logsURL maps the server base URL to the WebSocket endpoint with the query parameters.
func logsURL(server, target string, tail int, grep string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", errcode.Wrap(errcode.CLIArg002, "server URL", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", errcode.New(errcode.CLIArg002, "server must be http or https")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + logsPath
	q := url.Values{}
	q.Set("target", target)
	q.Set("tail", strconv.Itoa(tail))
	if grep != "" {
		q.Set("filter", grep)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
