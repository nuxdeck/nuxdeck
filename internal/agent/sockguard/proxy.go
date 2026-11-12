// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Limits from docs/08-engineering-spec.md.
const (
	DefaultMaxConns    = 32
	DefaultTimeout     = 10 * time.Second
	DefaultMaxInspect  = 2 << 20
	maxListBytes       = 16 << 20 // a host with thousands of containers
	maxErrorBody       = 64 << 10
	maxEventLine       = 1 << 20
	denyLogInterval    = time.Minute
	maxTrackedDenials  = 1024
	upstreamDialTimout = 3 * time.Second
)

// Config is the guard's settings. Zero values take the spec's defaults.
type Config struct {
	// Upstream is the runtime socket; empty means the first of Candidates that exists, tried per connection.
	Upstream   string
	Candidates []string
	Timeout    time.Duration
	MaxConns   int
	MaxInspect int
	Log        *slog.Logger
}

// Candidates lists the runtime sockets to try, in the order of the spec.
func Candidates(getenv func(string) string) []string {
	c := []string{"/run/podman/podman.sock", "/var/run/docker.sock"}
	if x := getenv("XDG_RUNTIME_DIR"); x != "" {
		c = append(c, filepath.Join(x, "podman", "podman.sock"))
	}
	return c
}

// Guard is the filtering proxy.
type Guard struct {
	cfg    Config
	client *http.Client

	mu     sync.Mutex
	denied map[string]time.Time
}

// New builds a guard.
func New(cfg Config) *Guard {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxInspect <= 0 {
		cfg.MaxInspect = DefaultMaxInspect
	}
	g := &Guard{cfg: cfg, denied: map[string]time.Time{}}
	g.client = &http.Client{
		Transport: &http.Transport{
			DialContext:        g.dialUpstream,
			DisableCompression: true,
			MaxIdleConns:       4,
			IdleConnTimeout:    30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return g
}

func (g *Guard) dialUpstream(ctx context.Context, _, _ string) (net.Conn, error) {
	d := net.Dialer{Timeout: upstreamDialTimout}
	if g.cfg.Upstream != "" {
		return d.DialContext(ctx, "unix", g.cfg.Upstream)
	}
	for _, path := range g.cfg.Candidates {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			if c, err := d.DialContext(ctx, "unix", path); err == nil {
				return c, nil
			}
		}
	}
	return nil, errors.New("no container runtime socket found")
}

// ServeHTTP decides, forwards and filters one request.
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		g.deny(w, r)
		return
	}
	req, err := Decide(r.Method, r.RequestURI)
	if err != nil {
		g.deny(w, r)
		return
	}

	ctx := r.Context()
	if !req.Streaming {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.cfg.Timeout)
		defer cancel()
	}
	// Only the validated URI is sent; none of the caller's headers are.
	up, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+req.URI, nil)
	if err != nil {
		g.deny(w, r)
		return
	}
	up.Header.Set("User-Agent", "nux-sockguard")
	resp, err := g.client.Do(up)
	if err != nil {
		g.fail(w, r, http.StatusBadGateway, errcode.SKGUps001, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode != http.StatusOK:
		g.passthrough(w, resp, maxErrorBody, false)
	case req.route == rInfo || req.route == rList || req.route == rInspect:
		g.filtered(w, r, req, resp)
	case req.route == rEvents:
		g.events(w, resp)
	default:
		g.passthrough(w, resp, -1, req.Streaming)
	}
}

// filtered buffers a JSON answer up to its cap, filters it and sends it with an exact length.
func (g *Guard) filtered(w http.ResponseWriter, r *http.Request, req Request, resp *http.Response) {
	limit := int64(maxListBytes)
	if req.route == rInspect {
		limit = int64(g.cfg.MaxInspect)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		g.fail(w, r, http.StatusBadGateway, errcode.SKGUps001, err)
		return
	}
	if int64(len(body)) > limit {
		g.fail(w, r, http.StatusBadGateway, errcode.SKGUps002, fmt.Errorf("answer over %d bytes", limit))
		return
	}
	out, err := filterBody(req.route, body)
	if err != nil {
		g.fail(w, r, http.StatusBadGateway, errcode.SKGUps002, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	copySafeHeaders(w, resp, false)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// events filters the stream one JSON object per line. An unparseable line ends the stream
// rather than being forwarded unfiltered.
func (g *Guard) events(w http.ResponseWriter, resp *http.Response) {
	copySafeHeaders(w, resp, false)
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), maxEventLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		out, err := filterEvent(line)
		if err != nil {
			g.cfg.Log.Warn("event dropped and stream closed: not a JSON object", "error", err)
			return
		}
		if _, err := w.Write(append(out, '\n')); err != nil {
			return
		}
		_ = rc.Flush()
	}
}

// passthrough streams the body unchanged. limit < 0 means no cap.
func (g *Guard) passthrough(w http.ResponseWriter, resp *http.Response, limit int64, flush bool) {
	copySafeHeaders(w, resp, !flush && limit < 0)
	w.WriteHeader(resp.StatusCode)
	var src io.Reader = resp.Body
	if limit >= 0 {
		src = io.LimitReader(resp.Body, limit)
	}
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flush {
				_ = rc.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// copySafeHeaders forwards a short list of response headers and nothing else.
func copySafeHeaders(w http.ResponseWriter, resp *http.Response, length bool) {
	for _, h := range []string{"Content-Type", "Api-Version", "Ostype", "Docker-Experimental"} {
		if v := resp.Header.Get(h); v != "" && w.Header().Get(h) == "" {
			w.Header().Set(h, v)
		}
	}
	if length && resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
}

func (g *Guard) deny(w http.ResponseWriter, r *http.Request) {
	g.logDenied(r)
	writeError(w, http.StatusForbidden, errcode.SKGDeny001)
}

func (g *Guard) fail(w http.ResponseWriter, r *http.Request, status int, code errcode.Code, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}
	g.cfg.Log.Warn("upstream request failed", "code", code, "path", pathOf(r.RequestURI), "error", err)
	writeError(w, status, code)
}

func writeError(w http.ResponseWriter, status int, code errcode.Code) {
	e, _ := errcode.Lookup(code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`+"\n", code, e.Message)
}

func pathOf(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	if len(p) > 200 {
		p = p[:200]
	}
	return p
}

// logDenied logs a refusal at most once a minute per path, so a hostile client cannot flood the journal.
func (g *Guard) logDenied(r *http.Request) {
	path := pathOf(r.RequestURI)
	now := time.Now()
	g.mu.Lock()
	if len(g.denied) >= maxTrackedDenials {
		g.denied = map[string]time.Time{}
	}
	last, seen := g.denied[path]
	log := !seen || now.Sub(last) >= denyLogInterval
	if log {
		g.denied[path] = now
	}
	g.mu.Unlock()
	if log {
		g.cfg.Log.Warn("request refused", "code", errcode.SKGDeny001, "method", r.Method, "path", path)
	}
}

// Serve accepts on ln, at most MaxConns connections at a time, until ctx ends.
func (g *Guard) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(g.cfg.Log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(newLimitListener(ln, g.cfg.MaxConns)) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		_ = srv.Close() // streams that outlive the grace period are cut
	}
	return nil
}

// Listen creates the guard's socket, readable and writable by owner and group only.
// A stale socket from a crashed run is replaced; anything else at the path is left alone.
func Listen(path, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, errcode.Wrap(errcode.SKGSock001, "create directory", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errcode.New(errcode.SKGSock001, "%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, errcode.Wrap(errcode.SKGSock001, "remove stale socket", err)
		}
	}
	old := syscall.Umask(0o117) // created 0660, never wider, even for an instant
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, errcode.Wrap(errcode.SKGSock001, "listen on "+path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // 0660 is the specified mode
		_ = ln.Close()
		return nil, errcode.Wrap(errcode.SKGSock001, "set socket mode", err)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err == nil {
			var gid int
			if gid, err = strconv.Atoi(g.Gid); err == nil {
				err = os.Chown(path, -1, gid)
			}
		}
		if err != nil {
			_ = ln.Close()
			return nil, errcode.Wrap(errcode.SKGSock001, "give the socket to group "+group, err)
		}
	}
	return ln, nil
}

// limitListener holds at most n connections open; Accept waits for a free slot.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newLimitListener(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
