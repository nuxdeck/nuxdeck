// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	callTimeout     = 15 * time.Second
	maxAnswerBytes  = 17 << 20 // sockguard caps its largest answer at 16 MB
	maxLabels       = 64
	maxLabelValue   = 512
	maxPortBindings = 256
)

var errNotFound = errors.New("no such container")

// runtimeClient speaks the Docker-compatible API, but only to nux-sockguard's socket: the
// agent never opens the container runtime's own socket (ADR-011).
type runtimeClient struct {
	http *http.Client
}

func newRuntimeClient(socket string) *runtimeClient {
	return &runtimeClient{http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}}}
}

// get decodes a JSON answer, with a timeout for the whole call.
func (c *runtimeClient) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// open starts a GET and returns the response when it is a 200.
func (c *runtimeClient) open(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sockguard"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, errNotFound
	default:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
}

// kind reports whether the runtime behind sockguard is Docker or Podman.
func (c *runtimeClient) kind(ctx context.Context) (agentv1.Runtime, error) {
	var v struct {
		Platform   struct{ Name string }
		Components []struct{ Name string }
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		return agentv1.Runtime_RUNTIME_UNSPECIFIED, err
	}
	names := strings.ToLower(v.Platform.Name)
	for _, comp := range v.Components {
		names += " " + strings.ToLower(comp.Name)
	}
	if strings.Contains(names, "podman") {
		return agentv1.Runtime_RUNTIME_PODMAN, nil
	}
	return agentv1.Runtime_RUNTIME_DOCKER, nil
}

// list returns the IDs of every container, running or not.
func (c *runtimeClient) list(ctx context.Context) ([]string, error) {
	var items []struct {
		ID string `json:"Id"`
	}
	if err := c.get(ctx, "/containers/json?all=1", &items); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	return ids, nil
}

type inspectDoc struct {
	ID           string `json:"Id"`
	Name         string
	Created      string
	RestartCount int
	State        struct{ Status string }
	Config       struct {
		Image  string
		Labels map[string]string
	}
	NetworkSettings struct {
		Ports map[string][]struct{ HostIp, HostPort string } //nolint:revive,staticcheck // field names are the API's
	}
}

// inspect reads one container. The answer has already lost Env and mount sources in sockguard.
func (c *runtimeClient) inspect(ctx context.Context, id string, rt agentv1.Runtime) (*agentv1.Container, error) {
	var d inspectDoc
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &d); err != nil {
		return nil, err
	}
	return toContainer(&d, rt), nil
}

func toContainer(d *inspectDoc, rt agentv1.Runtime) *agentv1.Container {
	created, _ := time.Parse(time.RFC3339Nano, d.Created)
	ct := &agentv1.Container{
		Runtime:      rt,
		RuntimeId:    d.ID,
		Name:         strings.TrimPrefix(d.Name, "/"),
		Image:        d.Config.Image,
		State:        d.State.Status,
		Ports:        ports(d),
		Labels:       boundedLabels(d.Config.Labels),
		RestartCount: clampU32(d.RestartCount),
	}
	if !created.IsZero() {
		ct.CreatedAtUnixMs = created.UnixMilli()
	}
	return ct
}

func clampU32(n int) uint32 {
	if n < 0 {
		return 0
	}
	return uint32(n) //nolint:gosec // a restart counter far below 2^32
}

// ports lists published ports in a stable order, so an unchanged container compares equal.
func ports(d *inspectDoc) []*agentv1.PortMapping {
	var out []*agentv1.PortMapping
	for key, bindings := range d.NetworkSettings.Ports {
		portStr, proto, _ := strings.Cut(key, "/")
		cport, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			continue
		}
		for _, b := range bindings {
			hport, err := strconv.ParseUint(b.HostPort, 10, 16)
			if err != nil || len(out) >= maxPortBindings {
				continue
			}
			out = append(out, &agentv1.PortMapping{HostIp: b.HostIp, HostPort: uint32(hport), ContainerPort: uint32(cport), Protocol: proto})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ContainerPort != b.ContainerPort {
			return a.ContainerPort < b.ContainerPort
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.HostIp != b.HostIp {
			return a.HostIp < b.HostIp
		}
		return a.HostPort < b.HostPort
	})
	return out
}

// boundedLabels keeps a snapshot well under the 4 MB message limit however many labels a container carries.
func boundedLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxLabels {
		keys = keys[:maxLabels]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := in[k]
		if len(v) > maxLabelValue {
			v = v[:maxLabelValue]
		}
		out[k] = v
	}
	return out
}

// event is the part of a runtime event the collector uses.
type event struct {
	Type   string
	Action string
	Status string // older API versions
	ID     string `json:"id"`
	Actor  struct{ ID string }
}

func (e event) containerID() string {
	if e.Actor.ID != "" {
		return e.Actor.ID
	}
	return e.ID
}

// action returns the event's action without a suffix such as "health_status: healthy".
func (e event) action() string {
	a := e.Action
	if a == "" {
		a = e.Status
	}
	a, _, _ = strings.Cut(a, ":")
	return strings.TrimSpace(a)
}

// events opens the container event stream from a Unix time.
func (c *runtimeClient) events(ctx context.Context, since time.Time) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("filters", `{"type":["container"]}`)
	q.Set("since", strconv.FormatInt(since.Unix(), 10))
	resp, err := c.open(ctx, "/events?"+q.Encode())
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// changeKind maps an event action to the change it implies. ok is false for actions that
// change nothing the inventory reports (exec, attach, kill, resize, ...).
func changeKind(action string) (kind agentv1.ContainerChange_Kind, removed, ok bool) {
	switch action {
	case "create":
		return agentv1.ContainerChange_KIND_CREATED, false, true
	case "start":
		return agentv1.ContainerChange_KIND_STARTED, false, true
	case "die", "died", "stop":
		return agentv1.ContainerChange_KIND_STOPPED, false, true
	case "destroy", "remove", "removed":
		return agentv1.ContainerChange_KIND_REMOVED, true, true
	case "restart", "rename", "update", "pause", "unpause", "oom", "health_status":
		return agentv1.ContainerChange_KIND_UPDATED, false, true
	}
	return 0, false, false
}
