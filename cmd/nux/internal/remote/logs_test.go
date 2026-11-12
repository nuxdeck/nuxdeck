// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeLogs serves /api/v1/logs/stream. Each connection pops the next script: the frames to send and
// whether the server then drops the socket without a close frame, as a lost network path does.
type script struct {
	frames []string
	drop   bool
}

// fakeLogs
type fakeLogs struct {
	mu       sync.Mutex
	scripts  []script
	requests []string // raw query strings, in order
	auth     []string
	status   int // when non-zero, refuse the upgrade with this status
}

func (f *fakeLogs) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.URL.RawQuery)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		if f.status != 0 {
			f.mu.Unlock()
			writeErr(w, f.status, "API-NF-001", "refused", "check it")
			return
		}
		var sc script
		if len(f.scripts) > 0 {
			sc = f.scripts[0]
			f.scripts = f.scripts[1:]
		}
		frames := sc.frames
		f.mu.Unlock()

		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		for _, fr := range frames {
			if err := conn.Write(ctx, websocket.MessageText, []byte(fr)); err != nil {
				return
			}
		}
		if sc.drop {
			_ = conn.CloseNow()
			return
		}
		if len(frames) > 0 && strings.Contains(frames[len(frames)-1], `"end"`) {
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return
		}
		// Hold the connection until the client goes away, as a live stream does.
		_, _, _ = conn.Read(ctx)
	}
}

// syncBuffer lets the streaming goroutine and the test read output without a data race.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func lineFrame(ts int64, text string) string {
	b, _ := json.Marshal(map[string]any{"type": "line", "ts": ts, "stream": "stdout", "text": text})
	return string(b)
}

func newLogsServer(t *testing.T, f *fakeLogs) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)
	return srv
}

func logsOpts(follow bool) logsOptions {
	return logsOptions{Follow: follow, Tail: 100, RetryBase: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond, Idle: 150 * time.Millisecond}
}

func TestCLI2_LogsNonFollowPrintsReplayThenExits(t *testing.T) {
	f := &fakeLogs{scripts: []script{{frames: []string{lineFrame(1760000000000, "first"), lineFrame(1760000001000, "second")}}}}
	srv := newLogsServer(t, f)
	c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})

	var out, errOut syncBuffer
	a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
	if err := a.streamLogs(context.Background(), c, "container:"+apiCtrID, false, logsOpts(false)); err != nil {
		t.Fatalf("streamLogs: %v", err)
	}
	if !strings.Contains(out.String(), "first") || !strings.Contains(out.String(), "second") {
		t.Errorf("replay not printed: %q", out.String())
	}
	if !strings.Contains(f.requests[0], "target=container%3A"+apiCtrID) || !strings.Contains(f.requests[0], "tail=100") {
		t.Errorf("query = %s", f.requests[0])
	}
	if f.auth[0] != "Bearer "+testToken {
		t.Errorf("Authorization header = %q", f.auth[0])
	}
}

func TestCLI2_LogsFollowReconnectsWithoutReplay(t *testing.T) {
	f := &fakeLogs{scripts: []script{
		{frames: []string{lineFrame(1760000000000, "before-drop")}, drop: true},
		{frames: []string{lineFrame(1760000005000, "after-reconnect")}},
	}}
	srv := newLogsServer(t, f)
	c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})

	var out, errOut syncBuffer
	a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.streamLogs(ctx, c, "container:"+apiCtrID, false, logsOpts(true)) }()

	waitFor(t, func() bool { return strings.Contains(out.String(), "after-reconnect") })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Ctrl-C style cancel should exit cleanly, got %v", err)
	}
	if !strings.Contains(out.String(), "before-drop") {
		t.Errorf("first session lost: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "reconnecting") {
		t.Errorf("reconnect not announced: %q", errOut.String())
	}
	if len(f.requests) < 2 {
		t.Fatalf("expected a reconnect, saw %d requests", len(f.requests))
	}
	if !strings.Contains(f.requests[1], "tail=0") {
		t.Errorf("reconnect should not replay: %s", f.requests[1])
	}
}

func TestCLI2_LogsRefusalIsFinalAndNotRetried(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantCode int
	}{
		{"forbidden is auth", http.StatusForbidden, 3},
		{"not found is final", http.StatusNotFound, 4},
		{"validation is final", http.StatusUnprocessableEntity, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeLogs{status: tt.status}
			srv := newLogsServer(t, f)
			c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})
			var out, errOut syncBuffer
			a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
			err := a.streamLogs(context.Background(), c, "container:"+apiCtrID, false, logsOpts(true))
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := exitCode(err); got != tt.wantCode {
				t.Errorf("exit = %d, want %d (%v)", got, tt.wantCode, err)
			}
			if len(f.requests) != 1 {
				t.Errorf("refused stream retried %d times", len(f.requests))
			}
		})
	}
}

func TestCLI2_LogsEndFrameReconnectsWhenFollowing(t *testing.T) {
	f := &fakeLogs{scripts: []script{
		{frames: []string{`{"type":"end","reason":"agent disconnected"}`}},
		{frames: []string{lineFrame(1760000009000, "back-again")}},
	}}
	srv := newLogsServer(t, f)
	c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})
	var out, errOut syncBuffer
	a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.streamLogs(ctx, c, "container:"+apiCtrID, false, logsOpts(true)) }()
	waitFor(t, func() bool { return strings.Contains(out.String(), "back-again") })
	cancel()
	if err := <-done; err != nil {
		t.Errorf("stream returned %v after cancel", err)
	}
	if !strings.Contains(errOut.String(), "agent disconnected") {
		t.Errorf("end reason not shown: %q", errOut.String())
	}
}

func TestCLI2_LogsGrepAndSinceAreApplied(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour).UnixMilli()
	recent := now.Add(-time.Minute).UnixMilli()
	f := &fakeLogs{scripts: []script{{frames: []string{lineFrame(old, "ancient"), lineFrame(recent, "recent line")}}}}
	srv := newLogsServer(t, f)
	c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})
	var out, errOut syncBuffer
	a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
	o := logsOpts(false)
	o.Grep = "needle"
	o.Since = time.Hour
	if err := a.streamLogs(context.Background(), c, "container:"+apiCtrID, false, o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ancient") {
		t.Errorf("--since did not drop old lines: %q", out.String())
	}
	if !strings.Contains(out.String(), "recent line") {
		t.Errorf("recent line missing: %q", out.String())
	}
	if !strings.Contains(f.requests[0], "filter=needle") {
		t.Errorf("--grep not sent as filter: %s", f.requests[0])
	}
}

func TestCLI2_LogsJSONOutputIsLineDelimited(t *testing.T) {
	f := &fakeLogs{scripts: []script{{frames: []string{lineFrame(1760000000000, "x")}}}}
	srv := newLogsServer(t, f)
	c := mustDial(t, srv.URL, testToken, trust{Pin: pinOf(srv)})
	var out, errOut syncBuffer
	a := &app{env: Env{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader("")}}
	if err := a.streamLogs(context.Background(), c, "container:"+apiCtrID, true, logsOpts(false)); err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &frame); err != nil {
		t.Fatalf("not JSON: %v %q", err, out.String())
	}
	if frame["text"] != "x" {
		t.Errorf("frame = %v", frame)
	}
}

func TestCLI2_LogsTargetResolution(t *testing.T) {
	h := newHarness(t, nil)
	h.routes = newHarnessDefaults()
	c := mustDial(t, h.srv.URL, testToken, trust{Pin: h.pin})
	tests := []struct {
		name    string
		target  string
		want    string
		wantErr string
	}{
		{"by unique name", "db", "container:" + dbCtrID, ""},
		{"by id", apiCtrID, "container:" + apiCtrID, ""},
		{"explicit prefix", "container:db", "container:" + dbCtrID, ""},
		{"ambiguous name", "api", "", "CLI-ARG-004"},
		{"missing", "ghost", "", "API-NF-001"},
		{"journal by hostname", "journal:web-1:nginx.service", "journal:" + hostID + ":nginx.service", ""},
		{"journal needs unit", "journal:web-1", "", "CLI-ARG-002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTarget(context.Background(), c, tt.target)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %s", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolve = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func newHarnessDefaults() map[string]http.HandlerFunc {
	h := &harness{}
	return h.defaultRoutes()
}

func pinOf(srv *httptest.Server) string {
	return (&harness{srv: srv}).fingerprint()
}

func (h *harness) fingerprint() string {
	return pinFromCert(h.srv.Certificate().Raw)
}

func mustDial(t *testing.T, server, token string, tr trust) *conn {
	t.Helper()
	c, err := dial(server, token, tr)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
