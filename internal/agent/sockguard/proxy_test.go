// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// runtime is a stand-in for Docker or Podman that records what reaches it.
type runtime struct {
	mu      sync.Mutex
	seen    []*http.Request
	handler http.HandlerFunc
	sock    string
}

func newRuntime(t *testing.T, h http.HandlerFunc) *runtime {
	t.Helper()
	rt := &runtime{handler: h, sock: filepath.Join(t.TempDir(), "docker.sock")}
	ln, err := net.Listen("unix", rt.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		rt.seen = append(rt.seen, r)
		rt.mu.Unlock()
		rt.handler(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rt
}

func (rt *runtime) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.seen)
}

type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type harness struct {
	t    *testing.T
	sock string
	logs *logBuf
	http *http.Client
}

func startGuard(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, logs: &logBuf{}, sock: filepath.Join(t.TempDir(), "sg", "sockguard.sock")}
	cfg.Log = slog.New(slog.NewJSONHandler(h.logs, nil))
	ln, err := Listen(h.sock, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = New(cfg).Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	h.http = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", h.sock)
	}, DisableKeepAlives: true}}
	return h
}

func (h *harness) get(path string) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.http.Get("http://guard" + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// rawStatus sends a hand-written request, bypassing the Go client's tidying of URLs.
func (h *harness) rawStatus(request string) (int, string) {
	h.t.Helper()
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte(request))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func jsonReply(v string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Api-Version", "1.43")
		_, _ = io.WriteString(w, v)
	}
}

func TestAGT6_RefusedRequestsNeverReachTheRuntime(t *testing.T) {
	rt := newRuntime(t, jsonReply(`{}`))
	h := startGuard(t, Config{Upstream: rt.sock})

	for _, tt := range refusedRequests {
		status, body := h.rawStatus(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: guard\r\nConnection: close\r\n\r\n", tt.method, tt.uri))
		if status == http.StatusOK {
			t.Errorf("%s %q was served", tt.method, tt.uri)
		}
		if status == http.StatusForbidden && tt.method != "HEAD" && !strings.Contains(body, string(errcode.SKGDeny001)) {
			t.Errorf("%s %q: refusal lacks %s: %q", tt.method, tt.uri, errcode.SKGDeny001, body)
		}
	}
	if n := rt.count(); n != 0 {
		t.Fatalf("%d refused requests reached the runtime", n)
	}
}

func TestAGT6_BodiesAndUpgradesAreRefused(t *testing.T) {
	rt := newRuntime(t, jsonReply(`{}`))
	h := startGuard(t, Config{Upstream: rt.sock})
	for name, req := range map[string]string{
		"content length": "GET /info HTTP/1.1\r\nHost: g\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
		"chunked":        "GET /info HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"upgrade":        "GET /containers/abc/logs?follow=1 HTTP/1.1\r\nHost: g\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n",
		"connection":     "GET /info HTTP/1.1\r\nHost: g\r\nConnection: upgrade\r\n\r\n",
	} {
		if status, body := h.rawStatus(req); status != http.StatusForbidden || !strings.Contains(body, string(errcode.SKGDeny001)) {
			t.Errorf("%s: %d %q", name, status, body)
		}
	}
	if rt.count() != 0 {
		t.Error("a request with a body or upgrade reached the runtime")
	}
}

func TestOnlyAValidatedGETWithNoCallerHeadersIsForwarded(t *testing.T) {
	rt := newRuntime(t, jsonReply(`[]`))
	h := startGuard(t, Config{Upstream: rt.sock})

	req, _ := http.NewRequest("GET", "http://guard/v1.43/containers/json?size=1&all=true", nil)
	req.Header.Set("Authorization", "Bearer stolen")
	req.Header.Set("X-Registry-Auth", "eyJ")
	req.Header.Set("Cookie", "a=b")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if rt.count() != 1 {
		t.Fatalf("runtime saw %d requests, want 1", rt.count())
	}
	got := rt.seen[0]
	if got.Method != "GET" || got.RequestURI != "/v1.43/containers/json?all=true&size=1" || got.Host != "docker" {
		t.Errorf("forwarded %s %s Host %s", got.Method, got.RequestURI, got.Host)
	}
	for _, name := range []string{"Authorization", "X-Registry-Auth", "Cookie", "X-Forwarded-For", "Upgrade"} {
		if got.Header.Get(name) != "" {
			t.Errorf("header %s reached the runtime", name)
		}
	}
	if got.ContentLength > 0 {
		t.Error("a body reached the runtime")
	}
}

const inspectFixture = `{
 "Id": "abc123", "Name": "/web", "State": {"Running": true},
 "Config": {
  "Env": ["DB_PASSWORD=SECRET_VALUE_1", "API_TOKEN=SECRET_VALUE_2"],
  "CreateCommand": ["podman", "run", "-e", "DB_PASSWORD=SECRET_VALUE_3", "img"],
  "Labels": {"app": "web", "com.example.db_password": "SECRET_VALUE_4", "API_KEY": "SECRET_VALUE_5", "Secret-Thing": "SECRET_VALUE_6", "credentials": "SECRET_VALUE_7"},
  "Image": "nginx:1.27"
 },
 "ContainerConfig": {"Env": ["OLD=SECRET_VALUE_8"], "Labels": null},
 "HostConfig": {
  "Binds": ["/etc/secrets:/run/secrets:ro", "dbdata:/var/lib/db", "/anonymous"],
  "Mounts": [{"Type": "bind", "Source": "/home/ada/.ssh", "Target": "/ssh"}],
  "Memory": 17179869184
 },
 "Mounts": [{"Type": "bind", "Source": "/srv/secret-stuff", "Destination": "/x", "Name": "v", "Mode": "ro"}],
 "Nested": {"deeper": [{"Env": ["SNEAKY=SECRET_VALUE_9"], "keep": 1}]}
}`

func TestAGT6_ConfigEnvNeverSurvivesFiltering(t *testing.T) {
	rt := newRuntime(t, jsonReply(inspectFixture))
	h := startGuard(t, Config{Upstream: rt.sock})

	resp, body := h.get("/containers/abc123/json")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "SECRET_VALUE") || strings.Contains(body, `"Env"`) || strings.Contains(body, "CreateCommand") {
		t.Fatalf("a secret or an Env key survived: %s", body)
	}
	if strings.Contains(body, "/etc/secrets") || strings.Contains(body, "/home/ada") || strings.Contains(body, "/srv/secret-stuff") || strings.Contains(body, `"Source"`) {
		t.Fatalf("a mount source survived: %s", body)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("filtered body is not JSON: %v", err)
	}
	binds := got["HostConfig"].(map[string]any)["Binds"].([]any)
	if fmt.Sprint(binds) != "[/run/secrets:ro /var/lib/db /anonymous]" {
		t.Errorf("Binds = %v", binds)
	}
	labels := got["Config"].(map[string]any)["Labels"].(map[string]any)
	for k, v := range labels {
		redacted := v == "[redacted]"
		if want := secretKey.MatchString(k); redacted != want {
			t.Errorf("label %q = %v (redacted %v, want %v)", k, v, redacted, want)
		}
	}
	if labels["app"] != "web" || got["Id"] != "abc123" || got["Config"].(map[string]any)["Image"] != "nginx:1.27" {
		t.Errorf("ordinary fields were damaged: %s", body)
	}
	if !strings.Contains(body, "17179869184") {
		t.Errorf("a large number lost precision: %s", body)
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Api-Version") != "1.43" {
		t.Errorf("headers = %v", resp.Header)
	}
}

func TestListAndInfoFiltering(t *testing.T) {
	list := `[{"Id":"a","Names":["/web"],"Labels":{"app":"web","registry.password":"SECRET_VALUE"},"Mounts":[{"Source":"/srv/secret","Destination":"/d"}]},{"Id":"b","Labels":null}]`
	info := `{"ID":"x","Containers":3,"RegistryConfig":{"auth":"SECRET_VALUE"},"IndexServerAddress":"https://index","Plugins":{"Volume":["local"]},"Swarm":{"NodeID":"n","RemoteManagers":[{"Addr":"10.0.0.1"}]},"HttpProxy":"http://user:SECRET_VALUE@proxy","HttpsProxy":"x","NoProxy":"y","Labels":["site=a","api_token=SECRET_VALUE"],"ServerVersion":"27.0"}` //nolint:gosec // a fake secret that the test expects to be removed
	rt := newRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/info") {
			jsonReply(info)(w, r)
			return
		}
		jsonReply(list)(w, r)
	})
	h := startGuard(t, Config{Upstream: rt.sock})

	_, body := h.get("/containers/json")
	if strings.Contains(body, "SECRET_VALUE") || strings.Contains(body, "/srv/secret") || !strings.Contains(body, `"app":"web"`) {
		t.Errorf("list: %s", body)
	}
	_, body = h.get("/info")
	if strings.Contains(body, "SECRET_VALUE") {
		t.Errorf("info leaked: %s", body)
	}
	for _, dropped := range []string{"RegistryConfig", "Plugins", "Swarm", "HttpProxy", "IndexServerAddress"} {
		if strings.Contains(body, dropped) {
			t.Errorf("info still has %s", dropped)
		}
	}
	if !strings.Contains(body, `"ServerVersion":"27.0"`) || !strings.Contains(body, "site=a") {
		t.Errorf("info lost ordinary fields: %s", body)
	}
}

func TestEventsAreFilteredAsTheyStream(t *testing.T) {
	release := make(chan struct{})
	rt := newRuntime(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Type":"container","Action":"start","Actor":{"ID":"a","Attributes":{"name":"web","image":"nginx","com.example.api_key":"SECRET_VALUE","PASSWORD":"SECRET_VALUE"}}}`+"\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, `{"Type":"container","Action":"die","Actor":{"ID":"a","Attributes":{"name":"web"}}}`+"\n")
		_, _ = io.WriteString(w, "this is not json\n")
		_, _ = io.WriteString(w, `{"Type":"container","Action":"after-garbage"}`+"\n")
	})
	h := startGuard(t, Config{Upstream: rt.sock})

	resp, err := h.http.Get("http://guard/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	r := bufio.NewReader(resp.Body)

	line, err := r.ReadString('\n') // arrives while the runtime is still holding the stream open
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "SECRET_VALUE") || !strings.Contains(line, `"name":"web"`) || !strings.Contains(line, `"image":"nginx"`) {
		t.Errorf("event 1 = %s", line)
	}
	close(release)
	line, _ = r.ReadString('\n')
	if !strings.Contains(line, `"Action":"die"`) {
		t.Errorf("event 2 = %s", line)
	}
	rest, _ := io.ReadAll(r)
	if len(rest) != 0 {
		t.Errorf("the stream continued past an unparseable line: %q", rest)
	}
}

func TestLogsStreamThroughUnchanged(t *testing.T) {
	release := make(chan struct{})
	first := []byte{1, 0, 0, 0, 0, 0, 0, 6, 'h', 'e', 'l', 'l', 'o', '\n'} // Docker's multiplexed frame, bytes untouched
	second := []byte{2, 0, 0, 0, 0, 0, 0, 5, 'o', 'o', 'p', 's', '\n'}
	rt := newRuntime(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		_, _ = w.Write(first)
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write(second)
	})
	h := startGuard(t, Config{Upstream: rt.sock, Timeout: 200 * time.Millisecond})

	resp, err := h.http.Get("http://guard/containers/abc/logs?follow=true&stdout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got := make([]byte, len(first))
	if _, err := io.ReadFull(resp.Body, got); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first chunk = %v, %v", got, err)
	}
	time.Sleep(400 * time.Millisecond) // longer than the non-streaming timeout: follow=true must not be cut off
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(rest, second) {
		t.Errorf("rest = %v, want %v", rest, second)
	}
}

func TestUpstreamErrorsPassThroughAndBadAnswersDoNot(t *testing.T) {
	rt := newRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/missing/"):
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"No such container: missing"}`)
		case strings.Contains(r.URL.Path, "/big/"):
			_, _ = io.WriteString(w, `{"Config":{"Env":["SECRET_VALUE=`+strings.Repeat("x", 2048)+`"]}}`)
		case strings.Contains(r.URL.Path, "/broken/"):
			_, _ = io.WriteString(w, `{"Config":{"Env":["SECRET_VALUE=1"]`) // truncated
		case strings.Contains(r.URL.Path, "/weird/"):
			_, _ = io.WriteString(w, `["not","an","object"]`)
		case strings.Contains(r.URL.Path, "/trailing/"):
			_, _ = io.WriteString(w, `{"Id":"a"} {"Config":{"Env":["SECRET_VALUE"]}}`)
		}
	})
	h := startGuard(t, Config{Upstream: rt.sock, MaxInspect: 1024})

	if resp, body := h.get("/containers/missing/json"); resp.StatusCode != 404 || !strings.Contains(body, "No such container") {
		t.Errorf("404 = %d %q", resp.StatusCode, body)
	}
	for _, name := range []string{"big", "broken", "weird", "trailing"} {
		resp, body := h.get("/containers/" + name + "/json")
		if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, string(errcode.SKGUps002)) || strings.Contains(body, "SECRET_VALUE") {
			t.Errorf("%s: %d %q", name, resp.StatusCode, body)
		}
	}
}

func TestRuntimeProblemsAreReportedWithoutHanging(t *testing.T) {
	rt := newRuntime(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	h := startGuard(t, Config{Upstream: rt.sock, Timeout: 150 * time.Millisecond})

	start := time.Now()
	resp, body := h.get("/info")
	if resp.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, string(errcode.SKGUps001)) || time.Since(start) > 3*time.Second {
		t.Errorf("hanging runtime: %d %q after %v", resp.StatusCode, body, time.Since(start))
	}

	down := startGuard(t, Config{Upstream: filepath.Join(t.TempDir(), "nothing.sock")})
	if resp, body := down.get("/info"); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, string(errcode.SKGUps001)) {
		t.Errorf("missing socket: %d %q", resp.StatusCode, body)
	}
}

func TestUpstreamDiscoveryFollowsTheCandidateOrder(t *testing.T) {
	podman := newRuntime(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "podman") })
	docker := newRuntime(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "docker") })
	missing := filepath.Join(t.TempDir(), "missing.sock")

	h := startGuard(t, Config{Candidates: []string{missing, podman.sock, docker.sock}})
	if _, body := h.get("/_ping"); body != "podman" {
		t.Errorf("answered by %q, want the first existing candidate", body)
	}
	h = startGuard(t, Config{Candidates: []string{missing, docker.sock}})
	if _, body := h.get("/_ping"); body != "docker" {
		t.Errorf("answered by %q", body)
	}

	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}
	want := []string{"/run/podman/podman.sock", "/var/run/docker.sock", "/run/user/1000/podman/podman.sock"}
	if got := Candidates(func(k string) string { return env[k] }); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Candidates = %v, want %v", got, want)
	}
	if got := Candidates(func(string) string { return "" }); len(got) != 2 {
		t.Errorf("without XDG_RUNTIME_DIR: %v", got)
	}
}

func TestAtMostMaxConnsConnectionsAreServedAtOnce(t *testing.T) {
	rt := newRuntime(t, jsonReply(`{}`))
	h := startGuard(t, Config{Upstream: rt.sock, MaxConns: 2})

	hold := func() net.Conn {
		c, err := net.Dial("unix", h.sock)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET /info HTTP/1.1\r\nHost: g\r\n\r\n"))
		if _, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil {
			t.Fatal(err)
		}
		return c // kept open: keep-alive holds the slot
	}
	c1, c2 := hold(), hold()
	defer func() { _ = c2.Close() }()

	third, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	_, _ = third.Write([]byte("GET /info HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n"))
	_ = third.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := http.ReadResponse(bufio.NewReader(third), nil); err == nil {
		t.Fatal("a third connection was served while two held the slots")
	}

	_ = c1.Close() // frees a slot
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(third), nil); err != nil {
		t.Errorf("the waiting connection was not served after a slot freed: %v", err)
	}
}

func TestRefusalsAreLoggedOncePerMinutePerPath(t *testing.T) {
	rt := newRuntime(t, jsonReply(`{}`))
	h := startGuard(t, Config{Upstream: rt.sock})
	for range 20 {
		h.rawStatus("POST /containers/create HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n")
	}
	h.rawStatus("POST /build HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n")
	if n := strings.Count(h.logs.String(), `"msg":"request refused"`); n != 2 {
		t.Errorf("%d refusal log lines for 21 refusals on 2 paths, want 2:\n%s", n, h.logs.String())
	}
}

func TestListenSocketModeStaleSocketsAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run", "sockguard.sock")

	cur, _ := user.Current()
	grp, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Skip("cannot resolve the current group:", err)
	}
	ln, err := Listen(path, grp.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o660 || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket mode = %v, want a socket with 0660", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("socket directory mode = %v, must not be open to others", fi.Mode().Perm())
	}
	// A crashed run leaves its socket file behind; closing a unix listener removes it, so recreate one.
	if err := ln.(*net.UnixListener).Close(); err != nil {
		t.Fatal(err)
	}
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("test setup: no stale socket left")
	}
	again, err := Listen(path, "")
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	_ = again.Close()

	file := filepath.Join(dir, "precious")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file, ""); errcode.CodeOf(err) != errcode.SKGSock001 {
		t.Errorf("Listen over a regular file = %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "data" { //nolint:gosec // test fixture
		t.Error("a regular file was deleted")
	}
	if _, err := Listen(filepath.Join(dir, "x.sock"), "no-such-group-nux"); errcode.CodeOf(err) != errcode.SKGSock001 {
		t.Errorf("unknown group = %v", err)
	}
}
