// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/logs"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Handler goroutines of hijacked sockets outlive their test, so the interval is set once.
func init() { wsKeepalive = 40 * time.Millisecond }

// fakeAgentLink records what the broker tells agents.
type fakeAgentLink struct {
	mu   sync.Mutex
	sent []*agentv1.ServerMessage
}

func (f *fakeAgentLink) SendToAgent(_ string, m *agentv1.ServerMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeAgentLink) count(pick func(*agentv1.ServerMessage) bool) (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent {
		if pick(m) {
			n++
		}
	}
	return n
}

func (f *fakeAgentLink) opens() int {
	return f.count(func(m *agentv1.ServerMessage) bool { return m.GetOpenLog() != nil })
}

func (f *fakeAgentLink) closes() int {
	return f.count(func(m *agentv1.ServerMessage) bool { return m.GetCloseLog() != nil })
}

func (f *fakeAgentLink) firstOpen() *agentv1.OpenLogStream {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent {
		if o := m.GetOpenLog(); o != nil {
			return o
		}
	}
	return nil
}

// recAudit forwards to the real audit log and remembers the entries.
type recAudit struct {
	db   *store.Store
	fail bool
	mu   sync.Mutex
	got  []audit.Event
}

func (r *recAudit) RecordAudit(ctx context.Context, ev audit.Event) error {
	if r.fail {
		return errors.New("audit store down")
	}
	r.mu.Lock()
	r.got = append(r.got, ev)
	r.mu.Unlock()
	return r.db.RecordAudit(ctx, ev)
}

func (r *recAudit) events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.got...)
}

type logsEnv struct {
	*authEnv
	srv     *httptest.Server
	link    *fakeAgentLink
	broker  *logs.Broker
	aud     *recAudit
	admin   *http.Cookie
	hostID  string
	agentID string
	ctrID   string
	scope   LogScope
}

func newLogsEnv(t *testing.T, tune ...func(*logs.Options)) *logsEnv {
	t.Helper()
	e := newAuthEnv(t)
	le := &logsEnv{authEnv: e, link: &fakeAgentLink{}}
	bo := logs.Options{Sender: le.link}
	for _, f := range tune {
		f(&bo)
	}
	le.broker = logs.NewBroker(bo)
	le.aud = &recAudit{db: e.db}

	signedIn := e.setup()
	le.admin = sessionCookieOf(t, signedIn)
	le.agentID = e.newAgent(adminIDOf(t, signedIn))
	e.inv.SetPresence(le.agentID, true)
	e.inv.HandleMessage(le.agentID, hostMsg("web-1", "web"))
	hosts := decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: le.admin}))
	le.hostID = hosts.Items[0]["id"].(string)
	le.ctrID = decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + le.hostID, cookie: le.admin})).Items[0]["id"].(string)

	// Rebuild the handler with the log stream enabled, on the same services.
	log := slog.New(slog.NewJSONHandler(e.logs, nil))
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: e.db, Hasher: auth.NewHasherWithParams(8, 1, 1), Passwords: auth.NewPasswordPolicy(), SetupToken: e.token, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(Options{
		Log: log, Ready: e.db, UI: uiFS(), Auth: svc, PKI: e.pki, GatewayURL: "https://nux.example.com:8444", Revoker: e.revoker,
		Inventory: e.inv, Logs: le.broker, Audit: le.aud, LogScope: func(ctx context.Context, p auth.Principal, host, ctr string) bool {
			return le.scope == nil || le.scope(ctx, p, host, ctr)
		},
	})
	e.h = h
	le.srv = httptest.NewServer(h)
	t.Cleanup(le.srv.Close)
	return le
}

// userCookie adds a user with the given role (none when empty) and signs it in.
func (le *logsEnv) userCookie(role string) *http.Cookie {
	le.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(le.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		le.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	name := "lg" + role
	email := name + "@example.com"
	id := "01LG" + strings.ToUpper(name)
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, created_at) SELECT ?, ?, ?, password_hash, created_at FROM users WHERE email = ?`, id, email, name, adminEmail); err != nil {
		le.t.Fatal(err)
	}
	if role != "" {
		if _, err := db.Exec(`INSERT INTO role_bindings (id, subject_type, subject, role) VALUES (?, 'user', ?, ?)`, "01LGB"+strings.ToUpper(name), id, role); err != nil {
			le.t.Fatal(err)
		}
	}
	rec := le.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(email, goodPassword)})
	if rec.Code != http.StatusOK {
		le.t.Fatalf("login = %d %q", rec.Code, rec.Body)
	}
	return sessionCookieOf(le.t, rec)
}

func (le *logsEnv) target() string { return "container:" + le.ctrID }

// get issues the upgrade request without a WebSocket client, to inspect refusals.
func (le *logsEnv) get(query string, cookie *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	h := map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
	for k, v := range hdr {
		h[k] = v
	}
	return le.do(req{method: "GET", path: "/api/v1/logs/stream?" + query, cookie: cookie, headers: h})
}

func (le *logsEnv) dial(t *testing.T, query string, cookie *http.Cookie) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	u := "ws" + strings.TrimPrefix(le.srv.URL, "http") + "/api/v1/logs/stream?" + query
	hdr := http.Header{"Origin": {le.srv.URL}}
	if cookie != nil {
		hdr.Set("Cookie", cookie.Name+"="+cookie.Value)
	}
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if c != nil {
		t.Cleanup(func() { _ = c.CloseNow() })
	}
	return c, resp, err
}

func readEvent(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %q", b)
	}
	return m
}

func chunkMsg(streamID string, lines ...string) *agentv1.AgentMessage {
	var ls []*agentv1.LogLine
	for i, l := range lines {
		ls = append(ls, &agentv1.LogLine{TsUnixMs: 1761472800000 + int64(i), Source: agentv1.LogLine_SOURCE_STDOUT, Text: []byte(l)})
	}
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogChunk{LogChunk: &agentv1.LogChunk{StreamId: streamID, Lines: ls}}}
}

func TestLogsStreamAuthorisesFirst(t *testing.T) { // LOG-7
	le := newLogsEnv(t)
	q := "target=" + le.target()
	if rec := le.get(q, nil, nil); rec.Code != http.StatusUnauthorized || errCode(t, rec) != string(errcode.AuthDeny003) {
		t.Errorf("anonymous = %d %q", rec.Code, rec.Body)
	}
	// Even a malformed request from an anonymous caller learns nothing about validation.
	if rec := le.get("target=%00&tail=-9", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous malformed = %d", rec.Code)
	}
	if rec := le.get(q, le.userCookie(""), nil); rec.Code != http.StatusForbidden || errCode(t, rec) != string(errcode.AuthDeny005) {
		t.Errorf("no role = %d %q", rec.Code, rec.Body)
	}
	if le.link.opens() != 0 || len(le.aud.events()) != 0 {
		t.Error("a denied request reached the agent or the audit log")
	}
}

func TestLogsStreamRejectsForeignOrigins(t *testing.T) {
	le := newLogsEnv(t)
	q := "target=" + le.target()
	for name, hdr := range map[string]map[string]string{
		"other origin":     {"Origin": "https://evil.example"},
		"other port":       {"Origin": "http://example.com:81", "Host": "example.com"},
		"fetch metadata":   {"Sec-Fetch-Site": "cross-site"},
		"same-site origin": {"Sec-Fetch-Site": "same-site"},
	} {
		if rec := le.get(q, le.admin, hdr); rec.Code != http.StatusForbidden || errCode(t, rec) != string(errcode.AuthDeny004) {
			t.Errorf("%s = %d %q", name, rec.Code, rec.Body)
		}
	}
	if le.link.opens() != 0 || len(le.aud.events()) != 0 {
		t.Error("a cross-origin request opened a stream or wrote an audit entry")
	}
	if _, resp, err := le.dialWithOrigin(t, q, "https://evil.example"); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("real WebSocket client from another origin: err=%v resp=%v", err, resp)
	}
}

func (le *logsEnv) dialWithOrigin(t *testing.T, query, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	u := "ws" + strings.TrimPrefix(le.srv.URL, "http") + "/api/v1/logs/stream?" + query
	hdr := http.Header{"Origin": {origin}, "Cookie": {le.admin.Name + "=" + le.admin.Value}}
	return websocket.Dial(context.Background(), u, &websocket.DialOptions{HTTPHeader: hdr})
}

func TestLogsStreamValidatesInput(t *testing.T) {
	le := newLogsEnv(t)
	bad := []string{
		"", "target=", "target=nonsense", "target=container:", "target=container:../etc", "target=container:" + url.QueryEscape(le.ctrID+"/x"),
		"target=journal:" + le.hostID, "target=journal:" + le.hostID + ":", "target=journal:" + le.hostID + ":-f",
		"target=journal:" + le.hostID + ":" + url.QueryEscape("nginx;id"), "target=journal:" + le.hostID + ":" + url.QueryEscape("a b"),
		"target=journal:" + le.hostID + ":" + url.QueryEscape("$(id)"), "target=journal:" + le.hostID + ":--since%3Dx",
		"target=journal:nothost:nginx", "target=host:" + le.hostID,
		"target=" + le.target() + "&tail=-1", "target=" + le.target() + "&tail=10001", "target=" + le.target() + "&tail=abc",
		"target=" + le.target() + "&filter=" + strings.Repeat("a", 257), "target=" + le.target() + "&filter=a%00b", "target=" + le.target() + "&filter=a%0Ab",
	}
	for _, q := range bad {
		if rec := le.get(q, le.admin, nil); rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != string(errcode.APIVal001) {
			t.Errorf("%q = %d %q", q, rec.Code, rec.Body)
		}
	}
	if rec := le.do(req{method: "GET", path: "/api/v1/logs/stream?target=" + le.target(), cookie: le.admin}); rec.Code != http.StatusBadRequest {
		t.Errorf("plain GET = %d", rec.Code)
	}
	if rec := le.get("target=container:01HZ0000000000000000000001", le.admin, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown container = %d", rec.Code)
	}
	if rec := le.get("target=journal:01HZ0000000000000000000001:nginx", le.admin, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown host = %d", rec.Code)
	}
	if le.link.opens() != 0 || len(le.aud.events()) != 0 {
		t.Error("an invalid request reached the agent or the audit log")
	}
}

func TestLogsStreamEndToEnd(t *testing.T) { // LOG-1, LOG-7
	le := newLogsEnv(t)
	viewer := le.userCookie("viewer")

	start := time.Now()
	c, _, err := le.dial(t, "tail=25&target="+le.target(), viewer)
	if err != nil {
		t.Fatal(err)
	}
	open := le.link.firstOpen()
	if open == nil || open.GetContainerRuntimeId() != "rid-web" || open.GetTailLines() != 25 {
		t.Fatalf("open = %v", open)
	}
	le.broker.HandleMessage(le.agentID, chunkMsg(open.GetStreamId(), "hello <b>world</b>", ""))

	first, second := readEvent(t, c), readEvent(t, c)
	if time.Since(start) > 2*time.Second {
		t.Errorf("first line took %s", time.Since(start))
	}
	if first["type"] != "line" || first["stream"] != "stdout" || first["text"] != "hello <b>world</b>" || first["ts"] != float64(1761472800000) {
		t.Errorf("first = %v", first)
	}
	if second["text"] != "" || second["type"] != "line" {
		t.Errorf("second = %v", second)
	}

	evs := le.aud.events()
	if len(evs) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(evs))
	}
	if ev := evs[0]; ev.Action != "logs.stream" || ev.ActorID != "01LGLGVIEWER" || ev.TargetID != le.ctrID || ev.TargetType != "container" || ev.Result != audit.ResultSuccess || ev.IP == "" {
		t.Errorf("audit = %+v", ev)
	}
	if b, _ := json.Marshal(le.aud.events()); strings.Contains(string(b), "hello") {
		t.Error("log content reached the audit log")
	}

	// Leaving closes the agent stream.
	_ = c.Close(websocket.StatusNormalClosure, "")
	waitUntil(t, "close request", func() bool { return le.link.closes() == 1 })
}

func TestLogsStreamFilterAndEnd(t *testing.T) { // LOG-4 support
	le := newLogsEnv(t)
	c, _, err := le.dial(t, "filter=ERR&target="+le.target(), le.admin)
	if err != nil {
		t.Fatal(err)
	}
	id := le.link.firstOpen().GetStreamId()
	le.broker.HandleMessage(le.agentID, chunkMsg(id, "all fine", "an Error here", "ok"))
	if ev := readEvent(t, c); ev["text"] != "an Error here" {
		t.Errorf("filter let through %v", ev)
	}
	le.broker.HandleMessage(le.agentID, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_LogEnded{LogEnded: &agentv1.LogStreamEnded{StreamId: id, Code: "LOG-SRC-001"}}})
	if ev := readEvent(t, c); ev["type"] != "end" || ev["reason"] != "source_error" || ev["code"] != "LOG-SRC-001" {
		t.Errorf("end = %v", ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("after end: %v", err)
	}
}

func TestLogsStreamFanOut(t *testing.T) {
	le := newLogsEnv(t)
	c1, _, err := le.dial(t, "target="+le.target(), le.admin)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := le.dial(t, "target="+le.target(), le.admin)
	if err != nil {
		t.Fatal(err)
	}
	if le.link.opens() != 1 {
		t.Fatalf("agent got %d opens, want 1", le.link.opens())
	}
	if n := readEvent(t, c2); n["type"] != "notice" {
		t.Errorf("joiner expected a notice, got %v", n)
	}
	le.broker.HandleMessage(le.agentID, chunkMsg(le.link.firstOpen().GetStreamId(), "shared"))
	for _, c := range []*websocket.Conn{c1, c2} {
		if ev := readEvent(t, c); ev["text"] != "shared" {
			t.Errorf("event = %v", ev)
		}
	}
	_ = c1.Close(websocket.StatusNormalClosure, "")
	time.Sleep(100 * time.Millisecond)
	if le.link.closes() != 0 {
		t.Fatal("stream closed while a watcher remained")
	}
	_ = c2.Close(websocket.StatusNormalClosure, "")
	waitUntil(t, "close request", func() bool { return le.link.closes() == 1 })
}

func TestLogsStreamEndsWhenTheSessionDoes(t *testing.T) { // like the SSE handler
	le := newLogsEnv(t)
	signedIn := le.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword)})
	cookie, csrf := sessionCookieOf(t, signedIn), csrfOf(t, signedIn)
	c, _, err := le.dial(t, "target="+le.target(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if rec := le.do(req{method: "POST", path: "/api/v1/auth/logout", cookie: cookie, headers: map[string]string{csrfHeader: csrf}}); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if ev := readEvent(t, c); ev["type"] != "end" || ev["reason"] != "session_expired" {
		t.Errorf("event = %v", ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Errorf("close = %v", err)
	}
	waitUntil(t, "agent stream released", func() bool { return le.link.closes() == 1 })
}

func TestLogsStreamScopeHook(t *testing.T) { // LOG-7, NUX-37 hook
	le := newLogsEnv(t)
	var sawHost, sawCtr string
	le.scope = func(_ context.Context, _ auth.Principal, host, ctr string) bool {
		sawHost, sawCtr = host, ctr
		return false
	}
	if rec := le.get("target="+le.target(), le.admin, nil); rec.Code != http.StatusForbidden || errCode(t, rec) != string(errcode.AuthDeny005) {
		t.Errorf("out of scope = %d %q", rec.Code, rec.Body)
	}
	if sawHost != le.hostID || sawCtr != le.ctrID {
		t.Errorf("hook saw %q/%q", sawHost, sawCtr)
	}
	if le.link.opens() != 0 || len(le.aud.events()) != 0 {
		t.Error("an out-of-scope request opened a stream")
	}
}

func TestLogsStreamOfflineHost(t *testing.T) {
	le := newLogsEnv(t)
	le.inv.SetPresence(le.agentID, false)
	if rec := le.get("target="+le.target(), le.admin, nil); rec.Code != http.StatusConflict || errCode(t, rec) != string(errcode.LOGSrc003) {
		t.Errorf("offline = %d %q", rec.Code, rec.Body)
	}
	if le.link.opens() != 0 {
		t.Error("an offline host was asked to stream")
	}
}

func TestLogsStreamFailsClosedWithoutAnAuditEntry(t *testing.T) {
	le := newLogsEnv(t)
	le.aud.fail = true
	if rec := le.get("target="+le.target(), le.admin, nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("audit failure = %d %q", rec.Code, rec.Body)
	}
	waitUntil(t, "the reserved stream to be released", func() bool { return le.link.closes() == 1 })
	if le.broker.Streams() != 0 {
		t.Error("a stream stayed open without an audit entry")
	}
}

func TestLogsStreamLimit(t *testing.T) {
	le := newLogsEnv(t, func(o *logs.Options) { o.MaxPerUser = 1 })
	c, _, err := le.dial(t, "target="+le.target(), le.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	rec := le.get("target="+le.target(), le.admin, nil)
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != string(errcode.LOGStr001) || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second stream for the same user = %d %q, want 429 LOG-STR-001", rec.Code, rec.Body)
	}
	if n := len(le.aud.events()); n != 1 {
		t.Errorf("audit entries = %d; a refused stream must not be audited as opened", n)
	}
}

// The log endpoint is not registered at all without an audit sink.
func TestLogsStreamNeedsAnAuditSink(t *testing.T) {
	e := newAuthEnv(t)
	cookie := sessionCookieOf(t, e.setup())
	log := slog.New(slog.NewJSONHandler(e.logs, nil))
	svc, _ := auth.NewService(context.Background(), auth.Config{
		Repo: e.db, Hasher: auth.NewHasherWithParams(8, 1, 1), Passwords: auth.NewPasswordPolicy(), SetupToken: e.token, Log: log,
	})
	h := Handler(Options{Log: log, Ready: e.db, Auth: svc, Inventory: e.inv, Logs: logs.NewBroker(logs.Options{Sender: &fakeAgentLink{}})})
	rq := httptest.NewRequest("GET", "/api/v1/logs/stream?target=container:01HZ0000000000000000000001", nil)
	rq.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rq)
	if rec.Code != http.StatusNotFound {
		t.Errorf("without audit = %d", rec.Code)
	}
}
