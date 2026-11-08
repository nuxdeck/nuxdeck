// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// newAgent enrols a real agent (hosts belong to agents) and returns its ID.
func (e *authEnv) newAgent(adminID string) string {
	e.t.Helper()
	tok, err := e.pki.CreateToken(context.Background(), pki.Actor{UserID: adminID}, pki.TokenRequest{ServerURL: "https://nux.example.com:8444"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	res, err := e.pki.Enroll(context.Background(), pki.EnrollRequest{Token: tok.Token, CSRDER: csr, Hostname: "h", OS: "linux", Arch: "amd64"})
	if err != nil {
		e.t.Fatal(err)
	}
	return res.AgentID
}

func adminIDOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var s sessionJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil || s.User.ID == "" {
		t.Fatalf("no user in %q", rec.Body)
	}
	return s.User.ID
}

func hostMsg(name string, containers ...string) *agentv1.AgentMessage {
	snap := &agentv1.InventorySnapshot{Host: &agentv1.HostFacts{
		Hostname: name, Os: "linux", Distro: "Ubuntu", Kernel: "7.0", Arch: "amd64", CpuCount: 4, MemoryBytes: 1 << 30,
		Facts: map[string]string{"ips": "10.0.0.5"},
	}}
	for _, c := range containers {
		snap.Containers = append(snap.Containers, &agentv1.Container{Runtime: agentv1.Runtime_RUNTIME_DOCKER, RuntimeId: "rid-" + c, Name: c, Image: "nginx", State: "running"})
	}
	return &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Snapshot{Snapshot: snap}}
}

type listBody struct {
	Items      []map[string]any `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listBody {
	t.Helper()
	var l listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("not a list: %q", rec.Body)
	}
	return l
}

func TestInventoryEndpointsAuthoriseFirst(t *testing.T) {
	e := newAuthEnv(t)
	for _, path := range []string{"/api/v1/hosts", "/api/v1/hosts/01HZ0000000000000000000001", "/api/v1/containers", "/api/v1/containers/01HZ0000000000000000000001", "/api/v1/events"} {
		rec := e.do(req{method: "GET", path: path})
		if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "AUTH-DENY-003" {
			t.Errorf("anonymous %s: %d %q", path, rec.Code, rec.Body)
		}
	}
	if e.inv.Index() == nil {
		t.Fatal("no index")
	}
}

func TestINV1_HostsAndContainersAreListedAndFiltered(t *testing.T) {
	e := newAuthEnv(t)
	signedIn := e.setup()
	cookie := sessionCookieOf(t, signedIn)
	admin := adminIDOf(t, signedIn)

	a, b := e.newAgent(admin), e.newAgent(admin)
	e.inv.SetPresence(a, true)
	e.inv.HandleMessage(a, hostMsg("web-1", "web", "db"))
	e.inv.HandleMessage(b, hostMsg("web-2", "cache"))

	rec := e.do(req{method: "GET", path: "/api/v1/hosts", cookie: cookie})
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("hosts = %d %v", rec.Code, rec.Header())
	}
	hosts := decodeList(t, rec)
	if len(hosts.Items) != 2 || hosts.NextCursor != nil {
		t.Fatalf("hosts = %+v", hosts)
	}
	h0 := hosts.Items[0]
	if h0["hostname"] != "web-1" || h0["status"] != "online" || h0["distro"] != "Ubuntu" || h0["cpu_count"] != float64(4) || h0["gone_at"] != nil {
		t.Errorf("host = %v", h0)
	}
	if h0["facts"].(map[string]any)["ips"] != "10.0.0.5" {
		t.Errorf("facts = %v", h0["facts"])
	}

	if got := decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts?status=offline", cookie: cookie})); len(got.Items) != 1 || got.Items[0]["hostname"] != "web-2" {
		t.Errorf("offline hosts = %+v", got)
	}

	hostID := h0["id"].(string)
	all := decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers", cookie: cookie}))
	onHost := decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + hostID, cookie: cookie}))
	if len(all.Items) != 3 || len(onHost.Items) != 2 {
		t.Errorf("containers: %d total, %d on %s", len(all.Items), len(onHost.Items), hostID)
	}
	c0 := onHost.Items[0]
	if c0["host_id"] != hostID || c0["runtime"] != "docker" || c0["state"] != "running" || c0["ports"] == nil || c0["labels"] == nil {
		t.Errorf("container = %v", c0)
	}

	// Pagination walks every item once.
	var seen []string
	path := "/api/v1/containers?limit=2"
	for range 5 {
		l := decodeList(t, e.do(req{method: "GET", path: path, cookie: cookie}))
		for _, it := range l.Items {
			seen = append(seen, it["name"].(string))
		}
		if l.NextCursor == nil {
			break
		}
		path = "/api/v1/containers?limit=2&cursor=" + *l.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("pages gave %v", seen)
	}

	// Gone containers are hidden by default and shown on request.
	e.inv.HandleMessage(a, hostMsg("web-1", "web"))
	if got := decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + hostID, cookie: cookie})); len(got.Items) != 1 {
		t.Errorf("live containers = %d", len(got.Items))
	}
	withGone := decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + hostID + "&include_gone=true", cookie: cookie}))
	if len(withGone.Items) != 2 {
		t.Fatalf("with gone = %d", len(withGone.Items))
	}
	goneSeen := 0
	for _, it := range withGone.Items {
		if it["gone_at"] != nil {
			goneSeen++
		}
	}
	if goneSeen != 1 {
		t.Errorf("%d containers marked gone, want 1", goneSeen)
	}

	// By ID.
	cid := onHost.Items[0]["id"].(string)
	if rec := e.do(req{method: "GET", path: "/api/v1/hosts/" + hostID, cookie: cookie}); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hostname":"web-1"`) {
		t.Errorf("get host = %d %q", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/containers/" + cid, cookie: cookie}); rec.Code != 200 {
		t.Errorf("get container = %d %q", rec.Code, rec.Body)
	}
	for _, p := range []string{"/api/v1/hosts/01HZ0000000000000000000009", "/api/v1/hosts/not-an-id", "/api/v1/containers/01HZ0000000000000000000009", "/api/v1/containers/" + hostID} {
		if rec := e.do(req{method: "GET", path: p, cookie: cookie}); rec.Code != http.StatusNotFound || errCode(t, rec) != "API-NF-001" {
			t.Errorf("%s = %d %q", p, rec.Code, rec.Body)
		}
	}
}

func TestInventoryListValidation(t *testing.T) {
	e := newAuthEnv(t)
	cookie := sessionCookieOf(t, e.setup())
	for _, q := range []string{
		"/api/v1/hosts?limit=0", "/api/v1/hosts?limit=501", "/api/v1/hosts?limit=abc", "/api/v1/hosts?limit=-1",
		"/api/v1/hosts?cursor=nope", "/api/v1/hosts?cursor=" + strings.Repeat("A", 5000), "/api/v1/hosts?status=gone", "/api/v1/hosts?include_gone=maybe",
		"/api/v1/containers?host_id=x", "/api/v1/containers?state=RUN%20NING", "/api/v1/containers?state=" + strings.Repeat("a", 40),
	} {
		rec := e.do(req{method: "GET", path: q, cookie: cookie})
		if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "API-VAL-001" {
			t.Errorf("%s: %d %q", q, rec.Code, rec.Body)
		}
	}
}

// sseClient opens the event stream over a real connection.
type sseClient struct {
	resp *http.Response
	r    *bufio.Reader
	stop context.CancelFunc
}

func openStream(t *testing.T, srvURL string, cookieVal string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rq, _ := http.NewRequestWithContext(ctx, "GET", srvURL+"/api/v1/events", nil)
	rq.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookieVal}) //nolint:gosec // a request cookie in a test; Secure and HttpOnly are response attributes
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return &sseClient{resp: resp, r: bufio.NewReader(resp.Body), stop: cancel}
}

// next reads one event (skipping comments); ok is false if the stream ended or timed out.
func (c *sseClient) next(within time.Duration) (id, event string, data map[string]any, ok bool) {
	type result struct {
		id, event string
		data      map[string]any
		ok        bool
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		for {
			line, err := c.r.ReadString('\n')
			if err != nil {
				ch <- result{}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "id: "):
				r.id = line[4:]
			case strings.HasPrefix(line, "event: "):
				r.event = line[7:]
			case strings.HasPrefix(line, "data: "):
				_ = json.Unmarshal([]byte(line[6:]), &r.data)
			case line == "" && r.event != "":
				r.ok = true
				ch <- r
				return
			}
		}
	}()
	select {
	case r := <-ch:
		return r.id, r.event, r.data, r.ok
	case <-time.After(within):
		return "", "", nil, false
	}
}

func TestINV2_ChangesStreamToTheBrowser(t *testing.T) {
	e := newAuthEnv(t)
	signedIn := e.setup()
	admin := adminIDOf(t, signedIn)
	cookie := sessionCookieOf(t, signedIn)
	srv := httptest.NewServer(e.h)
	defer srv.Close()

	c := openStream(t, srv.URL, cookie.Value)
	if c.resp.StatusCode != 200 || !strings.HasPrefix(c.resp.Header.Get("Content-Type"), "text/event-stream") || c.resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stream = %d %v", c.resp.StatusCode, c.resp.Header)
	}
	first, _ := c.r.ReadString('\n')
	if first != "retry: 3000\n" {
		t.Errorf("first line = %q", first)
	}

	agent := e.newAgent(admin)
	start := time.Now()
	e.inv.HandleMessage(agent, hostMsg("web-1", "web"))

	var types []string
	var lastID string
	for range 2 {
		id, ev, data, ok := c.next(3 * time.Second)
		if !ok {
			t.Fatalf("stream gave %v and then nothing", types)
		}
		types = append(types, ev)
		if id <= lastID && lastID != "" {
			t.Errorf("event ids must increase: %s after %s", id, lastID)
		}
		lastID = id
		item, _ := data["item"].(map[string]any)
		if data["type"] != ev || item == nil || data["at"] == nil {
			t.Errorf("event %s data = %v", ev, data)
		}
		if ev == "container.created" && item["name"] != "web" {
			t.Errorf("container item = %v", item)
		}
	}
	if fmt.Sprint(types) != "[host.created container.created]" {
		t.Errorf("events = %v", types)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("events took %v to reach the browser; INV-2 allows 10 s end to end", took)
	}

	// A client that disconnects frees its slot.
	c.stop()
	waitUntil(t, "the subscription to be released", func() bool {
		subs := make([]interface{ Close() }, 0)
		for range 512 {
			s, err := e.inv.Subscribe()
			if err != nil {
				for _, x := range subs {
					x.Close()
				}
				return false
			}
			subs = append(subs, s)
		}
		for _, x := range subs {
			x.Close()
		}
		return true
	})
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEventStreamEndsWhenTheSessionDoes(t *testing.T) {
	old := sseKeepalive
	sseKeepalive = 40 * time.Millisecond
	t.Cleanup(func() { sseKeepalive = old })

	e := newAuthEnv(t)
	signedIn := e.setup()
	cookie, csrf := sessionCookieOf(t, signedIn), csrfOf(t, signedIn)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	c := openStream(t, srv.URL, cookie.Value)
	_, _ = c.r.ReadString('\n')

	if rec := e.do(req{method: "POST", path: "/api/v1/auth/logout", cookie: cookie, headers: map[string]string{csrfHeader: csrf}}); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %q", rec.Code, rec.Body)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := c.r.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream outlived the session that opened it")
	}
}

func TestEventStreamRefusesWhenFull(t *testing.T) {
	e := newAuthEnv(t)
	cookie := sessionCookieOf(t, e.setup())
	var held []interface{ Close() }
	for {
		s, err := e.inv.Subscribe()
		if err != nil {
			break
		}
		held = append(held, s)
	}
	defer func() {
		for _, s := range held {
			s.Close()
		}
	}()
	rec := e.do(req{method: "GET", path: "/api/v1/events", cookie: cookie})
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != string(errcode.APILim001) || rec.Header().Get("Retry-After") == "" {
		t.Errorf("full: %d %q", rec.Code, rec.Body)
	}
}
