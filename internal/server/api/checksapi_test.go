// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *testClock) Sleep(ctx context.Context, d time.Duration) error {
	c.advance(d)
	return ctx.Err()
}

type checkEnv struct {
	*authEnv
	admin, operator, viewer       *http.Cookie
	adminCSRF, opCSRF, viewerCSRF string
}

func newCheckEnv(t *testing.T) *checkEnv {
	t.Helper()
	e := newAuthEnv(t)
	signedIn := e.setup()
	c := &checkEnv{authEnv: e, admin: sessionCookieOf(t, signedIn), adminCSRF: csrfOf(t, signedIn)}
	c.operator, c.opCSRF = e.signInAs("operator")
	c.viewer, c.viewerCSRF = e.signInAs("viewer")
	return c
}

func (c *checkEnv) rawDB() *sql.DB {
	c.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(c.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		c.t.Fatal(err)
	}
	return db
}

func (c *checkEnv) send(method, path, body string, cookie *http.Cookie, csrf, ifMatch string) *httptest.ResponseRecorder {
	h := map[string]string{}
	if csrf != "" {
		h[csrfHeader] = csrf
	}
	if ifMatch != "" {
		h["If-Match"] = ifMatch
	}
	return c.do(req{method: method, path: path, body: body, cookie: cookie, headers: h})
}

func (c *checkEnv) op(method, path, body, ifMatch string) *httptest.ResponseRecorder {
	return c.send(method, path, body, c.operator, c.opCSRF, ifMatch)
}

const httpCheckBody = `{"name":"API health","type":"http","runner":"server","interval_s":60,"timeout_s":10,"retries":2,"enabled":true,
 "http":{"url":"https://example.com/health","method":"GET","expected_status":[200],"keyword":"ok",
 "headers":[{"name":"X-Env","value":"prod"},{"name":"X-Api-Key","secret":true,"secret_value":"KEY-PLAINTEXT-1"}],
 "auth":{"type":"bearer","token":"TOKEN-PLAINTEXT-1"}}}`

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %q", rec.Body)
	}
	return m
}

func (c *checkEnv) createCheck() (id, etag string) {
	c.t.Helper()
	rec := c.op("POST", "/api/v1/checks", httpCheckBody, "")
	if rec.Code != http.StatusCreated {
		c.t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	return decodeMap(c.t, rec)["id"].(string), rec.Header().Get("ETag")
}

func TestUPT_RolesGateEveryChecksEndpoint(t *testing.T) {
	c := newCheckEnv(t)
	id, etag := c.createCheck()
	path := "/api/v1/checks/" + id
	for _, tc := range []struct {
		method, path, body string
		write              bool
	}{
		{"GET", "/api/v1/checks", "", false},
		{"GET", path, "", false},
		{"GET", path + "/results", "", false},
		{"GET", path + "/uptime", "", false},
		{"POST", "/api/v1/checks", httpCheckBody, true},
		{"PUT", path, httpCheckBody, true},
		{"DELETE", path, "", true},
		{"POST", path + "/run", "", true},
	} {
		name := tc.method + " " + tc.path
		anon := c.send(tc.method, tc.path, tc.body, nil, "", etag)
		if anon.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous = %d, want 401", name, anon.Code)
		}
		v := c.send(tc.method, tc.path, tc.body, c.viewer, c.viewerCSRF, etag)
		if tc.write && v.Code != http.StatusForbidden {
			t.Errorf("%s viewer = %d, want 403", name, v.Code)
		}
		if !tc.write && v.Code != http.StatusOK {
			t.Errorf("%s viewer = %d, want 200", name, v.Code)
		}
	}
	// Nothing a viewer or anonymous caller tried changed anything.
	if rec := c.op("GET", path, "", ""); rec.Code != 200 || rec.Header().Get("ETag") != etag {
		t.Fatalf("check changed: %d etag %s", rec.Code, rec.Header().Get("ETag"))
	}
	// Operators and admins may write.
	if rec := c.send("POST", "/api/v1/checks", httpCheckBody, c.admin, c.adminCSRF, ""); rec.Code != http.StatusCreated {
		t.Fatalf("admin create = %d", rec.Code)
	}
	// Writes need the CSRF token.
	if rec := c.send("POST", "/api/v1/checks", httpCheckBody, c.operator, "", ""); rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
		t.Fatalf("no CSRF = %d", rec.Code)
	}
	if rec := c.send("DELETE", path, "", c.operator, "wrong", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF = %d", rec.Code)
	}
}

func TestUPT5_SecretsAreNeverReturnedOrLogged(t *testing.T) {
	c := newCheckEnv(t)
	id, _ := c.createCheck()
	run := c.op("POST", "/api/v1/checks/"+id+"/run", "", "")
	if run.Code != 200 {
		t.Fatalf("run = %d %s", run.Code, run.Body)
	}
	responses := []string{
		c.op("GET", "/api/v1/checks/"+id, "", "").Body.String(),
		c.op("GET", "/api/v1/checks", "", "").Body.String(),
		c.op("GET", "/api/v1/checks/"+id+"/results", "", "").Body.String(),
		run.Body.String(),
	}
	for _, body := range responses {
		for _, plain := range []string{"TOKEN-PLAINTEXT-1", "KEY-PLAINTEXT-1"} {
			if strings.Contains(body, plain) {
				t.Fatalf("%q leaked in %s", plain, body)
			}
		}
	}
	got := decodeMap(t, c.op("GET", "/api/v1/checks/"+id, "", ""))
	h := got["http"].(map[string]any)
	if tok := h["auth"].(map[string]any)["token"]; tok.(map[string]any)["set"] != true {
		t.Fatalf("token = %v, want {set:true}", tok)
	}
	hdrs := h["headers"].([]any)
	if sec := hdrs[1].(map[string]any); sec["secret"] != true || sec["secret_value"].(map[string]any)["set"] != true || sec["value"] != nil {
		t.Fatalf("secret header = %v", sec)
	}
	if strings.Contains(c.logs.String(), "PLAINTEXT") {
		t.Fatal("a secret reached the logs")
	}
	// Audit rows hold no plaintext either.
	db := c.rawDB()
	defer func() { _ = db.Close() }()
	rows, _ := db.Query(`SELECT details_json FROM audit_log`)
	for rows.Next() {
		var d string
		_ = rows.Scan(&d)
		if strings.Contains(d, "PLAINTEXT") {
			t.Fatalf("audit row leaks: %s", d)
		}
	}
	_ = rows.Close()
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM checks WHERE spec_json LIKE '%PLAINTEXT%' OR secret_refs_json LIKE '%PLAINTEXT%'`).Scan(&n)
	if n != 0 {
		t.Fatal("plaintext in the checks table")
	}
}

func TestUPT_IfMatchFlow(t *testing.T) {
	c := newCheckEnv(t)
	id, etag := c.createCheck()
	path := "/api/v1/checks/" + id
	// The echoed GET document round-trips: secrets come back as {"set":true} and are kept.
	doc := c.op("GET", path, "", "").Body.String()
	rec := c.op("PUT", path, doc, "")
	if rec.Code != http.StatusPreconditionRequired || errCode(t, rec) != "API-PRE-002" {
		t.Fatalf("no If-Match = %d %s", rec.Code, rec.Body)
	}
	rec = c.op("PUT", path, doc, `"c999"`)
	if rec.Code != http.StatusPreconditionFailed || errCode(t, rec) != "API-PRE-001" {
		t.Fatalf("stale If-Match = %d %s", rec.Code, rec.Body)
	}
	rec = c.op("PUT", path, strings.Replace(doc, `"API health"`, `"Renamed"`, 1), etag)
	newTag := rec.Header().Get("ETag")
	if rec.Code != 200 || newTag == etag || decodeMap(t, rec)["name"] != "Renamed" {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if rec = c.op("PUT", path, doc, etag); rec.Code != http.StatusPreconditionFailed { // the old version is stale now
		t.Fatalf("replayed update = %d", rec.Code)
	}
	// The token survived the echo.
	if tok := decodeMap(t, c.op("GET", path, "", ""))["http"].(map[string]any)["auth"].(map[string]any)["token"]; tok.(map[string]any)["set"] != true {
		t.Fatal("token lost on echoed update")
	}
	// A body with an unknown field is rejected.
	if rec = c.op("PUT", path, `{"name":"x","bogus":1}`, newTag); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", rec.Code)
	}
}

func TestUPT_CreateReadListRunResultsDelete(t *testing.T) {
	c := newCheckEnv(t)
	id, _ := c.createCheck()
	got := decodeMap(t, c.op("GET", "/api/v1/checks/"+id, "", ""))
	if st := got["status"].(map[string]any); st["state"] != "unknown" || st["last_checked"] != nil {
		t.Fatalf("fresh status = %v", st)
	}
	run := c.op("POST", "/api/v1/checks/"+id+"/run", "", "")
	if m := decodeMap(t, run); m["status"] != "up" || m["latency_ms"].(float64) != 7 {
		t.Fatalf("run = %s", run.Body)
	}
	if rec := c.op("POST", "/api/v1/checks/"+id+"/run", "", ""); rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "CHK-RUN-004" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("immediate re-run = %d %s", rec.Code, rec.Body)
	}
	got = decodeMap(t, c.op("GET", "/api/v1/checks/"+id, "", ""))
	if st := got["status"].(map[string]any); st["state"] != "up" || st["last_latency_ms"].(float64) != 7 || st["last_checked"] == nil {
		t.Fatalf("status after run = %v", st)
	}
	for i := 0; i < 3; i++ {
		c.clock.advance(6 * time.Second)
		if rec := c.op("POST", "/api/v1/checks/"+id+"/run", "", ""); rec.Code != 200 {
			t.Fatalf("run %d = %d", i, rec.Code)
		}
	}
	page1 := decodeMap(t, c.op("GET", "/api/v1/checks/"+id+"/results?limit=3", "", ""))
	next, _ := page1["next_cursor"].(string)
	if len(page1["items"].([]any)) != 3 || next == "" {
		t.Fatalf("page 1 = %v", page1)
	}
	page2 := decodeMap(t, c.op("GET", "/api/v1/checks/"+id+"/results?limit=3&cursor="+next, "", ""))
	if len(page2["items"].([]any)) != 1 || page2["next_cursor"] != nil {
		t.Fatalf("page 2 = %v", page2)
	}
	if rec := c.op("GET", "/api/v1/checks/"+id+"/results?cursor=junk", "", ""); rec.Code != 422 {
		t.Fatalf("bad cursor = %d", rec.Code)
	}
	if rec := c.op("GET", "/api/v1/checks/"+id+"/results?limit=0", "", ""); rec.Code != 422 {
		t.Fatalf("bad limit = %d", rec.Code)
	}
	up := decodeMap(t, c.op("GET", "/api/v1/checks/"+id+"/uptime", "", ""))
	if up["24h"].(float64) != 100 || up["90d"].(float64) != 100 {
		t.Fatalf("uptime = %v", up)
	}
	list := decodeMap(t, c.op("GET", "/api/v1/checks", "", ""))
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["status"].(map[string]any)["state"] != "up" {
		t.Fatalf("list = %v", list)
	}
	if rec := c.op("DELETE", "/api/v1/checks/"+id, "", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	for _, p := range []string{"", "/results", "/uptime"} {
		if rec := c.op("GET", "/api/v1/checks/"+id+p, "", ""); rec.Code != 404 {
			t.Fatalf("GET deleted %s = %d", p, rec.Code)
		}
	}
	if rec := c.op("GET", "/api/v1/checks/not-an-id", "", ""); rec.Code != 404 {
		t.Fatalf("bad id = %d", rec.Code)
	}
	if auditActions(t, c.authEnv, "check.create") != 1 || auditActions(t, c.authEnv, "check.run") != 4 || auditActions(t, c.authEnv, "check.delete") != 1 {
		t.Fatal("create, run and delete must each be audited")
	}
}

func TestUPT5_APIValidationNegatives(t *testing.T) {
	c := newCheckEnv(t)
	base := func(httpPart string) string {
		return `{"name":"x","type":"http","interval_s":60,"http":` + httpPart + `}`
	}
	for name, tc := range map[string]struct{ body, field string }{
		"CRLF header value":  {base(`{"url":"https://example.com/","headers":[{"name":"X-A","value":"a\r\nX-B: c"}]}`), "http.headers[0].value"},
		"userinfo":           {base(`{"url":"https://u:p@example.com/"}`), "http.url"},
		"ftp":                {base(`{"url":"ftp://example.com/"}`), "http.url"},
		"huge body":          {base(`{"url":"https://example.com/","method":"POST","body":"` + strings.Repeat("a", 5000) + `"}`), "http.body"},
		"Host header":        {base(`{"url":"https://example.com/","headers":[{"name":"Host","value":"evil"}]}`), "http.headers[0].name"},
		"loopback":           {base(`{"url":"http://127.0.0.1:8080/"}`), "http.url"},
		"metadata":           {base(`{"url":"http://169.254.169.254/latest/meta-data/"}`), "http.url"},
		"private w/o flag":   {base(`{"url":"http://10.0.0.5/"}`), "http.url"},
		"interval too small": {`{"name":"x","type":"tcp","interval_s":19,"tcp":{"host":"a.example.com","port":1}}`, "interval_s"},
		"unknown agent":      {`{"name":"x","type":"tcp","interval_s":60,"runner":"01AGENTAAAAAAAAAAAAAAAAAAA","tcp":{"host":"a.example.com","port":1}}`, "runner"},
	} {
		rec := c.op("POST", "/api/v1/checks", tc.body, "")
		if rec.Code != 422 || errCode(t, rec) != "API-VAL-001" {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
			continue
		}
		var b struct{ Error struct{ Field string } }
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if b.Error.Field != tc.field {
			t.Errorf("%s: field = %q, want %q", name, b.Error.Field, tc.field)
		}
	}
	// allow_private by an operator is accepted for a private literal.
	rec := c.op("POST", "/api/v1/checks", `{"name":"x","type":"tcp","interval_s":60,"allow_private":true,"tcp":{"host":"10.0.0.5","port":22}}`, "")
	if rec.Code != 201 {
		t.Fatalf("allow_private = %d %s", rec.Code, rec.Body)
	}
	// Bad content type, oversize and malformed bodies.
	if rec := c.do(req{method: "POST", path: "/api/v1/checks", body: httpCheckBody, cookie: c.operator, noJSON: true, headers: map[string]string{csrfHeader: c.opCSRF}}); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type = %d", rec.Code)
	}
	if rec := c.op("POST", "/api/v1/checks", `{"name":"`+strings.Repeat("a", 70<<10)+`"}`, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d", rec.Code)
	}
	if rec := c.op("POST", "/api/v1/checks", `{not json`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", rec.Code)
	}
}
