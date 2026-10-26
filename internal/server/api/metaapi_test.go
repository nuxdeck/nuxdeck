// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// signInAs adds a user holding role (sharing the admin's password) and returns its cookie and CSRF token.
func (e *authEnv) signInAs(role string) (*http.Cookie, string) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	email := role + "@example.com"
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, created_at) SELECT ?, ?, ?, password_hash, created_at FROM users WHERE email = ?`,
		"01"+strings.ToUpper(role), email, role, adminEmail); err != nil {
		e.t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO role_bindings (id, subject_type, subject, role) VALUES (?, 'user', ?, ?)`, "01B"+strings.ToUpper(role), "01"+strings.ToUpper(role), role); err != nil {
		e.t.Fatal(err)
	}
	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(email, goodPassword)})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("login as %s = %d %q", role, rec.Code, rec.Body)
	}
	return sessionCookieOf(e.t, rec), csrfOf(e.t, rec)
}

type metaEnv struct {
	*authEnv
	admin, csrf string
	cookie      *http.Cookie
	hostID      string
	ctrID       string
}

func newMetaEnv(t *testing.T) *metaEnv {
	t.Helper()
	e := newAuthEnv(t)
	signedIn := e.setup()
	m := &metaEnv{authEnv: e, cookie: sessionCookieOf(t, signedIn), csrf: csrfOf(t, signedIn), admin: adminIDOf(t, signedIn)}
	a, b := e.newAgent(m.admin), e.newAgent(m.admin)
	e.inv.HandleMessage(a, hostMsg("web-1", "web", "db"))
	e.inv.HandleMessage(b, hostMsg("web-2", "cache"))
	hosts := decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: m.cookie}))
	m.hostID = hosts.Items[0]["id"].(string)
	m.ctrID = decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + m.hostID, cookie: m.cookie})).Items[0]["id"].(string)
	return m
}

func (m *metaEnv) etag(kind, id string) string {
	m.t.Helper()
	rec := m.do(req{method: "GET", path: "/api/v1/" + kind + "/" + id, cookie: m.cookie})
	et := rec.Header().Get("ETag")
	if rec.Code != 200 || et == "" {
		m.t.Fatalf("GET %s/%s = %d etag=%q", kind, id, rec.Code, et)
	}
	return et
}

func (m *metaEnv) put(path, body, etag string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	h := map[string]string{csrfHeader: csrf}
	if etag != "" {
		h["If-Match"] = etag
	}
	return m.do(req{method: "PUT", path: path, body: body, cookie: cookie, headers: h})
}

func auditActions(t *testing.T, e *authEnv, action string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestINV3_TagsAndOwnerAreSetFilteredAndAudited(t *testing.T) {
	m := newMetaEnv(t)
	base := "/api/v1/items/hosts/" + m.hostID
	rec := m.put(base+"/tags", `{"tags":{"env":"production","team":"core"}}`, m.etag("hosts", m.hostID), m.cookie, m.csrf)
	if rec.Code != 200 {
		t.Fatalf("put tags = %d %q", rec.Code, rec.Body)
	}
	var h map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	if h["tags"].(map[string]any)["env"] != "production" || h["etag"] != rec.Header().Get("ETag") {
		t.Errorf("host = %v", h)
	}
	if rec := m.put(base+"/owner", `{"owner":"platform-team"}`, rec.Header().Get("ETag"), m.cookie, m.csrf); rec.Code != 200 {
		t.Fatalf("put owner = %d %q", rec.Code, rec.Body)
	}
	if n := auditActions(t, m.authEnv, "item.tags.update"); n != 1 {
		t.Errorf("tag audit entries = %d", n)
	}
	if n := auditActions(t, m.authEnv, "item.owner.update"); n != 1 {
		t.Errorf("owner audit entries = %d", n)
	}

	// Filtering: key:value, repeatable (AND), key only.
	for q, want := range map[string]int{"tag=env:production": 1, "tag=env:staging": 0, "tag=env:production&tag=team:core": 1, "tag=env:production&tag=team:x": 0, "tag=team": 1} {
		if got := decodeList(t, m.do(req{method: "GET", path: "/api/v1/hosts?" + q, cookie: m.cookie})); len(got.Items) != want {
			t.Errorf("hosts?%s = %d items, want %d", q, len(got.Items), want)
		}
	}
	// Invalid selectors are rejected against the allowlist.
	for _, bad := range []string{"tag=a%20b:c", "tag=:x", "tag=env:%27%3B--", "tag=env:" + strings.Repeat("a", 65)} {
		if rec := m.do(req{method: "GET", path: "/api/v1/hosts?" + bad, cookie: m.cookie}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("hosts?%s = %d", bad, rec.Code)
		}
	}

	// Containers carry their own tags and keep them across snapshots from the agent.
	cb := "/api/v1/items/containers/" + m.ctrID
	if rec := m.put(cb+"/tags", `{"tags":{"env":"staging"}}`, m.etag("containers", m.ctrID), m.cookie, m.csrf); rec.Code != 200 {
		t.Fatalf("put container tags = %d %q", rec.Code, rec.Body)
	}
	m.inv.HandleMessage(m.agentOf(m.hostID), hostMsg("web-1", "web", "db"))
	if got := decodeList(t, m.do(req{method: "GET", path: "/api/v1/containers?tag=env:staging", cookie: m.cookie})); len(got.Items) != 1 || got.Items[0]["id"] != m.ctrID {
		t.Errorf("container tags lost: %+v", got)
	}
}

func (m *metaEnv) agentOf(hostID string) string {
	rec := m.do(req{method: "GET", path: "/api/v1/hosts/" + hostID, cookie: m.cookie})
	var h struct {
		AgentID string `json:"agent_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	return h.AgentID
}

func TestINV3_StaleETagGets412AndWritesNothing(t *testing.T) {
	m := newMetaEnv(t)
	path := "/api/v1/items/hosts/" + m.hostID + "/tags"
	old := m.etag("hosts", m.hostID)
	if rec := m.put(path, `{"tags":{"env":"production"}}`, old, m.cookie, m.csrf); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body)
	}
	rec := m.put(path, `{"tags":{"env":"staging"}}`, old, m.cookie, m.csrf)
	if rec.Code != http.StatusPreconditionFailed || errCode(t, rec) != "API-PRE-001" {
		t.Errorf("stale = %d %q", rec.Code, rec.Body)
	}
	if rec := m.put(path, `{"tags":{"env":"staging"}}`, "", m.cookie, m.csrf); rec.Code != http.StatusPreconditionRequired || errCode(t, rec) != "API-PRE-002" {
		t.Errorf("no If-Match = %d %q", rec.Code, rec.Body)
	}
	if n := auditActions(t, m.authEnv, "item.tags.update"); n != 1 {
		t.Errorf("audit entries = %d, a rejected write must leave none", n)
	}
	if got := decodeList(t, m.do(req{method: "GET", path: "/api/v1/hosts?tag=env:production", cookie: m.cookie})); len(got.Items) != 1 {
		t.Errorf("stale write changed tags: %+v", got)
	}
}

func TestINV3_OnlyOperatorsAndAdminsMayEdit(t *testing.T) {
	m := newMetaEnv(t)
	path := "/api/v1/items/hosts/" + m.hostID + "/tags"
	etag := m.etag("hosts", m.hostID)

	if rec := m.do(req{method: "PUT", path: path, body: `{"tags":{}}`, headers: map[string]string{"If-Match": etag}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d", rec.Code)
	}
	vc, vcsrf := m.signInAs("viewer")
	if rec := m.put(path, `{"tags":{"env":"x"}}`, etag, vc, vcsrf); rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-005" {
		t.Errorf("viewer = %d %q", rec.Code, rec.Body)
	}
	if rec := m.put("/api/v1/items/hosts/"+m.hostID+"/owner", `{"owner":"me"}`, etag, vc, vcsrf); rec.Code != http.StatusForbidden {
		t.Errorf("viewer owner = %d", rec.Code)
	}
	oc, ocsrf := m.signInAs("operator")
	if rec := m.put(path, `{"tags":{"env":"x"}}`, etag, oc, ocsrf); rec.Code != 200 {
		t.Errorf("operator = %d %q", rec.Code, rec.Body)
	}
	// CSRF is still required.
	if rec := m.put(path, `{"tags":{}}`, m.etag("hosts", m.hostID), oc, ""); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF = %d", rec.Code)
	}
}

func TestINV3_InputIsValidated(t *testing.T) {
	m := newMetaEnv(t)
	tags := "/api/v1/items/hosts/" + m.hostID + "/tags"
	for _, body := range []string{`{"tags":{"bad key":"v"}}`, `{"tags":{"k":"<script>"}}`, `{"tags":{"k":""}}`, `{"tags":{"k":"v"},"extra":1}`} {
		if rec := m.put(tags, body, m.etag("hosts", m.hostID), m.cookie, m.csrf); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("%s = %d", body, rec.Code)
		}
	}
	if rec := m.put("/api/v1/items/hosts/"+m.hostID+"/owner", `{"owner":"<b>x</b>"}`, m.etag("hosts", m.hostID), m.cookie, m.csrf); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("owner = %d", rec.Code)
	}
	for _, p := range []string{"/api/v1/items/hosts/01HZ0000000000000000000001/tags", "/api/v1/items/volumes/" + m.hostID + "/tags", "/api/v1/items/hosts/nope/tags"} {
		if rec := m.put(p, `{"tags":{}}`, `"x"`, m.cookie, m.csrf); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d", p, rec.Code)
		}
	}
}

func TestINV5_SearchAuthorisesFirstAndRanks(t *testing.T) {
	m := newMetaEnv(t)
	if rec := m.do(req{method: "GET", path: "/api/v1/search?q=web"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d", rec.Code)
	}
	if rec := m.put("/api/v1/items/hosts/"+m.hostID+"/tags", `{"tags":{"env":"production"}}`, m.etag("hosts", m.hostID), m.cookie, m.csrf); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	search := func(q string) []map[string]any {
		rec := m.do(req{method: "GET", path: "/api/v1/search?q=" + q, cookie: m.cookie})
		if rec.Code != 200 {
			t.Fatalf("search %q = %d %q", q, rec.Code, rec.Body)
		}
		return decodeList(t, rec).Items
	}
	if got := search("web-1"); len(got) != 1 || got[0]["type"] != "host" || got[0]["match"] != "name" {
		t.Errorf("web-1 = %v", got)
	}
	if got := search("PRODUCTION"); len(got) != 1 || got[0]["match"] != "tag" {
		t.Errorf("tag search = %v", got)
	}
	if got := search("10.0.0"); len(got) != 2 || got[0]["match"] != "ip" {
		t.Errorf("ip search = %v", got)
	}
	if got := search("zzz-nothing"); len(got) != 0 {
		t.Errorf("no match = %v", got)
	}
	for _, q := range []string{"", "%20", strings.Repeat("a", 65)} {
		if rec := m.do(req{method: "GET", path: "/api/v1/search?q=" + q, cookie: m.cookie}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("q=%q = %d", q, rec.Code)
		}
	}
	vc, _ := m.signInAs("viewer")
	if rec := m.do(req{method: "GET", path: "/api/v1/search?q=web", cookie: vc}); rec.Code != 200 {
		t.Errorf("viewer search = %d", rec.Code)
	}
}
