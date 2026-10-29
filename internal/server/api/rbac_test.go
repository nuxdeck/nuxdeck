// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// rbacEnv has a staging host and a production host, each with one container, and the admin's cookie.
type rbacEnv struct {
	*logsEnv
	stgHost, prodHost, stgCtr, prodCtr string
	adminID                            string
}

func (e *rbacEnv) tag(host string, tags map[string]string) {
	e.t.Helper()
	h, _ := e.inv.Index().Host(host)
	if _, err := e.inv.UpdateMeta("host", host, h.ETag, inventory.MetaChange{Tags: tags}, audit.Event{ActorType: "user", Action: "item.tags.update", Result: audit.ResultSuccess}); err != nil {
		e.t.Fatal(err)
	}
}

func newRBACEnv(t *testing.T) *rbacEnv {
	t.Helper()
	le := newLogsEnv(t)
	e := &rbacEnv{logsEnv: le, stgHost: le.hostID, stgCtr: le.ctrID}
	e.adminID = adminIDOf(t, e.do(req{method: "GET", path: "/api/v1/me", cookie: le.admin}))
	prodAgent := e.newAgent(e.adminID)
	e.inv.SetPresence(prodAgent, true)
	e.inv.HandleMessage(prodAgent, hostMsg("prod-1", "db"))
	for _, h := range decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: le.admin})).Items {
		if h["hostname"] == "prod-1" {
			e.prodHost = h["id"].(string)
		}
	}
	for _, c := range decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers?host_id=" + e.prodHost, cookie: le.admin})).Items {
		e.prodCtr = c["id"].(string)
	}
	e.tag(e.stgHost, map[string]string{"env": "staging"})
	e.tag(e.prodHost, map[string]string{"env": "production"})
	return e
}

// bound adds a user holding one role with scope_json and signs it in.
func (e *rbacEnv) bound(name, role, scopeJSON string) *http.Cookie {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	id, email := "01RB"+strings.ToUpper(name), name+"@example.com"
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, created_at) SELECT ?, ?, ?, password_hash, created_at FROM users WHERE email = ?`, id, email, name, adminEmail); err != nil {
		e.t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO role_bindings (id, subject_type, subject, role, scope_json) VALUES (?, 'user', ?, ?, ?)`, "01RBB"+strings.ToUpper(name), id, role, scopeJSON); err != nil {
		e.t.Fatal(err)
	}
	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(email, goodPassword)})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("login = %d %q", rec.Code, rec.Body)
	}
	return sessionCookieOf(e.t, rec)
}

func names(l listBody, key string) []string {
	var out []string
	for _, it := range l.Items {
		out = append(out, it[key].(string))
	}
	return out
}

func TestACC5_ScopedViewerSeesOnlyItsEnvironment(t *testing.T) {
	e := newRBACEnv(t)
	v := e.bound("stgviewer", "viewer", `{"environments":["staging"]}`)

	if got := names(decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: v})), "hostname"); len(got) != 1 || got[0] != "web-1" {
		t.Errorf("scoped host list = %v", got)
	}
	if got := names(decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers", cookie: v})), "name"); len(got) != 1 || got[0] != "web" {
		t.Errorf("scoped container list = %v", got)
	}
	if got := len(decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: e.admin})).Items); got != 2 {
		t.Errorf("admin sees %d hosts, want 2", got)
	}

	for path, want := range map[string]int{
		"/api/v1/hosts/" + e.stgHost:       200,
		"/api/v1/hosts/" + e.prodHost:      404,
		"/api/v1/containers/" + e.stgCtr:   200,
		"/api/v1/containers/" + e.prodCtr:  404,
		"/api/v1/search?q=prod":            200,
		"/api/v1/hosts?tag=env:production": 200,
	} {
		if rec := e.do(req{method: "GET", path: path, cookie: v}); rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
	}
	if items := decodeList(t, e.do(req{method: "GET", path: "/api/v1/search?q=prod", cookie: v})).Items; len(items) != 0 {
		t.Errorf("search leaked production items: %v", items)
	}
	if items := decodeList(t, e.do(req{method: "GET", path: "/api/v1/search?q=prod", cookie: e.admin})).Items; len(items) == 0 {
		t.Error("admin search found nothing, so the leak check above proves nothing")
	}
	if items := decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts?tag=env:production", cookie: v})).Items; len(items) != 0 {
		t.Errorf("tag filter bypassed the scope: %v", items)
	}
}

func TestLOG7_ScopedViewerCannotOpenProductionLogs(t *testing.T) {
	e := newRBACEnv(t)
	v := e.bound("stgviewer", "viewer", `{"environments":["staging"]}`)

	for _, target := range []string{"container:" + e.prodCtr, "journal:" + e.prodHost + ":nginx.service"} {
		rec := e.get("target="+target, v, nil)
		if rec.Code != http.StatusForbidden || errCode(t, rec) != string(errcode.AuthRBAC002) {
			t.Errorf("%s = %d %q, want 403 AUTH-RBAC-002", target, rec.Code, rec.Body)
		}
	}
	if e.link.opens() != 0 || len(e.aud.events()) != 0 {
		t.Error("a refused stream reached the agent or the audit log")
	}

	c, _, err := e.dial(t, "target="+e.target(), v)
	if err != nil {
		t.Fatalf("staging stream: %v", err)
	}
	_ = c.CloseNow()
	if evs := e.aud.events(); len(evs) != 1 || evs[0].Action != "logs.stream" {
		t.Errorf("audit = %v, want one logs.stream entry", evs)
	}
}

func TestACC5_ScopedViewerGetsFilteredEvents(t *testing.T) {
	e := newRBACEnv(t)
	v := e.bound("stgviewer", "viewer", `{"environments":["staging"]}`)
	c := openStream(t, e.srv.URL, v.Value)
	if _, err := c.r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	e.tag(e.prodHost, map[string]string{"env": "production", "x": "1"}) // must not reach the viewer
	e.tag(e.stgHost, map[string]string{"env": "staging", "x": "1"})
	_, ev, data, ok := c.next(3 * time.Second)
	item, _ := data["item"].(map[string]any)
	if !ok || ev != "host.updated" || item["id"] != e.stgHost {
		t.Fatalf("first event = %q %v (ok %v), want the staging host only", ev, data, ok)
	}
	if id, ev, data, ok := c.next(300 * time.Millisecond); ok {
		t.Errorf("unexpected extra event %s %s %v", id, ev, data)
	}
}

func TestACC5_ScopedRolesAreGlobalChecksAndWrites(t *testing.T) {
	e := newRBACEnv(t)
	v := e.bound("stgviewer", "viewer", `{"environments":["staging"]}`)
	o := e.bound("stgoperator", "operator", `{"environments":["staging"]}`)

	// Global resources need an unscoped binding.
	for _, path := range []string{"/api/v1/checks", "/api/v1/status-pages", "/api/v1/role-bindings"} {
		if rec := e.do(req{method: "GET", path: path, cookie: v}); rec.Code != http.StatusForbidden {
			t.Errorf("scoped viewer GET %s = %d, want 403", path, rec.Code)
		}
	}

	// A scoped operator edits staging items only, and cannot tag one out of its scope.
	put := func(cookie *http.Cookie, id, body string) int {
		login := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody("stgoperator@example.com", goodPassword)})
		csrf := csrfOf(t, login)
		h, _ := e.inv.Index().Host(id)
		return e.do(req{
			method: "PUT", path: "/api/v1/items/hosts/" + id + "/tags", body: body, cookie: sessionCookieOf(t, login),
			headers: map[string]string{csrfHeader: csrf, "If-Match": h.ETag},
		}).Code
	}
	if got := put(o, e.prodHost, `{"tags":{"env":"production","a":"b"}}`); got != http.StatusNotFound {
		t.Errorf("tag prod host = %d, want 404", got)
	}
	if got := put(o, e.stgHost, `{"tags":{"env":"production"}}`); got != http.StatusForbidden {
		t.Errorf("tag staging host into production = %d, want 403", got)
	}
	if got := put(o, e.stgHost, `{"tags":{"env":"staging","a":"b"}}`); got != http.StatusOK {
		t.Errorf("tag staging host = %d, want 200", got)
	}
}

func TestACC5_UnreadableScopeGrantsNothing(t *testing.T) {
	e := newRBACEnv(t)
	for i, bad := range []string{`{"environments":`, `null`, `{"environments":[""]}`} {
		v := e.bound("badscope"+string(rune('a'+i)), "viewer", bad)
		if rec := e.do(req{method: "GET", path: "/api/v1/hosts", cookie: v}); rec.Code != http.StatusForbidden {
			t.Errorf("scope %s: GET /hosts = %d, want 403", bad, rec.Code)
		}
	}
}

func TestACC4_RoleBindingAdminAPI(t *testing.T) {
	e := newRBACEnv(t)
	login := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword)})
	cookie, csrf := sessionCookieOf(t, login), csrfOf(t, login)
	h := map[string]string{csrfHeader: csrf}

	body := `{"subject_type":"oidc_group","subject":"sre","role":"viewer","scope":{"environments":["staging"]}}`
	rec := e.do(req{method: "POST", path: "/api/v1/role-bindings", body: body, cookie: cookie, headers: h})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %q", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "POST", path: "/api/v1/role-bindings", body: body, cookie: cookie}); rec.Code != http.StatusForbidden {
		t.Errorf("create without CSRF = %d, want 403", rec.Code)
	}
	for _, bad := range []string{
		`{"subject_type":"team","subject":"x","role":"viewer","scope":{}}`,
		`{"subject_type":"user","subject":"nobody","role":"viewer","scope":{}}`,
		`{"subject_type":"oidc_group","subject":"x","role":"root","scope":{}}`,
		`{"subject_type":"oidc_group","subject":"x","role":"viewer","scope":{"tag_sets":[[]]}}`,
	} {
		if rec := e.do(req{method: "POST", path: "/api/v1/role-bindings", body: bad, cookie: cookie, headers: h}); rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != string(errcode.AuthRBAC003) {
			t.Errorf("create %s = %d %q", bad, rec.Code, rec.Body)
		}
	}

	list := decodeList(t, e.do(req{method: "GET", path: "/api/v1/role-bindings", cookie: cookie}))
	var groupID, adminBinding string
	for _, b := range list.Items {
		if b["subject"] == "sre" {
			groupID = b["id"].(string)
		} else if b["role"] == "admin" {
			adminBinding = b["id"].(string)
		}
	}
	if groupID == "" || adminBinding == "" {
		t.Fatalf("list = %v", list.Items)
	}
	if rec := e.do(req{method: "DELETE", path: "/api/v1/role-bindings/" + adminBinding, cookie: cookie, headers: h}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("deleting the last admin binding = %d, want 422", rec.Code)
	}
	if rec := e.do(req{method: "DELETE", path: "/api/v1/role-bindings/" + groupID, cookie: cookie, headers: h}); rec.Code != http.StatusNoContent {
		t.Errorf("delete = %d", rec.Code)
	}
	if rec := e.do(req{method: "DELETE", path: "/api/v1/role-bindings/" + groupID, cookie: cookie, headers: h}); rec.Code != http.StatusNotFound || errCode(t, rec) != string(errcode.AuthRBAC004) {
		t.Errorf("delete again = %d %q", rec.Code, rec.Body)
	}

	// Both changes are audited, and only admins reach the endpoints.
	var creates, deletes int
	rows, err := e.db.DB().Query(`SELECT action FROM audit_log WHERE action LIKE 'rolebinding.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		if a == "rolebinding.create" {
			creates++
		} else {
			deletes++
		}
	}
	if creates != 1 || deletes != 1 {
		t.Errorf("audit entries: %d creates, %d deletes, want 1 and 1", creates, deletes)
	}
	viewer := e.bound("plainviewer", "viewer", `{}`)
	if rec := e.do(req{method: "GET", path: "/api/v1/role-bindings", cookie: viewer}); rec.Code != http.StatusForbidden {
		t.Errorf("viewer list = %d, want 403", rec.Code)
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/role-bindings"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list = %d, want 401", rec.Code)
	}
}
