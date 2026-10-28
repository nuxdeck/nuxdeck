// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"strings"
	"testing"
)

const pageBodyFmt = `{"slug":"acme","title":"Acme","description":"Hello","published":true,"components":[{"name":"API","check_ids":["%s"]}]}`

func (c *checkEnv) pageBody() string {
	id, _ := c.createCheck()
	return strings.Replace(pageBodyFmt, "%s", id, 1)
}

func (c *checkEnv) createPage() (id, etag string) {
	c.t.Helper()
	rec := c.op("POST", "/api/v1/status-pages", c.pageBody(), "")
	if rec.Code != http.StatusCreated {
		c.t.Fatalf("create page = %d %s", rec.Code, rec.Body)
	}
	return decodeMap(c.t, rec)["id"].(string), rec.Header().Get("ETag")
}

func TestSTP_RolesGateEveryStatusPageEndpoint(t *testing.T) {
	c := newCheckEnv(t)
	id, _ := c.createPage()
	base := "/api/v1/status-pages"
	inc := `{"title":"t","body":"b","status":"investigating","impact":"none"}`
	created := c.op("POST", base+"/"+id+"/incidents", inc, "")
	iid := decodeMap(t, created)["id"].(string)
	for _, tc := range []struct {
		method, path, body string
		write              bool
	}{
		{"GET", base, "", false},
		{"GET", base + "/" + id, "", false},
		{"GET", base + "/" + id + "/incidents", "", false},
		{"POST", base, `{"slug":"x2","title":"x"}`, true},
		{"PUT", base + "/" + id, `{"title":"x"}`, true},
		{"DELETE", base + "/" + id, "", true},
		{"POST", base + "/" + id + "/incidents", inc, true},
		{"POST", base + "/" + id + "/incidents/" + iid + "/updates", `{"status":"monitoring","body":"x"}`, true},
		{"POST", base + "/" + id + "/incidents/" + iid + "/resolve", `{}`, true},
		{"DELETE", base + "/" + id + "/incidents/" + iid, "", true},
	} {
		name := tc.method + " " + tc.path
		if rec := c.send(tc.method, tc.path, tc.body, nil, "", "\"p1\""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous = %d", name, rec.Code)
		}
		rec := c.send(tc.method, tc.path, tc.body, c.viewer, c.viewerCSRF, "\"p1\"")
		if tc.write && rec.Code != http.StatusForbidden {
			t.Errorf("%s viewer = %d", name, rec.Code)
		}
		if !tc.write && rec.Code != http.StatusOK {
			t.Errorf("%s viewer = %d", name, rec.Code)
		}
		// An operator without the CSRF token is refused on writes.
		if tc.write {
			if rec := c.send(tc.method, tc.path, tc.body, c.operator, "wrong", "\"p1\""); rec.Code != http.StatusForbidden {
				t.Errorf("%s bad CSRF = %d", name, rec.Code)
			}
		}
	}
}

func TestSTP_PageCRUDWithETagAndAudit(t *testing.T) {
	c := newCheckEnv(t)
	id, etag := c.createPage()
	path := "/api/v1/status-pages/" + id

	if rec := c.op("PUT", path, `{"title":"Renamed","published":false}`, ""); rec.Code != http.StatusPreconditionRequired || errCode(t, rec) != "API-PRE-002" {
		t.Errorf("missing If-Match = %d", rec.Code)
	}
	rec := c.op("PUT", path, `{"title":"Renamed","published":false}`, etag)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == etag {
		t.Fatalf("update = %d etag %q", rec.Code, rec.Header().Get("ETag"))
	}
	if rec := c.op("PUT", path, `{"title":"Again"}`, etag); rec.Code != http.StatusPreconditionFailed || errCode(t, rec) != "API-PRE-001" {
		t.Errorf("stale = %d", rec.Code)
	}
	// A fetched document can be sent back unchanged.
	got := c.op("GET", path, "", "")
	if rec := c.op("PUT", path, got.Body.String(), got.Header().Get("ETag")); rec.Code != http.StatusOK {
		t.Errorf("round trip = %d %s", rec.Code, rec.Body)
	}
	if rec := c.op("PUT", path, `{"slug":"changed","title":"x"}`, c.op("GET", path, "", "").Header().Get("ETag")); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("slug change = %d", rec.Code)
	}
	if rec := c.op("POST", "/api/v1/status-pages", c.pageBody(), ""); rec.Code != http.StatusConflict || errCode(t, rec) != "STP-SLUG-001" {
		t.Errorf("duplicate slug = %d %s", rec.Code, rec.Body)
	}
	if rec := c.op("DELETE", path, "", ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete = %d", rec.Code)
	}
	if rec := c.op("GET", path, "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("get deleted = %d", rec.Code)
	}
	var n int
	if err := c.db.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'status_page.%'`).Scan(&n); err != nil || n != 4 {
		t.Errorf("audit rows = %d, %v", n, err)
	}
	for _, tc := range []struct{ name, body string }{
		{"bad slug", `{"slug":"Bad Slug","title":"x"}`},
		{"unknown check", `{"slug":"ok","title":"x","components":[{"name":"n","check_ids":["01HZZZZZZZZZZZZZZZZZZZZZZZ"]}]}`},
		{"control char", "{\"slug\":\"ok\",\"title\":\"a\\u0000b\"}"},
		{"unknown field", `{"slug":"ok","title":"x","evil":1}`},
		{"empty title", `{"slug":"ok","title":""}`},
	} {
		if rec := c.op("POST", "/api/v1/status-pages", tc.body, ""); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", tc.name, rec.Code)
		}
	}
	if rec := c.op("GET", "/api/v1/status-pages/not-a-ulid", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("bad id = %d", rec.Code)
	}
}

func TestSTP_PublicSurfaceBesideTheApp(t *testing.T) {
	c := newCheckEnv(t)
	id, _ := c.createPage()
	inc := c.op("POST", "/api/v1/status-pages/"+id+"/incidents", `{"title":"<b>Outage</b>","body":"line1\nline2","status":"investigating","impact":"major"}`, "")
	if inc.Code != http.StatusCreated {
		t.Fatalf("incident = %d %s", inc.Code, inc.Body)
	}
	iid := decodeMap(t, inc)["id"].(string)
	if rec := c.op("POST", "/api/v1/status-pages/"+id+"/incidents/"+iid+"/resolve", `{"body":"fixed"}`, ""); rec.Code != http.StatusOK || decodeMap(t, rec)["resolved_at"] == nil {
		t.Fatalf("resolve = %d %s", rec.Code, rec.Body)
	}

	// No session cookie: the public page is open, with its own CSP in place of the app's.
	rec := c.do(req{method: "GET", path: "/status/acme"})
	if rec.Code != http.StatusOK {
		t.Fatalf("public = %d %s", rec.Code, rec.Body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	if strings.Contains(rec.Body.String(), "<b>Outage") || !strings.Contains(rec.Body.String(), "&lt;b&gt;Outage&lt;/b&gt;") {
		t.Errorf("incident title not escaped: %s", rec.Body)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS lost")
	}
	if j := c.do(req{method: "GET", path: "/status/acme.json"}); j.Code != http.StatusOK || !strings.Contains(j.Body.String(), `"resolved_at":"`) {
		t.Errorf("json = %d %s", j.Code, j.Body)
	}
	// The app's own routes keep the app's policy.
	if app := c.do(req{method: "GET", path: "/healthz"}); !strings.Contains(app.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("app CSP = %q", app.Header().Get("Content-Security-Policy"))
	}
	// An unpublished page is a plain 404 to the world.
	rec2 := c.op("PUT", "/api/v1/status-pages/"+id, `{"title":"Acme","published":false}`, c.op("GET", "/api/v1/status-pages/"+id, "", "").Header().Get("ETag"))
	if rec2.Code != http.StatusOK {
		t.Fatal(rec2.Body)
	}
	if rec := c.do(req{method: "GET", path: "/status/acme"}); rec.Code != http.StatusNotFound {
		t.Errorf("unpublished = %d", rec.Code)
	}
	if rec := c.do(req{method: "POST", path: "/status/acme", body: "{}"}); rec.Code == http.StatusOK {
		t.Errorf("POST to the public page = %d", rec.Code)
	}
}
