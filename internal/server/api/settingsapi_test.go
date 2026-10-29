// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTEL_PreviewIsAdminOnlyAndIsSchemaV1(t *testing.T) {
	c := newCheckEnv(t)
	for name, cookie := range map[string]*http.Cookie{"viewer": c.viewer, "operator": c.operator} {
		if rec := c.send("GET", "/api/v1/telemetry/preview", "", cookie, "", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s preview = %d", name, rec.Code)
		}
	}
	if rec := c.send("GET", "/api/v1/telemetry/preview", "", nil, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous preview = %d", rec.Code)
	}
	rec := c.send("GET", "/api/v1/telemetry/preview", "", c.admin, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin preview = %d %s", rec.Code, rec.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["schema_version"] != float64(1) || len(m) != 20 {
		t.Errorf("preview = %v", m)
	}
}

func TestTEL_ToggleIsAdminCSRFAuditedAndOffByDefault(t *testing.T) {
	c := newCheckEnv(t)
	on := `{"key":"telemetry.enabled","value":true}`
	if rec := c.send("GET", "/api/v1/settings", "", c.admin, "", ""); !strings.Contains(rec.Body.String(), `"telemetry.enabled":false`) {
		t.Fatalf("default = %s", rec.Body)
	}
	if rec := c.send("PUT", "/api/v1/settings", on, c.operator, c.opCSRF, ""); rec.Code != http.StatusForbidden {
		t.Errorf("operator PUT = %d", rec.Code)
	}
	if rec := c.send("PUT", "/api/v1/settings", on, c.admin, "", ""); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF PUT = %d", rec.Code)
	}
	for _, bad := range []string{`{"key":"other","value":true}`, `{"key":"telemetry.enabled","value":"yes"}`, `{"key":"telemetry.enabled","value":null}`, `{"key":"telemetry.enabled","value":true,"x":1}`} {
		if rec := c.send("PUT", "/api/v1/settings", bad, c.admin, c.adminCSRF, ""); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", bad, rec.Code)
		}
	}
	if rec := c.send("PUT", "/api/v1/settings", on, c.admin, c.adminCSRF, ""); rec.Code != http.StatusOK {
		t.Fatalf("enable = %d %s", rec.Code, rec.Body)
	}
	preview := c.send("GET", "/api/v1/telemetry/preview", "", c.admin, "", "").Body.String()
	if strings.Contains(preview, "00000000-0000-4000") {
		t.Errorf("enabled preview still shows the placeholder ID: %s", preview)
	}
	if rec := c.send("PUT", "/api/v1/settings", `{"key":"telemetry.enabled","value":false}`, c.admin, c.adminCSRF, ""); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d", rec.Code)
	}
	if !strings.Contains(c.send("GET", "/api/v1/telemetry/preview", "", c.admin, "", "").Body.String(), "00000000-0000-4000") {
		t.Error("disabling did not delete the install ID")
	}
	var n int
	if err := c.db.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'settings.update'`).Scan(&n); err != nil || n != 2 {
		t.Errorf("audit entries = %d, %v", n, err)
	}
}

func TestINS3_PublicURLAndSetupFlagAreAdminCSRFAndAuditedAndValidated(t *testing.T) {
	c := newCheckEnv(t)
	put := func(body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		return c.send("PUT", "/api/v1/settings", body, cookie, csrf, "")
	}
	setURL := `{"key":"server.public_url","value":"https://nux.example.com:8443/"}`

	var defaults map[string]any
	if err := json.Unmarshal(c.send("GET", "/api/v1/settings", "", c.admin, "", "").Body.Bytes(), &defaults); err != nil {
		t.Fatal(err)
	}
	if defaults["server.public_url"] != "" || defaults["setup.completed"] != false {
		t.Errorf("defaults = %v", defaults)
	}

	if rec := put(setURL, c.operator, c.opCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("operator public_url = %d", rec.Code)
	}
	if rec := put(setURL, c.viewer, c.viewerCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("viewer public_url = %d", rec.Code)
	}
	if rec := put(setURL, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous public_url = %d", rec.Code)
	}
	if rec := put(setURL, c.admin, ""); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF public_url = %d", rec.Code)
	}
	if rec := put(`{"key":"setup.completed","value":true}`, c.operator, c.opCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("operator setup.completed = %d", rec.Code)
	}

	bad := []string{
		`{"key":"server.public_url","value":""}`,
		`{"key":"server.public_url","value":null}`,
		`{"key":"server.public_url","value":42}`,
		`{"key":"server.public_url","value":"ftp://nux.example.com"}`,
		`{"key":"server.public_url","value":"javascript:alert(1)"}`,
		`{"key":"server.public_url","value":"nux.example.com:8443"}`,
		`{"key":"server.public_url","value":"https://"}`,
		`{"key":"server.public_url","value":"https://admin:secret@nux.example.com"}`,
		`{"key":"server.public_url","value":"https://nux.example.com/path"}`,
		`{"key":"server.public_url","value":"https://nux.example.com?x=1"}`,
		`{"key":"server.public_url","value":"https://nux.example.com#frag"}`,
		`{"key":"server.public_url","value":"https://nux example.com"}`,
		`{"key":"server.public_url","value":"https://nux.example.com\r\nX: y"}`,
		`{"key":"setup.completed","value":"yes"}`,
		`{"key":"setup.completed","value":null}`,
		`{"key":"setup.unknown","value":true}`,
	}
	for _, body := range bad {
		if rec := put(body, c.admin, c.adminCSRF); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d %s", body, rec.Code, rec.Body)
		}
	}
	var n int
	if err := c.rawDB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'settings.update'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rejected writes left %d audit entries, %v", n, err)
	}

	rec := put(setURL, c.admin, c.adminCSRF)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"server.public_url":"https://nux.example.com:8443"`) {
		t.Fatalf("set public_url = %d %s", rec.Code, rec.Body)
	}
	rec = put(`{"key":"setup.completed","value":true}`, c.admin, c.adminCSRF)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"setup.completed":true`) {
		t.Fatalf("set setup.completed = %d %s", rec.Code, rec.Body)
	}
	got := c.send("GET", "/api/v1/settings", "", c.admin, "", "").Body.String()
	if !strings.Contains(got, `"server.public_url":"https://nux.example.com:8443"`) || !strings.Contains(got, `"setup.completed":true`) {
		t.Errorf("GET after writes = %s", got)
	}

	var audited int
	if err := c.rawDB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'settings.update' AND target_id IN ('server.public_url', 'setup.completed')`).Scan(&audited); err != nil || audited != 2 {
		t.Errorf("audit entries = %d, %v", audited, err)
	}
}

func TestINS3_NormalizePublicURL(t *testing.T) {
	ok := map[string]string{
		"https://nux.example.com":       "https://nux.example.com",
		"https://nux.example.com/":      "https://nux.example.com",
		"http://10.0.0.5:8443":          "http://10.0.0.5:8443",
		"HTTPS://nux.example.com:9443/": "https://nux.example.com:9443",
	}
	for in, want := range ok {
		got, err := normalizePublicURL(in)
		if err != nil || got != want {
			t.Errorf("normalizePublicURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "mailto:a@b.c", "https:///x", "https://a@b", "https://h/p", "https://h/?", "https://h/%zz", strings.Repeat("a", maxPublicURLBytes)} {
		if got, err := normalizePublicURL(in); err == nil {
			t.Errorf("normalizePublicURL(%q) accepted as %q", in, got)
		}
	}
}
