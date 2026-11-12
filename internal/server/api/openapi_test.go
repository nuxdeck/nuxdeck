// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"net/http"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	openapi "github.com/nuxdeck/nuxdeck/api"
)

// optionalRoutes are added by the single sign-on work. The document describes them whether or not
// the source registers them yet, so the coverage check accepts them in the document alone. Once a
// route is registered it must be documented like any other, which the check still enforces.
var optionalRoutes = map[string]bool{
	"GET /api/v1/auth/oidc/status":   true,
	"GET /api/v1/auth/oidc/start":    true,
	"GET /api/v1/auth/oidc/callback": true,
	"GET /api/v1/settings/oidc":      true,
	"PUT /api/v1/settings/oidc":      true,
	"DELETE /api/v1/settings/oidc":   true,
}

// sourceAPIRoutes returns "METHOD /api/v1/..." for every route the server registers (API-1).
func sourceAPIRoutes(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		if strings.HasPrefix(r.path, "/api/v1/") {
			out[r.method+" "+r.path] = true
		}
	}
	return out
}

// documentedAPIRoutes returns "METHOD /api/v1/..." for every operation in api/openapi.yaml.
func documentedAPIRoutes(t *testing.T) map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapi.Document, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]bool{}
	for path, raw := range doc.Paths {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("path %s is not an object", path)
		}
		for key := range item {
			switch m := strings.ToUpper(key); m {
			case http.MethodGet, http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
				out[m+" "+path] = true
			}
		}
	}
	return out
}

// TestCLI1_EveryRouteIsDocumented fails when a registered /api/v1 route is missing from the OpenAPI
// document, or when the document lists a route the server no longer registers (NUX-40).
func TestCLI1_EveryRouteIsDocumented(t *testing.T) {
	source := sourceAPIRoutes(t)
	documented := documentedAPIRoutes(t)
	if len(source) < 60 {
		t.Fatalf("route scan found only %d /api/v1 routes; the scanner is broken", len(source))
	}

	var missing, stale []string
	for key := range source {
		if !documented[key] {
			missing = append(missing, key)
		}
	}
	for key := range documented {
		if !source[key] && !optionalRoutes[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("registered but not in api/openapi.yaml; document them:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("in api/openapi.yaml but not registered; remove them or register the route:\n  %s", strings.Join(stale, "\n  "))
	}
}

// TestCLI1_OpenAPIDocumentIsServed checks the document endpoint: anonymous callers are refused, a
// signed-in viewer receives the embedded bytes unchanged (CLI-1, Authorize first).
func TestCLI1_OpenAPIDocumentIsServed(t *testing.T) {
	e := newRBACEnv(t)
	viewer := e.bound("docviewer", "viewer", `{}`)

	if rec := e.do(req{method: "GET", path: "/api/v1/openapi.yaml"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GET = %d, want 401", rec.Code)
	}
	for _, cookie := range []*http.Cookie{viewer, e.admin} {
		rec := e.do(req{method: "GET", path: "/api/v1/openapi.yaml", cookie: cookie})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/yaml" {
			t.Errorf("Content-Type = %q", ct)
		}
		if !bytes.Equal(rec.Body.Bytes(), openapi.Document) {
			t.Error("served document differs from the embedded api/openapi.yaml")
		}
	}
}
