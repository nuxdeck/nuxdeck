// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func uiFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":         {Data: []byte("<!doctype html><title>Nux Deck</title>")},
		"assets/app-abc.js":  {Data: []byte("console.log(1)")},
		"theme-init.js":      {Data: []byte("/* theme */")},
		".gitkeep":           {Data: nil},
		"assets/app-abc.css": {Data: []byte("body{}")},
	}
}

func uiHandler() http.Handler {
	return Handler(Options{Log: quiet, Ready: fakeReady{}, UI: uiFS()})
}

func TestUIServing(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		status    int
		bodyHas   string
		cacheCtrl string
	}{
		{"root", "GET", "/", 200, "Nux Deck", "no-cache"},
		{"explicit index", "GET", "/index.html", 200, "Nux Deck", "no-cache"},
		{"client route falls back to index", "GET", "/inventory", 200, "Nux Deck", "no-cache"},
		{"nested client route", "GET", "/inventory/hosts/web-01", 200, "Nux Deck", "no-cache"},
		{"hashed asset is immutable", "GET", "/assets/app-abc.js", 200, "console.log", "public, max-age=31536000, immutable"},
		{"unhashed file is revalidated", "GET", "/theme-init.js", 200, "theme", "no-cache"},
		{"missing asset is a JSON 404", "GET", "/assets/gone.js", 404, "API-NF-001", ""},
		{"dotfile is hidden", "GET", "/.gitkeep", 404, "API-NF-001", ""},
		{"unknown API path is not the UI", "GET", "/api/v1/nope", 404, "API-NF-001", ""},
		{"bare /api is not the UI", "GET", "/api", 404, "API-NF-001", ""},
		{"head works", "HEAD", "/", 200, "", "no-cache"},
		{"post is not the UI", "POST", "/", 404, "API-NF-001", ""},
		// The mux cleans the path and redirects; the target is then just another client route.
		{"traversal is redirected to the cleaned path", "GET", "/assets/../../etc/passwd", 307, "/etc/passwd", ""},
		{"cleaned traversal target is only the app", "GET", "/etc/passwd", 200, "Nux Deck", "no-cache"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			uiHandler().ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.status, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tt.bodyHas) {
				t.Errorf("body %q lacks %q", rec.Body, tt.bodyHas)
			}
			if got := rec.Header().Get("Cache-Control"); tt.cacheCtrl != "" && got != tt.cacheCtrl {
				t.Errorf("Cache-Control = %q, want %q", got, tt.cacheCtrl)
			}
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("UI responses must carry the CSP")
			}
		})
	}
}

func TestUIWithoutBuild(t *testing.T) {
	h := Handler(Options{Log: quiet, Ready: fakeReady{}, UI: fstest.MapFS{".gitkeep": {}}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "make build") {
		t.Errorf("status %d body %q", rec.Code, rec.Body)
	}
	// The API stays up without the UI.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d", rec.Code)
	}
}

func TestNoUIKeepsJSONNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler(Options{Log: quiet, Ready: fakeReady{}}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "API-NF-001") {
		t.Errorf("status %d body %q", rec.Code, rec.Body)
	}
}
