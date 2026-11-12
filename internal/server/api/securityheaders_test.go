// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// The exact header values are asserted, not substrings: a loosened policy must fail review.
var wantSecurityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	"X-Content-Type-Options":    "nosniff",
	"Referrer-Policy":           "no-referrer",
	"Content-Security-Policy":   "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
}

func TestSEC_SecurityHeadersOnAPIAndUIResponses(t *testing.T) {
	ui := fstest.MapFS{
		"index.html":     {Data: []byte("<!doctype html><title>nux</title>")},
		"assets/app.js":  {Data: []byte("console.log(1)")},
		"assets/app.css": {Data: []byte("body{}")},
	}
	h := Handler(Options{Log: quiet, Ready: fakeReady{}, UI: ui})

	paths := []string{"/healthz", "/readyz", "/api/v1/does-not-exist", "/", "/assets/app.js", "/assets/app.css"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			for name, want := range wantSecurityHeaders {
				if got := rec.Header().Get(name); got != want {
					t.Errorf("GET %s: %s = %q, want %q", path, name, got, want)
				}
			}
		})
	}
}
