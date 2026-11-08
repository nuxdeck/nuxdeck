// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"net"
	"net/http"
	"strings"
)

const (
	defaultRateLimit = 120
	maxSlugPath      = 80
	// publicCSP lets the page load only its own stylesheet and nothing else. Framing is off by
	// default: embedding a status page is a choice a later setting can make.
	publicCSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	cacheCtl  = "public, max-age=30"
)

var (
	notFoundHTML = []byte("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Not found</title><link rel=\"stylesheet\" href=\"/status/assets/status.css\"></head><body><main><h1>Status page not found</h1><p class=\"desc\">There is no status page at this address.</p></main></body></html>\n")
	notFoundJSON = []byte("{\"error\":{\"code\":\"API-NF-001\",\"message\":\"Resource not found\"}}\n")
	rateHTML     = []byte("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Too many requests</title></head><body><h1>Too many requests</h1><p>Try again in a minute.</p></body></html>\n")
	rateJSON     = []byte("{\"error\":{\"code\":\"STP-RATE-001\",\"message\":\"Too many status page requests\"}}\n")
	cssETag      = etagOf(statusCSS)
)

// RegisterPublic adds the anonymous routes: GET /status/{slug}, GET /status/{slug}.json and the
// stylesheet. They sit outside /api/v1, take no cookies and change nothing.
func (s *Service) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /status/assets/status.css", s.serveCSS)
	mux.HandleFunc("GET /status/{slug}", s.servePage)
}

// publicHeaders are set on every response of the public surface, found or not. They override
// the main application's policy: this surface needs a stricter one.
func publicHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", publicCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func (s *Service) serveCSS(w http.ResponseWriter, r *http.Request) {
	publicHeaders(w)
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", cssETag)
	if r.Header.Get("If-None-Match") == cssETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(statusCSS)
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Service) servePage(w http.ResponseWriter, r *http.Request) {
	publicHeaders(w)
	slug := r.PathValue("slug")
	asJSON := strings.HasSuffix(slug, ".json")
	slug = strings.TrimSuffix(slug, ".json")

	ip := clientIP(r)
	if s.limiter.Blocked(ip) {
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Cache-Control", "no-store")
		write(w, http.StatusTooManyRequests, asJSON, rateHTML, rateJSON)
		return
	}
	s.limiter.Fail(ip) // counts every request, hit or miss, so probing slugs is bounded

	var page *rendered
	if len(slug) <= maxSlugPath && SlugPattern.MatchString(slug) {
		page = s.lookup(slug)
	}
	if page == nil {
		// Unknown, unpublished and malformed slugs all end here, byte for byte the same.
		w.Header().Set("Cache-Control", "no-store")
		write(w, http.StatusNotFound, asJSON, notFoundHTML, notFoundJSON)
		return
	}
	body, etag := page.html, page.htmlETag
	if asJSON {
		body, etag = page.json, page.jsonETag
	}
	w.Header().Set("Cache-Control", cacheCtl)
	w.Header().Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm == etag || inm == "W/"+etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	write(w, http.StatusOK, asJSON, body, body)
}

func write(w http.ResponseWriter, status int, asJSON bool, html, js []byte) {
	body, ct := html, "text/html; charset=utf-8"
	if asJSON {
		body, ct = js, "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
