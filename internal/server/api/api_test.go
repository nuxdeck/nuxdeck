// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/tlsutil"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeReady struct{ err error }

func (f fakeReady) Ping(context.Context) error { return f.err }

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndReadiness(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		ready  error
		status int
	}{
		{"healthz", "/healthz", nil, http.StatusOK},
		{"readyz up", "/readyz", nil, http.StatusOK},
		{"readyz down", "/readyz", errors.New("db gone"), http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, Handler(Options{Log: quiet, Ready: fakeReady{tt.ready}, Version: "test"}), tt.path, nil)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if strings.Contains(rec.Body.String(), "db gone") {
				t.Error("internal error detail leaked to the client")
			}
		})
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	h := Handler(Options{Log: quiet, Ready: fakeReady{}})

	rec := get(t, h, "/healthz", map[string]string{"X-Request-ID": "trace-12345678"})
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Request-ID":           "trace-12345678",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe") {
		t.Errorf("weak CSP: %q", csp)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing HSTS")
	}

	for _, bad := range []string{"short", "has space in it!", strings.Repeat("a", 65), "new\nline12345"} {
		got := get(t, h, "/healthz", map[string]string{"X-Request-ID": bad}).Header().Get("X-Request-ID")
		if got == bad || len(got) != 16 {
			t.Errorf("request ID %q was accepted or replaced badly (%q)", bad, got)
		}
	}
}

func TestUnknownPathUsesErrorShape(t *testing.T) {
	rec := get(t, Handler(Options{Log: quiet, Ready: fakeReady{}}), "/nope", nil)
	var body struct {
		Error struct{ Code, Message, Hint string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound || body.Error.Code != "API-NF-001" || body.Error.Message == "" || body.Error.Hint == "" {
		t.Errorf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestPanicIsContained(t *testing.T) {
	h := recoverer(quiet, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	if rec := get(t, h, "/", nil); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("status %d body %q", rec.Code, rec.Body)
	}
}

func startServer(t *testing.T) (*Server, *http.Client, context.CancelFunc, <-chan error) {
	t.Helper()
	cert, err := tlsutil.Certificate(tlsutil.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	srv, err := NewServer(config.HTTP{HTTPSAddr: "127.0.0.1:0", RedirectAddr: "127.0.0.1:0"}, cert,
		Handler(Options{Log: quiet, Ready: fakeReady{}, Version: "test"}), quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true},
	}
	return srv, client, cancel, done
}

func TestServesHTTPSRedirectsHTTPAndShutsDown(t *testing.T) {
	srv, client, cancel, done := startServer(t)

	resp, err := client.Get("https://" + srv.HTTPSAddr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("status %d, TLS version %#x", resp.StatusCode, resp.TLS.Version)
	}

	resp, err = client.Get("http://" + srv.RedirectAddr() + "/healthz?x=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_, port, _ := strings.Cut(srv.HTTPSAddr(), ":")
	if want := "https://127.0.0.1:" + port + "/healthz?x=1"; resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
		t.Errorf("status %d Location %q, want 308 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}

func TestRedirectHandler(t *testing.T) {
	tests := []struct {
		port   string
		host   string
		status int
		loc    string
	}{
		{"443", "nux.example:8080", http.StatusPermanentRedirect, "https://nux.example/p"},
		{"443", "[::1]:8080", http.StatusPermanentRedirect, "https://[::1]/p"},
		{"8443", "nux.example:8080", http.StatusPermanentRedirect, "https://nux.example:8443/p"},
		{"8443", "[::1]:8080", http.StatusPermanentRedirect, "https://[::1]:8443/p"},
		{"8443", "evil.com/x", http.StatusBadRequest, ""},
		{"8443", "a@b", http.StatusBadRequest, ""},
		{"8443", "", http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Host = tt.host
		rec := httptest.NewRecorder()
		redirectHandler(tt.port).ServeHTTP(rec, req)
		if rec.Code != tt.status || rec.Header().Get("Location") != tt.loc {
			t.Errorf("host %q: status %d Location %q, want %d %q", tt.host, rec.Code, rec.Header().Get("Location"), tt.status, tt.loc)
		}
	}
}
