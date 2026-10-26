// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

const (
	goodPassword = "correct horse battery"
	adminEmail   = "ada@example.com"
)

type syncLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type authEnv struct {
	t       *testing.T
	h       http.Handler
	db      *store.Store
	token   *auth.SetupToken
	logs    *syncLog
	revoker *fakeRevoker
	pki     *pki.Service
	inv     *inventory.Service
	dir     string
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	dir := t.TempDir()
	logs := &syncLog{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db, err := store.Open(context.Background(), dir, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	token := auth.NewSetupToken(dir)
	if err := token.Ensure(); err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: db, Hasher: auth.NewHasherWithParams(8, 1, 1), Passwords: auth.NewPasswordPolicy(), SetupToken: token, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rv := &fakeRevoker{}
	pkiSvc := pki.NewService(db, ca)
	inv, err := inventory.NewService(db, log)
	if err != nil {
		t.Fatal(err)
	}
	return &authEnv{
		t: t, dir: dir, db: db, token: token, logs: logs, revoker: rv, pki: pkiSvc, inv: inv,
		h: Handler(Options{Log: log, Ready: db, UI: uiFS(), Auth: svc, PKI: pkiSvc, GatewayURL: "https://nux.example.com:8444", Revoker: rv, Inventory: inv}),
	}
}

type req struct {
	method, path, body string
	cookie             *http.Cookie
	headers            map[string]string
	noJSON             bool
}

func (e *authEnv) do(r req) *httptest.ResponseRecorder {
	e.t.Helper()
	var body io.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	hr := httptest.NewRequest(r.method, r.path, body)
	hr.RemoteAddr = "203.0.113.5:4711"
	if r.body != "" && !r.noJSON {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.cookie != nil {
		hr.AddCookie(r.cookie)
	}
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Error struct{ Code, Field, Hint string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("not an error body: %q", rec.Body)
	}
	return b.Error.Code
}

func sessionCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func csrfOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b sessionJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b.CSRFToken == "" {
		t.Fatalf("no CSRF token in %q", rec.Body)
	}
	return b.CSRFToken
}

func (e *authEnv) setup() *httptest.ResponseRecorder {
	tok, err := e.token.Read()
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok, "name": "Ada Admin", "email": adminEmail, "password": goodPassword})
	return e.do(req{method: "POST", path: "/api/v1/setup/admin", body: string(body)})
}

func loginBody(email, pw string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	return string(b)
}

func TestFirstRunSetupFlow(t *testing.T) {
	e := newAuthEnv(t)

	if rec := e.do(req{method: "GET", path: "/api/v1/setup/status"}); !strings.Contains(rec.Body.String(), `"setup_required":true`) {
		t.Errorf("status = %q", rec.Body)
	}

	rec := e.do(req{method: "POST", path: "/api/v1/setup/admin", body: `{"token":"wrong","name":"Ada","email":"a@example.com","password":"correct horse battery"}`})
	if rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-SETUP-001" {
		t.Errorf("wrong token: %d %q", rec.Code, rec.Body)
	}

	rec = e.setup()
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup = %d %q", rec.Code, rec.Body)
	}
	c := sessionCookieOf(t, rec)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("session cookie is not locked down: %+v", c)
	}
	if c.Expires.IsZero() {
		t.Error("the cookie must carry the session's absolute expiry")
	}
	if !strings.Contains(rec.Body.String(), `"roles":["admin"]`) {
		t.Errorf("body = %q", rec.Body)
	}

	if rec := e.do(req{method: "GET", path: "/api/v1/setup/status"}); !strings.Contains(rec.Body.String(), `"setup_required":false`) {
		t.Errorf("status after setup = %q", rec.Body)
	}
	if again := e.do(req{method: "POST", path: "/api/v1/setup/admin", body: `{"token":"x","name":"Eve","email":"eve@example.com","password":"correct horse battery"}`}); again.Code != http.StatusConflict || errCode(t, again) != "AUTH-SETUP-002" {
		t.Errorf("second setup: %d %q", again.Code, again.Body)
	}
	if n, err := e.db.VerifyAuditChain(context.Background()); err != nil || n < 2 {
		t.Errorf("audit chain: %d entries, %v", n, err)
	}
}

func TestSetupValidation(t *testing.T) {
	tests := []struct {
		name, mutate string
		status       int
		code, field  string
	}{
		{"short password", `"password":"short"`, 422, "AUTH-PWD-001", "password"},
		{"breached password", `"password":"123qweasdzxc"`, 422, "AUTH-PWD-001", "password"},
		{"bad email", `"email":"nope"`, 422, "API-VAL-001", "email"},
		{"empty name", `"name":""`, 422, "API-VAL-001", "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthEnv(t)
			tok, _ := e.token.Read()
			fields := map[string]string{"token": tok, "name": "Ada", "email": adminEmail, "password": goodPassword}
			var override map[string]string
			if err := json.Unmarshal([]byte("{"+tt.mutate+"}"), &override); err != nil {
				t.Fatal(err)
			}
			for k, v := range override {
				fields[k] = v
			}
			body, _ := json.Marshal(fields)
			rec := e.do(req{method: "POST", path: "/api/v1/setup/admin", body: string(body)})
			if rec.Code != tt.status || errCode(t, rec) != tt.code || !strings.Contains(rec.Body.String(), `"field":"`+tt.field+`"`) {
				t.Errorf("%d %q", rec.Code, rec.Body)
			}
			if tt.code == "AUTH-PWD-001" && !strings.Contains(rec.Body.String(), "hint") {
				t.Error("a rejected password must say why")
			}
		})
	}
}

func TestLoginMeLogout(t *testing.T) {
	e := newAuthEnv(t)
	e.setup()

	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody("ADA@example.com", goodPassword)})
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d %q", rec.Code, rec.Body)
	}
	cookie, csrf := sessionCookieOf(t, rec), csrfOf(t, rec)

	me := e.do(req{method: "GET", path: "/api/v1/me", cookie: cookie})
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), adminEmail) || csrfOf(t, me) != csrf {
		t.Errorf("me = %d %q", me.Code, me.Body)
	}
	if anon := e.do(req{method: "GET", path: "/api/v1/me"}); anon.Code != http.StatusUnauthorized || errCode(t, anon) != "AUTH-DENY-003" {
		t.Errorf("anonymous me = %d %q", anon.Code, anon.Body)
	}
	forged := &http.Cookie{Name: sessionCookie, Value: "forged"} //nolint:gosec // a forged cookie sent on purpose
	if rec := e.do(req{method: "GET", path: "/api/v1/me", cookie: forged}); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged cookie = %d", rec.Code)
	}

	// Logout needs the CSRF token.
	for name, hdr := range map[string]map[string]string{"missing": nil, "wrong": {csrfHeader: "nope"}} {
		rec := e.do(req{method: "POST", path: "/api/v1/auth/logout", cookie: cookie, headers: hdr})
		if rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
			t.Errorf("%s CSRF token: %d %q", name, rec.Code, rec.Body)
		}
	}
	if still := e.do(req{method: "GET", path: "/api/v1/me", cookie: cookie}); still.Code != http.StatusOK {
		t.Error("a rejected logout must leave the session alone")
	}

	out := e.do(req{method: "POST", path: "/api/v1/auth/logout", cookie: cookie, headers: map[string]string{csrfHeader: csrf}})
	if out.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %q", out.Code, out.Body)
	}
	if cleared := sessionCookieOf(t, out); cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("cookie not cleared: %+v", cleared)
	}
	if after := e.do(req{method: "GET", path: "/api/v1/me", cookie: cookie}); after.Code != http.StatusUnauthorized {
		t.Error("the old cookie must stop working after logout")
	}
	if out := e.do(req{method: "POST", path: "/api/v1/auth/logout"}); out.Code != http.StatusUnauthorized {
		t.Errorf("anonymous logout = %d", out.Code)
	}
}

func TestLoginFailuresAreUniform(t *testing.T) {
	e := newAuthEnv(t)
	e.setup()
	a := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, "wrong password here")})
	b := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody("nobody@example.com", "wrong password here")})
	if a.Code != 401 || b.Code != 401 || a.Body.String() != b.Body.String() {
		t.Errorf("a wrong password and an unknown account must look identical:\n%d %q\n%d %q", a.Code, a.Body, b.Code, b.Body)
	}
	if errCode(t, a) != "AUTH-DENY-001" {
		t.Errorf("code = %q", errCode(t, a))
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newAuthEnv(t)
	e.setup()
	var last *httptest.ResponseRecorder
	for i := 0; i < 11; i++ {
		last = e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, "wrong password here")})
	}
	if last.Code != http.StatusTooManyRequests || last.Header().Get("Retry-After") == "" || errCode(t, last) != "AUTH-DENY-002" {
		t.Errorf("11th attempt: %d %q", last.Code, last.Body)
	}
	if right := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword)}); right.Code != http.StatusTooManyRequests {
		t.Errorf("even the right password must wait while blocked, got %d", right.Code)
	}
}

func TestCrossSiteRequestsAreRefused(t *testing.T) {
	e := newAuthEnv(t)
	signedIn := e.setup()
	cookie, csrf := sessionCookieOf(t, signedIn), csrfOf(t, signedIn)

	attacks := map[string]map[string]string{
		"foreign origin":       {"Origin": "https://evil.example"},
		"cross-site fetch":     {"Sec-Fetch-Site": "cross-site"},
		"same-site (sibling)":  {"Sec-Fetch-Site": "same-site"},
		"origin with our host": {"Origin": "https://example.com.evil.example"},
	}
	for name, hdr := range attacks {
		for _, path := range []string{"/api/v1/auth/login", "/api/v1/setup/admin"} {
			rec := e.do(req{method: "POST", path: path, body: loginBody(adminEmail, goodPassword), headers: hdr})
			if rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
				t.Errorf("%s -> %s: %d %q", name, path, rec.Code, rec.Body)
			}
		}
		h := map[string]string{csrfHeader: csrf}
		for k, v := range hdr {
			h[k] = v
		}
		if rec := e.do(req{method: "POST", path: "/api/v1/auth/logout", cookie: cookie, headers: h}); rec.Code != http.StatusForbidden {
			t.Errorf("%s -> logout with a valid CSRF token: %d", name, rec.Code)
		}
	}
	// A same-origin browser request and a header-less client both work.
	ok := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword), headers: map[string]string{"Origin": "https://example.com", "Sec-Fetch-Site": "same-origin"}})
	if ok.Code != http.StatusOK {
		t.Errorf("same-origin login = %d %q", ok.Code, ok.Body)
	}
}

func TestStrictRequestParsing(t *testing.T) {
	e := newAuthEnv(t)
	e.setup()
	big := `{"email":"` + strings.Repeat("a", 9000) + `","password":"x"}`
	tests := []struct {
		name   string
		r      req
		status int
	}{
		{"wrong content type", req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword), headers: map[string]string{"Content-Type": "text/plain"}, noJSON: true}, 415},
		{"no content type", req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword), noJSON: true}, 415},
		{"unknown field", req{method: "POST", path: "/api/v1/auth/login", body: `{"email":"a@b.co","password":"x","admin":true}`}, 400},
		{"not json", req{method: "POST", path: "/api/v1/auth/login", body: `email=a`}, 400},
		{"trailing data", req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, "x") + `{"a":1}`}, 400},
		{"oversized body", req{method: "POST", path: "/api/v1/auth/login", body: big}, 413},
		{"empty object logs in nobody", req{method: "POST", path: "/api/v1/auth/login", body: `{}`}, 401},
	}
	for _, tt := range tests {
		if rec := e.do(tt.r); rec.Code != tt.status {
			t.Errorf("%s: %d %q, want %d", tt.name, rec.Code, rec.Body, tt.status)
		}
	}
}

func TestNothingSecretReachesLogsOrErrors(t *testing.T) {
	e := newAuthEnv(t)
	tok, _ := e.token.Read()
	rec := e.setup()
	cookie, csrf := sessionCookieOf(t, rec), csrfOf(t, rec)
	bad := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, "wrong password here")})
	e.do(req{method: "GET", path: "/api/v1/me", cookie: cookie})

	secrets := []string{goodPassword, "wrong password here", tok, cookie.Value, csrf}
	for _, s := range secrets {
		if strings.Contains(e.logs.String(), s) {
			t.Errorf("a secret leaked into the logs: %q", s)
		}
		if strings.Contains(bad.Body.String(), s) {
			t.Errorf("a secret leaked into an error response: %q", s)
		}
	}
	if strings.Contains(rec.Body.String(), goodPassword) || strings.Contains(rec.Body.String(), "argon2") {
		t.Error("responses must never carry the password or its hash")
	}
}

func TestUnknownAPIRoutesStayJSON404AndNoAuthMeansNoRoutes(t *testing.T) {
	e := newAuthEnv(t)
	if rec := e.do(req{method: "GET", path: "/api/v1/no-such-route"}); rec.Code != http.StatusNotFound || errCode(t, rec) != "API-NF-001" {
		t.Errorf("unknown route: %d %q", rec.Code, rec.Body)
	}
	bare := Handler(Options{Log: quiet, Ready: fakeReady{}})
	rec := httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("without an auth service /api/v1/me = %d, want 404", rec.Code)
	}
}
