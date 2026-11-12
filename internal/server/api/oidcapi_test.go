// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

const oidcAPISecret = "api-secret-value-do-not-leak"

type oidcAPIEnv struct {
	t     *testing.T
	h     http.Handler
	idp   *httptest.Server
	admin actor
}

// newOIDCAPIEnv runs nuxd's stack with a real store and an identity provider that serves discovery only.
func newOIDCAPIEnv(t *testing.T) *oidcAPIEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(context.Background(), dir, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	db.UseSecrets(box)
	db.Groups = db.OIDCGroupsOf

	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": "https://" + r.Host, "authorization_endpoint": "https://" + r.Host + "/authorize",
			"token_endpoint": "https://" + r.Host + "/token", "jwks_uri": "https://" + r.Host + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"},
		})
	}))
	t.Cleanup(idp.Close)

	hasher, pol := auth.NewHasherWithParams(8, 1, 1), auth.NewPasswordPolicy()
	acc, err := auth.NewAccounts(auth.AccountsConfig{Repo: db, Hasher: hasher, Passwords: pol, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token := auth.NewSetupToken(dir)
	if err := token.Ensure(); err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(context.Background(), auth.Config{Repo: db, Hasher: hasher, Passwords: pol, SetupToken: token, Log: log, Accounts: acc})
	if err != nil {
		t.Fatal(err)
	}
	oidc, err := auth.NewOIDC(auth.OIDCConfig{Repo: db, Service: svc, PublicURL: "https://nux.example.test", HTTPClient: idp.Client(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	e := &oidcAPIEnv{t: t, idp: idp, h: Handler(Options{Log: log, Ready: db, UI: uiFS(), Auth: svc, Accounts: acc, OIDC: oidc})}

	tok, _ := token.Read()
	rec := e.call(acall{method: "POST", path: "/api/v1/setup/admin", body: map[string]string{"token": tok, "name": "Ada", "email": adminEmail, "password": goodPassword}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup = %d %s", rec.Code, rec.Body)
	}
	var in struct {
		CSRFToken string `json:"csrf_token"`
	}
	decodeInto(t, rec, &in)
	e.admin = actor{cookie: sessionCookieOf(t, rec), csrf: in.CSRFToken}
	return e
}

func (e *oidcAPIEnv) call(c acall) *httptest.ResponseRecorder {
	e.t.Helper()
	var body io.Reader
	if c.body != nil {
		b, _ := json.Marshal(c.body)
		body = strings.NewReader(string(b))
	}
	r := httptest.NewRequest(c.method, c.path, body)
	r.RemoteAddr = "203.0.113.5:4711"
	if c.body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set(csrfHeader, c.csrf)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func TestOIDCSettingsSecretIsWriteOnly(t *testing.T) { // ACC-3, security
	e := newOIDCAPIEnv(t)
	put := map[string]any{
		"issuer": e.idp.URL, "client_id": "nux", "client_secret": oidcAPISecret,
		"allowed_domains": []string{"example.com"}, "groups_claim": "groups", "auto_provision": true,
	}

	if rec := e.call(acall{method: "GET", path: "/api/v1/settings/oidc"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous read = %d, want 401", rec.Code)
	}
	if rec := e.call(acall{method: "PUT", path: "/api/v1/settings/oidc", body: put, cookie: e.admin.cookie}); rec.Code != http.StatusForbidden {
		t.Fatalf("PUT without CSRF = %d, want 403", rec.Code)
	}

	rec := e.call(acall{method: "PUT", path: "/api/v1/settings/oidc", body: put, cookie: e.admin.cookie, csrf: e.admin.csrf})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), oidcAPISecret) {
		t.Fatal("the PUT response carries the client secret")
	}
	if !strings.Contains(rec.Body.String(), `"redirect_uri":"https://nux.example.test/api/v1/auth/oidc/callback"`) {
		t.Errorf("redirect URI not shown to the administrator: %s", rec.Body)
	}

	got := e.call(acall{method: "GET", path: "/api/v1/settings/oidc", cookie: e.admin.cookie})
	if got.Code != http.StatusOK || strings.Contains(got.Body.String(), oidcAPISecret) || !strings.Contains(got.Body.String(), `"client_secret_set":true`) {
		t.Fatalf("GET = %d %s; want the settings without the secret", got.Code, got.Body)
	}

	if rec := e.call(acall{method: "PUT", path: "/api/v1/settings/oidc", body: map[string]any{"issuer": e.idp.URL, "client_id": "nux", "secret": "x"}, cookie: e.admin.cookie, csrf: e.admin.csrf}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", rec.Code)
	}

	if rec := e.call(acall{method: "DELETE", path: "/api/v1/settings/oidc", cookie: e.admin.cookie, csrf: e.admin.csrf}); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if rec := e.call(acall{method: "GET", path: "/api/v1/settings/oidc", cookie: e.admin.cookie}); !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Fatalf("after delete: %s", rec.Body)
	}
}

func TestOIDCStartRedirectsWithPKCEAndRefusesExternalTargets(t *testing.T) { // ACC-3, security
	e := newOIDCAPIEnv(t)
	if rec := e.call(acall{method: "GET", path: "/api/v1/auth/oidc/start"}); rec.Code != http.StatusNotFound {
		t.Fatalf("start before setup = %d, want 404", rec.Code)
	}
	rec := e.call(acall{method: "PUT", path: "/api/v1/settings/oidc", cookie: e.admin.cookie, csrf: e.admin.csrf, body: map[string]any{
		"issuer": e.idp.URL, "client_id": "nux", "client_secret": oidcAPISecret, "auto_provision": true,
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}

	if rec := e.call(acall{method: "GET", path: "/api/v1/auth/oidc/status"}); !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("status = %s", rec.Body)
	}
	for _, target := range []string{"https://evil.example/", "//evil.example", "/\\evil.example"} {
		rec := e.call(acall{method: "GET", path: "/api/v1/auth/oidc/start?redirect_to=" + url.QueryEscape(target)})
		if rec.Code == http.StatusFound || rec.Header().Get("Location") != "" {
			t.Errorf("redirect_to %q was followed: %d %s", target, rec.Code, rec.Header().Get("Location"))
		}
	}

	rec = e.call(acall{method: "GET", path: "/api/v1/auth/oidc/start?redirect_to=/hosts"})
	if rec.Code != http.StatusFound {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host != strings.TrimPrefix(e.idp.URL, "https://") || loc.Path != "/authorize" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("code_challenge") == "" || loc.Query().Get("nonce") == "" {
		t.Errorf("authorisation request lacks PKCE or nonce: %s", loc.RawQuery)
	}
	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.OIDCStateCookie {
			state = c
		}
	}
	if state == nil || !state.HttpOnly || !state.Secure || state.SameSite != http.SameSiteLaxMode || state.Path != "/" || state.Value != loc.Query().Get("state") {
		t.Fatalf("state cookie = %+v; want HttpOnly, Secure, SameSite=Lax and the state value", state)
	}
}

func TestOIDCCallbackWithoutStateGoesBackToSignIn(t *testing.T) { // ACC-3, security
	e := newOIDCAPIEnv(t)
	rec := e.call(acall{method: "GET", path: "/api/v1/auth/oidc/callback?state=forged&code=abc"})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login?sso_error=AUTH-OIDC-002" {
		t.Fatalf("callback = %d %q, want a redirect to the sign-in page with the code", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Fatal("a failed callback set a session cookie")
		}
	}
}
