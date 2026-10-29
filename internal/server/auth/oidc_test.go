// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

const (
	testClientID = "nux-client"
	testSecret   = "s3cret-value-do-not-leak"
	testPublic   = "https://nux.example.test"
)

// fakeIDP is an in-process OpenID provider: discovery, JWKS and a token endpoint that checks the
// client secret, the redirect URI and the PKCE verifier.
type fakeIDP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	challenge string
	idToken   string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTestJSON(w, map[string]any{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != testClientID || secret != testSecret {
		w.WriteHeader(http.StatusUnauthorized)
		writeTestJSON(w, map[string]any{"error": "invalid_client"})
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	f.mu.Lock()
	challenge, idToken := f.challenge, f.idToken
	f.mu.Unlock()
	if r.PostForm.Get("code") != "code-ok" || r.PostForm.Get("redirect_uri") != testPublic+OIDCCallbackPath ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		w.WriteHeader(http.StatusBadRequest)
		writeTestJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}
	writeTestJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

// sign builds a compact JWS. alg "none" leaves the signature empty; HS256 uses the client secret,
// which is what an attacker holding only that secret could do.
func (f *fakeIDP) sign(alg string, claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	var sig []byte
	switch alg {
	case "RS256":
		digest := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	case "HS256":
		mac := hmac.New(sha256.New, []byte(testSecret))
		mac.Write([]byte(input))
		sig = mac.Sum(nil)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIDP) setChallenge(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenge = c
}

func (f *fakeIDP) setIDToken(t string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idToken = t
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// oidcFakeRepo extends the in-memory repository with OIDC state and group bindings.
type oidcFakeRepo struct {
	*fakeRepo

	mu         sync.Mutex
	provider   *OIDCProvider
	secret     string
	logins     map[string]OIDCLogin
	subjects   map[string]string // issuer|subject -> user ID
	groups     map[string][]string
	groupRoles map[string][]Role
}

func newOIDCFakeRepo() *oidcFakeRepo {
	return &oidcFakeRepo{
		fakeRepo: newFakeRepo(), logins: map[string]OIDCLogin{}, subjects: map[string]string{},
		groups: map[string][]string{}, groupRoles: map[string][]Role{},
	}
}

// Bindings mirrors store.Bindings: direct bindings plus those of the user's groups.
func (f *oidcFakeRepo) Bindings(_ context.Context, id string) ([]Binding, error) {
	f.fakeRepo.mu.Lock()
	var out []Binding
	for _, r := range f.roles[id] {
		out = append(out, Binding{Role: r})
	}
	f.fakeRepo.mu.Unlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.groups[id] {
		for _, r := range f.groupRoles[g] {
			out = append(out, Binding{Role: r})
		}
	}
	return out, nil
}

func (f *oidcFakeRepo) OIDCProvider(context.Context) (OIDCProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.provider == nil {
		return OIDCProvider{}, ErrNotFound
	}
	return *f.provider, nil
}

func (f *oidcFakeRepo) OIDCClientSecret(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.provider == nil {
		return "", ErrNotFound
	}
	return f.secret, nil
}

func (f *oidcFakeRepo) SaveOIDCProvider(_ context.Context, p OIDCProvider, secret string, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if secret != "" {
		f.secret = secret
	}
	if f.secret == "" {
		return errors.New("no secret")
	}
	f.provider = &p
	return f.recordEvent(ev)
}

func (f *oidcFakeRepo) DeleteOIDCProvider(_ context.Context, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.provider == nil {
		return ErrNotFound
	}
	f.provider, f.secret = nil, ""
	return f.recordEvent(ev)
}

func (f *oidcFakeRepo) CreateOIDCLogin(_ context.Context, l OIDCLogin) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins[l.StateHash] = l
	return nil
}

func (f *oidcFakeRepo) TakeOIDCLogin(_ context.Context, stateHash string) (OIDCLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.logins[stateHash]
	if !ok {
		return OIDCLogin{}, ErrNotFound
	}
	delete(f.logins, stateHash)
	return l, nil
}

func (f *oidcFakeRepo) UserByOIDCSubject(_ context.Context, issuer, subject string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.subjects[issuer+"|"+subject]
	if !ok {
		return User{}, ErrNotFound
	}
	return f.userByID(id)
}

func (f *oidcFakeRepo) SignInOIDC(_ context.Context, in OIDCSignIn, ev audit.Event) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := in.Issuer + "|" + in.Subject
	switch in.Mode {
	case OIDCLinkAccount:
		for _, id := range f.subjects {
			if id == in.User.ID {
				return User{}, ErrOIDCLinkConflict
			}
		}
	case OIDCNewAccount:
		f.fakeRepo.mu.Lock()
		_, taken := f.users[in.User.Email]
		if !taken {
			f.users[in.User.Email] = in.User
		}
		f.fakeRepo.mu.Unlock()
		if taken {
			return User{}, ErrOIDCEmailTaken
		}
	}
	f.subjects[key] = in.User.ID
	f.groups[in.User.ID] = in.Groups
	if err := f.recordEvent(ev); err != nil {
		return User{}, err
	}
	return f.userByID(in.User.ID)
}

// recordEvent appends to the audit list; the caller holds f.mu.
func (f *oidcFakeRepo) recordEvent(ev audit.Event) error {
	f.fakeRepo.mu.Lock()
	defer f.fakeRepo.mu.Unlock()
	f.audits = append(f.audits, ev)
	return nil
}

// userByID looks up an account; the caller holds f.mu.
func (f *oidcFakeRepo) userByID(id string) (User, error) {
	f.fakeRepo.mu.Lock()
	defer f.fakeRepo.mu.Unlock()
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// addUser inserts an account directly, optionally already linked to the provider subject.
func (f *oidcFakeRepo) addUser(u User, linkedSubject string) {
	f.fakeRepo.mu.Lock()
	f.users[u.Email] = u
	f.fakeRepo.mu.Unlock()
	if linkedSubject != "" {
		f.mu.Lock()
		f.subjects[testIssuerKey+"|"+linkedSubject] = u.ID
		f.mu.Unlock()
	}
}

var testIssuerKey string

type oidcHarness struct {
	t     *testing.T
	idp   *fakeIDP
	repo  *oidcFakeRepo
	svc   *Service
	oidc  *OIDC
	clock *testClock
	logs  *bytes.Buffer
}

func newOIDCHarness(t *testing.T, p OIDCProvider) *oidcHarness {
	t.Helper()
	idp := newFakeIDP(t)
	testIssuerKey = idp.srv.URL
	repo := newOIDCFakeRepo()
	clock := &testClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc, err := NewService(context.Background(), Config{
		Repo: repo, Hasher: NewHasherWithParams(8, 1, 1), Passwords: NewPasswordPolicy(),
		SetupToken: NewSetupToken(t.TempDir()), Log: log, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	oidc, err := NewOIDC(OIDCConfig{Repo: repo, Service: svc, PublicURL: testPublic, HTTPClient: idp.srv.Client(), Log: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	h := &oidcHarness{t: t, idp: idp, repo: repo, svc: svc, oidc: oidc, clock: clock, logs: logs}
	if p.Issuer == "" {
		p.Issuer = idp.srv.URL
	}
	if p.ClientID == "" {
		p.ClientID = testClientID
	}
	if p.GroupsClaim == "" {
		p.GroupsClaim = "groups"
	}
	if err := oidc.Save(context.Background(), p, testSecret, audit.Event{Action: "settings.oidc_update", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	return h
}

// start runs the redirect step, hands the PKCE challenge to the fake provider and returns the
// state and the nonce the attempt will be checked against.
func (h *oidcHarness) start(redirectTo string) (state, nonce string, location *url.URL) {
	h.t.Helper()
	loc, state, err := h.oidc.Start(context.Background(), redirectTo)
	if err != nil {
		h.t.Fatalf("start: %v", err)
	}
	location, err = url.Parse(loc)
	if err != nil {
		h.t.Fatal(err)
	}
	if location.Query().Get("code_challenge_method") != "S256" || location.Query().Get("state") != state {
		h.t.Fatalf("redirect lacks S256 PKCE or state: %s", loc)
	}
	h.idp.setChallenge(location.Query().Get("code_challenge"))
	h.repo.mu.Lock()
	nonce = h.repo.logins[hashToken(state)].Nonce
	h.repo.mu.Unlock()
	return state, nonce, location
}

func (h *oidcHarness) finish(state, cookie string) (*SignedIn, string, error) {
	return h.oidc.Finish(context.Background(), FinishRequest{State: state, Cookie: cookie, Code: "code-ok"},
		Client{IP: "203.0.113.9", UserAgent: "test"})
}

func (h *oidcHarness) validClaims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": h.idp.srv.URL, "aud": testClientID, "sub": "sub-ada", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"nonce": nonce, "email": "ada@example.com", "email_verified": true, "name": "Ada Lovelace",
		"groups": []string{"engineers"},
	}
}

// attempt signs in with a token built from the valid claims, changed by mutate.
func (h *oidcHarness) attempt(alg string, mutate func(map[string]any)) (*SignedIn, string, error) {
	h.t.Helper()
	state, nonce, _ := h.start("/hosts?x=1")
	claims := h.validClaims(nonce)
	if mutate != nil {
		mutate(claims)
	}
	h.idp.setIDToken(h.idp.sign(alg, claims))
	return h.finish(state, state)
}

func wantCode(t *testing.T, err error, want errcode.Code) {
	t.Helper()
	if got := errcode.CodeOf(err); got != want {
		t.Fatalf("code = %q (err: %v), want %q", got, err, want)
	}
}

func TestOIDCHappyPathProvisionsAndAppliesGroupRole(t *testing.T) { // ACC-3
	h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
	h.repo.groupRoles["engineers"] = []Role{RoleOperator}

	in, dest, err := h.attempt("RS256", nil)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if dest != "/hosts?x=1" || in.Cookie == "" || in.CSRFToken == "" {
		t.Fatalf("dest %q, session %+v", dest, in)
	}
	if len(in.Roles) != 1 || in.Roles[0] != RoleOperator {
		t.Fatalf("roles = %v, want the group's operator role", in.Roles)
	}
	if in.User.PasswordHash != "" {
		t.Error("a JIT account must have no password")
	}
	actions := strings.Join(h.repo.actions(), ",")
	if !strings.Contains(actions, "auth.oidc_login:success") || !strings.Contains(actions, "auth.login:success") {
		t.Errorf("audit = %s, want the SSO and session entries", actions)
	}
}

func TestOIDCRejectsInvalidIDTokens(t *testing.T) { // ACC-3, security
	tests := []struct {
		name   string
		alg    string
		mutate func(map[string]any)
		want   errcode.Code
	}{
		{"bad nonce", "RS256", func(c map[string]any) { c["nonce"] = "someone-else" }, errcode.AuthOIDC004},
		{"wrong audience", "RS256", func(c map[string]any) { c["aud"] = "another-client" }, errcode.AuthOIDC004},
		{"expired", "RS256", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, errcode.AuthOIDC004},
		{"wrong issuer", "RS256", func(c map[string]any) { c["iss"] = "https://evil.example" }, errcode.AuthOIDC004},
		{"alg none", "none", nil, errcode.AuthOIDC004},
		{"HS256 with the client secret", "HS256", nil, errcode.AuthOIDC004},
		{"missing subject", "RS256", func(c map[string]any) { delete(c, "sub") }, errcode.AuthOIDC004},
		{"unverified email", "RS256", func(c map[string]any) { c["email_verified"] = false }, errcode.AuthOIDC005},
		{"unverified email as string", "RS256", func(c map[string]any) { c["email_verified"] = "false" }, errcode.AuthOIDC005},
		{"no email", "RS256", func(c map[string]any) { delete(c, "email") }, errcode.AuthOIDC005},
		{"groups not a list", "RS256", func(c map[string]any) { c["groups"] = 42 }, errcode.AuthOIDC004},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
			_, _, err := h.attempt(tt.alg, tt.mutate)
			wantCode(t, err, tt.want)
			if !strings.Contains(strings.Join(h.repo.actions(), ","), "auth.oidc_failed:failure") {
				t.Error("the refusal was not audited")
			}
			if len(h.repo.subjects) != 0 {
				t.Error("a refused token created an identity")
			}
		})
	}
}

func TestOIDCStateCookieAndLoginAreSingleUse(t *testing.T) { // ACC-3, security
	h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
	h.repo.groupRoles["engineers"] = []Role{RoleViewer}

	state, _, _ := h.start("/")
	if _, _, err := h.finish(state, "a-different-cookie"); errcode.CodeOf(err) != errcode.AuthOIDC002 {
		t.Fatalf("mismatched cookie: %v", err)
	}
	if _, _, err := h.finish("never-issued", "never-issued"); errcode.CodeOf(err) != errcode.AuthOIDC002 {
		t.Fatalf("unknown state: %v", err)
	}

	state, nonce, _ := h.start("/")
	claims := h.validClaims(nonce)
	h.idp.setIDToken(h.idp.sign("RS256", claims))
	if _, _, err := h.finish(state, state); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, _, err := h.finish(state, state); errcode.CodeOf(err) != errcode.AuthOIDC002 {
		t.Fatalf("replayed state: %v", err)
	}

	state, nonce, _ = h.start("/")
	h.idp.setIDToken(h.idp.sign("RS256", h.validClaims(nonce)))
	h.clock.Advance(oidcLoginTTL + time.Second)
	if _, _, err := h.finish(state, state); errcode.CodeOf(err) != errcode.AuthOIDC002 {
		t.Fatalf("expired attempt: %v", err)
	}
}

func TestOIDCAccountRules(t *testing.T) { // ACC-3
	t.Run("no group with a role is denied a session", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
		in, _, err := h.attempt("RS256", func(c map[string]any) { delete(c, "groups") })
		wantCode(t, err, errcode.AuthOIDC008)
		if in != nil {
			t.Fatal("a user without a binding got a session")
		}
	})
	t.Run("disabled account is refused", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
		h.repo.addUser(User{ID: "user-ada", Email: "ada@example.com", Name: "Ada", Disabled: true}, "sub-ada")
		h.repo.groupRoles["engineers"] = []Role{RoleAdmin}
		_, _, err := h.attempt("RS256", nil)
		wantCode(t, err, errcode.AuthOIDC009)
	})
	t.Run("no account and no provisioning is refused", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{})
		_, _, err := h.attempt("RS256", nil)
		wantCode(t, err, errcode.AuthOIDC007)
	})
	t.Run("existing email is linked only when allowed", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{LinkExisting: true})
		h.repo.addUser(User{ID: "user-ada", Email: "ada@example.com", Name: "Ada"}, "")
		h.repo.groupRoles["engineers"] = []Role{RoleViewer}
		in, _, err := h.attempt("RS256", nil)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if in.User.ID != "user-ada" || h.repo.subjects[testIssuerKey+"|sub-ada"] != "user-ada" {
			t.Fatalf("identity not linked to the existing account: %+v", in.User)
		}
	})
	t.Run("existing email is not linked when the setting is off", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
		h.repo.addUser(User{ID: "user-ada", Email: "ada@example.com", Name: "Ada"}, "")
		h.repo.groupRoles["engineers"] = []Role{RoleViewer}
		_, _, err := h.attempt("RS256", nil)
		wantCode(t, err, errcode.AuthOIDC010)
	})
	t.Run("unverified email never links", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{LinkExisting: true})
		h.repo.addUser(User{ID: "user-ada", Email: "ada@example.com", Name: "Ada"}, "")
		_, _, err := h.attempt("RS256", func(c map[string]any) { delete(c, "email_verified") })
		wantCode(t, err, errcode.AuthOIDC005)
	})
	t.Run("domain outside the allowed list is refused", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{AutoProvision: true, AllowedDomains: []string{"example.org"}})
		_, _, err := h.attempt("RS256", nil)
		wantCode(t, err, errcode.AuthOIDC006)
	})
	t.Run("provider group changes reach the next sign-in", func(t *testing.T) {
		h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
		h.repo.groupRoles["engineers"] = []Role{RoleOperator}
		h.repo.groupRoles["auditors"] = []Role{RoleViewer}
		if _, _, err := h.attempt("RS256", nil); err != nil {
			t.Fatal(err)
		}
		in, _, err := h.attempt("RS256", func(c map[string]any) { c["groups"] = []string{"auditors"} })
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Roles) != 1 || in.Roles[0] != RoleViewer {
			t.Fatalf("roles = %v, want only the viewer role from the new group", in.Roles)
		}
	})
}

func TestSafeRedirect(t *testing.T) { // security: open redirect
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "/", true},
		{"/hosts?x=1", "/hosts?x=1", true},
		{"https://evil.example/", "", false},
		{"//evil.example/", "", false},
		{"/\\evil.example", "", false},
		{"/\t/evil.example", "", false},
		{"/a\r\nSet-Cookie:x", "", false},
		{"/%0d%0aSet-Cookie:x", "/%0d%0aSet-Cookie:x", true},
		{"javascript:alert(1)", "", false},
		{"evil.example", "", false},
	}
	for _, tt := range tests {
		got, err := safeRedirect(tt.in)
		if (err == nil) != tt.ok || (tt.ok && got != tt.want) {
			t.Errorf("safeRedirect(%q) = %q, %v; want %q ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestOIDCStartRefusesExternalRedirect(t *testing.T) { // security: open redirect
	h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
	_, _, err := h.oidc.Start(context.Background(), "https://evil.example/")
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "redirect_to" {
		t.Fatalf("start with external redirect = %v, want a redirect_to field error", err)
	}
}

func TestOIDCSecretNeverReachesLogsOrAudit(t *testing.T) { // security: secrets stay secret
	h := newOIDCHarness(t, OIDCProvider{AutoProvision: true})
	h.repo.groupRoles["engineers"] = []Role{RoleOperator}
	_, _, _ = h.attempt("RS256", func(c map[string]any) { c["aud"] = "wrong" })
	if _, _, err := h.attempt("RS256", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.logs.String(), testSecret) {
		t.Fatal("the client secret reached the logs")
	}
	h.repo.fakeRepo.mu.Lock()
	defer h.repo.fakeRepo.mu.Unlock()
	for _, ev := range h.repo.audits {
		for k, v := range ev.Details {
			if strings.Contains(strings.ToLower(k+" "+toString(v)), testSecret) {
				t.Fatalf("the client secret reached the audit entry %q", ev.Action)
			}
		}
	}
}

func toString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestOIDCSaveValidation(t *testing.T) { // ACC-3
	tests := []struct {
		name   string
		public string
		p      OIDCProvider
		secret string
		field  string
		code   errcode.Code
	}{
		{"plain http issuer", testPublic, OIDCProvider{Issuer: "http://idp.example", ClientID: "c"}, "s", "issuer", ""},
		{"link-local issuer", testPublic, OIDCProvider{Issuer: "https://169.254.169.254", ClientID: "c"}, "s", "issuer", ""},
		{"issuer with query", testPublic, OIDCProvider{Issuer: "https://idp.example/?x=1", ClientID: "c"}, "s", "issuer", ""},
		{"empty client id", testPublic, OIDCProvider{Issuer: "https://idp.example", ClientID: " "}, "s", "client_id", ""},
		{"bad groups claim", testPublic, OIDCProvider{Issuer: "https://idp.example", ClientID: "c", GroupsClaim: "a b"}, "s", "groups_claim", ""},
		{"bad domain", testPublic, OIDCProvider{Issuer: "https://idp.example", ClientID: "c", AllowedDomains: []string{"*.example"}}, "s", "allowed_domains", ""},
		{"first save without secret", testPublic, OIDCProvider{Issuer: "https://idp.example", ClientID: "c"}, "", "client_secret", ""},
		{"no public URL", "", OIDCProvider{Issuer: "https://idp.example", ClientID: "c"}, "s", "", errcode.AuthOIDC011},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newOIDCFakeRepo()
			svc, err := NewService(context.Background(), Config{
				Repo: repo, Hasher: NewHasherWithParams(8, 1, 1), Passwords: NewPasswordPolicy(),
				SetupToken: NewSetupToken(t.TempDir()), Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			o, err := NewOIDC(OIDCConfig{Repo: repo, Service: svc, PublicURL: tt.public, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
			if err != nil {
				t.Fatal(err)
			}
			err = o.Save(context.Background(), tt.p, tt.secret, audit.Event{Action: "settings.oidc_update"})
			if tt.code != "" {
				wantCode(t, err, tt.code)
				return
			}
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != tt.field {
				t.Fatalf("err = %v, want a field error on %q", err, tt.field)
			}
		})
	}
}
