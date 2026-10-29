// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

// OIDCStateCookie binds a sign-in attempt to the browser that started it. The __Host- prefix
// forces Secure, Path=/ and no Domain.
const OIDCStateCookie = "__Host-nux_oidc"

// OIDCCallbackPath is the redirect URI registered with the identity provider, relative to the public URL.
const OIDCCallbackPath = "/api/v1/auth/oidc/callback"

const (
	oidcLoginTTL       = 5 * time.Minute
	oidcHTTPTimeout    = 10 * time.Second
	maxOIDCGroups      = 256
	maxGroupLen        = 256
	maxRedirectLen     = 512
	maxOIDCDomains     = 20
	maxOIDCScopes      = 16
	maxClientIDLen     = 256
	maxOIDCSecretLen   = 4096
	defaultGroupsClaim = "groups"
)

// oidcSigningAlgs pins the ID token algorithms. HS256 is excluded on purpose: with a shared
// secret an attacker who knows the client secret could forge tokens. "none" is never allowed.
var oidcSigningAlgs = []string{oidc.RS256, oidc.ES256}

var (
	// ErrOIDCLinkConflict is returned when the account to link already has an identity.
	ErrOIDCLinkConflict = errors.New("account already has an identity")
	// ErrOIDCEmailTaken is returned when a new account would reuse an existing email address.
	ErrOIDCEmailTaken = errors.New("email already in use")

	groupsClaimPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	scopePattern       = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,64}$`)
	domainPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// OIDCProvider is the single identity provider of v0.1. The client secret is not part of it: it
// is written through the repository and never read back into this struct.
type OIDCProvider struct {
	Issuer         string
	ClientID       string
	Scopes         []string
	GroupsClaim    string
	AllowedDomains []string
	// AutoProvision creates an account on first sign-in when no account matches.
	AutoProvision bool
	// LinkExisting attaches the identity to an existing account with the same verified email.
	LinkExisting bool
	UpdatedAt    time.Time
}

// OIDCLogin is a sign-in attempt waiting for its callback. Only the hash of the state is kept.
type OIDCLogin struct {
	StateHash    string
	Nonce        string
	CodeVerifier string
	RedirectTo   string
	ExpiresAt    time.Time
}

// OIDCAccountMode says how a verified identity reached its account.
type OIDCAccountMode string

// The ways a sign-in reaches an account.
const (
	OIDCKnownAccount OIDCAccountMode = "known"
	OIDCLinkAccount  OIDCAccountMode = "link"
	OIDCNewAccount   OIDCAccountMode = "provisioned"
)

// OIDCSignIn is the account a sign-in resolved to, with the groups the provider reported now.
type OIDCSignIn struct {
	User    User
	Mode    OIDCAccountMode
	Issuer  string
	Subject string
	Groups  []string
}

// OIDCRepository is the persistence OIDC sign-in needs. Writes append their audit entry in the
// same transaction; the client secret is sealed by the implementation.
type OIDCRepository interface {
	Bindings(ctx context.Context, userID string) ([]Binding, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	UserByOIDCSubject(ctx context.Context, issuer, subject string) (User, error)
	// OIDCProvider returns ErrNotFound when no provider is configured.
	OIDCProvider(ctx context.Context) (OIDCProvider, error)
	OIDCClientSecret(ctx context.Context) (string, error)
	// SaveOIDCProvider stores p. An empty secret keeps the stored one.
	SaveOIDCProvider(ctx context.Context, p OIDCProvider, secret string, ev audit.Event) error
	// DeleteOIDCProvider returns ErrNotFound when no provider is configured.
	DeleteOIDCProvider(ctx context.Context, ev audit.Event) error
	CreateOIDCLogin(ctx context.Context, l OIDCLogin) error
	// TakeOIDCLogin returns and removes the login, so it can be used once. ErrNotFound if absent.
	TakeOIDCLogin(ctx context.Context, stateHash string) (OIDCLogin, error)
	// SignInOIDC applies the sign-in: it creates or links the account when needed, replaces the
	// account's groups and writes ev, all in one transaction.
	SignInOIDC(ctx context.Context, in OIDCSignIn, ev audit.Event) (User, error)
	RecordAudit(ctx context.Context, ev audit.Event) error
}

// OIDCConfig wires an OIDC service.
type OIDCConfig struct {
	Repo    OIDCRepository
	Service *Service
	// PublicURL is the https base URL users open; the redirect URI is PublicURL + OIDCCallbackPath.
	PublicURL string
	// HTTPClient reaches the provider; nil means a client with a 10 second timeout.
	HTTPClient *http.Client
	Log        *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// OIDC implements single sign-on: provider settings, the sign-in redirect and the callback.
type OIDC struct {
	cfg OIDCConfig

	mu sync.Mutex
	rt *oidcRuntime // built from the stored settings on first use; reset when they change
}

// oidcRuntime holds what a sign-in needs from the provider. It is rebuilt after a settings change.
type oidcRuntime struct {
	provider OIDCProvider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDC validates cfg and returns the service.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	if cfg.Repo == nil || cfg.Service == nil || cfg.Log == nil {
		return nil, errors.New("auth: OIDC needs Repo, Service and Log")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oidcHTTPTimeout}
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	return &OIDC{cfg: cfg}, nil
}

// RedirectURI is the callback URL to register with the provider, or "" without a public URL.
func (o *OIDC) RedirectURI() string {
	if o.cfg.PublicURL == "" {
		return ""
	}
	return o.cfg.PublicURL + OIDCCallbackPath
}

// Enabled reports whether a provider is configured.
func (o *OIDC) Enabled(ctx context.Context) (bool, error) {
	_, err := o.cfg.Repo.OIDCProvider(ctx)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, fmt.Errorf("read sso settings: %w", err)
	}
}

// Provider returns the stored settings, or false when none are configured.
func (o *OIDC) Provider(ctx context.Context) (OIDCProvider, bool, error) {
	p, err := o.cfg.Repo.OIDCProvider(ctx)
	switch {
	case err == nil:
		return p, true, nil
	case errors.Is(err, ErrNotFound):
		return OIDCProvider{}, false, nil
	default:
		return OIDCProvider{}, false, fmt.Errorf("read sso settings: %w", err)
	}
}

// Save validates and stores the provider settings. An empty secret keeps the stored one, and the
// first save needs a secret.
func (o *OIDC) Save(ctx context.Context, p OIDCProvider, secret string, ev audit.Event) error {
	if o.cfg.PublicURL == "" {
		return errcode.New(errcode.AuthOIDC011, "sso needs server.public_url")
	}
	p, err := normalizeProvider(p)
	if err != nil {
		return err
	}
	if secret != "" && len(secret) > maxOIDCSecretLen {
		return &FieldError{Field: "client_secret", Err: errors.New("the client secret is too long")}
	}
	_, configured, err := o.Provider(ctx)
	if err != nil {
		return err
	}
	if secret == "" && !configured {
		return &FieldError{Field: "client_secret", Err: errors.New("enter the client secret")}
	}
	p.UpdatedAt = o.cfg.Now()
	if err := o.cfg.Repo.SaveOIDCProvider(ctx, p, secret, ev); err != nil {
		return fmt.Errorf("save sso settings: %w", err)
	}
	o.reset()
	return nil
}

// Delete removes the provider settings. Accounts already linked keep their identity, but cannot
// sign in through SSO until it is configured again.
func (o *OIDC) Delete(ctx context.Context, ev audit.Event) error {
	err := o.cfg.Repo.DeleteOIDCProvider(ctx, ev)
	if errors.Is(err, ErrNotFound) {
		return errcode.New(errcode.AuthOIDC001, "sso is not configured")
	}
	if err != nil {
		return fmt.Errorf("delete sso settings: %w", err)
	}
	o.reset()
	return nil
}

// Start records a single-use sign-in attempt and returns the provider URL to send the browser to
// and the state to store in OIDCStateCookie. The request uses PKCE (S256) and a nonce.
func (o *OIDC) Start(ctx context.Context, redirectTo string) (location, state string, err error) {
	to, err := safeRedirect(redirectTo)
	if err != nil {
		return "", "", &FieldError{Field: "redirect_to", Err: err}
	}
	rt, err := o.runtime(ctx)
	if err != nil {
		return "", "", err
	}
	if state, err = randomToken(); err != nil {
		return "", "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", "", err
	}
	if err := o.cfg.Repo.CreateOIDCLogin(ctx, OIDCLogin{
		StateHash: hashToken(state), Nonce: nonce, CodeVerifier: verifier, RedirectTo: to,
		ExpiresAt: o.cfg.Now().Add(oidcLoginTTL),
	}); err != nil {
		return "", "", fmt.Errorf("record sign-in attempt: %w", err)
	}
	location = rt.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	return location, state, nil
}

// FinishRequest is the provider's redirect back to the callback.
type FinishRequest struct {
	// State is the state parameter the provider echoed; Cookie is the state cookie the browser sent.
	State         string
	Cookie        string
	Code          string
	ProviderError string
}

// Finish completes a sign-in. On success it returns the session and the path to open. Every
// failure is audited and returned with its AUTH-OIDC code; no detail from the provider is kept.
func (o *OIDC) Finish(ctx context.Context, req FinishRequest, c Client) (*SignedIn, string, error) {
	fail := func(email, reason string, err error) (*SignedIn, string, error) {
		o.recordFailure(ctx, c, email, reason, err)
		return nil, "", err
	}
	if req.State == "" || req.Cookie == "" || !constantEqual(req.State, req.Cookie) {
		return fail("", "state_mismatch", errcode.New(errcode.AuthOIDC002, "state does not match this browser"))
	}
	login, err := o.cfg.Repo.TakeOIDCLogin(ctx, hashToken(req.State))
	if errors.Is(err, ErrNotFound) {
		return fail("", "unknown_state", errcode.New(errcode.AuthOIDC002, "no sign-in attempt for this state"))
	}
	if err != nil {
		return fail("", "internal", fmt.Errorf("read sign-in attempt: %w", err))
	}
	if o.cfg.Now().After(login.ExpiresAt) {
		return fail("", "expired", errcode.New(errcode.AuthOIDC002, "sign-in attempt expired"))
	}
	if req.ProviderError != "" {
		return fail("", "provider_error", errcode.New(errcode.AuthOIDC003, "provider returned an error"))
	}
	if req.Code == "" {
		return fail("", "no_code", errcode.New(errcode.AuthOIDC003, "provider sent no code"))
	}
	rt, err := o.runtime(ctx)
	if err != nil {
		return fail("", "not_configured", err)
	}

	tok, err := rt.oauth.Exchange(o.clientContext(ctx), req.Code, oauth2.VerifierOption(login.CodeVerifier))
	if err != nil {
		return fail("", "token_exchange", errcode.Wrap(errcode.AuthOIDC003, "exchange code", err))
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return fail("", "no_id_token", errcode.New(errcode.AuthOIDC004, "token response has no ID token"))
	}
	idTok, err := rt.verifier.Verify(ctx, rawID)
	if err != nil {
		return fail("", "id_token_invalid", errcode.Wrap(errcode.AuthOIDC004, "verify ID token", err))
	}
	var claims map[string]json.RawMessage
	if err := idTok.Claims(&claims); err != nil {
		return fail("", "claims_malformed", errcode.Wrap(errcode.AuthOIDC004, "decode claims", err))
	}
	var nonce string
	if json.Unmarshal(claims["nonce"], &nonce) != nil || !constantEqual(nonce, login.Nonce) {
		return fail("", "nonce_mismatch", errcode.New(errcode.AuthOIDC004, "nonce does not match"))
	}
	if idTok.Subject == "" {
		return fail("", "no_subject", errcode.New(errcode.AuthOIDC004, "ID token has no subject"))
	}

	var rawEmail string
	_ = json.Unmarshal(claims["email"], &rawEmail)
	email, emailErr := normalizeEmail(rawEmail)
	if emailErr != nil {
		return fail("", "no_email", errcode.New(errcode.AuthOIDC005, "provider sent no usable email"))
	}
	present, verified, verr := emailVerified(claims["email_verified"])
	if verr != nil || (present && !verified) {
		return fail(email, "email_unverified", errcode.New(errcode.AuthOIDC005, "provider reports the email as unverified"))
	}
	groups, gerr := groupsFromClaim(claims[o.groupsClaim(rt)])
	if gerr != nil {
		return fail(email, "groups_malformed", errcode.Wrap(errcode.AuthOIDC004, "read groups", gerr))
	}

	p := rt.provider
	if len(p.AllowedDomains) > 0 && !slices.Contains(p.AllowedDomains, emailDomain(email)) {
		return fail(email, "domain_not_allowed", errcode.New(errcode.AuthOIDC006, "email domain is not allowed"))
	}

	user, mode, err := o.resolveAccount(ctx, rt, claims, rt.provider.Issuer, idTok.Subject, email, verified)
	if err != nil {
		return fail(email, reasonOf(err), err)
	}
	if user.Disabled {
		return fail(email, "disabled", errcode.New(errcode.AuthOIDC009, "account is disabled"))
	}

	signed, err := o.cfg.Repo.SignInOIDC(ctx, OIDCSignIn{
		User: user, Mode: mode, Issuer: rt.provider.Issuer, Subject: idTok.Subject, Groups: groups,
	}, audit.Event{
		ActorType: "user", ActorID: user.ID, Action: "auth.oidc_login", TargetType: "user", TargetID: user.ID,
		IP: c.IP, Result: audit.ResultSuccess, Details: map[string]any{"mode": string(mode), "groups": len(groups)},
	})
	if errors.Is(err, ErrOIDCLinkConflict) || errors.Is(err, ErrOIDCEmailTaken) {
		return fail(email, "identity_conflict", errcode.Wrap(errcode.AuthOIDC010, "apply sign-in", err))
	}
	if err != nil {
		return fail(email, "internal", fmt.Errorf("apply sign-in: %w", err))
	}

	bindings, err := o.cfg.Repo.Bindings(ctx, signed.ID)
	if err != nil {
		return fail(email, "internal", fmt.Errorf("look up role bindings: %w", err))
	}
	if len(bindings) == 0 {
		return fail(email, "no_role", errcode.New(errcode.AuthOIDC008, "no group of this user has a role"))
	}
	in, err := o.cfg.Service.startSession(ctx, signed, c, "oidc")
	if err != nil {
		return fail(email, "internal", err)
	}
	// The destination was checked when the sign-in started; checking it again here keeps an
	// open redirect out of the callback even if the stored value is ever written by another path.
	dest := login.RedirectTo
	if _, err := safeRedirect(dest); err != nil {
		dest = "/"
	}
	return in, dest, nil
}

// resolveAccount finds the account for a verified identity: by subject first, then, when the
// settings allow, by verified email; otherwise a new account when auto-provisioning is on.
func (o *OIDC) resolveAccount(ctx context.Context, rt *oidcRuntime, claims map[string]json.RawMessage, issuer, subject, email string, verified bool) (User, OIDCAccountMode, error) {
	user, err := o.cfg.Repo.UserByOIDCSubject(ctx, issuer, subject)
	if err == nil {
		return user, OIDCKnownAccount, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return User{}, "", fmt.Errorf("look up identity: %w", err)
	}

	existing, err := o.cfg.Repo.UserByEmail(ctx, email)
	switch {
	case err == nil:
		if !rt.provider.LinkExisting {
			return User{}, "", errcode.New(errcode.AuthOIDC010, "email belongs to another account")
		}
		if !verified {
			return User{}, "", errcode.New(errcode.AuthOIDC005, "linking needs a verified email")
		}
		return existing, OIDCLinkAccount, nil
	case !errors.Is(err, ErrNotFound):
		return User{}, "", fmt.Errorf("look up email: %w", err)
	}

	if !rt.provider.AutoProvision {
		return User{}, "", errcode.New(errcode.AuthOIDC007, "no account matches this identity")
	}
	if !verified {
		return User{}, "", errcode.New(errcode.AuthOIDC005, "creating an account needs a verified email")
	}
	id, err := ids.New()
	if err != nil {
		return User{}, "", err
	}
	return User{ID: id, Email: email, Name: displayName(claims, email), CreatedAt: o.cfg.Now()}, OIDCNewAccount, nil
}

// recordFailure audits a rejected sign-in. The audit write is best effort: the caller is refused either way.
func (o *OIDC) recordFailure(ctx context.Context, c Client, email, reason string, err error) {
	details := map[string]any{"reason": reason, "code": string(errcode.CodeOf(err))}
	if email != "" {
		details["email"] = maskEmail(email)
	}
	if werr := o.cfg.Repo.RecordAudit(ctx, audit.Event{
		ActorType: "anonymous", Action: "auth.oidc_failed", IP: c.IP, Result: audit.ResultFailure, Details: details,
	}); werr != nil {
		o.cfg.Log.Error("could not write audit entry", "action", "auth.oidc_failed", "error", werr)
	}
}

func (o *OIDC) groupsClaim(rt *oidcRuntime) string {
	if rt.provider.GroupsClaim == "" {
		return defaultGroupsClaim
	}
	return rt.provider.GroupsClaim
}

// runtime returns the cached provider client, discovering the provider on first use.
func (o *OIDC) runtime(ctx context.Context) (*oidcRuntime, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rt != nil {
		return o.rt, nil
	}
	p, configured, err := o.Provider(ctx)
	if err != nil {
		return nil, err
	}
	if !configured {
		return nil, errcode.New(errcode.AuthOIDC001, "sso is not configured")
	}
	if o.cfg.PublicURL == "" {
		return nil, errcode.New(errcode.AuthOIDC011, "sso needs server.public_url")
	}
	secret, err := o.cfg.Repo.OIDCClientSecret(ctx)
	if err != nil {
		return nil, fmt.Errorf("read client secret: %w", err)
	}
	// The provider keeps its context for key refreshes, which must outlive this request.
	provider, err := oidc.NewProvider(o.clientContext(context.WithoutCancel(ctx)), p.Issuer)
	if err != nil {
		return nil, errcode.Wrap(errcode.AuthOIDC003, "discover identity provider", err)
	}
	rt := &oidcRuntime{
		provider: p,
		oauth: oauth2.Config{
			ClientID: p.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(),
			RedirectURL: o.RedirectURI(), Scopes: p.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: oidcSigningAlgs}),
	}
	o.rt = rt
	return rt, nil
}

// clientContext makes provider requests use the configured HTTP client.
func (o *OIDC) clientContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, o.cfg.HTTPClient)
}

func (o *OIDC) reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rt = nil
}

func normalizeProvider(p OIDCProvider) (OIDCProvider, error) {
	issuer, err := url.Parse(strings.TrimSpace(p.Issuer))
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return p, &FieldError{Field: "issuer", Err: errors.New("use the https issuer URL of the provider, without query or fragment")}
	}
	if ip := net.ParseIP(issuer.Hostname()); ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return p, &FieldError{Field: "issuer", Err: errors.New("link-local addresses are not allowed")}
	}
	p.Issuer = issuer.String()

	p.ClientID = strings.TrimSpace(p.ClientID)
	if p.ClientID == "" || utf8.RuneCountInString(p.ClientID) > maxClientIDLen || strings.ContainsFunc(p.ClientID, unicode.IsSpace) {
		return p, &FieldError{Field: "client_id", Err: errors.New("enter the client ID")}
	}

	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if len(p.Scopes) > maxOIDCScopes {
		return p, &FieldError{Field: "scopes", Err: fmt.Errorf("use at most %d scopes", maxOIDCScopes)}
	}
	for _, s := range p.Scopes {
		if !scopePattern.MatchString(s) {
			return p, &FieldError{Field: "scopes", Err: errors.New("scopes may contain letters, digits and . _ : / -")}
		}
	}
	if !slices.Contains(p.Scopes, oidc.ScopeOpenID) {
		p.Scopes = append([]string{oidc.ScopeOpenID}, p.Scopes...)
	}

	p.GroupsClaim = strings.TrimSpace(p.GroupsClaim)
	if p.GroupsClaim == "" {
		p.GroupsClaim = defaultGroupsClaim
	}
	if !groupsClaimPattern.MatchString(p.GroupsClaim) {
		return p, &FieldError{Field: "groups_claim", Err: errors.New("use a claim name of letters, digits and . _ : -")}
	}

	if len(p.AllowedDomains) > maxOIDCDomains {
		return p, &FieldError{Field: "allowed_domains", Err: fmt.Errorf("use at most %d domains", maxOIDCDomains)}
	}
	domains := make([]string, 0, len(p.AllowedDomains))
	for _, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !domainPattern.MatchString(d) {
			return p, &FieldError{Field: "allowed_domains", Err: errors.New("use bare domain names such as example.com")}
		}
		if !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	p.AllowedDomains = domains
	return p, nil
}

// safeRedirect accepts only a path on this server. A value that could become another host once a
// browser or proxy normalises it (//host, backslashes, control characters, a scheme) is refused.
func safeRedirect(s string) (string, error) {
	if s == "" {
		return "/", nil
	}
	if len(s) > maxRedirectLen || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsRune(s, '\\') {
		return "", errors.New("use a path that starts with a single /")
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", errors.New("the path contains spaces or control characters")
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "", errors.New("use a path on this server")
	}
	return s, nil
}

// emailVerified reads the email_verified claim. Some providers send it as a string.
func emailVerified(raw json.RawMessage) (present, verified bool, err error) {
	if len(raw) == 0 {
		return false, false, nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return true, b, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && (s == "true" || s == "false") {
		return true, s == "true", nil
	}
	return true, false, errors.New("email_verified is not a boolean")
}

// groupsFromClaim accepts a list of names or a single name. An absent claim means no groups.
func groupsFromClaim(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var one string
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, errors.New("groups claim is neither a list nor a string")
		}
		list = []string{one}
	}
	out := make([]string, 0, len(list))
	for _, g := range list {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > maxGroupLen {
			return nil, errors.New("a group name is too long")
		}
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	if len(out) > maxOIDCGroups {
		return nil, fmt.Errorf("more than %d groups", maxOIDCGroups)
	}
	return out, nil
}

// displayName uses the name claim when it is valid, else the part of the email before @.
func displayName(claims map[string]json.RawMessage, email string) string {
	var name string
	_ = json.Unmarshal(claims["name"], &name)
	if n, err := normalizeName(name); err == nil {
		return n
	}
	local, _, _ := strings.Cut(email, "@")
	if n, err := normalizeName(local); err == nil {
		return n
	}
	return "user"
}

func emailDomain(email string) string {
	_, domain, _ := strings.Cut(email, "@")
	return domain
}

func reasonOf(err error) string {
	switch errcode.CodeOf(err) {
	case errcode.AuthOIDC005:
		return "email_unverified"
	case errcode.AuthOIDC007:
		return "no_account"
	case errcode.AuthOIDC010:
		return "identity_conflict"
	default:
		return "internal"
	}
}

func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
