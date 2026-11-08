// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

// oidcStateTTL matches the server-side sign-in lifetime: a cookie outliving it is useless.
const oidcStateTTL = 5 * time.Minute

type oidcAPI struct {
	*authAPI
	oidc *auth.OIDC
}

func (a *oidcAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/oidc/status", a.status)
	mux.HandleFunc("GET /api/v1/auth/oidc/start", a.start)
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", a.callback)
	mux.HandleFunc("GET /api/v1/settings/oidc", a.get)
	mux.HandleFunc("PUT /api/v1/settings/oidc", a.put)
	mux.HandleFunc("DELETE /api/v1/settings/oidc", a.remove)
}

// status tells the sign-in page whether to offer single sign-on.
func (a *oidcAPI) status(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionOIDCLogin); !ok {
		return
	}
	on, err := a.oidc.Enabled(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": on})
}

// start redirects the browser to the provider. The state cookie ties the callback to this browser.
func (a *oidcAPI) start(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionOIDCLogin); !ok {
		return
	}
	location, state, err := a.oidc.Start(r.Context(), r.URL.Query().Get("redirect_to"))
	if err != nil {
		a.failOIDC(w, r, err)
		return
	}
	http.SetCookie(w, oidcStateCookie(state, int(oidcStateTTL.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	// G710 is a taint false positive: location is the provider's authorize URL, built by oauth2 from the
	// discovered endpoint and our own state, nonce and PKCE values. redirect_to never reaches it; it is
	// validated by safeRedirect and stored server-side for the callback.
	http.Redirect(w, r, location, http.StatusFound) //nolint:gosec // G710: see the comment above
}

// callback finishes the sign-in. Failures go back to the sign-in page with the AUTH-OIDC code, so
// the page can say what went wrong; the provider's own error text is never shown.
func (a *oidcAPI) callback(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionOIDCLogin); !ok {
		return
	}
	var cookie string
	if c, err := r.Cookie(auth.OIDCStateCookie); err == nil {
		cookie = c.Value
	}
	http.SetCookie(w, oidcStateCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")

	q := r.URL.Query()
	in, dest, err := a.oidc.Finish(r.Context(), auth.FinishRequest{
		State: q.Get("state"), Cookie: cookie, Code: q.Get("code"), ProviderError: q.Get("error"),
	}, clientOf(r))
	if err != nil {
		code := errcode.CodeOf(err)
		if code == "" {
			code = errcode.APIInt001
		}
		http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(string(code)), http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: in.Cookie, Path: "/", Expires: in.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, dest, http.StatusFound)
}

// oidcSettingsJSON never carries the client secret, only whether one is stored.
type oidcSettingsJSON struct {
	Configured      bool     `json:"configured"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecretSet bool     `json:"client_secret_set"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groups_claim"`
	AllowedDomains  []string `json:"allowed_domains"`
	AutoProvision   bool     `json:"auto_provision"`
	LinkExisting    bool     `json:"link_existing"`
	RedirectURI     string   `json:"redirect_uri"`
}

func (a *oidcAPI) settingsJSON(p auth.OIDCProvider, configured bool) oidcSettingsJSON {
	out := oidcSettingsJSON{Configured: configured, RedirectURI: a.oidc.RedirectURI(), Scopes: []string{}, AllowedDomains: []string{}}
	if !configured {
		return out
	}
	out.Issuer, out.ClientID, out.ClientSecretSet = p.Issuer, p.ClientID, true
	out.Scopes, out.GroupsClaim, out.AllowedDomains = p.Scopes, p.GroupsClaim, p.AllowedDomains
	out.AutoProvision, out.LinkExisting = p.AutoProvision, p.LinkExisting
	return out
}

func (a *oidcAPI) get(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionSettingsRead); !ok {
		return
	}
	p, configured, err := a.oidc.Provider(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.settingsJSON(p, configured))
}

func (a *oidcAPI) put(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionSettingsWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	var body struct {
		Issuer         string   `json:"issuer"`
		ClientID       string   `json:"client_id"`
		ClientSecret   string   `json:"client_secret"`
		Scopes         []string `json:"scopes"`
		GroupsClaim    string   `json:"groups_claim"`
		AllowedDomains []string `json:"allowed_domains"`
		AutoProvision  bool     `json:"auto_provision"`
		LinkExisting   bool     `json:"link_existing"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	settings := auth.OIDCProvider{
		Issuer: body.Issuer, ClientID: body.ClientID, Scopes: body.Scopes, GroupsClaim: body.GroupsClaim,
		AllowedDomains: body.AllowedDomains, AutoProvision: body.AutoProvision, LinkExisting: body.LinkExisting,
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "settings.oidc_update", TargetType: "setting", TargetID: "oidc",
		IP: clientOf(r).IP, Result: audit.ResultSuccess,
		Details: map[string]any{
			"issuer": body.Issuer, "client_id": body.ClientID, "client_secret_changed": body.ClientSecret != "",
			"groups_claim": body.GroupsClaim, "auto_provision": body.AutoProvision, "link_existing": body.LinkExisting,
		},
	}
	if err := a.oidc.Save(r.Context(), settings, body.ClientSecret, ev); err != nil {
		a.failOIDC(w, r, err)
		return
	}
	saved, configured, err := a.oidc.Provider(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.settingsJSON(saved, configured))
}

func (a *oidcAPI) remove(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionSettingsWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "settings.oidc_delete", TargetType: "setting", TargetID: "oidc",
		IP: clientOf(r).IP, Result: audit.ResultSuccess,
	}
	if err := a.oidc.Delete(r.Context(), ev); err != nil {
		a.failOIDC(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// failOIDC maps the SSO codes to statuses and leaves everything else to the shared mapping.
func (a *oidcAPI) failOIDC(w http.ResponseWriter, r *http.Request, err error) {
	switch code := errcode.CodeOf(err); code {
	case errcode.AuthOIDC001:
		writeError(w, http.StatusNotFound, code)
	case errcode.AuthOIDC002, errcode.AuthOIDC004:
		writeError(w, http.StatusUnauthorized, code)
	case errcode.AuthOIDC003:
		writeError(w, http.StatusBadGateway, code)
	case errcode.AuthOIDC005, errcode.AuthOIDC006, errcode.AuthOIDC007, errcode.AuthOIDC008, errcode.AuthOIDC009:
		writeError(w, http.StatusForbidden, code)
	case errcode.AuthOIDC010:
		writeError(w, http.StatusConflict, code)
	case errcode.AuthOIDC011:
		writeError(w, http.StatusServiceUnavailable, code)
	default:
		a.fail(w, r, err)
	}
}

func oidcStateCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: auth.OIDCStateCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}
