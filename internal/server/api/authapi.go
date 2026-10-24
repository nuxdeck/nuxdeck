// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
)

const (
	// The __Host- prefix makes browsers insist on Secure, Path=/ and no Domain.
	sessionCookie = "__Host-nux_session"
	csrfHeader    = "X-CSRF-Token"
	maxBodyBytes  = 8 << 10
)

type authAPI struct {
	svc *auth.Service
	log *slog.Logger
}

func (a *authAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/setup/status", a.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/admin", a.setupAdmin)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.me)
}

type userJSON struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type sessionJSON struct {
	User      userJSON `json:"user"`
	CSRFToken string   `json:"csrf_token"`
}

func roleStrings(roles []auth.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

// begin identifies the caller from the session cookie and asks the policy for a
// decision. Nothing else runs until it returns true.
func (a *authAPI) begin(w http.ResponseWriter, r *http.Request, action auth.Action) (auth.Principal, *auth.Session, bool) {
	var p auth.Principal
	var sess *auth.Session
	if c, err := r.Cookie(sessionCookie); err == nil {
		var aerr error
		if p, sess, aerr = a.svc.Authenticate(r.Context(), c.Value); aerr != nil {
			a.fail(w, r, aerr)
			return p, nil, false
		}
	}
	if err := auth.Authorize(p, action); err != nil {
		a.fail(w, r, err)
		return p, nil, false
	}
	return p, sess, true
}

func (a *authAPI) setupStatus(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionSetupStatus); !ok {
		return
	}
	required, err := a.svc.SetupRequired(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"setup_required": required})
}

func (a *authAPI) setupAdmin(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionSetupComplete); !ok {
		return
	}
	if !sameOrigin(r) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "cross-site request"))
		return
	}
	var body struct {
		Token    string `json:"token"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	in, err := a.svc.CompleteSetup(r.Context(), auth.SetupRequest{Token: body.Token, Name: body.Name, Email: body.Email, Password: body.Password}, clientOf(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondSignedIn(w, http.StatusCreated, in)
}

func (a *authAPI) login(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionLogin); !ok {
		return
	}
	if !sameOrigin(r) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "cross-site request"))
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	in, err := a.svc.Login(r.Context(), body.Email, body.Password, clientOf(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondSignedIn(w, http.StatusOK, in)
}

func (a *authAPI) logout(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.begin(w, r, auth.ActionLogout)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	if err := a.svc.Logout(r.Context(), *sess, clientOf(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	clearSessionCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *authAPI) me(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionMeRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON{
		User:      userJSON{ID: p.UserID, Email: p.Email, Name: p.Name, Roles: roleStrings(p.Roles)},
		CSRFToken: sess.CSRFToken,
	})
}

func (a *authAPI) respondSignedIn(w http.ResponseWriter, status int, in *auth.SignedIn) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: in.Cookie, Path: "/", Expires: in.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, status, sessionJSON{
		User:      userJSON{ID: in.User.ID, Email: in.User.Email, Name: in.User.Name, Roles: roleStrings(in.Roles)},
		CSRFToken: in.CSRFToken,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// decode reads one strict JSON object: right content type, bounded size, no
// unknown fields, nothing after the value.
func (a *authAPI) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeErrorDetail(w, http.StatusUnsupportedMediaType, errcode.APIVal001, "", "Send Content-Type: application/json.")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	err = dec.Decode(dst)
	if err == nil {
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = errors.New("unexpected data after the JSON value")
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErrorDetail(w, http.StatusRequestEntityTooLarge, errcode.APIVal001, "", "The request body is too large.")
			return false
		}
		writeError(w, http.StatusBadRequest, errcode.APIVal001)
		return false
	}
	return true
}

// fail maps an error to a status and the shared error shape. Unexpected errors
// are logged with the request ID and shown to the client without detail.
func (a *authAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var fe *auth.FieldError
	field := ""
	hint := ""
	if errors.As(err, &fe) {
		field = fe.Field
		hint = fe.Err.Error()
		var inner *errcode.Error
		if errors.As(fe.Err, &inner) {
			hint = inner.Err.Error()
		}
	}

	var pe *pki.FieldError
	if errors.As(err, &pe) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, pe.Field, pe.Msg)
		return
	}

	code := errcode.CodeOf(err)
	if fe != nil && code == "" {
		code = errcode.APIVal001
	}
	switch code {
	case errcode.AuthDeny001, errcode.AuthDeny003:
		writeErrorDetail(w, http.StatusUnauthorized, code, field, hint)
	case errcode.AuthDeny002:
		w.Header().Set("Retry-After", strconv.Itoa(300))
		writeErrorDetail(w, http.StatusTooManyRequests, code, field, hint)
	case errcode.AuthDeny004, errcode.AuthDeny005, errcode.AuthSetup001:
		writeErrorDetail(w, http.StatusForbidden, code, field, hint)
	case errcode.AuthSetup002:
		writeErrorDetail(w, http.StatusConflict, code, field, hint)
	case errcode.AuthPwd001:
		writeErrorDetail(w, http.StatusUnprocessableEntity, code, field, hint)
	case errcode.APIVal001:
		writeErrorDetail(w, http.StatusUnprocessableEntity, code, field, hint)
	default:
		a.log.Error("request failed", "request_id", requestID(r.Context()), "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, errcode.APIInt001)
	}
}

func clientOf(r *http.Request) auth.Client {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return auth.Client{IP: ip, UserAgent: r.UserAgent()}
}

// sameOrigin is a second line of defence behind SameSite=Strict: browsers tell
// us when a request comes from another site or origin. Clients that send
// neither header (curl, the CLI) are not browsers and carry no ambient cookies.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}
