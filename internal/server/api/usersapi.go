// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

// accountsAPI serves user management, sessions, API tokens and two-factor.
type accountsAPI struct {
	*authAPI
	acc *auth.Accounts
}

func (x *accountsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", x.listUsers)
	mux.HandleFunc("POST /api/v1/users", x.createUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", x.updateUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", x.deleteUser)
	mux.HandleFunc("POST /api/v1/users/{id}/reset", x.resetUser)
	mux.HandleFunc("GET /api/v1/settings/security", x.getSecurity)
	mux.HandleFunc("PUT /api/v1/settings/security", x.putSecurity)
	mux.HandleFunc("GET /api/v1/users/{id}/sessions", x.listUserSessions)
	mux.HandleFunc("DELETE /api/v1/users/{id}/sessions/{handle}", x.revokeUserSession)

	mux.HandleFunc("POST /api/v1/me/password", x.changePassword)
	mux.HandleFunc("GET /api/v1/me/security", x.mySecurity)
	mux.HandleFunc("POST /api/v1/me/totp/enrol", x.totpEnrol)
	mux.HandleFunc("POST /api/v1/me/totp/confirm", x.totpConfirm)
	mux.HandleFunc("POST /api/v1/me/totp/disable", x.totpDisable)
	mux.HandleFunc("GET /api/v1/me/sessions", x.listMySessions)
	mux.HandleFunc("DELETE /api/v1/me/sessions/{handle}", x.revokeMySession)
	mux.HandleFunc("GET /api/v1/me/tokens", x.listTokens)
	mux.HandleFunc("POST /api/v1/me/tokens", x.createToken)
	mux.HandleFunc("DELETE /api/v1/me/tokens/{id}", x.revokeToken)

	mux.HandleFunc("POST /api/v1/auth/totp/verify", x.totpVerify)
	mux.HandleFunc("POST /api/v1/auth/totp/enrol", x.totpPendingEnrol)
}

// mutate authorises a state-changing request and checks the CSRF token. With
// sessionOnly it also refuses API tokens: credentials, sessions and
// two-factor can only be managed from a browser session.
func (x *accountsAPI) mutate(w http.ResponseWriter, r *http.Request, action auth.Action, sessionOnly bool) (auth.Principal, *auth.Session, bool) {
	p, sess, ok := x.begin(w, r, action)
	if !ok {
		return p, nil, false
	}
	if sessionOnly && p.Via == "token" {
		x.fail(w, r, errcode.New(errcode.AuthDeny005, "action %s needs a browser session", action))
		return p, nil, false
	}
	if !sameOrigin(r) || !x.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		x.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return p, nil, false
	}
	return p, sess, true
}

type accountJSON struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

func toAccountJSON(a auth.Account) accountJSON {
	return accountJSON{ID: a.ID, Email: a.Email, Name: a.Name, Role: string(a.Role), Disabled: a.Disabled, TOTPEnabled: a.TOTPEnabled, CreatedAt: a.CreatedAt}
}

func (x *accountsAPI) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := x.begin(w, r, auth.ActionUsersRead); !ok {
		return
	}
	list, err := x.acc.ListUsers(r.Context())
	if err != nil {
		x.fail(w, r, err)
		return
	}
	out := make([]accountJSON, 0, len(list))
	for _, a := range list {
		out = append(out, toAccountJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (x *accountsAPI) createUser(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionUsersWrite, false)
	if !ok {
		return
	}
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	a, err := x.acc.CreateUser(r.Context(), p, auth.NewUser{Email: body.Email, Name: body.Name, Password: body.Password, Role: auth.Role(body.Role)}, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAccountJSON(a))
}

func (x *accountsAPI) updateUser(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionUsersWrite, false)
	if !ok {
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	req := auth.UpdateUserRequest{Name: body.Name, Disabled: body.Disabled}
	if body.Role != nil {
		role := auth.Role(*body.Role)
		req.Role = &role
	}
	id := r.PathValue("id")
	if err := x.acc.UpdateUser(r.Context(), p, id, req, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	a, err := x.acc.GetUser(r.Context(), id)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAccountJSON(a))
}

func (x *accountsAPI) deleteUser(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionUsersWrite, false)
	if !ok {
		return
	}
	if err := x.acc.DeleteUser(r.Context(), p, r.PathValue("id"), clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (x *accountsAPI) resetUser(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionUsersWrite, false)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	if err := x.acc.ResetUser(r.Context(), p, r.PathValue("id"), body.Password, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (x *accountsAPI) getSecurity(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := x.begin(w, r, auth.ActionSettingsRead); !ok {
		return
	}
	on, err := x.acc.Require2FA(r.Context())
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"require_2fa": on})
}

func (x *accountsAPI) putSecurity(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionSettingsWrite, false)
	if !ok {
		return
	}
	var body struct {
		Require2FA *bool `json:"require_2fa"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	if body.Require2FA == nil {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "require_2fa", "Send require_2fa as true or false.")
		return
	}
	if err := x.acc.SetRequire2FA(r.Context(), p, *body.Require2FA, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"require_2fa": *body.Require2FA})
}
