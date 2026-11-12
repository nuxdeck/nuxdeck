// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

func (x *accountsAPI) changePassword(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := x.mutate(w, r, auth.ActionSessionsOwn, true)
	if !ok {
		return
	}
	var body struct {
		Current     string `json:"current_password"`
		NewPassword string `json:"new_password"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	if err := x.acc.ChangePassword(r.Context(), p, sess.IDHash, body.Current, body.NewPassword, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (x *accountsAPI) mySecurity(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.begin(w, r, auth.ActionTOTPOwn)
	if !ok {
		return
	}
	enabled, recovery, err := x.acc.TOTPStatus(r.Context(), p.UserID)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	required, err := x.acc.Require2FA(r.Context())
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": enabled, "recovery_codes_left": recovery, "require_2fa": required})
}

func (x *accountsAPI) totpEnrol(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionTOTPOwn, true)
	if !ok {
		return
	}
	enrol, err := x.acc.BeginTOTPEnrolment(r.Context(), p, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": enrol.Secret, "otpauth_uri": enrol.URI})
}

func (x *accountsAPI) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionTOTPOwn, true)
	if !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	codes, err := x.acc.ConfirmTOTP(r.Context(), p, body.Code, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (x *accountsAPI) totpDisable(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionTOTPOwn, true)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	if err := x.acc.DisableTOTP(r.Context(), p, body.Password, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// totpVerify is the second sign-in step. The pending-login ticket is the credential.
func (x *accountsAPI) totpVerify(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := x.begin(w, r, auth.ActionTOTPVerify); !ok {
		return
	}
	if !sameOrigin(r) {
		x.fail(w, r, errcode.New(errcode.AuthDeny004, "cross-site request"))
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	in, recovery, err := x.svc.VerifyTOTP(r.Context(), body.Ticket, body.Code, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	x.respondSignedInCodes(w, http.StatusOK, in, recovery)
}

// totpPendingEnrol starts enrolment for a user the server requires to have two-factor.
func (x *accountsAPI) totpPendingEnrol(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := x.begin(w, r, auth.ActionTOTPVerify); !ok {
		return
	}
	if !sameOrigin(r) {
		x.fail(w, r, errcode.New(errcode.AuthDeny004, "cross-site request"))
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	enrol, err := x.svc.BeginPendingEnrolment(r.Context(), body.Ticket, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": enrol.Secret, "otpauth_uri": enrol.URI})
}
