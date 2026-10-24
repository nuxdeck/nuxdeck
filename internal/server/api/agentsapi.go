// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
)

type agentsAPI struct {
	*authAPI
	pki        *pki.Service
	gatewayURL string
}

func (a *agentsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agents/tokens", a.createToken)
}

func (a *agentsAPI) createToken(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionAgentTokenCreate)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	var body struct {
		TTLSeconds int               `json:"ttl_seconds"`
		Labels     map[string]string `json:"labels"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	if body.TTLSeconds < 0 || body.TTLSeconds > int(pki.MaxTokenTTL.Seconds()) {
		a.fail(w, r, &pki.FieldError{Field: "ttl_seconds", Msg: "must be between 0 and 86400"})
		return
	}
	created, err := a.pki.CreateToken(r.Context(), pki.Actor{UserID: p.UserID, IP: clientOf(r).IP}, pki.TokenRequest{
		ServerURL: a.gatewayURL,
		TTL:       time.Duration(body.TTLSeconds) * time.Second,
		Labels:    body.Labels,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// The only time the token is visible; writeJSON already sets Cache-Control: no-store.
	writeJSON(w, http.StatusCreated, map[string]any{"id": created.ID, "token": created.Token, "expires_at": created.ExpiresAt.UTC().Format(time.RFC3339)})
}
