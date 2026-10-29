// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

type tokenJSON struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Bindings   []auth.Binding `json:"bindings"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	LastUsedAt *time.Time     `json:"last_used_at"`
}

func toTokenJSON(t auth.APIToken) tokenJSON {
	j := tokenJSON{ID: t.ID, Name: t.Name, Bindings: t.Scope, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt}
	if j.Bindings == nil {
		j.Bindings = []auth.Binding{}
	}
	if !t.LastUsedAt.IsZero() {
		used := t.LastUsedAt
		j.LastUsedAt = &used
	}
	return j
}

func (x *accountsAPI) listTokens(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.begin(w, r, auth.ActionTokensOwn)
	if !ok {
		return
	}
	list, err := x.acc.ListTokens(r.Context(), p.UserID)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	out := make([]tokenJSON, 0, len(list))
	for _, t := range list {
		out = append(out, toTokenJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// createToken shows the token once; only its hash is kept.
func (x *accountsAPI) createToken(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionTokensOwn, true)
	if !ok {
		return
	}
	var body struct {
		Name          string         `json:"name"`
		ExpiresInDays int            `json:"expires_in_days"`
		Bindings      []auth.Binding `json:"bindings"`
	}
	if !x.decode(w, r, &body) {
		return
	}
	plain, t, err := x.acc.CreateToken(r.Context(), p, body.Name, body.Bindings, time.Duration(body.ExpiresInDays)*24*time.Hour, clientOf(r))
	if err != nil {
		x.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "details": toTokenJSON(t)})
}

func (x *accountsAPI) revokeToken(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionTokensOwn, true)
	if !ok {
		return
	}
	if err := x.acc.RevokeToken(r.Context(), p, r.PathValue("id"), clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
