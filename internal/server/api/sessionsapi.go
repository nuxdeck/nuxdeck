// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

type sessionInfoJSON struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

func (x *accountsAPI) sessionList(w http.ResponseWriter, r *http.Request, userID, currentHandle string) {
	list, err := x.acc.ListSessions(r.Context(), userID)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	out := make([]sessionInfoJSON, 0, len(list))
	for _, s := range list {
		out = append(out, sessionInfoJSON{ID: s.ID, CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, ExpiresAt: s.ExpiresAt, IP: s.IP, UserAgent: s.UserAgent, Current: s.ID == currentHandle})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (x *accountsAPI) listMySessions(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := x.begin(w, r, auth.ActionSessionsOwn)
	if !ok {
		return
	}
	cur := ""
	if p.Via == "session" {
		cur = auth.SessionHandle(sess.IDHash)
	}
	x.sessionList(w, r, p.UserID, cur)
}

func (x *accountsAPI) revokeMySession(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := x.mutate(w, r, auth.ActionSessionsOwn, true)
	if !ok {
		return
	}
	handle := r.PathValue("handle")
	if err := x.acc.RevokeSession(r.Context(), p, p.UserID, handle, clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	if handle == auth.SessionHandle(sess.IDHash) {
		clearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (x *accountsAPI) listUserSessions(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := x.begin(w, r, auth.ActionSessionsAdmin); !ok {
		return
	}
	x.sessionList(w, r, r.PathValue("id"), "")
}

func (x *accountsAPI) revokeUserSession(w http.ResponseWriter, r *http.Request) {
	p, _, ok := x.mutate(w, r, auth.ActionSessionsAdmin, false)
	if !ok {
		return
	}
	if err := x.acc.RevokeSession(r.Context(), p, r.PathValue("id"), r.PathValue("handle"), clientOf(r)); err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
