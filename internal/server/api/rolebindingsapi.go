// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// RoleBindingStore persists role bindings; *store.Store implements it. Writes append their audit
// entry in the same transaction.
type RoleBindingStore interface {
	ListRoleBindings(ctx context.Context) ([]auth.StoredBinding, error)
	CreateRoleBinding(ctx context.Context, b auth.StoredBinding, ev audit.Event) (auth.StoredBinding, error)
	DeleteRoleBinding(ctx context.Context, id string, ev audit.Event) error
}

const maxSubjectLen = 256

type roleBindingsAPI struct {
	*authAPI
	store RoleBindingStore
}

func (a *roleBindingsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/role-bindings", a.list)
	mux.HandleFunc("POST /api/v1/role-bindings", a.create)
	mux.HandleFunc("DELETE /api/v1/role-bindings/{id}", a.remove)
}

type bindingIn struct {
	SubjectType string     `json:"subject_type"`
	Subject     string     `json:"subject"`
	Role        auth.Role  `json:"role"`
	Scope       auth.Scope `json:"scope"`
}

func (a *roleBindingsAPI) list(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionRoleBindingsRead); !ok {
		return
	}
	items, err := a.store.ListRoleBindings(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *roleBindingsAPI) create(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionRoleBindingsWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	var in bindingIn
	if !a.decode(w, r, &in) {
		return
	}
	b := auth.StoredBinding{SubjectType: in.SubjectType, Subject: strings.TrimSpace(in.Subject), Role: in.Role, Scope: in.Scope}
	if field, hint := validateBinding(b); field != "" {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.AuthRBAC003, field, hint)
		return
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "rolebinding.create", TargetType: "role_binding", IP: clientOf(r).IP, Result: audit.ResultSuccess,
		Details: map[string]any{"subject_type": b.SubjectType, "subject": b.Subject, "role": string(b.Role), "scope": b.Scope},
	}
	created, err := a.store.CreateRoleBinding(r.Context(), b, ev)
	if errors.Is(err, auth.ErrNotFound) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.AuthRBAC003, "subject", "No user has this ID.")
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/role-bindings/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (a *roleBindingsAPI) remove(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionRoleBindingsWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.AuthRBAC004)
		return
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "rolebinding.delete", TargetType: "role_binding", TargetID: id, IP: clientOf(r).IP, Result: audit.ResultSuccess,
	}
	switch err := a.store.DeleteRoleBinding(r.Context(), id, ev); {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.AuthRBAC004)
	case errors.Is(err, store.ErrLastAdmin):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.AuthRBAC003, "", "Keep at least one unscoped admin binding, or nobody can manage this server.")
	case err != nil:
		a.fail(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// validateBinding returns the offending field and a hint, or "" when the binding is acceptable.
func validateBinding(b auth.StoredBinding) (field, hint string) {
	if b.SubjectType != auth.SubjectUser && b.SubjectType != auth.SubjectOIDCGroup {
		return "subject_type", "Use user or oidc_group."
	}
	if b.Subject == "" || len(b.Subject) > maxSubjectLen {
		return "subject", "Use a user ID or a group name of up to 256 characters."
	}
	if !auth.ValidRole(b.Role) {
		return "role", "Use admin, operator or viewer."
	}
	if err := b.Scope.Validate(); err != nil {
		return "scope", err.Error()
	}
	return "", ""
}
