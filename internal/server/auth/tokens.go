// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

const (
	// TokenPrefix marks an API token so scanners and humans can recognise it.
	TokenPrefix       = "nuxt_" //nolint:gosec // a prefix, not a credential
	tokenRandomBytes  = 32
	maxTokenTTL       = 365 * 24 * time.Hour
	maxTokensPerUser  = 50
	tokenTouchEvery   = time.Minute
	maxTokenNameRunes = 100
)

// NewAPIToken returns a token to show once, and the SHA-256 to store.
func NewAPIToken() (plain, hash string, err error) {
	b := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate API token: %w", err)
	}
	plain = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, hashToken(plain), nil
}

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// scopeCovers reports whether everything inside inner is also inside outer.
func scopeCovers(outer, inner Scope) bool {
	if outer.IsZero() {
		return true
	}
	if inner.IsZero() {
		return false
	}
	for _, env := range inner.Environments {
		if !slices.Contains(outer.Environments, env) {
			return false
		}
	}
	// A tag set is an AND, so a set holding all of an outer set's tags is narrower than it.
	for _, in := range inner.TagSets {
		ok := false
		for _, out := range outer.TagSets {
			if len(out) > 0 && containsAll(in, out) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// bindingCovered reports whether the owner holds a binding at least as strong and wide as b.
func bindingCovered(owner []Binding, b Binding) bool {
	return slices.ContainsFunc(owner, func(o Binding) bool {
		return roleRank(o.Role) >= roleRank(b.Role) && roleRank(b.Role) > 0 && scopeCovers(o.Scope, b.Scope)
	})
}

// ScopeIsSubset reports whether every requested binding is covered by the owner's bindings.
func ScopeIsSubset(owner, requested []Binding) bool {
	if len(requested) == 0 {
		return false
	}
	for _, b := range requested {
		if !bindingCovered(owner, b) {
			return false
		}
	}
	return true
}

// intersectBindings keeps the token bindings the owner still holds. A binding the
// owner lost or was narrowed below is dropped, never downgraded: fail closed.
func intersectBindings(owner, token []Binding) []Binding {
	var out []Binding
	for _, b := range token {
		if bindingCovered(owner, b) {
			out = append(out, b)
		}
	}
	return out
}

func rolesOf(bs []Binding) []Role {
	var roles []Role
	for _, b := range bs {
		if !slices.Contains(roles, b.Role) {
			roles = append(roles, b.Role)
		}
	}
	return roles
}

// CreateToken mints a token for the signed-in user. scope must be covered by the user's own bindings.
func (a *Accounts) CreateToken(ctx context.Context, p Principal, name string, scope []Binding, ttl time.Duration, c Client) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxTokenNameRunes {
		return "", APIToken{}, &FieldError{Field: "name", Err: fmt.Errorf("enter a name of 1 to %d characters", maxTokenNameRunes)}
	}
	if ttl <= 0 || ttl > maxTokenTTL {
		return "", APIToken{}, &FieldError{Field: "expires_in_days", Err: errors.New("choose a lifetime of 1 to 365 days")}
	}
	for _, b := range scope {
		if roleRank(b.Role) == 0 {
			return "", APIToken{}, &FieldError{Field: "scope", Err: errors.New("unknown role")}
		}
	}
	owner, err := a.repo.UserBindings(ctx, p.UserID)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("look up bindings: %w", err)
	}
	if !ScopeIsSubset(owner, scope) {
		a.auditFailure(ctx, p, c, "tokens.create_denied", "scope_exceeds_owner")
		return "", APIToken{}, errcode.New(errcode.AuthToken002, "token scope is wider than its owner's")
	}
	existing, err := a.repo.ListTokens(ctx, p.UserID)
	if err != nil {
		return "", APIToken{}, err
	}
	if len(existing) >= maxTokensPerUser {
		return "", APIToken{}, &FieldError{Field: "name", Err: fmt.Errorf("at most %d tokens per user; revoke one first", maxTokensPerUser)}
	}
	plain, hash, err := NewAPIToken()
	if err != nil {
		return "", APIToken{}, err
	}
	id, err := ids.New()
	if err != nil {
		return "", APIToken{}, err
	}
	now := a.now()
	t := APIToken{ID: id, UserID: p.UserID, Name: name, Hash: hash, Scope: scope, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := a.repo.CreateToken(ctx, t, audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "tokens.create", TargetType: "api_token", TargetID: id,
		IP: c.IP, Result: audit.ResultSuccess, Details: map[string]any{"name": name, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)},
	}); err != nil {
		return "", APIToken{}, fmt.Errorf("store token: %w", err)
	}
	return plain, t, nil
}

// ListTokens lists the user's tokens; the secrets are not recoverable.
func (a *Accounts) ListTokens(ctx context.Context, userID string) ([]APIToken, error) {
	return a.repo.ListTokens(ctx, userID)
}

// RevokeToken deletes one of the user's own tokens.
func (a *Accounts) RevokeToken(ctx context.Context, p Principal, id string, c Client) error {
	err := a.repo.RevokeToken(ctx, p.UserID, id, audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "tokens.revoke", TargetType: "api_token", TargetID: id,
		IP: c.IP, Result: audit.ResultSuccess,
	})
	if errors.Is(err, ErrNotFound) {
		return errcode.New(errcode.AuthToken003, "no such token")
	}
	return err
}

// AuthenticateToken resolves a bearer token. An absent, malformed, unknown, expired
// or orphaned token yields the anonymous principal and no error; only
// storage failures are errors. The token's scope is re-checked against the
// owner's current bindings on every use.
func (s *Service) AuthenticateToken(ctx context.Context, bearer string) (Principal, error) {
	acc := s.cfg.Accounts
	if acc == nil || !strings.HasPrefix(bearer, TokenPrefix) || len(bearer) > 128 {
		return Principal{}, nil
	}
	t, owner, err := acc.repo.TokenByHash(ctx, hashToken(bearer))
	if errors.Is(err, ErrNotFound) {
		return Principal{}, nil
	}
	if err != nil {
		return Principal{}, fmt.Errorf("look up token: %w", err)
	}
	now := s.cfg.Now()
	if !now.Before(t.ExpiresAt) || owner.Disabled {
		return Principal{}, nil
	}
	bindings, err := acc.repo.UserBindings(ctx, owner.ID)
	if err != nil {
		return Principal{}, fmt.Errorf("look up bindings: %w", err)
	}
	effective := intersectBindings(bindings, t.Scope)
	if len(effective) == 0 {
		return Principal{}, nil
	}
	if now.Sub(t.LastUsedAt) > tokenTouchEvery {
		if err := acc.repo.TouchToken(ctx, t.ID, now); err != nil {
			s.cfg.Log.Warn("could not record token use", "error", err)
		}
	}
	return Principal{
		UserID: owner.ID, Email: owner.Email, Name: owner.Name,
		Roles: rolesOf(effective), Bindings: effective, Via: "token",
	}, nil
}
