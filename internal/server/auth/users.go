// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

const (
	maxSensitiveFailures = 5
	sensitiveWindow      = 15 * time.Minute
	sessionHandleLen     = 16
)

// AccountsConfig wires Accounts.
type AccountsConfig struct {
	Repo      AccountRepository
	Hasher    *Hasher
	Passwords *PasswordPolicy
	Log       *slog.Logger
	// Issuer labels the TOTP entry in authenticator apps.
	Issuer string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Accounts implements user management, two-factor enrolment, session management and API tokens.
type Accounts struct {
	repo      AccountRepository
	hasher    *Hasher
	passwords *PasswordPolicy
	log       *slog.Logger
	issuer    string
	now       func() time.Time
	// guard limits password and code guesses on the self-service endpoints, per user.
	guard *Limiter
}

// NewAccounts validates cfg.
func NewAccounts(cfg AccountsConfig) (*Accounts, error) {
	if cfg.Repo == nil || cfg.Hasher == nil || cfg.Passwords == nil || cfg.Log == nil {
		return nil, errors.New("auth: Repo, Hasher, Passwords and Log are required for accounts")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "Nux Deck"
	}
	return &Accounts{
		repo: cfg.Repo, hasher: cfg.Hasher, passwords: cfg.Passwords, log: cfg.Log, issuer: cfg.Issuer, now: cfg.Now,
		guard: NewLimiter(maxSensitiveFailures, sensitiveWindow, cfg.Now),
	}, nil
}

// SessionHandle is the public identifier of a session: a prefix of its stored hash.
func SessionHandle(idHash string) string {
	if len(idHash) < sessionHandleLen {
		return idHash
	}
	return idHash[:sessionHandleLen]
}

func (a *Accounts) auditFailure(ctx context.Context, p Principal, c Client, action, reason string) {
	if err := a.repo.RecordAudit(ctx, audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: action, IP: c.IP, Result: audit.ResultFailure, Details: map[string]any{"reason": reason},
	}); err != nil {
		a.log.Error("could not write audit entry", "action", action, "error", err)
	}
}

func actor(p Principal, action, targetType, targetID string, c Client, details map[string]any) audit.Event {
	if details == nil {
		details = map[string]any{}
	}
	if p.Via != "" {
		details["via"] = p.Via
	}
	return audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: action, TargetType: targetType, TargetID: targetID,
		IP: c.IP, Result: audit.ResultSuccess, Details: details,
	}
}

// NewUser is the input for creating an account.
type NewUser struct {
	Email, Name, Password string
	Role                  Role
}

func validRole(r Role) bool { return roleRank(r) > 0 }

// ListUsers returns every account.
func (a *Accounts) ListUsers(ctx context.Context) ([]Account, error) { return a.repo.ListAccounts(ctx) }

// GetUser returns one account.
func (a *Accounts) GetUser(ctx context.Context, id string) (Account, error) {
	acc, err := a.repo.AccountByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Account{}, errcode.New(errcode.AuthUser003, "no such user")
	}
	return acc, err
}

// CreateUser adds a local account with an initial password.
func (a *Accounts) CreateUser(ctx context.Context, p Principal, in NewUser, c Client) (Account, error) {
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return Account{}, &FieldError{Field: "email", Err: err}
	}
	name, err := normalizeName(in.Name)
	if err != nil {
		return Account{}, &FieldError{Field: "name", Err: err}
	}
	if !validRole(in.Role) {
		return Account{}, &FieldError{Field: "role", Err: errors.New("choose admin, operator or viewer")}
	}
	if err := a.passwords.Check(in.Password, email); err != nil {
		return Account{}, &FieldError{Field: "password", Err: err}
	}
	hash, err := a.hasher.Hash(ctx, in.Password)
	if err != nil {
		return Account{}, fmt.Errorf("hash password: %w", err)
	}
	id, err := ids.New()
	if err != nil {
		return Account{}, err
	}
	u := User{ID: id, Email: email, Name: name, PasswordHash: hash, CreatedAt: a.now()}
	err = a.repo.CreateAccount(ctx, u, in.Role, actor(p, "users.create", "user", id, c, map[string]any{"role": string(in.Role)}))
	if errors.Is(err, ErrEmailTaken) {
		return Account{}, errcode.New(errcode.AuthUser001, "email already in use")
	}
	if err != nil {
		return Account{}, fmt.Errorf("create user: %w", err)
	}
	u.PasswordHash = ""
	return Account{User: u, Role: in.Role}, nil
}

// UpdateUserRequest holds the fields an admin may change; nil leaves one alone.
type UpdateUserRequest struct {
	Name     *string
	Role     *Role
	Disabled *bool
}

// UpdateUser renames, re-roles, disables or enables an account. The last enabled admin cannot be demoted or disabled.
func (a *Accounts) UpdateUser(ctx context.Context, p Principal, id string, in UpdateUserRequest, c Client) error {
	if in.Name != nil {
		n, err := normalizeName(*in.Name)
		if err != nil {
			return &FieldError{Field: "name", Err: err}
		}
		in.Name = &n
	}
	if in.Role != nil && !validRole(*in.Role) {
		return &FieldError{Field: "role", Err: errors.New("choose admin, operator or viewer")}
	}
	details := map[string]any{}
	if in.Role != nil {
		details["role"] = string(*in.Role)
	}
	if in.Disabled != nil {
		details["disabled"] = *in.Disabled
	}
	return mapUserErr(a.repo.UpdateAccount(ctx, id, in.Name, in.Role, in.Disabled, actor(p, "users.update", "user", id, c, details)))
}

// DeleteUser removes an account; the last enabled admin cannot be removed.
func (a *Accounts) DeleteUser(ctx context.Context, p Principal, id string, c Client) error {
	return mapUserErr(a.repo.DeleteAccount(ctx, id, actor(p, "users.delete", "user", id, c, nil)))
}

// ResetUser gives the user a new password, removes their two-factor and ends their sessions and tokens.
func (a *Accounts) ResetUser(ctx context.Context, p Principal, id, newPassword string, c Client) error {
	acc, err := a.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if err := a.passwords.Check(newPassword, acc.Email); err != nil {
		return &FieldError{Field: "password", Err: err}
	}
	hash, err := a.hasher.Hash(ctx, newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return mapUserErr(a.repo.ResetAccount(ctx, id, hash, actor(p, "users.reset", "user", id, c, nil)))
}

func mapUserErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return errcode.New(errcode.AuthUser003, "no such user")
	case errors.Is(err, ErrInUse):
		return &FieldError{Field: "id", Err: errors.New("this user created agents or other records; disable the account instead")}
	case errors.Is(err, ErrLastAdmin):
		return errcode.New(errcode.AuthUser002, "last enabled administrator")
	}
	return err
}

// Require2FA reports the server-wide setting.
func (a *Accounts) Require2FA(ctx context.Context) (bool, error) { return a.repo.Require2FA(ctx) }

// SetRequire2FA turns the "everyone needs two-factor" setting on or off.
func (a *Accounts) SetRequire2FA(ctx context.Context, p Principal, on bool, c Client) error {
	return a.repo.SetRequire2FA(ctx, on, p.UserID, actor(p, "settings.require_2fa", "setting", "require_2fa", c, map[string]any{"value": on}))
}

// verifyOwnPassword checks the user's current password, counting a miss against their guard.
func (a *Accounts) verifyOwnPassword(ctx context.Context, acc Account, password string, c Client) error {
	key := "pw:" + acc.ID
	if a.guard.Blocked(key) {
		return errcode.New(errcode.AuthLock001, "too many failed attempts")
	}
	if len(password) > maxPasswordBytes {
		password = ""
	}
	ok, err := a.hasher.Verify(ctx, password, acc.PasswordHash)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !ok {
		a.guard.Fail(key)
		a.auditFailure(ctx, Principal{UserID: acc.ID}, c, "auth.password_check_failed", "bad_password")
		return errcode.New(errcode.AuthDeny001, "password rejected")
	}
	return nil
}

// ChangePassword sets a new password after checking the current one, and ends the user's other sessions.
func (a *Accounts) ChangePassword(ctx context.Context, p Principal, keepSession, current, next string, c Client) error {
	acc, err := a.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if err := a.verifyOwnPassword(ctx, acc, current, c); err != nil {
		return err
	}
	if err := a.passwords.Check(next, acc.Email); err != nil {
		return &FieldError{Field: "new_password", Err: err}
	}
	hash, err := a.hasher.Hash(ctx, next)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return a.repo.SetPassword(ctx, p.UserID, hash, keepSession, actor(p, "users.password_changed", "user", p.UserID, c, nil))
}

// ListSessions lists the user's sessions.
func (a *Accounts) ListSessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	return a.repo.ListSessions(ctx, userID)
}

// RevokeSession ends a session. An admin passes owner "" to revoke any user's session.
func (a *Accounts) RevokeSession(ctx context.Context, p Principal, owner, handle string, c Client) error {
	if len(handle) != sessionHandleLen {
		return errcode.New(errcode.AuthUser003, "no such session")
	}
	err := a.repo.DeleteSessionByHandle(ctx, owner, handle, actor(p, "sessions.revoke", "session", handle, c, nil))
	if errors.Is(err, ErrNotFound) {
		return errcode.New(errcode.AuthUser003, "no such session")
	}
	return err
}
