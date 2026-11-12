// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// Errors an AccountRepository returns for rules it enforces inside a transaction.
var (
	ErrEmailTaken = errors.New("email already in use")
	ErrLastAdmin  = errors.New("would remove the last enabled administrator")
	ErrBadState   = errors.New("two-factor state does not allow this")
)

// Account is a user as the admin screens see it.
type Account struct {
	User
	Role        Role
	TOTPEnabled bool
	HasSessions bool
}

// TOTPState is a user's second-factor state.
type TOTPState struct {
	Enabled bool
	// Pending means a secret exists that was never confirmed.
	Pending  bool
	LastStep int64
}

// APIToken is a stored token; the secret itself is never kept.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	Hash       string
	Scope      []Binding
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// SessionInfo is a session as listed to its owner. ID is a public handle, not the stored hash.
type SessionInfo struct {
	ID        string
	UserID    string
	Email     string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// AccountRepository is the persistence for user management, two-factor, sessions and
// API tokens. Every method that changes state appends its audit event in the same transaction.
type AccountRepository interface {
	ListAccounts(ctx context.Context) ([]Account, error)
	AccountByID(ctx context.Context, id string) (Account, error)
	// UserBindings lists every role binding of a user, with scope.
	UserBindings(ctx context.Context, userID string) ([]Binding, error)
	// CreateAccount returns ErrEmailTaken on a duplicate.
	CreateAccount(ctx context.Context, u User, role Role, ev audit.Event) error
	// UpdateAccount changes the given fields; ErrLastAdmin if that would leave no enabled admin.
	// Disabling or changing the role also ends the user's sessions.
	UpdateAccount(ctx context.Context, id string, name *string, role *Role, disabled *bool, ev audit.Event) error
	DeleteAccount(ctx context.Context, id string, ev audit.Event) error
	// SetPassword stores a new hash and ends the user's sessions except keepSession.
	SetPassword(ctx context.Context, id, hash, keepSession string, ev audit.Event) error
	// ResetAccount sets a new password hash, removes two-factor and ends every session and token.
	ResetAccount(ctx context.Context, id, hash string, ev audit.Event) error

	TOTPState(ctx context.Context, userID string) (TOTPState, error)
	// BeginTOTP stores a new, unconfirmed secret (sealed), or ErrBadState if TOTP is already enabled.
	BeginTOTP(ctx context.Context, userID string, secret []byte, ev audit.Event) error
	TOTPSecret(ctx context.Context, userID string) ([]byte, error)
	// ConfirmTOTP enables TOTP, records step as used and replaces the recovery codes with codeHashes.
	ConfirmTOTP(ctx context.Context, userID string, step int64, codeHashes []string, ev audit.Event) error
	// AdvanceTOTPStep atomically records step; false if it is not newer than the last one (a replay).
	AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error)
	DisableTOTP(ctx context.Context, userID string, ev audit.Event) error
	// UseRecoveryCode deletes the code with this hash; false if there is none.
	UseRecoveryCode(ctx context.Context, userID, codeHash string, ev audit.Event) (bool, error)
	RecoveryCodeCount(ctx context.Context, userID string) (int, error)

	ListSessions(ctx context.Context, userID string) ([]SessionInfo, error)
	// DeleteSessionByHandle ends a session by its public handle. owner "" matches any user.
	DeleteSessionByHandle(ctx context.Context, owner, handle string, ev audit.Event) error

	CreateToken(ctx context.Context, t APIToken, ev audit.Event) error
	TokenByHash(ctx context.Context, hash string) (APIToken, Account, error)
	ListTokens(ctx context.Context, userID string) ([]APIToken, error)
	RevokeToken(ctx context.Context, userID, id string, ev audit.Event) error
	TouchToken(ctx context.Context, id string, at time.Time) error

	// RecordAudit appends an event that changes nothing else, such as a failed check.
	RecordAudit(ctx context.Context, ev audit.Event) error

	Require2FA(ctx context.Context) (bool, error)
	SetRequire2FA(ctx context.Context, on bool, actorID string, ev audit.Event) error
}

// ErrInUse is returned when a user cannot be deleted because other records refer to them.
var ErrInUse = errors.New("user is referenced by other records")
