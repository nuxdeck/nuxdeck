// SPDX-License-Identifier: AGPL-3.0-only

// Package auth holds local accounts, sessions and authorisation decisions.
// Every handler asks Authorize for a decision before doing any work.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// ErrNotFound is returned by a Repository when a record does not exist.
var ErrNotFound = errors.New("not found")

// ErrSetupDone is returned by Repository.CreateAdmin when an account already exists.
var ErrSetupDone = errors.New("setup already completed")

// Role is a coarse permission level (docs/08-engineering-spec.md, role_bindings).
type Role string

// The roles of docs/08-engineering-spec.md.
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// User is a local account.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash string
	Disabled     bool
	CreatedAt    time.Time
}

// Session is a signed-in browser session. The cookie value is never stored, only its hash.
type Session struct {
	IDHash     string
	UserID     string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
}

// Repository is the persistence the auth module needs. Every method that changes
// state also appends its audit event in the same database transaction.
type Repository interface {
	UserCount(ctx context.Context) (int, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	// Bindings returns every role binding that applies to the user: those bound to the user directly
	// and those bound to an OIDC group the user currently belongs to. A binding whose scope cannot
	// be read is left out, so it grants nothing.
	Bindings(ctx context.Context, userID string) ([]Binding, error)
	// CreateAdmin inserts the first account with the admin role, or returns ErrSetupDone.
	CreateAdmin(ctx context.Context, u User, ev audit.Event) error
	CreateSession(ctx context.Context, s Session, ev audit.Event) error
	SessionByHash(ctx context.Context, idHash string) (Session, User, error)
	TouchSession(ctx context.Context, idHash string, seen time.Time) error
	DeleteSession(ctx context.Context, idHash string, ev audit.Event) error
	// RecordAudit appends an event that changes nothing else, such as a failed sign-in.
	RecordAudit(ctx context.Context, ev audit.Event) error
}

// Client describes the caller, for audit entries and session binding.
type Client struct {
	IP        string
	UserAgent string
}
