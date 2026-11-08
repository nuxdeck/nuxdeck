// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

var _ auth.Repository = (*Store)(nil)

// UserCount returns the number of accounts.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// UserByEmail finds an account by its lower-case email address.
func (s *Store) UserByEmail(ctx context.Context, email string) (auth.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, name, COALESCE(password_hash, ''), disabled, created_at FROM users WHERE email = ?`, email))
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(r rowScanner) (auth.User, error) {
	var u auth.User
	var disabled int
	var created int64
	if err := r.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &disabled, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.User{}, auth.ErrNotFound
		}
		return auth.User{}, err
	}
	u.Disabled = disabled == 1
	u.CreatedAt = time.UnixMilli(created)
	return u, nil
}

// Bindings lists the role bindings that apply to a user: those bound to the user directly and those
// bound to a group the user currently belongs to (the Groups hook). A binding with an unreadable
// scope is skipped, so it grants nothing.
func (s *Store) Bindings(ctx context.Context, userID string) ([]auth.Binding, error) {
	subjects := []any{userID}
	if s.Groups != nil {
		groups, err := s.Groups(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("look up groups: %w", err)
		}
		subjects = append(subjects, anySlice(groups)...)
	}
	// Group names and user IDs share one column; the subject_type check keeps them apart.
	query := `SELECT role, scope_json FROM role_bindings WHERE (subject_type = 'user' AND subject = ?)`
	if len(subjects) > 1 {
		query += ` OR (subject_type = 'oidc_group' AND subject IN (?` + strings.Repeat(`,?`, len(subjects)-2) + `))`
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY id`, subjects...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []auth.Binding
	for rows.Next() {
		var role, scopeJSON string
		if err := rows.Scan(&role, &scopeJSON); err != nil {
			return nil, err
		}
		scope, err := auth.ParseScope(scopeJSON)
		if err != nil {
			continue
		}
		out = append(out, auth.Binding{Role: auth.Role(role), Scope: scope})
	}
	return out, rows.Err()
}

func anySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// CreateAdmin inserts the first account and its admin role, or returns auth.ErrSetupDone if any account exists.
func (s *Store) CreateAdmin(ctx context.Context, u auth.User, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return auth.ErrSetupDone
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, email, name, password_hash, disabled, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
			u.ID, u.Email, u.Name, u.PasswordHash, u.CreatedAt.UnixMilli()); err != nil {
			return fmt.Errorf("insert user: %w", err)
		}
		bindingID, err := ids.New()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_bindings (id, subject_type, subject, role) VALUES (?, 'user', ?, 'admin')`, bindingID, u.ID); err != nil {
			return fmt.Errorf("insert role binding: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// CreateSession stores a session and its audit entry together.
func (s *Store) CreateSession(ctx context.Context, sess auth.Session, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sess.IDHash, sess.UserID, sess.CSRFToken, sess.CreatedAt.UnixMilli(), sess.LastSeenAt.UnixMilli(), sess.ExpiresAt.UnixMilli(), sess.IP, sess.UserAgent); err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// SessionByHash returns a session and its owner.
func (s *Store) SessionByHash(ctx context.Context, idHash string) (auth.Session, auth.User, error) {
	var sess auth.Session
	var created, seen, expires int64
	var u auth.User
	var disabled int
	var userCreated int64
	err := s.db.QueryRowContext(ctx, `SELECT s.id_hash, s.user_id, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent,
			u.id, u.email, u.name, COALESCE(u.password_hash, ''), u.disabled, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`, idHash).
		Scan(&sess.IDHash, &sess.UserID, &sess.CSRFToken, &created, &seen, &expires, &sess.IP, &sess.UserAgent,
			&u.ID, &u.Email, &u.Name, &u.PasswordHash, &disabled, &userCreated)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Session{}, auth.User{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.Session{}, auth.User{}, err
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = time.UnixMilli(created), time.UnixMilli(seen), time.UnixMilli(expires)
	u.Disabled, u.CreatedAt = disabled == 1, time.UnixMilli(userCreated)
	return sess, u, nil
}

// TouchSession records activity. It is not audited: it is bookkeeping, not a change anyone made.
func (s *Store) TouchSession(ctx context.Context, idHash string, seen time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, seen.UnixMilli(), idHash)
		return err
	})
}

// DeleteSession removes a session and records why.
func (s *Store) DeleteSession(ctx context.Context, idHash string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash); err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}
