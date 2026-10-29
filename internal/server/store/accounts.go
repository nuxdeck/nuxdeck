// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

var _ auth.AccountRepository = (*Store)(nil)

const accountColumns = `u.id, u.email, u.name, %s, u.disabled, u.created_at, u.totp_enabled,
	COALESCE((SELECT CASE MAX(CASE rb.role WHEN 'admin' THEN 3 WHEN 'operator' THEN 2 ELSE 1 END)
		WHEN 3 THEN 'admin' WHEN 2 THEN 'operator' WHEN 1 THEN 'viewer' END
		FROM role_bindings rb WHERE rb.subject_type = 'user' AND rb.subject = u.id), '')`

func scanAccount(r rowScanner) (auth.Account, error) {
	var a auth.Account
	var disabled, totp int
	var created int64
	var role string
	if err := r.Scan(&a.ID, &a.Email, &a.Name, &a.PasswordHash, &disabled, &created, &totp, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.Account{}, auth.ErrNotFound
		}
		return auth.Account{}, err
	}
	a.Disabled, a.CreatedAt, a.TOTPEnabled, a.Role = disabled == 1, time.UnixMilli(created), totp == 1, auth.Role(role)
	return a, nil
}

// ListAccounts lists every user, without password hashes.
func (s *Store) ListAccounts(ctx context.Context) ([]auth.Account, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT `+accountColumns+` FROM users u ORDER BY u.created_at, u.id`, `''`))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []auth.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AccountByID returns one user including the password hash.
func (s *Store) AccountByID(ctx context.Context, id string) (auth.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT `+accountColumns+` FROM users u WHERE u.id = ?`, `COALESCE(u.password_hash, '')`), id))
}

// UserBindings lists the role bindings bound directly to a user, with scope.
func (s *Store) UserBindings(ctx context.Context, userID string) ([]auth.Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role, scope_json FROM role_bindings WHERE subject_type = 'user' AND subject = ? ORDER BY role, id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []auth.Binding
	for rows.Next() {
		var role, scope string
		if err := rows.Scan(&role, &scope); err != nil {
			return nil, err
		}
		b := auth.Binding{Role: auth.Role(role)}
		if err := json.Unmarshal([]byte(scope), &b.Scope); err != nil {
			return nil, fmt.Errorf("decode binding scope: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CreateAccount inserts a user with one unscoped role binding.
func (s *Store) CreateAccount(ctx context.Context, u auth.User, role auth.Role, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO users (id, email, name, password_hash, disabled, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
			u.ID, u.Email, u.Name, u.PasswordHash, u.CreatedAt.UnixMilli())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return auth.ErrEmailTaken
			}
			return fmt.Errorf("insert user: %w", err)
		}
		if err := setUserRole(ctx, tx, u.ID, role); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

func setUserRole(ctx context.Context, tx *sql.Tx, userID string, role auth.Role) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE subject_type = 'user' AND subject = ?`, userID); err != nil {
		return fmt.Errorf("clear role bindings: %w", err)
	}
	id, err := ids.New()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO role_bindings (id, subject_type, subject, role) VALUES (?, 'user', ?, ?)`, id, userID, string(role)); err != nil {
		return fmt.Errorf("insert role binding: %w", err)
	}
	return nil
}

// otherEnabledAdmins counts enabled administrators besides exclude.
func otherEnabledAdmins(ctx context.Context, tx *sql.Tx, exclude string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT u.id) FROM users u JOIN role_bindings rb
		ON rb.subject_type = 'user' AND rb.subject = u.id AND rb.role = 'admin'
		WHERE u.disabled = 0 AND u.id != ?`, exclude).Scan(&n)
	return n, err
}

func currentAccount(ctx context.Context, tx *sql.Tx, id string) (role string, disabled bool, err error) {
	var d int
	err = tx.QueryRowContext(ctx, `SELECT u.disabled, COALESCE((SELECT CASE MAX(CASE rb.role WHEN 'admin' THEN 3 WHEN 'operator' THEN 2 ELSE 1 END)
		WHEN 3 THEN 'admin' WHEN 2 THEN 'operator' WHEN 1 THEN 'viewer' END
		FROM role_bindings rb WHERE rb.subject_type = 'user' AND rb.subject = u.id), '') FROM users u WHERE u.id = ?`, id).Scan(&d, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, auth.ErrNotFound
	}
	return role, d == 1, err
}

// UpdateAccount applies a partial update, refusing to leave the server without an enabled admin.
func (s *Store) UpdateAccount(ctx context.Context, id string, name *string, role *auth.Role, disabled *bool, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		curRole, curDisabled, err := currentAccount(ctx, tx, id)
		if err != nil {
			return err
		}
		newRole, newDisabled := curRole, curDisabled
		if role != nil {
			newRole = string(*role)
		}
		if disabled != nil {
			newDisabled = *disabled
		}
		if curRole == "admin" && !curDisabled && (newRole != "admin" || newDisabled) {
			n, err := otherEnabledAdmins(ctx, tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				return auth.ErrLastAdmin
			}
		}
		if name != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET name = ? WHERE id = ?`, *name, id); err != nil {
				return fmt.Errorf("update name: %w", err)
			}
		}
		if disabled != nil {
			d := 0
			if *disabled {
				d = 1
			}
			if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, d, id); err != nil {
				return fmt.Errorf("update disabled: %w", err)
			}
			if *disabled {
				if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
					return fmt.Errorf("end sessions: %w", err)
				}
			}
		}
		if role != nil && newRole != curRole {
			if err := setUserRole(ctx, tx, id, *role); err != nil {
				return err
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// DeleteAccount removes a user, their bindings, sessions and tokens.
func (s *Store) DeleteAccount(ctx context.Context, id string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		curRole, curDisabled, err := currentAccount(ctx, tx, id)
		if err != nil {
			return err
		}
		if curRole == "admin" && !curDisabled {
			n, err := otherEnabledAdmins(ctx, tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				return auth.ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE subject_type = 'user' AND subject = ?`, id); err != nil {
			return fmt.Errorf("delete bindings: %w", err)
		}
		var ref sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT totp_secret_ref FROM users WHERE id = ?`, id).Scan(&ref); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
			if strings.Contains(err.Error(), "FOREIGN KEY") {
				return auth.ErrInUse
			}
			return fmt.Errorf("delete user: %w", err)
		}
		if ref.Valid && s.secretBox != nil {
			if err := s.secretBox.Delete(ctx, tx, ref.String); err != nil {
				return fmt.Errorf("delete TOTP secret: %w", err)
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// SetPassword stores a new hash and ends every session of the user except keepSession.
func (s *Store) SetPassword(ctx context.Context, id, hash, keepSession string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`, id, keepSession); err != nil {
			return fmt.Errorf("end other sessions: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// ResetAccount replaces the password, drops two-factor and ends every session and token.
func (s *Store) ResetAccount(ctx context.Context, id, hash string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := s.dropTOTP(ctx, tx, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
		if err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return auth.ErrNotFound
		}
		for _, q := range []string{`DELETE FROM sessions WHERE user_id = ?`, `DELETE FROM api_tokens WHERE user_id = ?`} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return fmt.Errorf("revoke credentials: %w", err)
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// dropTOTP clears the secret, flags and recovery codes of a user.
func (s *Store) dropTOTP(ctx context.Context, tx *sql.Tx, id string) error {
	var ref sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT totp_secret_ref FROM users WHERE id = ?`, id).Scan(&ref); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_ref = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?`, id); err != nil {
		return fmt.Errorf("clear TOTP: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("clear recovery codes: %w", err)
	}
	if ref.Valid && s.secretBox != nil {
		if err := s.secretBox.Delete(ctx, tx, ref.String); err != nil {
			return fmt.Errorf("delete TOTP secret: %w", err)
		}
	}
	return nil
}

// TOTPState reads the second-factor flags.
func (s *Store) TOTPState(ctx context.Context, userID string) (auth.TOTPState, error) {
	var enabled int
	var ref sql.NullString
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT totp_enabled, totp_secret_ref, totp_last_step FROM users WHERE id = ?`, userID).Scan(&enabled, &ref, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.TOTPState{}, auth.ErrNotFound
	}
	return auth.TOTPState{Enabled: enabled == 1, Pending: enabled == 0 && ref.Valid, LastStep: last}, err
}

// BeginTOTP seals a new unconfirmed secret, replacing an earlier unconfirmed one.
func (s *Store) BeginTOTP(ctx context.Context, userID string, secret []byte, ev audit.Event) error {
	if s.secretBox == nil {
		return errors.New("secrets box not configured")
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var enabled int
		var ref sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT totp_enabled, totp_secret_ref FROM users WHERE id = ?`, userID).Scan(&enabled, &ref); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return auth.ErrNotFound
			}
			return err
		}
		if enabled == 1 {
			return auth.ErrBadState
		}
		if ref.Valid {
			if err := s.secretBox.Replace(ctx, tx, ref.String, secret); err != nil {
				return fmt.Errorf("replace TOTP secret: %w", err)
			}
		} else {
			id, err := s.secretBox.Put(ctx, tx, secret)
			if err != nil {
				return fmt.Errorf("store TOTP secret: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_ref = ? WHERE id = ?`, id, userID); err != nil {
				return fmt.Errorf("link TOTP secret: %w", err)
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// TOTPSecret opens the user's secret.
func (s *Store) TOTPSecret(ctx context.Context, userID string) ([]byte, error) {
	if s.secretBox == nil {
		return nil, errors.New("secrets box not configured")
	}
	var ref sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret_ref FROM users WHERE id = ?`, userID).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !ref.Valid) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.secretBox.Get(ctx, s.db, ref.String)
}

// ConfirmTOTP turns two-factor on and stores the hashed recovery codes.
func (s *Store) ConfirmTOTP(ctx context.Context, userID string, step int64, codeHashes []string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ? AND totp_enabled = 0 AND totp_secret_ref IS NOT NULL`, step, userID)
		if err != nil {
			return fmt.Errorf("enable TOTP: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return auth.ErrBadState
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("clear recovery codes: %w", err)
		}
		for _, h := range codeHashes {
			id, err := ids.New()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`, id, userID, h, s.now().UnixMilli()); err != nil {
				return fmt.Errorf("store recovery code: %w", err)
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// AdvanceTOTPStep records step only if it is newer than the last accepted one.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DisableTOTP turns two-factor off and removes the secret and recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT totp_enabled FROM users WHERE id = ?`, userID).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return auth.ErrNotFound
			}
			return err
		}
		if enabled != 1 {
			return auth.ErrBadState
		}
		if err := s.dropTOTP(ctx, tx, userID); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// UseRecoveryCode consumes a recovery code if it exists.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, codeHash string, ev audit.Event) (bool, error) {
	used := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?`, userID, codeHash)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil
		}
		used = true
		return s.appendAudit(ctx, tx, ev)
	})
	return used, err
}

// RecoveryCodeCount counts the unused codes.
func (s *Store) RecoveryCodeCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// ListSessions lists the live sessions of a user, newest first.
func (s *Store) ListSessions(ctx context.Context, userID string) ([]auth.SessionInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id_hash, s.user_id, u.email, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.user_id = ? AND s.expires_at > ? ORDER BY s.created_at DESC`, userID, s.now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []auth.SessionInfo
	for rows.Next() {
		var si auth.SessionInfo
		var hash string
		var created, seen, expires int64
		if err := rows.Scan(&hash, &si.UserID, &si.Email, &created, &seen, &expires, &si.IP, &si.UserAgent); err != nil {
			return nil, err
		}
		si.ID = auth.SessionHandle(hash)
		si.CreatedAt, si.LastSeen, si.ExpiresAt = time.UnixMilli(created), time.UnixMilli(seen), time.UnixMilli(expires)
		out = append(out, si)
	}
	return out, rows.Err()
}

// DeleteSessionByHandle ends the session with this public handle; owner "" matches any user.
func (s *Store) DeleteSessionByHandle(ctx context.Context, owner, handle string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var hash, user string
		err := tx.QueryRowContext(ctx, `SELECT id_hash, user_id FROM sessions WHERE substr(id_hash, 1, ?) = ? AND (? = '' OR user_id = ?)`,
			len(handle), handle, owner, owner).Scan(&hash, &user)
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, hash); err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
		if ev.Details == nil {
			ev.Details = map[string]any{}
		}
		ev.Details["user_id"] = user
		return s.appendAudit(ctx, tx, ev)
	})
}

// CreateToken stores a token's hash and scope.
func (s *Store) CreateToken(ctx context.Context, t auth.APIToken, ev audit.Event) error {
	scope, err := json.Marshal(t.Scope)
	if err != nil {
		return fmt.Errorf("encode scope: %w", err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, scope_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.UserID, t.Name, t.Hash, string(scope), t.CreatedAt.UnixMilli(), t.ExpiresAt.UnixMilli()); err != nil {
			return fmt.Errorf("insert token: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

func scanToken(r rowScanner, extra ...any) (auth.APIToken, error) {
	var t auth.APIToken
	var scope string
	var created, expires int64
	var used sql.NullInt64
	dest := append([]any{&t.ID, &t.UserID, &t.Name, &t.Hash, &scope, &created, &expires, &used}, extra...)
	if err := r.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.APIToken{}, auth.ErrNotFound
		}
		return auth.APIToken{}, err
	}
	if err := json.Unmarshal([]byte(scope), &t.Scope); err != nil {
		return auth.APIToken{}, fmt.Errorf("decode token scope: %w", err)
	}
	t.CreatedAt, t.ExpiresAt = time.UnixMilli(created), time.UnixMilli(expires)
	if used.Valid {
		t.LastUsedAt = time.UnixMilli(used.Int64)
	}
	return t, nil
}

const tokenColumns = `t.id, t.user_id, t.name, t.token_hash, t.scope_json, t.created_at, t.expires_at, t.last_used_at` //nolint:gosec // a column list, not a credential

// TokenByHash finds a token and its owner.
func (s *Store) TokenByHash(ctx context.Context, hash string) (auth.APIToken, auth.Account, error) {
	var disabled int
	var owner auth.Account
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+`, u.email, u.name, u.disabled
		FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`, hash), &owner.Email, &owner.Name, &disabled)
	if err != nil {
		return auth.APIToken{}, auth.Account{}, err
	}
	owner.ID, owner.Disabled = t.UserID, disabled == 1
	return t, owner, nil
}

// ListTokens lists a user's tokens, newest first.
func (s *Store) ListTokens(ctx context.Context, userID string) ([]auth.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens t WHERE t.user_id = ? ORDER BY t.created_at DESC, t.id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []auth.APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken deletes one of the user's tokens.
func (s *Store) RevokeToken(ctx context.Context, userID, id string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return auth.ErrNotFound
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// TouchToken records use. It is bookkeeping and is not audited.
func (s *Store) TouchToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, at.UnixMilli(), id)
	return err
}

// Require2FA reads the setting; absent means off.
func (s *Store) Require2FA(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key = 'require_2fa'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return v == "true", err
}

// SetRequire2FA stores the setting and its audit entry together.
func (s *Store) SetRequire2FA(ctx context.Context, on bool, actorID string, ev audit.Event) error {
	v := "false"
	if on {
		v = "true"
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_by, updated_at) VALUES ('require_2fa', ?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
			v, actorID, s.now().UnixMilli()); err != nil {
			return fmt.Errorf("store setting: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}
