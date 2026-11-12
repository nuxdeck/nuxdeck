// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

// ErrLastAdmin is returned when a change would leave nobody with an unscoped admin binding.
var ErrLastAdmin = errors.New("would remove the last unscoped admin binding")

// ListRoleBindings returns every binding, oldest first.
func (s *Store) ListRoleBindings(ctx context.Context) ([]auth.StoredBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_type, subject, role, scope_json FROM role_bindings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []auth.StoredBinding{}
	for rows.Next() {
		var b auth.StoredBinding
		var role, scopeJSON string
		if err := rows.Scan(&b.ID, &b.SubjectType, &b.Subject, &role, &scopeJSON); err != nil {
			return nil, err
		}
		b.Role = auth.Role(role)
		scope, perr := auth.ParseScope(scopeJSON)
		b.Scope, b.Invalid = scope, perr != nil
		out = append(out, b)
	}
	return out, rows.Err()
}

// CreateRoleBinding stores b (its ID is assigned here) and appends ev in the same transaction.
func (s *Store) CreateRoleBinding(ctx context.Context, b auth.StoredBinding, ev audit.Event) (auth.StoredBinding, error) {
	id, err := ids.New()
	if err != nil {
		return auth.StoredBinding{}, err
	}
	b.ID = id
	scope, err := json.Marshal(b.Scope)
	if err != nil {
		return auth.StoredBinding{}, fmt.Errorf("encode scope: %w", err)
	}
	ev.TargetID = id
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if b.SubjectType == auth.SubjectUser {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, b.Subject).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return auth.ErrNotFound
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_bindings (id, subject_type, subject, role, scope_json) VALUES (?, ?, ?, ?, ?)`,
			b.ID, b.SubjectType, b.Subject, string(b.Role), string(scope)); err != nil {
			return fmt.Errorf("insert role binding: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
	return b, err
}

// DeleteRoleBinding removes a binding and appends ev in the same transaction. It returns
// auth.ErrNotFound for an unknown ID and ErrLastAdmin if it is the last unscoped admin binding.
func (s *Store) DeleteRoleBinding(ctx context.Context, id string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var subjectType, subject, role, scopeJSON string
		err := tx.QueryRowContext(ctx, `SELECT subject_type, subject, role, scope_json FROM role_bindings WHERE id = ?`, id).
			Scan(&subjectType, &subject, &role, &scopeJSON)
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		if err != nil {
			return err
		}
		if scope, perr := auth.ParseScope(scopeJSON); perr == nil && role == string(auth.RoleAdmin) && scope.IsZero() {
			rows, err := tx.QueryContext(ctx, `SELECT scope_json FROM role_bindings WHERE role = 'admin' AND id <> ?`, id)
			if err != nil {
				return err
			}
			others := 0
			for rows.Next() {
				var sj string
				if err := rows.Scan(&sj); err != nil {
					_ = rows.Close()
					return err
				}
				if sc, perr := auth.ParseScope(sj); perr == nil && sc.IsZero() {
					others++
				}
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if others == 0 {
				return ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete role binding: %w", err)
		}
		ev.TargetID = id
		if ev.Details == nil {
			ev.Details = map[string]any{}
		}
		ev.Details["subject_type"], ev.Details["subject"], ev.Details["role"] = subjectType, subject, role
		return s.appendAudit(ctx, tx, ev)
	})
}
