// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// Setting reads one UI-editable setting as stored JSON; ok is false when it was never set.
func (s *Store) Setting(ctx context.Context, key string) (valueJSON string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key = ?`, key).Scan(&valueJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read setting %s: %w", key, err)
	}
	return valueJSON, true, nil
}

// SetSetting stores a setting and its audit entry in one transaction (AUD-1).
func (s *Store) SetSetting(ctx context.Context, key, valueJSON, actorID string, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_by, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
			key, valueJSON, actorID, s.now().UnixMilli()); err != nil {
			return fmt.Errorf("store setting %s: %w", key, err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}
