// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
)

var _ gateway.Repository = (*Store)(nil)

// AgentByID looks up an enrolled agent.
func (s *Store) AgentByID(ctx context.Context, id string) (gateway.AgentInfo, error) {
	info := gateway.AgentInfo{ID: id}
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT cert_serial, revoked_at IS NOT NULL FROM agents WHERE id = ?`, id).Scan(&info.CertSerial, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return gateway.AgentInfo{}, gateway.ErrAgentNotFound
	}
	info.Revoked = revoked == 1
	return info, err
}

// RevokedSerials lists every certificate serial ever issued to a revoked agent.
func (s *Store) RevokedSerials(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.serial FROM agent_certs c JOIN agents a ON a.id = c.agent_id WHERE a.revoked_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, err
		}
		out = append(out, serial)
	}
	return out, rows.Err()
}

// RevokeAgent marks an agent revoked and audits it in one transaction. It returns every
// certificate serial the agent was ever issued.
func (s *Store) RevokeAgent(ctx context.Context, id string, at time.Time, ev audit.Event) (serials []string, changed bool, err error) {
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var revokedAt sql.NullInt64
		var current string
		err := tx.QueryRowContext(ctx, `SELECT cert_serial, revoked_at FROM agents WHERE id = ?`, id).Scan(&current, &revokedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return gateway.ErrAgentNotFound
		}
		if err != nil {
			return fmt.Errorf("find agent: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT serial FROM agent_certs WHERE agent_id = ?`, id)
		if err != nil {
			return fmt.Errorf("list agent certificates: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var serial string
			if err := rows.Scan(&serial); err != nil {
				return err
			}
			serials = append(serials, serial)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if revokedAt.Valid {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET revoked_at = ? WHERE id = ?`, at.UnixMilli(), id); err != nil {
			return fmt.Errorf("revoke agent: %w", err)
		}
		changed = true
		ev.Details = map[string]any{"cert_serials": serials}
		return s.appendAudit(ctx, tx, ev)
	})
	return serials, changed, err
}

// TouchAgent records when the agent was last heard from.
func (s *Store) TouchAgent(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET last_seen_at = ? WHERE id = ?`, at.UnixMilli(), id)
	return err
}
