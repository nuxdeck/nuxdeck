// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
)

var _ pki.Repository = (*Store)(nil)

// CreateEnrollmentToken stores a token hash and its audit entry.
func (s *Store) CreateEnrollmentToken(ctx context.Context, t pki.TokenRecord, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens (id, token_hash, created_by, labels_json, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			t.ID, t.Hash, t.CreatedBy, t.LabelsJSON, t.CreatedAt.UnixMilli(), t.ExpiresAt.UnixMilli()); err != nil {
			return fmt.Errorf("insert enrolment token: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}

// RedeemEnrollmentToken spends a token and creates its agent atomically. The
// conditional UPDATE under the database write lock is what makes it single use.
func (s *Store) RedeemEnrollmentToken(ctx context.Context, hash string, now time.Time,
	redeem func(tokenID, labelsJSON string) (pki.Redemption, error),
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var id, labels string
		err := tx.QueryRowContext(ctx, `SELECT id, labels_json FROM enrollment_tokens
			WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, hash, now.UnixMilli()).Scan(&id, &labels)
		if errors.Is(err, sql.ErrNoRows) {
			return pki.ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("find enrolment token: %w", err)
		}
		res, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`, now.UnixMilli(), id)
		if err != nil {
			return fmt.Errorf("spend enrolment token: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return pki.ErrTokenInvalid
		}

		r, err := redeem(id, labels)
		if err != nil {
			return err
		}
		a := r.Agent
		if _, err := tx.ExecContext(ctx, `INSERT INTO agents (id, token_id, cert_serial, hostname, os, arch, version, labels_json, enrolled_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, id, a.CertSerial, a.Hostname, a.OS, a.Arch, a.Version, labels, a.EnrolledAt.UnixMilli()); err != nil {
			return fmt.Errorf("insert agent: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_certs (serial, agent_id, issued_at, not_after) VALUES (?, ?, ?, ?)`,
			a.CertSerial, a.ID, a.EnrolledAt.UnixMilli(), a.NotAfter.UnixMilli()); err != nil {
			return fmt.Errorf("record agent certificate: %w", err)
		}
		return s.appendAudit(ctx, tx, r.Event)
	})
}

// RenewAgentCertificate records a replacement certificate for a live agent and audits it atomically.
func (s *Store) RenewAgentCertificate(ctx context.Context, agentID string, issue func() (pki.CertRecord, audit.Event, error)) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var revoked sql.NullInt64
		var current string
		err := tx.QueryRowContext(ctx, `SELECT cert_serial, revoked_at FROM agents WHERE id = ?`, agentID).Scan(&current, &revoked)
		if errors.Is(err, sql.ErrNoRows) || revoked.Valid {
			return pki.ErrAgentUnavailable
		}
		if err != nil {
			return fmt.Errorf("find agent: %w", err)
		}
		rec, ev, err := issue()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_certs (serial, agent_id, issued_at, not_after) VALUES (?, ?, ?, ?)`,
			rec.Serial, agentID, rec.IssuedAt.UnixMilli(), rec.NotAfter.UnixMilli()); err != nil {
			return fmt.Errorf("record agent certificate: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET cert_serial = ? WHERE id = ?`, rec.Serial, agentID); err != nil {
			return fmt.Errorf("update agent certificate: %w", err)
		}
		return s.appendAudit(ctx, tx, ev)
	})
}
