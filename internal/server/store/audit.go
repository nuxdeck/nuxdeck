// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// appendAudit adds one entry to the chain inside tx. Because every write
// transaction takes the database write lock up front, the "last entry" read
// here cannot be overtaken by another writer before the insert.
func (s *Store) appendAudit(ctx context.Context, tx *sql.Tx, ev audit.Event) error {
	var lastID int64
	var lastHash string
	err := tx.QueryRowContext(ctx, `SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read last audit entry: %w", err)
	}

	details, err := audit.CanonicalDetails(ev.Details)
	if err != nil {
		return err
	}
	e := audit.Entry{ID: lastID + 1, TS: s.now().UnixMilli(), Event: ev, DetailsJSON: details, PrevHash: lastHash}
	if e.Hash, err = audit.Hash(e); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log
		(id, ts, actor_type, actor_id, action, target_type, target_id, ip, result, details_json, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TS, ev.ActorType, ev.ActorID, ev.Action, ev.TargetType, ev.TargetID, ev.IP, ev.Result, e.DetailsJSON, e.PrevHash, e.Hash); err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// RecordAudit appends an event that changes nothing else.
func (s *Store) RecordAudit(ctx context.Context, ev audit.Event) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return s.appendAudit(ctx, tx, ev) })
}

// VerifyAuditChain walks the whole log and returns the number of entries, or the first problem found.
func (s *Store) VerifyAuditChain(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, actor_type, actor_id, action, target_type, target_id, ip, result, details_json, prev_hash, hash
		FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("read audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var v audit.Verifier
	n := 0
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.ID, &e.TS, &e.Event.ActorType, &e.Event.ActorID, &e.Event.Action, &e.Event.TargetType, &e.Event.TargetID,
			&e.Event.IP, &e.Event.Result, &e.DetailsJSON, &e.PrevHash, &e.Hash); err != nil {
			return n, fmt.Errorf("scan audit entry: %w", err)
		}
		if err := v.Add(e); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// AppendAudit adds an entry inside the caller's transaction, so a change and its audit
// record commit together. It is for modules that own their tables (checks, channels).
func (s *Store) AppendAudit(ctx context.Context, tx *sql.Tx, ev audit.Event) error {
	return s.appendAudit(ctx, tx, ev)
}
