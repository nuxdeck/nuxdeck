// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// AuditFilter narrows a search or export. Zero fields match everything.
type AuditFilter struct {
	ActorID      string
	ActionPrefix string
	TargetType   string
	TargetID     string
	Result       string
	FromMS       int64 // inclusive, Unix ms; 0 = unbounded
	ToMS         int64 // exclusive, Unix ms; 0 = unbounded
	Text         string
}

const auditColumns = `id, ts, actor_type, actor_id, action, target_type, target_id, ip, result, details_json, prev_hash, hash`

// where builds the condition and its arguments. Everything user-supplied is a bound parameter.
func (f AuditFilter) where(beforeID int64) (string, []any) {
	var conds []string
	var args []any
	add := func(c string, a ...any) { conds = append(conds, c); args = append(args, a...) }
	if beforeID > 0 {
		add("id < ?", beforeID)
	}
	if f.ActorID != "" {
		add("actor_id = ?", f.ActorID)
	}
	if f.ActionPrefix != "" {
		// A range instead of LIKE so the (action, id) index applies and no wildcard needs escaping.
		add("action >= ? AND action < ?", f.ActionPrefix, prefixEnd(f.ActionPrefix))
	}
	if f.TargetType != "" {
		add("target_type = ?", f.TargetType)
	}
	if f.TargetID != "" {
		add("target_id = ?", f.TargetID)
	}
	if f.Result != "" {
		add("result = ?", f.Result)
	}
	if f.FromMS > 0 {
		add("ts >= ?", f.FromMS)
	}
	if f.ToMS > 0 {
		add("ts < ?", f.ToMS)
	}
	if f.Text != "" {
		add(`instr(lower(details_json), lower(?)) > 0`, f.Text)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// prefixEnd is the smallest string greater than every string starting with p.
func prefixEnd(p string) string { return p + "\U0010ffff" }

func scanAudit(rows *sql.Rows) (audit.Entry, error) {
	var e audit.Entry
	err := rows.Scan(&e.ID, &e.TS, &e.Event.ActorType, &e.Event.ActorID, &e.Event.Action, &e.Event.TargetType, &e.Event.TargetID,
		&e.Event.IP, &e.Event.Result, &e.DetailsJSON, &e.PrevHash, &e.Hash)
	if err != nil {
		return e, fmt.Errorf("scan audit entry: %w", err)
	}
	return e, nil
}

// SearchAudit returns up to limit entries, newest first, with ID below beforeID when that is set.
// next is the cursor for the following page, 0 when there is none.
func (s *Store) SearchAudit(ctx context.Context, f AuditFilter, beforeID int64, limit int) (entries []audit.Entry, next int64, err error) {
	cond, args := f.where(beforeID)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_log`+cond+` ORDER BY id DESC LIMIT ?`, append(args, limit+1)...) //nolint:gosec // cond is assembled from constant fragments; every value is a bound parameter
	if err != nil {
		return nil, 0, fmt.Errorf("search audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search audit log: %w", err)
	}
	if len(entries) > limit {
		entries = entries[:limit]
		next = entries[limit-1].ID
	}
	return entries, next, nil
}

// StreamAudit calls fn for every matching entry in ID order, holding one row at a time.
func (s *Store) StreamAudit(ctx context.Context, f AuditFilter, fn func(audit.Entry) error) error {
	cond, args := f.where(0)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_log`+cond+` ORDER BY id`, args...) //nolint:gosec // cond is assembled from constant fragments; every value is a bound parameter
	if err != nil {
		return fmt.Errorf("stream audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// VerifyAudit walks the whole chain in ID order and reports the first break. An error is
// returned only when the log could not be read.
func (s *Store) VerifyAudit(ctx context.Context) (audit.Verification, error) {
	var v audit.Verifier
	res := audit.Verification{OK: true}
	err := s.StreamAudit(ctx, AuditFilter{}, func(e audit.Entry) error {
		if verr := v.Add(e); verr != nil {
			res = audit.Verification{Entries: res.Entries, BrokenAt: e.ID, Reason: verr.Error()}
			return errStopWalk
		}
		res.Entries++
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return audit.Verification{}, err
	}
	return res, nil
}

var errStopWalk = errors.New("stop walk")
