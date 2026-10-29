// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const alertColumns = `id, rule_id, rule_name, kind, severity, fingerprint, item_type, item_id, item_name, summary, state, opened_at, acked_by, acked_at, resolved_at, resolve_reason, flap_count, last_notified_at, notify_pending`

func (s *Service) scanAlert(r scanner) (Alert, error) {
	var (
		a                        Alert
		opened                   int64
		acked, resolved, notifed sql.NullInt64
		pending                  int
	)
	if err := r.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.Kind, &a.Severity, &a.fingerprint, &a.ItemType, &a.ItemID, &a.ItemName, &a.Summary, &a.State,
		&opened, &a.AckedBy, &acked, &resolved, &a.ResolveReason, &a.FlapCount, &notifed, &pending); err != nil {
		return Alert{}, err
	}
	a.OpenedAt, a.AckedAt, a.ResolvedAt, a.LastNotifiedAt = fromMS(opened), fromNullMS(acked), fromNullMS(resolved), fromNullMS(notifed)
	a.notifyPending = pending == 1
	a.Link = s.Link(a.ItemType, a.ItemID)
	return a, nil
}

// AlertFilter narrows ListAlerts.
type AlertFilter struct {
	// State is open, acked, resolved or active (open and acked); empty means all.
	State    string
	Severity string
	ItemID   string
	RuleID   string
}

// ListAlerts returns alerts newest first, starting after the cursor (an alert ID).
func (s *Service) ListAlerts(ctx context.Context, f AlertFilter, before string, limit int) (items []Alert, next string, err error) {
	var where []string
	var args []any
	switch f.State {
	case "":
	case "active":
		where = append(where, `state IN ('open','acked')`)
	case StateOpen, StateAcked, StateResolved:
		where = append(where, `state = ?`)
		args = append(args, f.State)
	default:
		return nil, "", bad("state", "Use open, acked, resolved or active.")
	}
	if f.Severity != "" {
		if !validSeverity(f.Severity) {
			return nil, "", bad("severity", "Use info, warning or critical.")
		}
		where, args = append(where, `severity = ?`), append(args, f.Severity)
	}
	if f.ItemID != "" {
		where, args = append(where, `item_id = ?`), append(args, f.ItemID)
	}
	if f.RuleID != "" {
		where, args = append(where, `rule_id = ?`), append(args, f.RuleID)
	}
	if before != "" {
		where, args = append(where, `id < ?`), append(args, before)
	}
	q := `SELECT ` + alertColumns + ` FROM alerts`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	rows, err := s.db.DB().QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, "", fmt.Errorf("list alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		a, err := s.scanAlert(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].ID
	}
	return items, next, nil
}

// GetAlert returns one alert.
func (s *Service) GetAlert(ctx context.Context, id string) (Alert, error) {
	a, err := s.scanAlert(s.db.DB().QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, ErrNotFound
	}
	return a, err
}

// Ack acknowledges an alert: it stays open in the list but sends no more reminders.
// Acknowledging an acknowledged alert changes nothing; a resolved alert is ErrResolved.
func (s *Service) Ack(ctx context.Context, id string, who Actor) (Alert, error) {
	s.emu.Lock()
	defer s.emu.Unlock()
	var out Alert
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		a, err := s.scanAlert(tx.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = a
		switch a.State {
		case StateResolved:
			return ErrResolved
		case StateAcked:
			return nil
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE alerts SET state = 'acked', acked_by = ?, acked_at = ?, notify_pending = 0 WHERE id = ?`, who.UserID, ms(now), id); err != nil {
			return fmt.Errorf("acknowledge alert: %w", err)
		}
		out.State, out.AckedBy, out.AckedAt, out.notifyPending = StateAcked, who.UserID, &now, false
		return s.db.AppendAudit(ctx, tx, who.event("alert.ack", "alert", id, map[string]any{"rule_id": a.RuleID, "item_type": a.ItemType, "item_id": a.ItemID}))
	})
	if err != nil {
		return Alert{}, err
	}
	if cached, ok := s.active[out.fingerprint]; ok && cached.ID == id {
		cached.State, cached.AckedBy, cached.AckedAt, cached.notifyPending = out.State, out.AckedBy, out.AckedAt, false
	}
	return out, nil
}
