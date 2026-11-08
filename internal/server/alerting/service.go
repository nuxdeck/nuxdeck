// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// Options are the service's dependencies.
type Options struct {
	DB        *store.Store
	Checks    CheckSource
	Inventory Inventory
	Metrics   MetricSource
	Sink      Sink
	Log       *slog.Logger
	// Now is the clock; tests substitute a fake. Nil means time.Now.
	Now func() time.Time
	// PublicURL is the base of deep links, without a trailing slash. Empty disables links.
	PublicURL string
	// RepeatInterval re-sends a still-firing alert that was not acknowledged; 0 turns reminders off.
	RepeatInterval time.Duration
	// EvalInterval is the evaluation period; 0 means 15 seconds.
	EvalInterval time.Duration
	// Ticks replaces the evaluation ticker; for tests.
	Ticks <-chan time.Time
}

// Service owns rules, alerts, silences and routes, and runs the evaluation loop.
type Service struct {
	Options
	db *store.Store

	// emu serialises evaluation, acknowledgement and every other change to alert state, so the
	// in-memory view and the database never disagree.
	emu         sync.Mutex
	loaded      bool
	seeded      bool
	active      map[string]*Alert // fingerprint -> open or acked alert
	pending     map[string]time.Time
	samples     map[string][]restartSample
	lastPrune   time.Time
	kick        chan struct{}
	evalRuns    int64
	lastEvalErr error
}

// New builds a Service. Call Run to start evaluating.
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.EvalInterval <= 0 {
		o.EvalInterval = DefaultEvalPeriod
	}
	o.PublicURL = strings.TrimSuffix(o.PublicURL, "/")
	return &Service{
		Options: o, db: o.DB, active: map[string]*Alert{}, pending: map[string]time.Time{},
		samples: map[string][]restartSample{}, kick: make(chan struct{}, 1),
	}
}

func (s *Service) now() time.Time { return s.Now().UTC() }

// Kick asks the loop to evaluate soon; calls coalesce.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func fromNullMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func (a Actor) event(action, targetType, id string, details map[string]any) audit.Event {
	return audit.Event{ActorType: "user", ActorID: a.UserID, Action: action, TargetType: targetType, TargetID: id, IP: a.IP, Result: audit.ResultSuccess, Details: details}
}

func systemEvent(action, targetType, id string, details map[string]any) audit.Event {
	return audit.Event{ActorType: "system", ActorID: "alerting", Action: action, TargetType: targetType, TargetID: id, Result: audit.ResultSuccess, Details: details}
}

// Link returns the deep link to an item's page, or "" without a public URL.
func (s *Service) Link(itemType, itemID string) string {
	if s.PublicURL == "" {
		return ""
	}
	seg := map[string]string{ItemHost: "hosts", ItemContainer: "containers", ItemCheck: "checks"}[itemType]
	if seg == "" {
		return ""
	}
	return s.PublicURL + "/" + seg + "/" + itemID
}

// ---- rules ----

const ruleColumns = `id, name, kind, params_json, selector_json, severity, enabled, rev, created_by, updated_by, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanRule(r scanner) (Rule, error) {
	var (
		x                Rule
		params, selector string
		enabled          int
		created, updated int64
	)
	if err := r.Scan(&x.ID, &x.Name, &x.Kind, &params, &selector, &x.Severity, &enabled, &x.Rev, &x.CreatedBy, &x.UpdatedBy, &created, &updated); err != nil {
		return Rule{}, err
	}
	x.Params = json.RawMessage(params)
	if err := json.Unmarshal([]byte(selector), &x.Selector); err != nil {
		return Rule{}, fmt.Errorf("decode rule selector: %w", err)
	}
	x.Selector = x.Selector.normalize()
	x.Enabled = enabled == 1
	x.CreatedAt, x.UpdatedAt = fromMS(created), fromMS(updated)
	return x, nil
}

// validateRule checks a rule and returns it normalised (trimmed name, defaults in params).
func validateRule(in Rule) (Rule, error) {
	in.Name = clean(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > MaxNameLength {
		return in, bad("name", "Use 1 to 100 characters.")
	}
	if !validSeverity(in.Severity) {
		return in, bad("severity", "Use info, warning or critical.")
	}
	p, err := parseParams(in.Kind, in.Params)
	if err != nil {
		return in, err
	}
	in.Params = marshalParams(p)
	if err := in.Selector.validate("selector", true, true, false, false); err != nil {
		return in, err
	}
	in.Selector = in.Selector.normalize()
	return in, nil
}

// CreateRule stores a new rule.
func (s *Service) CreateRule(ctx context.Context, in Rule, who Actor) (Rule, error) {
	in, err := validateRule(in)
	if err != nil {
		return Rule{}, err
	}
	id, err := ids.New()
	if err != nil {
		return Rule{}, err
	}
	now := s.now()
	in.ID, in.Rev, in.CreatedBy, in.UpdatedBy, in.CreatedAt, in.UpdatedAt = id, 1, who.UserID, who.UserID, now, now
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_rules`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxRules {
			return bad("", "The rule limit is reached.")
		}
		if err := insertRule(ctx, tx, in); err != nil {
			return err
		}
		return s.db.AppendAudit(ctx, tx, who.event("rule.create", "alert_rule", id, ruleDetails(in)))
	})
	if err != nil {
		return Rule{}, err
	}
	s.Kick()
	return in, nil
}

func ruleDetails(r Rule) map[string]any {
	return map[string]any{"name": r.Name, "kind": r.Kind, "severity": r.Severity, "enabled": r.Enabled}
}

func insertRule(ctx context.Context, tx *sql.Tx, r Rule) error {
	sel, _ := json.Marshal(r.Selector)
	_, err := tx.ExecContext(ctx, `INSERT INTO alert_rules (`+ruleColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Kind, string(r.Params), string(sel), r.Severity, b2i(r.Enabled), r.Rev, r.CreatedBy, r.UpdatedBy, ms(r.CreatedAt), ms(r.UpdatedAt))
	if err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UpdateRule replaces a rule's definition if ifMatch is its current ETag.
func (s *Service) UpdateRule(ctx context.Context, id, ifMatch string, in Rule, who Actor) (Rule, error) {
	in, err := validateRule(in)
	if err != nil {
		return Rule{}, err
	}
	var out Rule
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		old, err := scanRule(tx.QueryRowContext(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if old.ETag() != ifMatch {
			return ErrStale
		}
		if old.Kind != in.Kind {
			return bad("kind", "The kind of a rule cannot change; create a new rule.")
		}
		out = old
		out.Name, out.Severity, out.Enabled, out.Selector, out.Params = in.Name, in.Severity, in.Enabled, in.Selector, in.Params
		out.Rev, out.UpdatedBy, out.UpdatedAt = old.Rev+1, who.UserID, s.now()
		sel, _ := json.Marshal(out.Selector)
		if _, err := tx.ExecContext(ctx, `UPDATE alert_rules SET name=?, params_json=?, selector_json=?, severity=?, enabled=?, rev=?, updated_by=?, updated_at=? WHERE id=?`,
			out.Name, string(out.Params), string(sel), out.Severity, b2i(out.Enabled), out.Rev, out.UpdatedBy, ms(out.UpdatedAt), id); err != nil {
			return fmt.Errorf("update rule: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("rule.update", "alert_rule", id, ruleDetails(out)))
	})
	if err != nil {
		return Rule{}, err
	}
	s.Kick()
	return out, nil
}

// DeleteRule removes a rule; its open alerts resolve on the next evaluation.
func (s *Service) DeleteRule(ctx context.Context, id string, who Actor) error {
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `SELECT name FROM alert_rules WHERE id = ?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete rule: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("rule.delete", "alert_rule", id, map[string]any{"name": name}))
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// GetRule returns one rule.
func (s *Service) GetRule(ctx context.Context, id string) (Rule, error) {
	r, err := scanRule(s.db.DB().QueryRowContext(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	return r, err
}

// ListRules returns rules ordered by ID after the cursor.
func (s *Service) ListRules(ctx context.Context, after string, limit int) (items []Rule, next string, err error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("list rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, r)
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

func (s *Service) enabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
