// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/ids"
)

const silenceColumns = `id, kind, selector_json, starts_at, ends_at, reason, created_by, created_at`

func scanSilence(r scanner, now time.Time) (Silence, error) {
	var (
		x                  Silence
		sel                string
		starts, ends, made int64
	)
	if err := r.Scan(&x.ID, &x.Kind, &sel, &starts, &ends, &x.Reason, &x.CreatedBy, &made); err != nil {
		return Silence{}, err
	}
	if err := json.Unmarshal([]byte(sel), &x.Selector); err != nil {
		return Silence{}, fmt.Errorf("decode silence selector: %w", err)
	}
	x.Selector = x.Selector.normalize()
	x.StartsAt, x.EndsAt, x.CreatedAt = fromMS(starts), fromMS(ends), fromMS(made)
	x.State = silenceState(x, now)
	return x, nil
}

// silenceState: a silence is active from StartsAt (inclusive) until EndsAt (exclusive).
func silenceState(x Silence, now time.Time) string {
	switch {
	case now.Before(x.StartsAt):
		return "scheduled"
	case now.Before(x.EndsAt):
		return "active"
	default:
		return "expired"
	}
}

// CreateSilence mutes notifications for matching items between StartsAt (default: now) and
// EndsAt. Alerts still open and are recorded while muted.
func (s *Service) CreateSilence(ctx context.Context, in Silence, who Actor) (Silence, error) {
	now := s.now()
	if in.Kind == "" {
		in.Kind = SilenceKindSilence
	}
	if in.Kind != SilenceKindSilence && in.Kind != SilenceKindMaintenance {
		return Silence{}, bad("kind", "Use silence or maintenance.")
	}
	in.Reason = clean(in.Reason)
	if in.Reason == "" || len([]rune(in.Reason)) > MaxReasonLength {
		return Silence{}, bad("reason", "Give a reason of 1 to 200 characters.")
	}
	if err := in.Selector.validate("selector", true, true, true, true); err != nil {
		return Silence{}, err
	}
	if in.Selector.empty() {
		return Silence{}, bad("selector", "Select at least one tag, item, severity or kind; a silence must not mute everything by accident.")
	}
	in.Selector = in.Selector.normalize()
	if in.StartsAt.IsZero() {
		in.StartsAt = now
	}
	in.StartsAt, in.EndsAt = in.StartsAt.UTC().Truncate(time.Millisecond), in.EndsAt.UTC().Truncate(time.Millisecond)
	if in.EndsAt.IsZero() || !in.EndsAt.After(in.StartsAt) {
		return Silence{}, bad("ends_at", "The end must be after the start.")
	}
	if !in.EndsAt.After(now) {
		return Silence{}, bad("ends_at", "The end is already in the past.")
	}
	if in.StartsAt.After(now.Add(MaxScheduleAhead)) {
		return Silence{}, bad("starts_at", "Schedule at most one year ahead.")
	}
	limit := MaxSilenceLength
	if in.Kind == SilenceKindMaintenance {
		limit = MaxMaintenance
	}
	if in.EndsAt.Sub(in.StartsAt) > limit {
		return Silence{}, bad("ends_at", fmt.Sprintf("A %s may last at most %d days.", in.Kind, int(limit.Hours()/24)))
	}
	id, err := ids.At(now)
	if err != nil {
		return Silence{}, err
	}
	in.ID, in.CreatedBy, in.CreatedAt = id, who.UserID, now
	sel, _ := json.Marshal(in.Selector)
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO silences (`+silenceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, in.Kind, string(sel), ms(in.StartsAt), ms(in.EndsAt), in.Reason, in.CreatedBy, ms(now)); err != nil {
			return fmt.Errorf("insert silence: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("silence.create", "silence", id, map[string]any{
			"kind": in.Kind, "starts_at": in.StartsAt.Format(time.RFC3339), "ends_at": in.EndsAt.Format(time.RFC3339), "reason": in.Reason,
		}))
	})
	if err != nil {
		return Silence{}, err
	}
	in.State = silenceState(in, now)
	s.Kick()
	return in, nil
}

// DeleteSilence ends a silence at once (or cancels a scheduled one).
func (s *Service) DeleteSilence(ctx context.Context, id string, who Actor) error {
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM silences WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("delete silence: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.db.AppendAudit(ctx, tx, who.event("silence.delete", "silence", id, nil))
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// ListSilences returns silences newest first after the cursor; activeOnly keeps those not yet expired.
func (s *Service) ListSilences(ctx context.Context, activeOnly bool, before string, limit int) (items []Silence, next string, err error) {
	now := s.now()
	q := `SELECT ` + silenceColumns + ` FROM silences WHERE id < ?`
	args := []any{before}
	if before == "" {
		args[0] = "~"
	}
	if activeOnly {
		q += ` AND ends_at > ?`
		args = append(args, ms(now))
	}
	rows, err := s.db.DB().QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, "", fmt.Errorf("list silences: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		x, err := scanSilence(rows, now)
		if err != nil {
			return nil, "", err
		}
		items = append(items, x)
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

// activeSilences returns the silences in force at now.
func (s *Service) activeSilences(ctx context.Context, now time.Time) ([]Silence, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+silenceColumns+` FROM silences WHERE starts_at <= ? AND ends_at > ?`, ms(now), ms(now))
	if err != nil {
		return nil, fmt.Errorf("load silences: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Silence
	for rows.Next() {
		x, err := scanSilence(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ---- routes ----

// RouteList is the ordered route list with its version.
type RouteList struct {
	Routes []Route
	Rev    int64
}

// ETag identifies the stored list.
func (l RouteList) ETag() string { return `"r` + itoa(l.Rev) + `"` }

func (s *Service) loadRoutes(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
},
) (RouteList, error) {
	var l RouteList
	var rev string
	switch err := q.QueryRowContext(ctx, `SELECT value FROM alerting_state WHERE key = 'routes_rev'`).Scan(&rev); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return l, fmt.Errorf("read route version: %w", err)
	default:
		_, _ = fmt.Sscanf(rev, "%d", &l.Rev)
	}
	rows, err := q.QueryContext(ctx, `SELECT id, selector_json, channel_id, continue FROM routes ORDER BY position`)
	if err != nil {
		return l, fmt.Errorf("load routes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	l.Routes = []Route{}
	for rows.Next() {
		var r Route
		var sel string
		var cont int
		if err := rows.Scan(&r.ID, &sel, &r.ChannelID, &cont); err != nil {
			return l, err
		}
		if err := json.Unmarshal([]byte(sel), &r.Selector); err != nil {
			return l, fmt.Errorf("decode route selector: %w", err)
		}
		r.Selector, r.Continue = r.Selector.normalize(), cont == 1
		l.Routes = append(l.Routes, r)
	}
	return l, rows.Err()
}

// Routes returns the ordered route list.
func (s *Service) Routes(ctx context.Context) (RouteList, error) { return s.loadRoutes(ctx, s.db.DB()) }

// ReplaceRoutes atomically replaces the whole list if ifMatch is its current ETag. Every
// channel must exist. Alerts go to the first matching route, and on to the following ones only
// while a matching route has Continue set. An alert matching no route is recorded, not sent.
func (s *Service) ReplaceRoutes(ctx context.Context, ifMatch string, in []Route, who Actor) (RouteList, error) {
	if len(in) > MaxRoutes {
		return RouteList{}, bad("routes", "Use at most 100 routes.")
	}
	out := make([]Route, len(in))
	for i, r := range in {
		if !ulidPattern.MatchString(r.ChannelID) {
			return RouteList{}, bad(fmt.Sprintf("routes[%d].channel_id", i), "Use the ID of an existing channel.")
		}
		if err := r.Selector.validate(fmt.Sprintf("routes[%d].selector", i), true, false, true, true); err != nil {
			return RouteList{}, err
		}
		id, err := ids.New()
		if err != nil {
			return RouteList{}, err
		}
		out[i] = Route{ID: id, Selector: r.Selector.normalize(), ChannelID: r.ChannelID, Continue: r.Continue}
	}
	var list RouteList
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		cur, err := s.loadRoutes(ctx, tx)
		if err != nil {
			return err
		}
		if cur.ETag() != ifMatch {
			return ErrStale
		}
		for i, r := range out {
			var one int
			if err := tx.QueryRowContext(ctx, `SELECT 1 FROM channels WHERE id = ?`, r.ChannelID).Scan(&one); errors.Is(err, sql.ErrNoRows) {
				return bad(fmt.Sprintf("routes[%d].channel_id", i), "That channel does not exist.")
			} else if err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM routes`); err != nil {
			return fmt.Errorf("clear routes: %w", err)
		}
		for i, r := range out {
			sel, _ := json.Marshal(r.Selector)
			if _, err := tx.ExecContext(ctx, `INSERT INTO routes (id, position, selector_json, channel_id, continue) VALUES (?, ?, ?, ?, ?)`,
				r.ID, i, string(sel), r.ChannelID, b2i(r.Continue)); err != nil {
				return fmt.Errorf("insert route: %w", err)
			}
		}
		list = RouteList{Routes: out, Rev: cur.Rev + 1}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alerting_state (key, value) VALUES ('routes_rev', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, itoa(list.Rev)); err != nil {
			return fmt.Errorf("store route version: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("routes.update", "routes", "routes", map[string]any{"count": len(out)}))
	})
	if err != nil {
		return RouteList{}, err
	}
	if list.Routes == nil {
		list.Routes = []Route{}
	}
	return list, nil
}

// matchRoutes returns the channel IDs for an alert, in route order, without duplicates.
func matchRoutes(routes []Route, sub subject) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range routes {
		if !r.Selector.matches(sub) {
			continue
		}
		if !seen[r.ChannelID] {
			seen[r.ChannelID] = true
			out = append(out, r.ChannelID)
		}
		if !r.Continue {
			break
		}
	}
	return out
}
