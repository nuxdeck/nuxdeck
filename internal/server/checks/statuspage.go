// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/statuspages"
)

var _ statuspages.CheckSource = (*Service)(nil)

// ExistingIDs returns the subset of ids that are checks.
func (s *Service) ExistingIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.DB().QueryContext(ctx, `SELECT id FROM checks WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("look up checks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// StatusStates maps every check ID to up, down or unknown; a disabled check is unknown.
func (s *Service) StatusStates(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT c.id, c.enabled, COALESCE(st.status, 'unknown') FROM checks c LEFT JOIN check_state st ON st.check_id = c.id`)
	if err != nil {
		return nil, fmt.Errorf("read check states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, st string
		var enabled int
		if err := rows.Scan(&id, &enabled, &st); err != nil {
			return nil, err
		}
		if enabled == 0 {
			st = StateUnknown
		}
		out[id] = st
	}
	return out, rows.Err()
}

// DailyUptime returns up and down seconds per UTC day for every check: `days` days from
// first (index 0). A rolled-up day wins over raw results, which fill the days not yet rolled up.
func (s *Service) DailyUptime(ctx context.Context, first time.Time, days int) (map[string][]statuspages.DaySeconds, error) {
	from := first.UTC().UnixMilli()
	to := from + int64(days)*dayMs
	out := map[string][]statuspages.DaySeconds{}
	row := func(id string, dayMsStart int64) *statuspages.DaySeconds {
		i := int((dayMsStart - from) / dayMs)
		if i < 0 || i >= days {
			return nil
		}
		if out[id] == nil {
			out[id] = make([]statuspages.DaySeconds, days)
		}
		return &out[id][i]
	}
	raw, err := s.db.DB().QueryContext(ctx, `SELECT r.check_id, r.ts / ? * ?, SUM(r.status = 'up') * c.interval_s, SUM(r.status = 'down') * c.interval_s
		FROM check_results r JOIN checks c ON c.id = r.check_id WHERE r.ts >= ? AND r.ts < ? GROUP BY r.check_id, r.ts / ?`, dayMs, dayMs, from, to, dayMs)
	if err != nil {
		return nil, fmt.Errorf("read raw uptime: %w", err)
	}
	for raw.Next() {
		var id string
		var d, u, dn int64
		if err := raw.Scan(&id, &d, &u, &dn); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if r := row(id, d); r != nil {
			r.Up, r.Down = u, dn
		}
	}
	if err := raw.Close(); err != nil {
		return nil, err
	}
	rolled, err := s.db.DB().QueryContext(ctx, `SELECT check_id, day, up_s, down_s FROM check_rollups_daily WHERE day >= ? AND day < ?`, from/1000, to/1000)
	if err != nil {
		return nil, fmt.Errorf("read rollups: %w", err)
	}
	defer func() { _ = rolled.Close() }()
	for rolled.Next() {
		var id string
		var d, u, dn int64
		if err := rolled.Scan(&id, &d, &u, &dn); err != nil {
			return nil, err
		}
		if r := row(id, d*1000); r != nil {
			r.Up, r.Down = u, dn
		}
	}
	return out, rolled.Err()
}
