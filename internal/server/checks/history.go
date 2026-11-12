// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// prepare validates a check for saving: shape, SSRF policy for literal addresses, and the runner.
func (s *Service) prepare(ctx context.Context, c *Check) error {
	if c.AllowPrivate && s.BlockPrivate {
		return bad("allow_private", "The server administrator has blocked private-range checks.")
	}
	if err := Normalize(c, probe.Policy{AllowPrivate: c.AllowPrivate}); err != nil {
		return err
	}
	if c.Runner == RunnerServer {
		return nil
	}
	if s.Agents == nil {
		return bad("runner", "Agent-run checks are not available.")
	}
	info, err := s.Agents.AgentByID(ctx, c.Runner)
	switch {
	case errors.Is(err, gateway.ErrAgentNotFound):
		return bad("runner", "No such agent.")
	case err != nil:
		return fmt.Errorf("look up agent: %w", err)
	case info.Revoked:
		return bad("runner", "This agent is revoked.")
	}
	return nil
}

// ---- results ----

// Page of results, newest first.
type resultRow struct {
	id int64
	Result
}

// Results returns up to limit results of a check, newest first, after cursor.
func (s *Service) Results(ctx context.Context, id, cursor string, limit int) (items []Result, next string, err error) {
	if _, _, err := s.load(ctx, id); err != nil {
		return nil, "", err
	}
	ts, rowID := int64(math.MaxInt64), int64(math.MaxInt64)
	if cursor != "" {
		a, b, ok := strings.Cut(cursor, ".")
		var e1, e2 error
		ts, e1 = strconv.ParseInt(a, 10, 64)
		rowID, e2 = strconv.ParseInt(b, 10, 64)
		if !ok || e1 != nil || e2 != nil {
			return nil, "", &ValidationError{"cursor", "Use the next_cursor value of the previous page."}
		}
	}
	rows, err := s.db.DB().QueryContext(ctx, `SELECT id, ts, status, latency_ms, error_code, detail FROM check_results
		WHERE check_id = ? AND (ts < ? OR (ts = ? AND id < ?)) ORDER BY ts DESC, id DESC LIMIT ?`, id, ts, ts, rowID, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("read results: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var all []resultRow
	for rows.Next() {
		var r resultRow
		var t int64
		if err := rows.Scan(&r.id, &t, &r.Status, &r.LatencyMS, &r.ErrorCode, &r.Detail); err != nil {
			return nil, "", err
		}
		r.TS = time.UnixMilli(t).UTC()
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(all) > limit {
		all = all[:limit]
		last := all[limit-1]
		next = strconv.FormatInt(last.TS.UnixMilli(), 10) + "." + strconv.FormatInt(last.id, 10)
	}
	for _, r := range all {
		items = append(items, r.Result)
	}
	return items, next, nil
}

// ---- uptime ----

const dayMs = int64(24 * time.Hour / time.Millisecond)

// secondsIn counts the up and down seconds of raw results in [from, to) milliseconds; each
// result stands for one interval of its status, and unknown results count for nothing.
func (s *Service) secondsIn(ctx context.Context, id string, from, to int64) (up, down int64, err error) {
	err = s.db.DB().QueryRowContext(ctx, `SELECT
		COALESCE(SUM(r.status = 'up'), 0) * c.interval_s, COALESCE(SUM(r.status = 'down'), 0) * c.interval_s
		FROM checks c LEFT JOIN check_results r ON r.check_id = c.id AND r.ts >= ? AND r.ts < ? WHERE c.id = ?`, from, to, id).Scan(&up, &down)
	return up, down, err
}

// Uptime computes uptime % over 24h, 7d, 30d and 90d from raw results and daily rollups.
func (s *Service) Uptime(ctx context.Context, id string) (Uptime, error) {
	if _, _, err := s.load(ctx, id); err != nil {
		return Uptime{}, err
	}
	now := s.clock.Now().UTC().UnixMilli()
	var u Uptime
	for _, w := range []struct {
		dst *(*float64)
		d   time.Duration
	}{{&u.H24, 24 * time.Hour}, {&u.D7, 7 * 24 * time.Hour}, {&u.D30, 30 * 24 * time.Hour}, {&u.D90, 90 * 24 * time.Hour}} {
		up, down, err := s.window(ctx, id, now-w.d.Milliseconds(), now+1)
		if err != nil {
			return Uptime{}, err
		}
		if up+down > 0 {
			v := math.Round(float64(up)/float64(up+down)*100000) / 1000
			*w.dst = &v
		}
	}
	return u, nil
}

// window sums [from, to) using rollups for whole UTC days and raw results for the edges.
func (s *Service) window(ctx context.Context, id string, from, to int64) (up, down int64, err error) {
	firstFull := (from + dayMs - 1) / dayMs * dayMs
	lastFull := to / dayMs * dayMs
	if firstFull >= lastFull {
		return s.secondsIn(ctx, id, from, to)
	}
	add := func(u, d int64, err error) error {
		up, down = up+u, down+d
		return err
	}
	if err := add(s.secondsIn(ctx, id, from, firstFull)); err != nil {
		return 0, 0, err
	}
	if err := add(s.secondsIn(ctx, id, lastFull, to)); err != nil {
		return 0, 0, err
	}
	rolled := map[int64][2]int64{}
	rows, err := s.db.DB().QueryContext(ctx, `SELECT day, up_s, down_s FROM check_rollups_daily WHERE check_id = ? AND day >= ? AND day < ?`, id, firstFull/1000, lastFull/1000)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var day, u, d int64
		if err := rows.Scan(&day, &u, &d); err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		rolled[day] = [2]int64{u, d}
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}
	for day := firstFull; day < lastFull; day += dayMs {
		if r, ok := rolled[day/1000]; ok { // an unrolled day is computed from raw results
			up, down = up+r[0], down+r[1]
			continue
		}
		if err := add(s.secondsIn(ctx, id, day, day+dayMs)); err != nil {
			return 0, 0, err
		}
	}
	return up, down, nil
}

// ---- maintenance ----

// Maintain rolls completed days up into check_rollups_daily, then prunes raw results older
// than 90 days and rollups older than 400 days. It is idempotent and safe to run any time.
func (s *Service) Maintain(ctx context.Context) error {
	now := s.clock.Now().UTC()
	today := now.UnixMilli() / dayMs * dayMs
	return s.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO check_rollups_daily (check_id, day, up_s, down_s, avg_latency_ms)
			SELECT r.check_id, r.ts / ? * 86400,
			       SUM(r.status = 'up') * c.interval_s, SUM(r.status = 'down') * c.interval_s,
			       COALESCE(CAST(AVG(CASE WHEN r.status = 'up' THEN r.latency_ms END) AS INTEGER), 0)
			FROM check_results r JOIN checks c ON c.id = r.check_id WHERE r.ts < ? GROUP BY r.check_id, r.ts / ?`, dayMs, today, dayMs); err != nil {
			return fmt.Errorf("roll up results: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM check_results WHERE ts < ?`, now.Add(-ResultRetention).UnixMilli()); err != nil {
			return fmt.Errorf("prune results: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM check_rollups_daily WHERE day < ?`, now.Add(-RollupRetention).Unix()); err != nil {
			return fmt.Errorf("prune rollups: %w", err)
		}
		return nil
	})
}

// ---- state ----

// State is the current status of one check, for consumers that resync after a lagged subscription.
type State struct {
	CheckID string
	Name    string
	Enabled bool
	Status  Status
}

// States lists the current status of every check.
func (s *Service) States(ctx context.Context) ([]State, error) {
	items, _, err := s.List(ctx, "", 1_000_000)
	if err != nil {
		return nil, err
	}
	out := make([]State, 0, len(items))
	for _, v := range items {
		out = append(out, State{CheckID: v.ID, Name: v.Name, Enabled: v.Enabled, Status: v.Status})
	}
	return out, nil
}
