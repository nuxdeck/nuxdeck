// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"math"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

// WriteForTest appends one sample every interval for each of lbls into the full-resolution database,
// bypassing ingest limits so tests can seed history. It exists for tests only.
func WriteForTest(s *Service, lbls []labels.Labels, from, to time.Time, interval time.Duration) (int, error) {
	app := s.store.full.Appender(context.Background())
	n := 0
	for ts := from; !ts.After(to); ts = ts.Add(interval) {
		for _, lbl := range lbls {
			if _, err := app.Append(0, lbl, ts.UnixMilli(), math.Mod(float64(n), 100)/100); err != nil {
				_ = app.Rollback()
				return n, err
			}
			n++
		}
	}
	return n, app.Commit()
}

// OldestForTest returns the oldest full-resolution timestamp held. Tests only.
func OldestForTest(s *Service) int64 { return s.oldestFull() }

// WriteDownForTest appends one sample every interval for each of lbls into the 5-minute database. Tests only.
func WriteDownForTest(s *Service, lbls []labels.Labels, from, to time.Time, interval time.Duration) (int, error) {
	app := s.store.down.Appender(context.Background())
	n := 0
	for ts := from; !ts.After(to); ts = ts.Add(interval) {
		for _, lbl := range lbls {
			if _, err := app.Append(0, lbl, ts.UnixMilli(), math.Mod(float64(n), 100)/100); err != nil {
				_ = app.Rollback()
				return n, err
			}
			n++
		}
	}
	return n, app.Commit()
}

// OldestDownForTest returns the oldest 5-minute timestamp held. Tests only.
func OldestDownForTest(s *Service) int64 {
	oldest := s.store.down.Head().MinTime()
	if blocks := s.store.down.Blocks(); len(blocks) > 0 {
		oldest = min(oldest, blocks[0].Meta().MinTime)
	}
	return oldest
}
