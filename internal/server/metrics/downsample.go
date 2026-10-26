// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

// downsampleChunk bounds the work (and memory) of one step of the job.
const downsampleChunk = 6 * time.Hour

// Downsample writes 5-minute averages of full-resolution data into the 5m database.
//
// A bucket is final once its end is older than replayWindow, because the agent may
// still replay older samples until then. The job is resumable and idempotent: progress
// is the watermark file, advanced only after a chunk is committed; a crash in between
// re-writes the same averages, and the TSDB ignores a duplicate (timestamp, value).
func (s *Service) Downsample(ctx context.Context) error {
	s.dsMu.Lock()
	defer s.dsMu.Unlock()

	bucket := downStep.Milliseconds()
	now := s.now()
	upper := now.Add(-replayWindow).UnixMilli()
	upper -= upper % bucket

	start := s.watermark()
	if start == 0 {
		oldest := s.oldestFull()
		if oldest == math.MaxInt64 {
			return nil // nothing ingested yet
		}
		start = oldest - oldest%bucket
	}
	// Full-resolution data older than its retention is gone; do not chase it.
	if floor := now.Add(-s.opts.FullRetention).UnixMilli(); start < floor {
		start = floor - floor%bucket
	}

	for start < upper {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+downsampleChunk.Milliseconds(), upper)
		if err := s.downsampleRange(ctx, start, end); err != nil {
			return err
		}
		if err := s.saveWatermark(end); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (s *Service) oldestFull() int64 {
	oldest := s.store.full.Head().MinTime()
	if blocks := s.store.full.Blocks(); len(blocks) > 0 {
		oldest = min(oldest, blocks[0].Meta().MinTime)
	}
	return oldest
}

// downsampleRange averages [from, to) into buckets of downStep.
func (s *Service) downsampleRange(ctx context.Context, from, to int64) error {
	bucket := downStep.Milliseconds()
	matcher, err := labels.NewMatcher(labels.MatchRegexp, nameLabel, namesRegexp())
	if err != nil {
		return err
	}
	q, err := s.store.full.Querier(from, to-1)
	if err != nil {
		return fmt.Errorf("open querier: %w", err)
	}
	defer func() { _ = q.Close() }()

	app := s.store.down.Appender(ctx)
	set := q.Select(ctx, false, nil, matcher)
	for set.Next() {
		series := set.At()
		lset := series.Labels()
		var sum float64
		var n int
		cur := int64(-1)
		flush := func() error {
			if n == 0 {
				return nil
			}
			_, err := app.Append(0, lset, cur, sum/float64(n))
			if err != nil && !errors.Is(err, storage.ErrDuplicateSampleForTimestamp) && !errors.Is(err, storage.ErrOutOfOrderSample) && !errors.Is(err, storage.ErrOutOfBounds) && !errors.Is(err, storage.ErrTooOldSample) {
				return err
			}
			return nil
		}
		it := series.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			t, v := it.At()
			if t < from || t >= to {
				continue
			}
			if b := t - t%bucket; b != cur {
				if err := flush(); err != nil {
					_ = app.Rollback()
					return fmt.Errorf("append average: %w", err)
				}
				cur, sum, n = b, 0, 0
			}
			sum += v
			n++
		}
		if err := it.Err(); err != nil {
			_ = app.Rollback()
			return fmt.Errorf("read series: %w", err)
		}
		if err := flush(); err != nil {
			_ = app.Rollback()
			return fmt.Errorf("append average: %w", err)
		}
	}
	if err := set.Err(); err != nil {
		_ = app.Rollback()
		return fmt.Errorf("select series: %w", err)
	}
	return app.Commit()
}
