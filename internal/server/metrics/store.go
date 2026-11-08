// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/prometheus/tsdb"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Retention defaults (MET-5).
const (
	DefaultFullRetention        = 15 * 24 * time.Hour
	DefaultDownsampledRetention = 90 * 24 * time.Hour

	// replayWindow is how far in the past a sample may be. The agent buffers 15
	// minutes; the margin covers clock drift. The TSDBs accept out-of-order
	// writes inside the same window so a replayed batch can interleave with live ones.
	replayWindow = 30 * time.Minute
	futureSkew   = 5 * time.Minute
)

// Store owns the two TSDBs.
type Store struct {
	full *tsdb.DB
	down *tsdb.DB
	dir  string
}

// openStore opens (creating) <dir>/full and <dir>/5m.
func openStore(dir string, fullRetention, downRetention time.Duration, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "create metrics directory", err)
	}
	open := func(name string, retention, ooo time.Duration) (*tsdb.DB, error) {
		opts := tsdb.DefaultOptions()
		opts.RetentionDuration = retention.Milliseconds()
		opts.OutOfOrderTimeWindow = ooo.Milliseconds()
		db, err := tsdb.Open(filepath.Join(dir, name), log.With("component", "tsdb", "db", name), nil, opts, nil)
		if err != nil {
			return nil, errcode.Wrap(errcode.SRVIO001, "open metrics database "+name, err)
		}
		return db, nil
	}
	full, err := open("full", fullRetention, replayWindow)
	if err != nil {
		return nil, err
	}
	down, err := open("5m", downRetention, 2*time.Hour)
	if err != nil {
		return nil, errors.Join(err, full.Close())
	}
	return &Store{full: full, down: down, dir: dir}, nil
}

func (s *Store) close() error {
	var errs []error
	for name, db := range map[string]*tsdb.DB{"full": s.full, "5m": s.down} {
		if err := db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s metrics database: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
