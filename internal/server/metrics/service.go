// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/prometheus/storage"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Options are the service's dependencies and settings.
type Options struct {
	// Dir is the TSDB parent directory, normally <data_dir>/tsdb.
	Dir       string
	Log       *slog.Logger
	Inventory Inventory
	// FullRetention and DownsampledRetention default to MET-5 (15 and 90 days).
	FullRetention, DownsampledRetention time.Duration
	// Interval is how often the downsampling job runs; default one hour.
	Interval time.Duration
	// Now supplies the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the metrics module.
type Service struct {
	opts   Options
	log    *slog.Logger
	store  *Store
	ing    *ingestor
	now    func() time.Time
	wm     atomic.Int64 // downsampled up to here (unix ms, exclusive); 0 until the first run
	dsMu   sync.Mutex   // serialises downsampling runs
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Open opens the databases and loads the downsampling watermark. Call Run to start
// the hourly job and Close to flush and release the databases.
func Open(o Options) (*Service, error) {
	if o.FullRetention <= 0 {
		o.FullRetention = DefaultFullRetention
	}
	if o.DownsampledRetention <= 0 {
		o.DownsampledRetention = DefaultDownsampledRetention
	}
	if o.Interval <= 0 {
		o.Interval = time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil || o.Inventory == nil || o.Dir == "" {
		return nil, errors.New("metrics: Dir, Log and Inventory are required")
	}
	st, err := openStore(o.Dir, o.FullRetention, o.DownsampledRetention, o.Log)
	if err != nil {
		return nil, err
	}
	s := &Service{opts: o, log: o.Log, store: st, now: o.Now}
	s.ing = newIngestor(o.Log, o.Inventory, func(ctx context.Context) storage.Appender { return st.full.Appender(ctx) }, o.Now)
	wm, err := s.loadWatermark()
	if err != nil {
		return nil, errors.Join(err, st.close())
	}
	s.wm.Store(wm)
	return s, nil
}

// HandleMessage is the gateway hook: it consumes metric batches and ignores the rest.
// agentID comes from the client certificate.
func (s *Service) HandleMessage(agentID string, m *agentv1.AgentMessage) {
	if b := m.GetMetrics(); b != nil {
		s.ing.handle(context.Background(), agentID, b)
	}
}

// Stats reports ingest counters.
func (s *Service) Stats() Stats { return s.ing.stats() }

// Run starts the hourly downsampling and retention job and returns at once. It stops on
// ctx or Close.
func (s *Service) Run(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.opts.Interval)
		defer t.Stop()
		for {
			if err := s.Maintain(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("metrics maintenance failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Maintain downsamples what is ready and lets the databases drop expired blocks (MET-5).
func (s *Service) Maintain(ctx context.Context) error {
	if err := s.Downsample(ctx); err != nil {
		return fmt.Errorf("downsample: %w", err)
	}
	// Compaction turns old head data into blocks, which is when the TSDB deletes blocks
	// beyond retention.
	return errors.Join(s.store.full.Compact(ctx), s.store.down.Compact(ctx))
}

// Close stops the job and closes the databases.
func (s *Service) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return s.store.close()
}

func (s *Service) watermark() int64 { return s.wm.Load() }

func (s *Service) watermarkPath() string { return filepath.Join(s.opts.Dir, "downsample.watermark") }

func (s *Service) loadWatermark() (int64, error) {
	b, err := os.ReadFile(s.watermarkPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, errcode.Wrap(errcode.SRVIO001, "read downsample watermark", err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v < 0 {
		s.log.Warn("ignoring unreadable downsample watermark; downsampling restarts from the oldest full-resolution data")
		return 0, nil
	}
	return v, nil
}

func (s *Service) saveWatermark(v int64) error {
	tmp := s.watermarkPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(v, 10)), 0o600); err != nil {
		return errcode.Wrap(errcode.SRVIO001, "write downsample watermark", err)
	}
	if err := os.Rename(tmp, s.watermarkPath()); err != nil {
		return errcode.Wrap(errcode.SRVIO001, "write downsample watermark", err)
	}
	s.wm.Store(v)
	return nil
}
