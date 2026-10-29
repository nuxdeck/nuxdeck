// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Collection interval default and bounds (MET-4).
const (
	DefaultInterval = 15 * time.Second
	MinInterval     = 5 * time.Second
	MaxInterval     = 60 * time.Second

	collectorHost       = "host_metrics"
	collectorContainers = "container_metrics"
)

// ClampInterval turns the server's seconds into a collection interval: 0 means the default,
// anything else is held to 5..60 s (MET-4).
func ClampInterval(seconds uint32) time.Duration {
	if seconds == 0 {
		return DefaultInterval
	}
	return min(max(time.Duration(seconds)*time.Second, MinInterval), MaxInterval)
}

// Config is the service's settings.
type Config struct {
	// Root is the filesystem root /proc and /sys are read below; "" means /.
	Root string
	// SockguardSocket is used for the container stats API fallback; "" disables it.
	SockguardSocket string
	// Containers lists the inventory's containers (runtime id, state, restart count).
	Containers func() []*agentv1.Container
	Log        *slog.Logger
	Now        func() time.Time
	// Buffer overrides the default 15 minute buffer; tests use it.
	Buffer *Buffer

	statfs statfsFunc
}

// Service samples on an interval into the buffer and serves batches to the stream.
type Service struct {
	cfg  Config
	buf  *Buffer
	host *hostCollector
	ctrs *containerCollector

	notify   chan struct{}
	interval chan time.Duration

	mu     sync.Mutex
	cur    time.Duration
	errs   map[string]*agentv1.CollectorError
	series map[string]*seriesID
	// counters absorbs resets: emitted = offset + raw, so the output never goes backwards.
	counters map[string]*counterState
}

type counterState struct {
	last, offset float64
	seen         bool
}

// New creates a service. Call Run to start sampling.
func New(cfg Config) *Service {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Buffer == nil {
		cfg.Buffer = NewBuffer(Retention, DefaultMaxSamples, cfg.Now)
	}
	return &Service{
		cfg: cfg, buf: cfg.Buffer,
		host:     newHostCollector(cfg.Root, cfg.statfs),
		ctrs:     newContainerCollector(cfg.Root, cfg.SockguardSocket, cfg.Containers),
		notify:   make(chan struct{}, 1),
		interval: make(chan time.Duration, 1),
		cur:      DefaultInterval,
		errs:     map[string]*agentv1.CollectorError{},
		series:   map[string]*seriesID{},
		counters: map[string]*counterState{},
	}
}

// SetInterval applies HelloAck.metric_interval_seconds or ConfigUpdate; it takes effect immediately.
func (s *Service) SetInterval(seconds uint32) {
	d := ClampInterval(seconds)
	s.mu.Lock()
	changed := d != s.cur
	s.cur = d
	s.mu.Unlock()
	if !changed {
		return
	}
	select {
	case <-s.interval: // replace a pending, stale value
	default:
	}
	s.interval <- d
}

// Interval is the interval currently in force.
func (s *Service) Interval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Notify signals that new samples were buffered.
func (s *Service) Notify() <-chan struct{} { return s.notify }

// Next returns the oldest unsent batch, or nil. Samples older than replayBefore are marked
// replayed. Call commit once the batch was sent.
func (s *Service) Next(replayBefore time.Time) (*agentv1.MetricBatch, func()) {
	return s.buf.next(replayBefore.UnixMilli())
}

// Errors lists the collectors that failed on the last tick.
func (s *Service) Errors() []*agentv1.CollectorError {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*agentv1.CollectorError, 0, len(s.errs))
	for _, e := range s.errs {
		out = append(out, e)
	}
	return out
}

// Run samples once at start, then every interval, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-s.interval:
			t.Reset(d)
		case <-t.C:
			s.Tick(ctx)
			t.Reset(s.Interval())
		}
	}
}

// Tick collects once. A failing collector is recorded and the others still run.
func (s *Service) Tick(ctx context.Context) {
	now := s.cfg.Now()
	hr, herr := s.host.collect()
	cr, cerr := s.ctrs.collect(ctx, now)
	s.setErr(collectorHost, errcode.AGTCol003, herr, now)
	s.setErr(collectorContainers, errcode.AGTCol004, cerr, now)

	ts := now.UnixMilli()
	s.mu.Lock()
	batch := make([]sample, 0, len(hr)+len(cr))
	seen := make(map[string]bool, len(hr)+len(cr))
	for _, r := range append(hr, cr...) {
		k := r.key()
		seen[k] = true
		v := r.value
		if r.counter {
			v = s.normalise(k, v)
		}
		id, ok := s.series[k]
		if !ok {
			id = newSeriesID(r.target, r.id, r.metric, r.labels)
			s.series[k] = id
		}
		batch = append(batch, sample{s: id, ts: ts, v: v})
	}
	for k := range s.series { // forget series that vanished (stopped containers, removed disks)
		if !seen[k] {
			delete(s.series, k)
			delete(s.counters, k)
		}
	}
	s.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	s.buf.push(batch)
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// normalise must be called with s.mu held.
func (s *Service) normalise(key string, raw float64) float64 {
	c := s.counters[key]
	if c == nil {
		c = &counterState{}
		s.counters[key] = c
	}
	if c.seen && raw < c.last {
		c.offset += c.last
	}
	c.last, c.seen = raw, true
	return c.offset + raw
}

func (s *Service) setErr(name string, code errcode.Code, err error, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.errs, name)
		return
	}
	if _, had := s.errs[name]; !had {
		s.cfg.Log.Warn("metric collector failed", "collector", name, "code", string(code), "error", err)
	}
	s.errs[name] = &agentv1.CollectorError{Collector: name, Code: string(code), AtUnixMs: now.UnixMilli()}
}
