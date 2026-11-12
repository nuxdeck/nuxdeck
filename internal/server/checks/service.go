// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Defaults.
const (
	DefaultMaxConcurrent = 32
	DefaultRetryDelay    = 2 * time.Second
	// maxJitter bounds the first-run offset so a new check reports soon while checks still spread out.
	maxJitter = 30 * time.Second
	// pendingGrace is how long past a check's timeout an agent may take to answer.
	pendingGrace = 10 * time.Second
	maxPending   = 4096
	// ManualRunGap is the least time between on-demand runs of one check.
	ManualRunGap    = 5 * time.Second
	maintenanceGap  = time.Hour
	ResultRetention = 90 * 24 * time.Hour
	RollupRetention = 400 * 24 * time.Hour
)

// Clock is the time source; tests substitute a fake so nothing sleeps.
type Clock interface {
	Now() time.Time
	// Sleep waits d or until ctx ends.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AgentDirectory looks up enrolled agents; *store.Store implements it.
type AgentDirectory interface {
	AgentByID(ctx context.Context, id string) (gateway.AgentInfo, error)
}

// Sender delivers a message to an agent without blocking; *gateway.Gateway implements it.
type Sender interface {
	SendToAgent(agentID string, m *agentv1.ServerMessage) error
}

// Options are the service's dependencies.
type Options struct {
	DB      *store.Store
	Secrets *secrets.Box
	Agents  AgentDirectory
	Sender  Sender
	Log     *slog.Logger
	Clock   Clock
	// BlockPrivate refuses allow_private on every check (checks.block_private).
	BlockPrivate  bool
	MaxConcurrent int
	RetryDelay    time.Duration

	// The fields below exist for tests.

	// Inline runs scheduled checks on the caller's goroutine inside Tick.
	Inline bool
	// Policy overrides the SSRF policy of server-run checks.
	Policy func(Check) probe.Policy
	// Exec overrides the probe runner of server-run checks.
	Exec func(ctx context.Context, p probe.Policy, s probe.Spec) probe.Result
}

// Service owns the checks: their storage, schedule, execution and history.
type Service struct {
	Options
	box   *secrets.Box
	db    *store.Store
	clock Clock
	hub   *Hub

	mu          sync.Mutex
	next        map[string]time.Time
	running     map[string]bool
	lastManual  map[string]time.Time
	pending     map[string]*pending
	lastMaint   time.Time
	sem         chan struct{}
	wg          sync.WaitGroup
	ignoredMsgs int
}

// New builds a Service. Call Run to start the schedule.
func New(o Options) *Service {
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = DefaultMaxConcurrent
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = DefaultRetryDelay
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Service{
		Options: o, box: o.Secrets, db: o.DB, clock: o.Clock, hub: NewHub(),
		next: map[string]time.Time{}, running: map[string]bool{}, lastManual: map[string]time.Time{}, pending: map[string]*pending{},
		sem: make(chan struct{}, o.MaxConcurrent),
	}
}

// Hub exposes the state-change stream.
// Hub exposes the state-change stream.
func (s *Service) Hub() *Hub { return s.hub }

// Offset is the stable delay of a check's first run, spreading checks over time.
func Offset(id string, interval time.Duration) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	window := min(interval, maxJitter)
	slots := int64(window / time.Millisecond)
	return time.Duration(int64(h.Sum32())%slots) * time.Millisecond
}

func (s *Service) schedule(c Check) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !c.Enabled {
		delete(s.next, c.ID)
		return
	}
	s.next[c.ID] = s.clock.Now().Add(Offset(c.ID, time.Duration(c.IntervalS)*time.Second))
}

func (s *Service) unschedule(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.next, id)
	delete(s.lastManual, id)
}

// Load schedules every enabled check in the database.
func (s *Service) Load(ctx context.Context) error {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var cs []Check
	for rows.Next() {
		c, _, err := scanCheck(rows)
		if err != nil {
			return err
		}
		cs = append(cs, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cs {
		s.schedule(c)
	}
	return nil
}

// Run loads the schedule and drives it until ctx ends, then waits for running checks.
func (s *Service) Run(ctx context.Context) error {
	if err := s.Load(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return nil
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick starts every check that is due at the clock's time, expires unanswered agent requests
// and runs the daily maintenance when it is time. Run calls it every second.
func (s *Service) Tick(ctx context.Context) {
	now := s.clock.Now()
	s.reapPending(now)
	s.mu.Lock()
	var due []string
	for id, at := range s.next {
		if !at.After(now) && !s.running[id] {
			due = append(due, id)
		}
	}
	maint := now.Sub(s.lastMaint) >= maintenanceGap
	if maint {
		s.lastMaint = now
	}
	s.mu.Unlock()

	for _, id := range due {
		s.spawn(ctx, id)
	}
	if maint {
		if err := s.Maintain(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("check maintenance failed", "error", err)
		}
	}
}

// spawn runs one scheduled check on a worker, if one is free; otherwise it stays due.
func (s *Service) spawn(ctx context.Context, id string) {
	s.mu.Lock()
	if s.running[id] {
		s.mu.Unlock()
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.mu.Unlock()
		return
	}
	s.running[id] = true
	s.mu.Unlock()

	work := func() {
		defer func() {
			<-s.sem
			s.mu.Lock()
			delete(s.running, id)
			s.mu.Unlock()
		}()
		c, refs, err := s.load(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				s.unschedule(id)
			}
			return
		}
		start := s.clock.Now()
		s.mu.Lock()
		if _, ok := s.next[id]; ok { // not unscheduled meanwhile
			s.next[id] = start.Add(time.Duration(c.IntervalS) * time.Second)
		}
		s.mu.Unlock()
		out := s.execute(ctx, c, refs, c.Retries)
		if err := s.record(ctx, c, out, nil); err != nil && ctx.Err() == nil {
			s.Log.Error("record check result", "check_id", id, "error", err)
		}
	}
	if s.Inline {
		work()
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		work()
	}()
}
