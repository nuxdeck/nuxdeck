// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"slices"
	"sync"
	"time"
)

const maxTrackedKeys = 10_000

// Limiter counts failures per key in a fixed window. It guards unauthenticated
// requests so they cannot flood the audit log, and per-address sign-in attempts.
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	seen   map[string]*bucket
}

type bucket struct {
	count int
	start time.Time
}

// NewLimiter allows limit failures per key per window.
func NewLimiter(limit int, window time.Duration, now func() time.Time) *Limiter {
	return &Limiter{max: limit, window: window, now: now, seen: map[string]*bucket{}}
}

// Blocked reports whether key has used up its failures in the current window.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.seen[key]
	return ok && l.now().Sub(b.start) < l.window && b.count >= l.max
}

// Fail records a failure for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, ok := l.seen[key]; !ok && len(l.seen) >= maxTrackedKeys {
		evictOldest(l.seen, maxTrackedKeys, func(b *bucket) bool { return now.Sub(b.start) >= l.window }, func(b *bucket) time.Time { return b.start })
	}
	b, ok := l.seen[key]
	if !ok || now.Sub(b.start) >= l.window {
		l.seen[key] = &bucket{count: 1, start: now}
		return
	}
	b.count++
}

// evictOldest makes room for one new key in a table capped at limit. Expired
// entries go first. If the table is still full, the entries whose windows
// started longest ago go, so one key's churn can never clear another key's
// live lock. Each eviction costs one sort of the table, which is negligible
// beside the password hash every failed sign-in already pays.
func evictOldest[V any](m map[string]V, limit int, expired func(V) bool, started func(V) time.Time) {
	for k, v := range m {
		if expired(v) {
			delete(m, k)
		}
	}
	excess := len(m) - limit + 1
	if excess <= 0 {
		return
	}
	type entry struct {
		key string
		at  time.Time
	}
	entries := make([]entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, entry{k, started(v)})
	}
	slices.SortFunc(entries, func(a, b entry) int { return a.at.Compare(b.at) })
	for _, e := range entries[:excess] {
		delete(m, e.key)
	}
}

// accountGuard counts failed sign-ins per account, whatever address they came
// from, and applies an increasing back-off once failures pass a threshold that
// is well above the per-address limit. A distributed guesser therefore cannot
// stay under the per-address limit indefinitely.
//
// Trade-off: while the back-off runs, the correct password is refused too, so
// an attacker who keeps failing can delay the real owner. The back-off is
// capped, so the owner regains access on their own, and an administrator
// clears it at once with a password reset (Accounts.ResetUser). Without this
// cap the lock would be a denial-of-service lever; without the lock a guesser
// could try passwords at the speed of the per-address limit from many addresses.
type accountGuard struct {
	mu        sync.Mutex
	threshold int
	base      time.Duration
	ceiling   time.Duration
	idleReset time.Duration
	now       func() time.Time
	seen      map[string]*accountState
}

type accountState struct {
	failures int
	last     time.Time
}

func newAccountGuard(threshold int, base, ceiling, idleReset time.Duration, now func() time.Time) *accountGuard {
	return &accountGuard{threshold: threshold, base: base, ceiling: ceiling, idleReset: idleReset, now: now, seen: map[string]*accountState{}}
}

// Blocked reports whether key is inside the back-off that its failures earned.
func (g *accountGuard) Blocked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.seen[key]
	if !ok {
		return false
	}
	since := g.now().Sub(st.last)
	if since >= g.idleReset {
		delete(g.seen, key)
		return false
	}
	return st.failures >= g.threshold && since < g.backoff(st.failures)
}

// Fail records a failed sign-in for key.
func (g *accountGuard) Fail(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st, ok := g.seen[key]
	if !ok {
		if len(g.seen) >= maxTrackedKeys {
			evictOldest(g.seen, maxTrackedKeys, func(s *accountState) bool { return now.Sub(s.last) >= g.idleReset }, func(s *accountState) time.Time { return s.last })
		}
		st = &accountState{}
		g.seen[key] = st
	}
	if now.Sub(st.last) >= g.idleReset {
		st.failures = 0
	}
	st.failures++
	st.last = now
}

// Reset forgets key's failures, after a successful sign-in or a password reset.
func (g *accountGuard) Reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.seen, key)
}

// backoff doubles from base for each failure past the threshold, up to ceiling.
func (g *accountGuard) backoff(failures int) time.Duration {
	d := g.base
	for i := g.threshold; i < failures && d < g.ceiling; i++ {
		d *= 2
	}
	return min(d, g.ceiling)
}
