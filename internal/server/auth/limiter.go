// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"sync"
	"time"
)

const maxTrackedKeys = 10_000

// Limiter counts failures per key in a fixed window. It is an interim guard so
// unauthenticated requests cannot flood the audit log; account lockout and
// per-account limits arrive with NUX-35.
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
	if len(l.seen) >= maxTrackedKeys {
		for k, b := range l.seen {
			if now.Sub(b.start) >= l.window {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= maxTrackedKeys { // all keys are live: drop the table rather than grow without bound
			l.seen = map[string]*bucket{}
		}
	}
	b, ok := l.seen[key]
	if !ok || now.Sub(b.start) >= l.window {
		l.seen[key] = &bucket{count: 1, start: now}
		return
	}
	b.count++
}
