// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"sync"
	"time"
)

// breaker is a small circuit breaker: after threshold consecutive failures it opens for
// cooldown, then lets one trial request through (half-open); the trial's outcome closes or
// re-opens it.
type breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
	trial     bool // a half-open trial is in flight
}

// allow reports whether a request may go out at now.
func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return true
	}
	if now.Before(b.openUntil) || b.trial {
		return false
	}
	b.trial = true
	return true
}

// record reports the outcome of a request that allow (or a bypass) let through.
func (b *breaker) record(now time.Time, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trial = false
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = now.Add(b.cooldown)
	}
}

func (b *breaker) state(now time.Time) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.failures < b.threshold:
		return "closed"
	case now.Before(b.openUntil):
		return "open"
	default:
		return "half-open"
	}
}
