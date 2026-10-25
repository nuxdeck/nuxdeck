// SPDX-License-Identifier: Apache-2.0

package run

import (
	"math/rand/v2"
	"time"
)

const (
	backoffMin = time.Second
	backoffMax = 60 * time.Second
	// stableAfter is how long a connection must last before the next failure starts from the minimum again.
	stableAfter = 30 * time.Second
)

// Backoff produces reconnect delays: exponential from min to max with equal jitter, so
// a fleet of agents that lost the server together does not return together.
type Backoff struct {
	Min, Max time.Duration
	// Rand returns a value in [0, 1); nil means math/rand/v2.
	Rand    func() float64
	attempt int
}

// Next returns the delay before the next attempt.
func (b *Backoff) Next() time.Duration {
	lo, hi := b.Min, b.Max
	if lo <= 0 {
		lo = backoffMin
	}
	if hi < lo {
		hi = backoffMax
	}
	d := lo
	for i := 0; i < b.attempt && d < hi; i++ {
		d *= 2
	}
	if d > hi {
		d = hi
	}
	b.attempt++
	r := rand.Float64
	if b.Rand != nil {
		r = b.Rand
	}
	return d/2 + time.Duration(r()*float64(d/2))
}

// Reset starts the sequence over after a healthy connection.
func (b *Backoff) Reset() { b.attempt = 0 }
