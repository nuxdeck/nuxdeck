// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import "time"

// tokenBucket admits messages at a steady rate with a bounded burst. It is not safe for
// concurrent use: each stream owns its bucket and only its handler goroutine touches it.
type tokenBucket struct {
	rate   float64 // tokens added per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rate float64, burst int, now func() time.Time) *tokenBucket {
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// allow takes one token and reports whether the message may pass.
func (b *tokenBucket) allow() bool {
	now := b.now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
