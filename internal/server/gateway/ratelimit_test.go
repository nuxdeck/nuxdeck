// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"testing"
	"time"
)

func TestTokenBucketAdmitsBurstThenRefillsAtRate(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	b := newTokenBucket(2, 3, clock) // 2 per second, burst of 3

	for i := range 3 {
		if !b.allow() {
			t.Fatalf("message %d of the burst was refused", i+1)
		}
	}
	if b.allow() {
		t.Fatal("a fourth message at the same instant was admitted")
	}
	now = now.Add(500 * time.Millisecond) // one token earned
	if !b.allow() {
		t.Fatal("one token should have refilled after 500ms at 2/s")
	}
	if b.allow() {
		t.Fatal("only one token should have refilled")
	}
	now = now.Add(time.Hour)
	for i := range 3 {
		if !b.allow() {
			t.Fatalf("refill is capped at the burst; message %d refused", i+1)
		}
	}
	if b.allow() {
		t.Fatal("refill exceeded the burst")
	}
}
