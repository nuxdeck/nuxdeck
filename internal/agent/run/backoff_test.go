// SPDX-License-Identifier: Apache-2.0

package run

import (
	"testing"
	"time"
)

func TestAGT5_BackoffGrowsExponentiallyToACap(t *testing.T) {
	b := &Backoff{Rand: func() float64 { return 0.999999 }} // top of the jitter range
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		got := b.Next()
		if lo, hi := w*time.Second/2, w*time.Second; got < lo || got > hi {
			t.Errorf("attempt %d = %v, want within [%v, %v]", i, got, lo, hi)
		}
	}
}

func TestAGT5_BackoffJitterSpreadsAgents(t *testing.T) {
	low := (&Backoff{Rand: func() float64 { return 0 }}).Next()
	high := (&Backoff{Rand: func() float64 { return 0.999 }}).Next()
	if low != 500*time.Millisecond || high < 990*time.Millisecond || high >= time.Second {
		t.Errorf("first delay spans [%v, %v], want about [500ms, 1s)", low, high)
	}
	for range 200 {
		if d := (&Backoff{}).Next(); d < 500*time.Millisecond || d >= time.Second {
			t.Fatalf("first delay %v outside [500ms, 1s)", d)
		}
	}
}

func TestAGT5_BackoffResetsAfterAStableConnection(t *testing.T) {
	b := &Backoff{Rand: func() float64 { return 0 }}
	for range 5 {
		b.Next()
	}
	b.Reset()
	if got := b.Next(); got != 500*time.Millisecond {
		t.Errorf("after Reset the delay is %v, want the minimum", got)
	}
}
