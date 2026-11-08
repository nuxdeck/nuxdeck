// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func TestACC7_LimiterEvictionNeverClearsRecentLocks(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	l := NewLimiter(1, time.Hour, clock.Now)

	// The old, live keys fill the table first.
	for i := range maxTrackedKeys - 1 {
		l.Fail(fmt.Sprintf("old-%d", i))
	}
	clock.Advance(time.Minute)
	l.Fail("recent")
	if !l.Blocked("recent") {
		t.Fatal("recent key must be blocked after one failure with limit 1")
	}

	// Churn: every new key evicts the oldest live key, never the recent lock.
	for i := range 500 {
		l.Fail(fmt.Sprintf("new-%d", i))
	}
	if !l.Blocked("recent") {
		t.Error("eviction cleared a recent lock; only the oldest entries may go")
	}
	if n := len(l.seen); n > maxTrackedKeys {
		t.Errorf("table holds %d keys, above the cap %d", n, maxTrackedKeys)
	}
}

func TestACC7_LimiterEvictsExpiredFirst(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	l := NewLimiter(1, time.Minute, clock.Now)
	for i := range maxTrackedKeys {
		l.Fail(fmt.Sprintf("k-%d", i))
	}
	clock.Advance(2 * time.Minute) // every entry has expired
	l.Fail("fresh")
	if len(l.seen) != 1 {
		t.Errorf("expired entries should all go, table holds %d", len(l.seen))
	}
}

func TestACC7_AccountGuardBacksOffAndRecovers(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	g := newAccountGuard(3, time.Minute, 4*time.Minute, time.Hour, clock.Now)
	for range 3 {
		g.Fail("ada@example.com")
	}
	if !g.Blocked("ada@example.com") {
		t.Fatal("threshold reached: account must be blocked")
	}
	clock.Advance(time.Minute)
	if g.Blocked("ada@example.com") {
		t.Fatal("first back-off is one minute")
	}
	g.Fail("ada@example.com") // fourth failure doubles the back-off to two minutes
	clock.Advance(time.Minute + time.Second)
	if !g.Blocked("ada@example.com") {
		t.Error("back-off must grow with each failure past the threshold")
	}
	for range 10 {
		g.Fail("ada@example.com")
	}
	clock.Advance(4 * time.Minute)
	if g.Blocked("ada@example.com") {
		t.Error("back-off must stop at the ceiling so the owner always regains access")
	}
	g.Fail("ada@example.com")
	g.Reset("ada@example.com")
	if g.Blocked("ada@example.com") {
		t.Error("a reset must clear the account's back-off")
	}
}

func TestACC7_AccountGuardCountsAcrossAddresses(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	ctx := context.Background()

	// One failure from each of many addresses stays under every per-address limit.
	for i := range accountFailureThreshold {
		c := Client{IP: fmt.Sprintf("198.51.100.%d", i+1)}
		if _, err := h.svc.Login(ctx, "ada@example.com", "wrong password here", c); errcode.CodeOf(err) != errcode.AuthDeny001 {
			t.Fatalf("attempt %d: code %q, want %q", i, errcode.CodeOf(err), errcode.AuthDeny001)
		}
	}
	fresh := Client{IP: "192.0.2.77"}
	if _, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", fresh); errcode.CodeOf(err) != errcode.AuthLock001 {
		t.Fatalf("correct password from a new address: code %q, want %q", errcode.CodeOf(err), errcode.AuthLock001)
	}
	if _, err := h.svc.Login(ctx, "nobody@example.com", "wrong password here", fresh); errcode.CodeOf(err) == errcode.AuthLock001 {
		t.Error("a lock on one account must not affect another")
	}

	h.clock.Advance(accountBackoffCeiling)
	if _, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", fresh); err != nil {
		t.Errorf("after the back-off the owner must regain access: %v", err)
	}
}

func TestACC7_ResetClearsAccountLock(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	ctx := context.Background()
	for i := range accountFailureThreshold {
		_, _ = h.svc.Login(ctx, "ada@example.com", "wrong password here", Client{IP: fmt.Sprintf("198.51.100.%d", i+1)})
	}
	if !h.svc.accountGuard.Blocked("ada@example.com") {
		t.Fatal("setup: account must be locked")
	}
	h.svc.accountGuard.Reset("ada@example.com")
	if _, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", Client{IP: "192.0.2.78"}); err != nil {
		t.Errorf("after an administrator's reset the owner signs in at once: %v", err)
	}
}
