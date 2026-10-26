// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func TestAuthorize(t *testing.T) {
	anon := Principal{}
	admin := Principal{UserID: "u1", Roles: []Role{RoleAdmin}}
	viewer := Principal{UserID: "u2", Roles: []Role{RoleViewer}}
	operator := Principal{UserID: "u3", Roles: []Role{RoleOperator}}
	roleless := Principal{UserID: "u4"} // signed in, but nothing binds a role to them
	tests := []struct {
		action   Action
		who      Principal
		wantCode errcode.Code
	}{
		{ActionSetupStatus, anon, ""},
		{ActionSetupComplete, anon, ""},
		{ActionLogin, anon, ""},
		{ActionLogin, admin, ""},
		{ActionLogout, anon, errcode.AuthDeny003},
		{ActionLogout, admin, ""},
		{ActionMeRead, anon, errcode.AuthDeny003},
		{ActionMeRead, admin, ""},
		{ActionInventoryRead, anon, errcode.AuthDeny003},
		{ActionInventoryRead, viewer, ""},
		{ActionInventoryRead, operator, ""},
		{ActionInventoryRead, admin, ""},
		{ActionInventoryRead, roleless, errcode.AuthDeny005},
		{ActionEventsStream, anon, errcode.AuthDeny003},
		{ActionEventsStream, viewer, ""},
		{ActionEventsStream, roleless, errcode.AuthDeny005},
		{ActionLogsStream, anon, errcode.AuthDeny003},
		{ActionLogsStream, viewer, ""},
		{ActionLogsStream, operator, ""},
		{ActionLogsStream, admin, ""},
		{ActionLogsStream, roleless, errcode.AuthDeny005},
		{ActionItemMetaUpdate, anon, errcode.AuthDeny003},
		{ActionItemMetaUpdate, viewer, errcode.AuthDeny005},
		{ActionItemMetaUpdate, roleless, errcode.AuthDeny005},
		{ActionItemMetaUpdate, operator, ""},
		{ActionItemMetaUpdate, admin, ""},
		{ActionSearch, anon, errcode.AuthDeny003},
		{ActionSearch, viewer, ""},
		{ActionSearch, roleless, errcode.AuthDeny005},
		{ActionAgentRevoke, viewer, errcode.AuthDeny005}, // admin-only actions stay out of a viewer's reach
		{ActionAgentTokenCreate, operator, errcode.AuthDeny005},
		{"hosts.read", admin, errcode.AuthDeny005}, // unknown actions fail closed, even for an admin
		{"", admin, errcode.AuthDeny005},
	}
	for _, tt := range tests {
		err := Authorize(tt.who, tt.action)
		if got := errcode.CodeOf(err); got != tt.wantCode {
			t.Errorf("Authorize(%v, %q) = %q, want %q", tt.who.Authenticated(), tt.action, got, tt.wantCode)
		}
	}
}

func TestHasherRoundTrip(t *testing.T) {
	h := NewHasherWithParams(8, 1, 1)
	ctx := context.Background()
	a, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := h.Hash(ctx, "correct horse battery")
	if a == b {
		t.Error("two hashes of one password must differ (random salt)")
	}
	if !strings.HasPrefix(a, "$argon2id$v=19$m=8,t=1,p=1$") {
		t.Errorf("not a PHC argon2id string: %q", a)
	}
	for pw, want := range map[string]bool{"correct horse battery": true, "Correct horse battery": false, "": false} {
		ok, err := h.Verify(ctx, pw, a)
		if err != nil || ok != want {
			t.Errorf("Verify(%q) = %v, %v; want %v", pw, ok, err, want)
		}
	}
}

func TestHasherRejectsBadEncodings(t *testing.T) {
	h := NewHasherWithParams(8, 1, 1)
	//nolint:gosec // malformed hashes used as test input
	for name, enc := range map[string]string{
		"empty":         "",
		"wrong algo":    "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5",
		"wrong version": "$argon2id$v=18$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5",
		"huge memory":   "$argon2id$v=19$m=4194304,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5",
		"zero passes":   "$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5",
		"bad salt":      "$argon2id$v=19$m=8,t=1,p=1$!!!$a2V5a2V5a2V5",
		"missing key":   "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$",
	} {
		if ok, err := h.Verify(context.Background(), "x", enc); ok || err == nil {
			t.Errorf("%s: Verify = %v, %v; want a rejection", name, ok, err)
		}
	}
}

func TestHasherHonoursContextWhenBusy(t *testing.T) {
	h := NewHasherWithParams(8, 1, 1)
	for i := 0; i < maxConcurrentHashes; i++ {
		h.slots <- struct{}{} // every slot taken
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "x"); err == nil {
		t.Error("a saturated hasher must give up when the context ends")
	}
}

func TestPasswordPolicy(t *testing.T) {
	p := NewPasswordPolicy()
	if len(p.common) < 40_000 {
		t.Errorf("breached-password list has %d entries, expected about 46,000", len(p.common))
	}
	tests := []struct {
		name, pw, email string
		ok              bool
	}{
		{"long enough", "correct horse battery", "a@example.com", true},
		{"exactly 12 characters", "plum-tangent", "a@example.com", true},
		{"11 characters", "abcdefghijk", "a@example.com", false},
		{"counts characters not bytes", "ééééééééééé", "a@example.com", false}, // 11 runes, 22 bytes
		{"12 multibyte characters", "éééééééééééé", "a@example.com", true},
		{"known breached", "123qweasdzxc", "a@example.com", false},
		{"breached in another case", "1QAZ2WSX3EDC", "a@example.com", false},
		{"the email address", "someone.long@example.com", "someone.long@example.com", false},
		{"too large", strings.Repeat("a", 300), "a@example.com", false},
	}
	for _, tt := range tests {
		err := p.Check(tt.pw, tt.email)
		if (err == nil) != tt.ok {
			t.Errorf("%s: Check = %v, want ok=%v", tt.name, err, tt.ok)
		}
		if err != nil && errcode.CodeOf(err) != errcode.AuthPwd001 {
			t.Errorf("%s: code = %q", tt.name, errcode.CodeOf(err))
		}
	}
}

func TestSetupToken(t *testing.T) {
	st := NewSetupToken(t.TempDir())
	if st.Verify("anything") {
		t.Error("no token file must mean no match")
	}
	if err := st.Ensure(); err != nil {
		t.Fatal(err)
	}
	first, err := st.Read()
	if err != nil || len(first) != 32 {
		t.Fatalf("token %q, err %v", first, err)
	}
	if err := st.Ensure(); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Read(); again != first {
		t.Error("Ensure must keep an existing token so restarts do not invalidate it")
	}
	info, _ := os.Stat(st.Path())
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %o, want 600", info.Mode().Perm())
	}
	if !st.Verify(first) || !st.Verify(" "+first+"\n") || st.Verify("wrong") || st.Verify("") {
		t.Error("Verify must accept only the token (ignoring surrounding whitespace)")
	}
	if err := st.Remove(); err != nil || st.Verify(first) {
		t.Errorf("token must be gone after Remove: %v", err)
	}
	if err := st.Remove(); err != nil {
		t.Errorf("removing twice must be harmless: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLimiter(3, time.Minute, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if l.Blocked("a") {
			t.Fatalf("blocked after only %d failures", i)
		}
		l.Fail("a")
	}
	if !l.Blocked("a") || l.Blocked("b") {
		t.Error("a must be blocked, b must not")
	}
	now = now.Add(time.Minute)
	if l.Blocked("a") {
		t.Error("the block must end with the window")
	}
}

func TestLimiterStaysBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLimiter(3, time.Hour, func() time.Time { return now })
	for i := 0; i < maxTrackedKeys*2; i++ {
		l.Fail(strings.Repeat("k", 1) + string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if len(l.seen) > maxTrackedKeys {
		t.Errorf("tracking %d keys, limit is %d", len(l.seen), maxTrackedKeys)
	}
}
