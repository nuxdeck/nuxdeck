// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 secret, 6-digit truncation of the published 8-digit codes.
func TestACC2_TOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(secret, unix/30); got != want {
			t.Errorf("t=%d: got %s, want %s", unix, got, want)
		}
	}
}

func TestACC2_TOTPWindowAndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	step := TOTPStep(now)

	if got, ok := VerifyTOTP(secret, totpCode(secret, step), now, 0); !ok || got != step {
		t.Fatalf("current code rejected: %d %v", got, ok)
	}
	for _, d := range []int64{-1, 1} {
		if _, ok := VerifyTOTP(secret, totpCode(secret, step+d), now, 0); !ok {
			t.Errorf("step %+d should be inside the window", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := VerifyTOTP(secret, totpCode(secret, step+d), now, 0); ok {
			t.Errorf("step %+d must be outside the window", d)
		}
	}
	if _, ok := VerifyTOTP(secret, totpCode(secret, step), now, step); ok {
		t.Error("a code at the last used step is a replay")
	}
	if _, ok := VerifyTOTP(secret, totpCode(secret, step-1), now, step); ok {
		t.Error("an older step than the last used one is a replay")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok && bad != totpCode(secret, step) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestACC2_OTPAuthURI(t *testing.T) {
	uri := OTPAuthURI("Nux Deck", "a@example.com", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Nux%20Deck:a@example.com?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(uri, want) {
			t.Errorf("%q missing %q", uri, want)
		}
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"); err != nil {
		t.Fatal(err)
	}
}

func TestACC2_RecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil || len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("got %d codes, %d hashes, %v", len(codes), len(hashes), err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Errorf("code %q is not xxxxx-xxxxx", c)
		}
		if seen[hashes[i]] {
			t.Error("duplicate hash")
		}
		seen[hashes[i]] = true
		if hashRecoveryCode(strings.ToLower(strings.ReplaceAll(c, "-", " "))) != hashes[i] {
			t.Errorf("entry of %q is not forgiving of case and separators", c)
		}
		if strings.Contains(hashes[i], c) {
			t.Error("hash must not contain the code")
		}
	}
	if hashRecoveryCode("short") != "" {
		t.Error("a malformed code must hash to nothing")
	}
}

func TestCLI3_ScopeSubset(t *testing.T) {
	prod := Scope{Environments: []string{"prod"}}
	prodWeb := Scope{TagSets: [][]string{{"web"}}}
	prodWebEU := Scope{TagSets: [][]string{{"web", "eu"}}}
	owner := []Binding{{Role: RoleOperator, Scope: prod}, {Role: RoleViewer}}

	cases := []struct {
		name string
		req  []Binding
		ok   bool
	}{
		{"same role and scope", []Binding{{Role: RoleOperator, Scope: prod}}, true},
		{"lower role, same scope", []Binding{{Role: RoleViewer, Scope: prod}}, true},
		{"unscoped viewer is held", []Binding{{Role: RoleViewer}}, true},
		{"higher role", []Binding{{Role: RoleAdmin, Scope: prod}}, false},
		{"operator unscoped exceeds scoped operator", []Binding{{Role: RoleOperator}}, false},
		{"other environment", []Binding{{Role: RoleOperator, Scope: Scope{Environments: []string{"staging"}}}}, false},
		{"subset of environments", []Binding{{Role: RoleOperator, Scope: Scope{Environments: []string{"prod"}}}}, true},
		{"more environments than owner", []Binding{{Role: RoleOperator, Scope: Scope{Environments: []string{"prod", "dev"}}}}, false},
		{"empty request", nil, false},
		{"unknown role", []Binding{{Role: "root"}}, false},
	}
	for _, c := range cases {
		if got := ScopeIsSubset(owner, c.req); got != c.ok {
			t.Errorf("%s: got %v, want %v", c.name, got, c.ok)
		}
	}

	tagOwner := []Binding{{Role: RoleViewer, Scope: prodWeb}}
	if !ScopeIsSubset(tagOwner, []Binding{{Role: RoleViewer, Scope: prodWebEU}}) {
		t.Error("web+eu is narrower than web")
	}
	if ScopeIsSubset(tagOwner, []Binding{{Role: RoleViewer, Scope: Scope{TagSets: [][]string{{"eu"}}}}}) {
		t.Error("eu alone is not inside web")
	}
	if ScopeIsSubset(tagOwner, []Binding{{Role: RoleViewer, Scope: prod}}) {
		t.Error("an environment is not inside a tag set")
	}
}

func TestCLI3_IntersectDropsLostBindings(t *testing.T) {
	token := []Binding{{Role: RoleAdmin}, {Role: RoleViewer}}
	got := intersectBindings([]Binding{{Role: RoleOperator}}, token)
	if len(got) != 1 || got[0].Role != RoleViewer {
		t.Fatalf("got %+v; the admin binding the owner no longer holds must be dropped, not downgraded", got)
	}
	if len(intersectBindings(nil, token)) != 0 {
		t.Error("an owner without bindings leaves the token powerless")
	}
}

func TestCLI3_TokenFormat(t *testing.T) {
	plain, hash, err := NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, TokenPrefix) || hashToken(plain) != hash || strings.Contains(hash, plain) {
		t.Errorf("token %q hash %q", plain, hash)
	}
	other, _, _ := NewAPIToken()
	if other == plain {
		t.Error("tokens must be random")
	}
}
