// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

var client = Client{IP: "203.0.113.5", UserAgent: "test"}

func TestSetupCreatesAdminAndSignsIn(t *testing.T) {
	h := newHarness(t)
	in := h.setupAdmin(t)

	if in.User.Email != "ada@example.com" || in.User.Name != "Ada Admin" {
		t.Errorf("user not normalised: %+v", in.User)
	}
	if !slices.Equal(in.Roles, []Role{RoleAdmin}) {
		t.Errorf("roles = %v, want [admin]", in.Roles)
	}
	if in.Cookie == "" || in.CSRFToken == "" || in.Cookie == in.CSRFToken {
		t.Error("session cookie and CSRF token must exist and differ")
	}
	if strings.Contains(in.User.PasswordHash, "correct horse") || !strings.HasPrefix(in.User.PasswordHash, "$argon2id$") {
		t.Errorf("password not hashed with argon2id: %q", in.User.PasswordHash)
	}
	if _, err := os.Stat(h.token.Path()); !os.IsNotExist(err) {
		t.Error("the setup token must be removed after setup")
	}
	if got := h.repo.actions(); !slices.Equal(got, []string{"setup.admin_created:success", "auth.login:success"}) {
		t.Errorf("audit = %v", got)
	}
	// Only the hash of the cookie is stored.
	for hash := range h.repo.sessions {
		if hash == in.Cookie || hash != hashToken(in.Cookie) {
			t.Error("session must be stored under the hash of the cookie")
		}
	}
}

func TestSetupRejections(t *testing.T) {
	good := SetupRequest{Name: "Ada", Email: "ada@example.com", Password: "correct horse battery"}
	tests := []struct {
		name      string
		mutate    func(r *SetupRequest, tok string)
		wantCode  errcode.Code
		wantField string
	}{
		{"wrong token", func(r *SetupRequest, _ string) { r.Token = "nope" }, errcode.AuthSetup001, ""},
		{"empty token", func(r *SetupRequest, _ string) { r.Token = "" }, errcode.AuthSetup001, ""},
		{"bad email", func(r *SetupRequest, tok string) { r.Token = tok; r.Email = "not-an-email" }, errcode.APIVal001 + "", "email"},
		{"display-name email", func(r *SetupRequest, tok string) { r.Token = tok; r.Email = "Ada <ada@example.com>" }, "", "email"},
		{"empty name", func(r *SetupRequest, tok string) { r.Token = tok; r.Name = "  " }, "", "name"},
		{"control character in name", func(r *SetupRequest, tok string) { r.Token = tok; r.Name = "Ada\x00" }, "", "name"},
		{"short password", func(r *SetupRequest, tok string) { r.Token = tok; r.Password = "short" }, errcode.AuthPwd001, "password"},
		{"breached password", func(r *SetupRequest, tok string) { r.Token = tok; r.Password = "123QWEASDZXC" }, errcode.AuthPwd001, "password"},
		{"password is the email", func(r *SetupRequest, tok string) {
			r.Token = tok
			r.Email = "longaddress@example.com"
			r.Password = "longaddress" + "@example.com"
		}, errcode.AuthPwd001, "password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tok, _ := h.token.Read()
			req := good
			tt.mutate(&req, tok)
			_, err := h.svc.CompleteSetup(context.Background(), req, client)
			if err == nil {
				t.Fatal("expected an error")
			}
			var fe *FieldError
			if tt.wantField != "" && (!errors.As(err, &fe) || fe.Field != tt.wantField) {
				t.Errorf("field error = %v, want field %q", err, tt.wantField)
			}
			if tt.wantCode != "" && tt.wantCode != errcode.APIVal001 && errcode.CodeOf(err) != tt.wantCode {
				t.Errorf("code = %q, want %q", errcode.CodeOf(err), tt.wantCode)
			}
			if n, _ := h.repo.UserCount(context.Background()); n != 0 {
				t.Error("a rejected setup must not create an account")
			}
			if _, err := os.Stat(h.token.Path()); err != nil {
				t.Error("a rejected setup must keep the token")
			}
		})
	}
}

func TestSetupOnlyOnce(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	_, err := h.svc.CompleteSetup(context.Background(), SetupRequest{Token: "x", Name: "Eve", Email: "eve@example.com", Password: "correct horse battery"}, client)
	if errcode.CodeOf(err) != errcode.AuthSetup002 {
		t.Errorf("code = %q, want %q", errcode.CodeOf(err), errcode.AuthSetup002)
	}
	required, _ := h.svc.SetupRequired(context.Background())
	if required {
		t.Error("setup must no longer be required")
	}
}

func TestLogin(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	ctx := context.Background()

	in, err := h.svc.Login(ctx, " ADA@example.com ", "correct horse battery", client)
	if err != nil || in.User.Email != "ada@example.com" {
		t.Fatalf("login failed: %v", err)
	}

	for name, creds := range map[string][2]string{
		"wrong password":   {"ada@example.com", "wrong password here"},
		"unknown user":     {"nobody@example.com", "correct horse battery"},
		"malformed email":  {"???", "correct horse battery"},
		"oversized secret": {"ada@example.com", strings.Repeat("a", 1000)},
	} {
		_, err := h.svc.Login(ctx, creds[0], creds[1], client)
		if errcode.CodeOf(err) != errcode.AuthDeny001 {
			t.Errorf("%s: code = %q, want %q", name, errcode.CodeOf(err), errcode.AuthDeny001)
		}
		if err != nil && strings.Contains(err.Error(), "ada@example.com") {
			t.Errorf("%s: the error must not echo the account", name)
		}
	}

	failures := 0
	for _, a := range h.repo.actions() {
		if a == "auth.login_failed:failure" {
			failures++
		}
	}
	if failures != 4 {
		t.Errorf("audited failures = %d, want 4", failures)
	}
	for _, e := range h.repo.audits {
		if e.Action == "auth.login_failed" {
			if got, _ := e.Details["email"].(string); strings.Contains(got, "ada@") || strings.Contains(got, "nobody@") {
				t.Errorf("audit must mask the email, got %q", got)
			}
		}
	}
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	u := h.repo.users["ada@example.com"]
	u.Disabled = true
	h.repo.users["ada@example.com"] = u

	_, err := h.svc.Login(context.Background(), "ada@example.com", "correct horse battery", client)
	if errcode.CodeOf(err) != errcode.AuthDeny001 {
		t.Errorf("code = %q, want %q", errcode.CodeOf(err), errcode.AuthDeny001)
	}
}

func TestFailuresAreRateLimitedPerAddress(t *testing.T) {
	h := newHarness(t)
	h.setupAdmin(t)
	ctx := context.Background()

	for i := 0; i < maxFailuresPerWindow; i++ {
		// Distinct accounts: failures on one account lock that account first (ACC-7).
		_, _ = h.svc.Login(ctx, fmt.Sprintf("user%d@example.com", i), "wrong password here", client)
	}
	// Even the right password is refused while blocked, and nothing more is audited.
	before := len(h.repo.audits)
	_, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", client)
	if errcode.CodeOf(err) != errcode.AuthDeny002 {
		t.Fatalf("code = %q, want %q", errcode.CodeOf(err), errcode.AuthDeny002)
	}
	if len(h.repo.audits) != before {
		t.Error("blocked requests must not write audit entries (disk-fill guard)")
	}
	// Another address is unaffected, and the block ends with the window.
	if _, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", Client{IP: "198.51.100.7"}); err != nil {
		t.Errorf("other address: %v", err)
	}
	h.clock.Advance(failureWindow + time.Second)
	if _, err := h.svc.Login(ctx, "ada@example.com", "correct horse battery", client); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid session", func(t *testing.T) {
		h := newHarness(t)
		in := h.setupAdmin(t)
		p, sess, err := h.svc.Authenticate(ctx, in.Cookie)
		if err != nil || !p.Authenticated() || p.Email != "ada@example.com" || !p.HasRole(RoleAdmin) || sess == nil {
			t.Fatalf("principal %+v session %v err %v", p, sess, err)
		}
	})
	t.Run("no cookie and unknown cookie are anonymous", func(t *testing.T) {
		h := newHarness(t)
		h.setupAdmin(t)
		for _, c := range []string{"", "garbage"} {
			p, sess, err := h.svc.Authenticate(ctx, c)
			if err != nil || p.Authenticated() || sess != nil {
				t.Errorf("cookie %q: principal %+v session %v err %v", c, p, sess, err)
			}
		}
	})
	t.Run("idle timeout", func(t *testing.T) {
		h := newHarness(t)
		in := h.setupAdmin(t)
		h.clock.Advance(12*time.Hour + time.Minute)
		if p, _, _ := h.svc.Authenticate(ctx, in.Cookie); p.Authenticated() {
			t.Error("a session idle for more than 12 hours must expire (ACC-6)")
		}
		if len(h.repo.sessions) != 0 {
			t.Error("an expired session must be deleted")
		}
	})
	t.Run("activity extends the idle window but not the absolute one", func(t *testing.T) {
		h := newHarness(t)
		in := h.setupAdmin(t)
		for i := 0; i < 6; i++ { // 6 x 11h = 66h, always under the idle limit
			h.clock.Advance(11 * time.Hour)
			if p, _, _ := h.svc.Authenticate(ctx, in.Cookie); !p.Authenticated() {
				t.Fatalf("active session expired after %d steps", i+1)
			}
		}
		h.clock.Advance(11 * time.Hour) // 77h
		h.clock.Advance(100 * time.Hour)
		if p, _, _ := h.svc.Authenticate(ctx, in.Cookie); p.Authenticated() {
			t.Error("the absolute lifetime of 7 days must end the session")
		}
	})
	t.Run("disabled user loses the session", func(t *testing.T) {
		h := newHarness(t)
		in := h.setupAdmin(t)
		u := h.repo.users["ada@example.com"]
		u.Disabled = true
		h.repo.users["ada@example.com"] = u
		if p, _, _ := h.svc.Authenticate(ctx, in.Cookie); p.Authenticated() {
			t.Error("a disabled user must not stay signed in")
		}
	})
	t.Run("last seen is refreshed at most once a minute", func(t *testing.T) {
		h := newHarness(t)
		in := h.setupAdmin(t)
		h.clock.Advance(10 * time.Second)
		_, _, _ = h.svc.Authenticate(ctx, in.Cookie)
		if h.repo.touched != 0 {
			t.Error("no write expected within a minute")
		}
		h.clock.Advance(2 * time.Minute)
		_, _, _ = h.svc.Authenticate(ctx, in.Cookie)
		if h.repo.touched != 1 {
			t.Errorf("touched = %d, want 1", h.repo.touched)
		}
	})
}

func TestLogoutAndCSRF(t *testing.T) {
	h := newHarness(t)
	in := h.setupAdmin(t)
	ctx := context.Background()
	_, sess, _ := h.svc.Authenticate(ctx, in.Cookie)

	if !h.svc.CheckCSRF(*sess, in.CSRFToken) {
		t.Error("the session's own CSRF token must be accepted")
	}
	for _, bad := range []string{"", "wrong", in.CSRFToken + "x", in.Cookie} {
		if h.svc.CheckCSRF(*sess, bad) {
			t.Errorf("CSRF token %q must be rejected", bad)
		}
	}

	if err := h.svc.Logout(ctx, *sess, client); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := h.svc.Authenticate(ctx, in.Cookie); p.Authenticated() {
		t.Error("the session must be gone after logout")
	}
	if got := h.repo.actions(); got[len(got)-1] != "auth.logout:success" {
		t.Errorf("last audit = %v", got)
	}
}

func TestEachLoginGetsNewSession(t *testing.T) {
	h := newHarness(t)
	a := h.setupAdmin(t)
	b, err := h.svc.Login(context.Background(), "ada@example.com", "correct horse battery", client)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cookie == b.Cookie || a.CSRFToken == b.CSRFToken {
		t.Error("sessions must be rotated on every login")
	}
}
