// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

const oidcTestSecret = "s3cret-value-do-not-leak"

func openOIDCStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "data"), discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	box, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	s.UseSecrets(box)
	s.Groups = s.OIDCGroupsOf
	return s
}

func oidcSettings() auth.OIDCProvider {
	return auth.OIDCProvider{
		Issuer: "https://idp.example", ClientID: "nux", Scopes: []string{"openid", "email"}, GroupsClaim: "groups",
		AllowedDomains: []string{"example.com"}, AutoProvision: true, UpdatedAt: time.UnixMilli(1_700_000_000_000),
	}
}

func oidcEvent(action string) audit.Event {
	return audit.Event{ActorType: "user", ActorID: "admin", Action: action, TargetType: "setting", TargetID: "oidc", Result: audit.ResultSuccess}
}

func TestOIDCSettingsSealTheSecret(t *testing.T) { // ACC-3, security
	s := openOIDCStore(t)
	ctx := context.Background()

	if _, err := s.OIDCProvider(ctx); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("before setup: %v, want ErrNotFound", err)
	}
	if err := s.SaveOIDCProvider(ctx, oidcSettings(), oidcTestSecret, oidcEvent("settings.oidc_update")); err != nil {
		t.Fatal(err)
	}
	got, err := s.OIDCProvider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "https://idp.example" || got.ClientID != "nux" || !got.AutoProvision || got.LinkExisting ||
		len(got.Scopes) != 2 || len(got.AllowedDomains) != 1 || got.AllowedDomains[0] != "example.com" {
		t.Fatalf("round trip lost settings: %+v", got)
	}

	secret, err := s.OIDCClientSecret(ctx)
	if err != nil || secret != oidcTestSecret {
		t.Fatalf("secret = %q, %v", secret, err)
	}
	var sealed []byte
	if err := s.DB().QueryRowContext(ctx, `SELECT ciphertext FROM secrets`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(oidcTestSecret)) {
		t.Fatal("the client secret is stored in plain text")
	}

	// An update without a secret keeps the stored one.
	changed := oidcSettings()
	changed.ClientID = "nux-2"
	if err := s.SaveOIDCProvider(ctx, changed, "", oidcEvent("settings.oidc_update")); err != nil {
		t.Fatal(err)
	}
	if secret, err := s.OIDCClientSecret(ctx); err != nil || secret != oidcTestSecret {
		t.Fatalf("secret after blank update = %q, %v", secret, err)
	}

	if err := s.DeleteOIDCProvider(ctx, oidcEvent("settings.oidc_delete")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OIDCProvider(ctx); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("after delete: %v, want ErrNotFound", err)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("sealed secrets left after delete: %d, %v", n, err)
	}
	if _, err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
}

func TestOIDCLoginIsSingleUseAndExpires(t *testing.T) { // ACC-3, security
	s := openOIDCStore(t)
	ctx := context.Background()
	now := time.Now()
	s.Now = func() time.Time { return now }

	if err := s.CreateOIDCLogin(ctx, auth.OIDCLogin{StateHash: "h1", Nonce: "n", CodeVerifier: "v", RedirectTo: "/x", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	l, err := s.TakeOIDCLogin(ctx, "h1")
	if err != nil || l.Nonce != "n" || l.CodeVerifier != "v" || l.RedirectTo != "/x" {
		t.Fatalf("take = %+v, %v", l, err)
	}
	if _, err := s.TakeOIDCLogin(ctx, "h1"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("second take: %v, want ErrNotFound", err)
	}
	if err := s.CreateOIDCLogin(ctx, auth.OIDCLogin{StateHash: "old", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOIDCLogin(ctx, auth.OIDCLogin{StateHash: "fresh", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeOIDCLogin(ctx, "old"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("expired row was kept: %v", err)
	}
}

func TestOIDCSignInAppliesGroupBindings(t *testing.T) { // ACC-3
	s := openOIDCStore(t)
	ctx := context.Background()
	if err := s.SaveOIDCProvider(ctx, oidcSettings(), oidcTestSecret, oidcEvent("settings.oidc_update")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO role_bindings (id, subject_type, subject, role) VALUES ('rb-eng', 'oidc_group', 'engineers', 'operator')`); err != nil {
		t.Fatal(err)
	}

	created := auth.User{ID: "user-ada", Email: "ada@example.com", Name: "Ada", CreatedAt: time.Now()}
	u, err := s.SignInOIDC(ctx, auth.OIDCSignIn{User: created, Mode: auth.OIDCNewAccount, Issuer: "https://idp.example", Subject: "sub-1", Groups: []string{"engineers", "staff"}},
		oidcEvent("auth.oidc_login"))
	if err != nil || u.ID != "user-ada" {
		t.Fatalf("provision: %+v, %v", u, err)
	}
	if found, err := s.UserByOIDCSubject(ctx, "https://idp.example", "sub-1"); err != nil || found.ID != "user-ada" {
		t.Fatalf("lookup by subject: %+v, %v", found, err)
	}
	bindings, err := s.Bindings(ctx, "user-ada")
	if err != nil || len(bindings) != 1 || bindings[0].Role != auth.RoleOperator {
		t.Fatalf("bindings = %+v, %v; want the engineers operator binding", bindings, err)
	}

	// The next sign-in replaces the groups, so a removed group loses its role.
	if _, err := s.SignInOIDC(ctx, auth.OIDCSignIn{User: u, Mode: auth.OIDCKnownAccount, Issuer: "https://idp.example", Subject: "sub-1", Groups: []string{"staff"}},
		oidcEvent("auth.oidc_login")); err != nil {
		t.Fatal(err)
	}
	if bindings, _ := s.Bindings(ctx, "user-ada"); len(bindings) != 0 {
		t.Fatalf("bindings after the group was removed = %+v", bindings)
	}

	// An identity can be linked to one account only.
	other := auth.User{ID: "user-bob", Email: "bob@example.com", Name: "Bob", CreatedAt: time.Now()}
	if _, err := s.SignInOIDC(ctx, auth.OIDCSignIn{User: other, Mode: auth.OIDCNewAccount, Issuer: "https://idp.example", Subject: "sub-2"}, oidcEvent("auth.oidc_login")); err != nil {
		t.Fatal(err)
	}
	_, err = s.SignInOIDC(ctx, auth.OIDCSignIn{User: other, Mode: auth.OIDCLinkAccount, Issuer: "https://idp.example", Subject: "sub-1"}, oidcEvent("auth.oidc_login"))
	if !errors.Is(err, auth.ErrOIDCLinkConflict) {
		t.Fatalf("linking a second identity: %v, want ErrOIDCLinkConflict", err)
	}
}
