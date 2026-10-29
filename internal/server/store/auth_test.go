// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir(), discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	fixed := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return fixed }
	return s
}

func ev(action string) audit.Event {
	return audit.Event{ActorType: "user", ActorID: "u1", Action: action, Result: audit.ResultSuccess, IP: "203.0.113.5", Details: map[string]any{"k": "v"}}
}

//nolint:gosec // the hash is a placeholder
func admin(id, email string) auth.User {
	return auth.User{ID: id, Email: email, Name: "Ada", PasswordHash: "$argon2id$x", CreatedAt: time.UnixMilli(1_790_000_000_000)}
}

func TestAdminSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)

	if n, err := s.UserCount(ctx); err != nil || n != 0 {
		t.Fatalf("UserCount = %d, %v", n, err)
	}
	if err := s.CreateAdmin(ctx, admin("u1", "ada@example.com"), ev("setup.admin_created")); err != nil {
		t.Fatal(err)
	}

	u, err := s.UserByEmail(ctx, "ada@example.com")
	if err != nil || u.ID != "u1" || u.Name != "Ada" || u.Disabled || u.PasswordHash != "$argon2id$x" {
		t.Fatalf("user = %+v, %v", u, err)
	}
	if bs, err := s.Bindings(ctx, "u1"); err != nil || len(bs) != 1 || bs[0].Role != auth.RoleAdmin || !bs[0].Scope.IsZero() {
		t.Errorf("bindings = %v, %v; want [admin]", bs, err)
	}
	if _, err := s.UserByEmail(ctx, "nobody@example.com"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("unknown user error = %v, want ErrNotFound", err)
	}

	now := time.UnixMilli(1_790_000_100_000)
	sess := auth.Session{IDHash: "hash1", UserID: "u1", CSRFToken: "csrf", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IP: "203.0.113.5", UserAgent: "ua"}
	if err := s.CreateSession(ctx, sess, ev("auth.login")); err != nil {
		t.Fatal(err)
	}
	got, gu, err := s.SessionByHash(ctx, "hash1")
	if err != nil || got.CSRFToken != "csrf" || !got.ExpiresAt.Equal(sess.ExpiresAt) || gu.Email != "ada@example.com" {
		t.Fatalf("session = %+v user %+v err %v", got, gu, err)
	}
	later := now.Add(5 * time.Minute)
	if err := s.TouchSession(ctx, "hash1", later); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.SessionByHash(ctx, "hash1"); !got.LastSeenAt.Equal(later) {
		t.Errorf("last seen = %v, want %v", got.LastSeenAt, later)
	}
	if err := s.DeleteSession(ctx, "hash1", ev("auth.logout")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByHash(ctx, "hash1"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("deleted session error = %v, want ErrNotFound", err)
	}

	n, err := s.VerifyAuditChain(ctx)
	if err != nil || n != 3 {
		t.Errorf("audit chain: %d entries, err %v; want 3 entries (setup, login, logout) and no error", n, err)
	}
}

func TestCreateAdminOnlyOnce(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if err := s.CreateAdmin(ctx, admin("u1", "a@example.com"), ev("setup.admin_created")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAdmin(ctx, admin("u2", "b@example.com"), ev("setup.admin_created")); !errors.Is(err, auth.ErrSetupDone) {
		t.Errorf("second admin error = %v, want ErrSetupDone", err)
	}
	if n, _ := s.VerifyAuditChain(ctx); n != 1 {
		t.Errorf("a rejected setup must not leave an audit entry, have %d", n)
	}
}

func TestConcurrentSetupCreatesExactlyOneAdmin(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)

	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.CreateAdmin(ctx, admin(fmt.Sprintf("u%d", i), fmt.Sprintf("user%d@example.com", i)), ev("setup.admin_created"))
		}()
	}
	wg.Wait()
	close(results)

	ok := 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, auth.ErrSetupDone):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if n, _ := s.UserCount(ctx); ok != 1 || n != 1 {
		t.Errorf("%d setups succeeded and %d users exist, want exactly 1 of each", ok, n)
	}
}

func TestAuditChainSurvivesConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.RecordAudit(ctx, ev(fmt.Sprintf("test.event.%d", i))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if n, err := s.VerifyAuditChain(ctx); err != nil || n != 20 {
		t.Errorf("chain: %d entries, err %v; want 20 entries and no error", n, err)
	}
}

func TestAuditLogRefusesChanges(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if err := s.RecordAudit(ctx, ev("test.event")); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE audit_log SET result = 'failure'`,
		`DELETE FROM audit_log`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%q must be refused by the database", stmt)
		}
	}
}

func TestTamperingWithTheLogIsDetected(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	for i := 0; i < 3; i++ {
		if err := s.RecordAudit(ctx, ev(fmt.Sprintf("test.event.%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// An attacker with file access drops the triggers, edits a row and tries to hide it.
	for _, stmt := range []string{
		`DROP TRIGGER audit_log_no_update`,
		`UPDATE audit_log SET action = 'forged' WHERE id = 2`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.VerifyAuditChain(ctx); err == nil {
		t.Fatal("the edited entry must be detected")
	}
}

func TestEmailsAreUniqueAndLowercase(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO users (id, email, name, disabled, created_at) VALUES ('x', 'Mixed@Example.com', 'n', 0, 1)`); err == nil {
		t.Error("the database must reject a mixed-case email")
	}
}

func TestACC5_BindingsCarryScopeAndGroups(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if err := s.CreateAdmin(ctx, admin("u1", "ada@example.com"), ev("setup.admin_created")); err != nil {
		t.Fatal(err)
	}
	s.Groups = func(context.Context, string) ([]string, error) { return []string{"sre"}, nil }
	for i, row := range [][3]string{
		{"user", "u1", `{"environments":["staging"]}`}, // a second binding for the same user
		{"oidc_group", "sre", `{"tag_sets":[["team:web"]]}`},
		{"oidc_group", "other", `{}`},              // a group the user is not in
		{"user", "u1", `{"environments":`},         // unreadable: grants nothing
		{"user", "u1", `null`},                     // would decode to unscoped: refused
		{"user", "someone-else", `{}`},             // another user's binding
		{"oidc_group", "sre", `{"tag_sets":[[]]}`}, // invalid
	} {
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO role_bindings (id, subject_type, subject, role, scope_json) VALUES (?, ?, ?, 'viewer', ?)`,
			"b"+strconv.Itoa(i), row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Bindings(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	var viewers []auth.Binding
	for _, b := range got {
		if b.Role == auth.RoleViewer {
			viewers = append(viewers, b)
		}
	}
	if len(got) != 3 || len(viewers) != 2 || viewers[0].Scope.Environments[0] != "staging" || viewers[1].Scope.TagSets[0][0] != "team:web" {
		t.Errorf("bindings = %+v", got)
	}

	s.Groups = nil
	if got, _ := s.Bindings(ctx, "u1"); len(got) != 2 {
		t.Errorf("without group data got %d bindings, want the 2 direct readable ones", len(got))
	}
}

func TestACC4_LastUnscopedAdminBindingCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if err := s.CreateAdmin(ctx, admin("u1", "ada@example.com"), ev("setup.admin_created")); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListRoleBindings(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if err := s.DeleteRoleBinding(ctx, list[0].ID, ev("rolebinding.delete")); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin = %v, want ErrLastAdmin", err)
	}
	extra, err := s.CreateRoleBinding(ctx, auth.StoredBinding{SubjectType: "oidc_group", Subject: "ops", Role: auth.RoleAdmin}, ev("rolebinding.create"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoleBinding(ctx, list[0].ID, ev("rolebinding.delete")); err != nil {
		t.Errorf("delete with another admin present = %v", err)
	}
	if err := s.DeleteRoleBinding(ctx, extra.ID, ev("rolebinding.delete")); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete the new last admin = %v", err)
	}
	if err := s.DeleteRoleBinding(ctx, "missing", ev("rolebinding.delete")); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}
	if _, err := s.CreateRoleBinding(ctx, auth.StoredBinding{SubjectType: "user", Subject: "ghost", Role: auth.RoleViewer}, ev("rolebinding.create")); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("binding for an unknown user = %v", err)
	}
}
