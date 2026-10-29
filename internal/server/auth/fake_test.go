// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// fakeRepo is an in-memory Repository that records audit events.
type fakeRepo struct {
	mu       sync.Mutex
	users    map[string]User // by email
	roles    map[string][]Role
	sessions map[string]Session
	audits   []audit.Event
	touched  int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{users: map[string]User{}, roles: map[string][]Role{}, sessions: map[string]Session{}}
}

func (f *fakeRepo) UserCount(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users), nil
}

func (f *fakeRepo) UserByEmail(_ context.Context, email string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	return User{}, ErrNotFound
}

func (f *fakeRepo) Bindings(_ context.Context, id string) ([]Binding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Binding
	for _, r := range f.roles[id] {
		out = append(out, Binding{Role: r})
	}
	return out, nil
}

func (f *fakeRepo) CreateAdmin(_ context.Context, u User, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.users) > 0 {
		return ErrSetupDone
	}
	f.users[u.Email] = u
	f.roles[u.ID] = []Role{RoleAdmin}
	f.audits = append(f.audits, ev)
	return nil
}

func (f *fakeRepo) CreateSession(_ context.Context, s Session, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[s.IDHash] = s
	f.audits = append(f.audits, ev)
	return nil
}

func (f *fakeRepo) SessionByHash(_ context.Context, h string) (Session, User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[h]
	if !ok {
		return Session{}, User{}, ErrNotFound
	}
	for _, u := range f.users {
		if u.ID == s.UserID {
			return s, u, nil
		}
	}
	return Session{}, User{}, ErrNotFound
}

func (f *fakeRepo) TouchSession(_ context.Context, h string, seen time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[h]
	s.LastSeenAt = seen
	f.sessions[h] = s
	f.touched++
	return nil
}

func (f *fakeRepo) DeleteSession(_ context.Context, h string, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, h)
	f.audits = append(f.audits, ev)
	return nil
}

func (f *fakeRepo) RecordAudit(_ context.Context, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, ev)
	return nil
}

func (f *fakeRepo) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.audits {
		out = append(out, e.Action+":"+e.Result)
	}
	return out
}

// testClock is a controllable clock.
type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time          { return c.t }
func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	svc   *Service
	repo  *fakeRepo
	clock *testClock
	token *SetupToken
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	repo := newFakeRepo()
	clock := &testClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	token := NewSetupToken(t.TempDir())
	if err := token.Ensure(); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(context.Background(), Config{
		Repo: repo, Hasher: NewHasherWithParams(8, 1, 1), Passwords: NewPasswordPolicy(), SetupToken: token,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{svc: svc, repo: repo, clock: clock, token: token}
}

func (h *harness) setupAdmin(t *testing.T) *SignedIn {
	t.Helper()
	tok, err := h.token.Read()
	if err != nil {
		t.Fatal(err)
	}
	in, err := h.svc.CompleteSetup(context.Background(), SetupRequest{Token: tok, Name: "Ada Admin", Email: "Ada@Example.com", Password: "correct horse battery"}, Client{IP: "203.0.113.5", UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

var _ = filepath.Join
