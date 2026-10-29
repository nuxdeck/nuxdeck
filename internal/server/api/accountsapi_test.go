// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

type accEnv struct {
	t     *testing.T
	h     http.Handler
	svc   *auth.Service
	db    *store.Store
	clock *testClock
	ip    string
}

type acall struct {
	method, path string
	body         any
	cookie       *http.Cookie
	csrf         string
	bearer       string
}

type actor struct {
	cookie *http.Cookie
	csrf   string
}

func newAccEnv(t *testing.T) *accEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(context.Background(), dir, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	db.UseSecrets(box)
	clock := &testClock{now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	hasher, pol := auth.NewHasherWithParams(8, 1, 1), auth.NewPasswordPolicy()
	acc, err := auth.NewAccounts(auth.AccountsConfig{Repo: db, Hasher: hasher, Passwords: pol, Log: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	token := auth.NewSetupToken(dir)
	if err := token.Ensure(); err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: db, Hasher: hasher, Passwords: pol, SetupToken: token, Log: log, Accounts: acc, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &accEnv{
		t: t, db: db, clock: clock, ip: "203.0.113.5", svc: svc,
		h: Handler(Options{Log: log, Ready: db, UI: uiFS(), Auth: svc, Accounts: acc}),
	}
	tok, _ := token.Read()
	rec := e.call(acall{method: "POST", path: "/api/v1/setup/admin", body: map[string]string{"token": tok, "name": "Ada", "email": adminEmail, "password": goodPassword}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup = %d %s", rec.Code, rec.Body)
	}
	return e
}

func (e *accEnv) call(c acall) *httptest.ResponseRecorder {
	e.t.Helper()
	var body io.Reader
	if c.body != nil {
		b, _ := json.Marshal(c.body)
		body = bytes.NewReader(b)
	}
	r := httptest.NewRequest(c.method, c.path, body)
	r.RemoteAddr = e.ip + ":4711"
	if c.body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set(csrfHeader, c.csrf)
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (a actor) do(e *accEnv, method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.call(acall{method: method, path: path, body: body, cookie: a.cookie, csrf: a.csrf})
}

func (e *accEnv) login(email, pw string) (actor, *httptest.ResponseRecorder) {
	e.t.Helper()
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": email, "password": pw}})
	if rec.Code != http.StatusOK {
		return actor{}, rec
	}
	var b struct {
		CSRF    string    `json:"csrf_token"`
		Pending *struct{} `json:"pending"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.Pending != nil {
		return actor{}, rec
	}
	return actor{cookie: sessionCookieOf(e.t, rec), csrf: b.CSRF}, rec
}

func (e *accEnv) mustLogin(email, pw string) actor {
	e.t.Helper()
	a, rec := e.login(email, pw)
	if a.cookie == nil {
		e.t.Fatalf("login %s = %d %s", email, rec.Code, rec.Body)
	}
	return a
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("bad body %q: %v", rec.Body, err)
	}
}

func (e *accEnv) createUser(admin actor, email, role string) string {
	e.t.Helper()
	rec := admin.do(e, "POST", "/api/v1/users", map[string]string{"email": email, "name": "Test " + role, "password": goodPassword, "role": role})
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("create %s = %d %s", email, rec.Code, rec.Body)
	}
	var j accountJSON
	decodeInto(e.t, rec, &j)
	return j.ID
}

func TestACC1_UserManagement(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)

	id := e.createUser(admin, "olivia@example.com", "operator")
	if rec := admin.do(e, "POST", "/api/v1/users", map[string]string{"email": "OLIVIA@example.com", "name": "Dup", "password": goodPassword, "role": "viewer"}); rec.Code != http.StatusConflict || errCode(t, rec) != "AUTH-USER-001" {
		t.Errorf("duplicate email: %d %s", rec.Code, rec.Body)
	}
	if rec := admin.do(e, "POST", "/api/v1/users", map[string]string{"email": "w@example.com", "name": "W", "password": "short", "role": "viewer"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("weak password: %d", rec.Code)
	}

	var list struct{ Users []accountJSON }
	decodeInto(t, admin.do(e, "GET", "/api/v1/users", nil), &list)
	if len(list.Users) != 2 || strings.Contains(admin.do(e, "GET", "/api/v1/users", nil).Body.String(), "hash") {
		t.Errorf("list = %+v", list)
	}

	op := e.mustLogin("olivia@example.com", goodPassword)
	if rec := op.do(e, "GET", "/api/v1/users", nil); rec.Code != http.StatusForbidden {
		t.Errorf("operator listing users = %d, want 403", rec.Code)
	}
	if rec := op.do(e, "POST", "/api/v1/users", map[string]string{"email": "x@example.com", "name": "X", "password": goodPassword, "role": "admin"}); rec.Code != http.StatusForbidden {
		t.Errorf("operator creating admin = %d, want 403", rec.Code)
	}
	if rec := e.call(acall{method: "GET", path: "/api/v1/users"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d", rec.Code)
	}

	// Disabling ends the user's sessions and blocks sign-in.
	if rec := admin.do(e, "PATCH", "/api/v1/users/"+id, map[string]any{"disabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body)
	}
	if rec := op.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("disabled user's session still works: %d", rec.Code)
	}
	if _, rec := e.login("olivia@example.com", goodPassword); rec.Code != http.StatusUnauthorized {
		t.Errorf("disabled login = %d", rec.Code)
	}

	// Admin reset: new password works, old does not.
	if rec := admin.do(e, "POST", "/api/v1/users/"+id+"/reset", map[string]string{"password": "another long passphrase"}); rec.Code != http.StatusNoContent {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	admin.do(e, "PATCH", "/api/v1/users/"+id, map[string]any{"disabled": false})
	if _, rec := e.login("olivia@example.com", goodPassword); rec.Code != http.StatusUnauthorized {
		t.Error("old password still works after reset")
	}
	e.mustLogin("olivia@example.com", "another long passphrase")

	if rec := admin.do(e, "DELETE", "/api/v1/users/"+id, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec := admin.do(e, "PATCH", "/api/v1/users/"+id, map[string]any{"name": "Ghost"}); rec.Code != http.StatusNotFound || errCode(t, rec) != "AUTH-USER-003" {
		t.Errorf("patch deleted = %d %s", rec.Code, rec.Body)
	}
}

func TestACC1_LastAdminCannotBeRemovedOrDisabled(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	var list struct{ Users []accountJSON }
	decodeInto(t, admin.do(e, "GET", "/api/v1/users", nil), &list)
	self := list.Users[0].ID

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"disable": admin.do(e, "PATCH", "/api/v1/users/"+self, map[string]any{"disabled": true}),
		"demote":  admin.do(e, "PATCH", "/api/v1/users/"+self, map[string]any{"role": "viewer"}),
		"delete":  admin.do(e, "DELETE", "/api/v1/users/"+self, nil),
	} {
		if rec.Code != http.StatusConflict || errCode(t, rec) != "AUTH-USER-002" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}

	// With a second enabled admin the first can step down.
	e.createUser(admin, "second@example.com", "admin")
	if rec := admin.do(e, "PATCH", "/api/v1/users/"+self, map[string]any{"role": "viewer"}); rec.Code != http.StatusOK {
		t.Errorf("demote with a second admin = %d %s", rec.Code, rec.Body)
	}
}

func (e *accEnv) enrol(a actor) (secret []byte, recovery []string) {
	e.t.Helper()
	rec := a.do(e, "POST", "/api/v1/me/totp/enrol", struct{}{})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("enrol = %d %s", rec.Code, rec.Body)
	}
	var b struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	decodeInto(e.t, rec, &b)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.Secret)
	if err != nil || !strings.HasPrefix(b.URI, "otpauth://totp/") {
		e.t.Fatalf("bad enrolment %+v: %v", b, err)
	}
	rec = a.do(e, "POST", "/api/v1/me/totp/confirm", map[string]string{"code": auth.TOTPCodeAt(secret, e.clock.Now())})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	var c struct {
		Codes []string `json:"recovery_codes"`
	}
	decodeInto(e.t, rec, &c)
	if len(c.Codes) != 10 {
		e.t.Fatalf("recovery codes = %v", c.Codes)
	}
	return secret, c.Codes
}

func (e *accEnv) pending(email string) string {
	e.t.Helper()
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": email, "password": goodPassword}})
	if rec.Code != http.StatusOK || len(rec.Result().Cookies()) != 0 {
		e.t.Fatalf("expected a pending login without a cookie: %d %s", rec.Code, rec.Body)
	}
	var b struct {
		Pending struct {
			Ticket string `json:"ticket"`
		} `json:"pending"`
	}
	decodeInto(e.t, rec, &b)
	return b.Pending.Ticket
}

func TestACC2_TOTPLoginReplayAndRecovery(t *testing.T) {
	e := newAccEnv(t)
	a := e.mustLogin(adminEmail, goodPassword)
	secret, recovery := e.enrol(a)

	verify := func(ticket, code string) *httptest.ResponseRecorder {
		return e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": ticket, "code": code}})
	}

	// The confirming code is already spent: it cannot also open a session.
	ticket := e.pending(adminEmail)
	if rec := verify(ticket, auth.TOTPCodeAt(secret, e.clock.Now())); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "AUTH-TOTP-001" {
		t.Fatalf("replayed code: %d %s", rec.Code, rec.Body)
	}
	if rec := verify(ticket, "000000"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong code = %d", rec.Code)
	}

	e.clock.advance(30 * time.Second)
	good := auth.TOTPCodeAt(secret, e.clock.Now())
	rec := verify(ticket, good)
	if rec.Code != http.StatusOK || sessionCookieOf(t, rec) == nil {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	// Same code, fresh ticket: replay.
	if rec := verify(e.pending(adminEmail), good); rec.Code != http.StatusUnauthorized {
		t.Errorf("replay accepted: %d", rec.Code)
	}
	// A used ticket is gone.
	if rec := verify(ticket, good); errCode(t, rec) != "AUTH-TOTP-002" {
		t.Errorf("reused ticket: %d %s", rec.Code, rec.Body)
	}

	// Recovery code works once.
	rc := recovery[0]
	if rec := verify(e.pending(adminEmail), strings.ToLower(rc)); rec.Code != http.StatusOK {
		t.Fatalf("recovery code: %d %s", rec.Code, rec.Body)
	}
	if rec := verify(e.pending(adminEmail), rc); rec.Code != http.StatusUnauthorized {
		t.Errorf("recovery code reused: %d", rec.Code)
	}

	// A ticket expires and is bound to the address that signed in.
	tk := e.pending(adminEmail)
	e.ip = "198.51.100.9"
	if rec := verify(tk, "123456"); errCode(t, rec) != "AUTH-TOTP-002" {
		t.Errorf("ticket from another address: %s", rec.Body)
	}
	e.ip = "203.0.113.5"
	tk = e.pending(adminEmail)
	e.clock.advance(6 * time.Minute)
	if rec := verify(tk, auth.TOTPCodeAt(secret, e.clock.Now())); errCode(t, rec) != "AUTH-TOTP-002" {
		t.Errorf("expired ticket: %s", rec.Body)
	}
}

func TestACC2_TicketBurnsAfterFiveWrongCodes(t *testing.T) {
	e := newAccEnv(t)
	a := e.mustLogin(adminEmail, goodPassword)
	secret, _ := e.enrol(a)
	e.clock.advance(30 * time.Second)
	tk := e.pending(adminEmail)
	for i := 0; i < 5; i++ {
		e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": tk, "code": "000001"}})
	}
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": tk, "code": auth.TOTPCodeAt(secret, e.clock.Now())}})
	if rec.Code == http.StatusOK {
		t.Error("a ticket must not survive five wrong codes")
	}
}

func TestACC2_DisableNeedsPassword(t *testing.T) {
	e := newAccEnv(t)
	a := e.mustLogin(adminEmail, goodPassword)
	e.enrol(a)
	if rec := a.do(e, "POST", "/api/v1/me/totp/disable", map[string]string{"password": "wrong wrong wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password = %d", rec.Code)
	}
	if rec := a.do(e, "POST", "/api/v1/me/totp/disable", map[string]string{"password": goodPassword}); rec.Code != http.StatusNoContent {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body)
	}
	e.mustLogin(adminEmail, goodPassword) // password-only again
}

func TestACC2_RequireTwoFactorForEveryone(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	e.createUser(admin, "vic@example.com", "viewer")
	if rec := admin.do(e, "PUT", "/api/v1/settings/security", map[string]bool{"require_2fa": true}); rec.Code != http.StatusOK {
		t.Fatalf("set = %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(acall{method: "PUT", path: "/api/v1/settings/security", body: map[string]bool{"require_2fa": false}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous set = %d", rec.Code)
	}

	// Vic has no authenticator: login yields an enrolment-only ticket.
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": "vic@example.com", "password": goodPassword}})
	var pend struct {
		Pending struct {
			Ticket string `json:"ticket"`
			Enrol  bool   `json:"enrol_required"`
		} `json:"pending"`
	}
	decodeInto(t, rec, &pend)
	if !pend.Pending.Enrol || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("login = %s", rec.Body)
	}
	rec = e.call(acall{method: "POST", path: "/api/v1/auth/totp/enrol", body: map[string]string{"ticket": pend.Pending.Ticket}})
	var enrol struct{ Secret string }
	decodeInto(t, rec, &enrol)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrol.Secret)
	if rec.Code != http.StatusOK || err != nil {
		t.Fatalf("enrol = %d %s", rec.Code, rec.Body)
	}
	rec = e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": pend.Pending.Ticket, "code": auth.TOTPCodeAt(secret, e.clock.Now())}})
	var done struct {
		Codes []string `json:"recovery_codes"`
	}
	decodeInto(t, rec, &done)
	if rec.Code != http.StatusOK || len(done.Codes) != 10 {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	vic := actor{cookie: sessionCookieOf(t, rec), csrf: csrfOf(t, rec)}
	if rec := vic.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusOK {
		t.Errorf("signed in after enrolment = %d", rec.Code)
	}
	// While required, a user cannot switch it off.
	if rec := vic.do(e, "POST", "/api/v1/me/totp/disable", map[string]string{"password": goodPassword}); rec.Code != http.StatusConflict {
		t.Errorf("disable while required = %d %s", rec.Code, rec.Body)
	}
}

func TestACC7_LockoutAfterRepeatedFailures(t *testing.T) {
	e := newAccEnv(t)
	for i := 0; i < 5; i++ {
		rec := e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": adminEmail, "password": "wrong password here"}})
		if errCode(t, rec) != "AUTH-DENY-001" {
			t.Fatalf("attempt %d = %s", i, rec.Body)
		}
	}
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": adminEmail, "password": goodPassword}})
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "AUTH-LOCK-001" {
		t.Fatalf("locked login = %d %s", rec.Code, rec.Body)
	}
	// Another address is not locked out; the lock is per account and address.
	e.ip = "198.51.100.77"
	e.mustLogin(adminEmail, goodPassword)
	e.ip = "203.0.113.5"

	// An unknown account locks the same way: no enumeration.
	e.ip = "198.51.100.88"
	defer func() { e.ip = "203.0.113.5" }()
	for i := 0; i < 5; i++ {
		e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": "nobody@example.com", "password": "wrong password here"}})
	}
	rec = e.call(acall{method: "POST", path: "/api/v1/auth/login", body: map[string]string{"email": "nobody@example.com", "password": goodPassword}})
	if errCode(t, rec) != "AUTH-LOCK-001" {
		t.Errorf("unknown account response differs: %s", rec.Body)
	}

	// The lock lapses.
	e.ip = "203.0.113.5"
	e.clock.advance(16 * time.Minute)
	e.mustLogin(adminEmail, goodPassword)

	// Every failure and the lock itself are in the audit log.
	var failed, locked int
	rows, err := e.db.DB().Query(`SELECT action FROM audit_log WHERE action IN ('auth.login_failed', 'auth.locked')`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		if a == "auth.locked" {
			locked++
		} else {
			failed++
		}
	}
	if failed != 10 || locked != 2 {
		t.Errorf("audit: %d failures, %d locks; want 10 and 2", failed, locked)
	}
}

func TestACC7_WrongTOTPCodesLockOut(t *testing.T) {
	e := newAccEnv(t)
	a := e.mustLogin(adminEmail, goodPassword)
	e.enrol(a)
	e.clock.advance(30 * time.Second)
	for i := 0; i < 5; i++ {
		tk := e.pending(adminEmail)
		e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": tk, "code": "111111"}})
	}
	rec := e.call(acall{method: "POST", path: "/api/v1/auth/totp/verify", body: map[string]string{"ticket": e.pending(adminEmail), "code": "111111"}})
	if errCode(t, rec) != "AUTH-LOCK-001" {
		t.Errorf("sixth wrong code: %s", rec.Body)
	}
}

func TestACC6_SessionsListAndRevoke(t *testing.T) {
	e := newAccEnv(t)
	first := e.mustLogin(adminEmail, goodPassword)
	second := e.mustLogin(adminEmail, goodPassword)

	var list struct{ Sessions []sessionInfoJSON }
	decodeInto(t, second.do(e, "GET", "/api/v1/me/sessions", nil), &list)
	var current string
	for _, s := range list.Sessions {
		if s.Current {
			current = s.ID
		}
	}
	var mine struct{ Sessions []sessionInfoJSON }
	decodeInto(t, first.do(e, "GET", "/api/v1/me/sessions", nil), &mine)
	other := ""
	for _, s := range mine.Sessions {
		if s.Current {
			other = s.ID
		}
	}
	if current == "" || other == "" || current == other || len(list.Sessions) != 3 { // setup, first, second
		t.Fatalf("sessions not identified: %+v", list)
	}
	if rec := second.do(e, "DELETE", "/api/v1/me/sessions/"+other, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if rec := first.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked session still works: %d", rec.Code)
	}
	if rec := second.do(e, "DELETE", "/api/v1/me/sessions/"+other, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoke twice = %d", rec.Code)
	}
	// CSRF is enforced.
	if rec := e.call(acall{method: "DELETE", path: "/api/v1/me/sessions/" + current, cookie: second.cookie}); rec.Code != http.StatusForbidden {
		t.Errorf("revoke without CSRF = %d", rec.Code)
	}

	// Users cannot revoke each other's sessions; admins can.
	admin := e.mustLogin(adminEmail, goodPassword)
	id := e.createUser(admin, "vic@example.com", "viewer")
	vic := e.mustLogin("vic@example.com", goodPassword)
	var vs struct{ Sessions []sessionInfoJSON }
	decodeInto(t, vic.do(e, "GET", "/api/v1/me/sessions", nil), &vs)
	if rec := second.do(e, "DELETE", "/api/v1/me/sessions/"+vs.Sessions[0].ID, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking someone else's session via /me = %d", rec.Code)
	}
	if rec := vic.do(e, "GET", "/api/v1/users/"+id+"/sessions", nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer listing user sessions = %d", rec.Code)
	}
	if rec := admin.do(e, "DELETE", "/api/v1/users/"+id+"/sessions/"+vs.Sessions[0].ID, nil); rec.Code != http.StatusNoContent {
		t.Errorf("admin revoke = %d %s", rec.Code, rec.Body)
	}
	if rec := vic.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("session revoked by admin still works: %d", rec.Code)
	}
}

func TestACC6_PasswordChangeEndsOtherSessions(t *testing.T) {
	e := newAccEnv(t)
	keep := e.mustLogin(adminEmail, goodPassword)
	other := e.mustLogin(adminEmail, goodPassword)
	if rec := keep.do(e, "POST", "/api/v1/me/password", map[string]string{"current_password": "nope nope nope nope", "new_password": "a brand new passphrase"}); rec.Code != http.StatusUnauthorized { //nolint:gosec // test data
		t.Errorf("wrong current password = %d", rec.Code)
	}
	if rec := keep.do(e, "POST", "/api/v1/me/password", map[string]string{"current_password": goodPassword, "new_password": "short"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("weak new password = %d", rec.Code)
	}
	if rec := keep.do(e, "POST", "/api/v1/me/password", map[string]string{"current_password": goodPassword, "new_password": "a brand new passphrase"}); rec.Code != http.StatusNoContent {
		t.Fatalf("change = %d %s", rec.Code, rec.Body)
	}
	if rec := keep.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusOK {
		t.Errorf("current session was ended: %d", rec.Code)
	}
	if rec := other.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("other session survived a password change: %d", rec.Code)
	}
	e.mustLogin(adminEmail, "a brand new passphrase")
}

func (e *accEnv) mintToken(a actor, name string, days int, bindings any) (string, *httptest.ResponseRecorder) {
	e.t.Helper()
	rec := a.do(e, "POST", "/api/v1/me/tokens", map[string]any{"name": name, "expires_in_days": days, "bindings": bindings})
	var b struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b.Token, rec
}

func TestCLI3_TokenLifecycle(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)

	tok, rec := e.mintToken(admin, "ci", 30, []map[string]any{{"role": "admin", "scope": map[string]any{}}})
	if rec.Code != http.StatusCreated || !strings.HasPrefix(tok, "nuxt_") {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}

	// Only the hash is stored, and listing never shows the secret.
	var stored string
	if err := e.db.DB().QueryRow(`SELECT token_hash FROM api_tokens`).Scan(&stored); err != nil || stored == tok || strings.Contains(stored, tok) || len(stored) != 64 {
		t.Errorf("stored %q (%v)", stored, err)
	}
	if body := admin.do(e, "GET", "/api/v1/me/tokens", nil).Body.String(); strings.Contains(body, tok) || !strings.Contains(body, `"name":"ci"`) {
		t.Errorf("list = %s", body)
	}

	// Bearer works without CSRF, never sets a cookie and never creates a session.
	rec = e.call(acall{method: "GET", path: "/api/v1/users", bearer: tok})
	if rec.Code != http.StatusOK || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("bearer GET = %d %s", rec.Code, rec.Body)
	}
	rec = e.call(acall{method: "POST", path: "/api/v1/users", bearer: tok, body: map[string]string{"email": "bot@example.com", "name": "Bot", "password": goodPassword, "role": "viewer"}})
	if rec.Code != http.StatusCreated {
		t.Errorf("bearer POST without CSRF = %d %s", rec.Code, rec.Body)
	}
	var sessions int
	_ = e.db.DB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	if sessions != 2 { // setup and the admin sign-in
		t.Errorf("sessions = %d; tokens must not create any", sessions)
	}
	// The audit entry names the token's owner.
	var actorID string
	if err := e.db.DB().QueryRow(`SELECT actor_id FROM audit_log WHERE action = 'users.create'`).Scan(&actorID); err != nil || actorID == "" {
		t.Errorf("audit actor = %q (%v)", actorID, err)
	}

	// Credentials and tokens are session-only.
	for _, c := range []acall{
		{method: "POST", path: "/api/v1/me/tokens", body: map[string]any{"name": "x", "expires_in_days": 1, "bindings": []map[string]any{{"role": "viewer"}}}},
		{method: "POST", path: "/api/v1/me/password", body: map[string]string{"current_password": goodPassword, "new_password": "yet another passphrase"}},
		{method: "POST", path: "/api/v1/me/totp/enrol", body: struct{}{}},
	} {
		c.bearer = tok
		if rec := e.call(c); rec.Code != http.StatusForbidden {
			t.Errorf("%s with a token = %d, want 403", c.path, rec.Code)
		}
	}

	if rec := e.call(acall{method: "GET", path: "/api/v1/users", bearer: "nuxt_" + strings.Repeat("A", 43)}); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "AUTH-TOKEN-001" {
		t.Errorf("unknown token = %d %s", rec.Code, rec.Body)
	}
	// A bad bearer does not fall back to a valid cookie.
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: "garbage", cookie: admin.cookie}); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad bearer with good cookie = %d", rec.Code)
	}

	var tl struct{ Tokens []tokenJSON }
	decodeInto(t, admin.do(e, "GET", "/api/v1/me/tokens", nil), &tl)
	if tl.Tokens[0].LastUsedAt == nil {
		t.Error("last_used_at not recorded")
	}
	if rec := admin.do(e, "DELETE", "/api/v1/me/tokens/"+tl.Tokens[0].ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if rec := e.call(acall{method: "GET", path: "/api/v1/users", bearer: tok}); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token = %d", rec.Code)
	}
	if rec := admin.do(e, "DELETE", "/api/v1/me/tokens/"+tl.Tokens[0].ID, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoke twice = %d", rec.Code)
	}
}

func TestCLI3_TokenScopeSubsetAtCreationAndUse(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	opID := e.createUser(admin, "olivia@example.com", "operator")
	op := e.mustLogin("olivia@example.com", goodPassword)

	if _, rec := e.mintToken(op, "too wide", 7, []map[string]any{{"role": "admin"}}); rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-TOKEN-002" {
		t.Errorf("operator minting admin token = %d %s", rec.Code, rec.Body)
	}
	if _, rec := e.mintToken(op, "empty", 7, []map[string]any{}); rec.Code != http.StatusForbidden {
		t.Errorf("token without bindings = %d", rec.Code)
	}
	if _, rec := e.mintToken(op, "forever", 4000, []map[string]any{{"role": "viewer"}}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("lifetime over a year = %d", rec.Code)
	}
	if _, rec := e.mintToken(op, "no expiry", 0, []map[string]any{{"role": "viewer"}}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("token without expiry = %d", rec.Code)
	}
	tok, rec := e.mintToken(op, "ok", 7, []map[string]any{{"role": "operator"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("operator token = %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"operator"`) {
		t.Errorf("token me = %d %s", rec.Code, rec.Body)
	}

	// Demoting the owner narrows the token at use time.
	if rec := admin.do(e, "PATCH", "/api/v1/users/"+opID, map[string]any{"role": "viewer"}); rec.Code != http.StatusOK {
		t.Fatalf("demote = %d", rec.Code)
	}
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusUnauthorized {
		t.Errorf("token still valid after its owner lost the role: %d %s", rec.Code, rec.Body)
	}
}

func TestCLI3_TokenExpiryAndDisabledOwner(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	id := e.createUser(admin, "olivia@example.com", "operator")
	op := e.mustLogin("olivia@example.com", goodPassword)
	tok, _ := e.mintToken(op, "short", 1, []map[string]any{{"role": "viewer"}})

	e.clock.advance(11 * time.Hour) // inside the 12 hour idle timeout of the admin session
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusOK {
		t.Fatalf("before expiry = %d", rec.Code)
	}
	admin.do(e, "PATCH", "/api/v1/users/"+id, map[string]any{"disabled": true})
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusUnauthorized {
		t.Errorf("token of a disabled user = %d", rec.Code)
	}
	admin.do(e, "PATCH", "/api/v1/users/"+id, map[string]any{"disabled": false})
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusOK {
		t.Fatalf("re-enabled = %d", rec.Code)
	}
	e.clock.advance(14 * time.Hour)
	if rec := e.call(acall{method: "GET", path: "/api/v1/me", bearer: tok}); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "AUTH-TOKEN-001" {
		t.Errorf("expired token = %d %s", rec.Code, rec.Body)
	}
}

// SEC-LOGOUT: a token has no session to end, so sign-out with one is refused rather than indexing an empty hash.
func TestSEC_LogoutWithTokenIsRefused(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	tok, rec := e.mintToken(admin, "ci", 30, []map[string]any{{"role": "admin", "scope": map[string]any{}}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	rec = e.call(acall{method: "POST", path: "/api/v1/auth/logout", bearer: tok})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "AUTH-DENY-005") {
		t.Errorf("token logout = %d %s", rec.Code, rec.Body)
	}
	if rec := admin.do(e, "GET", "/api/v1/me", nil); rec.Code != http.StatusOK {
		t.Errorf("the browser session was affected: %d", rec.Code)
	}
}

// SEC-STREAM: a long-lived stream re-proves its caller on each keepalive. A bearer token must be
// checked as well (it used to end the stream, now it follows the token) and a revoked one must end it.
func TestSEC_ReauthenticateFollowsTheToken(t *testing.T) {
	e := newAccEnv(t)
	admin := e.mustLogin(adminEmail, goodPassword)
	tok, rec := e.mintToken(admin, "stream", 30, []map[string]any{{"role": "admin", "scope": map[string]any{}}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	a := &authAPI{svc: e.svc}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if p, ok := a.reauthenticate(context.Background(), r); !ok || p.Via != "token" {
		t.Fatalf("live token: ok=%v via=%q", ok, p.Via)
	}
	var tl struct{ Tokens []tokenJSON }
	decodeInto(t, admin.do(e, "GET", "/api/v1/me/tokens", nil), &tl)
	if rec := admin.do(e, "DELETE", "/api/v1/me/tokens/"+tl.Tokens[0].ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if _, ok := a.reauthenticate(context.Background(), r); ok {
		t.Error("a revoked token still re-authenticates a stream")
	}
	anon := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	if _, ok := a.reauthenticate(context.Background(), anon); ok {
		t.Error("a request with no credential re-authenticates")
	}
}
