// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A long-lived stream must stop as soon as the caller loses access: removing the
// role binding that grants it, or disabling the account.
func TestACC6_RoleRemovalAndDisableEndOpenStreams(t *testing.T) {
	old := sseKeepalive
	sseKeepalive = 40 * time.Millisecond
	t.Cleanup(func() { sseKeepalive = old })

	e := newRBACEnv(t)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	login := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword)})
	admin, csrf := sessionCookieOf(t, login), csrfOf(t, login)
	h := map[string]string{csrfHeader: csrf}

	t.Run("role binding removed", func(t *testing.T) {
		userID := e.insertUser("rolestream@example.com")
		rec := e.do(req{
			method: "POST", path: "/api/v1/role-bindings", cookie: admin, headers: h,
			body: `{"subject_type":"user","subject":"` + userID + `","role":"viewer","scope":{}}`,
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("grant = %d %q", rec.Code, rec.Body)
		}
		bindingID := decodeCreatedID(t, rec)
		viewer := e.signIn("rolestream@example.com")
		c := openStream(t, srv.URL, viewer.Value)
		if _, err := c.r.ReadString('\n'); err != nil {
			t.Fatalf("stream did not open: %v", err)
		}
		if rec := e.do(req{method: "DELETE", path: "/api/v1/role-bindings/" + bindingID, cookie: admin, headers: h}); rec.Code != http.StatusNoContent {
			t.Fatalf("revoke = %d %q", rec.Code, rec.Body)
		}
		awaitStreamEnd(t, c, "a stream whose role binding was removed")
	})

	t.Run("account disabled", func(t *testing.T) {
		userID := e.insertUser("disablestream@example.com")
		rec := e.do(req{
			method: "POST", path: "/api/v1/role-bindings", cookie: admin, headers: h,
			body: `{"subject_type":"user","subject":"` + userID + `","role":"viewer","scope":{}}`,
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("grant = %d %q", rec.Code, rec.Body)
		}
		viewer := e.signIn("disablestream@example.com")
		c := openStream(t, srv.URL, viewer.Value)
		if _, err := c.r.ReadString('\n'); err != nil {
			t.Fatalf("stream did not open: %v", err)
		}
		e.execSQL(`UPDATE users SET disabled = 1 WHERE id = ?`, userID)
		awaitStreamEnd(t, c, "a stream whose account was disabled")
	})
}

// insertUser copies the admin's password hash into a new user, as bound does.
func (e *rbacEnv) insertUser(email string) string {
	e.t.Helper()
	id := "01RB" + email[:4] + "STREAM"
	e.execSQL(`INSERT INTO users (id, email, name, password_hash, created_at) SELECT ?, ?, ?, password_hash, created_at FROM users WHERE email = ?`, id, email, email, adminEmail)
	return id
}

func (e *rbacEnv) signIn(email string) *http.Cookie {
	e.t.Helper()
	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody(email, goodPassword)})
	if rec.Code != http.StatusOK {
		e.t.Fatalf("login %s = %d %q", email, rec.Code, rec.Body)
	}
	return sessionCookieOf(e.t, rec)
}

func (e *rbacEnv) execSQL(query string, args ...any) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		e.t.Fatal(err)
	}
}

func awaitStreamEnd(t *testing.T, c *sseClient, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := c.r.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s stayed open", what)
	}
}

func decodeCreatedID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b.ID == "" {
		t.Fatalf("no id in %q: %v", rec.Body, err)
	}
	return b.ID
}
