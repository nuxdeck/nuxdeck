// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// newAuditRowsEnv wires every service that a state-changing route needs: accounts, alerting,
// channels and role bindings on top of the usual test environment.
func newAuditRowsEnv(t *testing.T) *authEnv {
	t.Helper()
	e := newAuthEnv(t)
	log := slog.New(slog.DiscardHandler)
	hasher, pol := auth.NewHasherWithParams(8, 1, 1), auth.NewPasswordPolicy()
	// Sessions expire against the store clock, which is wall time, so accounts use it too.
	acc, err := auth.NewAccounts(auth.AccountsConfig{Repo: e.db, Hasher: hasher, Passwords: pol, Log: log, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: e.db, Hasher: hasher, Passwords: pol, SetupToken: e.token, Log: log, Accounts: acc, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, secrets.KeyLen)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	e.db.UseSecrets(box)
	ca, err := pki.LoadOrCreateCA(filepath.Join(e.dir, "gateway-pki"), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The real gateway, not the fake revoker: Revoke is what writes the agent.revoke row.
	gw, err := gateway.New(context.Background(), gateway.Options{
		Log: log, Repo: e.db, CA: ca, Now: e.clock.Now,
		ServerCert: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("not serving") },
	})
	if err != nil {
		t.Fatal(err)
	}
	sender := notify.NewSender(notify.Options{Log: log, Sleep: func(context.Context, time.Duration) error { return nil }, Policy: func(bool) probe.Policy { return probe.Policy{} }})
	channels := alerting.NewChannels(alerting.ChannelOptions{DB: e.db, Secrets: box, Sender: sender, Log: log, Now: e.clock.Now})
	alerts := alerting.New(alerting.Options{DB: e.db, Checks: e.checks, Inventory: alerting.FromInventory(e.inv), Now: e.clock.Now, PublicURL: "https://nux.example.com", Log: log})
	e.h = Handler(Options{
		Log: log, Ready: e.db, UI: uiFS(), Auth: svc, PKI: e.pki, GatewayURL: "https://nux.example.com:8444", Revoker: gw,
		Inventory: e.inv, Checks: e.checks, StatusPages: e.pages, Telemetry: e.tel, Alerting: alerts, Channels: channels,
		RoleBindings: e.db, Accounts: acc,
	})
	return e
}

// adminSession is the signed-in administrator that performs every state change.
type adminSession struct {
	cookie *http.Cookie
	csrf   string
	id     string
}

func (s adminSession) do(e *authEnv, method, path, body string) *httptest.ResponseRecorder {
	return e.do(req{method: method, path: path, body: body, cookie: s.cookie, headers: map[string]string{csrfHeader: s.csrf}})
}

// etagOf returns the ETag of the item at path, which an update of a versioned item must echo
// in If-Match. Singletons such as settings have none and return "".
func etagOf(e *authEnv, s adminSession, path string) string {
	rec := s.do(e, http.MethodGet, path, "")
	if rec.Code != http.StatusOK {
		return ""
	}
	return rec.Header().Get("ETag")
}

// stateChange is one state-changing request and the audit action it must record. prep runs
// before the audit snapshot, so the rows it writes are not counted against the request.
type stateChange struct {
	name   string
	prep   func(t *testing.T, e *authEnv, s adminSession) (method, path, body string)
	action string
	status int
}

// AUD-1 (behaviour): every area that changes state writes exactly one audit row for each
// request, with the expected action, in addition to the static coverage check above.
func TestAUD1_StateChangesWriteExactlyOneAuditRow(t *testing.T) {
	e := newAuditRowsEnv(t)
	setup := e.setup()
	s := adminSession{cookie: sessionCookieOf(t, setup), csrf: csrfOf(t, setup)}
	s.id = e.queryString(t, "SELECT id FROM users WHERE email = ?", adminEmail)
	for _, c := range stateChanges() {
		t.Run(c.name, func(t *testing.T) {
			method, path, body := c.prep(t, e, s)
			headers := map[string]string{csrfHeader: s.csrf}
			if tag := etagOf(e, s, path); method == http.MethodPut && tag != "" {
				headers["If-Match"] = tag
			}
			before := e.auditRowCount(t)
			rec := e.do(req{method: method, path: path, body: body, cookie: s.cookie, headers: headers})
			if rec.Code != c.status {
				t.Fatalf("%s %s: status %d, want %d: %s", method, path, rec.Code, c.status, rec.Body)
			}
			if got := e.auditRowCount(t) - before; got != 1 {
				t.Fatalf("%s %s wrote %d audit rows, want exactly 1", method, path, got)
			}
			if got := e.queryString(t, "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1"); got != c.action {
				t.Errorf("%s %s recorded action %q, want %q", method, path, got, c.action)
			}
		})
	}
}

func stateChanges() []stateChange {
	const (
		created = http.StatusCreated
		ok      = http.StatusOK
		noBody  = http.StatusNoContent
	)
	return []stateChange{
		// users
		fixed("users create", "POST", "/api/v1/users", `{"email":"bot@example.com","name":"Bot","password":"`+goodPassword+`","role":"viewer"}`, "users.create", created),
		{name: "users update", action: "users.update", status: ok, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "PATCH", "/api/v1/users/" + newUser(t, e, s), `{"name":"Bot Renamed"}`
		}},
		{name: "users password reset", action: "users.reset", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "POST", "/api/v1/users/" + newUser(t, e, s) + "/reset", `{"password":"another long passphrase"}`
		}},
		{name: "users delete", action: "users.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/users/" + newUser(t, e, s), ""
		}},
		// checks
		fixed("checks create", "POST", "/api/v1/checks", httpCheckBody, "check.create", created),
		{name: "checks delete", action: "check.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/checks/" + create(t, s, e, "/api/v1/checks", httpCheckBody), ""
		}},
		// alert rules, channels and silences
		{name: "checks update", action: "check.update", status: ok, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "PUT", "/api/v1/checks/" + create(t, s, e, "/api/v1/checks", httpCheckBody), httpCheckBody
		}},
		{name: "rules update", action: "rule.update", status: ok, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "PUT", "/api/v1/rules/" + create(t, s, e, "/api/v1/rules", ruleBody), ruleBody
		}},
		{name: "channels update", action: "channel.update", status: ok, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "PUT", "/api/v1/channels/" + create(t, s, e, "/api/v1/channels", channelJSON("update-target")), channelJSON("oncall-renamed")
		}},
		fixed("rules create", "POST", "/api/v1/rules", ruleBody, "rule.create", created),
		{name: "rules delete", action: "rule.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/rules/" + create(t, s, e, "/api/v1/rules", ruleBody), ""
		}},
		fixed("channels create", "POST", "/api/v1/channels", channelJSON("oncall"), "channel.create", created),
		{name: "channels delete", action: "channel.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/channels/" + create(t, s, e, "/api/v1/channels", channelJSON("gone")), ""
		}},
		{name: "silences create", action: "silence.create", status: created, prep: func(_ *testing.T, e *authEnv, _ adminSession) (string, string, string) {
			return "POST", "/api/v1/silences", silenceBody(e)
		}},
		{name: "silences delete", action: "silence.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/silences/" + create(t, s, e, "/api/v1/silences", silenceBody(e)), ""
		}},
		// role bindings
		{name: "role binding create", action: "rolebinding.create", status: created, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "POST", "/api/v1/role-bindings", bindingBody(newUser(t, e, s))
		}},
		{name: "role binding delete", action: "rolebinding.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/role-bindings/" + create(t, s, e, "/api/v1/role-bindings", bindingBody(newUser(t, e, s))), ""
		}},
		// status pages
		fixed("status page create", "POST", "/api/v1/status-pages", `{"slug":"acme","title":"Acme","description":"","published":false,"components":[]}`, "status_page.create", created),
		{name: "status page delete", action: "status_page.delete", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/status-pages/" + create(t, s, e, "/api/v1/status-pages", `{"slug":"gone","title":"Gone","description":"","published":false,"components":[]}`), ""
		}},
		// settings
		fixed("settings update", "PUT", "/api/v1/settings", `{"key":"telemetry.enabled","value":false}`, "settings.update", ok),
		fixed("security settings update", "PUT", "/api/v1/settings/security", `{"require_2fa":false}`, "settings.require_2fa", ok),
		// agents: enrolment tokens and revocation
		fixed("agent token create", "POST", "/api/v1/agents/tokens", `{"ttl_seconds":600,"labels":{}}`, "agent.token.create", created),
		{name: "agent revoke", action: "agent.revoke", status: noBody, prep: func(_ *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "POST", "/api/v1/agents/" + e.newAgent(s.id) + "/revoke", ""
		}},
		// the administrator's own tokens and sessions
		fixed("own token create", "POST", "/api/v1/me/tokens", `{"name":"ci","expires_in_days":1,"bindings":[{"role":"viewer"}]}`, "tokens.create", created),
		{name: "own token delete", action: "tokens.revoke", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/me/tokens/" + create(t, s, e, "/api/v1/me/tokens", `{"name":"gone","expires_in_days":1,"bindings":[{"role":"viewer"}]}`), ""
		}},
		{name: "own session revoke", action: "sessions.revoke", status: noBody, prep: func(t *testing.T, e *authEnv, s adminSession) (string, string, string) {
			return "DELETE", "/api/v1/me/sessions/" + otherSession(t, e, s), ""
		}},
	}
}

func channelJSON(name string) string {
	return fmt.Sprintf(`{"name":%q,"type":"webhook","enabled":true,"allow_private":false,"config":{"url":"https://hooks.example.com/nux"}}`, name)
}

func fixed(name, method, path, body, action string, status int) stateChange {
	return stateChange{name: name, action: action, status: status, prep: func(*testing.T, *authEnv, adminSession) (string, string, string) {
		return method, path, body
	}}
}

// create makes a resource through the API as the administrator and returns its id. Its audit
// rows are written before the snapshot, so they do not count against the request under test.
func create(t *testing.T, s adminSession, e *authEnv, path, body string) string {
	t.Helper()
	rec := s.do(e, http.MethodPost, path, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup POST %s: %d %s", path, rec.Code, rec.Body)
	}
	var v struct {
		ID      string `json:"id"`
		Details struct {
			ID string `json:"id"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("setup POST %s: %v: %s", path, err, rec.Body)
	}
	// Token creation answers with its id under "details"; the other resources use "id".
	if id := cmpOr(v.ID, v.Details.ID); id != "" {
		return id
	}
	t.Fatalf("setup POST %s returned no id: %s", path, rec.Body)
	return ""
}

func newUser(t *testing.T, e *authEnv, s adminSession) string {
	t.Helper()
	email := fmt.Sprintf("user%d@example.com", time.Now().UnixNano())
	return create(t, s, e, "/api/v1/users", fmt.Sprintf(`{"email":%q,"name":"Temp","password":%q,"role":"viewer"}`, email, goodPassword))
}

func bindingBody(userID string) string {
	return fmt.Sprintf(`{"subject_type":"user","subject":%q,"role":"viewer","scope":{}}`, userID)
}

func silenceBody(e *authEnv) string {
	now := e.clock.Now()
	return fmt.Sprintf(`{"kind":"maintenance","selector":{"tags":["env:production"]},"starts_at":%q,"ends_at":%q,"reason":"deploy"}`,
		now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
}

// otherSession signs in a second time and returns the handle of that session, which is not
// the administrator's current one.
func otherSession(t *testing.T, e *authEnv, s adminSession) string {
	t.Helper()
	if rec := e.do(req{method: http.MethodPost, path: "/api/v1/auth/login", body: loginBody(adminEmail, goodPassword)}); rec.Code != http.StatusOK {
		t.Fatalf("second login: %d %s", rec.Code, rec.Body)
	}
	rec := s.do(e, http.MethodGet, "/api/v1/me/sessions", "")
	var v struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("sessions: %v %s", err, rec.Body)
	}
	for _, x := range v.Sessions {
		if !x.Current {
			return x.ID
		}
	}
	t.Fatalf("no second session listed: %s", rec.Body)
	return ""
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (e *authEnv) auditRowCount(t *testing.T) int {
	t.Helper()
	return int(e.queryInt(t, "SELECT COUNT(*) FROM audit_log"))
}

func (e *authEnv) queryInt(t *testing.T, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.db.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *authEnv) queryString(t *testing.T, q string, args ...any) string {
	t.Helper()
	var s string
	if err := e.db.DB().QueryRow(q, args...).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
