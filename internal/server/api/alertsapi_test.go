// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

type alertEnv struct {
	*checkEnv
	box      *secrets.Box
	alerts   *alerting.Service
	channels *alerting.Channels
	got      atomic.Value // last body received by the fake receiver
	status   atomic.Int32
	hookURL  string
}

func newAlertEnv(t *testing.T) *alertEnv {
	t.Helper()
	e := newAuthEnv(t)
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: e.db, Hasher: auth.NewHasherWithParams(8, 1, 1), Passwords: auth.NewPasswordPolicy(), SetupToken: e.token, Log: quiet,
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
	a := &alertEnv{box: box}
	a.status.Store(200)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a.got.Store(string(b))
		w.WriteHeader(int(a.status.Load()))
	}))
	t.Cleanup(recv.Close)
	a.hookURL = strings.Replace(recv.URL, "127.0.0.1", "localhost", 1) + "/hook/SECRET-HOOK-PATH"

	sender := notify.NewSender(notify.Options{
		Policy: func(bool) probe.Policy { return probe.Policy{AllowLoopback: true} },
		Sleep:  func(context.Context, time.Duration) error { return nil },
	})
	a.channels = alerting.NewChannels(alerting.ChannelOptions{DB: e.db, Secrets: box, Sender: sender, Log: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), Now: e.clock.Now})
	a.alerts = alerting.New(alerting.Options{DB: e.db, Checks: e.checks, Inventory: alerting.FromInventory(e.inv), Now: e.clock.Now, PublicURL: "https://nux.example.com", Log: quiet})
	e.h = Handler(Options{
		Log: quiet, Ready: e.db, UI: uiFS(), Auth: svc, PKI: e.pki, GatewayURL: "https://nux.example.com:8444", Revoker: e.revoker,
		Inventory: e.inv, Checks: e.checks, Alerting: a.alerts, Channels: a.channels,
	})
	signedIn := e.setup()
	c := &checkEnv{authEnv: e, admin: sessionCookieOf(t, signedIn), adminCSRF: csrfOf(t, signedIn)}
	c.operator, c.opCSRF = e.signInAs("operator")
	c.viewer, c.viewerCSRF = e.signInAs("viewer")
	a.checkEnv = c
	return a
}

func (a *alertEnv) as(role, method, path, body, ifMatch string) *httptest.ResponseRecorder {
	switch role {
	case "admin":
		return a.send(method, path, body, a.admin, a.adminCSRF, ifMatch)
	case "operator":
		return a.send(method, path, body, a.operator, a.opCSRF, ifMatch)
	case "viewer":
		return a.send(method, path, body, a.viewer, a.viewerCSRF, ifMatch)
	}
	return a.send(method, path, body, nil, "", ifMatch)
}

func (a *alertEnv) mustCode(rec *httptest.ResponseRecorder, want int) *httptest.ResponseRecorder {
	a.t.Helper()
	if rec.Code != want {
		a.t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body)
	}
	return rec
}

const ruleBody = `{"name":"Prod hosts offline","kind":"host_offline","severity":"critical","enabled":true,"selector":{"tags":["env:production"]},"params":{"for_s":60}}`

func (a *alertEnv) channelBody() string {
	return `{"name":"oncall","type":"webhook","enabled":true,"allow_private":false,"config":{"url":"` + a.hookURL + `","headers":[{"name":"X-Token","secret":true,"secret_value":"HDR-SECRET-VALUE"}]}}`
}

func (a *alertEnv) insertAlert(id, state string) {
	a.t.Helper()
	db := a.rawDB()
	defer func() { _ = db.Close() }()
	resolved := "NULL"
	if state == "resolved" {
		resolved = "1"
	}
	_, err := db.Exec(`INSERT INTO alerts (id, rule_id, rule_name, kind, severity, fingerprint, item_type, item_id, item_name, summary, state, opened_at, resolved_at)
		VALUES (?, '01RRRRRRRRRRRRRRRRRRRRRRRR', 'Host offline', 'host_offline', 'critical', ?, 'host', '01HHHHHHHHHHHHHHHHHHHHHHHH', 'web-1', 'Agent is offline', ?, 1000, `+resolved+`)`, id, id, state)
	if err != nil {
		a.t.Fatal(err)
	}
}

const (
	alertA = "01AAAAAAAAAAAAAAAAAAAAAAA1"
	alertB = "01AAAAAAAAAAAAAAAAAAAAAAA2"
	alertC = "01AAAAAAAAAAAAAAAAAAAAAAA3"
	nobody = "01NNNNNNNNNNNNNNNNNNNNNNNN"
)

// Every endpoint: anonymous 401, and the role boundary of docs/08-engineering-spec.md.
func TestALR_RolesGateEveryEndpoint(t *testing.T) {
	a := newAlertEnv(t)
	rule := decodeMap(t, a.mustCode(a.as("operator", "POST", "/api/v1/rules", ruleBody, ""), 201))
	ruleID := rule["id"].(string)
	ch := decodeMap(t, a.mustCode(a.as("admin", "POST", "/api/v1/channels", a.channelBody(), ""), 201))
	chID := ch["id"].(string)
	a.insertAlert(alertA, "open")
	end := a.clock.Now().Add(time.Hour).Format(time.RFC3339)
	silenceBody := `{"selector":{"tags":["env:staging"]},"ends_at":"` + end + `","reason":"deploy"}`

	type ep struct {
		method, path, body string
		min                string // lowest role allowed
		ifMatch            string
	}
	eps := []ep{
		{"GET", "/api/v1/rules", "", "viewer", ""},
		{"GET", "/api/v1/rules/" + ruleID, "", "viewer", ""},
		{"POST", "/api/v1/rules", ruleBody, "operator", ""},
		{"PUT", "/api/v1/rules/" + nobody, ruleBody, "operator", `"a1"`},
		{"DELETE", "/api/v1/rules/" + nobody, "", "operator", ""},
		{"GET", "/api/v1/alerts", "", "viewer", ""},
		{"GET", "/api/v1/alerts/" + alertA, "", "viewer", ""},
		{"POST", "/api/v1/alerts/" + nobody + "/ack", "", "operator", ""},
		{"GET", "/api/v1/silences", "", "viewer", ""},
		{"POST", "/api/v1/silences", silenceBody, "operator", ""},
		{"DELETE", "/api/v1/silences/" + nobody, "", "operator", ""},
		{"GET", "/api/v1/channels", "", "admin", ""},
		{"GET", "/api/v1/channels/" + chID, "", "admin", ""},
		{"POST", "/api/v1/channels", `{"name":"slack","type":"slack","config":{"url":"https://hooks.slack.com/services/A/B/C"}}`, "admin", ""},
		{"PUT", "/api/v1/channels/" + nobody, a.channelBody(), "admin", `"n1"`},
		{"DELETE", "/api/v1/channels/" + nobody, "", "admin", ""},
		{"POST", "/api/v1/channels/" + nobody + "/test", "", "admin", ""},
		{"GET", "/api/v1/routes", "", "admin", ""},
		{"PUT", "/api/v1/routes", `{"routes":[]}`, "admin", `"r0"`},
	}
	rank := map[string]int{"anon": 0, "viewer": 1, "operator": 2, "admin": 3}
	for _, e := range eps {
		for _, role := range []string{"anon", "viewer", "operator", "admin"} {
			rec := a.as(role, e.method, e.path, e.body, e.ifMatch)
			name := role + " " + e.method + " " + e.path
			switch {
			case role == "anon":
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s = %d, want 401", name, rec.Code)
				}
			case rank[role] < rank[e.min]:
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s = %d, want 403", name, rec.Code)
				}
			default:
				if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden || rec.Code >= 500 {
					t.Errorf("%s = %d %s, want an allowed outcome", name, rec.Code, rec.Body)
				}
			}
		}
	}
	// A denied write changed nothing.
	if n := a.count(`SELECT count(*) FROM alert_rules`); n < 1 {
		t.Error("rules vanished")
	}
	// Writes need the CSRF token.
	for _, e := range eps {
		if e.method == "GET" {
			continue
		}
		rec := a.send(e.method, e.path, e.body, a.admin, "", e.ifMatch)
		if rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
			t.Errorf("%s %s without CSRF = %d", e.method, e.path, rec.Code)
		}
	}
}

func (a *alertEnv) count(q string, args ...any) int {
	a.t.Helper()
	db := a.rawDB()
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		a.t.Fatal(err)
	}
	return n
}

func TestALR1_RulesLifecycleAndPreconditions(t *testing.T) {
	a := newAlertEnv(t)
	rec := a.mustCode(a.as("operator", "POST", "/api/v1/rules", ruleBody, ""), 201)
	rule := decodeMap(t, rec)
	etag := rec.Header().Get("ETag")
	id := rule["id"].(string)
	if etag == "" || rec.Header().Get("Location") != "/api/v1/rules/"+id {
		t.Errorf("etag %q location %q", etag, rec.Header().Get("Location"))
	}
	if rule["params"].(map[string]any)["for_s"] != float64(60) || rule["created_by"] != "01OPERATOR" {
		t.Errorf("rule = %v", rule)
	}

	got := a.mustCode(a.as("viewer", "GET", "/api/v1/rules/"+id, "", ""), 200)
	if got.Header().Get("ETag") != etag {
		t.Error("GET etag differs")
	}
	// No If-Match -> 428; stale -> 412; fresh -> 200 and a new ETag.
	if rec := a.as("operator", "PUT", "/api/v1/rules/"+id, ruleBody, ""); rec.Code != 428 || errCode(t, rec) != "API-PRE-002" {
		t.Errorf("no If-Match = %d %s", rec.Code, rec.Body)
	}
	if rec := a.as("operator", "PUT", "/api/v1/rules/"+id, ruleBody, `"a99"`); rec.Code != 412 || errCode(t, rec) != "API-PRE-001" {
		t.Errorf("stale = %d %s", rec.Code, rec.Body)
	}
	upd := strings.Replace(ruleBody, "Prod hosts offline", "Renamed", 1)
	rec = a.mustCode(a.as("operator", "PUT", "/api/v1/rules/"+id, upd, etag), 200)
	if rec.Header().Get("ETag") == etag || decodeMap(t, rec)["name"] != "Renamed" {
		t.Errorf("update = %s", rec.Body)
	}
	if rec := a.as("operator", "PUT", "/api/v1/rules/"+id, upd, etag); rec.Code != 412 {
		t.Errorf("reusing the old ETag = %d", rec.Code)
	}
	// Echoing a GET document back is accepted.
	cur := a.mustCode(a.as("operator", "GET", "/api/v1/rules/"+id, "", ""), 200)
	a.mustCode(a.as("operator", "PUT", "/api/v1/rules/"+id, cur.Body.String(), cur.Header().Get("ETag")), 200)

	list := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/rules", "", ""), 200))
	if len(list.Items) != 1 {
		t.Errorf("list = %v", list.Items)
	}
	a.mustCode(a.as("operator", "DELETE", "/api/v1/rules/"+id, "", ""), 204)
	a.mustCode(a.as("operator", "GET", "/api/v1/rules/"+id, "", ""), 404)
	a.mustCode(a.as("operator", "DELETE", "/api/v1/rules/"+id, "", ""), 404)
	a.mustCode(a.as("operator", "GET", "/api/v1/rules/not-an-id", "", ""), 404)
}

func TestALR1_RuleValidationNegatives(t *testing.T) {
	a := newAlertEnv(t)
	for name, body := range map[string]string{
		"unknown kind":      `{"name":"x","kind":"disk_full","severity":"info","params":{}}`,
		"unknown field":     `{"name":"x","kind":"check_down","severity":"info","params":{},"extra":1}`,
		"unknown param":     `{"name":"x","kind":"check_down","severity":"info","params":{"threshold":1}}`,
		"bad severity":      `{"name":"x","kind":"check_down","severity":"fatal","params":{}}`,
		"threshold range":   `{"name":"x","kind":"metric_threshold","severity":"info","params":{"target":"host","metric":"cpu","threshold":500}}`,
		"empty name":        `{"name":" ","kind":"check_down","severity":"info","params":{}}`,
		"tag selector bad":  `{"name":"x","kind":"check_down","severity":"info","params":{},"selector":{"tags":["a b"]}}`,
		"severity selector": `{"name":"x","kind":"check_down","severity":"info","params":{},"selector":{"severity":["info"]}}`,
	} {
		if rec := a.as("operator", "POST", "/api/v1/rules", body, ""); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s = %d %s, want 4xx", name, rec.Code, rec.Body)
		} else if errCode(t, rec) != "API-VAL-001" {
			t.Errorf("%s code = %s", name, errCode(t, rec))
		}
	}
	if rec := a.send("POST", "/api/v1/rules", ruleBody, a.operator, a.opCSRF, ""); rec.Code != 201 {
		t.Fatal("setup")
	}
	// Not JSON.
	rec := a.do(req{method: "POST", path: "/api/v1/rules", body: ruleBody, cookie: a.operator, noJSON: true, headers: map[string]string{csrfHeader: a.opCSRF}})
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("no content type = %d", rec.Code)
	}
}

func TestALR_AlertsListFilterAndAck(t *testing.T) {
	a := newAlertEnv(t)
	a.insertAlert(alertA, "open")
	a.insertAlert(alertB, "resolved")
	a.insertAlert(alertC, "open")

	list := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/alerts", "", ""), 200))
	if len(list.Items) != 3 || list.Items[0]["id"] != alertC {
		t.Fatalf("newest first expected: %v", list.Items)
	}
	first := list.Items[0]
	if first["link"] != "https://nux.example.com/hosts/01HHHHHHHHHHHHHHHHHHHHHHHH" || first["item_type"] != "host" || first["state"] != "open" {
		t.Errorf("alert = %v", first)
	}
	if got := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/alerts?state=resolved", "", ""), 200)); len(got.Items) != 1 {
		t.Errorf("resolved filter = %d", len(got.Items))
	}
	if got := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/alerts?state=active&limit=1", "", ""), 200)); len(got.Items) != 1 || got.NextCursor == nil {
		t.Errorf("paging = %+v", got)
	}
	for _, q := range []string{"state=weird", "severity=huge", "cursor=zzz", "limit=0", "item_id=bad"} {
		if rec := a.as("viewer", "GET", "/api/v1/alerts?"+q, "", ""); rec.Code != 422 {
			t.Errorf("?%s = %d", q, rec.Code)
		}
	}

	rec := a.mustCode(a.as("operator", "POST", "/api/v1/alerts/"+alertA+"/ack", "", ""), 200)
	ack := decodeMap(t, rec)
	if ack["state"] != "acked" || ack["acked_by"] != "01OPERATOR" || ack["acked_at"] == nil {
		t.Errorf("ack = %v", ack)
	}
	a.mustCode(a.as("admin", "POST", "/api/v1/alerts/"+alertA+"/ack", "", ""), 200) // idempotent
	if got := decodeMap(t, a.mustCode(a.as("viewer", "GET", "/api/v1/alerts/"+alertA, "", ""), 200)); got["acked_by"] != "01OPERATOR" {
		t.Errorf("ack replaced by the second call: %v", got)
	}
	if rec := a.as("operator", "POST", "/api/v1/alerts/"+alertB+"/ack", "", ""); rec.Code != 409 || errCode(t, rec) != "ALR-RULE-001" {
		t.Errorf("ack resolved = %d %s", rec.Code, rec.Body)
	}
	a.mustCode(a.as("operator", "POST", "/api/v1/alerts/"+nobody+"/ack", "", ""), 404)
	if a.count(`SELECT count(*) FROM audit_log WHERE action = 'alert.ack'`) != 1 {
		t.Error("ack audit entries")
	}
}

func TestALR5_SilencesAPI(t *testing.T) {
	a := newAlertEnv(t)
	now := a.clock.Now()
	body := func(extra string) string {
		return `{"selector":{"tags":["env:staging"]},"ends_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `","reason":"deploy"` + extra + `}`
	}
	rec := a.mustCode(a.as("operator", "POST", "/api/v1/silences", body(""), ""), 201)
	s := decodeMap(t, rec)
	if s["state"] != "active" || s["kind"] != "silence" || s["created_by"] != "01OPERATOR" || s["reason"] != "deploy" {
		t.Errorf("silence = %v", s)
	}
	m := decodeMap(t, a.mustCode(a.as("operator", "POST", "/api/v1/silences",
		`{"kind":"maintenance","selector":{"ids":["01HHHHHHHHHHHHHHHHHHHHHHHH"]},"starts_at":"`+now.Add(2*time.Hour).Format(time.RFC3339)+`","ends_at":"`+now.Add(3*time.Hour).Format(time.RFC3339)+`","reason":"patching"}`, ""), 201))
	if m["state"] != "scheduled" || m["kind"] != "maintenance" {
		t.Errorf("maintenance = %v", m)
	}
	list := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/silences?active=true", "", ""), 200))
	if len(list.Items) != 2 {
		t.Errorf("list = %v", list.Items)
	}
	for name, b := range map[string]string{
		"no selector":    `{"selector":{},"ends_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `","reason":"x"}`,
		"no reason":      `{"selector":{"tags":["a"]},"ends_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`,
		"too long":       `{"selector":{"tags":["a"]},"ends_at":"` + now.Add(40*24*time.Hour).Format(time.RFC3339) + `","reason":"x"}`,
		"in the past":    `{"selector":{"tags":["a"]},"ends_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","reason":"x"}`,
		"bad time":       `{"selector":{"tags":["a"]},"ends_at":"tomorrow","reason":"x"}`,
		"unknown field":  `{"selector":{"tags":["a"]},"ends_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `","reason":"x","bogus":1}`,
		"end before beg": `{"selector":{"tags":["a"]},"starts_at":"` + now.Add(2*time.Hour).Format(time.RFC3339) + `","ends_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `","reason":"x"}`,
	} {
		if rec := a.as("operator", "POST", "/api/v1/silences", b, ""); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	a.mustCode(a.as("operator", "DELETE", "/api/v1/silences/"+s["id"].(string), "", ""), 204)
	a.mustCode(a.as("operator", "DELETE", "/api/v1/silences/"+s["id"].(string), "", ""), 404)
	if list := decodeList(t, a.mustCode(a.as("viewer", "GET", "/api/v1/silences", "", ""), 200)); len(list.Items) != 1 {
		t.Errorf("after delete = %v", list.Items)
	}
}

// ALR-3 / T7: credentials are write-only, never logged, audited or stored in the clear.
func TestALR3_ChannelSecretsNeverLeak(t *testing.T) {
	a := newAlertEnv(t)
	rec := a.mustCode(a.as("admin", "POST", "/api/v1/channels", a.channelBody(), ""), 201)
	ch := decodeMap(t, rec)
	id, etag := ch["id"].(string), rec.Header().Get("ETag")
	cfg := ch["config"].(map[string]any)
	if cfg["url"].(map[string]any)["set"] != true {
		t.Fatalf("config = %v", cfg)
	}
	if hd := cfg["headers"].([]any)[0].(map[string]any); hd["secret_value"].(map[string]any)["set"] != true || hd["value"] != nil {
		t.Fatalf("header = %v", hd)
	}
	if ch["last_status"] != "never" || ch["last_sent_at"] != nil {
		t.Errorf("channel = %v", ch)
	}

	a.mustCode(a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""), 200)
	body, _ := a.got.Load().(string)
	if !strings.Contains(body, `"test":true`) {
		t.Errorf("receiver got %q", body)
	}

	responses := []string{
		rec.Body.String(),
		a.as("admin", "GET", "/api/v1/channels", "", "").Body.String(),
		a.as("admin", "GET", "/api/v1/channels/"+id, "", "").Body.String(),
	}
	for _, r := range responses {
		for _, secret := range []string{"SECRET-HOOK-PATH", "HDR-SECRET-VALUE", "localhost:"} {
			if strings.Contains(r, secret) {
				t.Fatalf("%q leaked in %s", secret, r)
			}
		}
	}
	got := a.mustCode(a.as("admin", "GET", "/api/v1/channels/"+id, "", ""), 200)
	if got.Header().Get("ETag") != etag {
		t.Errorf("etag changed by a test send: %s vs %s", got.Header().Get("ETag"), etag)
	}
	if after := decodeMap(t, got); after["last_status"] != "ok" || after["last_sent_at"] == nil {
		t.Errorf("delivery result not recorded: %v", after)
	}
	// Echo the document: secrets are kept (PUT with {"set":true}).
	a.mustCode(a.as("admin", "PUT", "/api/v1/channels/"+id, got.Body.String(), etag), 200)
	a.clock.advance(time.Minute)
	a.mustCode(a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""), 200)

	if logs := a.logs.String(); strings.Contains(logs, "SECRET-HOOK-PATH") || strings.Contains(logs, "HDR-SECRET-VALUE") {
		t.Error("a secret reached the logs")
	}
	db := a.rawDB()
	defer func() { _ = db.Close() }()
	for _, q := range []string{`SELECT group_concat(details_json) FROM audit_log`, `SELECT group_concat(config_json || secret_refs_json) FROM channels`, `SELECT group_concat(hex(ciphertext)) FROM secrets`} {
		var s string
		_ = db.QueryRow(q).Scan(&s)
		if strings.Contains(s, "SECRET-HOOK-PATH") || strings.Contains(s, "HDR-SECRET-VALUE") || strings.Contains(s, "localhost") {
			t.Errorf("plaintext in %q", q)
		}
	}
	if a.count(`SELECT count(*) FROM audit_log WHERE action = 'channel.test'`) != 2 || a.count(`SELECT count(*) FROM audit_log WHERE action IN ('channel.create','channel.update')`) != 2 {
		t.Error("channel changes and tests are not all audited")
	}
}

func TestALR3_ChannelPreconditionsRateLimitAndValidation(t *testing.T) {
	a := newAlertEnv(t)
	rec := a.mustCode(a.as("admin", "POST", "/api/v1/channels", a.channelBody(), ""), 201)
	id, etag := decodeMap(t, rec)["id"].(string), rec.Header().Get("ETag")
	if rec := a.as("admin", "PUT", "/api/v1/channels/"+id, a.channelBody(), ""); rec.Code != 428 {
		t.Errorf("no If-Match = %d", rec.Code)
	}
	if rec := a.as("admin", "PUT", "/api/v1/channels/"+id, a.channelBody(), `"n42"`); rec.Code != 412 {
		t.Errorf("stale = %d", rec.Code)
	}
	a.mustCode(a.as("admin", "PUT", "/api/v1/channels/"+id, strings.Replace(a.channelBody(), `"oncall"`, `"oncall-2"`, 1), etag), 200)

	a.mustCode(a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""), 200)
	if rec := a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""); rec.Code != 429 || errCode(t, rec) != "ALR-SEND-006" || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second test = %d %s", rec.Code, rec.Body)
	}
	a.clock.advance(11 * time.Second)
	a.status.Store(500)
	if rec := a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""); rec.Code != 502 || errCode(t, rec) != "ALR-SEND-002" {
		t.Errorf("failing receiver = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(a.as("admin", "GET", "/api/v1/channels/"+id, "", "").Body.String(), `"last_error_code":"ALR-SEND-002"`) == false {
		t.Error("failure not recorded on the channel")
	}

	for name, body := range map[string]string{ //nolint:gosec // test documents, not credentials
		"unknown type":    `{"name":"x","type":"sms","config":{}}`,
		"http slack":      `{"name":"x","type":"slack","config":{"url":"http://hooks.slack.com/x"}}`,
		"metadata target": `{"name":"x","type":"webhook","config":{"url":"http://169.254.169.254/latest/meta-data"}}`,
		"loopback target": `{"name":"x","type":"webhook","config":{"url":"https://127.0.0.1/hook"}}`,
		"missing secret":  `{"name":"x","type":"slack","config":{}}`,
		"unknown config":  `{"name":"x","type":"slack","config":{"url":"https://a.example/b","token":"t"}}`,
		"smtp plaintext":  `{"name":"x","type":"smtp","config":{"host":"m.example.com","security":"none","username":"u","password":"p","from":"a@example.com","to":["b@example.com"]}}`,
		"smtp injection":  `{"name":"x","type":"smtp","config":{"host":"m.example.com","from":"a@example.com","to":["b@example.com\r\nBcc: e@evil.test"]}}`,
		"duplicate name":  `{"name":"oncall-2","type":"slack","config":{"url":"https://hooks.slack.com/a"}}`,
		"empty name":      `{"name":"","type":"slack","config":{"url":"https://hooks.slack.com/a"}}`,
	} {
		if rec := a.as("admin", "POST", "/api/v1/channels", body, ""); rec.Code != 422 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	a.mustCode(a.as("admin", "DELETE", "/api/v1/channels/"+id, "", ""), 204)
	a.mustCode(a.as("admin", "POST", "/api/v1/channels/"+id+"/test", "", ""), 404)
}

// T11: a channel that reaches loopback or cloud metadata is refused when sending, whatever the name.
func TestT11_WebhookSSRFBlockedAtSendTime(t *testing.T) {
	a := newAlertEnv(t)
	rec := a.mustCode(a.as("admin", "POST", "/api/v1/channels", `{"name":"local","type":"webhook","enabled":true,"config":{"url":"`+a.hookURL+`"}}`, ""), 201)
	id := decodeMap(t, rec)["id"].(string)
	// The production sender: strict policy, same database and secrets.
	prod := alerting.NewChannels(alerting.ChannelOptions{DB: a.db, Secrets: a.box, Sender: notify.NewSender(notify.Options{}), Now: a.clock.Now})
	err := prod.Deliver(context.Background(), id, notify.Message{Kind: "firing"})
	if err == nil || !strings.Contains(err.Error(), "ALR-SEND-003") {
		t.Fatalf("err = %v, want ALR-SEND-003", err)
	}
	if _, ok := a.got.Load().(string); ok {
		t.Error("the receiver was reached")
	}
	ch, _ := prod.Get(context.Background(), id)
	if ch.LastStatus != "failed" || ch.LastErrorCode != "ALR-SEND-003" {
		t.Errorf("channel = %+v", ch)
	}
}

func TestALR4_RoutesAPI(t *testing.T) {
	a := newAlertEnv(t)
	rec := a.mustCode(a.as("admin", "GET", "/api/v1/routes", "", ""), 200)
	if rec.Header().Get("ETag") != `"r0"` || strings.TrimSpace(rec.Body.String()) != `{"routes":[]}` {
		t.Fatalf("empty routes = %q %s", rec.Header().Get("ETag"), rec.Body)
	}
	ch := decodeMap(t, a.mustCode(a.as("admin", "POST", "/api/v1/channels", a.channelBody(), ""), 201))["id"].(string)
	body := `{"routes":[{"selector":{"tags":["env:production"],"severity":["critical"]},"channel_id":"` + ch + `","continue":true},{"selector":{},"channel_id":"` + ch + `","continue":false}]}`
	if rec := a.as("admin", "PUT", "/api/v1/routes", body, ""); rec.Code != 428 {
		t.Errorf("no If-Match = %d", rec.Code)
	}
	if rec := a.as("admin", "PUT", "/api/v1/routes", body, `"r7"`); rec.Code != 412 {
		t.Errorf("stale = %d", rec.Code)
	}
	for name, b := range map[string]string{
		"unknown channel": `{"routes":[{"selector":{},"channel_id":"` + nobody + `"}]}`,
		"bad channel id":  `{"routes":[{"selector":{},"channel_id":"x"}]}`,
		"bad selector":    `{"routes":[{"selector":{"tags":["a b"]},"channel_id":"` + ch + `"}]}`,
		"unknown field":   `{"routes":[{"selector":{},"channel_id":"` + ch + `","extra":1}]}`,
		"ids in selector": `{"routes":[{"selector":{"ids":["` + nobody + `"]},"channel_id":"` + ch + `"}]}`,
	} {
		if rec := a.as("admin", "PUT", "/api/v1/routes", b, `"r0"`); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	rec = a.mustCode(a.as("admin", "PUT", "/api/v1/routes", body, `"r0"`), 200)
	if rec.Header().Get("ETag") != `"r1"` {
		t.Errorf("etag = %s", rec.Header().Get("ETag"))
	}
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Routes) != 2 || doc.Routes[0]["id"] == "" || doc.Routes[0]["continue"] != true {
		t.Errorf("routes = %s", rec.Body)
	}
	// The GET document can be sent back unchanged (ids are ignored and reassigned).
	got := a.mustCode(a.as("admin", "GET", "/api/v1/routes", "", ""), 200)
	a.mustCode(a.as("admin", "PUT", "/api/v1/routes", got.Body.String(), got.Header().Get("ETag")), 200)
	if a.count(`SELECT count(*) FROM routes`) != 2 || a.count(`SELECT count(*) FROM audit_log WHERE action = 'routes.update'`) != 2 {
		t.Error("routes or their audit entries")
	}
	// Deleting the channel removes its routes and moves the version.
	a.mustCode(a.as("admin", "DELETE", "/api/v1/channels/"+ch, "", ""), 204)
	after := a.mustCode(a.as("admin", "GET", "/api/v1/routes", "", ""), 200)
	if strings.TrimSpace(after.Body.String()) != `{"routes":[]}` || after.Header().Get("ETag") != `"r3"` {
		t.Errorf("after channel delete: %s %s", after.Header().Get("ETag"), after.Body)
	}
}
