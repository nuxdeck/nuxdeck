// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

type metricsEnv struct {
	*authEnv
	admin  *http.Cookie
	hostID string
	ctrID  string
	agent  string
}

func newMetricsEnv(t *testing.T) *metricsEnv {
	t.Helper()
	e := newAuthEnv(t)
	signedIn := e.setup()
	cookie := sessionCookieOf(t, signedIn)
	agent := e.newAgent(adminIDOf(t, signedIn))
	e.inv.HandleMessage(agent, hostMsg("web-1", "web"))
	hosts := decodeList(t, e.do(req{method: "GET", path: "/api/v1/hosts", cookie: cookie}))
	hostID := hosts.Items[0]["id"].(string)
	ctrID := decodeList(t, e.do(req{method: "GET", path: "/api/v1/containers", cookie: cookie})).Items[0]["id"].(string)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mt, err := metrics.Open(metrics.Options{Dir: filepath.Join(e.dir, "tsdb"), Log: log, Inventory: e.inv.Index()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mt.Close() })
	svc, err := auth.NewService(context.Background(), auth.Config{
		Repo: e.db, Hasher: auth.NewHasherWithParams(8, 1, 1), Passwords: auth.NewPasswordPolicy(), SetupToken: e.token, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = Handler(Options{Log: log, Ready: e.db, UI: uiFS(), Auth: svc, PKI: e.pki, Revoker: e.revoker, Inventory: e.inv, Metrics: mt})

	now := time.Now().Add(-time.Second)
	mt.HandleMessage(agent, &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricBatch{Series: []*agentv1.Series{
		{
			Target: &agentv1.Target{Kind: agentv1.TargetKind_TARGET_KIND_HOST}, Metric: "nux_host_cpu_usage_ratio", Labels: map[string]string{"cpu": "all"},
			Points: []*agentv1.Point{{TsUnixMs: now.UnixMilli(), Value: 0.5}},
		},
	}}}})
	return &metricsEnv{authEnv: e, admin: cookie, hostID: hostID, ctrID: ctrID, agent: agent}
}

func (m *metricsEnv) queryPath(target, metric string) string {
	to := time.Now().Add(time.Minute)
	return "/api/v1/metrics/query?target=" + target + "&metric=" + metric +
		"&from=" + strconv.FormatInt(to.Add(-time.Hour).UnixMilli(), 10) + "&to=" + strconv.FormatInt(to.UnixMilli(), 10)
}

func TestMetricsEndpointsAuthoriseFirst(t *testing.T) {
	m := newMetricsEnv(t)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(m.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, created_at) SELECT '01NOROLE', 'norole@example.com', 'n', password_hash, created_at FROM users WHERE email = ?`, adminEmail); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	rec := m.do(req{method: "POST", path: "/api/v1/auth/login", body: loginBody("norole@example.com", goodPassword)})
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d %q", rec.Code, rec.Body)
	}
	noRole := sessionCookieOf(t, rec)

	paths := []string{
		m.queryPath(m.hostID, "nux_host_cpu_usage_ratio"), "/api/v1/overview/pressure",
		// Invalid input must not be reported before authorisation.
		"/api/v1/metrics/query?target=%00&metric=x",
	}
	for _, p := range paths {
		if got := m.do(req{method: "GET", path: p}).Code; got != http.StatusUnauthorized {
			t.Errorf("anonymous %s = %d, want 401", p, got)
		}
		if got := m.do(req{method: "GET", path: p, cookie: noRole}).Code; got != http.StatusForbidden {
			t.Errorf("no-role %s = %d, want 403", p, got)
		}
	}
}

func TestMetricsQueryAPI(t *testing.T) {
	m := newMetricsEnv(t)
	rec := m.do(req{method: "GET", path: m.queryPath(m.hostID, "nux_host_cpu_usage_ratio"), cookie: m.admin})
	if rec.Code != http.StatusOK {
		t.Fatalf("query = %d %q", rec.Code, rec.Body)
	}
	var body struct {
		Resolution string `json:"resolution"`
		Kind       string `json:"kind"`
		Series     []struct {
			Metric string            `json:"metric"`
			Labels map[string]string `json:"labels"`
			Points [][2]float64      `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Resolution != "full" || len(body.Series) != 1 || body.Series[0].Points[0][1] != 0.5 || body.Series[0].Labels["cpu"] != "all" {
		t.Fatalf("body = %s", rec.Body)
	}

	to := strconv.FormatInt(time.Now().UnixMilli(), 10)
	from := strconv.FormatInt(time.Now().Add(-time.Hour).UnixMilli(), 10)
	cases := map[string]struct {
		path   string
		status int
		field  string
	}{
		"bad target":     {"/api/v1/metrics/query?target=nope&metric=nux_host_load_average&from=" + from + "&to=" + to, 422, "target"},
		"unknown target": {"/api/v1/metrics/query?target=01AAAAAAAAAAAAAAAAAAAAAAAA&metric=nux_host_load_average&from=" + from + "&to=" + to, 404, ""},
		"injection":      {"/api/v1/metrics/query?target=" + m.hostID + "&metric=up%7Bx%3D%22y%22%7D&from=" + from + "&to=" + to, 422, "metric"},
		"wrong kind":     {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_container_cpu_usage_ratio&from=" + from + "&to=" + to, 422, "metric"},
		"missing from":   {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&to=" + to, 422, "from"},
		"to before from": {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&from=" + to + "&to=" + from, 422, "to"},
		"huge range":     {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&from=1000&to=" + to, 422, "from"},
		"bad step":       {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&from=" + from + "&to=" + to + "&step=0", 422, "step"},
		"bad label":      {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&from=" + from + "&to=" + to + "&label=evil:1", 422, "label"},
		"label no colon": {"/api/v1/metrics/query?target=" + m.hostID + "&metric=nux_host_load_average&from=" + from + "&to=" + to + "&label=mode", 422, "label"},
		"pressure limit": {"/api/v1/overview/pressure?limit=0", 422, "limit"},
	}
	for name, c := range cases {
		rec := m.do(req{method: "GET", path: c.path, cookie: m.admin})
		if rec.Code != c.status {
			t.Errorf("%s = %d %q, want %d", name, rec.Code, rec.Body, c.status)
			continue
		}
		if c.field != "" {
			var e struct{ Error struct{ Code, Field string } }
			_ = json.Unmarshal(rec.Body.Bytes(), &e)
			if e.Error.Field != c.field || e.Error.Code != "API-VAL-001" {
				t.Errorf("%s: error = %+v", name, e.Error)
			}
		}
	}
}

func TestPressureAPI(t *testing.T) {
	m := newMetricsEnv(t)
	rec := m.do(req{method: "GET", path: "/api/v1/overview/pressure", cookie: m.admin})
	if rec.Code != http.StatusOK {
		t.Fatalf("pressure = %d %q", rec.Code, rec.Body)
	}
	var rep metrics.PressureReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Hosts) != 1 || rep.Hosts[0].CPUPercent == nil || *rep.Hosts[0].CPUPercent != 50 || len(rep.Containers) != 1 {
		t.Fatalf("report = %s", rec.Body)
	}
}
