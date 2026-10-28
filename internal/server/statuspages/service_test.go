// SPDX-License-Identifier: AGPL-3.0-only

package statuspages_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/statuspages"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

var (
	bg  = context.Background()
	now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	who = statuspages.Actor{UserID: "01USER", IP: "203.0.113.9"}
)

const (
	checkA = "01HZZZZZZZZZZZZZZZZZZZZZZA"
	checkB = "01HZZZZZZZZZZZZZZZZZZZZZZB"
)

type fakeChecks struct {
	mu     sync.Mutex
	exist  map[string]bool
	states map[string]string
	daily  map[string][]statuspages.DaySeconds
}

func (f *fakeChecks) ExistingIDs(_ context.Context, ids []string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for _, id := range ids {
		if f.exist[id] {
			out[id] = true
		}
	}
	return out, nil
}

func (f *fakeChecks) StatusStates(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.states {
		out[k] = v
	}
	return out, nil
}

func (f *fakeChecks) DailyUptime(context.Context, time.Time, int) (map[string][]statuspages.DaySeconds, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.daily, nil
}

type env struct {
	t  *testing.T
	db *store.Store
	fc *fakeChecks
	s  *statuspages.Service
}

func newEnv(t *testing.T, mut ...func(*statuspages.Options)) *env {
	t.Helper()
	db, err := store.Open(bg, t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	fc := &fakeChecks{exist: map[string]bool{checkA: true, checkB: true}, states: map[string]string{checkA: "up", checkB: "up"}}
	o := statuspages.Options{DB: db, Checks: fc, Now: func() time.Time { return now }}
	for _, m := range mut {
		m(&o)
	}
	return &env{t: t, db: db, fc: fc, s: statuspages.New(o)}
}

func (e *env) page(slug string, published bool) statuspages.Page {
	e.t.Helper()
	p, err := e.s.CreatePage(bg, statuspages.PageInput{
		Slug: slug, Title: "Acme " + slug, Published: published,
		Components: []statuspages.ComponentInput{{Name: "API", CheckIDs: []string{checkA, checkB}}},
	}, who)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.DB().QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.DB().Query(`SELECT action FROM audit_log WHERE action LIKE 'status_page.%' OR action LIKE 'incident.%' ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

func (e *env) get(path string, hdr ...string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	e.s.RegisterPublic(mux)
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "198.51.100.7:5555"
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func validation(t *testing.T, err error, field string) {
	t.Helper()
	var ve *statuspages.ValidationError
	if !errors.As(err, &ve) || ve.Field != field {
		t.Fatalf("err = %v, want a validation error on %s", err, field)
	}
}

func TestSTP1_CreateUpdateDeleteWithAudit(t *testing.T) {
	e := newEnv(t)
	p := e.page("acme", true)
	if p.Rev != 1 || len(p.Components) != 1 || p.Components[0].CheckIDs[0] != checkA {
		t.Fatalf("page = %+v", p)
	}
	_, err := e.s.CreatePage(bg, statuspages.PageInput{Slug: "acme", Title: "dup"}, who)
	if !errors.Is(err, statuspages.ErrSlugTaken) {
		t.Fatalf("duplicate slug err = %v", err)
	}
	in := statuspages.PageInput{Title: "Renamed", Published: false, Components: []statuspages.ComponentInput{
		{Name: "Web", CheckIDs: []string{checkB}}, {Name: "API", CheckIDs: []string{checkA}},
	}}
	u, err := e.s.UpdatePage(bg, p.ID, p.ETag(), in, who)
	if err != nil {
		t.Fatal(err)
	}
	if u.Rev != 2 || u.Slug != "acme" || u.Title != "Renamed" || u.Published || u.Components[0].Name != "Web" || u.Components[1].Name != "API" {
		t.Fatalf("updated = %+v", u)
	}
	if err := e.s.DeletePage(bg, p.ID, who); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.GetPage(bg, p.ID); !errors.Is(err, statuspages.ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	want := "status_page.create status_page.update status_page.delete"
	if got := strings.Join(e.auditActions(), " "); got != want {
		t.Errorf("audit = %q, want %q", got, want)
	}
}

func TestSTP1_SlugIsImmutable(t *testing.T) {
	e := newEnv(t)
	p := e.page("acme", false)
	_, err := e.s.UpdatePage(bg, p.ID, p.ETag(), statuspages.PageInput{Slug: "other", Title: "x"}, who)
	validation(t, err, "slug")
	if _, err := e.s.UpdatePage(bg, p.ID, p.ETag(), statuspages.PageInput{Slug: "acme", Title: "same slug ok"}, who); err != nil {
		t.Fatal(err)
	}
}

func TestSTP1_StaleETagChangesNothing(t *testing.T) {
	e := newEnv(t)
	p := e.page("acme", false)
	if _, err := e.s.UpdatePage(bg, p.ID, p.ETag(), statuspages.PageInput{Title: "one"}, who); err != nil {
		t.Fatal(err)
	}
	before := len(e.auditActions())
	_, err := e.s.UpdatePage(bg, p.ID, p.ETag(), statuspages.PageInput{Title: "two"}, who)
	if !errors.Is(err, statuspages.ErrStale) {
		t.Fatalf("err = %v", err)
	}
	got, _ := e.s.GetPage(bg, p.ID)
	if got.Title != "one" || len(e.auditActions()) != before {
		t.Errorf("stale update leaked: %+v, audit %d -> %d", got, before, len(e.auditActions()))
	}
}

func TestSTP1_ComponentChecksAreValidated(t *testing.T) {
	e := newEnv(t)
	mk := func(ids ...string) statuspages.PageInput {
		return statuspages.PageInput{Slug: "acme", Title: "t", Components: []statuspages.ComponentInput{{Name: "n", CheckIDs: ids}}}
	}
	for name, in := range map[string]statuspages.PageInput{
		"unknown check":    mk("01HZZZZZZZZZZZZZZZZZZZZZZZ"),
		"malformed id":     mk("not-an-id"),
		"duplicate in one": mk(checkA, checkA),
		"sql-ish id":       mk("' OR 1=1 --"),
	} {
		_, err := e.s.CreatePage(bg, in, who)
		var ve *statuspages.ValidationError
		if !errors.As(err, &ve) || !strings.HasPrefix(ve.Field, "components[0]") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	tooMany := mk()
	for i := 0; i <= statuspages.MaxComponents; i++ {
		tooMany.Components = append(tooMany.Components, statuspages.ComponentInput{Name: fmt.Sprint("c", i)})
	}
	_, err := e.s.CreatePage(bg, tooMany, who)
	validation(t, err, "components")
	if e.count(`SELECT COUNT(*) FROM status_pages`) != 0 || len(e.auditActions()) != 0 {
		t.Error("a rejected page left rows or audit entries behind")
	}
}

func TestSTP1_CascadeDelete(t *testing.T) {
	e := newEnv(t)
	p := e.page("acme", true)
	other := e.page("keep", true)
	inc, err := e.s.CreateIncident(bg, p.ID, statuspages.IncidentInput{Title: "t", Body: "b", Status: "investigating", Impact: "minor"}, who)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.AddUpdate(bg, p.ID, inc.ID, statuspages.UpdateInput{Status: "monitoring", Body: "ok"}, who); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.CreateIncident(bg, other.ID, statuspages.IncidentInput{Title: "t", Body: "b", Status: "investigating", Impact: "none"}, who); err != nil {
		t.Fatal(err)
	}
	if err := e.s.DeletePage(bg, p.ID, who); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{"status_components": 1, "incidents": 1, "incident_updates": 1, "status_pages": 1} {
		if got := e.count(`SELECT COUNT(*) FROM ` + table); got != want {
			t.Errorf("%s rows = %d, want %d", table, got, want)
		}
	}
	if rec := e.get("/status/acme"); rec.Code != http.StatusNotFound {
		t.Errorf("deleted page still served: %d", rec.Code)
	}
}

func TestSTP2_IncidentLifecycleAndAudit(t *testing.T) {
	e := newEnv(t)
	p := e.page("acme", true)
	elsewhere := e.page("elsewhere", false).ID
	inc, err := e.s.CreateIncident(bg, p.ID, statuspages.IncidentInput{Title: " Slow API ", Body: "We are looking.\r\nMore soon.", Status: "investigating", Impact: "minor"}, who)
	if err != nil {
		t.Fatal(err)
	}
	if inc.Title != "Slow API" || inc.Body != "We are looking.\nMore soon." || len(inc.Updates) != 1 || inc.ResolvedAt != nil {
		t.Fatalf("incident = %+v", inc)
	}
	inc, err = e.s.AddUpdate(bg, p.ID, inc.ID, statuspages.UpdateInput{Status: "identified", Body: "Found it.", Impact: "major"}, who)
	if err != nil || inc.Impact != "major" || inc.Status != "identified" || len(inc.Updates) != 2 {
		t.Fatalf("update = %+v, %v", inc, err)
	}
	inc, err = e.s.AddUpdate(bg, p.ID, inc.ID, statuspages.UpdateInput{Status: "resolved"}, who)
	if err != nil || inc.ResolvedAt == nil || !inc.ResolvedAt.Equal(now) || len(inc.Updates) != 3 {
		t.Fatalf("resolve = %+v, %v", inc, err)
	}
	if _, err := e.s.AddUpdate(bg, p.ID, inc.ID, statuspages.UpdateInput{Status: "monitoring", Body: ""}, who); err == nil {
		t.Error("an empty non-resolving update was accepted")
	}
	if _, err := e.s.AddUpdate(bg, elsewhere, inc.ID, statuspages.UpdateInput{Status: "monitoring", Body: "x"}, who); !errors.Is(err, statuspages.ErrNotFound) {
		t.Errorf("update through another page = %v", err)
	}
	if got := strings.Join(e.auditActions(), " "); !strings.HasSuffix(got, "incident.create incident.update incident.resolve") {
		t.Errorf("audit = %q", got)
	}
	_, err = e.s.CreateIncident(bg, p.ID, statuspages.IncidentInput{Title: "t", Body: "b", Status: "nope", Impact: "none"}, who)
	validation(t, err, "status")
	_, err = e.s.CreateIncident(bg, p.ID, statuspages.IncidentInput{Title: "t", Body: "b", Status: "resolved", Impact: "huge"}, who)
	validation(t, err, "impact")
	_, err = e.s.CreateIncident(bg, "01HZZZZZZZZZZZZZZZZZZZZZZZ", statuspages.IncidentInput{Title: "t", Body: "b", Status: "resolved", Impact: "none"}, who)
	if !errors.Is(err, statuspages.ErrNotFound) {
		t.Errorf("incident on a missing page = %v", err)
	}
}

func TestSTP2_PublicPageFollowsChecksAndEdits(t *testing.T) {
	e := newEnv(t)
	e.page("acme", true)
	if err := e.s.Refresh(bg); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status     string `json:"status"`
		Components []struct {
			Status string `json:"status"`
			Days   []any  `json:"days"`
		} `json:"components"`
	}
	read := func() {
		rec := e.get("/status/acme.json")
		if rec.Code != 200 {
			t.Fatalf("code = %d", rec.Code)
		}
		got.Components = nil
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if got.Status != "operational" || len(got.Components[0].Days) != 90 {
		t.Fatalf("got = %+v", got)
	}
	e.fc.mu.Lock()
	e.fc.states[checkB] = "down"
	e.fc.mu.Unlock()
	read()
	if got.Status != "operational" {
		t.Error("projection changed before a refresh")
	}
	if err := e.s.Refresh(bg); err != nil {
		t.Fatal(err)
	}
	read()
	if got.Status != "degraded" {
		t.Errorf("status = %s, want degraded", got.Status)
	}
	// An admin edit shows at once.
	p, _ := e.s.ListPages(bg)
	if _, err := e.s.UpdatePage(bg, p[0].ID, p[0].ETag(), statuspages.PageInput{Title: "x", Published: false}, who); err != nil {
		t.Fatal(err)
	}
	if rec := e.get("/status/acme.json"); rec.Code != http.StatusNotFound {
		t.Errorf("unpublished page served: %d", rec.Code)
	}
}

func TestSTP3_UnknownAndUnpublishedAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	e.page("draft", false)
	e.page("live", true)
	_ = e.s.Refresh(bg)
	for _, suffix := range []string{"", ".json"} {
		a, b, c := e.get("/status/draft"+suffix), e.get("/status/nope"+suffix), e.get("/status/Bad_Slug"+suffix)
		for _, r := range []*httptest.ResponseRecorder{b, c} {
			if r.Code != http.StatusNotFound || r.Body.String() != a.Body.String() {
				t.Errorf("%q: unknown differs from unpublished: %d %q", suffix, r.Code, r.Body)
			}
			if fmt.Sprint(r.Header()) != fmt.Sprint(a.Header()) {
				t.Errorf("%q: headers differ: %v vs %v", suffix, r.Header(), a.Header())
			}
		}
		if a.Code != 404 || a.Header().Get("ETag") != "" {
			t.Errorf("%q: draft = %d, etag %q", suffix, a.Code, a.Header().Get("ETag"))
		}
	}
	if long := e.get("/status/" + strings.Repeat("a", 5000)); long.Code != 404 {
		t.Errorf("long slug = %d", long.Code)
	}
}

func TestSTP3_HeadersCachingAndNoCookies(t *testing.T) {
	e := newEnv(t)
	e.page("live", true)
	_ = e.s.Refresh(bg)
	for _, path := range []string{"/status/live", "/status/live.json", "/status/nope", "/status/assets/status.css"} {
		rec := e.get(path)
		h := rec.Header()
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "style-src 'self'") ||
			!strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers = %v", path, h)
		}
		if h.Get("Set-Cookie") != "" {
			t.Errorf("%s sets a cookie", path)
		}
	}
	rec := e.get("/status/live")
	if rec.Header().Get("Cache-Control") != "public, max-age=30" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("headers = %v", rec.Header())
	}
	etag := rec.Header().Get("ETag")
	if again := e.get("/status/live", "If-None-Match", etag); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("conditional = %d", again.Code)
	}
	if j := e.get("/status/live.json"); !strings.HasPrefix(j.Header().Get("Content-Type"), "application/json") || j.Header().Get("ETag") == etag {
		t.Errorf("json headers = %v", j.Header())
	}
	if css := e.get("/status/assets/status.css"); !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") || css.Body.Len() == 0 {
		t.Errorf("css = %v", css.Header())
	}
	post := httptest.NewRequest("POST", "/status/live", nil)
	mux := http.NewServeMux()
	e.s.RegisterPublic(mux)
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, post)
	if prec.Code != http.StatusMethodNotAllowed && prec.Code != http.StatusNotFound {
		t.Errorf("POST = %d", prec.Code)
	}
}

func TestSTP3_RateLimitPerIP(t *testing.T) {
	cur := now
	e := newEnv(t, func(o *statuspages.Options) { o.RateLimit = 5; o.Now = func() time.Time { return cur } })
	e.page("live", true)
	_ = e.s.Refresh(bg)
	for i := 0; i < 5; i++ {
		if rec := e.get("/status/live"); rec.Code != 200 {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	rec := e.get("/status/nope.json")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "STP-RATE-001") {
		t.Fatalf("over the limit = %d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("429 lacks the public CSP")
	}
	// Another address is unaffected, and the window passes.
	mux := http.NewServeMux()
	e.s.RegisterPublic(mux)
	r := httptest.NewRequest("GET", "/status/live", nil)
	r.RemoteAddr = "198.51.100.99:1"
	ok := httptest.NewRecorder()
	mux.ServeHTTP(ok, r)
	if ok.Code != 200 {
		t.Errorf("other IP = %d", ok.Code)
	}
	cur = cur.Add(61 * time.Second)
	if rec := e.get("/status/live"); rec.Code != 200 {
		t.Errorf("after the window = %d", rec.Code)
	}
}

// TestSTP3_ProjectionLeaksNothingInternal builds the projection from real check rows whose
// names, targets, runners, error details and IDs are all recognisable, and asserts that none
// of them reaches the HTML or the JSON.
func TestSTP3_ProjectionLeaksNothingInternal(t *testing.T) {
	db, err := store.Open(bg, t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	chk := checks.New(checks.Options{DB: db, Clock: fixedClock{}})

	type nasty struct{ id, name, spec, runner, errCode, detail string }
	rows := []nasty{
		{
			"01HAAAAAAAAAAAAAAAAAAAAAAA", "prod-db-primary.corp.internal", `{"url":"https://admin:hunter2@10.20.30.40:8443/internal/health?token=S3CR3T"}`, "01HAGENTAAAAAAAAAAAAAAAAAA",
			"CHK-TCP-001", "dial tcp 10.20.30.40:5432: connect: connection refused (db-primary-01.internal)",
		},
		{
			"01HBBBBBBBBBBBBBBBBBBBBBBB", "vault.secret-host.example", `{"host":"fe80::1ff:fe23:4567:890a","port":6379}`, "server",
			"CHK-HTTP-002", `unexpected status 500 from http://192.168.7.7/<script>alert(1)</script>`,
		},
	}
	ctx := bg
	for _, r := range rows {
		mustExec(t, db.DB(), `INSERT INTO checks (id, name, type, spec_json, secret_refs_json, runner, interval_s, timeout_s, retries, enabled, allow_private, rev, created_by, updated_by, created_at, updated_at)
			VALUES (?, ?, 'tcp', ?, '{}', ?, 60, 5, 0, 1, 0, 1, 'u', 'u', 0, 0)`, r.id, r.name, r.spec, r.runner)
		mustExec(t, db.DB(), `INSERT INTO check_state (check_id, status, since_at, last_checked_at, last_latency_ms, last_error_code, last_detail) VALUES (?, 'down', 0, 0, 1, ?, ?)`, r.id, r.errCode, r.detail)
		mustExec(t, db.DB(), `INSERT INTO check_results (check_id, ts, status, latency_ms, error_code, detail) VALUES (?, ?, 'down', 1, ?, ?)`, r.id, now.UnixMilli()-1000, r.errCode, r.detail)
		mustExec(t, db.DB(), `INSERT INTO check_rollups_daily (check_id, day, up_s, down_s, avg_latency_ms) VALUES (?, ?, 80000, 6400, 12)`, r.id, now.Add(-48*time.Hour).Truncate(24*time.Hour).Unix())
	}
	svc := statuspages.New(statuspages.Options{DB: db, Checks: chk, Now: func() time.Time { return now }})
	if _, err := svc.CreatePage(ctx, statuspages.PageInput{Slug: "acme", Title: "Acme", Description: "Public status", Published: true, Components: []statuspages.ComponentInput{
		{Name: "Database", CheckIDs: []string{rows[0].id}}, {Name: "Cache", CheckIDs: []string{rows[1].id}},
	}}, who); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, s: svc}

	htmlOut, jsonOut := e.get("/status/acme"), e.get("/status/acme.json")
	if htmlOut.Code != 200 || jsonOut.Code != 200 {
		t.Fatalf("codes = %d %d", htmlOut.Code, jsonOut.Code)
	}
	var page struct {
		Status     string `json:"status"`
		Components []struct {
			Status string                    `json:"status"`
			Uptime *float64                  `json:"uptime_90d"`
			Days   []struct{ Status string } `json:"days"`
		} `json:"components"`
	}
	_ = json.Unmarshal(jsonOut.Body.Bytes(), &page)
	if page.Status != "outage" || page.Components[0].Status != "outage" || page.Components[0].Uptime == nil {
		t.Fatalf("projection did not use the real rows: %s", jsonOut.Body)
	}
	if got := page.Components[0].Days[87].Status; got != "outage" { // the rolled-up day is 92.6% up
		t.Errorf("rolled-up day = %s, want outage", got)
	}
	for _, out := range []string{htmlOut.Body.String(), jsonOut.Body.String()} {
		for _, r := range rows {
			for _, secret := range []string{r.id, r.name, r.runner, r.errCode, r.detail, "10.20.30.40", "192.168.7.7", "fe80::", "hunter2", "S3CR3T", "internal", "corp", "secret-host", "5432", "6379", "token=", "dial tcp"} {
				if strings.Contains(out, secret) {
					t.Errorf("public output contains %q", secret)
				}
			}
		}
	}
	// The public output also carries no raw check id of any kind.
	if strings.Contains(htmlOut.Body.String(), "01HAAAA") || strings.Contains(jsonOut.Body.String(), "check") {
		t.Error("check identifiers or the word check leaked")
	}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time                                   { return now }
func (fixedClock) Sleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
