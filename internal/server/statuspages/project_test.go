// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 28, 12, 34, 56, 0, time.UTC)

func TestSTP2_ComponentStatusDerivation(t *testing.T) {
	states := map[string]string{"a": "up", "b": "up", "c": "down", "d": "down", "e": "unknown"}
	for _, tc := range []struct {
		name string
		ids  []string
		want Status
	}{
		{"all up", []string{"a", "b"}, StatusOperational},
		{"some down", []string{"a", "c"}, StatusDegraded},
		{"all down", []string{"c", "d"}, StatusOutage},
		{"single down", []string{"c"}, StatusOutage},
		{"up and unknown", []string{"a", "e"}, StatusUnknown},
		{"down and unknown", []string{"c", "e"}, StatusDegraded},
		{"all unknown", []string{"e"}, StatusUnknown},
		{"no checks", nil, StatusUnknown},
		{"deleted checks ignored", []string{"a", "gone"}, StatusOperational},
		{"only deleted", []string{"gone"}, StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := componentStatus(tc.ids, states); got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSTP2_NinetyDayBarsWithGaps(t *testing.T) {
	days := make([]DaySeconds, HistoryDays)
	days[HistoryDays-1] = DaySeconds{Up: 86400}             // today: fully up
	days[HistoryDays-2] = DaySeconds{Up: 90000, Down: 1000} // 98.9%: degraded
	days[HistoryDays-3] = DaySeconds{Up: 100, Down: 86300}  // outage
	days[HistoryDays-5] = DaySeconds{Up: 86300, Down: 100}  // 99.88%: operational
	days[0] = DaySeconds{Up: 85000, Down: 1400}             // 98.4%: degraded
	src := pageSource{Title: "T", Components: []Component{{Name: "API", CheckIDs: []string{"c1"}}, {Name: "Empty"}}}
	p := buildPublic(src, map[string]string{"c1": "up"}, map[string][]DaySeconds{"c1": days}, fixedNow)

	if len(p.Components) != 2 || len(p.Components[0].Days) != HistoryDays {
		t.Fatalf("components = %+v", p.Components)
	}
	d := p.Components[0].Days
	if d[0].Date != "2026-07-31" || d[HistoryDays-1].Date != "2026-10-28" {
		t.Errorf("date range = %s .. %s", d[0].Date, d[HistoryDays-1].Date)
	}
	want := map[int]Status{
		0: StatusDegraded, 1: StatusUnknown, HistoryDays - 1: StatusOperational, HistoryDays - 2: StatusDegraded,
		HistoryDays - 3: StatusOutage, HistoryDays - 4: StatusUnknown, HistoryDays - 5: StatusOperational,
	}
	for i, w := range want {
		if d[i].Status != w {
			t.Errorf("day %d (%s) = %s, want %s", i, d[i].Date, d[i].Status, w)
		}
	}
	if p.Components[0].Uptime90d == nil || *p.Components[0].Uptime90d <= 0 || *p.Components[0].Uptime90d >= 100 {
		t.Errorf("uptime = %v", p.Components[0].Uptime90d)
	}
	if p.Components[1].Uptime90d != nil || p.Components[1].Status != StatusUnknown {
		t.Errorf("empty component = %+v", p.Components[1])
	}
	if p.Status != StatusUnknown { // worst of operational and unknown
		t.Errorf("overall = %s", p.Status)
	}
	if !p.GeneratedAt.Equal(time.Date(2026, 10, 28, 12, 34, 0, 0, time.UTC)) {
		t.Errorf("generated_at = %s", p.GeneratedAt)
	}
}

func TestSTP2_OverallStatusIsTheWorstComponent(t *testing.T) {
	mk := func(states map[string]string) Status {
		src := pageSource{Components: []Component{{Name: "a", CheckIDs: []string{"x"}}, {Name: "b", CheckIDs: []string{"y"}}}}
		return buildPublic(src, states, nil, fixedNow).Status
	}
	for _, tc := range []struct {
		x, y string
		want Status
	}{{"up", "up", StatusOperational}, {"up", "down", StatusOutage}, {"unknown", "up", StatusUnknown}, {"down", "unknown", StatusOutage}} {
		if got := mk(map[string]string{"x": tc.x, "y": tc.y}); got != tc.want {
			t.Errorf("%s/%s = %s, want %s", tc.x, tc.y, got, tc.want)
		}
	}
	if buildPublic(pageSource{}, nil, nil, fixedNow).Status != StatusUnknown {
		t.Error("a page without components should be unknown")
	}
}

func TestSTP2_IncidentVisibility(t *testing.T) {
	old := fixedNow.Add(-20 * day)
	recent := fixedNow.Add(-2 * day)
	src := pageSource{Incidents: []Incident{
		{Title: "old resolved", Status: IncResolved, CreatedAt: old.Add(-time.Hour), ResolvedAt: &old},
		{Title: "recent resolved", Status: IncResolved, CreatedAt: recent.Add(-time.Hour), ResolvedAt: &recent},
		{Title: "open", Status: IncInvestigating, CreatedAt: fixedNow.Add(-30 * day), Updates: []IncidentUpdate{{Status: IncInvestigating, Body: "x", At: fixedNow}}},
	}}
	got := buildPublic(src, nil, nil, fixedNow).Incidents
	if len(got) != 2 || got[0].Title != "open" || got[1].Title != "recent resolved" {
		t.Fatalf("incidents = %+v", got)
	}
	if got[1].ResolvedAt == nil || len(got[0].Updates) != 1 {
		t.Errorf("fields lost: %+v", got)
	}
}

func TestSTP1_SlugValidation(t *testing.T) {
	for _, ok := range []string{"a", "acme", "acme-status", "a1", "0day", strings.Repeat("a", 64)} {
		if err := validSlug(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a.b", "a b", "a/b", "..", "a%2fb", strings.Repeat("a", 65), "é", "assets", "a\n", "a.json"} {
		if err := validSlug(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSTP1_TextRules(t *testing.T) {
	for _, s := range []string{"a\x00b", "a\u202eb", "a\u200bb", "a\x1bb", "a\tb", "\xff", "a\u2028b", "x\uFEFFy"} {
		if _, err := cleanText("f", s, 1, 50, true); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := cleanText("f", "a\nb", 1, 50, false); err == nil {
		t.Error("newline accepted in single-line text")
	}
	if got, err := cleanText("f", "  a\r\nb\rc  ", 1, 50, true); err != nil || got != "a\nb\nc" {
		t.Errorf("multiline = %q, %v", got, err)
	}
	if _, err := cleanText("f", strings.Repeat("é", 51), 1, 50, false); err == nil {
		t.Error("51 runes accepted for a 50 limit")
	}
	if _, err := cleanText("f", "   ", 1, 50, false); err == nil {
		t.Error("blank accepted for a required field")
	}
	if got, err := cleanText("f", "Zażółć 日本語 🚀", 1, 50, false); err != nil || got == "" {
		t.Errorf("unicode text rejected: %v", err)
	}
}

func hostilePage() PublicPage {
	up := 99.5
	res := fixedNow
	return PublicPage{
		Title:       `<script>alert(1)</script>"'&`,
		Description: "line1\n<img src=x onerror=alert(2)>",
		Status:      StatusDegraded,
		GeneratedAt: fixedNow.Truncate(time.Minute),
		Components: []PublicComponent{{
			Name: `"><svg onload=alert(3)>`, Status: StatusOperational, Uptime90d: &up,
			Days: []PublicDay{{Date: "2026-10-28", Status: StatusOperational}},
		}},
		Incidents: []PublicIncident{{
			Title: `</title><script>x()</script>`, Body: "a <b>bold</b>\r\n' onmouseover='x\u202e", Status: IncInvestigating, Impact: ImpactMajor,
			StartedAt: fixedNow, ResolvedAt: &res,
			Updates: []PublicUpdate{{Status: IncInvestigating, Body: "first", At: fixedNow}, {Status: IncMonitoring, Body: `<a href="javascript:x">y</a>`, At: fixedNow}},
		}},
	}
}

func TestSTP2_HTMLEscapesHostileText(t *testing.T) {
	out, err := renderHTML(hostilePage())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, bad := range []string{"<script", "<img", "<svg", "<b>", `<a href="javascript`, "</title><script"} {
		if strings.Contains(s, bad) {
			t.Errorf("unescaped %q in output", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&#34;", "&lt;b&gt;bold&lt;/b&gt;", "<br>"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "<style") || strings.Contains(s, " style=") || strings.Count(s, "<script") > 0 {
		t.Error("inline style or script present")
	}
}

func TestSTP2_JSONHasTheExactSchema(t *testing.T) {
	b, _ := json.Marshal(hostilePage())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	keys := func(v any) []string {
		var out []string
		for k := range v.(map[string]any) {
			out = append(out, k)
		}
		return out
	}
	if len(keys(m)) != 6 {
		t.Errorf("top-level keys = %v", keys(m))
	}
	c := m["components"].([]any)[0]
	if len(keys(c)) != 4 {
		t.Errorf("component keys = %v", keys(c))
	}
	if len(keys(m["incidents"].([]any)[0])) != 7 {
		t.Errorf("incident keys = %v", keys(m["incidents"].([]any)[0]))
	}
}

// TestSTP2_GoldenHTML pins the markup of the public page; the UI's axe test reads the same file.
// Regenerate with UPDATE_GOLDEN=1.
func TestSTP2_GoldenHTML(t *testing.T) {
	up := 99.931
	res := fixedNow.Add(-time.Hour)
	days := make([]PublicDay, HistoryDays)
	for i := range days {
		days[i] = PublicDay{Date: fixedNow.Truncate(day).Add(time.Duration(i-HistoryDays+1) * day).Format(time.DateOnly), Status: StatusOperational}
	}
	days[10].Status, days[20].Status, days[30].Status = StatusDegraded, StatusOutage, StatusUnknown
	p := PublicPage{
		Title: "Acme status", Description: "Live status of Acme services.\nQuestions: support@example.com", Status: StatusDegraded, GeneratedAt: fixedNow.Truncate(time.Minute),
		Components: []PublicComponent{
			{Name: "API", Status: StatusOperational, Uptime90d: &up, Days: days},
			{Name: "Dashboard", Status: StatusUnknown, Days: days},
		},
		Incidents: []PublicIncident{
			{
				Title: "Elevated API errors", Body: "We see elevated errors.\nInvestigating.", Status: IncMonitoring, Impact: ImpactMinor, StartedAt: fixedNow.Add(-3 * time.Hour),
				Updates: []PublicUpdate{{Status: IncInvestigating, Body: "We see elevated errors.\nInvestigating.", At: fixedNow.Add(-3 * time.Hour)}, {Status: IncMonitoring, Body: "A fix is rolled out.", At: fixedNow.Add(-time.Hour)}},
			},
			{
				Title: "Login outage", Body: "Login was down.", Status: IncResolved, Impact: ImpactMajor, StartedAt: fixedNow.Add(-48 * time.Hour), ResolvedAt: &res,
				Updates: []PublicUpdate{{Status: IncInvestigating, Body: "Login was down.", At: fixedNow.Add(-48 * time.Hour)}, {Status: IncResolved, Body: "", At: res}},
			},
		},
	}
	got, err := renderHTML(p)
	if err != nil {
		t.Fatal(err)
	}
	const path = "testdata/public.golden.html"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("rendered page differs from testdata/public.golden.html; run with UPDATE_GOLDEN=1 if the change is intended")
	}
}
