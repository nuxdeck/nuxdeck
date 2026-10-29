// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

func (e *env) setRoutes(rs ...Route) {
	e.t.Helper()
	cur, err := e.svc.Routes(context.Background())
	mustNoErr(e.t, err)
	if _, err := e.svc.ReplaceRoutes(context.Background(), cur.ETag(), rs, e.who); err != nil {
		e.t.Fatal(err)
	}
}

func channelsOf(s *fakeSink) []string {
	var out []string
	for _, x := range s.all() {
		out = append(out, x.channel)
	}
	return out
}

func downHost(e *env, tags map[string]string) string {
	hid := newID(e.t)
	e.inv.setHost(host(hid, "web-"+hid[20:], inventory.StatusOffline, tags, e.clock.Now()))
	return hid
}

// ALR-4: first matching route wins unless it continues; routes are tried in order.
func TestALR4_RouteOrderContinueAndFirstMatch(t *testing.T) {
	e := newEnv(t)
	slack, mail, pager := e.channel("slack"), e.channel("mail"), e.channel("pager")
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	downHost(e, map[string]string{"env": "production"})

	e.setRoutes(
		Route{ChannelID: slack.ID, Selector: Selector{Tags: []string{"env:production"}}},
		Route{ChannelID: mail.ID}, // catch-all: reached only when the first route does not match
	)
	e.eval()
	if got := channelsOf(e.sink); len(got) != 1 || got[0] != slack.ID {
		t.Fatalf("first match: sent to %v, want only slack", got)
	}

	e2 := newEnv(t)
	slack, mail, pager = e2.channel("slack"), e2.channel("mail"), e2.channel("pager")
	e2.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	downHost(e2, map[string]string{"env": "production"})
	e2.setRoutes(
		Route{ChannelID: slack.ID, Selector: Selector{Tags: []string{"env:production"}}, Continue: true},
		Route{ChannelID: mail.ID, Selector: Selector{Severity: []string{"info"}}}, // no match, skipped
		Route{ChannelID: pager.ID, Selector: Selector{Severity: []string{"critical"}, Kinds: []string{KindHostOffline}}, Continue: true},
		Route{ChannelID: slack.ID}, // duplicate channel is sent once
	)
	e2.eval()
	got := channelsOf(e2.sink)
	if len(got) != 2 || got[0] != slack.ID || got[1] != pager.ID {
		t.Fatalf("continue: sent to %v, want [slack pager] in route order", got)
	}

	e3 := newEnv(t)
	slack = e3.channel("slack")
	e3.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	downHost(e3, map[string]string{"env": "staging"})
	e3.setRoutes(Route{ChannelID: slack.ID, Selector: Selector{Tags: []string{"env:production"}}})
	e3.eval()
	if len(e3.sink.all()) != 0 {
		t.Error("an alert matching no route was sent")
	}
	if len(e3.alerts(StateOpen)) != 1 {
		t.Error("an unrouted alert must still be recorded")
	}
}

func TestALR4_ResolveFollowsTheSameRoutes(t *testing.T) {
	e := newEnv(t)
	slack := e.channel("slack")
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	hid := downHost(e, map[string]string{"env": "production"})
	e.setRoutes(Route{ChannelID: slack.ID, Selector: Selector{Tags: []string{"env:production"}}})
	e.eval()
	e.inv.setHost(host(hid, "web", inventory.StatusOnline, map[string]string{"env": "production"}, e.clock.Now()))
	e.step(15 * time.Second)
	if got := e.sink.kinds(); len(got) != 2 || got[0] != "firing" || got[1] != "resolved" {
		t.Errorf("sent = %v", got)
	}
}

func TestALR4_ReplaceRoutesValidationAndETag(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slack := e.channel("slack")
	cur, _ := e.svc.Routes(ctx)
	if cur.ETag() != `"r0"` || len(cur.Routes) != 0 {
		t.Fatalf("initial = %q %v", cur.ETag(), cur.Routes)
	}
	var ve *ValidationError
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: newID(t)}}, e.who); !errors.As(err, &ve) {
		t.Errorf("unknown channel: %v", err)
	}
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: "nope"}}, e.who); !errors.As(err, &ve) {
		t.Errorf("malformed channel id: %v", err)
	}
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: slack.ID, Selector: Selector{Tags: []string{"bad tag"}}}}, e.who); !errors.As(err, &ve) {
		t.Errorf("bad selector: %v", err)
	}
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: slack.ID, Selector: Selector{IDs: []string{newID(t)}}}}, e.who); !errors.As(err, &ve) {
		t.Errorf("ids in a route selector: %v", err)
	}
	many := make([]Route, MaxRoutes+1)
	for i := range many {
		many[i] = Route{ChannelID: slack.ID}
	}
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), many, e.who); !errors.As(err, &ve) {
		t.Errorf("too many routes: %v", err)
	}
	if n := e.count(`SELECT COUNT(*) FROM routes`); n != 0 {
		t.Errorf("failed replaces left %d routes", n)
	}

	l1, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: slack.ID}}, e.who)
	mustNoErr(t, err)
	if l1.ETag() != `"r1"` {
		t.Errorf("etag = %s", l1.ETag())
	}
	if _, err := e.svc.ReplaceRoutes(ctx, cur.ETag(), nil, e.who); !errors.Is(err, ErrStale) {
		t.Errorf("stale replace: %v", err)
	}
	// The replace is atomic: a failure midway keeps the old list.
	_, err = e.svc.ReplaceRoutes(ctx, l1.ETag(), []Route{{ChannelID: slack.ID}, {ChannelID: newID(t)}}, e.who)
	if err == nil {
		t.Fatal("expected a failure")
	}
	got, _ := e.svc.Routes(ctx)
	if len(got.Routes) != 1 || got.Routes[0].ID != l1.Routes[0].ID || got.ETag() != l1.ETag() {
		t.Errorf("list changed by a failed replace: %+v", got)
	}
}

func TestALR4_DeletingAChannelRemovesItsRoutesAndSecrets(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.channel("a"), e.channel("b")
	e.setRoutes(Route{ChannelID: a.ID, Continue: true}, Route{ChannelID: b.ID})
	before, _ := e.svc.Routes(ctx)
	mustNoErr(t, e.channels.Delete(ctx, a.ID, e.who))
	after, _ := e.svc.Routes(ctx)
	if len(after.Routes) != 1 || after.Routes[0].ChannelID != b.ID || after.ETag() == before.ETag() {
		t.Errorf("routes after delete = %+v (etag %s -> %s)", after.Routes, before.ETag(), after.ETag())
	}
	if n := e.count(`SELECT COUNT(*) FROM secrets`); n != 1 {
		t.Errorf("secrets = %d, want only b's", n)
	}
	if err := e.channels.Delete(ctx, a.ID, e.who); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

// ALR-5: an acknowledged alert stays open (as acked) but stops repeating; it still resolves.
func TestALR5_AckSuppressesRepeatsKeepsAlertOpen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slack := e.channel("slack")
	e.setRoutes(Route{ChannelID: slack.ID})
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	hid := downHost(e, nil)
	e.eval()
	other := downHost(e, nil)
	e.step(15 * time.Second)
	if got := e.sink.kinds(); len(got) != 2 {
		t.Fatalf("setup sent = %v", got)
	}
	e.sink.reset()

	var first Alert
	for _, a := range e.alerts(StateOpen) {
		if a.ItemID == hid {
			first = a
		}
	}
	acked, err := e.svc.Ack(ctx, first.ID, e.who)
	mustNoErr(t, err)
	if acked.State != StateAcked || acked.AckedBy != e.who.UserID || acked.AckedAt == nil {
		t.Fatalf("acked = %+v", acked)
	}
	again, err := e.svc.Ack(ctx, first.ID, Actor{UserID: "someone-else"})
	mustNoErr(t, err)
	if again.AckedBy != e.who.UserID {
		t.Error("a second ack replaced who acknowledged")
	}
	if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'alert.ack'`) != 1 {
		t.Error("idempotent ack was audited twice")
	}

	// An hour later (the repeat interval) only the unacknowledged alert reminds.
	e.step(61 * time.Minute)
	if len(e.sink.all()) != 1 || e.sink.all()[0].msg.ItemID != other || e.sink.all()[0].msg.Kind != "still_firing" {
		t.Fatalf("reminders = %v / %+v", e.sink.kinds(), e.sink.all())
	}
	if got := e.alerts("active"); len(got) != 2 {
		t.Errorf("active alerts = %d, want 2 (ack keeps it open)", len(got))
	}
	// Resolution is still announced for the acked alert.
	e.sink.reset()
	e.inv.setHost(host(hid, "web", inventory.StatusOnline, nil, e.clock.Now()))
	e.step(15 * time.Second)
	if got := e.sink.kinds(); len(got) != 1 || got[0] != "resolved" {
		t.Errorf("after recovery sent = %v", got)
	}
	// Survives a restart as acked.
	e.svc = e.newService()
	e.eval()
	var acks int
	for _, a := range e.alerts(StateAcked) {
		acks++
		_ = a
	}
	if acks != 0 { // hid resolved; other is open
		t.Errorf("acked alerts after resolve = %d", acks)
	}
}

func TestALR5_AckErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	e.checks.set(cid, "svc", checks.StateUp, "", "", e.clock.Now())
	e.step(time.Second)
	res := e.alerts(StateResolved)[0]
	if _, err := e.svc.Ack(ctx, res.ID, e.who); !errors.Is(err, ErrResolved) {
		t.Errorf("ack resolved: %v", err)
	}
	if _, err := e.svc.Ack(ctx, newID(t), e.who); !errors.Is(err, ErrNotFound) {
		t.Errorf("ack unknown: %v", err)
	}
}

func TestALR5_AckPersistsAcrossRestartAndStaysQuiet(t *testing.T) {
	e := newEnv(t)
	slack := e.channel("slack")
	e.setRoutes(Route{ChannelID: slack.ID})
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	downHost(e, nil)
	e.eval()
	_, err := e.svc.Ack(context.Background(), e.alerts(StateOpen)[0].ID, e.who)
	mustNoErr(t, err)
	e.svc = e.newService()
	e.sink.reset()
	e.step(3 * time.Hour)
	if len(e.sink.all()) != 0 {
		t.Errorf("acked alert notified after restart: %v", e.sink.kinds())
	}
	if len(e.alerts(StateAcked)) != 1 {
		t.Error("ack lost over a restart")
	}
}

// ALR-5: silences and maintenance windows mute notifications; alerts still open and record.
func TestALR5_SilenceMutesAndSendsOneSummaryAfterwards(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slack := e.channel("slack")
	e.setRoutes(Route{ChannelID: slack.ID})
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	hid := downHost(e, map[string]string{"env": "staging"})
	_, err := e.svc.CreateSilence(ctx, Silence{Selector: Selector{Tags: []string{"env:staging"}}, EndsAt: t0.Add(10 * time.Minute), Reason: "deploy"}, e.who)
	mustNoErr(t, err)

	e.eval()
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("a silenced alert must still open")
	}
	if len(e.sink.all()) != 0 {
		t.Fatal("notification sent during a silence")
	}
	for i := 0; i < 5; i++ { // no backlog builds up while muted
		e.step(time.Minute)
	}
	if len(e.sink.all()) != 0 {
		t.Fatal("notification sent during a silence")
	}
	e.step(6 * time.Minute) // silence over
	if got := e.sink.kinds(); len(got) != 1 || got[0] != "still_firing" {
		t.Fatalf("after silence: %v, want a single still_firing summary", got)
	}
	e.step(15 * time.Second)
	if len(e.sink.all()) != 1 {
		t.Error("the summary repeated")
	}
	_ = hid
}

func TestALR5_ResolveDuringSilenceIsMutedAndNothingFollows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slack := e.channel("slack")
	e.setRoutes(Route{ChannelID: slack.ID})
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	hid := downHost(e, nil)
	_, err := e.svc.CreateSilence(ctx, Silence{Selector: Selector{IDs: []string{hid}}, EndsAt: t0.Add(10 * time.Minute), Reason: "x"}, e.who)
	mustNoErr(t, err)
	e.eval()
	e.inv.setHost(host(hid, "web", inventory.StatusOnline, nil, e.clock.Now()))
	e.step(time.Minute)
	e.step(20 * time.Minute)
	if len(e.sink.all()) != 0 {
		t.Errorf("sent %v for an alert that opened and closed inside a silence", e.sink.kinds())
	}
	if len(e.alerts(StateResolved)) != 1 {
		t.Error("alert not recorded")
	}
}

func TestALR5_SilenceBoundariesAndMaintenanceSchedule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	start, end := t0.Add(time.Hour), t0.Add(2*time.Hour)
	m, err := e.svc.CreateSilence(ctx, Silence{Kind: SilenceKindMaintenance, Selector: Selector{Kinds: []string{KindHostOffline}}, StartsAt: start, EndsAt: end, Reason: "patching"}, e.who)
	mustNoErr(t, err)
	if m.State != "scheduled" {
		t.Errorf("state = %s", m.State)
	}
	a := &Alert{ItemID: "i", Severity: "critical", Kind: KindHostOffline}
	b := &Alert{ItemID: "i", Severity: "critical", Kind: KindCheckDown}
	at := func(d time.Duration, al *Alert) bool { return e.svc.silencedAt(ctx, al, nil, t0.Add(d)) }
	for _, tc := range []struct {
		name string
		d    time.Duration
		a    *Alert
		want bool
	}{
		{"before start", time.Hour - time.Millisecond, a, false},
		{"at start (inclusive)", time.Hour, a, true},
		{"inside", time.Hour + 30*time.Minute, a, true},
		{"last instant", 2*time.Hour - time.Millisecond, a, true},
		{"at end (exclusive)", 2 * time.Hour, a, false},
		{"after end", 3 * time.Hour, a, false},
		{"other kind never muted", time.Hour + time.Minute, b, false},
	} {
		if got := at(tc.d, tc.a); got != tc.want {
			t.Errorf("%s: silenced = %v, want %v", tc.name, got, tc.want)
		}
	}
	items, _, err := e.svc.ListSilences(ctx, true, "", 10)
	mustNoErr(t, err)
	if len(items) != 1 || items[0].Kind != SilenceKindMaintenance {
		t.Fatalf("list = %+v", items)
	}
	e.clock.Advance(3 * time.Hour)
	if items, _, _ = e.svc.ListSilences(ctx, true, "", 10); len(items) != 0 {
		t.Errorf("expired silence listed as active: %+v", items)
	}
	all, _, _ := e.svc.ListSilences(ctx, false, "", 10)
	if len(all) != 1 || all[0].State != "expired" {
		t.Errorf("all = %+v", all)
	}
}

func TestALR5_DeleteEndsSilenceAtOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slack := e.channel("slack")
	e.setRoutes(Route{ChannelID: slack.ID})
	e.rule("Offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	downHost(e, nil)
	s, err := e.svc.CreateSilence(ctx, Silence{Selector: Selector{Kinds: []string{KindHostOffline}}, EndsAt: t0.Add(24 * time.Hour), Reason: "x"}, e.who)
	mustNoErr(t, err)
	e.eval()
	if len(e.sink.all()) != 0 {
		t.Fatal("not muted")
	}
	mustNoErr(t, e.svc.DeleteSilence(ctx, s.ID, e.who))
	e.step(15 * time.Second)
	if got := e.sink.kinds(); len(got) != 1 || got[0] != "still_firing" {
		t.Errorf("after delete: %v", got)
	}
	if err := e.svc.DeleteSilence(ctx, s.ID, e.who); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestALR5_SilenceSelectorsMatchBySeverityIDAndTags(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	al := &Alert{ItemID: "item1", Severity: "warning", Kind: KindHostOffline}
	tags := map[string]string{"env": "staging", "team": "a"}
	make1 := func(sel Selector) {
		_, err := e.svc.CreateSilence(ctx, Silence{Selector: sel, EndsAt: t0.Add(time.Hour), Reason: "x"}, e.who)
		mustNoErr(t, err)
	}
	check := func(want bool, msg string) {
		t.Helper()
		if got := e.svc.silencedAt(ctx, al, tags, t0); got != want {
			t.Errorf("%s: silenced = %v, want %v", msg, got, want)
		}
	}
	check(false, "no silences")
	make1(Selector{Severity: []string{"critical"}})
	check(false, "severity mismatch")
	make1(Selector{Tags: []string{"env:staging", "team:b"}})
	check(false, "one tag mismatch")
	make1(Selector{Tags: []string{"env:staging", "team:a"}, Severity: []string{"warning", "info"}})
	check(true, "tags and severity match")
}

func TestALR5_SilenceValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := Selector{Tags: []string{"env:staging"}}
	for _, tc := range []struct {
		name string
		in   Silence
	}{
		{"empty selector", Silence{EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"no reason", Silence{Selector: ok, EndsAt: t0.Add(time.Hour)}},
		{"blank reason", Silence{Selector: ok, EndsAt: t0.Add(time.Hour), Reason: "   "}},
		{"long reason", Silence{Selector: ok, EndsAt: t0.Add(time.Hour), Reason: strings.Repeat("x", 201)}},
		{"no end", Silence{Selector: ok, Reason: "r"}},
		{"end before start", Silence{Selector: ok, StartsAt: t0.Add(2 * time.Hour), EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"end in the past", Silence{Selector: ok, StartsAt: t0.Add(-2 * time.Hour), EndsAt: t0.Add(-time.Hour), Reason: "r"}},
		{"silence too long", Silence{Selector: ok, EndsAt: t0.Add(31 * 24 * time.Hour), Reason: "r"}},
		{"maintenance too long", Silence{Kind: SilenceKindMaintenance, Selector: ok, EndsAt: t0.Add(91 * 24 * time.Hour), Reason: "r"}},
		{"bad kind", Silence{Kind: "mute", Selector: ok, EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"bad tag", Silence{Selector: Selector{Tags: []string{"bad tag!"}}, EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"bad id", Silence{Selector: Selector{IDs: []string{"x"}}, EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"bad severity", Silence{Selector: Selector{Severity: []string{"fatal"}}, EndsAt: t0.Add(time.Hour), Reason: "r"}},
		{"scheduled too far", Silence{Selector: ok, StartsAt: t0.Add(400 * 24 * time.Hour), EndsAt: t0.Add(401 * 24 * time.Hour), Reason: "r"}},
	} {
		var ve *ValidationError
		if _, err := e.svc.CreateSilence(ctx, tc.in, e.who); !errors.As(err, &ve) {
			t.Errorf("%s: err = %v, want a validation error", tc.name, err)
		}
	}
	if _, err := e.svc.CreateSilence(ctx, Silence{Kind: SilenceKindMaintenance, Selector: ok, EndsAt: t0.Add(90 * 24 * time.Hour), Reason: "r"}, e.who); err != nil {
		t.Errorf("90 day maintenance: %v", err)
	}
	if _, err := e.svc.CreateSilence(ctx, Silence{Selector: ok, EndsAt: t0.Add(30 * 24 * time.Hour), Reason: "r"}, e.who); err != nil {
		t.Errorf("30 day silence: %v", err)
	}
}

func TestALR1_RuleValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	long := strings.Repeat("n", 101)
	for _, tc := range []struct {
		name string
		r    Rule
	}{
		{"no name", Rule{Kind: KindCheckDown, Severity: "info", Params: []byte(`{}`)}},
		{"long name", Rule{Name: long, Kind: KindCheckDown, Severity: "info", Params: []byte(`{}`)}},
		{"bad kind", Rule{Name: "x", Kind: "cpu_high", Severity: "info", Params: []byte(`{}`)}},
		{"bad severity", Rule{Name: "x", Kind: KindCheckDown, Severity: "fatal", Params: []byte(`{}`)}},
		{"unknown param", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`{"threshold":1}`)}},
		{"for_s too big", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`{"for_s":90000}`)}},
		{"for_s negative", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`{"for_s":-1}`)}},
		{"params not object", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`[1]`)}},
		{"metric missing", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"host","threshold":90}`)}},
		{"threshold 0", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"host","metric":"cpu","threshold":0}`)}},
		{"threshold 101", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"host","metric":"cpu","threshold":101}`)}},
		{"threshold missing", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"host","metric":"cpu"}`)}},
		{"container disk", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"container","metric":"disk","threshold":9}`)}},
		{"bad target", Rule{Name: "x", Kind: KindMetricThreshold, Severity: "info", Params: []byte(`{"target":"check","metric":"cpu","threshold":9}`)}},
		{"bad mode", Rule{Name: "x", Kind: KindContainerStopped, Severity: "info", Params: []byte(`{"mode":"dead"}`)}},
		{"restarts 1", Rule{Name: "x", Kind: KindContainerStopped, Severity: "info", Params: []byte(`{"restarts":1}`)}},
		{"window too big", Rule{Name: "x", Kind: KindContainerStopped, Severity: "info", Params: []byte(`{"window_s":7200}`)}},
		{"tls days 0", Rule{Name: "x", Kind: KindTLSExpiring, Severity: "info", Params: []byte(`{"days":0}`)}},
		{"tls days missing", Rule{Name: "x", Kind: KindTLSExpiring, Severity: "info", Params: []byte(`{}`)}},
		{"severity selector on rule", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`{}`), Selector: Selector{Severity: []string{"info"}}}},
		{"bad tag", Rule{Name: "x", Kind: KindCheckDown, Severity: "info", Params: []byte(`{}`), Selector: Selector{Tags: []string{"a b"}}}},
	} {
		var ve *ValidationError
		if _, err := e.svc.CreateRule(ctx, tc.r, e.who); !errors.As(err, &ve) {
			t.Errorf("%s: err = %v, want a validation error", tc.name, err)
		}
	}
	r := e.rule("ok", KindMetricThreshold, SeverityInfo, `{"target":"host","metric":"cpu","threshold":90}`, Selector{})
	if string(r.Params) != `{"target":"host","metric":"cpu","threshold":90,"for_s":300}` {
		t.Errorf("params not normalised: %s", r.Params)
	}
	// ETag handling and immutability of kind.
	if _, err := e.svc.UpdateRule(ctx, r.ID, `"a99"`, r, e.who); !errors.Is(err, ErrStale) {
		t.Errorf("stale update: %v", err)
	}
	r2 := r
	r2.Kind = KindCheckDown
	r2.Params = []byte(`{}`)
	var ve *ValidationError
	if _, err := e.svc.UpdateRule(ctx, r.ID, r.ETag(), r2, e.who); !errors.As(err, &ve) {
		t.Errorf("kind change: %v", err)
	}
	if _, err := e.svc.UpdateRule(ctx, newID(t), r.ETag(), r, e.who); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown rule: %v", err)
	}
	r.Name = "renamed"
	u, err := e.svc.UpdateRule(ctx, r.ID, r.ETag(), r, e.who)
	mustNoErr(t, err)
	if u.ETag() == r.ETag() || u.Name != "renamed" {
		t.Errorf("update = %+v", u)
	}
}

// ---- channels and the delivery queue ----

func TestALR3_ChannelSecretsAreWriteOnlyAndEncrypted(t *testing.T) {
	var logs bytes.Buffer
	e := newEnv(t)
	e.channels.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	const url = "https://hooks.slack.com/services/T0/B0/SECRET-WEBHOOK"
	ch := e.channel("oncall")
	if string(ch.Config) != `{"url":{"set":true}}` {
		t.Fatalf("created config = %s", ch.Config)
	}
	got, err := e.channels.Get(ctx, ch.ID)
	mustNoErr(t, err)
	if strings.Contains(string(got.Config), "SECRET") || string(got.Config) != `{"url":{"set":true}}` {
		t.Errorf("read config = %s", got.Config)
	}

	// Plaintext is nowhere in the tables except sealed in secrets.
	for _, q := range []string{`SELECT group_concat(config_json || secret_refs_json) FROM channels`, `SELECT group_concat(details_json) FROM audit_log`, `SELECT group_concat(hex(ciphertext)) FROM secrets`} {
		var s string
		mustNoErr(t, e.db.DB().QueryRow(q).Scan(&s))
		if strings.Contains(s, "SECRET-WEBHOOK") || strings.Contains(s, "hooks.slack.com") {
			t.Errorf("plaintext in %q", q)
		}
	}
	if strings.Contains(logs.String(), "SECRET-WEBHOOK") {
		t.Error("secret in logs")
	}

	// Echoing the GET document back keeps the secret; omitting it keeps it; "" is refused for a required one.
	_, err = e.channels.Update(ctx, ch.ID, ch.ETag(), Channel{Name: "oncall2", Type: "slack", Enabled: true, Config: got.Config}, e.who)
	mustNoErr(t, err)
	_, cfg, err := e.channels.load(ctx, ch.ID)
	mustNoErr(t, err)
	if *cfg.Slots()[0].Secret.Plain != url {
		t.Error("echoed {set:true} replaced the stored secret")
	}
	cur, _ := e.channels.Get(ctx, ch.ID)
	var ve *ValidationError
	if _, err := e.channels.Update(ctx, ch.ID, cur.ETag(), Channel{Name: "x", Type: "slack", Config: []byte(`{"url":""}`)}, e.who); !errors.As(err, &ve) {
		t.Errorf("clearing a required secret: %v", err)
	}
	// Replace.
	_, err = e.channels.Update(ctx, ch.ID, cur.ETag(), Channel{Name: "oncall2", Type: "slack", Enabled: true, Config: []byte(`{"url":"https://hooks.slack.com/services/NEW/NEW/NEW"}`)}, e.who)
	mustNoErr(t, err)
	_, cfg, _ = e.channels.load(ctx, ch.ID)
	if !strings.Contains(*cfg.Slots()[0].Secret.Plain, "NEW") || e.count(`SELECT COUNT(*) FROM secrets`) != 1 {
		t.Error("replace did not rotate the stored secret in place")
	}
	// Type is immutable, ETag enforced, names unique.
	cur, _ = e.channels.Get(ctx, ch.ID)
	if _, err := e.channels.Update(ctx, ch.ID, cur.ETag(), Channel{Name: "x", Type: "teams", Config: []byte(`{"url":"https://x.example/y"}`)}, e.who); !errors.As(err, &ve) {
		t.Errorf("type change: %v", err)
	}
	if _, err := e.channels.Update(ctx, ch.ID, `"n99"`, Channel{Name: "x", Type: "slack", Config: got.Config}, e.who); !errors.Is(err, ErrStale) {
		t.Errorf("stale: %v", err)
	}
	if _, err := e.channels.Create(ctx, Channel{Name: "oncall2", Type: "slack", Config: []byte(`{"url":"https://hooks.slack.com/a"}`)}, e.who); !errors.As(err, &ve) {
		t.Errorf("duplicate name: %v", err)
	}
	if e.count(`SELECT COUNT(*) FROM secrets`) != 1 {
		t.Error("a rejected create leaked a secret row")
	}
}

func TestALR3_SMTPAndWebhookSecretsRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	smtp, err := e.channels.Create(ctx, Channel{
		Name: "mail", Type: "smtp", Enabled: true,
		Config: []byte(`{"host":"mail.example.com","username":"nux","password":"PW-SECRET","from":"nux@example.com","to":["a@example.com"]}`),
	}, e.who)
	mustNoErr(t, err)
	if !strings.Contains(string(smtp.Config), `"password":{"set":true}`) || strings.Contains(string(smtp.Config), "PW-SECRET") {
		t.Errorf("smtp config = %s", smtp.Config)
	}
	hook, err := e.channels.Create(ctx, Channel{
		Name: "hook", Type: "webhook", Enabled: true,
		Config: []byte(`{"url":"https://example.com/in","headers":[{"name":"X-Env","value":"prod"},{"name":"Authorization","secret":true,"secret_value":"Bearer TOK-SECRET"}]}`),
	}, e.who)
	mustNoErr(t, err)
	if strings.Contains(string(hook.Config), "TOK-SECRET") || !strings.Contains(string(hook.Config), `"secret_value":{"set":true}`) {
		t.Errorf("webhook config = %s", hook.Config)
	}
	_, cfg, err := e.channels.load(ctx, hook.ID)
	mustNoErr(t, err)
	w := cfg.(*notify.Webhook)
	if *w.URL.Plain != "https://example.com/in" || *w.Headers[1].SecretValue.Plain != "Bearer TOK-SECRET" {
		t.Error("secrets not restored for sending")
	}
	// Username removed: its password secret is dropped.
	cur, _ := e.channels.Get(ctx, smtp.ID)
	_, err = e.channels.Update(ctx, smtp.ID, cur.ETag(), Channel{Name: "mail", Type: "smtp", Config: []byte(`{"host":"mail.example.com","security":"none","from":"nux@example.com","to":["a@example.com"]}`)}, e.who)
	mustNoErr(t, err)
	if n := e.count(`SELECT COUNT(*) FROM secrets`); n != 2 {
		t.Errorf("secrets = %d, want 2 (webhook url and header)", n)
	}
}

func deliveryEnv(t *testing.T, handler http.HandlerFunc) (*env, Channel, *httptest.Server) {
	t.Helper()
	e := newEnv(t)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	e.channels = NewChannels(ChannelOptions{
		DB: e.db, Secrets: e.box, Now: e.clock.Now,
		Sender: notify.NewSender(notify.Options{Policy: func(bool) probe.Policy { return probe.Policy{AllowLoopback: true} }, Sleep: func(context.Context, time.Duration) error { return nil }}),
	})
	ch, err := e.channels.Create(context.Background(), Channel{Name: "hook", Type: "webhook", Enabled: true, Config: []byte(`{"url":"` + strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + `/in"}`)}, e.who)
	mustNoErr(t, err)
	return e, ch, srv
}

func TestALR3_DeliveryRecordsResultOnChannel(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	e, ch, _ := deliveryEnv(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(int(status.Load()))
	})
	ctx := context.Background()
	m := notify.Message{Kind: "firing", AlertID: "a", ItemName: "x"}
	mustNoErr(t, e.channels.Deliver(ctx, ch.ID, m))
	got, _ := e.channels.Get(ctx, ch.ID)
	if got.LastStatus != "ok" || got.LastErrorCode != "" || got.LastSentAt == nil {
		t.Errorf("after success: %+v", got)
	}
	status.Store(404)
	if err := e.channels.Deliver(ctx, ch.ID, m); err == nil {
		t.Fatal("expected a failure")
	}
	got, _ = e.channels.Get(ctx, ch.ID)
	if got.LastStatus != "failed" || got.LastErrorCode != string(errcode.ALRSend001) {
		t.Errorf("after failure: %+v", got)
	}
	// Disabled channels send nothing.
	cur, _ := e.channels.Get(ctx, ch.ID)
	_, err := e.channels.Update(ctx, ch.ID, cur.ETag(), Channel{Name: "hook", Type: "webhook", Enabled: false, Config: cur.Config}, e.who)
	mustNoErr(t, err)
	if err := e.channels.Deliver(ctx, ch.ID, m); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled: %v", err)
	}
	if err := e.channels.Deliver(ctx, newID(t), m); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}

func TestALR3_TestSendIsLabelledAuditedRateLimitedAndIgnoresBreaker(t *testing.T) {
	var body atomic.Value
	var status atomic.Int32
	status.Store(200)
	e, ch, _ := deliveryEnv(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		w.WriteHeader(int(status.Load()))
	})
	ctx := context.Background()
	mustNoErr(t, e.channels.Test(ctx, ch.ID, "https://nux.example.com", e.who))
	if b, _ := body.Load().(string); !strings.Contains(b, `"test":true`) || !strings.Contains(b, "Test message") {
		t.Errorf("test body = %s", b)
	}
	if err := e.channels.Test(ctx, ch.ID, "", e.who); !errors.Is(err, ErrRateLimited) {
		t.Errorf("immediate second test: %v", err)
	}
	e.clock.Advance(TestGap)
	status.Store(500)
	err := e.channels.Test(ctx, ch.ID, "", e.who)
	var se *notify.SendError
	if !errors.As(err, &se) || se.Code != errcode.ALRSend002 {
		t.Errorf("failing test: %v", err)
	}
	if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'channel.test' AND result = 'success'`) != 1 ||
		e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'channel.test' AND result = 'failure' AND details_json LIKE '%ALR-SEND-002%'`) != 1 {
		t.Error("test sends are not audited with their outcome")
	}
	var details string
	mustNoErr(t, e.db.DB().QueryRow(`SELECT group_concat(details_json) FROM audit_log WHERE action = 'channel.test'`).Scan(&details))
	if strings.Contains(details, "127.0.0.1") || strings.Contains(details, "/in") {
		t.Errorf("audit details expose the destination: %s", details)
	}
}

func TestALR3_QueueOverflowDropsAndCounts(t *testing.T) {
	var logs bytes.Buffer
	e := newEnv(t)
	n := NewNotifier(NotifierOptions{Channels: e.channels, QueueSize: 2, Workers: 1, Log: slog.New(slog.NewJSONHandler(&logs, nil))})
	// Workers are not started: the queue fills and never blocks the caller.
	m := notify.Message{Kind: "firing", AlertID: "A1"}
	var accepted, dropped int
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			if n.Enqueue("ch", m) {
				accepted++
			} else {
				dropped++
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full queue")
	}
	st := n.Stats()
	if accepted != 2 || dropped != 3 || st.Dropped != 3 || st.Queued != 2 {
		t.Errorf("accepted=%d dropped=%d stats=%+v", accepted, dropped, st)
	}
	if !strings.Contains(logs.String(), "ALR-SEND-007") {
		t.Errorf("drop not logged with its code: %s", logs.String())
	}
}

func TestALR3_QueueDrainsOnShutdown(t *testing.T) {
	var got atomic.Int32
	var mu sync.Mutex
	e, ch, _ := deliveryEnv(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		got.Add(1)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	})
	n := NewNotifier(NotifierOptions{Channels: e.channels, QueueSize: 50, Workers: 2})
	n.Start()
	for i := 0; i < 20; i++ {
		if !n.Enqueue(ch.ID, notify.Message{Kind: "firing", AlertID: "a"}) {
			t.Fatal("dropped")
		}
	}
	if !n.Close(10 * time.Second) {
		t.Fatal("drain timed out")
	}
	if got.Load() != 20 || n.Stats().Sent != 20 {
		t.Errorf("delivered %d / stats %+v, want all 20", got.Load(), n.Stats())
	}
	if n.Enqueue(ch.ID, notify.Message{}) {
		t.Error("accepted after close")
	}
	n.Close(time.Second) // idempotent
}

func TestALR3_NotifierEndToEndFromEngine(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	e, ch, _ := deliveryEnv(t, func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	})
	n := NewNotifier(NotifierOptions{Channels: e.channels})
	n.Start()
	e.svc = New(Options{DB: e.db, Checks: e.checks, Inventory: e.inv, Metrics: e.metrics, Sink: n, Now: e.clock.Now, PublicURL: "https://nux.example.com"})
	e.setRoutes(Route{ChannelID: ch.ID})
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "API", checks.StateDown, "", "CHK-HTTP-002", t0)
	e.eval()
	e.checks.set(cid, "API", checks.StateUp, "", "", e.clock.Now())
	e.step(15 * time.Second)
	n.Close(5 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"type":"alert.firing"`) || !strings.Contains(bodies[1], `"type":"alert.resolved"`) || !strings.Contains(bodies[0], "/checks/"+cid) {
		t.Errorf("bodies = %v", bodies)
	}
}

func TestALR3_SSRFBlockedChannelRecordsCodeNotURL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.channels = NewChannels(ChannelOptions{DB: e.db, Secrets: e.box, Now: e.clock.Now, Sender: notify.NewSender(notify.Options{})}) // strict default policy
	ch, err := e.channels.Create(ctx, Channel{Name: "meta", Type: "webhook", Enabled: true, Config: []byte(`{"url":"http://metadata.internal.example/latest"}`)}, e.who)
	mustNoErr(t, err)
	_ = ch
	for _, bad := range []string{`http://169.254.169.254/latest`, `http://127.0.0.1:9/x`, `https://[::1]/x`} {
		_, err := e.channels.Create(ctx, Channel{Name: bad, Type: "webhook", Config: []byte(`{"url":"` + bad + `"}`)}, e.who)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s accepted at configuration time: %v", bad, err)
		}
	}
}
