// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
)

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ALR-1, ALR-2: a check going down opens one alert within one evaluation; recovering resolves it
// and sends the resolve message.
func TestALR1_CheckDownFiresAndResolves(t *testing.T) {
	e := newEnv(t)
	ch := e.channel("oncall")
	e.routeAll(ch.ID)
	e.rule("Checks down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)

	e.checks.set(cid, "API health", checks.StateUp, "", "", t0)
	e.eval()
	if n := len(e.alerts("")); n != 0 {
		t.Fatalf("alerts while up = %d", n)
	}

	e.clock.Advance(10 * time.Second)
	e.checks.set(cid, "API health", checks.StateDown, "status 503", "CHK-HTTP-002", e.clock.Now())
	e.eval()
	open := e.alerts(StateOpen)
	if len(open) != 1 {
		t.Fatalf("open alerts = %d, want 1", len(open))
	}
	a := open[0]
	if a.ItemType != ItemCheck || a.ItemID != cid || a.ItemName != "API health" || a.Severity != SeverityCritical || a.Link != "https://nux.example.com/checks/"+cid {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Summary, "CHK-HTTP-002") {
		t.Errorf("summary = %q", a.Summary)
	}
	if got := e.sink.kinds(); len(got) != 1 || got[0] != "firing" {
		t.Fatalf("sent = %v", got)
	}

	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 || len(e.sink.all()) != 1 {
		t.Error("a second evaluation duplicated the alert or its notification")
	}

	e.checks.set(cid, "API health", checks.StateUp, "", "", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts("active")) != 0 {
		t.Fatal("alert still active after recovery")
	}
	res := e.alerts(StateResolved)
	if len(res) != 1 || res[0].ResolveReason != "cleared" || res[0].ResolvedAt == nil {
		t.Fatalf("resolved = %+v", res)
	}
	if got := e.sink.kinds(); len(got) != 2 || got[1] != "resolved" {
		t.Fatalf("sent = %v, want firing then resolved", got)
	}
	if m := e.sink.all()[1].msg; m.ResolvedAt == nil || m.Link == "" || m.ItemName != "API health" {
		t.Errorf("resolve message = %+v", m)
	}
}

// ALR-2: with the 15 second period, a condition that exists at time T fires by T+15s (and no
// later than 60s), including when the first sighting falls between two evaluations.
func TestALR2_FiresWithinSixtySeconds(t *testing.T) {
	e := newEnv(t)
	e.rule("Down", KindCheckDown, SeverityWarning, `{}`, Selector{})
	cid := newID(t)
	e.eval()
	start := e.clock.Now()
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", start.Add(2*time.Second))
	var firedAfter time.Duration
	for i := 1; i <= 4; i++ {
		e.step(15 * time.Second)
		if len(e.alerts(StateOpen)) == 1 {
			firedAfter = e.clock.Now().Sub(start)
			break
		}
	}
	if firedAfter == 0 || firedAfter > 60*time.Second {
		t.Errorf("fired after %v, want <= 60s", firedAfter)
	}
	if firedAfter > 15*time.Second {
		t.Errorf("fired after %v, want within one evaluation period", firedAfter)
	}
}

// The event-driven path: a check state change published on the hub evaluates at once, without a tick.
func TestALR2_EventDrivenEvaluation(t *testing.T) {
	e := newEnv(t)
	e.rule("Down", KindCheckDown, SeverityWarning, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateUp, "", "", t0)
	ticks := make(chan time.Time) // never ticks
	e.svc.Ticks = ticks
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = e.svc.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	time.Sleep(50 * time.Millisecond) // let Run subscribe and run its first evaluation
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", e.clock.Now())
	e.checks.hub.Publish(checks.Event{CheckID: cid, From: "up", To: "down"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(e.alerts(StateOpen)) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no alert after a published check event and no tick")
}

func TestALR1_ForDurationDelaysTheAlert(t *testing.T) {
	e := newEnv(t)
	e.rule("Down 60s", KindCheckDown, SeverityCritical, `{"for_s":60}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	for _, at := range []time.Duration{15, 30, 45} {
		e.clock.Advance(15 * time.Second)
		e.eval()
		if len(e.alerts("")) != 0 {
			t.Fatalf("alert opened at +%ds, before the 60s for-duration", at+15)
		}
	}
	e.step(15 * time.Second) // +60s
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("no alert at +60s")
	}
}

func TestALR1_ForDurationResetsWhenConditionClears(t *testing.T) {
	e := newEnv(t)
	hid := newID(t)
	e.rule("CPU", KindMetricThreshold, SeverityWarning, `{"target":"host","metric":"cpu","threshold":90,"for_s":60}`, Selector{})
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, t0))
	e.metrics.setHost(hid, pct(95), nil, nil)
	e.eval()
	e.step(45 * time.Second)
	e.metrics.setHost(hid, pct(50), nil, nil) // dips
	e.step(15 * time.Second)
	e.metrics.setHost(hid, pct(95), nil, nil)
	e.step(15 * time.Second)
	e.step(45 * time.Second) // only 45s since the dip
	if len(e.alerts("")) != 0 {
		t.Fatal("alert opened although the condition did not hold for 60s in a row")
	}
	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("no alert after 60s of sustained CPU")
	}
}

func TestALR1_HostOffline(t *testing.T) {
	e := newEnv(t)
	hid := newID(t)
	e.rule("Host offline", KindHostOffline, SeverityCritical, `{}`, Selector{})
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, map[string]string{"env": "production"}, t0))
	e.eval()
	if len(e.alerts("")) != 0 {
		t.Fatal("alert for an online host")
	}
	e.clock.Advance(20 * time.Second)
	e.inv.setHost(host(hid, "web-1", inventory.StatusOffline, map[string]string{"env": "production"}, e.clock.Now()))
	e.eval()
	a := e.alerts(StateOpen)
	if len(a) != 1 || a[0].ItemType != ItemHost || a[0].Link != "https://nux.example.com/hosts/"+hid {
		t.Fatalf("alerts = %+v", a)
	}
	e.clock.Advance(20 * time.Second)
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, e.clock.Now()))
	e.eval()
	if len(e.alerts(StateResolved)) != 1 {
		t.Fatal("not resolved after the host came back")
	}
	// A host that is gone (removed) resolves rather than alerting.
	e.inv.setHost(host(hid, "web-1", inventory.StatusOffline, nil, e.clock.Now()))
	e.eval()
	e.inv.setHost(host(hid, "web-1", inventory.StatusGone, nil, e.clock.Now()))
	e.eval()
	if len(e.alerts("active")) != 0 {
		t.Error("alert stayed active for a gone host")
	}
}

func TestALR1_ContainerStoppedAndRestartLoop(t *testing.T) {
	e := newEnv(t)
	hid, cid := newID(t), newID(t)
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, t0))
	e.rule("Stopped", KindContainerStopped, SeverityWarning, `{"mode":"stopped"}`, Selector{})
	e.rule("Loop", KindContainerStopped, SeverityCritical, `{"mode":"restart_loop","restarts":3,"window_s":300}`, Selector{})
	ctr := inventory.Container{ID: cid, HostID: hid, Name: "api", State: "running", RestartCount: 0}
	e.inv.setContainer(ctr)
	e.eval()
	if len(e.alerts("")) != 0 {
		t.Fatal("alert for a healthy container")
	}

	// Restart loop: 3 restarts within 5 minutes, container still "running" between them.
	for _, n := range []int{1, 2, 3} {
		ctr.RestartCount = n
		e.inv.setContainer(ctr)
		e.step(30 * time.Second)
	}
	loop := e.alerts(StateOpen)
	if len(loop) != 1 || loop[0].RuleName != "Loop" || !strings.Contains(loop[0].Summary, "3 restarts") {
		t.Fatalf("alerts = %+v", loop)
	}

	// Stopped: exited container.
	ctr.State = "exited"
	e.inv.setContainer(ctr)
	e.step(15 * time.Second)
	if got := len(e.alerts(StateOpen)); got != 2 {
		t.Fatalf("open alerts = %d, want stopped + loop", got)
	}

	// Restarts age out of the window and the container runs again: both resolve.
	ctr.State = "running"
	e.inv.setContainer(ctr)
	e.step(6 * time.Minute)
	e.step(15 * time.Second)
	if got := len(e.alerts("active")); got != 0 {
		t.Fatalf("active alerts = %d, want 0 after recovery", got)
	}
}

func TestALR1_ContainerOfOfflineHostIsHeldNotAlerted(t *testing.T) {
	e := newEnv(t)
	hid, cid := newID(t), newID(t)
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, t0))
	e.inv.setContainer(inventory.Container{ID: cid, HostID: hid, Name: "api", State: "exited"})
	e.rule("Stopped", KindContainerStopped, SeverityWarning, `{"mode":"stopped"}`, Selector{})
	e.eval()
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("setup: no alert")
	}
	e.inv.setHost(host(hid, "web-1", inventory.StatusOffline, nil, e.clock.Now()))
	e.inv.setContainer(inventory.Container{ID: cid, HostID: hid, Name: "api", State: "running"}) // stale report
	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 {
		t.Error("the alert resolved on stale state of an offline host")
	}
}

func TestALR1_MetricThresholds(t *testing.T) {
	for _, metric := range []string{"cpu", "memory", "disk"} {
		t.Run(metric, func(t *testing.T) {
			e := newEnv(t)
			hid := newID(t)
			e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, t0))
			e.rule("High "+metric, KindMetricThreshold, SeverityWarning, `{"target":"host","metric":"`+metric+`","threshold":80,"for_s":0}`, Selector{})
			set := func(v float64) {
				var c, m, d *float64
				switch metric {
				case "cpu":
					c = pct(v)
				case "memory":
					m = pct(v)
				default:
					d = pct(v)
				}
				e.metrics.setHost(hid, c, m, d)
			}
			set(80) // not above
			e.eval()
			if len(e.alerts("")) != 0 {
				t.Fatal("alert at exactly the threshold")
			}
			set(80.5)
			e.step(15 * time.Second)
			a := e.alerts(StateOpen)
			if len(a) != 1 || !strings.Contains(a[0].Summary, "80.5%") {
				t.Fatalf("alerts = %+v", a)
			}
			e.metrics.setHost(hid, nil, nil, nil) // no data: held
			e.step(15 * time.Second)
			if len(e.alerts(StateOpen)) != 1 {
				t.Fatal("alert resolved on missing data")
			}
			set(10)
			e.step(15 * time.Second)
			if len(e.alerts("active")) != 0 {
				t.Fatal("alert did not resolve")
			}
		})
	}
}

func TestALR1_ContainerMetricThreshold(t *testing.T) {
	e := newEnv(t)
	hid, cid := newID(t), newID(t)
	e.inv.setHost(host(hid, "web-1", inventory.StatusOnline, nil, t0))
	e.inv.setContainer(inventory.Container{ID: cid, HostID: hid, Name: "api", State: "running"})
	e.rule("Container mem", KindMetricThreshold, SeverityWarning, `{"target":"container","metric":"memory","threshold":90,"for_s":0}`, Selector{})
	e.metrics.mu.Lock()
	e.metrics.rep.Containers = []metrics.Pressure{{ID: cid, MemoryPercent: pct(95)}}
	e.metrics.mu.Unlock()
	e.eval()
	if a := e.alerts(StateOpen); len(a) != 1 || a[0].ItemType != ItemContainer {
		t.Fatalf("alerts = %+v", a)
	}
}

func TestALR1_TLSExpiring(t *testing.T) {
	e := newEnv(t)
	e.rule("TLS", KindTLSExpiring, SeverityWarning, `{"days":14}`, Selector{})
	cid, other := newID(t), newID(t)
	e.checks.set(cid, "site cert", checks.StateUp, "days_remaining=40", "", t0)
	e.checks.set(other, "http check", checks.StateUp, "", "", t0)
	e.eval()
	if len(e.alerts("")) != 0 {
		t.Fatal("alert for a certificate with 40 days left")
	}
	e.checks.set(cid, "site cert", checks.StateUp, "days_remaining=14", "", e.clock.Now())
	e.step(15 * time.Second)
	a := e.alerts(StateOpen)
	if len(a) != 1 || !strings.Contains(a[0].Summary, "14 days") || a[0].ItemID != cid {
		t.Fatalf("alerts = %+v", a)
	}
	// Warn-days down state keeps the detail: still firing.
	e.checks.set(cid, "site cert", checks.StateDown, "days_remaining=9", "CHK-TLS-003", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("alert gone while the certificate is still near expiry")
	}
	// Expired.
	e.checks.set(cid, "site cert", checks.StateDown, "expired", "CHK-TLS-003", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 {
		t.Fatal("alert gone for an expired certificate")
	}
	// Renewed.
	e.checks.set(cid, "site cert", checks.StateUp, "days_remaining=89", "", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts("active")) != 0 {
		t.Fatal("alert did not resolve after renewal")
	}
}

// ALR-1: selectors by tag and by item ID.
func TestALR1_SelectorMatching(t *testing.T) {
	e := newEnv(t)
	prod, stage := newID(t), newID(t)
	e.inv.setHost(host(prod, "prod-1", inventory.StatusOffline, map[string]string{"env": "production", "team": "core"}, t0))
	e.inv.setHost(host(stage, "stage-1", inventory.StatusOffline, map[string]string{"env": "staging"}, t0))
	e.rule("prod only", KindHostOffline, SeverityCritical, `{}`, Selector{Tags: []string{"env:production"}})
	e.eval()
	a := e.alerts(StateOpen)
	if len(a) != 1 || a[0].ItemID != prod {
		t.Fatalf("tag selector alerts = %+v", a)
	}

	e2 := newEnv(t)
	e2.inv.setHost(host(prod, "prod-1", inventory.StatusOffline, map[string]string{"env": "production"}, t0))
	e2.inv.setHost(host(stage, "stage-1", inventory.StatusOffline, nil, t0))
	e2.rule("by id", KindHostOffline, SeverityCritical, `{}`, Selector{IDs: []string{stage}})
	e2.eval()
	if a := e2.alerts(StateOpen); len(a) != 1 || a[0].ItemID != stage {
		t.Fatalf("id selector alerts = %+v", a)
	}

	e3 := newEnv(t)
	e3.inv.setHost(host(prod, "prod-1", inventory.StatusOffline, map[string]string{"env": "production", "team": "core"}, t0))
	e3.rule("two tags", KindHostOffline, SeverityCritical, `{}`, Selector{Tags: []string{"env:production", "team:payments"}})
	e3.eval()
	if len(e3.alerts("")) != 0 {
		t.Error("a host missing one of two required tags matched")
	}

	// A container inherits its host's tags.
	e4 := newEnv(t)
	cid := newID(t)
	e4.inv.setHost(host(prod, "prod-1", inventory.StatusOnline, map[string]string{"env": "production"}, t0))
	e4.inv.setContainer(inventory.Container{ID: cid, HostID: prod, Name: "api", State: "exited"})
	e4.rule("ctr", KindContainerStopped, SeverityWarning, `{"mode":"stopped"}`, Selector{Tags: []string{"env:production"}})
	e4.eval()
	if len(e4.alerts(StateOpen)) != 1 {
		t.Error("container did not inherit host tags")
	}

	// A tag selector never matches a check (checks have no tags); an ID selector does.
	e5 := newEnv(t)
	chk := newID(t)
	e5.checks.set(chk, "c", checks.StateDown, "", "CHK-TCP-001", t0)
	e5.rule("tagged", KindCheckDown, SeverityWarning, `{}`, Selector{Tags: []string{"env:production"}})
	e5.eval()
	if len(e5.alerts("")) != 0 {
		t.Error("tag selector matched a check")
	}
	e5.rule("by id", KindCheckDown, SeverityWarning, `{}`, Selector{IDs: []string{chk}})
	e5.step(time.Second)
	if len(e5.alerts(StateOpen)) != 1 {
		t.Error("id selector did not match the check")
	}
}

// ALR-2: exactly one open alert per rule and item, even with concurrent evaluation, including two
// service instances sharing a database (the unique index is the backstop).
func TestALR2_DedupeSingleOpenAlertConcurrently(t *testing.T) {
	e := newEnv(t)
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	other := e.newService()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := e.svc
			if i%2 == 1 {
				s = other
			}
			_ = s.Evaluate(context.Background())
		}(i)
	}
	wg.Wait()
	if n := e.count(`SELECT COUNT(*) FROM alerts WHERE state IN ('open','acked')`); n != 1 {
		t.Fatalf("open alerts = %d, want exactly 1", n)
	}
	// The database refuses a second open alert for the fingerprint outright.
	_, err := e.db.DB().Exec(`INSERT INTO alerts (id, rule_id, rule_name, kind, severity, fingerprint, item_type, item_id, item_name, summary, state, opened_at)
		SELECT 'X'||id, rule_id, rule_name, kind, severity, fingerprint, item_type, item_id, item_name, summary, 'open', opened_at FROM alerts`)
	if err == nil {
		t.Fatal("duplicate open alert accepted by the database")
	}
}

// ALR-2: a restart reloads open alerts and does not announce them again.
func TestALR2_RestartDoesNotRenotify(t *testing.T) {
	e := newEnv(t)
	ch := e.channel("oncall")
	e.routeAll(ch.ID)
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	if len(e.sink.all()) != 1 {
		t.Fatal("setup: expected one notification")
	}
	first := e.alerts(StateOpen)[0]

	e.svc = e.newService() // restart: empty memory, same database
	e.sink.reset()
	e.step(15 * time.Second)
	e.step(15 * time.Second)
	if got := e.sink.all(); len(got) != 0 {
		t.Fatalf("restart re-notified: %v", e.sink.kinds())
	}
	open := e.alerts(StateOpen)
	if len(open) != 1 || open[0].ID != first.ID {
		t.Fatalf("alerts after restart = %+v", open)
	}
	// And it still resolves properly after the restart.
	e.checks.set(cid, "svc", checks.StateUp, "", "", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts(StateResolved)) != 1 || len(e.sink.all()) != 1 || e.sink.all()[0].msg.Kind != "resolved" {
		t.Errorf("after restart: resolved=%d sent=%v", len(e.alerts(StateResolved)), e.sink.kinds())
	}
}

func TestALR2_FlapCountIsRecorded(t *testing.T) {
	e := newEnv(t)
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	for i := 0; i < 3; i++ {
		e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", e.clock.Now())
		e.step(15 * time.Second)
		e.checks.set(cid, "svc", checks.StateUp, "", "", e.clock.Now())
		e.step(15 * time.Second)
	}
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", e.clock.Now())
	e.step(15 * time.Second)
	a := e.alerts(StateOpen)
	if len(a) != 1 || a[0].FlapCount != 3 {
		t.Fatalf("alert flap_count = %+v, want 3 earlier closures", a)
	}
	// Outside the 30 minute window earlier alerts no longer count.
	e.checks.set(cid, "svc", checks.StateUp, "", "", e.clock.Now())
	e.step(15 * time.Second)
	e.clock.Advance(31 * time.Minute)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", e.clock.Now())
	e.eval()
	if a := e.alerts(StateOpen); len(a) != 1 || a[0].FlapCount != 0 {
		t.Errorf("flap_count = %+v, want 0", a)
	}
}

func TestALR2_RuleDisabledOrDeletedResolvesItsAlerts(t *testing.T) {
	e := newEnv(t)
	r := e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	r.Enabled = false
	_, err := e.svc.UpdateRule(context.Background(), r.ID, r.ETag(), r, e.who)
	mustNoErr(t, err)
	e.step(time.Second)
	res := e.alerts(StateResolved)
	if len(res) != 1 || res[0].ResolveReason != "rule_removed" {
		t.Fatalf("resolved = %+v", res)
	}
}

func TestALR2_UnknownDataNeverResolves(t *testing.T) {
	e := newEnv(t)
	e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	e.checks.set(cid, "svc", checks.StateUnknown, "", "", e.clock.Now())
	e.step(15 * time.Second)
	if len(e.alerts(StateOpen)) != 1 {
		t.Error("an unknown check state resolved the alert")
	}
}

func TestALR1_BoundedStateAfterManyEvaluations(t *testing.T) {
	e := newEnv(t)
	hid, cid := newID(t), newID(t)
	e.inv.setHost(host(hid, "h", inventory.StatusOnline, nil, t0))
	e.rule("Loop", KindContainerStopped, SeverityWarning, `{"mode":"restart_loop","window_s":3600}`, Selector{})
	e.inv.setContainer(inventory.Container{ID: cid, HostID: hid, Name: "api", State: "running"})
	for i := 0; i < 1000; i++ {
		e.step(15 * time.Second)
	}
	if n := len(e.svc.samples[cid]); n > int(maxSampleWindow/(15*time.Second))+2 {
		t.Errorf("restart samples = %d, not bounded", n)
	}
	e.inv.mu.Lock()
	e.inv.ctrs = nil
	e.inv.mu.Unlock()
	e.step(15 * time.Second)
	if len(e.svc.samples) != 0 {
		t.Error("samples of removed containers kept")
	}
}

// ALR-8: default rules are created once when the first host is known, and can be edited or deleted.
func TestALR8_DefaultRulesSeededOnce(t *testing.T) {
	e := newEnv(t)
	_, _ = e.db.DB().Exec(`DELETE FROM alerting_state WHERE key = 'defaults_seeded'`)
	e.svc = e.newService()
	e.eval()
	if n := e.count(`SELECT COUNT(*) FROM alert_rules`); n != 0 {
		t.Fatalf("rules before any host = %d", n)
	}
	e.inv.setHost(host(newID(t), "web-1", inventory.StatusOnline, nil, t0))
	e.eval()
	want := len(defaultRules)
	if n := e.count(`SELECT COUNT(*) FROM alert_rules WHERE enabled = 1`); n != want {
		t.Fatalf("default rules = %d, want %d", n, want)
	}
	items, _, _ := e.svc.ListRules(context.Background(), "", 100)
	for _, r := range items { // every default is an ordinary editable rule
		r.Enabled = false
		if _, err := e.svc.UpdateRule(context.Background(), r.ID, r.ETag(), r, e.who); err != nil {
			t.Fatalf("edit default %s: %v", r.Name, err)
		}
	}
	mustNoErr(t, e.svc.DeleteRule(context.Background(), items[0].ID, e.who))
	e.svc = e.newService() // restart
	e.eval()
	if n := e.count(`SELECT COUNT(*) FROM alert_rules`); n != want-1 {
		t.Errorf("rules after restart = %d, want %d (defaults must not come back)", n, want-1)
	}
}

// Audit entries share the transaction of the change they describe (AUD-1).
func TestAUD1_AuditIsInTheSameTransaction(t *testing.T) {
	e := newEnv(t)
	if _, err := e.db.DB().Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit down'); END`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.svc.CreateRule(ctx, Rule{Name: "x", Kind: KindCheckDown, Severity: SeverityInfo, Params: []byte(`{}`)}, e.who); err == nil {
		t.Fatal("rule created although its audit entry failed")
	}
	if n := e.count(`SELECT COUNT(*) FROM alert_rules`); n != 0 {
		t.Errorf("rules after rolled-back create = %d", n)
	}
	if _, err := e.svc.CreateSilence(ctx, Silence{Selector: Selector{Tags: []string{"env"}}, EndsAt: t0.Add(time.Hour), Reason: "r"}, e.who); err == nil {
		t.Fatal("silence created although its audit entry failed")
	}
	if n := e.count(`SELECT COUNT(*) FROM silences`); n != 0 {
		t.Errorf("silences after rolled-back create = %d", n)
	}
	if _, err := e.channels.Create(ctx, Channel{Name: "c", Type: "slack", Config: []byte(`{"url":"https://hooks.slack.com/x"}`)}, e.who); err == nil {
		t.Fatal("channel created although its audit entry failed")
	}
	if n := e.count(`SELECT COUNT(*) FROM channels`) + e.count(`SELECT COUNT(*) FROM secrets`); n != 0 {
		t.Errorf("channel or secret rows after rolled-back create = %d", n)
	}
	// The engine's transitions too: no audit, no alert.
	e.rule2NoAudit()
	e.checks.set(newID(t), "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	if n := e.count(`SELECT COUNT(*) FROM alerts`); n != 0 {
		t.Errorf("alerts opened without an audit entry = %d", n)
	}
	// Drop the trigger: everything works and every change has its entry.
	if _, err := e.db.DB().Exec(`DROP TRIGGER fail_audit`); err != nil {
		t.Fatal(err)
	}
	e.eval()
	if e.count(`SELECT COUNT(*) FROM alerts`) != 1 || e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'alert.open'`) != 1 {
		t.Error("alert.open not audited with the alert")
	}
}

// rule2NoAudit inserts a rule directly, bypassing the audited path, so the engine has work to do.
func (e *env) rule2NoAudit() {
	e.t.Helper()
	_, err := e.db.DB().Exec(`INSERT INTO alert_rules (id, name, kind, params_json, selector_json, severity, enabled, rev, created_by, updated_by, created_at, updated_at)
		VALUES (?, 'raw', 'check_down', '{"for_s":0}', '{"tags":[],"ids":[],"severity":[],"kinds":[]}', 'critical', 1, 1, 'u', 'u', 0, 0)`, newID(e.t))
	mustNoErr(e.t, err)
}

func TestAUD1_EveryStateChangeIsAudited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch := e.channel("c")
	r := e.rule("Down", KindCheckDown, SeverityCritical, `{}`, Selector{})
	cid := newID(t)
	e.checks.set(cid, "svc", checks.StateDown, "", "CHK-TCP-001", t0)
	e.eval()
	a := e.alerts(StateOpen)[0]
	_, err := e.svc.Ack(ctx, a.ID, e.who)
	mustNoErr(t, err)
	s, err := e.svc.CreateSilence(ctx, Silence{Selector: Selector{IDs: []string{cid}}, EndsAt: t0.Add(time.Hour), Reason: "r"}, e.who)
	mustNoErr(t, err)
	mustNoErr(t, e.svc.DeleteSilence(ctx, s.ID, e.who))
	cur, _ := e.svc.Routes(ctx)
	_, err = e.svc.ReplaceRoutes(ctx, cur.ETag(), []Route{{ChannelID: ch.ID}}, e.who)
	mustNoErr(t, err)
	e.checks.set(cid, "svc", checks.StateUp, "", "", e.clock.Now())
	e.step(time.Second)
	mustNoErr(t, e.svc.DeleteRule(ctx, r.ID, e.who))
	mustNoErr(t, e.channels.Delete(ctx, ch.ID, e.who))
	for _, action := range []string{"channel.create", "rule.create", "alert.open", "alert.ack", "silence.create", "silence.delete", "routes.update", "alert.resolve", "rule.delete", "channel.delete"} {
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action) != 1 {
			t.Errorf("audit entries for %s = %d, want 1", action, e.count(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action))
		}
	}
	if _, err := e.db.VerifyAuditChain(ctx); err != nil {
		t.Errorf("audit chain: %v", err)
	}
	if e.count(`SELECT COUNT(*) FROM audit_log WHERE actor_type = 'system' AND action = 'alert.open'`) != 1 {
		t.Error("engine entries are not attributed to the system")
	}
}
