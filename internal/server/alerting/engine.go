// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
)

// observation is what one rule sees about one item at one evaluation.
type observation struct {
	itemType string
	itemID   string
	name     string
	tags     map[string]string
	// known is false when the data needed to decide is missing (no sample, agent offline, check
	// not run yet): the alert's state is then left as it is.
	known  bool
	active bool
	// since is when the condition began, if the source knows; otherwise the first evaluation that saw it.
	since   time.Time
	summary string
}

type restartSample struct {
	at    time.Time
	count int
}

// inputs loads each data source at most once per evaluation.
type inputs struct {
	s          *Service
	ctx        context.Context
	checks     []checks.State
	checksDone bool
	hosts      []inventory.Host
	hostsByID  map[string]inventory.Host
	ctrs       []inventory.Container
	pressure   map[string]metrics.Pressure
	pressDone  bool
	sampled    bool
}

func (in *inputs) checkStates() ([]checks.State, error) {
	if !in.checksDone {
		st, err := in.s.Checks.States(in.ctx)
		if err != nil {
			return nil, err
		}
		in.checks, in.checksDone = st, true
	}
	return in.checks, nil
}

func (in *inputs) allHosts() []inventory.Host {
	if in.hostsByID == nil {
		in.hosts = in.s.Inventory.Hosts()
		in.hostsByID = make(map[string]inventory.Host, len(in.hosts))
		for _, h := range in.hosts {
			in.hostsByID[h.ID] = h
		}
	}
	return in.hosts
}

func (in *inputs) containers() []inventory.Container {
	if in.ctrs == nil {
		in.ctrs = in.s.Inventory.Containers()
		if in.ctrs == nil {
			in.ctrs = []inventory.Container{}
		}
	}
	return in.ctrs
}

func (in *inputs) pressures() (map[string]metrics.Pressure, error) {
	if !in.pressDone {
		rep, err := in.s.Metrics.Pressure(in.ctx, 1_000_000)
		if err != nil {
			return nil, err
		}
		in.pressure = make(map[string]metrics.Pressure, len(rep.Hosts)+len(rep.Containers))
		for _, p := range rep.Hosts {
			in.pressure[p.ID] = p
		}
		for _, p := range rep.Containers {
			in.pressure[p.ID] = p
		}
		in.pressDone = true
	}
	return in.pressure, nil
}

// containerTags are the host's tags overlaid with the container's own, so env:production on a
// host also routes and silences its containers.
func (in *inputs) containerTags(c inventory.Container) map[string]string {
	in.allHosts()
	out := map[string]string{}
	for k, v := range in.hostsByID[c.HostID].Tags {
		out[k] = v
	}
	for k, v := range c.Tags {
		out[k] = v
	}
	return out
}

func trimText(s string, n int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > n {
		return string(r[:n])
	}
	return string(r)
}

// observe turns one rule into observations. The selector is applied here.
func (s *Service) observe(in *inputs, r Rule, p any, now time.Time) ([]observation, error) {
	var out []observation
	pick := func(id string, tags map[string]string) bool {
		return r.Selector.matches(subject{id: id, tags: tags})
	}
	switch r.Kind {
	case KindCheckDown, KindTLSExpiring:
		states, err := in.checkStates()
		if err != nil {
			return nil, err
		}
		for _, st := range states {
			if !st.Enabled || !pick(st.CheckID, nil) {
				continue
			}
			o := observation{itemType: ItemCheck, itemID: st.CheckID, name: st.Name}
			if st.Status.Since != nil {
				o.since = *st.Status.Since
			}
			if r.Kind == KindCheckDown {
				o.known, o.active = st.Status.State != checks.StateUnknown, st.Status.State == checks.StateDown
				o.summary = "Check is down"
				if st.Status.LastErrorCode != "" {
					o.summary += " (" + st.Status.LastErrorCode + ")"
				}
				if st.Status.LastDetail != "" {
					o.summary += ": " + trimText(st.Status.LastDetail, 120)
				}
				out = append(out, o)
				continue
			}
			o.since = time.Time{} // an expiring certificate has no start; the for-duration counts from first sight
			days, ok := tlsDays(st.Status)
			o.known = ok
			if ok {
				o.active = days <= p.(*TLSParams).Days
				if days < 0 {
					o.summary = "Certificate has expired"
				} else {
					o.summary = fmt.Sprintf("Certificate expires in %d days", days)
				}
			}
			out = append(out, o)
		}
	case KindHostOffline:
		for _, h := range in.allHosts() {
			if h.Status == inventory.StatusGone || !pick(h.ID, h.Tags) {
				continue
			}
			o := observation{itemType: ItemHost, itemID: h.ID, name: h.Hostname, tags: h.Tags, known: true, active: h.Status == inventory.StatusOffline, since: h.LastSeenAt, summary: "Agent is offline"}
			out = append(out, o)
		}
	case KindContainerStopped:
		cp := p.(*ContainerParams)
		in.allHosts()
		if !in.sampled {
			s.trackRestarts(in.containers(), now)
			in.sampled = true
		}
		for _, c := range in.containers() {
			tags := in.containerTags(c)
			if c.GoneAt != nil || !pick(c.ID, tags) {
				continue
			}
			o := observation{itemType: ItemContainer, itemID: c.ID, name: c.Name, tags: tags, known: true}
			if h, ok := in.hostsByID[c.HostID]; !ok || h.Status != inventory.StatusOnline {
				o.known = false // its state is as old as the host's last report
				out = append(out, o)
				continue
			}
			stopped := (c.State == "exited" || c.State == "dead") && cp.Mode != ModeRestartLoop
			looping := false
			if cp.Mode != ModeStopped {
				n := s.restartsWithin(c.ID, now, time.Duration(cp.WindowS)*time.Second)
				looping = n >= cp.Restarts || c.State == "restarting"
				if looping {
					o.summary = fmt.Sprintf("Restart loop: %d restarts in %d seconds", n, cp.WindowS)
				}
			}
			o.active = stopped || looping
			if stopped {
				o.summary = "Container is " + c.State
			}
			out = append(out, o)
		}
	case KindMetricThreshold:
		mp := p.(*MetricParams)
		pr, err := in.pressures()
		if err != nil {
			return nil, err
		}
		emit := func(itemType, id, name string, tags map[string]string) {
			if !pick(id, tags) {
				return
			}
			o := observation{itemType: itemType, itemID: id, name: name, tags: tags}
			row, ok := pr[id]
			var v *float64
			if ok {
				switch mp.Metric {
				case "cpu":
					v = row.CPUPercent
				case "memory":
					v = row.MemoryPercent
				default:
					v = row.DiskPercent
				}
			}
			if v != nil {
				o.known, o.active = true, *v > *mp.Threshold
				o.summary = fmt.Sprintf("%s usage is %.1f%% (threshold %.0f%%)", strings.ToUpper(mp.Metric[:1])+mp.Metric[1:], *v, *mp.Threshold)
			}
			out = append(out, o)
		}
		if mp.Target == ItemHost {
			for _, h := range in.allHosts() {
				if h.Status == inventory.StatusGone {
					continue
				}
				emit(ItemHost, h.ID, h.Hostname, h.Tags)
			}
		} else {
			in.allHosts()
			for _, c := range in.containers() {
				if c.GoneAt == nil {
					emit(ItemContainer, c.ID, c.Name, in.containerTags(c))
				}
			}
		}
	}
	return out, nil
}

// tlsDays reads the remaining days from a TLS check's result. The check reports
// "days_remaining=N", or "expired" once the certificate is past its end.
func tlsDays(st checks.Status) (int, bool) {
	switch {
	case strings.HasPrefix(st.LastDetail, "days_remaining="):
		n, err := strconv.Atoi(strings.TrimPrefix(st.LastDetail, "days_remaining="))
		return n, err == nil
	case st.LastDetail == "expired" && st.LastErrorCode == "CHK-TLS-003":
		return -1, true
	}
	return 0, false
}

// maxSampleWindow bounds the restart history kept per container.
const maxSampleWindow = time.Hour

func (s *Service) trackRestarts(list []inventory.Container, now time.Time) {
	present := make(map[string]bool, len(list))
	for _, c := range list {
		present[c.ID] = true
		sm := s.samples[c.ID]
		if n := len(sm); n > 0 && c.RestartCount < sm[n-1].count { // recreated: counting starts over
			sm = nil
		}
		sm = append(sm, restartSample{at: now, count: c.RestartCount})
		cut := 0
		for cut < len(sm)-1 && now.Sub(sm[cut].at) > maxSampleWindow {
			cut++
		}
		s.samples[c.ID] = append(sm[:0:0], sm[cut:]...)
	}
	for id := range s.samples {
		if !present[id] {
			delete(s.samples, id)
		}
	}
}

// restartsWithin counts restarts between the oldest sample inside the window and the newest.
func (s *Service) restartsWithin(id string, now time.Time, window time.Duration) int {
	sm := s.samples[id]
	if len(sm) == 0 {
		return 0
	}
	base := sm[len(sm)-1]
	for _, x := range sm {
		if now.Sub(x.at) <= window {
			base = x
			break
		}
	}
	return sm[len(sm)-1].count - base.count
}

// ---- evaluation ----

// Evaluate runs every enabled rule once, opens and resolves alerts, and sends the
// notifications that are due. It is safe to call concurrently.
func (s *Service) Evaluate(ctx context.Context) error {
	s.emu.Lock()
	defer s.emu.Unlock()
	if err := s.ensureLoaded(ctx); err != nil {
		return err
	}
	now := s.now()
	in := &inputs{s: s, ctx: ctx}
	if err := s.seedDefaults(ctx, in); err != nil {
		s.Log.Error("create default alert rules", "error", err)
	}
	rules, err := s.enabledRules(ctx)
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		live[r.ID] = true
		p, err := parseParams(r.Kind, r.Params)
		if err != nil {
			s.Log.Error("alert rule has invalid params", "rule_id", r.ID, "error", err)
			s.holdRule(r.ID, seen)
			continue
		}
		obs, err := s.observe(in, r, p, now)
		if err != nil {
			s.Log.Error("evaluate alert rule", "rule_id", r.ID, "kind", r.Kind, "error", err)
			s.holdRule(r.ID, seen) // no data this round must not resolve anything
			continue
		}
		for _, o := range obs {
			fp := r.ID + ":" + o.itemID
			seen[fp] = true
			if err := s.apply(ctx, r, p, o, fp, now); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				s.Log.Error("apply alert state", "rule_id", r.ID, "item_id", o.itemID, "error", err)
			}
		}
	}
	for fp, a := range s.active {
		if seen[fp] {
			continue
		}
		reason := "item_removed"
		if !live[a.RuleID] {
			reason = "rule_removed"
		}
		if err := s.resolve(ctx, a, reason, now); err != nil && ctx.Err() == nil {
			s.Log.Error("resolve alert", "alert_id", a.ID, "error", err)
		}
	}
	for fp := range s.pending {
		if !seen[fp] {
			delete(s.pending, fp)
		}
	}
	s.housekeeping(ctx, now)
	s.evalRuns++
	return nil
}

// holdRule marks every active alert and pending condition of a rule as seen.
func (s *Service) holdRule(ruleID string, seen map[string]bool) {
	prefix := ruleID + ":"
	for fp := range s.active {
		if strings.HasPrefix(fp, prefix) {
			seen[fp] = true
		}
	}
	for fp := range s.pending {
		if strings.HasPrefix(fp, prefix) {
			seen[fp] = true
		}
	}
}

func forDuration(p any) time.Duration {
	switch v := p.(type) {
	case *CheckDownParams:
		return time.Duration(v.forS(0)) * time.Second
	case *HostOfflineParams:
		return time.Duration(v.forS(0)) * time.Second
	case *ContainerParams:
		return time.Duration(v.forS(0)) * time.Second
	case *MetricParams:
		return time.Duration(v.forS(defaultMetricFor)) * time.Second
	case *TLSParams:
		return time.Duration(v.forS(0)) * time.Second
	}
	return 0
}

func (s *Service) apply(ctx context.Context, r Rule, p any, o observation, fp string, now time.Time) error {
	cur := s.active[fp]
	switch {
	case !o.known:
		return nil
	case o.active:
		if cur != nil {
			return nil
		}
		since, ok := s.pending[fp]
		if !ok {
			since = now
			if !o.since.IsZero() && o.since.Before(now) {
				since = o.since
			}
			s.pending[fp] = since
		}
		if now.Sub(since) < forDuration(p) {
			return nil
		}
		if len(s.active) >= MaxActiveAlerts {
			s.Log.Error("open alert limit reached; not opening a new alert", "limit", MaxActiveAlerts)
			return nil
		}
		delete(s.pending, fp)
		return s.open(ctx, r, o, fp, now)
	default:
		delete(s.pending, fp)
		if cur != nil {
			return s.resolve(ctx, cur, "cleared", now)
		}
	}
	return nil
}

func (s *Service) open(ctx context.Context, r Rule, o observation, fp string, now time.Time) error {
	id, err := ids.At(now)
	if err != nil {
		return err
	}
	a := &Alert{
		ID: id, RuleID: r.ID, RuleName: r.Name, Kind: r.Kind, Severity: r.Severity, ItemType: o.itemType, ItemID: o.itemID, ItemName: trimText(o.name, 200),
		Summary: trimText(o.summary, 300), State: StateOpen, OpenedAt: now, fingerprint: fp, Link: s.Link(o.itemType, o.itemID),
	}
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE fingerprint = ? AND state = 'resolved' AND resolved_at >= ?`, fp, ms(now.Add(-FlapWindow))).Scan(&a.FlapCount); err != nil {
			return fmt.Errorf("count flaps: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alerts (id, rule_id, rule_name, kind, severity, fingerprint, item_type, item_id, item_name, summary, state, opened_at, flap_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
			a.ID, a.RuleID, a.RuleName, a.Kind, a.Severity, fp, a.ItemType, a.ItemID, a.ItemName, a.Summary, ms(now), a.FlapCount); err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, systemEvent("alert.open", "alert", a.ID, map[string]any{
			"rule_id": a.RuleID, "rule_name": a.RuleName, "severity": a.Severity, "item_type": a.ItemType, "item_id": a.ItemID, "flap_count": a.FlapCount,
		}))
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") { // another writer won; the cache catches up on reload
			s.loaded = false
			return nil
		}
		return err
	}
	s.active[fp] = a
	s.dispatch(ctx, notifyFiring, a, o.tags, now)
	return nil
}

func (s *Service) resolve(ctx context.Context, a *Alert, reason string, now time.Time) error {
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE alerts SET state = 'resolved', resolved_at = ?, resolve_reason = ?, notify_pending = 0 WHERE id = ? AND state != 'resolved'`, ms(now), reason, a.ID)
		if err != nil {
			return fmt.Errorf("resolve alert: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		return s.db.AppendAudit(ctx, tx, systemEvent("alert.resolve", "alert", a.ID, map[string]any{"rule_id": a.RuleID, "item_type": a.ItemType, "item_id": a.ItemID, "reason": reason}))
	})
	if err != nil {
		return err
	}
	delete(s.active, a.fingerprint)
	a.State, a.ResolvedAt, a.ResolveReason = StateResolved, &now, reason
	s.dispatch(ctx, notifyResolved, a, s.tagsOf(a), now)
	return nil
}

// ensureLoaded reads the active alerts after a start, so a restart neither forgets nor repeats them.
func (s *Service) ensureLoaded(ctx context.Context) error {
	if s.loaded {
		return nil
	}
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE state IN ('open','acked') ORDER BY id LIMIT ?`, MaxActiveAlerts)
	if err != nil {
		return fmt.Errorf("load open alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	s.active = map[string]*Alert{}
	for rows.Next() {
		a, err := s.scanAlert(rows)
		if err != nil {
			return err
		}
		s.active[a.fingerprint] = &a
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var v string
	switch err := s.db.DB().QueryRowContext(ctx, `SELECT value FROM alerting_state WHERE key = 'defaults_seeded'`).Scan(&v); {
	case err == nil:
		s.seeded = true
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	s.loaded = true
	return nil
}

// tagsOf looks up the current tags of an alert's item for routing and silences.
func (s *Service) tagsOf(a *Alert) map[string]string {
	if s.Inventory == nil {
		return nil
	}
	switch a.ItemType {
	case ItemHost:
		if h, ok := s.Inventory.Host(a.ItemID); ok {
			return h.Tags
		}
	case ItemContainer:
		if c, ok := s.Inventory.Container(a.ItemID); ok {
			out := map[string]string{}
			if h, ok := s.Inventory.Host(c.HostID); ok {
				for k, v := range h.Tags {
					out[k] = v
				}
			}
			for k, v := range c.Tags {
				out[k] = v
			}
			return out
		}
	}
	return nil
}

// Run evaluates every EvalInterval and whenever a check, host or container changes, until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	ticks := s.Ticks
	if ticks == nil {
		t := time.NewTicker(s.EvalInterval)
		defer t.Stop()
		ticks = t.C
	}
	var checkEvents <-chan checks.Event
	var checkSub *checks.Subscription
	var invEvents <-chan inventory.Event
	var invSub *inventory.Subscription
	subscribe := func() {
		if s.Checks != nil && checkSub == nil {
			checkSub = s.Checks.Hub().Subscribe()
			checkEvents = checkSub.C
		}
		if s.Inventory != nil && invSub == nil {
			if sub, err := s.Inventory.Subscribe(); err == nil {
				invSub, invEvents = sub, sub.C
			}
		}
	}
	defer func() {
		if checkSub != nil {
			checkSub.Close()
		}
		if invSub != nil {
			invSub.Close()
		}
	}()
	subscribe()
	eval := func() {
		if err := s.Evaluate(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("alert evaluation failed", "error", err)
		}
	}
	eval()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			subscribe()
			eval()
		case <-s.kick:
			eval()
		case _, ok := <-checkEvents:
			if !ok { // fell behind: the next evaluation re-reads every state
				checkSub, checkEvents = nil, nil
				subscribe()
			}
			drain(checkEvents)
			eval()
		case ev, ok := <-invEvents:
			if !ok {
				invSub, invEvents = nil, nil
				subscribe()
			}
			drain(invEvents)
			if ok && ev.Type != inventory.EventResync {
				eval()
			}
		}
	}
}

func drain[T any](c <-chan T) {
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// ---- default rules (ALR-8) ----

type defaultRule struct {
	name, kind, severity string
	params               string
}

var defaultRules = []defaultRule{
	{"Host offline", KindHostOffline, SeverityCritical, `{"for_s":60}`},
	{"Container stopped or restarting", KindContainerStopped, SeverityWarning, `{"mode":"either"}`},
	{"Check down", KindCheckDown, SeverityCritical, `{"for_s":0}`},
	{"High CPU", KindMetricThreshold, SeverityWarning, `{"target":"host","metric":"cpu","threshold":90,"for_s":300}`},
	{"High memory", KindMetricThreshold, SeverityWarning, `{"target":"host","metric":"memory","threshold":90,"for_s":300}`},
	{"High disk usage", KindMetricThreshold, SeverityWarning, `{"target":"host","metric":"disk","threshold":90,"for_s":600}`},
	{"TLS certificate expiring", KindTLSExpiring, SeverityWarning, `{"days":14}`},
}

// seedDefaults creates the default rules once, when the first host is known. They are ordinary
// rules: edit, disable or delete them freely; a deleted default is not recreated.
func (s *Service) seedDefaults(ctx context.Context, in *inputs) error {
	if s.seeded || s.Inventory == nil || len(in.allHosts()) == 0 {
		return nil
	}
	now := s.now()
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, d := range defaultRules {
			r, err := validateRule(Rule{Name: d.name, Kind: d.kind, Severity: d.severity, Enabled: true, Params: []byte(d.params)})
			if err != nil {
				return err
			}
			id, err := ids.At(now)
			if err != nil {
				return err
			}
			r.ID, r.Rev, r.Enabled, r.CreatedBy, r.UpdatedBy, r.CreatedAt, r.UpdatedAt = id, 1, true, "system", "system", now, now
			if err := insertRule(ctx, tx, r); err != nil {
				return err
			}
			if err := s.db.AppendAudit(ctx, tx, systemEvent("rule.create", "alert_rule", id, map[string]any{"name": r.Name, "kind": r.Kind, "severity": r.Severity, "default": true})); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO alerting_state (key, value) VALUES ('defaults_seeded', '1')`)
		return err
	})
	if err != nil {
		return err
	}
	s.seeded = true
	return nil
}
