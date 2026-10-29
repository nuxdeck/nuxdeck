// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
)

const (
	notifyFiring   = notify.KindFiring
	notifyResolved = notify.KindResolved
	notifyStill    = notify.KindStillFiring
)

func (s *Service) message(kind string, a *Alert, now time.Time) notify.Message {
	return notify.Message{
		Kind: kind, AlertID: a.ID, Severity: a.Severity, RuleID: a.RuleID, RuleName: a.RuleName, RuleKind: a.Kind,
		ItemType: a.ItemType, ItemID: a.ItemID, ItemName: a.ItemName, Summary: a.Summary, Link: a.Link,
		Since: a.OpenedAt, ResolvedAt: a.ResolvedAt, FlapCount: a.FlapCount, At: now,
	}
}

// silencedAt reports whether a silence or maintenance window mutes the alert at now.
func (s *Service) silencedAt(ctx context.Context, a *Alert, tags map[string]string, now time.Time) bool {
	list, err := s.activeSilences(ctx, now)
	if err != nil {
		s.Log.Error("load silences", "error", err) // fail open: an unreadable silence list must not hide an outage
		return false
	}
	sub := subject{id: a.ItemID, tags: tags, severity: a.Severity, kind: a.Kind}
	for _, x := range list {
		if x.Selector.matches(sub) {
			return true
		}
	}
	return false
}

// dispatch routes one notification. A muted firing notification is remembered (notify_pending) and
// sent once, as "still firing", if the alert outlives the silence; a muted resolve is dropped.
// An alert that was never announced sends no resolve either.
func (s *Service) dispatch(ctx context.Context, kind string, a *Alert, tags map[string]string, now time.Time) {
	if s.Sink == nil {
		return
	}
	if kind == notifyResolved && a.LastNotifiedAt == nil {
		return
	}
	if s.silencedAt(ctx, a, tags, now) {
		if kind != notifyResolved && !a.notifyPending {
			a.notifyPending = true
			s.persistNotify(ctx, a)
		}
		return
	}
	list, err := s.Routes(ctx)
	if err != nil {
		s.Log.Error("load routes", "error", err)
		return
	}
	channels := matchRoutes(list.Routes, subject{id: a.ItemID, tags: tags, severity: a.Severity, kind: a.Kind})
	if len(channels) == 0 {
		return
	}
	m := s.message(kind, a, now)
	for _, c := range channels {
		s.Sink.Enqueue(c, m)
	}
	if kind != notifyResolved {
		a.LastNotifiedAt, a.notifyPending = &now, false
		s.persistNotify(ctx, a)
	}
}

func (s *Service) persistNotify(ctx context.Context, a *Alert) {
	var at any
	if a.LastNotifiedAt != nil {
		at = ms(*a.LastNotifiedAt)
	}
	if _, err := s.db.DB().ExecContext(ctx, `UPDATE alerts SET last_notified_at = ?, notify_pending = ? WHERE id = ?`, at, b2i(a.notifyPending), a.ID); err != nil && ctx.Err() == nil {
		s.Log.Error("record notification state", "alert_id", a.ID, "error", err)
	}
}

// housekeeping sends reminders and the post-silence summary, and prunes old rows once a day.
// An acknowledged alert gets neither.
func (s *Service) housekeeping(ctx context.Context, now time.Time) {
	for _, a := range s.active {
		if a.State == StateAcked {
			if a.notifyPending {
				a.notifyPending = false
				s.persistNotify(ctx, a)
			}
			continue
		}
		due := a.notifyPending
		if !due && s.RepeatInterval > 0 && a.LastNotifiedAt != nil && now.Sub(*a.LastNotifiedAt) >= s.RepeatInterval {
			due = true
		}
		if !due {
			continue
		}
		tags := s.tagsOf(a)
		if s.silencedAt(ctx, a, tags, now) {
			continue
		}
		a.notifyPending = false
		s.dispatch(ctx, notifyStill, a, tags, now)
	}
	if now.Sub(s.lastPrune) < 24*time.Hour {
		return
	}
	s.lastPrune = now
	if _, err := s.db.DB().ExecContext(ctx, `DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?`, ms(now.Add(-AlertRetention))); err != nil && ctx.Err() == nil {
		s.Log.Error("prune alerts", "error", err)
	}
	if _, err := s.db.DB().ExecContext(ctx, `DELETE FROM silences WHERE ends_at < ?`, ms(now.Add(-SilenceRetention))); err != nil && ctx.Err() == nil {
		s.Log.Error("prune silences", "error", err)
	}
}
