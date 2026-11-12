// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// HistoryDays is the length of the uptime bars (STP-2).
const HistoryDays = 90

const (
	day = 24 * time.Hour
	// resolvedVisible is how long a resolved incident stays on the public page.
	resolvedVisible = 14 * day
	maxPublicIncs   = 20
	// A day is operational from 99.5% up, degraded from 95%, outage below.
	operationalRatio = 0.995
	degradedRatio    = 0.95
)

// pageSource is everything buildPublic needs; it never leaves this package.
type pageSource struct {
	Title, Description string
	Components         []Component
	Incidents          []Incident
}

// componentStatus derives the current status from check states: all up is operational, all
// down is an outage, some down is degraded, anything else (no checks, unknown) is unknown.
func componentStatus(checkIDs []string, states map[string]string) Status {
	var up, down, n int
	for _, id := range checkIDs {
		st, ok := states[id]
		if !ok {
			continue // a deleted check no longer counts
		}
		n++
		switch st {
		case "up":
			up++
		case "down":
			down++
		}
	}
	switch {
	case n == 0:
		return StatusUnknown
	case down == n:
		return StatusOutage
	case down > 0:
		return StatusDegraded
	case up == n:
		return StatusOperational
	}
	return StatusUnknown
}

func dayStatus(up, down int64) Status {
	if up+down == 0 {
		return StatusUnknown
	}
	switch r := float64(up) / float64(up+down); {
	case r >= operationalRatio:
		return StatusOperational
	case r >= degradedRatio:
		return StatusDegraded
	}
	return StatusOutage
}

func severity(s Status) int {
	switch s {
	case StatusOutage:
		return 3
	case StatusDegraded:
		return 2
	case StatusUnknown:
		return 1
	}
	return 0
}

// buildPublic derives the public projection of one page.
func buildPublic(src pageSource, states map[string]string, daily map[string][]DaySeconds, now time.Time) PublicPage {
	now = now.UTC()
	first := now.Truncate(day).Add(-(HistoryDays - 1) * day)
	out := PublicPage{
		Title: src.Title, Description: src.Description, GeneratedAt: now.Truncate(time.Minute),
		Status: StatusOperational, Components: []PublicComponent{}, Incidents: []PublicIncident{},
	}
	for _, c := range src.Components {
		pc := PublicComponent{Name: c.Name, Status: componentStatus(c.CheckIDs, states), Days: make([]PublicDay, HistoryDays)}
		var tu, td int64
		for i := range pc.Days {
			var u, d int64
			for _, id := range c.CheckIDs {
				if s := daily[id]; i < len(s) {
					u, d = u+s[i].Up, d+s[i].Down
				}
			}
			tu, td = tu+u, td+d
			pc.Days[i] = PublicDay{Date: first.Add(time.Duration(i) * day).Format(time.DateOnly), Status: dayStatus(u, d)}
		}
		if tu+td > 0 {
			v := math.Round(float64(tu)/float64(tu+td)*100000) / 1000
			pc.Uptime90d = &v
		}
		out.Components = append(out.Components, pc)
		if severity(pc.Status) > severity(out.Status) {
			out.Status = pc.Status
		}
	}
	if len(src.Components) == 0 {
		out.Status = StatusUnknown
	}
	incs := make([]Incident, 0, len(src.Incidents))
	for _, in := range src.Incidents {
		if in.ResolvedAt == nil || now.Sub(*in.ResolvedAt) <= resolvedVisible {
			incs = append(incs, in)
		}
	}
	sort.SliceStable(incs, func(i, j int) bool {
		ai, aj := incs[i].ResolvedAt == nil, incs[j].ResolvedAt == nil
		if ai != aj {
			return ai
		}
		return incs[i].CreatedAt.After(incs[j].CreatedAt)
	})
	if len(incs) > maxPublicIncs {
		incs = incs[:maxPublicIncs]
	}
	for _, in := range incs {
		pi := PublicIncident{Title: in.Title, Body: in.Body, Status: in.Status, Impact: in.Impact, StartedAt: in.CreatedAt.UTC(), Updates: []PublicUpdate{}}
		if in.ResolvedAt != nil {
			t := in.ResolvedAt.UTC()
			pi.ResolvedAt = &t
		}
		for _, u := range in.Updates {
			pi.Updates = append(pi.Updates, PublicUpdate{Status: u.Status, Body: u.Body, At: u.At.UTC()})
		}
		out.Incidents = append(out.Incidents, pi)
	}
	return out
}

// rendered is a projection with its serialisations, ready to serve.
type rendered struct {
	html, json         []byte
	htmlETag, jsonETag string
}

func etagOf(b []byte) string {
	h := sha256.Sum256(b)
	return `"` + hex.EncodeToString(h[:8]) + `"`
}

func render(p PublicPage) (*rendered, error) {
	js, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode public page: %w", err)
	}
	js = append(js, '\n')
	h, err := renderHTML(p)
	if err != nil {
		return nil, err
	}
	return &rendered{html: h, json: js, htmlETag: etagOf(h), jsonETag: etagOf(js)}, nil
}

// Refresh rebuilds the projection of every published page from the database and the checks.
// On failure the previous projection stays in place.
func (s *Service) Refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	now := s.now()
	srcs, err := s.loadSources(ctx)
	if err != nil {
		return fmt.Errorf("load pages: %w", err)
	}
	next := make(map[string]*rendered, len(srcs))
	if len(srcs) > 0 {
		states, err := s.checks.StatusStates(ctx)
		if err != nil {
			return fmt.Errorf("read check states: %w", err)
		}
		first := now.UTC().Truncate(day).Add(-(HistoryDays - 1) * day)
		daily, err := s.checks.DailyUptime(ctx, first, HistoryDays)
		if err != nil {
			return fmt.Errorf("read daily uptime: %w", err)
		}
		for slug, src := range srcs {
			r, err := render(buildPublic(src, states, daily, now))
			if err != nil {
				return err
			}
			next[slug] = r
		}
	}
	s.projMu.Lock()
	s.proj = next
	s.projMu.Unlock()
	return nil
}

func (s *Service) lookup(slug string) *rendered {
	s.projMu.RLock()
	defer s.projMu.RUnlock()
	return s.proj[slug]
}

// loadSources reads every published page with its components and incidents.
func (s *Service) loadSources(ctx context.Context) (map[string]pageSource, error) {
	db := s.db.DB()
	rows, err := db.QueryContext(ctx, `SELECT id, slug, title, description FROM status_pages WHERE published = 1`)
	if err != nil {
		return nil, err
	}
	byID := map[string]string{}
	out := map[string]pageSource{}
	for rows.Next() {
		var id, slug string
		var src pageSource
		if err := rows.Scan(&id, &slug, &src.Title, &src.Description); err != nil {
			_ = rows.Close()
			return nil, err
		}
		byID[id] = slug
		out[slug] = src
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	comps, err := s.allComponents(ctx, db)
	if err != nil {
		return nil, err
	}
	for pid, cs := range comps {
		if slug, ok := byID[pid]; ok {
			src := out[slug]
			src.Components = cs
			out[slug] = src
		}
	}
	for pid, slug := range byID {
		incs, err := s.incidents(ctx, db, pid, maxPublicIncs*2, s.now().Add(-resolvedVisible))
		if err != nil {
			return nil, err
		}
		src := out[slug]
		src.Incidents = incs
		out[slug] = src
	}
	return out, nil
}

type queryer interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}
