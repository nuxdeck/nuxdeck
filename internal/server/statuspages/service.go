// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// RefreshEvery is how often the projection is rebuilt in addition to every admin change.
const RefreshEvery = 15 * time.Second

// Options are the service's dependencies.
type Options struct {
	DB     *store.Store
	Checks CheckSource
	Log    *slog.Logger
	// Now is the clock; tests substitute a fixed one.
	Now func() time.Time
	// RateLimit is the public requests allowed per client IP per minute; zero means the default.
	RateLimit int
}

// Service owns status pages, their incidents and the public projection.
type Service struct {
	db     *store.Store
	checks CheckSource
	log    *slog.Logger
	now    func() time.Time

	refreshMu sync.Mutex
	projMu    sync.RWMutex
	proj      map[string]*rendered
	limiter   *auth.Limiter
}

// New builds a Service. Call Run to keep the projection fresh.
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.RateLimit <= 0 {
		o.RateLimit = defaultRateLimit
	}
	return &Service{
		db: o.DB, checks: o.Checks, log: o.Log, now: o.Now, proj: map[string]*rendered{},
		limiter: auth.NewLimiter(o.RateLimit, time.Minute, o.Now),
	}
}

// Run rebuilds the projection now and every RefreshEvery until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(RefreshEvery)
	defer t.Stop()
	for {
		if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("refresh status pages", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a Actor) event(action, targetType, id string, details map[string]any) audit.Event {
	return audit.Event{ActorType: "user", ActorID: a.UserID, Action: action, TargetType: targetType, TargetID: id, IP: a.IP, Result: audit.ResultSuccess, Details: details}
}

// afterWrite refreshes the projection so an edit shows publicly at once.
func (s *Service) afterWrite(ctx context.Context) {
	if err := s.Refresh(ctx); err != nil {
		s.log.Error("refresh status pages after write", "error", err)
	}
}

func (s *Service) verifyChecks(ctx context.Context, in PageInput) error {
	var all []string
	for _, c := range in.Components {
		all = append(all, c.CheckIDs...)
	}
	if len(all) == 0 {
		return nil
	}
	have, err := s.checks.ExistingIDs(ctx, all)
	if err != nil {
		return fmt.Errorf("verify checks: %w", err)
	}
	for i, c := range in.Components {
		for _, id := range c.CheckIDs {
			if !have[id] {
				return bad(fmt.Sprintf("components[%d].check_ids", i), "Choose existing checks.")
			}
		}
	}
	return nil
}

func pageDetails(p PageInput) map[string]any {
	return map[string]any{"slug": p.Slug, "title": p.Title, "published": p.Published, "components": len(p.Components)}
}

// CreatePage stores a new page with its components and audit entry in one transaction.
func (s *Service) CreatePage(ctx context.Context, in PageInput, who Actor) (Page, error) {
	if err := validSlug(in.Slug); err != nil {
		return Page{}, err
	}
	clean, err := normalizePage(in)
	if err != nil {
		return Page{}, err
	}
	if err := s.verifyChecks(ctx, clean); err != nil {
		return Page{}, err
	}
	id, err := ids.New()
	if err != nil {
		return Page{}, fmt.Errorf("create page id: %w", err)
	}
	now := s.now().UTC()
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM status_pages`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPages {
			return bad("slug", "The server allows at most "+fmt.Sprint(MaxPages)+" status pages.")
		}
		var taken int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM status_pages WHERE slug = ?`, clean.Slug).Scan(&taken); err != nil {
			return err
		}
		if taken > 0 {
			return ErrSlugTaken
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO status_pages (id, slug, title, description, published, created_by, created_at, updated_at, rev)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`, id, clean.Slug, clean.Title, clean.Description, b2i(clean.Published), who.UserID, now.UnixMilli(), now.UnixMilli()); err != nil {
			return fmt.Errorf("insert page: %w", err)
		}
		if err := insertComponents(ctx, tx, id, clean.Components); err != nil {
			return err
		}
		return s.db.AppendAudit(ctx, tx, who.event("status_page.create", "status_page", id, pageDetails(clean)))
	})
	if err != nil {
		return Page{}, err
	}
	s.afterWrite(ctx)
	return s.GetPage(ctx, id)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func insertComponents(ctx context.Context, tx *sql.Tx, pageID string, cs []ComponentInput) error {
	for i, c := range cs {
		cid, err := ids.New()
		if err != nil {
			return fmt.Errorf("create component id: %w", err)
		}
		raw, _ := json.Marshal(c.CheckIDs)
		if _, err := tx.ExecContext(ctx, `INSERT INTO status_components (id, page_id, name, position, check_ids_json) VALUES (?, ?, ?, ?, ?)`,
			cid, pageID, c.Name, i, string(raw)); err != nil {
			return fmt.Errorf("insert component: %w", err)
		}
	}
	return nil
}

// UpdatePage replaces a page's editable fields and components. ifMatch must be the ETag the caller edited.
func (s *Service) UpdatePage(ctx context.Context, id, ifMatch string, in PageInput, who Actor) (Page, error) {
	clean, err := normalizePage(in)
	if err != nil {
		return Page{}, err
	}
	if err := s.verifyChecks(ctx, clean); err != nil {
		return Page{}, err
	}
	now := s.now().UTC()
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		var slug string
		var rev int64
		err := tx.QueryRowContext(ctx, `SELECT slug, rev FROM status_pages WHERE id = ?`, id).Scan(&slug, &rev)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if (Page{Rev: rev}).ETag() != ifMatch {
			return ErrStale
		}
		if in.Slug != "" && in.Slug != slug {
			return bad("slug", "The slug cannot be changed after the page is created.")
		}
		clean.Slug = slug
		if _, err := tx.ExecContext(ctx, `UPDATE status_pages SET title=?, description=?, published=?, updated_at=?, rev=? WHERE id=?`,
			clean.Title, clean.Description, b2i(clean.Published), now.UnixMilli(), rev+1, id); err != nil {
			return fmt.Errorf("update page: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM status_components WHERE page_id = ?`, id); err != nil {
			return fmt.Errorf("replace components: %w", err)
		}
		if err := insertComponents(ctx, tx, id, clean.Components); err != nil {
			return err
		}
		return s.db.AppendAudit(ctx, tx, who.event("status_page.update", "status_page", id, pageDetails(clean)))
	})
	if err != nil {
		return Page{}, err
	}
	s.afterWrite(ctx)
	return s.GetPage(ctx, id)
}

// DeletePage removes a page with its components, incidents and timeline entries.
func (s *Service) DeletePage(ctx context.Context, id string, who Actor) error {
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var slug, title string
		err := tx.QueryRowContext(ctx, `SELECT slug, title FROM status_pages WHERE id = ?`, id).Scan(&slug, &title)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM status_pages WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete page: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("status_page.delete", "status_page", id, map[string]any{"slug": slug, "title": title}))
	})
	if err != nil {
		return err
	}
	s.afterWrite(ctx)
	return nil
}

const pageColumns = `id, slug, title, description, published, created_at, updated_at, rev`

func scanPage(r interface{ Scan(...any) error }) (Page, error) {
	var p Page
	var pub int
	var c, u int64
	if err := r.Scan(&p.ID, &p.Slug, &p.Title, &p.Description, &pub, &c, &u, &p.Rev); err != nil {
		return Page{}, err
	}
	p.Published = pub == 1
	p.CreatedAt, p.UpdatedAt = time.UnixMilli(c).UTC(), time.UnixMilli(u).UTC()
	p.Components = []Component{}
	return p, nil
}

// GetPage returns one page.
func (s *Service) GetPage(ctx context.Context, id string) (Page, error) {
	p, err := scanPage(s.db.DB().QueryRowContext(ctx, `SELECT `+pageColumns+` FROM status_pages WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Page{}, ErrNotFound
	}
	if err != nil {
		return Page{}, err
	}
	comps, err := s.allComponents(ctx, s.db.DB(), id)
	if err != nil {
		return Page{}, err
	}
	if cs := comps[id]; cs != nil {
		p.Components = cs
	}
	return p, nil
}

// ListPages returns every page (at most MaxPages), newest first.
func (s *Service) ListPages(ctx context.Context) ([]Page, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+pageColumns+` FROM status_pages ORDER BY created_at DESC, id DESC LIMIT ?`, MaxPages)
	if err != nil {
		return nil, fmt.Errorf("list pages: %w", err)
	}
	var out []Page
	for rows.Next() {
		p, err := scanPage(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	comps, err := s.allComponents(ctx, s.db.DB())
	if err != nil {
		return nil, err
	}
	for i := range out {
		if cs := comps[out[i].ID]; cs != nil {
			out[i].Components = cs
		}
	}
	if out == nil {
		out = []Page{}
	}
	return out, nil
}

// allComponents reads components of one page, or of every page when no ID is given.
func (s *Service) allComponents(ctx context.Context, q queryer, pageID ...string) (map[string][]Component, error) {
	query, args := `SELECT page_id, id, name, check_ids_json FROM status_components`, []any{}
	if len(pageID) > 0 {
		query += ` WHERE page_id = ?`
		args = append(args, pageID[0])
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY page_id, position`, args...)
	if err != nil {
		return nil, fmt.Errorf("read components: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]Component{}
	for rows.Next() {
		var pid, raw string
		var c Component
		if err := rows.Scan(&pid, &c.ID, &c.Name, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &c.CheckIDs); err != nil || c.CheckIDs == nil {
			c.CheckIDs = []string{}
		}
		out[pid] = append(out[pid], c)
	}
	return out, rows.Err()
}

// ---- incidents ----

// incidents reads up to limit incidents of a page, newest first, with their timelines. A non-zero
// visibleSince keeps only unresolved incidents and those resolved since then.
func (s *Service) incidents(ctx context.Context, q queryer, pageID string, limit int, visibleSince ...time.Time) ([]Incident, error) {
	query := `SELECT id, page_id, title, body, status, impact, created_by, created_at, updated_at, resolved_at FROM incidents WHERE page_id = ?`
	args := []any{pageID}
	if len(visibleSince) > 0 {
		query += ` AND (resolved_at IS NULL OR resolved_at >= ?)`
		args = append(args, visibleSince[0].UnixMilli())
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY created_at DESC, id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("read incidents: %w", err)
	}
	var out []Incident
	idx := map[string]int{}
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		idx[in.ID] = len(out)
		out = append(out, in)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return []Incident{}, nil
	}
	urows, err := q.QueryContext(ctx, `SELECT u.incident_id, u.status, u.body, u.created_by, u.created_at FROM incident_updates u
		JOIN incidents i ON i.id = u.incident_id WHERE i.page_id = ? ORDER BY u.id`, pageID)
	if err != nil {
		return nil, fmt.Errorf("read incident updates: %w", err)
	}
	defer func() { _ = urows.Close() }()
	for urows.Next() {
		var iid string
		var u IncidentUpdate
		var at int64
		if err := urows.Scan(&iid, &u.Status, &u.Body, &u.CreatedBy, &at); err != nil {
			return nil, err
		}
		u.At = time.UnixMilli(at).UTC()
		if i, ok := idx[iid]; ok {
			out[i].Updates = append(out[i].Updates, u)
		}
	}
	return out, urows.Err()
}

func scanIncident(r interface{ Scan(...any) error }) (Incident, error) {
	var in Incident
	var c, u int64
	var res sql.NullInt64
	if err := r.Scan(&in.ID, &in.PageID, &in.Title, &in.Body, &in.Status, &in.Impact, &in.CreatedBy, &c, &u, &res); err != nil {
		return Incident{}, err
	}
	in.CreatedAt, in.UpdatedAt = time.UnixMilli(c).UTC(), time.UnixMilli(u).UTC()
	if res.Valid {
		t := time.UnixMilli(res.Int64).UTC()
		in.ResolvedAt = &t
	}
	in.Updates = []IncidentUpdate{}
	return in, nil
}

// ListIncidents returns a page's incidents, newest first.
func (s *Service) ListIncidents(ctx context.Context, pageID string) ([]Incident, error) {
	if _, err := s.GetPage(ctx, pageID); err != nil {
		return nil, err
	}
	return s.incidents(ctx, s.db.DB(), pageID, MaxIncidentsPerPage)
}

func (s *Service) getIncident(ctx context.Context, pageID, id string) (Incident, error) {
	in, err := scanIncident(s.db.DB().QueryRowContext(ctx, `SELECT id, page_id, title, body, status, impact, created_by, created_at, updated_at, resolved_at
		FROM incidents WHERE id = ? AND page_id = ?`, id, pageID))
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, err
	}
	all, err := s.incidents(ctx, s.db.DB(), pageID, MaxIncidentsPerPage)
	if err != nil {
		return Incident{}, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	return in, nil
}

func incDetails(in Incident) map[string]any {
	return map[string]any{"page_id": in.PageID, "title": in.Title, "status": in.Status, "impact": in.Impact}
}

// CreateIncident posts an incident, with its first timeline entry and audit entry in one transaction.
func (s *Service) CreateIncident(ctx context.Context, pageID string, in IncidentInput, who Actor) (Incident, error) {
	title, err := cleanText("title", in.Title, 1, MaxIncidentTitle, false)
	if err != nil {
		return Incident{}, err
	}
	body, err := cleanText("body", in.Body, 1, MaxIncidentBody, true)
	if err != nil {
		return Incident{}, err
	}
	if err := validIncidentStatus("status", in.Status); err != nil {
		return Incident{}, err
	}
	if err := validImpact("impact", in.Impact); err != nil {
		return Incident{}, err
	}
	id, err := ids.New()
	if err != nil {
		return Incident{}, fmt.Errorf("create incident id: %w", err)
	}
	now := s.now().UTC()
	inc := Incident{ID: id, PageID: pageID, Title: title, Body: body, Status: in.Status, Impact: in.Impact, CreatedBy: who.UserID}
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		if err := pageExists(ctx, tx, pageID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE page_id = ?`, pageID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxIncidentsPerPage {
			return bad("title", "This page has reached the incident limit; delete the page's old incidents first.")
		}
		var res any
		if in.Status == IncResolved {
			res = now.UnixMilli()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO incidents (id, page_id, title, body, status, impact, created_by, created_at, updated_at, resolved_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, pageID, title, body, in.Status, in.Impact, who.UserID, now.UnixMilli(), now.UnixMilli(), res); err != nil {
			return fmt.Errorf("insert incident: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO incident_updates (incident_id, status, body, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
			id, in.Status, body, who.UserID, now.UnixMilli()); err != nil {
			return fmt.Errorf("insert incident update: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("incident.create", "incident", id, incDetails(inc)))
	})
	if err != nil {
		return Incident{}, err
	}
	s.afterWrite(ctx)
	return s.getIncident(ctx, pageID, id)
}

func pageExists(ctx context.Context, tx *sql.Tx, pageID string) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM status_pages WHERE id = ?`, pageID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// AddUpdate appends a timeline entry and moves the incident to its status; a resolved status
// closes the incident, and any other status reopens it.
func (s *Service) AddUpdate(ctx context.Context, pageID, incidentID string, in UpdateInput, who Actor) (Incident, error) {
	if err := validIncidentStatus("status", in.Status); err != nil {
		return Incident{}, err
	}
	minBody := 1
	if in.Status == IncResolved {
		minBody = 0 // resolving needs no further words
	}
	body, err := cleanText("body", in.Body, minBody, MaxIncidentBody, true)
	if err != nil {
		return Incident{}, err
	}
	if in.Impact != "" {
		if err := validImpact("impact", in.Impact); err != nil {
			return Incident{}, err
		}
	}
	now := s.now().UTC()
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT id, page_id, title, body, status, impact, created_by, created_at, updated_at, resolved_at
			FROM incidents WHERE id = ? AND page_id = ?`, incidentID, pageID)
		cur, err := scanIncident(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_updates WHERE incident_id = ?`, incidentID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxUpdatesPerInc {
			return bad("body", "This incident has reached its update limit.")
		}
		impact := cur.Impact
		if in.Impact != "" {
			impact = in.Impact
		}
		var res any
		if in.Status == IncResolved {
			if cur.ResolvedAt != nil {
				res = cur.ResolvedAt.UnixMilli()
			} else {
				res = now.UnixMilli()
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE incidents SET status=?, impact=?, updated_at=?, resolved_at=? WHERE id=?`,
			in.Status, impact, now.UnixMilli(), res, incidentID); err != nil {
			return fmt.Errorf("update incident: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO incident_updates (incident_id, status, body, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
			incidentID, in.Status, body, who.UserID, now.UnixMilli()); err != nil {
			return fmt.Errorf("insert incident update: %w", err)
		}
		cur.Status, cur.Impact = in.Status, impact
		action := "incident.update"
		if in.Status == IncResolved {
			action = "incident.resolve"
		}
		return s.db.AppendAudit(ctx, tx, who.event(action, "incident", incidentID, incDetails(cur)))
	})
	if err != nil {
		return Incident{}, err
	}
	s.afterWrite(ctx)
	return s.getIncident(ctx, pageID, incidentID)
}

// DeleteIncident removes an incident and its timeline.
func (s *Service) DeleteIncident(ctx context.Context, pageID, incidentID string, who Actor) error {
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var title string
		err := tx.QueryRowContext(ctx, `SELECT title FROM incidents WHERE id = ? AND page_id = ?`, incidentID, pageID).Scan(&title)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM incidents WHERE id = ?`, incidentID); err != nil {
			return fmt.Errorf("delete incident: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("incident.delete", "incident", incidentID, map[string]any{"page_id": pageID, "title": title}))
	})
	if err != nil {
		return err
	}
	s.afterWrite(ctx)
	return nil
}
