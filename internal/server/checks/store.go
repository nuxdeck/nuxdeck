// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
	"github.com/nuxdeck/nuxdeck/pkg/probe"
)

// Errors returned by Service methods.
var (
	ErrNotFound = errors.New("check not found")
	ErrStale    = errors.New("check changed since it was read")
)

// secretSlot is one place a credential can live in a check.
type secretSlot struct {
	key string
	s   *Secret
}

// slots lists the secret fields currently in use.
func slots(c *Check) []secretSlot {
	if c.HTTP == nil {
		return nil
	}
	var out []secretSlot
	for i := range c.HTTP.Headers {
		if h := &c.HTTP.Headers[i]; h.Secret {
			out = append(out, secretSlot{"header:" + strings.ToLower(h.Name), h.Set})
		}
	}
	if a := c.HTTP.Auth; a != nil {
		switch a.Type {
		case "basic":
			out = append(out, secretSlot{"auth.password", a.Password})
		case "bearer":
			out = append(out, secretSlot{"auth.token", a.Token})
		}
	}
	return out
}

// applySecrets stores, replaces, keeps or removes every credential of c inside tx and returns
// the new reference map. Plaintext is dropped from c afterwards.
func (s *Service) applySecrets(ctx context.Context, tx *sql.Tx, c *Check, old map[string]string) (map[string]string, error) {
	refs := map[string]string{}
	for _, sl := range slots(c) {
		prev, had := old[sl.key]
		switch {
		case sl.s.Plain == nil: // keep
			if had {
				refs[sl.key] = prev
				sl.s.IsSet = true
			}
		case *sl.s.Plain == "": // clear
			sl.s.IsSet = false
		case had:
			if err := s.box.Replace(ctx, tx, prev, []byte(*sl.s.Plain)); err != nil {
				return nil, fmt.Errorf("replace secret: %w", err)
			}
			refs[sl.key], sl.s.IsSet = prev, true
		default:
			id, err := s.box.Put(ctx, tx, []byte(*sl.s.Plain))
			if err != nil {
				return nil, fmt.Errorf("store secret: %w", err)
			}
			refs[sl.key], sl.s.IsSet = id, true
		}
		sl.s.Plain = nil
		if !sl.s.IsSet {
			return nil, bad("http."+strings.Replace(sl.key, "header:", "headers.", 1), "A value is required.")
		}
	}
	for key, id := range old {
		if _, kept := refs[key]; kept {
			continue
		}
		if err := s.box.Delete(ctx, tx, id); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return nil, fmt.Errorf("delete secret: %w", err)
		}
	}
	return refs, nil
}

func specJSON(c *Check) (string, error) {
	var v any
	switch c.Type {
	case probe.TypeHTTP:
		v = c.HTTP
	case probe.TypeTCP:
		v = c.TCP
	case probe.TypeDNS:
		v = c.DNS
	case probe.TypeTLS:
		v = c.TLS
	default:
		v = c.Ping
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func setSpec(c *Check, raw string) error {
	var dst any
	switch c.Type {
	case probe.TypeHTTP:
		c.HTTP = &HTTPConfig{}
		dst = c.HTTP
	case probe.TypeTCP:
		c.TCP = &TCPConfig{}
		dst = c.TCP
	case probe.TypeDNS:
		c.DNS = &DNSConfig{}
		dst = c.DNS
	case probe.TypeTLS:
		c.TLS = &TLSConfig{}
		dst = c.TLS
	default:
		c.Ping = &PingConfig{}
		dst = c.Ping
	}
	return json.Unmarshal([]byte(raw), dst)
}

const checkColumns = `id, name, type, spec_json, secret_refs_json, runner, interval_s, timeout_s, retries, enabled, allow_private, rev, created_by, updated_by, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanCheck(r scanner) (Check, map[string]string, error) {
	var c Check
	var spec, refsJSON string
	var typ string
	var enabled, allow int
	var created, updated int64
	if err := r.Scan(&c.ID, &c.Name, &typ, &spec, &refsJSON, &c.Runner, &c.IntervalS, &c.TimeoutS, &c.Retries, &enabled, &allow, &c.Rev, &c.CreatedBy, &c.UpdatedBy, &created, &updated); err != nil {
		return Check{}, nil, err
	}
	c.Type, c.Enabled, c.AllowPrivate = probe.Type(typ), enabled == 1, allow == 1
	c.CreatedAt, c.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	if err := setSpec(&c, spec); err != nil {
		return Check{}, nil, fmt.Errorf("decode spec of check %s: %w", c.ID, err)
	}
	refs := map[string]string{}
	if err := json.Unmarshal([]byte(refsJSON), &refs); err != nil {
		return Check{}, nil, fmt.Errorf("decode secret refs of check %s: %w", c.ID, err)
	}
	return c, refs, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Actor identifies who changes a check, for the audit entry.
type Actor struct{ UserID, IP string }

func (a Actor) event(action, id string, details map[string]any) audit.Event {
	return audit.Event{ActorType: "user", ActorID: a.UserID, Action: action, TargetType: "check", TargetID: id, IP: a.IP, Result: audit.ResultSuccess, Details: details}
}

// auditDetails lists what changed without any credential: field names and flags only.
func auditDetails(c *Check) map[string]any {
	d := map[string]any{"name": c.Name, "type": string(c.Type), "runner": c.Runner, "interval_s": c.IntervalS, "enabled": c.Enabled, "allow_private": c.AllowPrivate}
	var set []string
	for _, sl := range slots(c) {
		if sl.s.IsSet {
			set = append(set, sl.key)
		}
	}
	if len(set) > 0 {
		d["secrets_set"] = set
	}
	return d
}

// Create validates, stores and schedules a new check, with its secrets and audit entry in one transaction.
func (s *Service) Create(ctx context.Context, in Check, who Actor) (View, error) {
	if err := s.prepare(ctx, &in); err != nil {
		return View{}, err
	}
	id, err := ids.New()
	if err != nil {
		return View{}, fmt.Errorf("create check id: %w", err)
	}
	in.ID, in.Rev = id, 1
	now := s.clock.Now().UTC()
	in.CreatedBy, in.UpdatedBy, in.CreatedAt, in.UpdatedAt = who.UserID, who.UserID, now, now
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		refs, err := s.applySecrets(ctx, tx, &in, nil)
		if err != nil {
			return err
		}
		spec, err := specJSON(&in)
		if err != nil {
			return err
		}
		refsJSON, _ := json.Marshal(refs)
		if _, err := tx.ExecContext(ctx, `INSERT INTO checks (`+checkColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.ID, in.Name, string(in.Type), spec, string(refsJSON), in.Runner, in.IntervalS, in.TimeoutS, in.Retries, b2i(in.Enabled), b2i(in.AllowPrivate), in.Rev, in.CreatedBy, in.UpdatedBy, now.UnixMilli(), now.UnixMilli()); err != nil {
			return fmt.Errorf("insert check: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("check.create", in.ID, auditDetails(&in)))
	})
	if err != nil {
		return View{}, err
	}
	s.schedule(in)
	return s.view(ctx, in)
}

// Update replaces a check. ifMatch must be the ETag of the version the caller edited.
func (s *Service) Update(ctx context.Context, id, ifMatch string, in Check, who Actor) (View, error) {
	if err := s.prepare(ctx, &in); err != nil {
		return View{}, err
	}
	var out Check
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		cur, refs, err := scanCheck(tx.QueryRowContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.ETag() != ifMatch {
			return ErrStale
		}
		in.ID, in.CreatedBy, in.CreatedAt, in.Rev = cur.ID, cur.CreatedBy, cur.CreatedAt, cur.Rev+1
		in.UpdatedBy, in.UpdatedAt = who.UserID, s.clock.Now().UTC()
		newRefs, err := s.applySecrets(ctx, tx, &in, refs)
		if err != nil {
			return err
		}
		spec, err := specJSON(&in)
		if err != nil {
			return err
		}
		refsJSON, _ := json.Marshal(newRefs)
		if _, err := tx.ExecContext(ctx, `UPDATE checks SET name=?, type=?, spec_json=?, secret_refs_json=?, runner=?, interval_s=?, timeout_s=?, retries=?, enabled=?, allow_private=?, rev=?, updated_by=?, updated_at=? WHERE id=?`,
			in.Name, string(in.Type), spec, string(refsJSON), in.Runner, in.IntervalS, in.TimeoutS, in.Retries, b2i(in.Enabled), b2i(in.AllowPrivate), in.Rev, in.UpdatedBy, in.UpdatedAt.UnixMilli(), id); err != nil {
			return fmt.Errorf("update check: %w", err)
		}
		out = in
		return s.db.AppendAudit(ctx, tx, who.event("check.update", id, auditDetails(&in)))
	})
	if err != nil {
		return View{}, err
	}
	s.schedule(out)
	return s.view(ctx, out)
}

// Delete removes a check, its history and its secrets.
func (s *Service) Delete(ctx context.Context, id string, who Actor) error {
	var name string
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		c, refs, err := scanCheck(tx.QueryRowContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		name = c.Name
		for _, sid := range refs {
			if err := s.box.Delete(ctx, tx, sid); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return fmt.Errorf("delete secret: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM checks WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete check: %w", err)
		}
		return s.db.AppendAudit(ctx, tx, who.event("check.delete", id, map[string]any{"name": name}))
	})
	if err != nil {
		return err
	}
	s.unschedule(id)
	return nil
}

// Get returns one check with its status.
func (s *Service) Get(ctx context.Context, id string) (View, error) {
	c, _, err := scanCheck(s.db.DB().QueryRowContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, c)
}

// List returns checks ordered by ID (creation order), after the cursor.
func (s *Service) List(ctx context.Context, after string, limit int) (items []View, next string, err error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("list checks: %w", err)
	}
	var cs []Check
	for rows.Next() {
		c, _, err := scanCheck(rows)
		if err != nil {
			_ = rows.Close()
			return nil, "", err
		}
		cs = append(cs, c)
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}
	if len(cs) > limit {
		cs = cs[:limit]
		next = cs[limit-1].ID
	}
	for _, c := range cs {
		v, err := s.view(ctx, c)
		if err != nil {
			return nil, "", err
		}
		items = append(items, v)
	}
	return items, next, nil
}

func (s *Service) view(ctx context.Context, c Check) (View, error) {
	st, err := s.status(ctx, c.ID)
	return View{Check: c, Status: st}, err
}

func (s *Service) status(ctx context.Context, id string) (Status, error) {
	var state, code, detail string
	var since, last, lat int64
	err := s.db.DB().QueryRowContext(ctx, `SELECT status, since_at, last_checked_at, last_latency_ms, last_error_code, last_detail FROM check_state WHERE check_id = ?`, id).Scan(&state, &since, &last, &lat, &code, &detail)
	if errors.Is(err, sql.ErrNoRows) {
		return Status{State: StateUnknown}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("read check state: %w", err)
	}
	sinceT, lastT := time.UnixMilli(since).UTC(), time.UnixMilli(last).UTC()
	return Status{State: state, Since: &sinceT, LastChecked: &lastT, LastLatencyMS: &lat, LastErrorCode: code, LastDetail: detail}, nil
}

// load reads a check and its secret references for execution.
func (s *Service) load(ctx context.Context, id string) (Check, map[string]string, error) {
	c, refs, err := scanCheck(s.db.DB().QueryRowContext(ctx, `SELECT `+checkColumns+` FROM checks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Check{}, nil, ErrNotFound
	}
	return c, refs, err
}
