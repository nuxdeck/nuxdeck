// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// AuditStore reads the audit log; *store.Store implements it. There is deliberately no method
// that changes or removes an entry (AUD-2).
type AuditStore interface {
	Auditor
	SearchAudit(ctx context.Context, f store.AuditFilter, beforeID int64, limit int) ([]audit.Entry, int64, error)
	StreamAudit(ctx context.Context, f store.AuditFilter, fn func(audit.Entry) error) error
	VerifyAudit(ctx context.Context) (audit.Verification, error)
}

type auditAPI struct {
	*authAPI
	store AuditStore
}

func (a *auditAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/audit", a.search)
	mux.HandleFunc("GET /api/v1/audit/export", a.export)
	mux.HandleFunc("GET /api/v1/audit/verify", a.verify)
}

// auditEntryJSON is the wire form of an entry. Details are masked on every read.
type auditEntryJSON struct {
	ID         int64           `json:"id"`
	TS         string          `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	IP         string          `json:"ip"`
	Result     string          `json:"result"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

func toAuditJSON(e audit.Entry) auditEntryJSON {
	return auditEntryJSON{
		ID: e.ID, TS: time.UnixMilli(e.TS).UTC().Format(time.RFC3339Nano), ActorType: e.Event.ActorType, ActorID: e.Event.ActorID,
		Action: e.Event.Action, TargetType: e.Event.TargetType, TargetID: e.Event.TargetID, IP: e.Event.IP, Result: e.Event.Result,
		Details: json.RawMessage(audit.MaskDetails(e.DetailsJSON)), PrevHash: e.PrevHash, Hash: e.Hash,
	}
}

const maxAuditField = 256

// filterOf parses the shared filters of search and export.
func filterOf(w http.ResponseWriter, r *http.Request) (store.AuditFilter, bool) {
	q := r.URL.Query()
	bad := func(field, hint string) (store.AuditFilter, bool) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, field, hint)
		return store.AuditFilter{}, false
	}
	f := store.AuditFilter{
		ActorID: q.Get("actor"), ActionPrefix: q.Get("action"), TargetType: q.Get("target_type"),
		TargetID: q.Get("target_id"), Result: q.Get("result"), Text: q.Get("q"),
	}
	for field, v := range map[string]string{"actor": f.ActorID, "action": f.ActionPrefix, "target_type": f.TargetType, "target_id": f.TargetID, "q": f.Text} {
		if len(v) > maxAuditField {
			return bad(field, "Use at most 256 characters.")
		}
	}
	if f.Result != "" && f.Result != audit.ResultSuccess && f.Result != audit.ResultFailure {
		return bad("result", "Use success or failure.")
	}
	for field, dst := range map[string]*int64{"from": &f.FromMS, "to": &f.ToMS} {
		if v := q.Get(field); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return bad(field, "Use an RFC 3339 time such as 2026-10-28T12:00:00Z.")
			}
			*dst = t.UnixMilli()
		}
	}
	return f, true
}

func (a *auditAPI) search(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionAuditRead); !ok {
		return
	}
	f, ok := filterOf(w, r)
	if !ok {
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	var before int64
	if cursor != "" {
		n, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || n < 1 {
			writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
			return
		}
		before = n
	}
	entries, next, err := a.store.SearchAudit(r.Context(), f, before, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]auditEntryJSON, 0, len(entries))
	for _, e := range entries {
		items = append(items, toAuditJSON(e))
	}
	nextCursor := ""
	if next > 0 {
		nextCursor = strconv.FormatInt(next, 10)
	}
	writeJSON(w, http.StatusOK, pageOf(items, nextCursor))
}

func (a *auditAPI) verify(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionAuditRead); !ok {
		return
	}
	v, err := a.store.VerifyAudit(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	body := map[string]any{"ok": v.OK, "entries": v.Entries}
	if !v.OK {
		body["broken_at"] = v.BrokenAt
		body["reason"] = v.Reason
		body["code"] = string(errcode.AUDChain001)
	}
	writeJSON(w, http.StatusOK, body)
}

const exportFlushEvery = 200

// export streams the matching entries as JSON lines, one entry in memory at a time.
func (a *auditAPI) export(w http.ResponseWriter, r *http.Request) {
	p, _, ok := a.begin(w, r, auth.ActionAuditExport)
	if !ok {
		return
	}
	f, ok := filterOf(w, r)
	if !ok {
		return
	}
	// Recorded before the first byte leaves, so an export that is cut short is still on the record.
	details := map[string]any{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 && v[0] != "" && k != "cursor" && k != "limit" {
			details[k] = v[0]
		}
	}
	err := a.store.RecordAudit(r.Context(), audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "audit.export", TargetType: "audit", IP: clientOf(r).IP,
		Result: audit.ResultSuccess, Details: map[string]any{"filters": details},
	})
	if err != nil {
		a.log.Error("record audit export", "request_id", requestID(r.Context()), "error", err)
		writeError(w, http.StatusInternalServerError, errcode.AUDExp001)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="nux-audit-`+time.Now().UTC().Format("20060102T150405Z")+`.jsonl"`)
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)
	n := 0
	err = a.store.StreamAudit(r.Context(), f, func(e audit.Entry) error {
		if err := enc.Encode(toAuditJSON(e)); err != nil { // Encode ends each value with a newline
			return err
		}
		if n++; n%exportFlushEvery == 0 {
			return rc.Flush()
		}
		return nil
	})
	if err != nil {
		// The status line is gone; the client sees a truncated file and the log has the cause.
		a.log.Error("audit export interrupted", "request_id", requestID(r.Context()), "code", errcode.AUDExp001, "entries", n, "error", err)
	}
}
