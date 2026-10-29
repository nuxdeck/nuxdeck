// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// maxAlertBody bounds rule, silence, channel and route documents.
const maxAlertBody = 64 << 10

type alertsAPI struct {
	*authAPI
	alerts   *alerting.Service
	channels *alerting.Channels
	// inv resolves the items alerts and selectors name, for scope checks (ACC-5); nil treats them as unscoped-only.
	inv *inventory.Service
}

func (a *alertsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/rules", a.listRules)
	mux.HandleFunc("POST /api/v1/rules", a.createRule)
	mux.HandleFunc("GET /api/v1/rules/{id}", a.getRule)
	mux.HandleFunc("PUT /api/v1/rules/{id}", a.updateRule)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", a.deleteRule)

	mux.HandleFunc("GET /api/v1/alerts", a.listAlerts)
	mux.HandleFunc("GET /api/v1/alerts/{id}", a.getAlert)
	mux.HandleFunc("POST /api/v1/alerts/{id}/ack", a.ack)

	mux.HandleFunc("GET /api/v1/silences", a.listSilences)
	mux.HandleFunc("POST /api/v1/silences", a.createSilence)
	mux.HandleFunc("DELETE /api/v1/silences/{id}", a.deleteSilence)

	mux.HandleFunc("GET /api/v1/channels", a.listChannels)
	mux.HandleFunc("POST /api/v1/channels", a.createChannel)
	mux.HandleFunc("GET /api/v1/channels/{id}", a.getChannel)
	mux.HandleFunc("PUT /api/v1/channels/{id}", a.updateChannel)
	mux.HandleFunc("DELETE /api/v1/channels/{id}", a.deleteChannel)
	mux.HandleFunc("POST /api/v1/channels/{id}/test", a.testChannel)

	mux.HandleFunc("GET /api/v1/routes", a.getRoutes)
	mux.HandleFunc("PUT /api/v1/routes", a.putRoutes)
}

// write is the shared head of the changing endpoints: authorise, CSRF and path ID.
func (a *alertsAPI) write(w http.ResponseWriter, r *http.Request, action auth.Action, needID bool) (alerting.Actor, string, auth.Principal, bool) {
	p, sess, ok := a.begin(w, r, action)
	if !ok {
		return alerting.Actor{}, "", p, false
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return alerting.Actor{}, "", p, false
	}
	var id string
	if needID {
		id = r.PathValue("id")
		if !ulid.MatchString(id) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return alerting.Actor{}, "", p, false
		}
	}
	return alerting.Actor{UserID: p.UserID, IP: clientOf(r).IP}, id, p, true
}

// read authorises a GET and validates the path ID, if any.
func (a *alertsAPI) read(w http.ResponseWriter, r *http.Request, action auth.Action, needID bool) (string, auth.Principal, bool) {
	p, _, ok := a.begin(w, r, action)
	if !ok {
		return "", p, false
	}
	if !needID {
		return "", p, true
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return "", p, false
	}
	return id, p, true
}

func ifMatchOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := strings.TrimPrefix(r.Header.Get("If-Match"), "W/")
	if v == "" {
		writeError(w, http.StatusPreconditionRequired, errcode.APIPre002)
		return "", false
	}
	return v, true
}

// alertErr renders a service error and reports whether there was one.
func (a *alertsAPI) alertErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var ve *alerting.ValidationError
	var se *notify.SendError
	switch {
	case errors.As(err, &ve):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, ve.Field, ve.Msg)
	case errors.Is(err, alerting.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.APINF001)
	case errors.Is(err, alerting.ErrStale):
		writeError(w, http.StatusPreconditionFailed, errcode.APIPre001)
	case errors.Is(err, alerting.ErrResolved):
		writeError(w, http.StatusConflict, errcode.ALRRule001)
	case errors.Is(err, alerting.ErrDisabled):
		writeError(w, http.StatusConflict, errcode.ALRSend008)
	case errors.Is(err, alerting.ErrRateLimited):
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, errcode.ALRSend006)
	case errors.As(err, &se):
		writeError(w, http.StatusBadGateway, se.Code)
	default:
		a.fail(w, r, err)
	}
	return true
}

func pageOf[T any](items []T, next string) pageJSON[T] {
	out := pageJSON[T]{Items: items}
	if items == nil {
		out.Items = []T{}
	}
	if next != "" {
		out.NextCursor = &next
	}
	return out
}

// cursorOf reads and validates ?cursor= for the descending lists (an ID).
func cursorOf(w http.ResponseWriter, r *http.Request) (cursor string, limit int, ok bool) {
	cursor, limit, ok = pageParams(w, r)
	if ok && cursor != "" && !ulid.MatchString(cursor) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
		return "", 0, false
	}
	return cursor, limit, ok
}

// ---- rules ----

func (a *alertsAPI) listRules(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.read(w, r, auth.ActionRulesRead, false)
	if !ok {
		return
	}
	cursor, limit, ok := cursorOf(w, r)
	if !ok {
		return
	}
	items, next, err := a.alerts.ListRules(r.Context(), cursor, limit)
	if a.alertErr(w, r, err) {
		return
	}
	// Filtering follows pagination, so a scoped caller can get a short page that still has a cursor.
	items = keep(items, func(rule alerting.Rule) bool { return selectorCovered(p, auth.ActionRulesRead, a.inv, rule.Selector) })
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) getRule(w http.ResponseWriter, r *http.Request) {
	id, p, ok := a.read(w, r, auth.ActionRulesRead, true)
	if !ok {
		return
	}
	rule, err := a.alerts.GetRule(r.Context(), id)
	if a.alertErr(w, r, err) {
		return
	}
	if !selectorCovered(p, auth.ActionRulesRead, a.inv, rule.Selector) {
		scopeDenied(w)
		return
	}
	w.Header().Set("ETag", rule.ETag())
	writeJSON(w, http.StatusOK, rule)
}

func (a *alertsAPI) createRule(w http.ResponseWriter, r *http.Request) {
	who, _, p, ok := a.write(w, r, auth.ActionRulesWrite, false)
	if !ok {
		return
	}
	var in alerting.Rule
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	if !selectorCovered(p, auth.ActionRulesWrite, a.inv, in.Selector) {
		a.fail(w, r, errcode.New(errcode.AuthRBAC002, "rule selector is outside the caller's scope"))
		return
	}
	rule, err := a.alerts.CreateRule(r.Context(), in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", rule.ETag())
	w.Header().Set("Location", "/api/v1/rules/"+rule.ID)
	writeJSON(w, http.StatusCreated, rule)
}

func (a *alertsAPI) updateRule(w http.ResponseWriter, r *http.Request) {
	who, id, p, ok := a.write(w, r, auth.ActionRulesWrite, true)
	if !ok {
		return
	}
	ifMatch, ok := ifMatchOf(w, r)
	if !ok {
		return
	}
	var in alerting.Rule
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	if !a.ruleWritable(w, r, p, id, &in.Selector) {
		return
	}
	rule, err := a.alerts.UpdateRule(r.Context(), id, ifMatch, in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", rule.ETag())
	writeJSON(w, http.StatusOK, rule)
}

func (a *alertsAPI) deleteRule(w http.ResponseWriter, r *http.Request) {
	who, id, p, ok := a.write(w, r, auth.ActionRulesWrite, true)
	if !ok {
		return
	}
	if !a.ruleWritable(w, r, p, id, nil) {
		return
	}
	if a.alertErr(w, r, a.alerts.DeleteRule(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- alerts ----

func (a *alertsAPI) listAlerts(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.read(w, r, auth.ActionAlertsRead, false)
	if !ok {
		return
	}
	cursor, limit, ok := cursorOf(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := alerting.AlertFilter{State: q.Get("state"), Severity: q.Get("severity"), ItemID: q.Get("item_id"), RuleID: q.Get("rule_id")}
	if (f.ItemID != "" && !ulid.MatchString(f.ItemID)) || (f.RuleID != "" && !ulid.MatchString(f.RuleID)) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "item_id", "Use an item or rule ID.")
		return
	}
	items, next, err := a.alerts.ListAlerts(r.Context(), f, cursor, limit)
	if a.alertErr(w, r, err) {
		return
	}
	items = keep(items, func(al alerting.Alert) bool { return p.Covers(auth.ActionAlertsRead, alertResource(a.inv, al)) })
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) getAlert(w http.ResponseWriter, r *http.Request) {
	id, p, ok := a.read(w, r, auth.ActionAlertsRead, true)
	if !ok {
		return
	}
	al, err := a.alerts.GetAlert(r.Context(), id)
	if a.alertErr(w, r, err) {
		return
	}
	if !p.Covers(auth.ActionAlertsRead, alertResource(a.inv, al)) {
		scopeDenied(w)
		return
	}
	writeJSON(w, http.StatusOK, al)
}

func (a *alertsAPI) ack(w http.ResponseWriter, r *http.Request) {
	who, id, p, ok := a.write(w, r, auth.ActionAlertsAck, true)
	if !ok {
		return
	}
	if cur, err := a.alerts.GetAlert(r.Context(), id); err == nil && !p.Covers(auth.ActionAlertsAck, alertResource(a.inv, cur)) {
		scopeDenied(w)
		return
	}
	al, err := a.alerts.Ack(r.Context(), id, who)
	if a.alertErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, al)
}

// ---- silences ----

func (a *alertsAPI) listSilences(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.read(w, r, auth.ActionSilencesRead, false)
	if !ok {
		return
	}
	cursor, limit, ok := cursorOf(w, r)
	if !ok {
		return
	}
	active := false
	switch r.URL.Query().Get("active") {
	case "", "false":
	case "true":
		active = true
	default:
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "active", "Use true or false.")
		return
	}
	items, next, err := a.alerts.ListSilences(r.Context(), active, cursor, limit)
	if a.alertErr(w, r, err) {
		return
	}
	items = keep(items, func(sl alerting.Silence) bool { return selectorCovered(p, auth.ActionSilencesRead, a.inv, sl.Selector) })
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) createSilence(w http.ResponseWriter, r *http.Request) {
	who, _, p, ok := a.write(w, r, auth.ActionSilencesWrite, false)
	if !ok {
		return
	}
	var in alerting.Silence
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	if !selectorCovered(p, auth.ActionSilencesWrite, a.inv, in.Selector) {
		a.fail(w, r, errcode.New(errcode.AuthRBAC002, "silence selector is outside the caller's scope"))
		return
	}
	s, err := a.alerts.CreateSilence(r.Context(), in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("Location", "/api/v1/silences/"+s.ID)
	writeJSON(w, http.StatusCreated, s)
}

func (a *alertsAPI) deleteSilence(w http.ResponseWriter, r *http.Request) {
	who, id, p, ok := a.write(w, r, auth.ActionSilencesWrite, true)
	if !ok {
		return
	}
	if !unrestricted(p, auth.ActionSilencesWrite) {
		if !a.silenceInScope(r, p, id) {
			scopeDenied(w)
			return
		}
	}
	if a.alertErr(w, r, a.alerts.DeleteSilence(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- channels ----

func (a *alertsAPI) listChannels(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.read(w, r, auth.ActionChannelsRead, false); !ok {
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	if cursor != "" && !ulid.MatchString(cursor) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
		return
	}
	items, next, err := a.channels.List(r.Context(), cursor, limit)
	if a.alertErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) getChannel(w http.ResponseWriter, r *http.Request) {
	id, _, ok := a.read(w, r, auth.ActionChannelsRead, true)
	if !ok {
		return
	}
	ch, err := a.channels.Get(r.Context(), id)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", ch.ETag())
	writeJSON(w, http.StatusOK, ch)
}

func (a *alertsAPI) createChannel(w http.ResponseWriter, r *http.Request) {
	who, _, _, ok := a.write(w, r, auth.ActionChannelsWrite, false)
	if !ok {
		return
	}
	var in alerting.Channel
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	ch, err := a.channels.Create(r.Context(), in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", ch.ETag())
	w.Header().Set("Location", "/api/v1/channels/"+ch.ID)
	writeJSON(w, http.StatusCreated, ch)
}

func (a *alertsAPI) updateChannel(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, auth.ActionChannelsWrite, true)
	if !ok {
		return
	}
	ifMatch, ok := ifMatchOf(w, r)
	if !ok {
		return
	}
	var in alerting.Channel
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	ch, err := a.channels.Update(r.Context(), id, ifMatch, in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", ch.ETag())
	writeJSON(w, http.StatusOK, ch)
}

func (a *alertsAPI) deleteChannel(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, auth.ActionChannelsWrite, true)
	if !ok {
		return
	}
	if a.alertErr(w, r, a.channels.Delete(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *alertsAPI) testChannel(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, auth.ActionChannelsTest, true)
	if !ok {
		return
	}
	if a.alertErr(w, r, a.channels.Test(r.Context(), id, a.alerts.PublicURL, who)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- routes ----

type routesDoc struct {
	Routes []alerting.Route `json:"routes"`
}

func (a *alertsAPI) getRoutes(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.read(w, r, auth.ActionRoutesRead, false); !ok {
		return
	}
	l, err := a.alerts.Routes(r.Context())
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", l.ETag())
	writeJSON(w, http.StatusOK, routesDoc{Routes: l.Routes})
}

func (a *alertsAPI) putRoutes(w http.ResponseWriter, r *http.Request) {
	who, _, _, ok := a.write(w, r, auth.ActionRoutesWrite, false)
	if !ok {
		return
	}
	ifMatch, ok := ifMatchOf(w, r)
	if !ok {
		return
	}
	var in routesDoc
	if !a.decodeMax(w, r, &in, maxAlertBody) {
		return
	}
	l, err := a.alerts.ReplaceRoutes(r.Context(), ifMatch, in.Routes, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", l.ETag())
	writeJSON(w, http.StatusOK, routesDoc{Routes: l.Routes})
}

// keep returns the items f accepts, never nil.
func keep[T any](items []T, f func(T) bool) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		if f(it) {
			out = append(out, it)
		}
	}
	return out
}

// ruleWritable checks that a scoped caller may change rule id, and that the replacement selector
// (if any) stays in scope. A caller with an unscoped role skips the lookup.
func (a *alertsAPI) ruleWritable(w http.ResponseWriter, r *http.Request, p auth.Principal, id string, next *alerting.Selector) bool {
	if unrestricted(p, auth.ActionRulesWrite) {
		return true
	}
	cur, err := a.alerts.GetRule(r.Context(), id)
	if err != nil {
		return !a.alertErr(w, r, err)
	}
	if !selectorCovered(p, auth.ActionRulesWrite, a.inv, cur.Selector) {
		scopeDenied(w)
		return false
	}
	if next != nil && !selectorCovered(p, auth.ActionRulesWrite, a.inv, *next) {
		a.fail(w, r, errcode.New(errcode.AuthRBAC002, "rule selector is outside the caller's scope"))
		return false
	}
	return true
}

// silenceInScope finds silence id among the stored silences and checks its selector against p.
func (a *alertsAPI) silenceInScope(r *http.Request, p auth.Principal, id string) bool {
	items, _, err := a.alerts.ListSilences(r.Context(), false, "", 500)
	if err != nil {
		return false
	}
	for _, s := range items {
		if s.ID == id {
			return selectorCovered(p, auth.ActionSilencesWrite, a.inv, s.Selector)
		}
	}
	return false
}
