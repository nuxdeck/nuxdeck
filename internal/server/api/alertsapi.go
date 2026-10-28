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
)

// maxAlertBody bounds rule, silence, channel and route documents.
const maxAlertBody = 64 << 10

type alertsAPI struct {
	*authAPI
	alerts   *alerting.Service
	channels *alerting.Channels
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
func (a *alertsAPI) write(w http.ResponseWriter, r *http.Request, action auth.Action, needID bool) (alerting.Actor, string, bool) {
	p, sess, ok := a.begin(w, r, action)
	if !ok {
		return alerting.Actor{}, "", false
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return alerting.Actor{}, "", false
	}
	var id string
	if needID {
		id = r.PathValue("id")
		if !ulid.MatchString(id) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return alerting.Actor{}, "", false
		}
	}
	return alerting.Actor{UserID: p.UserID, IP: clientOf(r).IP}, id, true
}

// read authorises a GET and validates the path ID, if any.
func (a *alertsAPI) read(w http.ResponseWriter, r *http.Request, action auth.Action, needID bool) (string, bool) {
	if _, _, ok := a.begin(w, r, action); !ok {
		return "", false
	}
	if !needID {
		return "", true
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return "", false
	}
	return id, true
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
	if _, ok := a.read(w, r, auth.ActionRulesRead, false); !ok {
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
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) getRule(w http.ResponseWriter, r *http.Request) {
	id, ok := a.read(w, r, auth.ActionRulesRead, true)
	if !ok {
		return
	}
	rule, err := a.alerts.GetRule(r.Context(), id)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", rule.ETag())
	writeJSON(w, http.StatusOK, rule)
}

func (a *alertsAPI) createRule(w http.ResponseWriter, r *http.Request) {
	who, _, ok := a.write(w, r, auth.ActionRulesWrite, false)
	if !ok {
		return
	}
	var in alerting.Rule
	if !a.decodeMax(w, r, &in, maxAlertBody) {
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
	who, id, ok := a.write(w, r, auth.ActionRulesWrite, true)
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
	rule, err := a.alerts.UpdateRule(r.Context(), id, ifMatch, in, who)
	if a.alertErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", rule.ETag())
	writeJSON(w, http.StatusOK, rule)
}

func (a *alertsAPI) deleteRule(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionRulesWrite, true)
	if !ok {
		return
	}
	if a.alertErr(w, r, a.alerts.DeleteRule(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- alerts ----

func (a *alertsAPI) listAlerts(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.read(w, r, auth.ActionAlertsRead, false); !ok {
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
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) getAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := a.read(w, r, auth.ActionAlertsRead, true)
	if !ok {
		return
	}
	al, err := a.alerts.GetAlert(r.Context(), id)
	if a.alertErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, al)
}

func (a *alertsAPI) ack(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionAlertsAck, true)
	if !ok {
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
	if _, ok := a.read(w, r, auth.ActionSilencesRead, false); !ok {
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
	writeJSON(w, http.StatusOK, pageOf(items, next))
}

func (a *alertsAPI) createSilence(w http.ResponseWriter, r *http.Request) {
	who, _, ok := a.write(w, r, auth.ActionSilencesWrite, false)
	if !ok {
		return
	}
	var in alerting.Silence
	if !a.decodeMax(w, r, &in, maxAlertBody) {
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
	who, id, ok := a.write(w, r, auth.ActionSilencesWrite, true)
	if !ok {
		return
	}
	if a.alertErr(w, r, a.alerts.DeleteSilence(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- channels ----

func (a *alertsAPI) listChannels(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.read(w, r, auth.ActionChannelsRead, false); !ok {
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
	id, ok := a.read(w, r, auth.ActionChannelsRead, true)
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
	who, _, ok := a.write(w, r, auth.ActionChannelsWrite, false)
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
	who, id, ok := a.write(w, r, auth.ActionChannelsWrite, true)
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
	who, id, ok := a.write(w, r, auth.ActionChannelsWrite, true)
	if !ok {
		return
	}
	if a.alertErr(w, r, a.channels.Delete(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *alertsAPI) testChannel(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionChannelsTest, true)
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
	if _, ok := a.read(w, r, auth.ActionRoutesRead, false); !ok {
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
	who, _, ok := a.write(w, r, auth.ActionRoutesWrite, false)
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
