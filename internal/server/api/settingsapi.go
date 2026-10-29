// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/telemetry"
)

// The settings the API accepts. Each key has its own typed handling, never a free-form key/value
// store, so adding one means adding a case to put and a field to view.
const (
	keyTelemetryEnabled = "telemetry.enabled"
	keyPublicURL        = "server.public_url"
	keySetupCompleted   = "setup.completed"
)

// maxPublicURLBytes bounds the stored address; agents embed it in every enrolment token.
const maxPublicURLBytes = 2048

// settingsStore reads and writes the UI-editable settings table; *store.Store implements it.
type settingsStore interface {
	Setting(ctx context.Context, key string) (valueJSON string, ok bool, err error)
	SetSetting(ctx context.Context, key, valueJSON, actorID string, ev audit.Event) error
}

type settingsAPI struct {
	*authAPI
	tel   *telemetry.Service
	store settingsStore
}

func (a *settingsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/settings", a.get)
	mux.HandleFunc("PUT /api/v1/settings", a.put)
	mux.HandleFunc("GET /api/v1/telemetry/preview", a.preview)
}

func (a *settingsAPI) get(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionSettingsRead); !ok {
		return
	}
	view, err := a.view(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// view is the settings document both GET and PUT return.
func (a *settingsAPI) view(ctx context.Context) (map[string]any, error) {
	on, err := a.tel.Enabled(ctx)
	if err != nil {
		return nil, err
	}
	publicURL, err := a.stringSetting(ctx, keyPublicURL)
	if err != nil {
		return nil, err
	}
	completed, err := a.boolSetting(ctx, keySetupCompleted)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		keyTelemetryEnabled: on,
		"telemetry.locked":  a.tel.Locked(),
		keyPublicURL:        publicURL,
		keySetupCompleted:   completed,
	}, nil
}

func (a *settingsAPI) stringSetting(ctx context.Context, key string) (string, error) {
	raw, ok, err := a.store.Setting(ctx, key)
	if err != nil || !ok {
		return "", err
	}
	var s string
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return "", fmt.Errorf("decode setting %s: %w", key, err)
	}
	return s, nil
}

func (a *settingsAPI) boolSetting(ctx context.Context, key string) (bool, error) {
	raw, ok, err := a.store.Setting(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	var b bool
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return false, fmt.Errorf("decode setting %s: %w", key, err)
	}
	return b, nil
}

func (a *settingsAPI) put(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := a.begin(w, r, auth.ActionSettingsWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	var body struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "settings.update", TargetType: "setting", TargetID: body.Key,
		IP: clientOf(r).IP, Result: audit.ResultSuccess,
	}
	switch body.Key {
	case keyTelemetryEnabled:
		a.putTelemetry(w, r, body.Value, ev)
	case keyPublicURL:
		a.putPublicURL(w, r, body.Value, ev)
	case keySetupCompleted:
		a.putBool(w, r, body.Value, ev)
	default:
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "key", "Use telemetry.enabled, server.public_url or setup.completed.")
	}
}

func (a *settingsAPI) putTelemetry(w http.ResponseWriter, r *http.Request, raw json.RawMessage, ev audit.Event) {
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err != nil || string(raw) == "null" {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "value", "Send true or false.")
		return
	}
	ev.Details = map[string]any{"key": keyTelemetryEnabled, "value": enabled}
	switch err := a.tel.SetEnabled(r.Context(), enabled, ev); {
	case errors.Is(err, telemetry.ErrLocked):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "value", "Telemetry is switched off by NUX_TELEMETRY=off on the server.")
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}
	a.respondView(w, r)
}

func (a *settingsAPI) putPublicURL(w http.ResponseWriter, r *http.Request, raw json.RawMessage, ev audit.Event) {
	var address string
	if err := json.Unmarshal(raw, &address); err != nil {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "value", "Send the address as a string.")
		return
	}
	normalized, err := normalizePublicURL(address)
	if err != nil {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "value", err.Error())
		return
	}
	a.save(w, r, keyPublicURL, normalized, ev)
}

func (a *settingsAPI) putBool(w http.ResponseWriter, r *http.Request, raw json.RawMessage, ev audit.Event) {
	var flag bool
	if err := json.Unmarshal(raw, &flag); err != nil || string(raw) == "null" {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "value", "Send true or false.")
		return
	}
	a.save(w, r, keySetupCompleted, flag, ev)
}

// save writes one typed value and its audit entry, then answers with the full settings view.
func (a *settingsAPI) save(w http.ResponseWriter, r *http.Request, key string, value any, ev audit.Event) {
	raw, err := json.Marshal(value)
	if err != nil {
		a.fail(w, r, fmt.Errorf("encode setting %s: %w", key, err))
		return
	}
	ev.TargetID = key
	ev.Details = map[string]any{"key": key, "value": value}
	if err := a.store.SetSetting(r.Context(), key, string(raw), ev.ActorID, ev); err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondView(w, r)
}

func (a *settingsAPI) respondView(w http.ResponseWriter, r *http.Request) {
	view, err := a.view(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// publicURLProblem is shown to the administrator verbatim, so it reads as a sentence rather than a Go error string.
type publicURLProblem string

func (p publicURLProblem) Error() string { return string(p) }

// normalizePublicURL accepts the bare address agents and browsers use to reach this server:
// http or https, a host, and no credentials, path, query or fragment. It returns scheme://host[:port].
func normalizePublicURL(raw string) (string, error) {
	const hint = "Use the address people open in the browser, such as https://nux.example.com:8443."
	if raw == "" || len(raw) > maxPublicURLBytes || strings.ContainsFunc(raw, isControlOrSpace) {
		return "", publicURLProblem(hint)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", publicURLProblem("Use an http or https address with a host name. " + hint)
	}
	if u.User != nil {
		return "", publicURLProblem("Remove the user name and password from the address. Credentials never belong in the URL.")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", publicURLProblem("Use the bare address with no path, query or fragment. " + hint)
	}
	return u.Scheme + "://" + u.Host, nil
}

func isControlOrSpace(r rune) bool {
	return r < 0x20 || r == 0x7f || r == ' '
}

// preview returns the exact bytes the next report would carry.
func (a *settingsAPI) preview(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionTelemetryRead); !ok {
		return
	}
	raw, err := a.tel.Preview(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
