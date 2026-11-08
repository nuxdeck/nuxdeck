// SPDX-License-Identifier: AGPL-3.0-only

// Package api serves nuxd's HTTP surface: the health endpoints today, the REST
// API and embedded UI as they land.
package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/logs"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/statuspages"
	"github.com/nuxdeck/nuxdeck/internal/server/telemetry"
)

// Readiness reports whether a dependency is usable.
type Readiness interface {
	Ping(ctx context.Context) error
}

// Revoker ends an agent's access and closes its stream; *gateway.Gateway implements it.
type Revoker interface {
	Revoke(ctx context.Context, actor gateway.Actor, agentID string) error
}

// Options are the handler's dependencies.
type Options struct {
	Log     *slog.Logger
	Ready   Readiness
	Version string
	// UI is the built web UI; nil serves only the API.
	UI fs.FS
	// Auth enables sign-in and first-run setup; nil serves only health checks and the UI.
	Auth *auth.Service
	// PKI enables enrolment-token creation; it needs Auth. GatewayURL is the https URL agents dial,
	// embedded in every token.
	PKI        *pki.Service
	GatewayURL string
	// Revoker enables agent revocation; it needs Auth.
	Revoker Revoker
	// Inventory serves hosts, containers and the live event stream; it needs Auth.
	Inventory *inventory.Service
	// Logs, with Auth, Inventory and Audit, enables GET /api/v1/logs/stream. LogScope narrows
	// who may read which host's logs (NUX-37); nil allows every viewer.
	Logs     *logs.Broker
	Audit    Auditor
	LogScope LogScope
	// Metrics serves chart queries and the overview ranking; it needs Auth and Inventory.
	Metrics *metrics.Service
	// Checks serves the uptime-check endpoints; it needs Auth.
	Checks *checks.Service
	// Alerting and Channels serve rules, alerts, silences, channels and routes; both are needed, with Auth.
	Alerting *alerting.Service
	Channels *alerting.Channels
	// AuditLog serves audit search, export and chain verification (admin); it needs Auth. When nil,
	// Ready is used if it also implements AuditStore, as *store.Store does.
	AuditLog AuditStore
	// StatusPages serves the public status pages; with Auth it also enables their admin API.
	StatusPages *statuspages.Service
	// Telemetry serves the settings endpoints and the payload preview; it needs Auth.
	Telemetry *telemetry.Service
	// RoleBindings enables the role-binding admin API (ACC-4, ACC-5); it needs Auth.
	RoleBindings RoleBindingStore
	// Accounts enables user management, sessions, API tokens and two-factor; it needs Auth.
	Accounts *auth.Accounts
	// OIDC enables single sign-on and its settings; it needs Auth.
	OIDC *auth.OIDC
}

// Handler returns the full HTTP handler with its middleware.
func Handler(o Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": o.Version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := o.Ready.Ping(ctx); err != nil {
			o.Log.Error("readiness check failed", "request_id", requestID(r.Context()), "error", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if o.Auth != nil {
		a := &authAPI{svc: o.Auth, log: o.Log}
		a.register(mux)
		(&openAPIAPI{authAPI: a}).register(mux)
		if o.Inventory != nil {
			(&inventoryAPI{authAPI: a, inv: o.Inventory}).register(mux)
			if o.Metrics != nil {
				(&metricsAPI{authAPI: a, m: o.Metrics, inv: o.Inventory}).register(mux)
			}
		}
		if o.Inventory != nil && o.Logs != nil && o.Audit != nil { // without an audit sink there is no stream
			(&logsAPI{authAPI: a, inv: o.Inventory, broker: o.Logs, audit: o.Audit, scope: o.LogScope}).register(mux)
		}
		if o.Checks != nil {
			(&checksAPI{authAPI: a, checks: o.Checks}).register(mux)
		}
		if o.StatusPages != nil {
			(&statusPagesAPI{authAPI: a, pages: o.StatusPages}).register(mux)
		}
		if ss, _ := o.Ready.(settingsStore); o.Telemetry != nil && ss != nil {
			(&settingsAPI{authAPI: a, tel: o.Telemetry, store: ss}).register(mux)
		}
		if o.Alerting != nil && o.Channels != nil {
			(&alertsAPI{authAPI: a, alerts: o.Alerting, channels: o.Channels, inv: o.Inventory}).register(mux)
		}
		if as := auditStoreOf(o); as != nil {
			(&auditAPI{authAPI: a, store: as}).register(mux)
		}
		if o.RoleBindings != nil {
			(&roleBindingsAPI{authAPI: a, store: o.RoleBindings}).register(mux)
		}
		if o.Accounts != nil {
			(&accountsAPI{authAPI: a, acc: o.Accounts}).register(mux)
		}
		if o.OIDC != nil {
			(&oidcAPI{authAPI: a, oidc: o.OIDC}).register(mux)
		}
		if o.PKI != nil {
			(&agentsAPI{authAPI: a, pki: o.PKI, gatewayURL: o.GatewayURL, revoker: o.Revoker}).register(mux)
		}
	}

	if o.StatusPages != nil {
		o.StatusPages.RegisterPublic(mux) // anonymous; sets its own stricter CSP over securityHeaders
	}

	var ui http.Handler
	if o.UI != nil {
		ui = newUI(o.UI)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		api := r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
		if ui != nil && !api && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			ui.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusNotFound, errcode.APINF001)
	})

	return recoverer(o.Log, withRequestID(securityHeaders(accessLog(o.Log, mux))))
}

func auditStoreOf(o Options) AuditStore {
	if o.AuditLog != nil {
		return o.AuditLog
	}
	as, _ := o.Ready.(AuditStore)
	return as
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError renders the shared error shape from the code registry; it never
// includes internal detail.
func writeError(w http.ResponseWriter, status int, code errcode.Code) {
	writeErrorDetail(w, status, code, "", "")
}

// writeErrorDetail adds the offending field and a specific hint. The hint must
// come from our own validators, never from user input or internal errors.
func writeErrorDetail(w http.ResponseWriter, status int, code errcode.Code, field, hint string) {
	e, _ := errcode.Lookup(code)
	if hint == "" {
		hint = e.Hint
	}
	body := map[string]string{"code": string(code), "message": e.Message, "hint": hint}
	if field != "" {
		body["field"] = field
	}
	writeJSON(w, status, map[string]any{"error": body})
}
