// SPDX-License-Identifier: AGPL-3.0-only

// Package api serves nuxd's HTTP surface: the health endpoints today, the REST
// API and embedded UI as they land.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Readiness reports whether a dependency is usable.
type Readiness interface {
	Ping(ctx context.Context) error
}

// Options are the handler's dependencies.
type Options struct {
	Log     *slog.Logger
	Ready   Readiness
	Version string
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
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
	})

	return recoverer(o.Log, withRequestID(securityHeaders(accessLog(o.Log, mux))))
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
	e, _ := errcode.Lookup(code)
	writeJSON(w, status, map[string]any{"error": map[string]string{
		"code": string(code), "message": e.Message, "hint": e.Hint,
	}})
}
