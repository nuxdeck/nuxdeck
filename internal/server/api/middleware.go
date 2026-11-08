// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

type ctxKey struct{}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// withRequestID keeps a well-formed inbound X-Request-ID so traces can span
// services, and otherwise generates one.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach Flush and Hijack for SSE and WebSocket.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog records method, path and status only: never query strings, headers or bodies.
func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("request", "request_id", requestID(r.Context()), "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value, not an error chain
					panic(rec)
				}
				log.Error("handler panic", "request_id", requestID(r.Context()), "panic", rec)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// bearerToken returns the API token from an Authorization: Bearer header. present
// is true whenever the header uses the Bearer scheme, even if the token is empty,
// so a bad token is refused rather than silently falling back to a cookie.
func bearerToken(r *http.Request) (token string, present bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

// reauthenticate looks the caller up again, as begin did, for a long-lived stream. It reads the
// credential from the request, so a bearer token is checked as well as a session cookie.
func (a *authAPI) reauthenticate(ctx context.Context, r *http.Request) (auth.Principal, bool) {
	if token, present := bearerToken(r); present {
		p, err := a.svc.AuthenticateToken(ctx, token)
		return p, err == nil && p.Authenticated()
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return auth.Principal{}, false
	}
	p, _, err := a.svc.Authenticate(ctx, c.Value)
	return p, err == nil && p.Authenticated()
}

// beginToken authenticates an API token. A token request carries no ambient
// credential, so the cross-site checks do not apply: it is given a one-request
// CSRF value that the shared handlers then find in place. It never creates a session.
func (a *authAPI) beginToken(w http.ResponseWriter, r *http.Request, token string) (auth.Principal, *auth.Session, bool) {
	p, err := a.svc.AuthenticateToken(r.Context(), token)
	if err != nil {
		a.fail(w, r, err)
		return p, nil, false
	}
	if !p.Authenticated() {
		a.fail(w, r, errcode.New(errcode.AuthToken001, "token not accepted"))
		return p, nil, false
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	csrf := hex.EncodeToString(b)
	r.Header.Set(csrfHeader, csrf)
	return p, &auth.Session{CSRFToken: csrf}, true
}
