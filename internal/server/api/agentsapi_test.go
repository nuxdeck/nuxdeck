// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
)

func TestAGT1_CreateTokenNeedsAdminSessionAndCSRF(t *testing.T) {
	e := newAuthEnv(t)
	const path = "/api/v1/agents/tokens"

	if rec := e.do(req{method: "POST", path: path, body: `{}`}); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "AUTH-DENY-003" {
		t.Errorf("anonymous: %d %q", rec.Code, rec.Body)
	}

	signedIn := e.setup()
	cookie, csrf := sessionCookieOf(t, signedIn), csrfOf(t, signedIn)

	if rec := e.do(req{method: "POST", path: path, body: `{}`, cookie: cookie}); rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
		t.Errorf("no CSRF token: %d %q", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "POST", path: path, body: `{}`, cookie: cookie, headers: map[string]string{csrfHeader: csrf, "Sec-Fetch-Site": "cross-site"}}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site: %d %q", rec.Code, rec.Body)
	}

	rec := e.do(req{method: "POST", path: path, body: `{"labels":{"env":"staging"}}`, cookie: cookie, headers: map[string]string{csrfHeader: csrf}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a response holding a secret must not be cached")
	}
	var out struct{ ID, Token, ExpiresAt string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	tok, err := pki.ParseToken(out.Token)
	if err != nil || tok.ServerURL != "https://nux.example.com:8444" {
		t.Errorf("token = %+v, %v", tok, err)
	}
	if strings.Contains(e.logs.String(), tok.Secret) {
		t.Error("the token secret reached the logs")
	}
}

func TestCreateTokenValidation(t *testing.T) {
	e := newAuthEnv(t)
	signedIn := e.setup()
	h := map[string]string{csrfHeader: csrfOf(t, signedIn)}
	for name, body := range map[string]string{
		"negative ttl":  `{"ttl_seconds":-1}`,
		"ttl too long":  `{"ttl_seconds":86401}`,
		"huge ttl":      `{"ttl_seconds":9223372036854775807}`,
		"unknown field": `{"admin":true}`,
		"empty label":   `{"labels":{"":"x"}}`,
	} {
		rec := e.do(req{method: "POST", path: "/api/v1/agents/tokens", body: body, cookie: sessionCookieOf(t, signedIn), headers: h})
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || errCode(t, rec) != "API-VAL-001" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Body)
		}
	}
}

type fakeRevoker struct {
	mu      sync.Mutex
	revoked []string
	actors  []gateway.Actor
}

func (f *fakeRevoker) Revoke(_ context.Context, actor gateway.Actor, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == unknownAgent {
		return gateway.ErrAgentNotFound
	}
	f.revoked = append(f.revoked, id)
	f.actors = append(f.actors, actor)
	return nil
}

const (
	knownAgent   = "01HZ0000000000000000000001"
	unknownAgent = "01HZ0000000000000000000002"
)

func TestAGT4_RevokeEndpoint(t *testing.T) {
	e := newAuthEnv(t)
	path := func(id string) string { return "/api/v1/agents/" + id + "/revoke" }

	if rec := e.do(req{method: "POST", path: path(knownAgent)}); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d %q", rec.Code, rec.Body)
	}
	signedIn := e.setup()
	cookie, csrf := sessionCookieOf(t, signedIn), csrfOf(t, signedIn)
	h := map[string]string{csrfHeader: csrf}

	if rec := e.do(req{method: "POST", path: path(knownAgent), cookie: cookie}); rec.Code != http.StatusForbidden || errCode(t, rec) != "AUTH-DENY-004" {
		t.Errorf("no CSRF token: %d %q", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "POST", path: path("not-an-id"), cookie: cookie, headers: h}); rec.Code != http.StatusNotFound {
		t.Errorf("malformed id: %d %q", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "POST", path: path(unknownAgent), cookie: cookie, headers: h}); rec.Code != http.StatusNotFound || errCode(t, rec) != "API-NF-001" {
		t.Errorf("unknown agent: %d %q", rec.Code, rec.Body)
	}
	if len(e.revoker.revoked) != 0 {
		t.Fatalf("revoked %v before any valid request", e.revoker.revoked)
	}

	rec := e.do(req{method: "POST", path: path(knownAgent), cookie: cookie, headers: h})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %q", rec.Code, rec.Body)
	}
	if len(e.revoker.revoked) != 1 || e.revoker.revoked[0] != knownAgent || e.revoker.actors[0].UserID == "" {
		t.Errorf("revoker saw %v by %v", e.revoker.revoked, e.revoker.actors)
	}
}
