// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

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
