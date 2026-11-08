// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewWritesJSONAtLevel(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, "warn")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown", "request_id", "abc")

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("output is not one JSON object: %q: %v", buf.String(), err)
	}
	if line["msg"] != "shown" || line["request_id"] != "abc" || line["level"] != "WARN" {
		t.Errorf("unexpected line: %v", line)
	}
}

func TestNewRejectsUnknownLevel(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "loud"); err == nil {
		t.Fatal("expected an error for an unknown level")
	}
}

// Secrets pushed through the logger, by key and inside free text, never reach the output.
func TestRedactionMasksSecretsByKeyAndInText(t *testing.T) {
	//nolint:gosec // G101: fake credentials, the test proves the redactor masks them
	const (
		password   = "hunter2-correct-horse"
		apiToken   = "tok_live_9f8e7d6c"
		bearer     = "eyJhbGciOiJIUzI1NiJ9.payload"
		cookie     = "nux_session=s3cr3tcookie"
		passphrase = "open sesame phrase"
		masterKey  = "bWFzdGVyLWtleS1tYXRlcmlhbA=="
	)
	var buf bytes.Buffer
	log, err := New(&buf, "debug")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("login",
		"Password", password,
		"api_token", apiToken,
		"authorization", "Bearer "+bearer,
		"Set-Cookie", cookie,
		"master_key", masterKey,
		"user", "ada@example.com",
	)
	log.Error("request failed", "error", errors.New(`upstream rejected token=`+apiToken+` and password: `+password))
	log.Info("nested", slog.Group("auth", "passphrase", passphrase, "outcome", "ok"))

	out := buf.String()
	for _, secret := range []string{password, apiToken, bearer, "s3cr3tcookie", passphrase, masterKey} {
		if strings.Contains(out, secret) {
			t.Errorf("log output leaks %q: %s", secret, out)
		}
	}
	for _, want := range []string{"[REDACTED]", "ada@example.com", `"outcome":"ok"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log output lacks %q: %s", want, out)
		}
	}
}
