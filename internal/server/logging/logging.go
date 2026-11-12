// SPDX-License-Identifier: AGPL-3.0-only

// Package logging builds the structured JSON logger. Callers must never log
// secrets, tokens, environment variables or request bodies; the handler masks
// them too, as a second line of defence.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveKeys are matched as case-insensitive substrings of attribute keys,
// so "api_key", "Set-Cookie" and "db_password" are all masked.
var sensitiveKeys = []string{"password", "passphrase", "secret", "token", "authorization", "cookie", "key"}

// assignmentRE finds "name=value" and "name: value" pairs inside free text,
// such as an error message that quotes a credential.
var assignmentRE = regexp.MustCompile(`(?i)(` + strings.Join(sensitiveKeys, "|") + `)(\s*[=:]\s*)("[^"]*"|\S+)`)

var bearerRE = regexp.MustCompile(`(?i)bearer\s+\S+`)

// New returns a JSON logger at the named level (debug, info, warn or error).
func New(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l, ReplaceAttr: redact})), nil
}

// redact masks the value of any attribute whose key names a secret, and scrubs
// credentials out of string and error values. Group attributes pass through:
// the handler calls ReplaceAttr for each member, so nested keys are covered.
func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	switch v := a.Value.Any().(type) {
	case error:
		return slog.String(a.Key, scrub(v.Error()))
	case string:
		return slog.String(a.Key, scrub(v))
	}
	return a
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func scrub(text string) string {
	text = assignmentRE.ReplaceAllString(text, "${1}${2}"+redacted)
	return bearerRE.ReplaceAllString(text, "Bearer "+redacted)
}
