// SPDX-License-Identifier: AGPL-3.0-only

// Package logging builds the structured JSON logger. Callers must never log
// secrets, tokens, environment variables or request bodies.
package logging

import (
	"fmt"
	"io"
	"log/slog"
)

// New returns a JSON logger at the named level (debug, info, warn or error).
func New(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l})), nil
}
