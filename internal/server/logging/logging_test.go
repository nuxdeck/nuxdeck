// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"encoding/json"
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
