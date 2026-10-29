// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// pagePath is relative to this package, which is where go test runs.
const pagePath = "../../reference/error-codes.md"

func TestErrorCodePageIsCurrent(t *testing.T) {
	want := Render(errcode.Entries())
	have, err := os.ReadFile(pagePath)
	if err != nil {
		t.Fatalf("read %s: %v (run: go run ./site/tools/errorcodes)", pagePath, err)
	}
	if !bytes.Equal(have, want) {
		t.Fatalf("%s is stale; run: go run ./site/tools/errorcodes", filepath.Clean(pagePath))
	}
}

func TestRenderListsEveryCodeOnce(t *testing.T) {
	out := string(Render(errcode.Entries()))
	for _, e := range errcode.Entries() {
		row := "| `" + string(e.Code) + "` |"
		if n := strings.Count(out, row); n != 1 {
			t.Errorf("code %s appears %d times, want 1", e.Code, n)
		}
	}
}

func TestRenderEscapesPipes(t *testing.T) {
	got := string(Render([]errcode.Entry{{Code: "SRV-CFG-001", Title: "a|b", Message: "m", Hint: "h"}}))
	if !strings.Contains(got, `a\|b`) {
		t.Errorf("pipe not escaped in table cell: %q", got)
	}
}
