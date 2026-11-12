// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The spec keeps nux-sockguard small enough to audit and free of third-party code.
func TestSourceStaysSmallAndStandardLibraryOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // package source
		if err != nil {
			t.Fatal(err)
		}
		lines += strings.Count(string(b), "\n")

		parsed, err := parser.ParseFile(token.NewFileSet(), f, b, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(path, "/")
			stdlib := !strings.Contains(first, ".")
			if !stdlib && path != "github.com/nuxdeck/nuxdeck/internal/errcode" {
				t.Errorf("%s imports %s: sockguard may use only the standard library and the error-code registry", f, path)
			}
		}
	}
	if lines > 1000 {
		t.Errorf("sockguard is %d lines, the spec keeps it under about 1,000", lines)
	}
	t.Logf("%d lines", lines)
}
