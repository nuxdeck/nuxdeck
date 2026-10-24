// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"io/fs"
	"testing"
)

func TestFSIsEmbedded(t *testing.T) {
	fsys, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	// The placeholder keeps the embed valid before the UI is built, and the build keeps it.
	if _, err := fs.Stat(fsys, ".gitkeep"); err != nil {
		t.Errorf("placeholder missing: %v", err)
	}
}
