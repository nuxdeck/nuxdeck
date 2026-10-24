// SPDX-License-Identifier: AGPL-3.0-only

// Package web embeds the built UI. web/dist holds only a placeholder until the
// UI is built (make web), so the Go build never depends on Node.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built UI with index.html at its root.
func FS() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
