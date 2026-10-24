// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// newUI serves the built single-page UI: hashed assets are cached for a year,
// and any extensionless path falls back to index.html for client-side routing.
// Without index.html (the UI was not built) it answers 503 with a plain note.
func newUI(fsys fs.FS) http.Handler {
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The web UI is not included in this build. Run make build to include it.\n"))
		})
	}

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "index.html" {
			serveIndex(w, r)
			return
		}
		if strings.HasPrefix(path.Base(name), ".") {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return
		}

		if info, err := fs.Stat(fsys, name); err == nil && !info.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			//nolint:gosec // name is cleaned above and fs.FS rejects paths that escape its root
			http.ServeFileFS(w, r, fsys, name)
			return
		}
		if path.Ext(name) != "" {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return
		}
		serveIndex(w, r)
	})
}
