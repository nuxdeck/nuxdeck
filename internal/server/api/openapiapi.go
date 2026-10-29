// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	openapi "github.com/nuxdeck/nuxdeck/api"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
)

// openAPIAPI serves the API description that the CLI and the UI clients are generated from (CLI-1).
type openAPIAPI struct {
	*authAPI
}

func (a *openAPIAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/openapi.yaml", a.document)
}

// document serves the embedded description. Any signed-in viewer may read it: it names routes and
// schemas but holds no data.
func (a *openAPIAPI) document(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionAPISpecRead); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapi.Document)
}
