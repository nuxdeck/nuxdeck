// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"net/http"
	"net/http/httptest"
)

// newLocalServer serves "welcome" and reports the request headers it saw.
func newLocalServer(saw func(map[string]string)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := map[string]string{}
		for k := range r.Header {
			h[k] = r.Header.Get(k)
		}
		saw(h)
		_, _ = w.Write([]byte("welcome"))
	}))
}
