// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCLI1_GeneratedClientReadsSetupStatus checks the generated client against a server that answers
// the documented shape of GET /api/v1/setup/status (CLI-1).
func TestCLI1_GeneratedClientReadsSetupStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/setup/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"setup_required":true}`))
	}))
	defer srv.Close()

	c, err := NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rsp, err := c.GetSetupStatusWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rsp.JSON200 == nil || !rsp.JSON200.SetupRequired {
		t.Fatalf("status %d, body %q", rsp.StatusCode(), rsp.Body)
	}
}
