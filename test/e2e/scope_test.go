// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestM4_StagingViewerCannotSeeProduction is the M4 exit criterion: a Viewer scoped to env=staging
// cannot see production hosts or containers through REST, the live event stream or the log stream.
// The admin's stream is checked too, so a silent stream cannot pass for filtering.
func TestM4_StagingViewerCannotSeeProduction(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	viewer := s.scopedViewer(ctx, t)
	prodContainer := s.nginx[0]
	stagingContainer := s.failing[0]

	t.Run("rest", func(t *testing.T) {
		hosts, err := listAll[hostRow](ctx, viewer, "/api/v1/hosts")
		if err != nil {
			t.Fatalf("viewer lists hosts: %v", err)
		}
		if findHost(hosts, agentAHostname) == nil {
			t.Errorf("viewer cannot see the staging host %s", agentAHostname)
		}
		if findHost(hosts, agentBHostname) != nil {
			t.Errorf("viewer sees the production host %s in the list", agentBHostname)
		}
		if err := viewer.do(ctx, http.MethodGet, "/api/v1/hosts/"+s.hostB, nil, nil); !refusedOrHidden(err) {
			t.Errorf("viewer reads the production host directly: %v", err)
		}

		rows, err := listAll[containerRow](ctx, viewer, "/api/v1/containers")
		if err != nil {
			t.Fatalf("viewer lists containers: %v", err)
		}
		for _, id := range s.nginx {
			if containerListed(rows, id) {
				t.Errorf("viewer sees production container %s in the list", id)
			}
		}
		if !anyListed(rows, s.failing) {
			t.Errorf("viewer cannot see the staging container")
		}
		if err := viewer.do(ctx, http.MethodGet, "/api/v1/containers/"+prodContainer, nil, nil); !refusedOrHidden(err) {
			t.Errorf("viewer reads the production container directly: %v", err)
		}
		now := time.Now()
		if err := viewer.do(ctx, http.MethodGet, "/api/v1/metrics/query?target="+s.hostB+"&metric="+metricHostCPU+
			"&from="+fmt.Sprint(now.Add(-time.Hour).UnixMilli())+"&to="+fmt.Sprint(now.UnixMilli())+"&step=60", nil, nil); !refusedOrHidden(err) {
			t.Errorf("viewer queries production host metrics: %v", err)
		}
	})

	t.Run("logs", func(t *testing.T) {
		conn, err := viewer.dialLogs(ctx, "container:"+prodContainer, 10)
		if err == nil {
			_ = conn.CloseNow()
			t.Fatalf("viewer opened a live tail on the production container")
		}
		if !refusedOrHidden(err) {
			t.Errorf("viewer's log request failed for an unexpected reason: %v", err)
		}
	})

	t.Run("events", func(t *testing.T) {
		adminEvents, err := s.admin.streamEvents(ctx)
		if err != nil {
			t.Fatalf("admin opens events: %v", err)
		}
		viewerEvents, err := viewer.streamEvents(ctx)
		if err != nil {
			t.Fatalf("viewer opens events: %v", err)
		}

		probe := randomToken(t)
		s.setProbeTag(ctx, t, "containers", prodContainer, productionEnv, probe)
		waitForEvent(t, adminEvents, prodContainer, 30*time.Second)

		// Any production event the viewer was going to get would have arrived by now.
		quiet := time.After(3 * time.Second)
		for {
			select {
			case ev, ok := <-viewerEvents:
				if !ok {
					t.Fatalf("viewer's event stream closed")
				}
				if ev.Item.ID == prodContainer || ev.Item.ID == s.hostB {
					t.Fatalf("viewer received a %s event for a production item", ev.Type)
				}
				continue
			case <-quiet:
			}
			break
		}

		s.setProbeTag(ctx, t, "containers", stagingContainer, stagingEnv, probe)
		waitForEvent(t, viewerEvents, stagingContainer, 30*time.Second)
	})
}

// scopedViewer creates a viewer whose only binding is env=staging and returns its own client.
func (s *stack) scopedViewer(ctx context.Context, t testing.TB) *apiClient {
	t.Helper()
	token := randomToken(t)
	email := fmt.Sprintf("viewer-%s@nuxdeck.test", token)
	password := "viewer passphrase " + token + " 2026"
	var acct struct {
		ID string `json:"id"`
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/users", map[string]string{
		"email": email, "name": "Staging Viewer", "password": password, "role": "viewer",
	}, &acct); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	// Creating a user with a role also stores an unscoped binding for it; the bindings union, so
	// that one would give the viewer everything. Remove it, then add the scoped binding.
	var bindings struct {
		Items []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
			Scope   struct {
				Environments []string   `json:"environments"`
				TagSets      [][]string `json:"tag_sets"`
			} `json:"scope"`
		} `json:"items"`
	}
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/role-bindings", nil, &bindings); err != nil {
		t.Fatalf("list role bindings: %v", err)
	}
	for _, b := range bindings.Items {
		if b.Subject == acct.ID && len(b.Scope.Environments) == 0 && len(b.Scope.TagSets) == 0 {
			if err := s.admin.do(ctx, http.MethodDelete, "/api/v1/role-bindings/"+b.ID, nil, nil); err != nil {
				t.Fatalf("remove unscoped viewer binding: %v", err)
			}
		}
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/role-bindings", map[string]any{
		"subject_type": "user", "subject": acct.ID, "role": "viewer",
		"scope": map[string]any{"tag_sets": [][]string{{"env:" + stagingEnv}}},
	}, nil); err != nil {
		t.Fatalf("bind viewer to staging: %v", err)
	}
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/role-bindings", nil, &bindings); err != nil {
		t.Fatalf("list role bindings: %v", err)
	}
	var remaining int
	for _, b := range bindings.Items {
		if b.Subject == acct.ID {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("viewer has %d role bindings, want exactly the staging binding", remaining)
	}
	client, err := newAPIClient(s.env.BaseURL, s.env.CAPEM)
	if err != nil {
		t.Fatalf("viewer client: %v", err)
	}
	if err := client.login(ctx, email, password); err != nil {
		t.Fatalf("viewer login: %v", err)
	}
	return client
}

// setProbeTag changes one item's tags, keeping its env tag, so that the change emits an event.
func (s *stack) setProbeTag(ctx context.Context, t testing.TB, itemType, id, env, probe string) {
	t.Helper()
	if err := s.setTags(ctx, itemType, id, map[string]string{"env": env, "e2e-probe": probe}); err != nil {
		t.Fatalf("tag %s %s: %v", itemType, id, err)
	}
}

// waitForEvent waits until the stream delivers an event for itemID.
func waitForEvent(t testing.TB, events <-chan inventoryEvent, itemID string, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("event stream closed before an event for %s", itemID)
			}
			if ev.Item.ID == itemID {
				return
			}
		case <-deadline:
			t.Fatalf("no event for %s within %s", itemID, within)
		}
	}
}

// refusedOrHidden reports whether err is the API refusing or hiding an item: 403 or 404.
func refusedOrHidden(err error) bool {
	return asAPIError(err, http.StatusForbidden) || asAPIError(err, http.StatusNotFound)
}

func containerListed(rows []containerRow, id string) bool {
	for _, r := range rows {
		if r.ID == id {
			return true
		}
	}
	return false
}

func anyListed(rows []containerRow, ids []string) bool {
	for _, id := range ids {
		if containerListed(rows, id) {
			return true
		}
	}
	return false
}
