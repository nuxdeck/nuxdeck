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

// offlineBound is the AGT-7 requirement: a host shows offline within 60 seconds of its agent
// disconnecting. The clock starts before the stop command, so the bound is not optimistic.
const offlineBound = 60 * time.Second

// TestAGT7_StoppedAgentMarksHostOffline stops agent-b, requires its host to show offline within
// 60 seconds, then starts the agent again and requires it back online.
func TestAGT7_StoppedAgentMarksHostOffline(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// A failed assertion must not leave agent-b stopped for the scenarios that follow.
	t.Cleanup(func() {
		restartCtx, restartCancel := context.WithTimeout(context.Background(), time.Minute)
		defer restartCancel()
		if _, err := s.compose(restartCtx, "up", "-d", "agent-b"); err != nil {
			t.Errorf("restart agent-b in cleanup: %v", err)
		}
	})

	stoppedAt := time.Now()
	if _, err := s.compose(ctx, "stop", "-t", "10", "agent-b"); err != nil {
		t.Fatalf("stop agent-b: %v", err)
	}
	elapsed := eventually(t, offlineBound, "host "+agentBHostname+" to show offline", func() (bool, string, error) {
		return hostHasStatus(ctx, s, s.hostB, "offline")
	})
	if since := time.Since(stoppedAt); since > offlineBound {
		t.Fatalf("host went offline after %s, over the %s bound", since, offlineBound)
	}
	t.Logf("host %s showed offline %s after its agent stopped", agentBHostname, elapsed)

	if _, err := s.compose(ctx, "start", "agent-b"); err != nil {
		t.Fatalf("start agent-b: %v", err)
	}
	eventually(t, 2*time.Minute, "host "+agentBHostname+" to come back online", func() (bool, string, error) {
		return hostHasStatus(ctx, s, s.hostB, "online")
	})
}

// hostHasStatus reads one host and reports whether its status is want.
func hostHasStatus(ctx context.Context, s *stack, hostID, want string) (bool, string, error) {
	var h hostRow
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/hosts/"+hostID, nil, &h); err != nil {
		return false, "unreadable", err
	}
	return h.Status == want, fmt.Sprintf("status %q", h.Status), nil
}
