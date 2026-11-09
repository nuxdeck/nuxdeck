// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"
)

// TestT1_EnrolmentTokenIsSingleUse checks that a spent enrolment token cannot enrol a second agent.
// The bootstrap spent agent-b's token; replaying it into a fresh state directory must fail, and
// it must not create a third host.
func TestT1_EnrolmentTokenIsSingleUse(t *testing.T) {
	s := requireStack(t)
	if s.tokenB == "" {
		t.Skip("needs a fresh stack: the enrolment token is only known to the run that bootstrapped it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	before, err := listAll[hostRow](ctx, s.admin, "/api/v1/hosts")
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}

	// A fresh state directory, so the failure can only come from the spent token.
	out, err := s.compose(ctx, "run", "--rm", "-T", "--no-deps",
		"-e", "NUX_ENROLL_TOKEN="+s.tokenB, "-e", "NUX_STATE_DIR=/tmp/replay",
		"agent-b", "agent", "enroll")
	if err == nil {
		t.Fatalf("replaying a spent enrolment token succeeded; output: %s", out)
	}

	after, err := listAll[hostRow](ctx, s.admin, "/api/v1/hosts")
	if err != nil {
		t.Fatalf("list hosts after replay: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("replay changed the host count from %d to %d", len(before), len(after))
	}
}
