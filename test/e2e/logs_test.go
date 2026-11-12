// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// logStartBound is the M2 exit criterion and LOG-1: a tail starts delivering lines within 2 seconds.
const logStartBound = 2 * time.Second

// TestM2_NginxLogTailStartsWithinTwoSeconds opens a live tail on the nginx container, first with
// a request already in the log, then with a request made after the tail is open.
func TestM2_NginxLogTailStartsWithinTwoSeconds(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := "container:" + s.nginx[0]

	before := randomToken(t)
	s.probeNginx(ctx, t, before)

	conn, err := s.admin.dialLogs(ctx, target, 50)
	if err != nil {
		t.Fatalf("open log tail: %v", err)
	}
	defer func() { _ = conn.CloseNow() }()

	start := time.Now()
	first, cancelFirst := context.WithTimeout(ctx, logStartBound)
	found, err := readLogLines(first, conn, before)
	cancelFirst()
	if err != nil || !found {
		t.Fatalf("tail did not deliver the replayed request line within %s: found=%t err=%v", logStartBound, found, err)
	}
	t.Logf("replayed line arrived %s after the tail opened", time.Since(start))

	after := randomToken(t)
	s.probeNginx(ctx, t, after)
	live, cancelLive := context.WithTimeout(ctx, logStartBound)
	found, err = readLogLines(live, conn, after)
	cancelLive()
	if err != nil || !found {
		t.Fatalf("tail did not deliver a line for a request made after it opened, within %s: found=%t err=%v", logStartBound, found, err)
	}
}

// probeNginx makes one request inside the nginx container, so its access log gets a line with
// the token in the path.
func (s *stack) probeNginx(ctx context.Context, t testing.TB, token string) {
	t.Helper()
	_, err := s.compose(ctx, "exec", "-T", nginxService, "wget", "-q", "-O", "/dev/null",
		fmt.Sprintf("http://127.0.0.1/?probe=%s", token))
	if err != nil {
		t.Fatalf("generate request in nginx: %v", err)
	}
}
