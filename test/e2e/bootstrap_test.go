// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	agentAHostname = "e2e-agent-a"
	agentBHostname = "e2e-agent-b"
	nginxService   = "nginx"
	failingService = "failing"
	stagingEnv     = "staging"
	productionEnv  = "production"
	adminName      = "E2E Admin"
)

// stack is the state every scenario starts from: an admin session, both agents enrolled and
// online, and the containers the scenarios watch. Scenarios that change it restore it.
type stack struct {
	env   stackEnv
	admin *apiClient
	// hostA is agent-a, tagged env=staging; hostB is agent-b, tagged env=production.
	hostA, hostB string
	// tokenB is agent-b's enrolment token, already spent; the T1 scenario replays it.
	tokenB string
	// nginx and failing hold every container record for the service. Both agents see the whole
	// Docker daemon they share, so each container has one record per host; all are tagged.
	nginx   []string
	failing []string
}

var (
	stackOnce sync.Once
	stackRef  *stack
	stackErr  error
)

// requireStack bootstraps the stack once for the whole run and fails the calling test if that
// did not work.
func requireStack(t *testing.T) *stack {
	t.Helper()
	stackOnce.Do(func() { stackRef, stackErr = bootstrap() })
	if stackErr != nil {
		t.Fatalf("stack bootstrap: %v", stackErr)
	}
	return stackRef
}

func bootstrap() (*stack, error) {
	env, err := stackEnvFromOS()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	admin, err := newAPIClient(env.BaseURL, env.CAPEM)
	if err != nil {
		return nil, err
	}
	if err := waitForReady(ctx, admin, env.BaseURL); err != nil {
		return nil, fmt.Errorf("nuxd not ready: %w", err)
	}
	s := &stack{env: env, admin: admin}
	required, err := s.setupRequired(ctx)
	if err != nil {
		return nil, err
	}
	if required {
		if err := createAdmin(ctx, env, admin); err != nil {
			return nil, err
		}
		if _, err := s.enrol(ctx, "agent-a"); err != nil {
			return nil, err
		}
		s.tokenB, err = s.enrolToken(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := s.enrolWith(ctx, "agent-b", s.tokenB); err != nil {
			return nil, err
		}
		if _, err := s.compose(ctx, "up", "-d", "agent-a", "agent-b"); err != nil {
			return nil, err
		}
	} else {
		// A stack that is already set up (make e2e-up, then go test) keeps its admin and agents.
		// The single-use token test needs a fresh stack and skips itself here.
		if err := admin.login(ctx, env.AdminEmail, env.AdminPassword); err != nil {
			return nil, fmt.Errorf("reuse existing stack: %w", err)
		}
	}
	if err := s.waitHosts(ctx); err != nil {
		return nil, err
	}
	if err := s.tagInventory(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// setupRequired reports whether first-run setup has not happened yet on this server.
func (s *stack) setupRequired(ctx context.Context) (bool, error) {
	var status struct {
		SetupRequired bool `json:"setup_required"`
	}
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/setup/status", nil, &status); err != nil {
		return false, fmt.Errorf("read setup status: %w", err)
	}
	return status.SetupRequired, nil
}

// waitForReady polls the liveness endpoint until nuxd answers or the context ends.
func waitForReady(ctx context.Context, admin *apiClient, base string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ok, err := httpStatusOK(ctx, admin.http, base+"/healthz")
		if err == nil && ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no healthy answer from %s/healthz: %v", base, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// createAdmin completes first-run setup with the setup token the server printed, the same way an
// operator would, and signs the admin in.
func createAdmin(ctx context.Context, env stackEnv, admin *apiClient) error {
	out, err := env.compose(ctx, "exec", "-T", "nuxd", "nuxd", "setup-token")
	if err != nil {
		return fmt.Errorf("read setup token: %w", err)
	}
	var created struct {
		CSRFToken string `json:"csrf_token"`
	}
	body := map[string]string{
		"token": strings.TrimSpace(out), "name": adminName, "email": env.AdminEmail, "password": env.AdminPassword,
	}
	if err := admin.do(ctx, http.MethodPost, "/api/v1/setup/admin", body, &created); err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	admin.csrf = created.CSRFToken
	return nil
}

// compose runs a Compose command against this stack.
func (s *stack) compose(ctx context.Context, args ...string) (string, error) {
	return s.env.compose(ctx, args...)
}

// enrolToken creates one single-use enrolment token.
func (s *stack) enrolToken(ctx context.Context) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/agents/tokens", map[string]int{"ttl_seconds": 3600}, &out); err != nil {
		return "", fmt.Errorf("create enrolment token: %w", err)
	}
	return out.Token, nil
}

// enrol creates a token and spends it on the named agent service.
func (s *stack) enrol(ctx context.Context, service string) (string, error) {
	tok, err := s.enrolToken(ctx)
	if err != nil {
		return "", err
	}
	return s.enrolWith(ctx, service, tok)
}

// enrolWith runs `nux agent enroll` in a one-off container of the agent service, so the identity
// lands in that agent's state volume. The token travels in the environment of that container.
func (s *stack) enrolWith(ctx context.Context, service, token string) (string, error) {
	out, err := s.compose(ctx, "run", "--rm", "-T", "--no-deps", "-e", "NUX_ENROLL_TOKEN="+token, service, "agent", "enroll")
	if err != nil {
		return "", fmt.Errorf("enrol %s: %w", service, err)
	}
	return out, nil
}

// waitHosts waits until both agents are registered and online, and records their host IDs.
func (s *stack) waitHosts(ctx context.Context) error {
	var lastSeen string
	deadline := time.Now().Add(3 * time.Minute)
	for {
		hosts, err := listAll[hostRow](ctx, s.admin, "/api/v1/hosts")
		if err == nil {
			a, b := findHost(hosts, agentAHostname), findHost(hosts, agentBHostname)
			if a != nil && b != nil && a.Status == "online" && b.Status == "online" {
				s.hostA, s.hostB = a.ID, b.ID
				return nil
			}
			lastSeen = fmt.Sprintf("%d hosts", len(hosts))
		} else {
			lastSeen = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("agents did not come online; last seen: %s", lastSeen)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// tagInventory gives the hosts and the service containers the env tags the scoped-viewer scenario
// depends on. Container records are tagged by service, so every record of one container agrees.
func (s *stack) tagInventory(ctx context.Context) error {
	if err := s.setTags(ctx, "hosts", s.hostA, map[string]string{"env": stagingEnv}); err != nil {
		return err
	}
	if err := s.setTags(ctx, "hosts", s.hostB, map[string]string{"env": productionEnv}); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		nginx, failing, err := s.containerRecords(ctx)
		if err == nil && len(nginx) > 0 && len(failing) > 0 {
			s.nginx, s.failing = nginx, failing
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("containers not in the inventory (nginx %d, failing %d, error %v)", len(nginx), len(failing), err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	for _, id := range s.nginx {
		if err := s.setTags(ctx, "containers", id, map[string]string{"env": productionEnv}); err != nil {
			return err
		}
	}
	for _, id := range s.failing {
		if err := s.setTags(ctx, "containers", id, map[string]string{"env": stagingEnv}); err != nil {
			return err
		}
	}
	return nil
}

// containerRecords returns the inventory IDs of this stack's nginx and failing containers. Names
// carry the compose project, so they cannot match a container the operator runs.
func (s *stack) containerRecords(ctx context.Context) (nginx, failing []string, err error) {
	rows, err := listAll[containerRow](ctx, s.admin, "/api/v1/containers")
	if err != nil {
		return nil, nil, err
	}
	nginxName := s.env.Project + "-" + nginxService + "-1"
	failingName := s.env.Project + "-" + failingService + "-1"
	for _, r := range rows {
		switch strings.TrimPrefix(r.Name, "/") {
		case nginxName:
			nginx = append(nginx, r.ID)
		case failingName:
			failing = append(failing, r.ID)
		}
	}
	return nginx, failing, nil
}

// setTags replaces the tags of one host or container, reading its ETag first.
func (s *stack) setTags(ctx context.Context, itemType, id string, tags map[string]string) error {
	resp, err := s.admin.call(ctx, http.MethodGet, fmt.Sprintf("/api/v1/%s/%s", itemType, id), nil, nil)
	if err != nil {
		return err
	}
	if resp.Status != http.StatusOK {
		return apiErr(resp)
	}
	hdr := http.Header{"If-Match": {etagOf(resp)}}
	put, err := s.admin.call(ctx, http.MethodPut, fmt.Sprintf("/api/v1/items/%s/%s/tags", itemType, id), map[string]any{"tags": tags}, hdr)
	if err != nil {
		return err
	}
	if put.Status != http.StatusOK {
		return fmt.Errorf("tag %s %s: %w", itemType, id, apiErr(put))
	}
	return nil
}

// hostRow and containerRow are the inventory fields the scenarios read.
type hostRow struct {
	ID       string            `json:"id"`
	Hostname string            `json:"hostname"`
	Status   string            `json:"status"`
	Tags     map[string]string `json:"tags"`
}

type containerRow struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	Name   string `json:"name"`
	State  string `json:"state"`
}

func findHost(hosts []hostRow, hostname string) *hostRow {
	for i := range hosts {
		if hosts[i].Hostname == hostname {
			return &hosts[i]
		}
	}
	return nil
}
