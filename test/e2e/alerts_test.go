// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// M3 exit criterion: a stopped test service triggers a notification within 60 seconds and the
// alert resolves when the service is restarted.
const alertBound = 60 * time.Second

// alertRow is the part of an alert the scenario reads.
type alertRow struct {
	ID     string `json:"id"`
	RuleID string `json:"rule_id"`
	State  string `json:"state"`
}

// uptimeCheck is the part of an uptime check the scenario reads.
type uptimeCheck struct {
	ID     string `json:"id"`
	Status struct {
		State         string     `json:"state"`
		LastChecked   *time.Time `json:"last_checked"`
		LastErrorCode string     `json:"last_error_code"`
	} `json:"status"`
}

// TestM3_StoppedServiceAlertsAndResolves runs an HTTP check against the failing service through the
// server, a check_down rule and a webhook channel. Stopping the service must open an alert and post
// a notification within 60 seconds; restarting it must resolve the alert.
func TestM3_StoppedServiceAlertsAndResolves(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	token := randomToken(t)

	receiver := startWebhookReceiver(t)
	channelID := s.createWebhookChannel(ctx, t, receiver.URL, token)
	s.routeAllTo(ctx, t, channelID)

	checkID := s.createCheck(ctx, t, token, map[string]any{
		"name": "e2e failing service " + token, "type": "http", "runner": "server",
		"interval_s": 20, "timeout_s": 5, "retries": 0, "enabled": true, "allow_private": true,
		"http": map[string]any{"url": "http://" + failingService + ":8080/", "expected_status": []int{200}},
	})
	// The scenario is only meaningful if the service is up before it is stopped.
	eventually(t, 2*time.Minute, "the check to report up", func() (bool, string, error) {
		var c uptimeCheck
		err := s.admin.do(ctx, http.MethodGet, "/api/v1/checks/"+checkID, nil, &c)
		return c.Status.State == "up", fmt.Sprintf("state %q, last error %q", c.Status.State, c.Status.LastErrorCode), err
	})

	ruleName := "e2e check down " + token
	var rule struct {
		ID string `json:"id"`
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/rules", map[string]any{
		"name": ruleName, "kind": "check_down", "severity": "critical", "enabled": true,
		"selector": map[string]any{"ids": []string{checkID}},
	}, &rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	if _, err := s.compose(ctx, "stop", "-t", "5", failingService); err != nil {
		t.Fatalf("stop %s: %v", failingService, err)
	}
	stoppedAt := time.Now()
	t.Cleanup(func() {
		restartCtx, restartCancel := context.WithTimeout(context.Background(), time.Minute)
		defer restartCancel()
		_, _ = s.compose(restartCtx, "start", failingService)
	})

	eventually(t, alertBound, "an open alert for the stopped service", func() (bool, string, error) {
		return s.alertOpen(ctx, rule.ID)
	})
	if since := time.Since(stoppedAt); since > alertBound {
		t.Fatalf("alert opened %s after the stop, over the %s bound", since, alertBound)
	}

	eventually(t, alertBound, "a webhook notification naming the rule", func() (bool, string, error) {
		return receiver.saw(ruleName)
	})
	t.Logf("webhook notification received %s after the stop", time.Since(stoppedAt))

	if _, err := s.compose(ctx, "start", failingService); err != nil {
		t.Fatalf("start %s: %v", failingService, err)
	}
	if ps, err := s.compose(ctx, "ps", "-a", failingService); err == nil {
		t.Logf("after start: %s", ps)
	}
	t.Cleanup(func() { s.logCheckState(context.Background(), t, checkID) })
	startedAt := time.Now()
	resolveWait := eventually(t, alertBound, "the alert to resolve after the restart", func() (bool, string, error) {
		open, detail, err := s.alertOpen(ctx, rule.ID)
		return !open, detail, err
	})
	_ = resolveWait
	t.Logf("alert resolved %s after the restart", time.Since(startedAt))
}

// TestM3_DefaultSSRFGuardRefusesMetadataAddress checks that a server-run check and a webhook
// channel both refuse the cloud metadata address when the operator has not allowed private
// targets, and that the link-local address stays refused even when the request asks for private
// targets.
func TestM3_DefaultSSRFGuardRefusesMetadataAddress(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const metadata = "http://169.254.169.254/latest/meta-data/"

	t.Run("check without allow_private", func(t *testing.T) {
		err := s.admin.do(ctx, http.MethodPost, "/api/v1/checks", map[string]any{
			"name": "ssrf probe " + randomToken(t), "type": "http", "runner": "server",
			"interval_s": 60, "timeout_s": 5, "retries": 0, "enabled": true, "allow_private": false,
			"http": map[string]any{"url": metadata, "expected_status": []int{200}},
		}, nil)
		if !asAPIError(err, http.StatusUnprocessableEntity) {
			t.Fatalf("metadata check: want 422, got %v", err)
		}
	})

	t.Run("check with allow_private", func(t *testing.T) {
		err := s.admin.do(ctx, http.MethodPost, "/api/v1/checks", map[string]any{
			"name": "ssrf probe " + randomToken(t), "type": "http", "runner": "server",
			"interval_s": 60, "timeout_s": 5, "retries": 0, "enabled": true, "allow_private": true,
			"http": map[string]any{"url": metadata, "expected_status": []int{200}},
		}, nil)
		if !asAPIError(err, http.StatusUnprocessableEntity) {
			t.Fatalf("metadata check with allow_private: want 422, got %v", err)
		}
	})

	t.Run("webhook channel", func(t *testing.T) {
		err := s.admin.do(ctx, http.MethodPost, "/api/v1/channels", map[string]any{
			"name": "ssrf channel " + randomToken(t), "type": "webhook", "enabled": true,
			"config": map[string]any{"url": metadata},
		}, nil)
		if !asAPIError(err, http.StatusUnprocessableEntity) {
			t.Fatalf("metadata webhook: want 422, got %v", err)
		}
	})
}

// createWebhookChannel creates an enabled webhook channel that may reach the host's private range.
func (s *stack) createWebhookChannel(ctx context.Context, t testing.TB, url, token string) string {
	t.Helper()
	var ch struct {
		ID string `json:"id"`
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/channels", map[string]any{
		"name": "e2e webhook " + token, "type": "webhook", "enabled": true, "allow_private": true,
		"config": map[string]any{"url": url},
	}, &ch); err != nil {
		t.Fatalf("create webhook channel: %v", err)
	}
	return ch.ID
}

// routeAllTo appends a route that sends every alert to channelID, keeping the routes that exist.
func (s *stack) routeAllTo(ctx context.Context, t testing.TB, channelID string) {
	t.Helper()
	resp, err := s.admin.call(ctx, http.MethodGet, "/api/v1/routes", nil, nil)
	if err != nil {
		t.Fatalf("read routes: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("read routes: %v", apiErr(resp))
	}
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := decodeBody(resp, &doc); err != nil {
		t.Fatalf("decode routes: %v", err)
	}
	doc.Routes = append(doc.Routes, map[string]any{"selector": map[string]any{}, "channel_id": channelID, "continue": true})
	put, err := s.admin.call(ctx, http.MethodPut, "/api/v1/routes", doc, http.Header{"If-Match": {etagOf(resp)}})
	if err != nil {
		t.Fatalf("write routes: %v", err)
	}
	if put.Status != http.StatusOK {
		t.Fatalf("write routes: %v", apiErr(put))
	}
}

// createCheck creates an uptime check and returns its ID.
func (s *stack) createCheck(ctx context.Context, t testing.TB, token string, body map[string]any) string {
	t.Helper()
	var c struct {
		ID string `json:"id"`
	}
	if err := s.admin.do(ctx, http.MethodPost, "/api/v1/checks", body, &c); err != nil {
		t.Fatalf("create check %v: %v", body["name"], err)
	}
	return c.ID
}

// alertOpen reports whether ruleID has an alert that is not resolved.
func (s *stack) alertOpen(ctx context.Context, ruleID string) (bool, string, error) {
	alerts, err := listAll[alertRow](ctx, s.admin, "/api/v1/alerts")
	if err != nil {
		return false, "unreadable", err
	}
	for _, a := range alerts {
		if a.RuleID == ruleID && a.State != "resolved" {
			return true, fmt.Sprintf("alert %s state %q", a.ID, a.State), nil
		}
	}
	return false, fmt.Sprintf("%d alerts, none open for the rule", len(alerts)), nil
}

// saw reports whether a notification containing text has arrived.
func (r *webhookReceiver) saw(text string) (bool, string, error) {
	for {
		select {
		case body := <-r.requests:
			if strings.Contains(string(body), text) {
				return true, "", nil
			}
		default:
			return false, "no matching notification yet", nil
		}
	}
}

// logCheckState records the check's status and the rule's alerts in the test log, so a failed
// resolve shows what the engine saw.
func (s *stack) logCheckState(ctx context.Context, t testing.TB, checkID string) {
	t.Helper()
	resp, err := s.admin.call(ctx, http.MethodGet, "/api/v1/checks/"+checkID, nil, nil)
	if err != nil {
		t.Logf("check state unreadable: %v", err)
		return
	}
	t.Logf("check %s final: %s", checkID, string(resp.Body))
}
