// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// backupArchive is the file the backup service writes, under .stack/backup on the host.
const backupArchive = "nux-e2e.nuxbak"

// TestAUD2_AuditChainVerifies checks the hash chain after every other scenario has changed state.
// It runs last (this file sorts last), so it covers the enrolments, checks, rules, tags and users
// the earlier scenarios created.
func TestAUD2_AuditChainVerifies(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var verify struct {
		OK      bool   `json:"ok"`
		Entries int64  `json:"entries"`
		Reason  string `json:"reason"`
	}
	if err := s.admin.do(ctx, http.MethodGet, "/api/v1/audit/verify", nil, &verify); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !verify.OK {
		t.Fatalf("audit chain is broken: %s", verify.Reason)
	}
	if verify.Entries == 0 {
		t.Fatalf("audit chain holds no entries after the scenarios ran")
	}
	t.Logf("audit chain verified over %d entries", verify.Entries)
}

// TestNFR6_BackupRestoresOnFreshDataDir stops nuxd, writes an encrypted backup with `nux backup`,
// restores it into an empty volume and serves that volume on its own port. The restored server
// must accept the admin's password, list both hosts and verify its audit chain.
func TestNFR6_BackupRestoresOnFreshDataDir(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		_, _ = s.compose(cleanupCtx, "--profile", "restore", "rm", "-f", "-s", "nuxd-restored")
		if _, err := s.compose(cleanupCtx, "up", "-d", "nuxd"); err != nil {
			t.Errorf("restart nuxd after the backup test: %v", err)
		}
	})

	if _, err := s.compose(ctx, "stop", "-t", "20", "nuxd"); err != nil {
		t.Fatalf("stop nuxd for a consistent backup: %v", err)
	}
	if _, err := s.compose(ctx, "--profile", "backup", "run", "--rm", "-T", "backup"); err != nil {
		t.Fatalf("nux backup: %v", err)
	}
	info, err := os.Stat(filepath.Join(s.env.StackDir, "backup", backupArchive))
	if err != nil || info.Size() == 0 {
		t.Fatalf("backup archive missing or empty: %v", err)
	}

	if _, err := s.compose(ctx, "up", "-d", "--wait", "nuxd"); err != nil {
		t.Fatalf("start nuxd after the backup: %v", err)
	}
	if err := waitForReady(ctx, s.admin, s.env.BaseURL); err != nil {
		t.Fatalf("nuxd after the backup: %v", err)
	}

	if _, err := s.compose(ctx, "--profile", "restore", "run", "--rm", "-T", "restore"); err != nil {
		t.Fatalf("nux restore into a fresh volume: %v", err)
	}
	if _, err := s.compose(ctx, "--profile", "restore", "up", "-d", "nuxd-restored"); err != nil {
		t.Fatalf("start the restored nuxd: %v", err)
	}
	caPath := filepath.Join(s.env.StackDir, "restored-ca.pem")
	if _, err := s.compose(ctx, "--profile", "restore", "cp", "nuxd-restored:/var/lib/nuxd-restored/tls/server.crt", caPath); err != nil {
		t.Fatalf("copy the restored certificate: %v", err)
	}

	restored, err := newAPIClient(s.env.RestoreURL, caPath)
	if err != nil {
		t.Fatalf("restored client: %v", err)
	}
	if err := waitForReady(ctx, restored, s.env.RestoreURL); err != nil {
		t.Fatalf("restored nuxd: %v", err)
	}
	if err := restored.login(ctx, s.env.AdminEmail, s.env.AdminPassword); err != nil {
		t.Fatalf("admin cannot sign in to the restored server: %v", err)
	}

	hosts, err := listAll[hostRow](ctx, restored, "/api/v1/hosts")
	if err != nil {
		t.Fatalf("restored server lists hosts: %v", err)
	}
	if findHost(hosts, agentAHostname) == nil || findHost(hosts, agentBHostname) == nil {
		t.Errorf("restored server is missing an enrolled host; it has %d", len(hosts))
	}

	var verify struct {
		OK bool `json:"ok"`
	}
	if err := restored.do(ctx, http.MethodGet, "/api/v1/audit/verify", nil, &verify); err != nil {
		t.Fatalf("restored audit verify: %v", err)
	}
	if !verify.OK {
		t.Errorf("restored audit chain does not verify")
	}
}
