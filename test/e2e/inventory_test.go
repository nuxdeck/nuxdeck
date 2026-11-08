// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"
)

// hostFacts are the host fields INV-1 requires the agent to report.
type hostFacts struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Kernel      string `json:"kernel"`
	Arch        string `json:"arch"`
	CPUCount    int    `json:"cpu_count"`
	MemoryBytes int64  `json:"memory_bytes"`
}

// TestINV1_InventoryDiscoversHostsAndContainers checks that both agents report their host facts
// and that the inventory lists the nginx and failing containers as running.
func TestINV1_InventoryDiscoversHostsAndContainers(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	hosts, err := listAll[hostFacts](ctx, s.admin, "/api/v1/hosts")
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h.Hostname != agentAHostname && h.Hostname != agentBHostname {
			continue
		}
		seen[h.Hostname] = true
		if h.OS == "" || h.Kernel == "" || h.Arch == "" || h.CPUCount <= 0 || h.MemoryBytes <= 0 {
			t.Errorf("host %s is missing facts: os=%q kernel=%q arch=%q cpus=%d memory=%d",
				h.Hostname, h.OS, h.Kernel, h.Arch, h.CPUCount, h.MemoryBytes)
		}
	}
	for _, name := range []string{agentAHostname, agentBHostname} {
		if !seen[name] {
			t.Errorf("host %s is not in the inventory", name)
		}
	}

	rows, err := listAll[containerRow](ctx, s.admin, "/api/v1/containers")
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	if !anyRunning(rows, s.nginx) {
		t.Errorf("nginx container is not listed as running on any host")
	}
	if !anyRunning(rows, s.failing) {
		t.Errorf("failing container is not listed as running on any host")
	}
}

// anyRunning reports whether one of the record IDs is listed in the running state.
func anyRunning(rows []containerRow, ids []string) bool {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for _, r := range rows {
		if want[r.ID] && r.State == "running" {
			return true
		}
	}
	return false
}
