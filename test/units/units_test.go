// SPDX-License-Identifier: Apache-2.0

// Package units checks the shipped systemd units against the security requirements.
package units

import (
	"os"
	"strings"
	"testing"
)

func directives(t *testing.T, path string) map[string][]string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // repository file
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(line, "#") {
			out[k] = append(out[k], v)
		}
	}
	return out
}

// AGT-6: the agent runs as a non-root user with no access to the container sockets.
func TestAGT6_AgentUnitIsSandboxed(t *testing.T) {
	d := directives(t, "../../deploy/systemd/nux-agent.service")

	one := func(key string) string {
		if len(d[key]) != 1 {
			t.Fatalf("%s must be set exactly once, found %v", key, d[key])
		}
		return d[key][0]
	}
	if u := one("User"); u == "root" || u == "0" {
		t.Errorf("User = %q, the agent must not run as root", u)
	}
	for key, want := range map[string]string{
		"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "MemoryDenyWriteExecute": "yes",
	} {
		if got := one(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if caps := d["CapabilityBoundingSet"]; len(caps) != 1 || caps[0] != "" {
		t.Errorf("CapabilityBoundingSet = %q, want empty (no capabilities)", caps)
	}
	if one("RestartPreventExitStatus") != "78" {
		t.Error("exit status 78 (revoked, bad identity) must stop restarts")
	}

	for _, key := range []string{"SupplementaryGroups", "Group"} {
		for _, v := range d[key] {
			for _, banned := range []string{"docker", "podman", "root", "wheel", "sudo"} {
				if strings.Contains(v, banned) {
					t.Errorf("%s=%s gives the agent access it must not have", key, v)
				}
			}
		}
	}
	for _, v := range d["ReadWritePaths"] {
		if strings.Contains(v, "sock") {
			t.Errorf("ReadWritePaths=%s exposes a socket to the agent", v)
		}
	}
}

// ADR-011: the process that holds the container socket has no network and no capabilities.
func TestAGT6_SockguardUnitHasNoNetworkAndNoPrivileges(t *testing.T) {
	d := directives(t, "../../deploy/systemd/nux-sockguard.service")

	one := func(key string) string {
		if len(d[key]) != 1 {
			t.Fatalf("%s must be set exactly once, found %v", key, d[key])
		}
		return d[key][0]
	}
	for key, want := range map[string]string{
		"User": "nux-sg", "Group": "nux", "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX",
		"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "MemoryMax": "64M",
		"RuntimeDirectory": "nux", "MemoryDenyWriteExecute": "yes",
	} {
		if got := one(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if caps := d["CapabilityBoundingSet"]; len(caps) != 1 || caps[0] != "" {
		t.Errorf("CapabilityBoundingSet = %q, want empty", caps)
	}
	if !strings.Contains(strings.Join(d["SystemCallFilter"], " "), "@system-service") {
		t.Errorf("SystemCallFilter = %v, want @system-service", d["SystemCallFilter"])
	}
	if !strings.Contains(one("ExecStart"), "sockguard") {
		t.Errorf("ExecStart = %q", one("ExecStart"))
	}
}
