---
title: Agents
description: Enrol a host, run the read-only agent and nux-sockguard, and understand what the agent may do.
weight: 20
---

The agent (`nux agent`) runs on each Linux host. It holds one outbound mutual-TLS stream to nuxd on port 8444 and sends inventory, metrics and check results. It never accepts inbound connections.

## Guarantees

- **Read-only (ADR-010).** No agent code changes a host or a container. It reports facts and runs checks and log reads only.
- **Only nux-sockguard touches the container socket (ADR-011).** The agent talks to `/run/nux/sockguard.sock`. `nux sockguard` forwards only `GET` calls on a fixed allowlist: `/_ping`, `/version`, `/info`, `/containers/json`, `/containers/{id}/json`, `/containers/{id}/logs`, `/containers/{id}/stats` and `/events`. It drops environment variables and host paths, redacts label values whose keys look like secrets, and refuses everything else with `SKG-DENY-001`.
- **Certificates are per agent.** Each agent makes its own ECDSA P-256 key. Certificates are valid for 24 hours and renewed about 16 hours after issue. Revoking an agent puts its certificate on a deny list checked on every connection.
- **The server is pinned.** The enrolment token carries the CA fingerprint, so the agent trusts only the nuxd it was given.

## Enrol a host

1. In the UI, go to **Inventory**, choose **Add host**, and create a token. Tokens are single use and expire after one hour. The UI shows the token once.
2. On the host, run the installer with the token (it verifies signatures as for the server):

   ```sh
   curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token TOKEN
   ```

   The installer installs `nux` and `nux-sockguard` with their systemd units (`nux-agent.service`, `nux-sockguard.service`). It reads `NUX_ENROLL_TOKEN` if `--token` is not given.

3. Or enrol by hand:

   ```sh
   sudo nux agent enroll --token-file /root/enrol.token   # or --token, or NUX_ENROLL_TOKEN
   sudo systemctl enable --now nux-sockguard nux-agent
   ```

   `nux agent enroll` takes `--token VALUE`, `--token-file FILE` (`-` reads stdin, up to 4 KiB), `--force` (replace an existing identity) and `--state-dir DIR` (default `/var/lib/nux-agent`, or `NUX_STATE_DIR`). The token is tried in this order: `--token`, `--token-file`, `NUX_ENROLL_TOKEN`. The gateway address comes from the token, so there is no server flag. Avoid `--token` on shared hosts, since arguments are visible in the process list.

Re-enrolling a host that already has an identity fails with `AGT-ENR-001` unless you pass `--force`.

## Prerequisites

- Docker or Podman running on the host, if you want container inventory, logs and container metrics. Podman is supported alongside Docker. Sockguard finds the socket at `/run/podman/podman.sock`, then `/var/run/docker.sock`, then `$XDG_RUNTIME_DIR/podman/podman.sock`, or you can pass `--upstream`.
- cgroups v2 mounted at `/sys/fs/cgroup` for container metrics.
- The `nux` group for the agent user, so it can reach the sockguard socket (mode 0660, owner `nux-sg:nux`).
- `journalctl` installed, and the agent user in the `systemd-journal` group, for journal logs.
- **ICMP checks:** an unprivileged ping needs the runner's group in `net.ipv4.ping_group_range`. Without it, ping checks fail with `CHK-PING-002`. Add a line such as `net.ipv4.ping_group_range = 0 2147483647` in `/etc/sysctl.d/` and run `sysctl --system`, or run ping checks from a server-side runner instead.

## Agent commands

| Command            | Use                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------- |
| `nux agent enroll` | Enrol this host (run once)                                                          |
| `nux agent run`    | Run the agent (`--state-dir`, `--sockguard-socket`). Used by the unit, not by hand. |
| `nux sockguard`    | Run the read-only proxy (`--socket`, `--upstream`, `--group`). Used by the unit.    |

`nux agent run` exits with status 78 when its identity is revoked or unusable (`AGT-REV-001`, `AGT-ID-001`, `AGT-ID-002`). The unit does not restart on that status, so the host stays out until you enrol again with `nux agent enroll --force`.

## Revoke a host

Revoke the agent from its host page or with `nux agents revoke ID` (see [CLI](cli.md)). The agent disconnects with `AGT-REV-001` and does not reconnect until re-enrolled.

## Troubleshooting

See [Troubleshooting](troubleshooting.md). Start with `journalctl -u nux-agent -f` and `nux sockguard --help`.
