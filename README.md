# Nux Deck

A free, open-source, self-hosted operations console for DevOps, SRE and platform engineers. v0.1 covers Linux hosts, Docker and Podman containers, resource metrics, live logs, uptime checks, alerting, status pages, SSO, RBAC and an audit log.

> **Status: alpha.** v0.1 ("See it") is feature complete and covered by unit, integration and end-to-end tests, but it has not run in production yet. Read [Limits and known gaps](site/limits.md) before you rely on it, and test on a non-critical server first.

It ships as two Go binaries: `nuxd` (server, web UI embedded) and `nux` (agent, CLI and `nux sockguard`). Agents connect outbound to the server over mutual TLS.

## Repository layout

| Path                            | Contents                               | Licence          |
| ------------------------------- | -------------------------------------- | ---------------- |
| `cmd/nuxd/`, `internal/server/` | Server                                 | AGPL-3.0         |
| `web/`                          | Svelte 5 + TypeScript UI               | AGPL-3.0         |
| `cmd/nux/`, `internal/agent/`   | Agent and CLI                          | Apache-2.0       |
| `internal/errcode/`             | Error codes shared by server and agent | Apache-2.0       |
| `proto/`, `pkg/`                | Agent protocol, generated Go client    | Apache-2.0       |
| `deploy/`, `test/`              | systemd units, Dockerfiles, e2e tests  | Apache-2.0       |
| `docs/`                         | Planning documents (vision to roadmap) | see `REUSE.toml` |

Full licence texts are in `LICENSES/`; see [LICENSE](LICENSE) for the split.

## Quick look on your own machine

You need Go, Node 24 and pnpm. This runs the server and UI with hot reload, then enrols your own machine as a host:

```sh
make build
NUXD_GATEWAY_PUBLIC_URL=https://localhost:8444 make dev      # UI on http://localhost:5173
```

In another terminal, print the first-run token and finish setup in the browser:

```sh
NUXD_DATA_DIR=$PWD/.dev-data bin/nuxd setup-token
```

Then use **Inventory, Add host** in the UI to create a token and enrol with `nux agent enroll` and `nux agent run` as described in [Agents](site/agents.md). Or run `make e2e-up` for a ready-made stack with two agents, and `make e2e-down` to remove it.

## Development

| Command                  | Does                                                                   |
| ------------------------ | ---------------------------------------------------------------------- |
| `make lint`              | golangci-lint, buf, ESLint, Prettier and `svelte-check`                |
| `make test`              | `go test -race ./...`, the UI tests and the installer script tests     |
| `make build`             | builds the UI, then `nuxd` and `nux` into `bin/`                       |
| `make e2e`               | end-to-end suite on Docker: Go scenarios and Playwright with axe       |
| `make api` / `api-check` | regenerate the REST clients from `api/openapi.yaml`, or check they are |

`make dev-agent` is not implemented yet. The web UI uses pnpm (`web/pnpm-lock.yaml`); see [CONTRIBUTING.md](CONTRIBUTING.md).

## Deploy it

The full walk-through (network, DNS, certificates, reverse proxy, first sign-in, backups, upgrades and a hardening checklist) is the [deployment guide](site/deployment.md). In short:

```sh
curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --version <version>     # server
sudo nuxd setup-token                                                      # first-run token
```

The script (`deploy/install/install.sh`) downloads the release, verifies the cosign signature and the checksum, and only then installs `nuxd` and a sandboxed systemd unit. Nothing is installed if either check fails. You can also run the container image `ghcr.io/nuxdeck/nuxd:<tag>` with a volume on `/var/lib/nuxd` (see [Install](site/install.md)).

Set `server.public_url` and `gateway.public_url` to your real host name in `/etc/nuxd/nuxd.yaml` **before** you enrol hosts, because enrolment tokens carry the gateway address. Open ports 8443 (UI and API) and 8444 (agents). Every setting is in the [configuration reference](site/configuration.md). Back up the master key (`/var/lib/nuxd/master.key`) separately from the database.

## Add a host

In the UI, open **Inventory, Add host**: it creates a single-use token (valid 1 hour), shows the install command with the token in it, and says "Connected: <host>" the moment the agent arrives. The same token can be made with `POST /api/v1/agents/tokens`. On the host, as root:

```sh
curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --version <version> --agent --token 'nuxtok1.…'
```

The installer verifies the release signature and checksum like the server install, creates the `nux` and `nux-sg` system users (only `nux-sg` joins the `docker` group), installs `nux` with the `nux-agent` and `nux-sockguard` units, enrols the host (the token goes in on standard input, never in a process's arguments) and starts both services. Re-running it upgrades the binary and keeps the host's identity. Without the installer, `nux agent enroll --token-file …` followed by `nux agent run` does the same by hand.

The token carries the gateway address and the CA fingerprint, so the agent verifies `nuxd` before it sends the secret. The key is created on the host and never leaves it; the certificate lasts 24 hours and renews itself after 16. The agent only dials out (port 8444). If the agent is revoked, its identity is damaged or its certificate expired while it was offline, it exits with status 78 and systemd does not restart it: run `nux agent enroll --force` with a new token.

Container data comes only through `nux sockguard` (`deploy/systemd/nux-sockguard.service`, user `nux-sg`, the only account in the `docker` group). It listens on `/run/nux/sockguard.sock` (mode 0660, group `nux`), forwards a fixed list of read-only `GET` calls and strips environment variables and mount sources from the answers; the agent itself never opens the Docker or Podman socket. Rootless Podman needs a user unit that v0.1 does not ship yet.

Once connected, the agent reports the host (OS, kernel, CPU, memory, disks, IPs, boot time) and its Docker and Podman containers (image, state, published ports, restarts), then every change as it happens. Without `nux-sockguard` or a container runtime the host is still reported and the heartbeat carries `AGT-COL-001`.

`nuxd` keeps what agents report in SQLite and in an in-memory index. Signed-in users read it with `GET /api/v1/hosts`, `/hosts/{id}`, `/containers` and `/containers/{id}` (cursor pagination: `?limit=&cursor=`; filters `status`, `host_id`, `state`, `include_gone`). `GET /api/v1/events` is a Server-Sent Events stream of changes (`host.created`, `host.updated`, `container.created`, `container.updated`, `container.removed`); it carries changes only, so reload through the lists after connecting and whenever a `resync` event arrives. Containers that disappear are kept, marked gone, and hidden unless `include_gone=true`.

## Project

- [User documentation](site/index.md) · [Deployment guide](site/deployment.md)
- [Roadmap](docs/07-roadmap.md) · [Architecture](docs/03-architecture.md) · [Security](docs/04-security.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md)
