# Nux Deck

A free, open-source, self-hosted operations console for DevOps, SRE and platform engineers. v0.1 covers Linux hosts, Docker and Podman containers, resource metrics, live logs, uptime checks, alerting, status pages, SSO, RBAC and an audit log.

> **Status: pre-alpha.** Sprint 1 is in progress. `nuxd` serves the UI with first-run setup and sign-in; hosts, metrics and checks are not built yet.

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

## Development

| Command      | Does                                |
| ------------ | ----------------------------------- |
| `make lint`  | golangci-lint                       |
| `make test`  | `go test -race ./...`               |
| `make build` | builds `nuxd` and `nux` into `bin/` |

`make dev-agent`, `api` and `e2e` exit with an error naming the backlog item that will implement them.

## Try nuxd

```
make build
NUXD_DATA_DIR=$PWD/data NUXD_HTTPS_ADDR=127.0.0.1:8443 NUXD_REDIRECT_ADDR=127.0.0.1:8080 bin/nuxd
curl -k https://localhost:8443/healthz
```

Open <https://localhost:8443> in a browser (accept the self-signed certificate). The first visit shows setup: run `bin/nuxd setup-token` (with the same `NUXD_*` settings) and enter its output to create the administrator. The token is a 0600 file in the data directory and is never logged; in a container use `docker exec <name> nuxd setup-token`.

## Install on a Linux host

```
curl -fsSL https://get.nuxdeck.com | sudo sh
```

The script (`deploy/install/install.sh`) downloads the release, verifies the cosign signature and the checksum, and only then installs `nuxd` and a sandboxed systemd unit. Nothing is installed if either check fails. Pin a release with `--version v0.1.0-alpha.1`.

First start creates the data directory (mode 0700), `nux.db` and a self-signed certificate. Settings layer in this order: built-in defaults, the YAML file (`--config`, default `/etc/nuxd/nuxd.yaml`), then `NUXD_*` environment variables (`NUXD_DATA_DIR`, `NUXD_LOG_LEVEL`, `NUXD_HTTPS_ADDR`, `NUXD_REDIRECT_ADDR`, `NUXD_TLS_CERT_FILE`, `NUXD_TLS_KEY_FILE`, `NUXD_TLS_HOSTNAMES`, `NUXD_GATEWAY_PUBLIC_URL`). First start also creates the agent CA in `pki/` (`ca.key` mode 0600); `NUXD_GATEWAY_PUBLIC_URL` is the https address agents dial, embedded in enrolment tokens (default `https://<hostname>:8444`). In a container the data directory must be a named volume or a directory owned by uid 65532. The HTTP-to-HTTPS redirect assumes the HTTPS port is published unchanged (`-p 8443:8443`).

## Project

- [Roadmap](docs/07-roadmap.md) · [Architecture](docs/03-architecture.md) · [Security](docs/04-security.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md)
