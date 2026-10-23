# Nux Deck

A free, open-source, self-hosted operations console for DevOps, SRE and platform engineers. v0.1 covers Linux hosts, Docker and Podman containers, resource metrics, live logs, uptime checks, alerting, status pages, SSO, RBAC and an audit log.

> **Status: pre-alpha.** The repository is being bootstrapped (Sprint 1). Nothing is installable yet.

It ships as two Go binaries: `nuxd` (server, web UI embedded) and `nux` (agent, CLI and `nux sockguard`). Agents connect outbound to the server over mutual TLS.

## Repository layout

| Path                                | Contents                                  | Licence    |
| ----------------------------------- | ----------------------------------------- | ---------- |
| `cmd/nuxd/`, `internal/server/`     | Server                                    | AGPL-3.0   |
| `web/`                              | Svelte 5 + TypeScript UI                  | AGPL-3.0   |
| `cmd/nux/`, `internal/agent/`       | Agent and CLI                             | Apache-2.0 |
| `proto/`, `pkg/`                    | Agent protocol, generated Go client       | Apache-2.0 |
| `deploy/`, `test/`                  | systemd units, Dockerfiles, e2e tests     | Apache-2.0 |
| `docs/`                             | Planning documents (vision to roadmap)    | see `REUSE.toml` |

Full licence texts are in `LICENSES/`; see [LICENSE](LICENSE) for the split.

## Development

| Command      | Does                                                       |
| ------------ | ---------------------------------------------------------- |
| `make lint`  | golangci-lint                                              |
| `make test`  | `go test -race ./...`                                      |
| `make build` | `go build ./...`                                           |

`make dev`, `dev-agent`, `proto`, `api`, `e2e` and `release-snapshot` exit with an error naming the backlog item that will implement them.

## Project

- [Roadmap](docs/07-roadmap.md) · [Architecture](docs/03-architecture.md) · [Security](docs/04-security.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md)
