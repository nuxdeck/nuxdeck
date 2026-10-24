# Contributing to Nux Deck

Thanks for helping. Planning documents in `docs/` define what we build; read the ones that touch your change before starting.

There is no CLA and no sign-off requirement. By contributing you agree your work is licensed under the licence of the directory it lands in (see `LICENSES/` and `REUSE.toml`).

## Workflow

- Branches: `nux-<issue>-<short-name>`, merged to `staging` by pull request (see below).
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), for example `feat(agent): add podman socket discovery`.
- Pull requests reference the backlog item and requirement IDs: `Closes NUX-15 · INV-1, INV-2`.
- Run `make lint` and `make test` before opening a pull request.

## What CI checks

Every pull request must pass these jobs (`.github/workflows/ci.yml`) before it can merge:

| Job                 | Checks                                                                                             |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `build-test`        | `go build`, `go vet`, `go test -race` (includes the licence-boundary test)                         |
| `web`               | UI: ESLint, Prettier, `svelte-check`, Vitest with axe, production build and CSP check, `npm audit` |
| `lint`              | golangci-lint: staticcheck, gosec, errcheck, revive, gofumpt                                       |
| `govulncheck`       | Known vulnerabilities in dependencies and the standard library (`make vuln`)                       |
| `semgrep`           | Semgrep static analysis                                                                            |
| `licences`          | `reuse lint` and the dependency licence allowlist (`make licences`)                                |
| `dependency-review` | New dependencies: high-severity advisories and disallowed licences                                 |
| `release-gate`      | Snapshot release build and Trivy scan of both images (critical and high fail)                      |
| `reproducible`      | Two builds of the same commit produce identical binaries                                           |

Branch flow: open pull requests against `staging`. Pull requests into `staging` and `main`, and pushes to `staging`, also run `release-gate` (GoReleaser snapshot build and Trivy scan of the images) and `reproducible` (two builds, identical hashes). `main` changes only by a pull request from `staging` approved by a code owner (`.github/CODEOWNERS`); each merge to `main` publishes the next `v0.1.0-alpha.N` release (ADR-015).

## Licensing rules

<!-- REUSE-IgnoreStart -->

- Every new source file starts with an SPDX header: `// SPDX-License-Identifier: AGPL-3.0-only` for `cmd/nuxd/`, `internal/server/` and `web/`, or `// SPDX-License-Identifier: Apache-2.0` for everything else.

<!-- REUSE-IgnoreEnd -->

- Apache-2.0 code must never import `internal/server/` or `cmd/nuxd/`. `test/boundary` enforces this.
- Each new direct dependency needs a stated reason in the pull request and an AGPL-compatible licence. Prefer the standard library.

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in public issues.
