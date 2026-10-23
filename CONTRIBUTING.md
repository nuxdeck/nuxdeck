# Contributing to Nux Deck

Thanks for helping. Planning documents in `docs/` define what we build; read the ones that touch your change before starting.

## Sign off your commits (DCO)

There is no CLA. Every commit must carry a `Signed-off-by` line, which certifies the Developer Certificate of Origin 1.1 below:

```
git commit -s
```

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Workflow

- Branches: `nux-<issue>-<short-name>`; merge to protected `main` by pull request.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), for example `feat(agent): add podman socket discovery`.
- Pull requests reference the backlog item and requirement IDs: `Closes NUX-15 · INV-1, INV-2`.
- Run `make lint` and `make test` before opening a pull request.

## What CI checks

Every pull request must pass these jobs (`.github/workflows/ci.yml`) before it can merge:

| Job                 | Checks                                                                          |
| ------------------- | ------------------------------------------------------------------------------- |
| `build-test`        | `go build`, `go vet`, `go test -race` (includes the licence-boundary test)      |
| `lint`              | golangci-lint: staticcheck, gosec, errcheck, revive, gofumpt                    |
| `govulncheck`       | Known vulnerabilities in dependencies and the standard library (`make vuln`)    |
| `semgrep`           | Semgrep static analysis                                                         |
| `licences`          | `reuse lint` and the dependency licence allowlist (`make licences`)             |
| `dependency-review` | New dependencies: high-severity advisories and disallowed licences              |
| `dco`               | `Signed-off-by` on every commit                                                 |

`main` is protected: changes land only through a pull request that passes these jobs and is approved by a code owner (`.github/CODEOWNERS`).

## Licensing rules

<!-- REUSE-IgnoreStart -->
- Every new source file starts with an SPDX header: `// SPDX-License-Identifier: AGPL-3.0-only` for `cmd/nuxd/`, `internal/server/` and `web/`, or `// SPDX-License-Identifier: Apache-2.0` for everything else.
<!-- REUSE-IgnoreEnd -->
- Apache-2.0 code must never import `internal/server/` or `cmd/nuxd/`. `test/boundary` enforces this.
- Each new direct dependency needs a stated reason in the pull request and an AGPL-compatible licence. Prefer the standard library.

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in public issues.
