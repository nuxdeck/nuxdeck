# test/e2e

End-to-end tests for the v0.1 release gate. They run the real `nuxd` and `nux` binaries in a
Docker Compose stack and drive them through the REST API, the live event stream and the log
stream. The suite is part of NUX-46 (security review and hardening) and its exit checks cover the
M1 to M4 milestone exits and NFR-6.

Licence: Apache-2.0.

## Running it

```sh
make e2e        # stack up, Go scenarios, Playwright suite (if present), stack down
make e2e-up     # start the stack and leave it running, for iteration
make e2e-down   # remove the stack that make e2e-up recorded
```

Requirements: Docker with Compose v2, Go (the version in `go.mod`), and `/var/run/docker.sock`
readable by the user running the target. The stack is Docker only; the Podman job described in
`docs/08-engineering-spec.md` is not part of this suite yet. The Go binaries are compiled on the
host. Base images (`alpine`, `nginx`) are pulled when they are not present, so a first run on a new
machine needs network access.

`make e2e` always tears the stack down, including after a failure or Ctrl-C. Exit status is
non-zero if the stack, a Go scenario or a Playwright test failed.

## What the stack is

`compose.yaml` defines:

| Service                          | Role                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `nuxd`                           | Server: HTTPS API and UI on 127.0.0.1 (default 18443), agent gateway on 18444.                            |
| `agent-a`, `agent-b`             | Two agents, enrolled by the harness. `agent-a` is tagged `env=staging`, `agent-b` `env=production`.     |
| `sockguard-a`, `sockguard-b`     | Each agent's `nux sockguard` sidecar, the only process that mounts the Docker socket.                     |
| `nginx`                          | A web server with a healthcheck; its access log is the log-tail source. Tagged `env=production`.          |
| `failing`                        | A deliberately failing service: its healthcheck never passes and the alert scenario stops and starts it. Tagged `env=staging`. |
| `backup`, `restore`, `nuxd-restored` | Profile-gated services for the NFR-6 backup and restore check.                                      |

Isolation: the stack has a random project name (`nux-e2e-<hex>`), no service sets `container_name`,
every host port is bound to 127.0.0.1 and is above 1024, and the ports are the first free ones from
their defaults, so an existing nuxd on 18443 does not block the run. The harness only ever calls
Compose with its own project name. It does not touch containers or volumes it did not create.

**Limitation.** The two agents share the host's Docker daemon, so each one reports every container
on the host, including the operator's own. Each container therefore has one inventory record per
host. The harness tags every record of `nginx` and `failing`, and the scoped-viewer scenario relies
on those tags. The sidecars mount the socket read-only and sockguard only allows GET requests, so
the stack reads the other containers' metadata but never changes them.

## What the Go scenarios cover

Scenarios are named after requirement IDs where practical. They share one bootstrapped stack
(`bootstrap_test.go`): setup of the admin through the setup token, enrolment of both agents, tagging.

| Test                                               | Requirement           | What it checks                                                                                 |
| -------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------- |
| `TestT1_EnrolmentTokenIsSingleUse`                 | T1 (enrolment)        | A spent token cannot enrol again and creates no host.                                         |
| `TestINV1_InventoryDiscoversHostsAndContainers`    | INV-1                 | Two hosts with OS, kernel, arch, CPUs and memory; nginx and failing listed as running.        |
| `TestAGT7_StoppedAgentMarksHostOffline`            | AGT-7, M1 exit        | Host shows offline within 60 s of its agent stopping, and online again after a restart.       |
| `TestMET1_HostMetricsBecomeQueryable`              | MET-1                 | CPU, memory, filesystem and network series get points.                                        |
| `TestMET2_ContainerMetricsBecomeQueryable`         | MET-2                 | CPU and memory series for nginx get points.                                                    |
| `TestMET4_CollectionIntervalIsFifteenSeconds`      | MET-4                 | Sample gaps stay in the 5 to 60 s range and the median is near 15 s.                           |
| `TestM2_NginxLogTailStartsWithinTwoSeconds`        | LOG-1, M2 exit        | A tail delivers a line within 2 s, both for a replayed line and after a new request.          |
| `TestM3_StoppedServiceAlertsAndResolves`           | ALR-1, ALR-3, M3 exit | Stopping `failing` opens a check-down alert and posts a webhook within 60 s; restart resolves. |
| `TestM3_DefaultSSRFGuardRefusesMetadataAddress`    | UPT-2, SSRF guard     | Checks and webhooks to 169.254.169.254 are refused by default, with or without allow_private. |
| `TestM4_StagingViewerCannotSeeProduction`          | ACC-5, M4 exit        | A viewer scoped to env=staging sees no production host, container, metric, log or event.     |
| `TestAUD2_AuditChainVerifies`                      | AUD-2                 | `GET /api/v1/audit/verify` reports ok after all the scenarios. Runs last.                     |
| `TestNFR6_BackupRestoresOnFreshDataDir`            | NFR-6                 | `nux backup` (encrypted) with nuxd stopped, `nux restore` into an empty volume, restored server signs in, lists both hosts, verifies its chain. Runs last. |

The tests run in file order and not in parallel. `TestAGT7` and `TestNFR6` stop nuxd or an agent
and restart it in `t.Cleanup`. The waits poll with deadlines (`eventually` in `harness_test.go`),
and there are no fixed sleeps except the 3-second quiet window that checks a viewer stream stays
silent.

## Playwright

If `test/e2e/ui/package.json` exists, `make e2e` runs `npm ci && npx playwright test` there after the
Go scenarios. The UI suite is owned separately. It reads the stack from the environment written to
`test/e2e/.stack/env`:

| Variable              | Value                                                  |
| --------------------- | ------------------------------------------------------ |
| `E2E_BASE_URL`        | `https://localhost:<port>`, the nuxd HTTPS address       |
| `E2E_ADMIN_EMAIL`     | Admin account created by the harness                     |
| `E2E_ADMIN_PASSWORD`  | Admin password, generated per run                        |
| `E2E_CA_PEM`          | Path to the server certificate to trust                  |

`make e2e-up` writes that file, so the UI suite can be run against a live stack with
`set -a; . test/e2e/.stack/env; set +a` and then `npx playwright test` in `test/e2e/ui`.

## Files

- `compose.yaml` the stack; `docker/Dockerfile.nuxd` and `docker/Dockerfile.nux` the test-only images.
- `stack-up.sh`, `stack-down.sh`, `run.sh`, `lib.sh` build, start, remove and orchestrate the stack.
- `harness_test.go`, `client_test.go`, `bootstrap_test.go` the test support.
- `*_test.go` the scenarios, each with the `e2e` build tag so `make test` does not run them.
- `.stack/` generated per run and removed by teardown; it holds the environment file, the CA
  certificate, the passphrase for the backup and the backup archive. It is git-ignored.

## Troubleshooting

- A stack from an earlier run is still recorded: `make e2e-down`, then retry.
- Port in use: the harness moves to the next free port. An explicit `E2E_HTTPS_PORT`,
  `E2E_GATEWAY_PORT` or `E2E_RESTORE_PORT` is the starting point for the search.
- Read a container's logs with `docker compose -p <project> -f test/e2e/compose.yaml logs <service>`,
  where `<project>` is in `test/e2e/.stack/project`.
- `/var/run/docker.sock` missing or unreadable: the sidecars cannot start. Check the socket's group
  and your membership of it.
