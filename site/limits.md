---
title: Limits and known gaps
description: What v0.1 does not do yet, and where the build differs from the requirements.
weight: 180
---

Nux Deck v0.1 ("See it") is deliberately small. This page lists the limits you will meet and the places where this build differs from the requirements in `docs/02-requirements.md`. The requirement text is unchanged; the gaps are recorded here so operators are not surprised.

## Scope

- Linux amd64 and arm64 hosts only.
- Docker and Podman containers. Kubernetes is planned for v0.2.
- Agents are read-only. Nux Deck does not start, stop, restart or change containers or hosts.
- One server. There is no high availability and no clustering.
- Design target: about 200 agents per server.

## Known gaps in v0.1 build

| Requirement                                                   | What the build does                                                                                                                                        |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T3: alert when one agent identity connects from two addresses | Not implemented. Agent certificates are valid for 24 hours and can be revoked, but no two-address alert is raised.                                         |
| T4: session binding                                           | Not implemented. Sessions are bound to the cookie only; IP and user agent are recorded but do not invalidate a session. Idle and absolute expiry do apply. |
| T13: per-agent rate limits on agent messages                  | Not implemented. The only gateway rate limit is on enrolment attempts (`GW-RATE-001`). Message size caps and the concurrent log-stream limit do apply.     |
| ALR-7: grouping of flapping alerts                            | Partly implemented. The number of re-openings in 30 minutes is reported as `flap_count` in notifications. Alerts are not grouped or suppressed.            |
| STP-4: custom logo, colours and CNAME per status page         | Not implemented in this build. Status pages have a title, description, components and incidents only.                                                      |
| AUD-4: forwarding audit events to syslog or a webhook         | Not implemented. Use the export and verify endpoints, and back up the database.                                                                            |
| Audit hash chain verified on export                           | The chain is verified at startup, on restore and by `GET /api/v1/audit/verify`. The export itself is not verified.                                         |

## Other limits

- **Passwords.** The common-password list is embedded. There is no live breached-password lookup.
- **Single sign-on.** Only a generic OIDC issuer is supported, configured through the API and not the configuration file. Provider-specific settings for Google, Microsoft or GitHub are not built in.
- **Agent list.** The API has no agent list endpoint. The CLI `agents ls` derives agents from hosts.
- **Status pages.** No `.json` form. Public pages are served at `/status/<slug>`.
- **OpenAPI.** Served at `/api/v1/openapi.yaml` (not `.json`).
- **Metrics endpoint.** nuxd does not expose a Prometheus `/metrics` endpoint in v0.1.
- **`nuxd audit` subcommand.** Not present. Use the API for on-demand verification.
- **Telemetry endpoint.** Fixed in the build; there is no configuration key to change it.
- **Container actions.** None. Nux Deck does not run commands in containers or on hosts.
- **Developer targets.** `make dev-agent` and `make e2e` are placeholders in this build.
- **Enrolment.** `nux agent enroll` takes its gateway address from the token; there is no `--server` flag.
- **Backups.** No scheduling or off-box copy; run `nuxd backup` from cron while nuxd is stopped.
