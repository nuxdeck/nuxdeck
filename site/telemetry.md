---
title: Telemetry
description: Exactly what diagnostic telemetry sends, how to preview it, and how to turn it off.
weight: 150
---

Telemetry is **off by default** and opt-in from **Settings** (admin). It sends a small daily report that helps the project understand installs. It never sends host names, IP addresses, check targets, alert content, logs or metrics.

## What is sent

One report per day, schema version 1. The fields are fixed; no other field is ever added without a new schema version.

| Field                                               | Content                                                                            |
| --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `schema_version`                                    | `1`                                                                                |
| `install_id`                                        | Random ID for this installation; deleted when you turn telemetry off               |
| `report_date`                                       | Day the report covers                                                              |
| `nuxd_version`                                      | Server version                                                                     |
| `release_channel`                                   | Release channel                                                                    |
| `os`, `arch`, `distro_family`                       | Platform                                                                           |
| `install_method`                                    | From `NUX_INSTALL_METHOD`                                                          |
| `storage_backend`                                   | Database backend                                                                   |
| `agents_bucket`, `clusters_bucket`, `checks_bucket` | Count bucket: `0`, `1-5`, `6-20`, `21-100`, `101-500` or `500+`                    |
| `agent_versions`                                    | Map of agent version to count                                                      |
| `features`                                          | Map of feature name to boolean (for example single sign-on enabled)                |
| `notifier_types`                                    | List of channel types in use                                                       |
| `server_memory_mb_p95`                              | Server memory, 95th percentile                                                     |
| `server_uptime_bucket`                              | Uptime bucket                                                                      |
| `restarts_24h`                                      | Restart count in 24 hours                                                          |
| `error_codes_24h`                                   | Map of error code to count. Codes and counts only, never messages or stack traces. |

## Preview

Before you opt in, or at any time, see the exact bytes the next report would carry:

- UI: **Settings**, Telemetry, Preview.
- API: `GET /api/v1/telemetry/preview` (admin). Before opt-in the install ID is a placeholder.
- CLI: `nux telemetry show` prints the payload and sends nothing.

## Schedule and endpoint

One report every 24 hours with up to one hour of jitter. Each report is tried up to three times with a 10-second timeout. Redirects are not followed. The endpoint is `https://telemetry.nuxdeck.com/v1/report`, fixed in the build. A failed report is dropped (`TEL-SEND-001`); there is no retry queue.

## Turn it off

- In **Settings**, switch telemetry off. Turning it off deletes the install ID.
- Lock it off for a whole deployment with the environment variable `NUX_TELEMETRY=off` (case-insensitive). Nothing is sent and the setting cannot be turned on. Any other value has no effect.

Blocking the endpoint at the firewall also stops reports; that only logs `TEL-SEND-001`.
