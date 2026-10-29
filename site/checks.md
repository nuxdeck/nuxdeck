---
title: Uptime checks
description: Check types, where checks run, the SSRF guard, and how credentials are stored.
weight: 50
---

A check probes a target on an interval and records each result. Checks drive status pages and the check alerts.

## Types

Each check has one type and one settings object for that type. Other types' objects are rejected.

| Type   | Settings                                                                                                                                                                                                                                     | Defaults and limits                                                                                                                                                |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `http` | `url` (max 2048 characters), `method` (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS), `headers` (up to 20, value max 1024), `body` (max 4096), expected status, keyword and JSON conditions, `verify_tls`, `max_redirects`, `max_body_bytes` | Method GET. `verify_tls` true. Redirects 5 (max 10). Body read limit 64 KiB (max 1 MiB). Forbidden headers include `Host`, `Content-Length` and `X-Forwarded-For`. |
| `tcp`  | host and port                                                                                                                                                                                                                                | Connect only.                                                                                                                                                      |
| `dns`  | name, `record_type` (A, AAAA, CNAME, TXT, MX), `expected` (up to 10 values)                                                                                                                                                                  |                                                                                                                                                                    |
| `tls`  | host, `port`, `warn_days`, `verify_chain`                                                                                                                                                                                                    | Port 443. Warn 14 days before expiry (0 to 365). Chain verified.                                                                                                   |
| `ping` | host, `count`                                                                                                                                                                                                                                | Count 3 (1 to 5). Needs `ping_group_range`, see [Agents](agents.md).                                                                                               |

Every check also has `interval_s` (20 to 86400, default per type), `timeout_s` (1 to 60, below the interval; default the smaller of 10 and interval minus 1), `retries` (0 to 5), `enabled` and `runner`.

## Where a check runs

- `runner: server` (default). nuxd runs the probe.
- `runner: <agent id>`. The agent on that host runs it, from inside that network. If the agent is offline the run fails with `CHK-RUN-001`.

Use an agent runner for internal services. Server runners see only what the server can reach.

## SSRF guard

Probes connect only to addresses the guard allows, and the guard checks the address actually connected to, so DNS rebinding cannot bypass it.

Always blocked, for server and agent runners alike: unspecified, multicast and link-local addresses, `0.0.0.0/8`, `240.0.0.0/4`, cloud metadata endpoints, and anything that is not public unicast. Embedded IPv4 in NAT64 and 6to4 addresses is checked too.

Loopback is blocked for server runners. Agent runners are allowed to reach loopback.

Private ranges (RFC 1918, IPv6 ULA, CGNAT `100.64.0.0/10`) are blocked unless the check has `allow_private: true`. That flag is per check and defaults to false. nuxd refuses it when `checks.block_private` (`NUXD_CHECKS_BLOCK_PRIVATE`) is true. A literal private IP in a server-run check fails validation unless `allow_private` is set, and a server-run check cannot use `allow_private` while `block_private` is on.

A blocked target fails with `CHK-NET-001`.

## Credentials

A check can carry a password, token or header value. Credentials are write-only:

- Set a value with a JSON string. Send `""` to clear it. Omit the field, or send `null`, to keep the stored value.
- Reads return only `{"set": true}` or `{"set": false}`.
- Values are encrypted with the master key (see [Install](install.md#master-key-back-it-up)).

If a stored credential cannot be read, the check fails with `CHK-SEC-001`; save it again with its credentials.

## Running and history

- **Run now** runs a check immediately (`POST /api/v1/checks/{id}/run`). Runs are limited to one every few seconds (`CHK-RUN-004`).
- `GET /api/v1/checks/{id}/results` returns history; `GET /api/v1/checks/{id}/uptime` returns the uptime percentage.
- Concurrent server-side probes are bounded by `checks.max_concurrent` (default 32).

Writes need the operator role and use `ETag` with `If-Match`.
