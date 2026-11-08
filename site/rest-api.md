---
title: REST API
description: Authentication, CSRF, ETags, pagination, errors and the live streams.
weight: 110
---

The API lives under `/api/v1`, returns JSON, and is described by the OpenAPI 3.1 document at **`GET /api/v1/openapi.yaml`** (viewer role). Generate clients from that document; `pkg/client` (Go) and the UI types are generated from it.

## Authentication

- **Browser:** sign in with `POST /api/v1/auth/login`. The response sets the `__Host-nux_session` cookie and returns a `csrf_token` in the body.
- **Scripts:** send an API token as `Authorization: Bearer nuxt_...`. Create one under your account. Tokens take precedence over the cookie.

## CSRF

For cookie sessions, every `POST`, `PUT`, `PATCH` and `DELETE` must send:

- the `X-CSRF-Token` header with the token from sign-in, and
- a same-site origin (`Sec-Fetch-Site` and `Origin` must agree).

Bearer requests do not need the header. The sign-in, setup, two-factor and WebSocket endpoints check same-origin only.

## Concurrency: ETag and If-Match

Writes to checks, status pages, rules, channels, item tags and owners honour `ETag` and `If-Match`. Send the ETag from the last `GET` on update:

```http
PUT /api/v1/checks/ID
If-Match: "c4"
```

- A stale ETag returns `412` with `API-PRE-001`.
- A missing `If-Match` on endpoints that require one returns `428` with `API-PRE-002`.

## Pagination

Lists take `limit` (default 50, maximum 500) and `cursor`. The response includes `next_cursor` when more results exist. Pass it back as `cursor`. Cursors are opaque ULIDs.

Lists accept tag selectors, for example `?tag=env:production`.

## Errors

Errors use one shape with RFC 9110 status codes:

```json
{
  "error": {
    "code": "API-VAL-001",
    "message": "...",
    "hint": "...",
    "field": "interval"
  }
}
```

The `code` is listed in the [error code reference](reference/error-codes.md). Send the `X-Request-ID` response header to support when reporting a `API-INT-001` error. Internal details are never returned.

## Streams

- **Server-Sent Events:** `GET /api/v1/events` pushes inventory, check and alert changes, filtered by your scope. A keepalive is sent every 15 seconds. Too many open streams return `API-LIM-001`.
- **Log WebSocket:** `GET /api/v1/logs/stream?target=&tail=&filter=`. Requires an `Upgrade: websocket` request. Tail defaults to 100 lines and at most 10,000. Limits: see [Live logs](metrics-logs.md#live-logs).

## Health

- `GET /healthz` returns `{status, version}`.
- `GET /readyz` checks the database and returns `200`, or `503` when it is unavailable.

Both are unauthenticated and sit outside `/api/v1`.

## Main route groups

| Group         | Paths (under `/api/v1`)                                                                                            |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| Setup         | `setup/status`, `setup/admin`                                                                                      |
| Auth          | `auth/login`, `auth/logout`, `auth/totp/verify`, `auth/oidc/status`, `auth/oidc/start`, `auth/oidc/callback`, `me` |
| Self          | `me/password`, `me/security`, `me/totp/enrol\|confirm\|disable`, `me/sessions`, `me/tokens`                        |
| Users         | `users`, `users/{id}` (PATCH, DELETE), `users/{id}/reset`, `users/{id}/sessions`                                   |
| Role bindings | `role-bindings`, `role-bindings/{id}`                                                                              |
| Settings      | `settings`, `settings/security`, `settings/oidc`, `telemetry/preview`                                              |
| Inventory     | `hosts`, `containers`, `search`, `items/{type}/{id}/tags`, `items/{type}/{id}/owner`                               |
| Metrics       | `metrics/query`, `overview/pressure`                                                                               |
| Checks        | `checks`, `checks/{id}`, `checks/{id}/run`, `checks/{id}/results`, `checks/{id}/uptime`                            |
| Alerting      | `rules`, `alerts`, `alerts/{id}`, `alerts/{id}/ack`, `silences`, `channels`, `channels/{id}/test`, `routes`        |
| Status pages  | `status-pages` and its incidents                                                                                   |
| Agents        | `agents/tokens` (POST), `agents/{id}/revoke` (POST)                                                                |
| Audit         | `audit`, `audit/export`, `audit/verify`                                                                            |
| Streams       | `events` (SSE), `logs/stream` (WebSocket)                                                                          |

Outside `/api/v1`: `/healthz`, `/readyz`, `/status/{slug}` (public status pages).

The OpenAPI document is authoritative for methods, bodies and responses.
