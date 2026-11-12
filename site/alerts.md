---
title: Alerts, silences, routes and channels
description: Alert rules, default rules, deduplication, silences and maintenance, notification routes, channel types, and testing.
weight: 60
---

## Rules

A rule has a kind, parameters, a selector (which items it applies to) and a severity (`info`, `warning` or `critical`). An alert opens when the condition holds for `for_s` seconds and resolves when it stops holding.

| Kind                | Parameters                                                                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `check_down`        | `for_s` (default 0)                                                                                                                             |
| `host_offline`      | `for_s` (default 0)                                                                                                                             |
| `container_stopped` | `mode` (`stopped`, `restart_loop`, `either`; default `either`), `restarts` (2 to 100, default 3), `window_s` (60 to 3600, default 600), `for_s` |
| `metric_threshold`  | `target` (host or container), `metric` (`cpu`, `memory`, `disk`; disk is host only), `threshold` (above 0 up to 100), `for_s` (default 300)     |
| `tls_expiring`      | `days` (1 to 825), `for_s`                                                                                                                      |

Unknown fields are rejected. `for_s` may be at most 86400.

### Default rules

On the first start with a host known, nuxd creates these rules. They are ordinary rules: edit or delete them, and a deleted default is not recreated.

| Rule                            | Severity | Condition                            |
| ------------------------------- | -------- | ------------------------------------ |
| Host offline                    | critical | Offline for 60 s                     |
| Container stopped or restarting | warning  | Either mode                          |
| Check down                      | critical | Immediately                          |
| High CPU                        | warning  | Host CPU at or above 90 for 300 s    |
| High memory                     | warning  | Host memory at or above 90 for 300 s |
| High disk usage                 | warning  | Host disk at or above 90 for 600 s   |
| TLS certificate expiring        | warning  | 14 days                              |

## Deduplication and flapping

Each alert has a fingerprint, `rule_id:item_id`, and at most one open alert exists per fingerprint. An alert is `open`, `acked` or `resolved`.

The `for_s` delay is the main protection against flapping. When an alert opens, nuxd also counts resolved alerts with the same fingerprint in the last 30 minutes and reports that count as `flap_count` in the notification. The count is informational; it does not suppress or group alerts (see [Limits](limits.md)).

Acknowledging an alert (`POST /api/v1/alerts/{id}/ack`, operator role) stops reminders for it.

## Reminders

While an alert stays open and unacknowledged, nuxd repeats its notification every `alerting.repeat_interval_minutes` (default 240, 0 to 10080; 0 turns reminders off).

## Silences and maintenance

A silence mutes matching alerts for a time window. A maintenance window is a silence of kind `maintenance`.

- A selector must name at least one tag, item ID, severity or kind.
- A silence lasts at most 30 days, a maintenance window at most 90 days, and it may start at most a year ahead.
- Alerts still open and are recorded while muted; notifications are not sent.
- If an alert opened during a silence is still firing when the silence ends, one "still firing" message is sent.
- A resolution during a silence is not sent.

Create one with the CLI:

```sh
nux silences create --reason "Patch window" --duration 2h --kind maintenance --tag env:staging
nux silences ls --active
nux silences rm ID
```

## Routes

Routes decide which channel receives an alert. They are an ordered list (at most 100). Each route has a selector (tags, item IDs, severities, kinds) and a `channel_id`.

The first matching route sends the alert. A route with `continue` also lets later routes match. An alert that matches no route is recorded but not sent. Edit routes with `GET` and `PUT /api/v1/routes` (admin).

## Channels

Channel types: `smtp`, `slack`, `teams`, `discord`, `telegram` and `webhook`. Unknown config fields are rejected.

| Type                        | Settings                                                                                                                                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `smtp`                      | `host`, `port` (default 587 with STARTTLS, 465 with TLS, 25 with none), `security` (`none`, `starttls` default, `tls`), `username`, `password` (secret), `from`, `to` (1 to 20 addresses). Credentials are refused without TLS. |
| `slack`, `teams`, `discord` | `url` (secret, https only)                                                                                                                                                                                                      |
| `telegram`                  | `bot_token` (secret), `chat_id`                                                                                                                                                                                                 |
| `webhook`                   | Generic webhook settings                                                                                                                                                                                                        |

Secrets are write-only, as for checks.

Channels to private addresses need `allow_private` on the channel. Without it, deliveries to loopback, link-local, metadata or private targets fail with `ALR-SEND-003`. Admins only.

## Notifications and deep links

Each notification links to the item: `{server.public_url}/hosts/{id}`, `/containers/{id}` or `/checks/{id}`. Deep links need `server.public_url` to be set; without it, notifications carry no links.

## Test a channel

Use **Test** in the UI or `POST /api/v1/channels/{id}/test`. Tests are limited to one every 10 seconds per channel (`ALR-SEND-006`). Every test is audited as `channel.test`.

## Delivery failures

Deliveries are queued (`alerting.queue_size`, default 256; a full queue drops new notifications with `ALR-SEND-007`) and sent by `alerting.workers` (default 4). Several failures in a row pause a channel briefly (`ALR-SEND-004`). Alerts are recorded even when delivery fails.

Resolving an alert while its notification is muted does not send a resolution message.
