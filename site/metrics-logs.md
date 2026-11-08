---
title: Metrics and logs
description: Resource charts, retention, and live container and journal logs.
weight: 40
---

## Metrics

Agents send samples regularly: host CPU, memory, disk, and per-container CPU and memory. The server writes them to an embedded Prometheus TSDB in `<data_dir>/tsdb`.

Retention is set in configuration:

| Setting                                                                          | Default | Meaning                                                                  |
| -------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------ |
| `metrics.retention_days` (`NUXD_METRICS_RETENTION_DAYS`)                         | 15      | Full-resolution samples are kept this many days.                         |
| `metrics.downsampled_retention_days` (`NUXD_METRICS_DOWNSAMPLED_RETENTION_DAYS`) | 90      | 5-minute averages are kept this long. Must be at least `retention_days`. |

Both accept 1 to 3650 days. Older data is downsampled into 5-minute averages.

Charts are served by `GET /api/v1/metrics/query` (`target`, `metric`, `from`, `to`, `step`) and drawn with uPlot. `GET /api/v1/overview/pressure` summarises CPU, memory and disk pressure for the overview page.

Telemetry never carries your host metrics; it carries only the schema v1 fields listed in [Telemetry](telemetry.md).

## Live logs

Open a container or a systemd unit from its page and choose **Logs**. The UI streams over a WebSocket at `/api/v1/logs/stream` (`target`, `tail`, `filter`). The server asks the agent for the source and closes the agent stream when the last viewer leaves.

- Container logs come through nux-sockguard (`/containers/{id}/logs`).
- Journal logs need `journalctl` on the host and the agent user in the `systemd-journal` group.
- A tail returns 100 lines by default and at most 10,000.

Limits: a user can hold a limited number of live log streams (`LOG-STR-001`). A slow connection drops lines and says so (`LOG-STR-003`). Narrow the stream with a filter.

## Logs from the CLI

```sh
nux logs web                   # last 100 lines
nux logs web -f                # follow; reconnects with backoff
nux logs web --tail 500 --grep timeout --since 10m
nux logs journal:HOST:nginx.service
nux logs container:3f9a2c
```

`TARGET` is a name or ID, `container:ID`, or `journal:HOST:UNIT`. `--tail` is 0 to 10000, `--since` is a Go duration such as `10m`, and `--grep` is at most 256 characters. Without `-f`, `nux logs` exits after about a second of silence. With `-f`, it reconnects after failures with exponential backoff (1 s to 30 s, jittered). Ctrl-C exits with status 0. See [CLI](cli.md).
