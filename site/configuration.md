---
title: Configuration reference
description: Every nuxd configuration key and environment variable, with defaults and limits.
weight: 140
---

nuxd reads settings in three layers: built-in defaults, then a YAML file, then `NUXD_*` environment variables. Environment variables win.

The file is `/etc/nuxd/nuxd.yaml` unless you pass `--config FILE` or set `NUXD_CONFIG`. A file named explicitly and missing is an error; the default path is optional. Unknown YAML keys are rejected, and invalid values stop nuxd at start with `SRV-CFG-002`.

The master key is never a setting. See [Install](install.md#master-key-back-it-up).

## Keys

| Key                                  | Environment variable                      | Default                            | Limits and notes                                                                                                                                                      |
| ------------------------------------ | ----------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data_dir`                           | `NUXD_DATA_DIR`                           | `/var/lib/nuxd`                    | Absolute path                                                                                                                                                         |
| `log.level`                          | `NUXD_LOG_LEVEL`                          | `info`                             | `debug`, `info`, `warn`, `error`                                                                                                                                      |
| `http.https_addr`                    | `NUXD_HTTPS_ADDR`                         | `:8443`                            | UI and API. `host:port`.                                                                                                                                              |
| `http.redirect_addr`                 | `NUXD_REDIRECT_ADDR`                      | `:8080`                            | Redirects plain HTTP to HTTPS. `host:port`.                                                                                                                           |
| `tls.cert_file`                      | `NUXD_TLS_CERT_FILE`                      | empty                              | Set together with `tls.key_file`                                                                                                                                      |
| `tls.key_file`                       | `NUXD_TLS_KEY_FILE`                       | empty                              | Set together with `tls.cert_file`. Without both, nuxd generates and renews a self-signed certificate in the data directory.                                           |
| `tls.hostnames`                      | `NUXD_TLS_HOSTNAMES`                      | empty                              | Bare host names or IPs for the self-signed certificate. The variable is a comma-separated list and replaces the file's list. The machine's host name is always added. |
| `gateway.addr`                       | `NUXD_GATEWAY_ADDR`                       | `:8444`                            | Agent gateway (mutual TLS). `host:port`.                                                                                                                              |
| `gateway.public_url`                 | `NUXD_GATEWAY_PUBLIC_URL`                 | `https://<host name>:8444`         | `https://` URL with no path; embedded in enrolment tokens                                                                                                             |
| `server.public_url`                  | `NUXD_PUBLIC_URL`                         | `https://<host name>:<https port>` | `https://` URL with no path, user info, query or fragment. Used for alert deep links and single sign-on redirects.                                                    |
| `metrics.retention_days`             | `NUXD_METRICS_RETENTION_DAYS`             | `15`                               | 1 to 3650                                                                                                                                                             |
| `metrics.downsampled_retention_days` | `NUXD_METRICS_DOWNSAMPLED_RETENTION_DAYS` | `90`                               | At least `retention_days`; at most 3650                                                                                                                               |
| `secrets.master_key_file`            | `NUXD_MASTER_KEY_FILE`                    | `<data_dir>/master.key`            | Absolute path, mode 0600. Not allowed together with `NUXD_MASTER_KEY`.                                                                                                |
| `checks.block_private`               | `NUXD_CHECKS_BLOCK_PRIVATE`               | `false`                            | `true` or `false`. When true, no check may set `allow_private`.                                                                                                       |
| `checks.max_concurrent`              | (none)                                    | `0` (means 32)                     | 0 to 1024                                                                                                                                                             |
| `alerting.repeat_interval_minutes`   | (none)                                    | `240`                              | 0 (off) to 10080                                                                                                                                                      |
| `alerting.queue_size`                | (none)                                    | `256`                              | 1 to 100000. A full queue drops new notifications.                                                                                                                    |
| `alerting.workers`                   | (none)                                    | `4`                                | 1 to 64                                                                                                                                                               |
| `backup.pre_upgrade_keep`            | (none)                                    | `3`                                | 0 (off) to 100                                                                                                                                                        |

Environment variables not in the table: `NUXD_CONFIG` (path to the file) and `NUXD_MASTER_KEY` (base64 master key, 32 bytes).

## Environment only

| Variable             | Meaning                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------- |
| `NUXD_MASTER_KEY`    | Master key, base64 of 32 random bytes. Refused together with `secrets.master_key_file`.   |
| `NUX_TELEMETRY`      | `off` locks telemetry off (any other value has no effect). See [Telemetry](telemetry.md). |
| `NUX_INSTALL_METHOD` | Free-text install method reported in telemetry (for example `container`).                 |

## Example

```yaml
data_dir: /var/lib/nuxd
http:
  https_addr: ":8443"
  redirect_addr: ":8080"
tls:
  cert_file: /etc/nuxd/tls/fullchain.pem
  key_file: /etc/nuxd/tls/privkey.pem
server:
  public_url: https://nux.example.com:8443
gateway:
  public_url: https://nux.example.com:8444
metrics:
  retention_days: 30
  downsampled_retention_days: 365
checks:
  block_private: false
alerting:
  repeat_interval_minutes: 120
backup:
  pre_upgrade_keep: 5
```

Restart nuxd after changes: `sudo systemctl restart nuxd`.
