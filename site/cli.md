---
title: Command-line reference
description: Every nux command, its flags, the sign-in files and exit codes.
weight: 100
---

`nux` is the host agent and the command-line client. Run `nux help` for the list of remote commands.

## Global flags

Global flags go **before** the command word:

| Flag            | Default                                                       | Meaning                            |
| --------------- | ------------------------------------------------------------- | ---------------------------------- |
| `--config FILE` | `nux/config.yaml` in the user config directory (`NUX_CONFIG`) | CLI settings file                  |
| `--server URL`  | `https://localhost:8443` (`NUX_SERVER`)                       | nuxd address                       |
| `--log-level`   | `info` (`NUX_LOG_LEVEL`)                                      | `debug`, `info`, `warn` or `error` |

Precedence: flag, then `NUX_*` environment variable, then config file, then default. The config file takes `server` and `log_level` and rejects unknown keys.

Connection flags for remote commands, shown after the command word: `--server`, `--token` (prefer `NUX_TOKEN`), `--ca-file` (`NUX_CA_FILE`), `--pin sha256:HEX`, and `--insecure-skip-verify` (discouraged). Data commands also take `--output table|json` (default `table`). List commands take `--limit` (default 50, 1 to 500) and `--cursor`.

## Sign-in

```sh
nux login --server https://nuxd.example.com:8443 --token-file ~/.config/nux/token
echo "$TOKEN" | nux login --server https://nuxd.example.com:8443 --token-stdin
NUX_TOKEN=... nux login --server https://nuxd.example.com:8443
nux logout
```

`login` takes exactly one token source: `--token-file`, `--token-stdin` or `--token`. Without one, it uses `NUX_TOKEN`. It checks the token with `GET /me` before saving it, and prints the account it signed in as.

The sign-in file is `$XDG_CONFIG_HOME/nux/config.json` (or the user config directory's `nux/config.json`), mode 0600 in a 0700 directory. It stores the server, the token in clear text, the CA file and the pin. It is separate from the `--config` YAML. `nux logout` deletes it; the token stays valid on the server, so revoke it in the UI. Each command warns if this file is readable by others.

### Certificates, pins and first use

- With `--ca-file`, nux trusts that CA.
- With `--pin sha256:...` (64 hex digits, colons optional), nux accepts only the certificate with that SHA-256 fingerprint and skips chain checks.
- If the chain is untrusted and no pin, CA or insecure flag is set, nux shows the certificate fingerprint and asks `Trust this certificate? [y/N]`. Only `y` or `yes` is accepted. An accepted fingerprint is saved as the pin for later commands. Declining exits with `CLI-NET-002`.

Re-run `login` if the certificate was replaced on purpose.

## Remote commands

| Command                                         | Notes                                                                                                                                                           |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hosts ls`                                      | `--status online\|offline`, `--include-gone`, `--tag K[:V]` (repeatable)                                                                                        |
| `hosts get ID`                                  |                                                                                                                                                                 |
| `containers ls`                                 | `--host ID`, `--state S`, `--include-gone`                                                                                                                      |
| `containers get ID`                             |                                                                                                                                                                 |
| `checks ls` / `checks get ID` / `checks run ID` |                                                                                                                                                                 |
| `alerts ls`                                     | `--state open\|acked\|resolved`, `--severity info\|warning\|critical`, `--item-id ID`, `--rule-id ID`                                                           |
| `alerts get ID` / `alerts ack ID`               |                                                                                                                                                                 |
| `silences ls`                                   | `--active`                                                                                                                                                      |
| `silences create`                               | `--reason TEXT` and `--duration D` or `--ends TIME`; optional `--kind silence\|maintenance`, `--starts TIME`, `--id ID`, `--tag T`, `--severity S` (repeatable) |
| `silences rm ID`                                |                                                                                                                                                                 |
| `agents ls`                                     | Agents derived from hosts that reported through them (the API has no agent list)                                                                                |
| `agents token create`                           | `--ttl-seconds N`. Printed once.                                                                                                                                |
| `agents revoke ID`                              |                                                                                                                                                                 |
| `telemetry show`                                | Prints the payload that would be sent. Sends nothing.                                                                                                           |
| `logout`                                        | Removes the sign-in file                                                                                                                                        |

`logs TARGET`:

```sh
nux logs web -f --tail 200 --grep error --since 15m
```

- `TARGET`: a name or ID, `container:ID`, or `journal:HOST:UNIT`. A name matching several items fails with `CLI-ARG-004`.
- `--tail` 0 to 10000 (default 100); `--since` a positive Go duration; `--grep` at most 256 characters.
- Without `-f`, the command exits after about a second of silence.
- With `-f`, it reconnects after 409, 429 or 5xx responses and transport failures, with jittered exponential backoff from 1 s to 30 s. Authentication, permission and not-found refusals stop it at once.
- Ctrl-C exits 0.

`backup` and `restore` run `nuxd` on this host, passing arguments and output through. See [Backup and restore](backup-restore.md).

## Agent and sockguard

| Command            | Flags                                                                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `nux agent enroll` | `--token VALUE`, `--token-file FILE` (`-` is stdin), `--force`, `--state-dir DIR`. Token sources in order: flag, file, `NUX_ENROLL_TOKEN`. |
| `nux agent run`    | `--state-dir DIR`, `--sockguard-socket PATH`                                                                                               |
| `nux sockguard`    | `--socket PATH` (default `/run/nux/sockguard.sock`, mode 0660), `--upstream PATH`, `--group NAME`                                          |

Environment: `NUX_STATE_DIR` (default `/var/lib/nux-agent`), `NUX_SOCKGUARD_SOCKET`, `NUX_ENROLL_TOKEN`, `NUX_NUXD_BIN`, `XDG_RUNTIME_DIR`. Sockguard searches `/run/podman/podman.sock`, `/var/run/docker.sock` and `$XDG_RUNTIME_DIR/podman/podman.sock` when `--upstream` is not given.

## Exit codes

| Code | Meaning                                                                                                                                                   |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Success, help, or Ctrl-C on `logs -f`                                                                                                                     |
| 1    | General failure, including server errors not listed below, transport errors and runtime errors                                                            |
| 2    | Usage errors (`CLI-ARG-001` to `004`) and configuration errors                                                                                            |
| 3    | Not signed in or not allowed (`CLI-AUTH-001`, `AUTH-TOKEN-001`, `AUTH-DENY-001` to `005`, HTTP 401 or 403)                                                |
| 4    | Not found (`API-NF-001`, HTTP 404)                                                                                                                        |
| 78   | `nux agent run` stopped because the identity is revoked or unusable (`AGT-REV-001`, `AGT-ID-001`, `AGT-ID-002`). systemd does not restart on this status. |

`nux backup` and `nux restore` return nuxd's exit code.

Error codes printed by the CLI are listed in the [error code reference](reference/error-codes.md).
