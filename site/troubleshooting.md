---
title: Troubleshooting
description: Common problems, the error code to look up, and where to look first.
weight: 160
---

Start with the code. Every error shows one (`AREA-CATEGORY-NNN`); look it up in the [error code reference](reference/error-codes.md), which gives the meaning and the next step. Include the code and the `X-Request-ID` response header when you report a problem.

## Where to look

| What          | Where                                                                  |
| ------------- | ---------------------------------------------------------------------- |
| Server log    | `journalctl -u nuxd -f` (JSON lines)                                   |
| Agent log     | `journalctl -u nux-agent -f`                                           |
| Sockguard log | `journalctl -u nux-sockguard -f`                                       |
| Audit chain   | Startup log line `audit chain verified`, or `GET /api/v1/audit/verify` |
| Setup token   | `sudo nuxd setup-token`                                                |

## Common problems

**Browser warns about the certificate.** The first start uses a generated self-signed certificate. Install your own with `tls.cert_file` and `tls.key_file`, or put a reverse proxy in front. Agents pin the CA from the enrolment token, so the agent path is not affected by the browser warning.

**Setup asks for a token and `setup-token` says none exists.** Setup is complete, or nuxd has not started yet. Check `systemctl status nuxd`. Sign in instead.

**nuxd refuses to start with `SRV-SEC-001`.** The master key is missing, malformed or readable by others. Provide the 32-byte base64 key or fix the file mode (0600). See [Install](install.md#master-key-back-it-up).

**nuxd refuses to start with `SRV-SEC-002`.** The database holds secrets sealed with a different key. Restore the original key.

**nuxd does not start after an upgrade with `BAK-UPG-001`.** The pre-upgrade backup could not be written. Free disk space, check permissions on `<data_dir>/backups`, and start again. See [Upgrade](upgrade.md).

**`SRV-CFG-002` at start.** A setting is invalid. The message names it. Check [Configuration](configuration.md) for the allowed range.

**Agent enrolment fails.**

- `AGT-ENR-003`: the token's CA fingerprint does not match. Copy the token again in full, and check for a proxy that intercepts TLS.
- `GW-TOK-001`: the token expired (one hour) or was used. Create a new one.
- `AGT-ENR-001`: the host already has an identity. Use `nux agent enroll --force` with a new token.

**Agent shows offline.** Check `journalctl -u nux-agent`. `GW-STR-004` means heartbeats stopped; check the network path to port 8444. `AGT-REV-001` means the host was revoked; enrol again.

**Container inventory or logs are missing.** `AGT-COL-001` or `LOG-SRC-001`: check that Docker or Podman runs, that `nux-sockguard` is running, and that the agent user is in the `nux` group. `SKG-UPS-001` means sockguard cannot reach the runtime socket; pass `--upstream`.

**Journal logs are missing.** `LOG-SRC-002`: install `journalctl` and add the agent user to `systemd-journal`.

**Ping checks fail with `CHK-PING-002`.** Allow the runner's group in `net.ipv4.ping_group_range`. See [Agents](agents.md#prerequisites).

**Checks report `CHK-NET-001`.** The target is private, loopback or metadata. Use an agent runner inside that network, or set `allow_private` on the check if `checks.block_private` is false. See [Checks](checks.md#ssrf-guard).

**Notifications fail.** `ALR-SEND-001` (rejected) and `ALR-SEND-002` (not delivered) come from the receiving service. Use the channel's test button. `ALR-SEND-004` means sending is paused after repeated failures. See [Alerts](alerts.md#delivery-failures).

**Sign-in is blocked.** `AUTH-DENY-002` and `AUTH-LOCK-001` are rate limits. Wait 15 minutes. `AUTH-TOTP-001`: check the device clock; recovery codes also work.

**`AUTH-RBAC-002` or `AUTH-DENY-005` for something you expect to see.** Your role or scope does not cover it. Ask an admin to check your role binding.

**Single sign-on fails.** `AUTH-OIDC-011`: set `server.public_url`. `AUTH-OIDC-004`: check the client ID, issuer and signing algorithm (RS256 or ES256 only). `AUTH-OIDC-008`: none of your groups is bound to a role.

**CLI `CLI-NET-002` certificate not trusted.** Use `--ca-file`, or `--pin` with the fingerprint nuxd shows.

**Audit chain broken (`AUD-CHAIN-001`).** Entries were changed outside nuxd. Keep the database as it is, copy it for analysis, and restore from a backup taken before the first broken entry.

**`BAK-LOCK-001` during backup or restore.** nuxd is running. Stop it first.

## Support bundle

When asking for help, include the nuxd version (`nuxd --version`), the error codes, the relevant log lines with secrets removed, and your config file with `server.public_url` and host names redacted. Never send the master key, the setup token, API tokens or the database.
