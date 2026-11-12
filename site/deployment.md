---
title: Deploy to production
description: A complete walk-through for running Nux Deck on a server you manage, from network and DNS to first host, backups and upgrades.
weight: 15
---

This guide takes you from an empty Linux server to a running Nux Deck with its first monitored host. Read it once through before you start. The pages it links to are the reference for each step.

## What you are deploying

| Part            | Runs on                   | Listens on                                                                           | Talks to                                      |
| --------------- | ------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------- |
| `nuxd`          | One server                | 8443 (UI and API, HTTPS), 8444 (agent gateway, mutual TLS), 8080 (redirect to HTTPS) | Agents, your browsers, notification targets   |
| `nux agent`     | Each monitored host       | Nothing (outbound only)                                                              | `nuxd` on port 8444                           |
| `nux sockguard` | Each host with containers | A local Unix socket, `/run/nux/sockguard.sock`                                       | The local Docker or Podman socket (read-only) |

There is one `nuxd`. It has no high availability and no clustering, and the design target is about 200 agents per server (see [Limits](limits.md)). Hosts need no inbound ports.

## Before you start

**The server**

- Linux, amd64 or arm64, with systemd, `curl`, `tar` and `sha256sum`. The installer needs root.
- Persistent disk for `/var/lib/nuxd`. Metrics are kept for 15 days at full resolution and 90 days downsampled by default; size the disk for your host count and retention (see [Configuration](configuration.md)).
- A DNS name for the server, for example `nux.example.com`. Agents and browsers both use it, and it ends up inside enrolment tokens and certificates. Choose it before you enrol anything, because changing it later means re-enrolling hosts.

**The network**

| From                 | To                 | Port     | Why                                         |
| -------------------- | ------------------ | -------- | ------------------------------------------- |
| Browsers             | Server             | 8443/tcp | UI and API                                  |
| Browsers (optional)  | Server             | 8080/tcp | Redirects plain HTTP to HTTPS               |
| Every monitored host | Server             | 8444/tcp | Agent gateway                               |
| Server               | Internet           | 443/tcp  | Installer and updates, notification targets |
| Server               | Your check targets | varies   | Uptime checks that run on the server        |

Open 8444 only to the addresses your hosts use if you can. The gateway needs a valid agent certificate, but there is no reason to expose it more widely than necessary.

**On each monitored host**

- Linux with systemd, and Docker or Podman if you want container data. Container metrics need cgroups v2 at `/sys/fs/cgroup`. Journal logs need `journalctl`. See [Agents](agents.md#prerequisites).
- Outbound access to `nuxd` on port 8444 and to GitHub for the installer.

## 1. Install the server

```sh
curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --version <version>
```

Pin the version you tested. Without `--version` the installer takes the newest release. It downloads the release, verifies the cosign signature and the checksum, and installs nothing if either check fails. It then creates the `nuxd` user, installs `/usr/local/bin/nuxd` and the hardened `nuxd.service` unit, and starts the service.

To read the script first, download `deploy/install/install.sh` from the repository at the same tag, read it, and run it with `sudo sh install.sh --version <version>`.

To run `nuxd` as a container instead, see [Install the server](install.md#option-b-container-image). Use an exact image tag and a named volume for `/var/lib/nuxd`.

## 2. Configure before the first real use

Create `/etc/nuxd/nuxd.yaml`. Set the public addresses before you create any enrolment token, because tokens carry the gateway address:

```yaml
server:
  public_url: https://nux.example.com:8443
gateway:
  public_url: https://nux.example.com:8444
tls:
  hostnames: [nux.example.com]
```

Then restart:

```sh
sudo systemctl restart nuxd
```

- `gateway.public_url` is the address every agent dials. The gateway's certificate is issued for it, so the host name must be right.
- `server.public_url` is used for alert links and single sign-on redirects. Single sign-on will not start without it.
- `tls.hostnames` adds your name to the self-signed certificate of the UI. If you use your own certificate (next section) it does not apply.

The full list of keys and variables is in [Configuration](configuration.md). Settings are read from defaults, then this file, then `NUXD_*` variables, and an unknown key stops `nuxd` at start.

## 3. Choose how browsers trust the UI

The UI and API are on port 8443. Pick one:

**A. Your own certificate (recommended for a public name).** Point `tls.cert_file` and `tls.key_file` at a certificate for your name, for example from Let's Encrypt, and make both readable by the `nuxd` user. Renewal is up to you, and restart `nuxd` after renewing so it picks up the new files.

```yaml
tls:
  cert_file: /etc/nuxd/tls/fullchain.pem
  key_file: /etc/nuxd/tls/privkey.pem
```

**B. The generated self-signed certificate.** It works immediately, but every browser shows a warning until you install a trusted certificate or distribute the certificate. Agents are not affected, because they trust the internal CA that their enrolment token pins.

**C. A reverse proxy in front.** Terminate TLS on the proxy and forward to `nuxd` on 8443 (HTTPS). Three rules:

1. Proxy **only port 8443**. The agent gateway on 8444 uses mutual TLS with certificates issued by `nuxd`'s own CA, so a proxy must not terminate it. Either expose 8444 directly or pass it through as plain TCP.
2. The live log stream is a WebSocket and the event feed is Server-Sent Events. The proxy must allow WebSocket upgrades and must not buffer or time out long responses.
3. Set `server.trusted_proxies` to the proxy's address range (for example `["10.0.0.0/8"]`), or every user appears to come from the proxy and share one sign-in rate limit. `nuxd` then reads the client address from `X-Forwarded-For`, but only from those peers.

An nginx location block as a starting point (adapt it, it is not part of the tested build):

```nginx
location / {
    proxy_pass https://127.0.0.1:8443;
    proxy_ssl_verify off;                  # nuxd's own certificate; the proxy-to-nuxd hop is local
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

## 4. Open the firewall

For example with `ufw`:

```sh
sudo ufw allow 8443/tcp
sudo ufw allow from <monitored host or network> to any port 8444 proto tcp
```

Add 8080/tcp if you want the HTTP redirect. Check `https://nux.example.com:8443/healthz` from another machine.

## 5. First sign-in

On the server:

```sh
sudo nuxd setup-token
```

Open `https://nux.example.com:8443`, paste the token, and create the first administrator (a password of at least 12 characters that is not a common one). Turn on TOTP for this account straight away (see [Users and security](users-security.md)). Setup is a one-time step, and the token is deleted when it completes.

## 6. Back up the master key now

Every stored secret (webhook URLs, SMTP passwords, TOTP secrets) is encrypted with the master key in `/var/lib/nuxd/master.key`. Without it a restored database cannot be read. Copy it to somewhere that is **not** the same place as your database backups, such as a password manager or an offline store, and keep it out of git. Details: [Install](install.md#master-key-back-it-up).

## 7. Enrol the first host

In the UI, open **Inventory**, choose **Add host**, and copy the install command. It contains a single-use token that expires after an hour. On the host, as root:

```sh
curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --version <version> --agent --token '<token>'
```

The installer creates the `nux` and `nux-sg` users, installs `nux` with the `nux-agent` and `nux-sockguard` units, enrols the host (the token goes in on standard input, never in the process list) and starts both services. The UI shows "Connected" within seconds, and the host's inventory and metrics follow. If it does not connect, check `journalctl -u nux-agent -f` and [Troubleshooting](troubleshooting.md).

Things to know about the agent host:

- The agent is read-only and only dials out. It does not accept connections.
- Container data comes only through `nux sockguard`, which runs as `nux-sg`, the only account added to the `docker` group. Membership of that group is equivalent to root on the host for that account, which is why sockguard accepts only a fixed list of read-only `GET` calls. See [Agents](agents.md#guarantees) and the limits below.
- Rootless Podman needs a user unit that this release does not ship.
- Roll out to more hosts one at a time, at least at first, so you can see what each enrolment looks like.

## 8. Set up alerting before you need it

1. Add a notification channel (Slack, Teams, Discord, Telegram, SMTP or a webhook), and use its test button. See [Alerts](alerts.md).
2. Add an uptime check for the things you care about: [Checks](checks.md).
3. Add a status page if you want one: [Status pages](status-pages.md).

Set up a second administrator, and keep the first one's recovery codes somewhere safe. Roles and scopes are described in [Users and security](users-security.md).

## 9. Back up on a schedule

`nuxd backup` needs the server stopped, because it takes an exclusive lock on the data directory. A nightly backup therefore means a short stop. For example, as a root script run by a systemd timer or cron:

```sh
systemctl stop nuxd
nuxd backup --out /srv/backups/nuxd-$(date +%F).nuxbak --passphrase-file /root/backup.pass
systemctl start nuxd
```

Store the archives off the server and keep the passphrase separate from them. **Test a restore on a scratch machine before you rely on it**, as described in [Backup and restore](backup-restore.md). An archive you have never restored is a hope, not a backup.

## 10. Operate it

- **Is it up?** `https://nux.example.com:8443/healthz`. Monitor this from somewhere else, ideally another instance or a hosted uptime service, because `nuxd` cannot report its own outage.
- **Logs.** `journalctl -u nuxd -f` (JSON lines). Secrets and tokens are masked in the logs.
- **Audit log.** Every state-changing action is recorded in a hash chain. The chain is verified at start and by `GET /api/v1/audit/verify`.
- **Disk.** Watch `/var/lib/nuxd`, mainly `tsdb/` and `backups/`. Lower `metrics.retention_days` if it grows too fast.
- **Certificates.** Agent certificates last 24 hours and renew themselves. If you use your own UI certificate, renew it and restart `nuxd`.

## Upgrade

1. Read the release notes.
2. Take a backup (step 9).
3. Run the installer with the new version: `sudo sh install.sh --version <new>` on the server, then on each host with `--agent`.

`nuxd` writes an encrypted pre-upgrade archive before it migrates the database, and refuses to start if it cannot. Agents one minor version behind the server stay supported. Rolling back needs a restore. See [Upgrade](upgrade.md).

## Hardening checklist

- [ ] The DNS name is final and `server.public_url` and `gateway.public_url` use it.
- [ ] The UI has a trusted certificate, or a proxy with one.
- [ ] 8444 is open only to the hosts that need it.
- [ ] Behind a proxy: `server.trusted_proxies` is set, and 8444 is not proxied.
- [ ] Every administrator has TOTP, and you have more than one administrator.
- [ ] The master key is backed up separately from the database.
- [ ] A restore has been tested.
- [ ] `nuxd`'s health is monitored from outside.
- [ ] Telemetry is the way you want it. It is off by default and opt-in from Settings (see [Telemetry](telemetry.md)).
- [ ] `checks.block_private` is `true` if the server should never probe private addresses.

## Known limits of this release

Read [Limits and known gaps](limits.md) before you decide where to use this. In short:

- One server, no clustering, about 200 agents.
- Linux amd64 and arm64 only.
- Agents are read-only. Nux Deck cannot start, stop or change anything.
- The audit chain detects accidental damage and simple edits, but someone with write access to the database file can rewrite it consistently.
- Sockguard strips environment variables and mount sources, but container command lines and health output still pass through to the server. Keep secrets out of container commands (use files or a secrets mechanism instead).
