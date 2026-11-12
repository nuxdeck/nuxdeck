---
title: Install the server
description: Install nuxd as a binary with systemd or as a container, then finish setup in the browser.
weight: 10
---

## Requirements

- Linux amd64 or arm64.
- Persistent storage for the data directory (default `/var/lib/nuxd`).
- Outbound HTTPS to GitHub or GHCR when installing, and to any notification or check targets you configure.

## Option A: binary with systemd

The install script downloads a release, verifies its cosign signature and checksum, and installs `nuxd` with a hardened unit:

```sh
curl -fsSL https://get.nuxdeck.com | sudo sh
# or pin a release
sudo sh install.sh --version v0.1.0-alpha.1
```

Nothing is installed unless both the signature and the checksum verify. The installer uses `deploy/systemd/nuxd.service`, which runs `/usr/local/bin/nuxd` as the `nuxd` user, with `StateDirectory=nuxd` (`/var/lib/nuxd`, mode 0700) and `ConfigurationDirectory=nuxd` (`/etc/nuxd`, optional `nuxd.yaml`).

```sh
sudo systemctl enable --now nuxd
sudo systemctl status nuxd
journalctl -u nuxd -f
```

## Option B: container image

```sh
docker run -d --name nuxd \
  -p 8443:8443 -p 8444:8444 \
  -v nuxd-data:/var/lib/nuxd \
  ghcr.io/nuxdeck/nuxd:<tag>
```

The image runs as UID/GID 65532 and exposes 8443 (UI and API) and 8444 (agent gateway). Mount a volume at the data directory so the database, certificates and master key survive restarts. Use an exact tag rather than `latest`.

## First start

nuxd listens on **https://<host>:8443** with a self-signed certificate it generates in the data directory (unless you set `tls.cert_file` and `tls.key_file`). Your browser will warn about it until you install a trusted certificate or a reverse proxy in front.

On the first start with no accounts, nuxd writes a setup token to the data directory and logs that setup is required. The token itself is never logged. Print it on the server host:

```sh
sudo nuxd setup-token            # or: docker exec nuxd /usr/local/bin/nuxd setup-token
```

`nuxd setup-token` reads `<data_dir>/setup-token` and prints it. If it reports that there is no token, setup is already complete, or nuxd has not started yet.

## Setup wizard

Open the UI and follow the wizard:

1. Paste the setup token.
2. Create the first administrator (email, name and a password of at least 12 characters that is not a common or breached password).
3. Optionally enable TOTP for your account (see [Users and security](users-security.md)).

Set the public URL users open before you rely on alert deep links or single sign-on. It is `server.public_url` (`NUXD_PUBLIC_URL`), an `https://` URL with no path, and nuxd reads it at start. Single sign-on refuses to start without it (`AUTH-OIDC-011`).

Enrol your first host next: [Agents](agents.md).

## Data directory

Everything lives under `data_dir` (default `/var/lib/nuxd`, set with `data_dir` or `NUXD_DATA_DIR`):

| Path         | Contents                                                             |
| ------------ | -------------------------------------------------------------------- |
| `nux.db`     | SQLite database (WAL mode)                                           |
| `tsdb/`      | Metrics store                                                        |
| `pki/`       | Internal CA for agent certificates                                   |
| `master.key` | Master key, created on first start if none is configured (mode 0600) |
| `backups/`   | Pre-upgrade archives                                                 |
| `nuxd.lock`  | Held while nuxd runs                                                 |

## Master key: back it up

Every stored secret (webhook URLs, SMTP passwords, check credentials, TOTP secrets) is encrypted with a master key. The key is taken from, in order:

1. `NUXD_MASTER_KEY` (base64 of 32 random bytes). Setting this and `secrets.master_key_file` together is an error.
2. The file named by `secrets.master_key_file` (`NUXD_MASTER_KEY_FILE`, absolute path, mode 0600).
3. `<data_dir>/master.key`, generated on first start.

nuxd refuses to start if the database holds secrets and no key is found, so it never silently generates a replacement.

> **Warning.** Back up the master key separately from the database. A backup without the key cannot decrypt stored secrets, and the key does not expire. If you lose it, you must re-enter every secret. Keep it out of git and out of images.

`nuxd backup` includes the key only when you ask for it (see [Backup and restore](backup-restore.md)).

## Next steps

- [Agents](agents.md): enrol hosts.
- [Backup and restore](backup-restore.md): set up backups before you rely on the system.
- [Configuration](configuration.md): ports, retention and public URLs.
