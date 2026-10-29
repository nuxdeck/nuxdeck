---
title: Upgrade
description: Upgrade nuxd and agents safely, with automatic pre-upgrade backups and rollback.
weight: 170
---

## Before you upgrade

1. Read the release notes for schema or configuration changes.
2. Confirm disk space for a backup: the pre-upgrade archive is roughly the size of the data directory.
3. Take an offline backup as described in [Backup and restore](backup-restore.md).

## Upgrade the server

With the installer:

```sh
sudo sh install.sh --version v0.1.0-alpha.2
```

Or with the container image, change the tag and recreate the container:

```sh
docker pull ghcr.io/nuxdeck/nuxd:v0.1.0-alpha.2
docker stop nuxd && docker rm nuxd
# run again with the same -v volume and the new tag
```

Then restart nuxd (`sudo systemctl restart nuxd`) if the installer did not.

On start, if the database has pending migrations, nuxd first writes an encrypted pre-upgrade archive to `<data_dir>/backups/` and only then applies them. A fresh install skips it. If the archive cannot be written, migrations are not applied and nuxd does not start (`BAK-UPG-001`). Keep `backup.pre_upgrade_keep` at 3 or more while you test a release.

A newer database is never opened by an older nuxd: it refuses with `SRV-MIG-002`. Downgrades need a restore.

## Upgrade agents

Agents one minor version behind the server stay supported. Upgrade hosts with the installer's `--agent` option, or replace the `nux` binary and restart `nux-agent` and `nux-sockguard`.

## Rollback

1. Stop nuxd.
2. Restore the pre-upgrade archive into the data directory with the master key:

   ```sh
   sudo nuxd restore --in /var/lib/nuxd/backups/pre-upgrade-<time>-v<from>-to-v<to>.nuxbak \
     --data-dir /var/lib/nuxd --master-key-file /etc/nuxd/master.key
   ```

3. Install the older binary and start it. The previous data directory is at `<data_dir>.pre-restore`; keep it until you are satisfied.

Pre-upgrade archives are encrypted with the master key, so keep that key with your backups.
