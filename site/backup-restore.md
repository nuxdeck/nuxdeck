---
title: Backup and restore
description: Take an offline backup of the whole data directory, restore it, handle the master key, and use pre-upgrade backups.
weight: 130
---

A backup is one archive of everything under the data directory: the database, metrics, certificates, the agent CA and (optionally) the keys.

## Back up

Run `nuxd backup` **while nuxd is stopped**. nuxd holds an exclusive lock on the data directory for its whole run; a backup or restore against a running server fails with `BAK-LOCK-001`.

```sh
sudo systemctl stop nuxd
sudo nuxd backup --out /srv/backups/nuxd-$(date +%F).nuxbak --passphrase-file /root/backup.pass
sudo systemctl start nuxd
```

Flags:

| Flag                               | Meaning                                                                                                                |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `--out PATH`                       | Required. Archive path, outside the data directory (`BAK-SRC-001` otherwise). Written to `PATH.partial`, then renamed. |
| `--passphrase-file FILE`           | Encrypt with the passphrase in the file (trailing newline trimmed; an empty file is an error).                         |
| `--unencrypted`                    | Write a plaintext archive instead.                                                                                     |
| `--include-master-key-unencrypted` | With `--unencrypted` only: also copy the master key and agent CA key.                                                  |
| `--config FILE`                    | Configuration to read (default `/etc/nuxd/nuxd.yaml`, or `NUXD_CONFIG`).                                               |

Exactly one of `--passphrase-file` or `--unencrypted` is required.

The summary line reports files, bytes, schema version, and whether the archive is encrypted and holds the master key.

### Keys

- Encrypted archives (`--passphrase-file`) include `master.key` and the agent CA (`pki/`), so a restore recovers the secrets.
- Unencrypted archives leave both keys out unless you add `--include-master-key-unencrypted`. Then stored secrets cannot be decrypted after a restore and agents must enrol again. nuxd warns about this.

The archive is encrypted with a key from Argon2id (the passphrase, or the master key for pre-upgrade archives). Payloads are sealed in 64 KiB AES-256-GCM frames. A plaintext header holds the magic `NUXBAK`, the version and the KDF salt.

Symbolic links and special files in the data directory make the backup fail with `BAK-SRC-001`.

### What is copied

The database is copied with `VACUUM INTO` (a consistent snapshot), not by copying live files. The metrics store (`tsdb/`) and the rest of the data directory are copied as files, which is why nuxd must be stopped.

## Restore

```sh
sudo systemctl stop nuxd
sudo nuxd restore --in /srv/backups/nuxd-2026-10-27.nuxbak --data-dir /var/lib/nuxd --passphrase-file /root/backup.pass
sudo systemctl start nuxd
```

| Flag                     | Meaning                                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `--in PATH`              | Required. Archive to restore.                                                                               |
| `--data-dir DIR`         | Required, absolute. Target data directory.                                                                  |
| `--passphrase-file FILE` | Passphrase for an encrypted archive.                                                                        |
| `--master-key-file FILE` | Open a pre-upgrade archive with the master key from this file. Cannot be combined with `--passphrase-file`. |

Restore checks checksums, the database (`quick_check`), the schema version and the audit chain before it touches the target. It refuses archives from a newer nuxd (`BAK-VER-001`) and a broken audit chain (`BAK-AUDIT-001`).

The restore extracts to a staging directory next to the target. The existing data directory is renamed to `<data_dir>.pre-restore` and is never deleted. If `.pre-restore` already exists, restore refuses with `BAK-REST-001`; move the old one aside first.

If the archive has no master key, set `NUXD_MASTER_KEY` or `secrets.master_key_file` to the original key, or stored secrets stay unreadable.

## Wrappers on the agent host

`nux backup` and `nux restore` run `nuxd` with the same arguments and return its exit code. They need `nuxd` on `PATH`, or `NUX_NUXD_BIN` set to its path (`CLI-NUXD-001` otherwise).

## Pre-upgrade backups

Before applying database migrations to an existing database, nuxd writes an encrypted archive to `<data_dir>/backups/` (mode 0700), named `pre-upgrade-<UTC time>-v<from>-to-v<to>.nuxbak`. It is encrypted with the master key and includes the master key and the CA, so it is restorable on its own with `--master-key-file`.

- Fresh installs have nothing to back up and skip it.
- `backup.pre_upgrade_keep` (default 3, 0 to 100) sets how many to keep; older ones are deleted. 0 turns the feature off.
- If the backup fails, migrations are not applied and nuxd does not start (`BAK-UPG-001`). Fix disk space or permissions and start again.

To roll back an upgrade: stop nuxd, run `nuxd restore --in <file> --data-dir <dir> --master-key-file <master key file>`, then start the older binary.

## Schedule

nuxd does not schedule off-box backups. Run `nuxd backup` from cron or a timer while stopped, copy the archive off the host, and test a restore at least once.
