# Archive node and backup/restore runbook (Task 0.37)

## Policy

An archive node keeps the complete block database and **must not enable
pruning**. `role = "archive"` fails closed unless:

- `features.pruning = false`
- `storage.backups_enabled = true`
- `storage.backup_dir` is set
- backup interval and retention are non-zero

Use [`config/archive.toml`](../../config/archive.toml) as the testnet template.
Production paths, API keys, genesis and bootnodes must be supplied by the
operator; secrets never belong in TOML committed to Git.

## Scheduled backups

When backups are enabled, the node immediately creates a `budlum-*.budbak`
file and repeats on `backup_interval_secs`. Each backup is:

1. preceded by a sled flush;
2. written as `*.partial` and `fsync`ed;
3. atomically renamed;
4. checked against a SHA-256 payload checksum, then decoded and checked for duplicate keys and schema metadata;
5. rotated to `backup_retention_count` files.

A framing check is not a disaster-recovery test. Run the restore drill below on
a different disk/host and monitor failures as paging alerts.

## One-shot offline backup

Stop the node first when making a release/upgrade backup:

```bash
sudo systemctl stop budlum-core
budlum-core \
  --db-path /var/lib/budlum/data \
  --backup-dir /var/lib/budlum/backups \
  --backup-retention-count 168 \
  --backup-now
sudo systemctl start budlum-core
```

Never copy a live sled directory with `cp` or `rsync`.

## Restore drill

The restore target must be absent or empty; restore never overwrites a database.

```bash
BACKUP=/var/lib/budlum/backups/budlum-<timestamp>.budbak
RESTORE=/var/lib/budlum/restore-drill
rm -rf "$RESTORE"

budlum-core --db-path "$RESTORE" --restore-backup "$BACKUP"
budlum-core --db-path "$RESTORE" --check-db
```

The restore command decodes the backup, imports in bounded batches, opens the
normal storage/migration path, and runs chain integrity checks. A non-zero exit
or any reported integrity error fails the drill.

The repository script automates the same sequence:

```bash
BUDLUM_BIN=target/release/budlum-core \
SOURCE_DB=/var/lib/budlum/data \
BACKUP_DIR=/var/lib/budlum/backups \
ops/backup_restore_drill.sh
```

## Recovery acceptance checklist

- Record source canonical height and latest finalized hash before the drill.
- Restore to a clean path on a separate volume.
- `--check-db` reports no corruption.
- Start a read-only/archive process against the restored DB and compare height,
  finalized hash, domain registry root and latest global header hash.
- Record elapsed restore time and backup size.
- Keep at least one tested copy outside the node's failure domain.
- Do not delete the old database until the restored node has synced and served
  health checks successfully.
