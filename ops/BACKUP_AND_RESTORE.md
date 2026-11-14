# Backup and restore drill (testnet)

the implementation track item 8 asked for the backup drill to be re-run against the paths the node
persists **now**. The paths grew: the drill was written when the node kept one
database directory.

## What has to be in a backup

| Path | Written by | On by default | In the backup |
|---|---|---|---|
| `<storage.data_dir>` (sled) | `src/storage/db.rs` | yes | yes, the `.budbak` file is a full dump of it |
| `./data/<network>/vote-history.json` | `src/network/node.rs::save_vote_history` | **yes, every network** | **no**: copy it, and see below |
| `/home/budlum/data/validator<seat>/vote-history.json` | local two-seat testnet (`ops/testnet-local-validator.py`) | **yes, one file per seat** | **no**: back up and restore each seat separately |
| `./data/<network>/banned-peers.json` | `src/network/node.rs` | where `security.persist_banned_peers` is set | **no**: copy it |
| faucet `--state-file` | `src/bin/budlum-faucet.rs` | when the faucet is enabled | **no**: copy it with the funding-key backup |
| `relayer-pending.json` beside the relayer cursor | `src/relayer/worker.rs` | when the relayer is enabled | **no**: copy it before restarting external actions |
| `<storage.snapshot_dir>` | the snapshot task | only when configured | no: a snapshot is derived, not state |
| `<storage.backup_dir>` | `--backup-now` | yes | no: this is the destination |

The vote history is the one that matters. A restored node without its vote
high-water marks will re-sign a height it already voted at. On a chain that has
not moved that is harmless; across a reorg it is equivocation, and the penalty
is `double_sign_slash_ratio_fixed`, 50% of the bond, for what was a crash and a
restart. The file is therefore part of what "restored" means, not an optional
extra.

The ban list costs peer churn when it is missing. The faucet state carries
cooldowns, the daily allowance, request demand and the reserved nonce; losing
it can reopen limits after restart. The relayer pending store prevents an
external action from being repeated while its result awaits finality. Both are
required for a complete service restore, not just a database integrity check.

The local testnet's `ceremony` volume is also outside every database backup.
Preserve its genesis and all eight validator key, P2P identity and bootnode
files together with `faucet.seed`: replacing the seed loses control of the
community allocation. Do not rerun key generation or assemble a new genesis
against restored validator databases. Keep an encrypted, access-controlled
copy of the secret files separate from the public genesis and records.

## The drill

The tool checks the database; the sidecar files are copied explicitly so the
operator and CI exercise the same complete restore:

```
# 1. The backup, restore and check, against a stopped node's database.
SOURCE_DB=./data/testnet/budlum.db \
BACKUP_DIR=./data/testnet/backups \
BUDLUM_BIN=./target/release/budlum-core \
cargo run --manifest-path xtask/tools/Cargo.toml -- backup-drill
```

```
# 2. The files the drill does not carry, copied beside the restored database.
# On a single-validator host, restore each sidecar to its configured path,
# NOT inside the freshly restored database directory unless that is its path.
install -m 600 <saved-vote-history-file> <configured-vote-history-path>
# The ban file can be absent on a new node; restore it if it was backed up.
install -m 600 <saved-banned-peers-file> <configured-banned-peer-path>
# The local testnet puts two seats in each validator volume: 1+5, 2+6,
# 3+7, 4+8. Copy BOTH stopped seats' histories into the same seat paths
# in the replacement volume; never use one seat's file for the other.
for seat in 1 5; do  # use 2 6, 3 7 or 4 8 for the other volumes
    install -D -m 600 "<saved-volume>/validator${seat}/vote-history.json" \
        "<restored-volume>/validator${seat}/vote-history.json"
    if [ -f "<saved-volume>/validator${seat}/banned-peers.json" ]; then
        install -D -m 600 "<saved-volume>/validator${seat}/banned-peers.json" \
            "<restored-volume>/validator${seat}/banned-peers.json"
    fi
done
# Restore the operator-selected faucet state and relayer cursor directory too.
install -m 600 <faucet-state-file> <configured-faucet-state-path>
install -m 600 <relayer-db>/relayer-pending.json <configured-relayer-pending-path>
```

The drill drives the same three flags the runbook gives an operator
(`--backup-now`, `--restore-backup`, `--check-db`), restores into an empty
temporary directory, and fails on a non-zero exit status rather than on a
substring in the output. It refuses a backup older than the run, so a stale
`.budbak` in the directory cannot make it pass.

## What the drill does not prove

* **A tampered backup is refused.** It is refused by
 `decode_database_backup`, which rejects a checksum mismatch and an unknown
 format version, but the drill does not exercise it: minting a valid backup
 needs the node's own bincode and hash framing, and a fixture that reproduced
 it in the tool would be a second implementation of the format proving
 itself. `verify_snapshot` runs on the file the node just wrote, which is the
 case that has to hold every hour.
* **The node comes back up.** The drill checks the restored database, not a
 restarted node's view of the chain. `docker compose -f ops/testnet-local.yml
 up` and `bud_getStatus` are the check for that, and section 3 of
 `docs/OPERATIONS.md` is the procedure.
* **Timing.** No number in this document is a measurement of how long a restore
 takes.

## Testnet rehearsal

Run the drill against the testnet profile's own paths before the launch
rehearsal (`the implementation track`), and record the result in `docs/rehearsal/`. The two source
locks that hold the drill and the runbook to the code are
`the_drill_covers_every_persisted_path`, `restore_refuses_a_target_that_is_not_empty`
and `the_restore_is_checked_after_it_is_written` in
`src/tests/backup_covers_persisted_paths.rs`.

`docs/OPERATIONS.md` section 2 links here; its section 3 is the restore
procedure this document does not repeat.
