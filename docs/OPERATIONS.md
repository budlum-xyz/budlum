# Operations runbook (testnet)

How to run a Budlum testnet node day to day: keys, backups, restores,
upgrades and incidents. Endpoints and
parameters are in `docs/TESTNET.md`; validator duties in
`docs/VALIDATOR_GUIDE.md`.

## 1. Keys

| Key | Created by | Lives in | Secret |
|---|---|---|---|
| Validator key set (signing, VRF, BLS, PQ) | `bud validator init` | `./secrets/testnet-validator.key` (0600) | yes |
| Validator ceremony record | `bud validator init` | anywhere | no |
| P2P identity | `bud node identity` or the first node start | `./secrets/testnet-node-id.key` | yes (it is the peer id) |
| Faucet key (ML-DSA-87 seed) | `budlum-faucet keygen` | `./secrets/faucet.seed` (0600) | yes |

Rules:

- `secrets/` and `data/` are ignored by git; never commit, paste or log a
  key (K7).
- Back up every secret file offline, encrypted, in two places.
- A lost validator key cannot be recovered: unbond with it while you still
  have it, or the stake stays bonded to a validator nobody can run.
- Never run the same validator key on two hosts at once. Two nodes signing
  with one key produce two blocks for one slot, which is a slashable double
  signature.

## 2. Backups

The node writes verified backups of its database on a schedule
(`config/testnet.toml`, `[storage]`: `backups_enabled`, `backup_dir`,
`backup_interval_secs` = 3600, `backup_retention_count` = 24).

- One backup now: `budlum-core --config config/testnet.toml --backup-now`
  writes one verified backup and exits.
- Check the database: `budlum-core --db-path <path> --check-db`; add
  `--repair-db` to rebuild the index after a failed check.
- The drill (backup, restore into an empty directory, integrity check):
  `cargo run --manifest-path xtask/tools/Cargo.toml -- backup-drill`.

A backup is not the only way back: the chain is replayed from blocks, so a
node can also resync from peers. A backup saves the time a full replay takes.

## 3. Restore

1. Stop the node.
2. Move the damaged database aside (keep it for the incident report).
3. `budlum-core --db-path <empty path> --restore-backup <backup file>`
   restores into an empty directory and exits.
4. `budlum-core --db-path <path> --check-db` must pass.
5. Start the node; it replays any blocks after the backup from its peers.

## 4. Upgrades

1. Read the release notes for a consensus change. A consensus change on the
   testnet comes with a new genesis or an activation height
; never mix versions across one.
2. Take a backup (`--backup-now`).
3. Stop the node, replace the binary, start it.
4. Watch `bud_getStatus`: `blockNumber` must grow and `finalizedHeight` must
   follow.
5. Validators upgrade one at a time. While fewer than two thirds of the
   stake runs the new binary, finality waits; it does not fork.

## 5. Monitoring

Prometheus scrapes each node's metrics listener (loopback; scrape through a
local agent). Rules: `ops/monitoring/alerts.yml`. Dashboard:
`ops/monitoring/grafana/budlum-testnet.json`.

### RPC transport security

The public RPC listener can terminate TLS itself: set `rpc.tls_cert_file` and
`rpc.tls_key_file` (PEM) in the node config, or `--rpc-tls-cert-file` and
`--rpc-tls-key-file`. The listener speaks TLS 1.3 and offers X25519MLKEM768
(RFC 10024) as its only key-exchange group, so a client that offers X25519
alone cannot connect. On mainnet a public RPC listener off loopback needs TLS;
a loopback listener behind a TLS front stays valid. A certificate without its
key stops the node at start.

## 6. Incidents

| Alert | First checks | Actions |
|---|---|---|
| `BudlumChainHalted` | Peer count; logs for "validate" refusals; clock (NTP) | Restart a stuck node; if every node is stuck, collect logs from all and escalate. |
| `BudlumFinalityStalled` | How many validators vote: do two thirds of the stake run and see each other? | Bring missing validators back; a jailed validator stays out until its jail ends. |
| `BudlumForkSuspected` / `BudlumNodesDisagreeOnHeight` | Compare `bud_getBlockByNumber` hashes across nodes at the same height | Stop the minority node, restore or resync it; keep its database for the report. |
| `BudlumPeerCountLow` | Firewall on 5001; bootnodes and DNS seeds | Fix the peer source; a node with no peer source refuses to start. |
| `BudlumMempoolNearFull` | `budlum_rpc_rate_limited_total`; senders | Spam is bounded per sender (200) and evicted by fee; raise nothing in config without review. |
| `BudlumDiskFillingUp` | Data directory size | Add disk; enable pruning only on non-archive nodes. |
| A validator key may have leaked | - | Stop the validator at once (double-sign risk), unbond with the old key from a clean host, generate new keys, rejoin. |

For each incident write: time line, alerts, actions, cause, and what changes
so it does not happen again. Security issues follow `docs/SECURITY.md`.
