# Backup drill

Run this before a public testnet launch and after every change to a
persistence path. A backup that has never been restored is not a backup.

## Paths covered

`config/testnet.toml` names the new persistence paths. All of them live under
`/var/lib/budlum` and all of them are included below:

| Path | Contents |
| --- | --- |
| `data/testnet/budlum.db` | chain and state database |
| `data/testnet/snapshots` | state snapshots |
| `data/testnet/backups` | node-written backups |
| `data/testnet/banned-peers.json` | P2P ban list |
| `secrets/testnet-node-id.key` | libp2p identity |
| `secrets/testnet-validator.key` | validator key material |
| `softhsm/tokens` | SoftHSM2 token store (DOC-GAP-01) |
| relay reservation files | in-flight external actions |

The operator RPC and metrics listeners are not persistence paths. Caddy
certificates live in Caddy's own data directory and are reissued by ACME.

## Drill

1. Stop the service: `sudo systemctl stop budlum-core`.
2. Snapshot the paths to a dated directory with `tar` and record the SHA-256
   of the archive. Do not overwrite the previous snapshot.
3. Copy the archive to a second host. A backup on the same disk does not
   survive a disk failure.
4. On a clean host, restore the archive, repeat `ops/TESTNET_FIRST_RUN.md`
   steps 1 and 2 with the restored token directory, and start the node.
5. Compare `bud_chainId`, the tip height and the finalized height against the
   source host. Verify the faucet's `GET /health` reports the same chain id.
6. Restore the relay reservation file and confirm the worker reports held
   reservations instead of replaying external actions.
7. Record the archive hash, the two hosts, the commands and the result in the
   launch checklist. A drill that fails is a finding, not a skipped step.

## Restarts

Cooldowns, the daily cap and the proof-of-work difficulty live in the
faucet's memory. A restart issues new challenges and forgets cooldowns; only
the faucet balance bounds the total across restarts. Operators must protect
restarts with the same care as the funding key: do not restart the faucet to
clear a rate limit.
