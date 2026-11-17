# Scenario 11 finality stall

Live evidence: `Testnet Rehearsal` run `227` (id `44005032414`) on `testnet` `f1338e7f26`.

Scenario 11 stops validator4 and requires the finalized height to move and the tip to
reach 58. It failed: `finalized 35->35, tip 42->62`.

## What the logs show

- Validator2 and validator3 sit on their own fork at tip 53 and request sync over and
  over. Every round ends with `peer returned no headers past our locator`, so the round
  closes and the next gossip block reopens it against the same peer.
- Validator1 reorgs to the canonical branch at height 58 and asks for headers with a
  locator built from its own fork. The canonical producer answers nothing, so validator1
  keeps asking the peers it already asked.
- With the round stuck at checkpoint 50, the votes cast for the canonical hash while a
  node held the fork are refused with `Prevote checkpoint hash mismatch` and dropped.
  A vote is published once, so the author can never resend it.
- Result: no node reaches a prevote quorum at 50 while three of four validators are
  online, and `finalized` never moves.

## Findings

### B-0022

- File: `src/network/node.rs` (`request_headers_from_peer`, sync round bookkeeping)
- Severity: High
- What: the peer that answered with nothing past our locator is asked again on the next
  trigger, because `last_stalled_sync_peer` is set only on an outbound failure of the active
  request or on a stuck-round expiry, and nothing sets it for an empty reply.
- Why: a follower behind a fork cannot resolve it from a peer on the same fork, and the
  canonical producer is connected but never asked.
- Impact: Scenario 11 stall. Finality stops while 3/4 validators are live.
- Fix: `last_empty_sync_peer` records the peer that answered empty. The peer choice moved
  into `choose_sync_header_target`, which rotates to another connected peer for one round
  and falls back to the same peer when it is the only one. A peer that makes progress
  clears the marker.
- Status: resolved and tested on `testnet` in commit `ad88285c`.

### B-0023

- File: `src/network/deferred_votes.rs`, `src/network/node.rs` (vote admission)
- Severity: High
- What: deferred votes are keyed on `(epoch, height)` only, and the `checkpoint hash
  mismatch` refusal is terminal: the vote is reported `Ignore` and forgotten.
- Why: after a reorg the node opens a round on the canonical hash at a height where it
  already holds votes for the abandoned hash. The canonical votes were dropped when they
  arrived, and no one can resend them.
- Impact: a single reorg at a checkpoint height costs every vote cast before it, which is
  how the Scenario 11 round at 50 lost its quorum.
- Fix: `DeferredVotes` keys entries on `(epoch, height, checkpoint_hash, voter, kind)`,
  `take_for_round` replays only the votes that match the open round, `prune_through` drops
  votes at or below the finalized height, and an authenticated vote refused for a hash
  mismatch is now held instead of dropped.
- Status: resolved and tested on `testnet` in commit `595bf1cd` / `ad88285c`.

### B-0024

- File: `src/chain/blockchain.rs` (`apply_reorg`), `src/persistence/{traits,db}.rs`
- Severity: Medium
- What: on a reorg the node rebuilds its in-memory global header archive but never removes
  the superseded rows from storage.
- Why: the durable rows keep the abandoned headers, so the next read loads a
  non-contiguous prefix, logs `Skipping stored global header with non-contiguous height`
  and drops every header past the fork.
- Impact: after a restart a node loses its global header archive beyond the fork point,
  which weakens the light client path and the anchor emission after any reorg.
- Fix: `BlockchainStorage::prune_global_headers_from` removes rows at and above a height
  and rewrites `LAST_GLOBAL_HEIGHT`; `apply_reorg` prunes from the first reconciled header
  and re-saves the reconciled set.
- Status: resolved and tested on `testnet` in commit `595bf1cd` / `ad88285c`.
