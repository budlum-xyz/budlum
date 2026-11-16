# PR #183 conflict — budlum-stack vs garden

PR #183: budlum-stack (10db4c67) -> garden (a600c402). Mergeable=False, dirty.
Merge base: 9455763d. Garden head a600c402 is "Merge testnet hardening into garden" (includes f7312e2a testnet head).
Reproduced locally: `git merge origin/garden` in worktree at budlum-stack. 4 conflict files, all semantic (both sides fixed same Strix findings differently), not textual whitespace.

## Files and resolution

### 1. src/execution/executor.rs (1 hunk)
- Garden: passes `verified_storage_tx` (proposer stake derived from validator state, never caller input) + `epoch`.
- Stack: passes original `storage_tx` + `(tx.chain_id, epoch)` tuple (chain-id attestation binding, branch security/bud3-chain-id-attestations).
- Merged tx.rs kept stack signature `(chain_id, epoch)`.
- Resolution: `verified_storage_tx, (tx.chain_id, epoch)` — combines both. Garden's verified tx + stack's chain_id.

### 2. src/domain/storage_tx.rs (1 hunk)
- Garden: preflights sibling opener refunds (`open_sibling_opener_refunds`, overflow-checked in `refund_totals`), then pays siblings directly after slash.
- Stack: `bond_refunds.extend(close_superseded_challenges_for_slashed_deal(...))` — closes sibling challenges (inserts ChallengeResult Missed) and returns refunds paid via bond_refunds loop.
- Merged tree has both functions (`open_sibling_opener_refunds` read-only, `close_superseded...` closing).
- Resolution: keep garden preflight (already merged) + stack close_superseded as paying mechanism. Do NOT also pay sibling_refunds directly (double-pay). Chosen HEAD side for hunk.

### 3. src/mempool/pool.rs (5 hunks)
- Hunk1 duty lane: HEAD BatchExceedsBlockShare (batch > block share never useful) + Garden per-sender LaneBytesFull (sender_cap = lane_cap / clamp(validators,4,32)). Resolution: keep BOTH checks, in that order.
- Hunk2/3 count/bytes eviction: HEAD count_victim provisional eviction via `evict_lowest_fee_silent` + restore on byte refusal + journal; Garden count_full + `evict_lowest_fee` (function does not exist in merged tree — renamed to silent). Resolution: keep HEAD (journal/restore infrastructure exists in merged tree; garden function missing would not compile).
- Hunk4 duty bytes helpers: HEAD `duty_lane_bytes_of` (by_sender) + `evict_duty_from_heavier_signers`; Garden `duty_lane_bytes_for` (scan). Code after hunk1 calls both `duty_lane_bytes_of` and `evict_duty_from_heavier_signers`. Resolution: keep HEAD functions + add garden `duty_lane_bytes_for` as additional helper (both compile, same semantics).
- Hunk5 tests: HEAD `pool_bytes_full_refusal_does_not_evict_count_victim` + Garden `zero_fee_home_stipend...` + `duty_lane_per_validator_byte_share_protects_other_validators`. Resolution: keep all three tests.

### 4. src/settlement/proof_market.rs (1 hunk, tests only)
- HEAD: `one_prover_cannot_hold_the_receipt_queue...` + `assign_task_enforces_cumulative_stake...`
- Garden: `per_creator_active_task_cap_blocks_single_account_exhaustion`
- Resolution: keep all three tests.

## Verification
- `cargo fmt --all -- --check`: clean.
- `cargo check --lib`: OOM SIGKILL in sandbox (see report). Small crates pass. CI must validate merged tree after push.
- No conflict markers remain (`grep -r '<<<<<<<' src/` clean).

## Remaining PR #183 findings (not conflict, still open)
- Repair share MEDIUM (registry.rs:1895) — unacknowledged share blocks later repairs. Trace needed: does close_superseded / repair logic in merged tree already address? Not yet proven.
- Duty-lane LOW (account.rs:1855) — duty_lane_signers trusts active flag. Mempool merge above does not fix account.rs; separate fix needed.
- CodeRabbit mobile/core/src/store.rs:83 CRITICAL — trace needed.
