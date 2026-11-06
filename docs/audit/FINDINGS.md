# Findings ledger

The single findings ledger of the directive (section 14). The register of
BLG-001 to BLG-267 is written in the directive itself; this file carries the
findings found after it, from BLG-268 on, and the closure record of every
finding whose fix is carried or merged.

## Rules

1. An identity (`BLG-NNN`) is never reused and never renumbered.
2. Severity is Critical, High, Medium or Low.
3. Status is `open`, `confirmed` (open and reproduced), `closed` (the fix
   merged), `closed by removal` (the code is gone) or `invalid` (the condition
   no longer exists, with evidence).
4. Live verification of BLG-001 to BLG-267 belongs to WP-01 to WP-04, and its
   output is `docs/audit/LIVE_STATUS.md`.
5. Closure protocol: the required test is written and covers the failure mode,
   the fix makes it green, and the record carries the pull request / commit and
   CI run.
6. A new finding is written here with the next free identity, and the row names
   the package that closes it.

## New findings

| Identity | Severity | Location | Finding | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-268 | High | `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs`, `src/chain/chain_actor.rs` | The gate refuses an unmodified copy of the tree: `chain_actor.rs` calls `required_fee` on `self.blockchain.state`, and the gate reads that as a consensus-state write outside block execution. | CI 42050659038, job 127488353707 | WP-17 |
| BLG-269 | Medium | `xtask/gates/src/gates/indexing_is_not_new.rs` | Two files under `src/` are outside the recorded index at run time, so the ratchet cannot be satisfied by the tree it guards. | CI 42050659038 | WP-42 |
| BLG-270 | Medium | `xtask/gates/src/gates/dead_pub_api.rs`, `.github/dead-pub-api-baseline.txt` | The dead public API count is 182 against a baseline of 173. | CI 42050659038 | WP-42 |
| BLG-271 | Medium | `xtask/gates/src/gates/guards_reachable.rs` | Five guards are unwired against a baseline of three. | CI 42050659038 | WP-42 |
| BLG-272 | High | `src/tests/bud3_door.rs`, `src/storage/bud3/bof1.rs`, `crates/bud-codec/src/lib.rs` | `cargo fmt --check` reports three diffs on `main` (`cccf1da`). | CI 42050659038, job 127488354480 | WP-10 |
| BLG-273 | Critical | `Cargo.toml` feature matrix, `src/` test suite | Core feature matrix `--no-default-features --features "pq-ml-dsa wallet-ml-dsa"` and library test suite fail on `main`. | CI 42050659038, jobs 127488354234 and 127488354235 | WP-01 |
| BLG-274 | Medium | `src/network/`, `.github/workflows/ci.yml` | Network hardening test step fails with exit 101 on `main`. | CI 42050659038, job 127488354561 | WP-15 |
| BLG-275 | Low | `deny.toml`, `.github/workflows/ci.yml` | Cargo deny jobs (root and fuzz) fail on `main`. | CI 42050659038, jobs 127488354574 and 127488354282 | WP-42 |
| BLG-276 | High | `crates/uel-abi/src/lib.rs`, `crates/uel-abi/src/transport.rs`, `crates/uel-abi/src/mock.rs`, `crates/uel-abi/tests/transport.rs` | `crates/uel-abi` unconditionally compiled `std::os::unix::net::UnixStream` in `transport.rs`, breaking `Cross-Platform Digest (windows-latest)` whenever `budlum-uel-abi` is built on Windows, and `panic_digest` / `panic_message` lived inside the Unix-only module rather than `host.rs`. | `crates/uel-abi/src/transport.rs:24` (`use std::os::unix::net::UnixStream;`); closed in PR `#36` (`aa7b8c5`, `47d4e05`) | WP-26 |

## Closure record (WP-09, WP-26..WP-33, PR #36)

| Identity | Status | Location | Verification test / gate | Pull request |
|---|---|---|---|---|
| BLG-088 | closed (in review, PR #36) | `crates/uel-abi/src/transport.rs`, `crates/uel-abi/tests/transport.rs` | `handshake_echoes_request_id_and_rejects_mismatch` | PR `#36` |
| BLG-248 | closed (in review, PR #36) | `src/execution/coordinator/mod.rs` (`StatefulBudZeroEe`), `src/execution/coordinator/state.rs` | `budzero_stateful_storage_persists_across_blocks` | PR `#36` |
| BLG-250 | closed (in review, PR #36) | `execution/Cargo.toml`, `src/execution/coordinator/worker.rs`, `xtask/gates/src/gates/ee_workers_build_with_unwind.rs` | `uel_worker_panic_yields_fault_receipt`, `uel_worker_death_does_not_commit`, gate `ee-workers-build-with-unwind` | PR `#36` |
| BLG-256 | closed (in review, PR #36) | `src/core/account.rs`, `xtask/gates/src/gates/economy_invariants.rs` | `frac_attos_stays_below_1e12`, `uel_bud_conservation`, gate `economy-invariants` | PR `#36` |
| BLG-260 | closed (in review, PR #36) | `src/execution/coordinator/overlay.rs` (`BlockReadCache`, `TxOverlay`), `docs/EXECUTION.md` | `coordinator_overlay_rolls_back_frame`, `execution_root_binds_every_namespace`, `uel_cross_arch_roots_equal` | PR `#36` |
| BLG-267 | closed (in review, PR #36) | `src/execution/coordinator/foreign/`, `docs/pq/classical_allowlist.toml`, `xtask/gates/src/gates/classical_crypto_is_paired.rs` | `foreign_account_cannot_touch_pq_holding`, `emergency_alert_suspends_foreign_keeps_adopt`, gate `classical-crypto-is-paired` | PR `#36` |
| BLG-276 | closed (in review, PR #36) | `crates/uel-abi/src/{lib,host,mock,transport}.rs`, `crates/uel-abi/tests/transport.rs` | `Cross-Platform Digest (windows-latest)` + `crates/uel-abi` test suite | PR `#36` |
