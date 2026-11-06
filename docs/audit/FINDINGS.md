# Findings ledger

The single findings ledger of the directive (section 14). The register of
BLG-001 to BLG-267 is written in the directive itself; this file carries the
findings found after it, from BLG-268 on, and the closure record of every
finding whose fix has merged.

## Rules

1. An identity (`BLG-NNN`) is never reused and never renumbered.
2. Severity is Critical, High, Medium or Low.
3. Status is `open`, `confirmed` (open and reproduced), `closed` (the fix
   merged), `closed by removal` (the code is gone) or `invalid` (the condition
   no longer exists, with evidence).
4. Live verification of BLG-001 to BLG-267 belongs to WP-01 to WP-04, and its
   output is `docs/audit/LIVE_STATUS.md`.
5. Closure protocol: the required test is written first and is red before the
   fix, the pull request description quotes that red output, the fix makes it
   green, and the record then carries the merge commit and the CI run number.
6. A new finding is written here with the next free identity, and the row names
   the package that closes it.

## New findings

Every row below was read from the live tree and from GitHub on 2026-11-06. The
run is CI 42050659038 on `main` (`cccf1da`). The job logs are served by a host
the working environment cannot reach, so each row quotes the check-run
annotation text, which is the part of the log the workflow promotes to an
annotation on purpose.

| Identity | Severity | Location | Finding | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-268 | High | `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs`, `src/chain/chain_actor.rs` | The gate refuses an unmodified copy of the tree: `chain_actor.rs` calls `required_fee` on `self.blockchain.state`, and the gate reads that as a consensus-state write outside block execution. A gate that refuses the tree is either wrong about the rule or the tree is wrong about the call; the two are reconciled in one pull request. | CI 42050659038, job 127488353707: `FAIL [no-out-of-block-consensus-writes]: canary: an unmodified copy was refused: chain_actor.rs calls \`required_fee\` on \`self.blockchain.state\`, which is not a read` | WP-17 |
| BLG-269 | Medium | `xtask/gates/src/gates/indexing_is_not_new.rs` | Two files under `src/` are outside the recorded index at run time, so the ratchet cannot be satisfied by the tree it guards. | CI 42050659038: `FAIL [indexing-is-not-new]: 2 file(s) outside the baseline index at runtime` | WP-42 |
| BLG-270 | Medium | `xtask/gates/src/gates/dead_pub_api.rs`, `.github/dead-pub-api-baseline.txt` | The dead public API count is 182 against a baseline of 173. Nine public items are reachable from no caller in the tree. | CI 42050659038: `FAIL [dead-public-api-is-ratcheted]: dead public api: 182 \| baseline: 173` | WP-42 |
| BLG-271 | Medium | `xtask/gates/src/gates/guards_reachable.rs` | Five guards are unwired against a baseline of three. | CI 42050659038: `FAIL [guards-are-reachable]: unwired guards: 5 \| baseline: 3` | WP-42 |
| BLG-272 | High | `src/tests/bud3_door.rs` line 242, `src/storage/bud3/bof1.rs` line 278, `crates/bud-codec/src/lib.rs` line 304 | The format check reports three diffs, so the quality job cannot go green and `cargo fmt --check` stops being a signal. | CI 42050659038, job 127488354480: `Diff in .../src/tests/bud3_door.rs:242`, `.../src/storage/bud3/bof1.rs:278`, `.../crates/bud-codec/src/lib.rs:304` | WP-10 |
| BLG-273 | Critical | `Cargo.toml` feature matrix, `src/` test suite | The core does not build under `--no-default-features --features "pq-ml-dsa wallet-ml-dsa"` and the library test step fails, both with exit 101. `badges-are-current` then refuses to compare a badge against a red run, so the badge gate is red as well. A branch that cannot build its own declared feature matrix has no green CI to offer a release. | CI 42050659038, job 127488354234 step `Feature matrix: pq-ml-dsa solo`, job 127488354235 step `Test`, and annotation `FAIL [badges-are-current]: test log records failures; refusing to compare badge against a red run` | WP-01 |
| BLG-274 | Medium | `src/network/`, `.github/workflows/ci.yml` network hardening job | The network hardening test step fails with exit 101. | CI 42050659038, job 127488354561 step `network hardening tests` | WP-15 |
| BLG-275 | Low | `deny.toml`, `.github/workflows/ci.yml` cargo deny jobs | Both cargo deny jobs (root and fuzz) fail, so the dependency policy is not enforced on this tree. | CI 42050659038, jobs 127488354574 and 127488354282 | WP-42 |

## Closure record

No finding is closed on this branch. WP-20 touches no code under `src/`, so its
row set is empty and the ledger keeps BLG-268 to BLG-275 open.
