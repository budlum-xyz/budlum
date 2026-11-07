# PR #79 execution-limits integration review

| Field | Value |
|---|---|
| Reviewed source | PR #79, `130aacd8a2ed95f4e163c23842b38c6793dc7476` |
| Integration target | PR #140 / `arena/8f90e12c-budlum` |
| Source check inventory | 1 failed Dependency Review check; 43 cancelled, 55 pending and 3 skipped checks in the captured inventory. None is represented here as a passing build or test run. |
| Current execution evidence | Static/source and Python checks only; no Rust toolchain, Cargo build, Rust test or conformance run was available |

## Disposition

The source branch's still-applicable BudZero budget correction is adapted into the
current coordinator. `MAX_BLOCK_CONTRACT_GAS` was 64,000,000 BGU while the hard
block limit was 60,000,000 BGU. It now equals the block limit. Compile-time
assertions cover the per-call and per-environment ceilings, and five regression
locks cover the constants, all native soft limits, the 60/61-call admission
boundary, the separate conformance runner and the documentation table.

The following source material is deliberately not restored verbatim:

- The two indexing rewrites and formatter changes were already present in the
  current tree.
- `execution/conformance/` now contains a real Cargo workspace and runner. The
  source README saying that no crate exists is obsolete.
- The source's 589-line catalog lock expects its older Markdown catalog. The
  current execution-limits document and runner have a different, later structure;
  five focused locks retain the still-relevant invariant without replacing them.
- `GATE_DEBT_2026-11-06.md` is a historical snapshot of `cccf1da1`, with baseline
  counts and path ownership that do not describe the integration head. It is not
  presented as current evidence.

## Finding identity and status

PR #79 named the gas defect `BLG-280`. The canonical ledger already uses that
identity for the closed static-call prefix-confusion finding. The budget defect is
therefore recorded as **BLG-302**. It remains **open; locally corrected, pinned
Rust CI pending**. Static review is not a closure run, and no upstream ecosystem
conformance, cross-architecture equivalence or performance result is claimed.

## Executed integration checks

- Parsed the native, coordinator and external-runner constants and verified the
  BudZero alias, compile-time cross-module check, document rows and 60/61-call
  regression wiring.
- Tree-sitter parsed all five changed Rust source/test files without syntax
  errors. This is not type checking or compilation.
- Integration audit: 14/14 current-tree checks passed; its separate 14-canary
  self-test had already passed during this integration session.
- RPC ratchet: 201 methods, 1,140 test functions, 150 baseline gaps, no new or
  stale gaps.
- No-legacy ratchet: 90 findings in 87 files, no new or stale findings.
- Genesis rehearsal unit suite: 12/12 passed. This is not a live rehearsal.
- Staged diff whitespace/error check passed.

A Rust 1.97.1 build, `src/tests/conformance_locks.rs` execution, strict Clippy,
required CI and the external conformance/nightly matrix remain outstanding.
