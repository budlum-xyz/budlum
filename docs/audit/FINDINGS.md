# Findings ledger (single integrator)

| Field | Value |
|---|---|
| Document | `docs/audit/FINDINGS.md`, required by directive 14.1.5 and 15.5.8 |
| Owner | this integration pull request (BLG-290: one named integrator) |
| Live base | `main` = `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` |
| Live snapshot | 70 open pull requests, 2026-11-06 |
| Rule | a finding closes only with a commit SHA and a CI run number (directive 0.3.5). A local parse, a prose claim or a self report is not closure evidence. |
| Numbering | BLG-288..BLG-304 are already allocated by the open stack. New findings here start at BLG-305. Duplicate allocations are themselves recorded (BLG-313). |

This file is the single migration target for the rows that eleven open pull
requests write into eleven different copies of this path, and for the rows
that PR #86 recorded in `docs/audit/LIVE_PR_STACK_AUDIT_2026-11-06.md` because
this file did not exist on `main`. No other branch was closed, merged or
retargeted to produce it.

## 1. Carried rows (identity and state as the open stack allocated them)

| ID | Severity | Finding | State at the live base |
|---|---|---|---|
| BLG-246 | Critical | Two-quorum committee finality | partially closed by PR #81; no CI run number |
| BLG-249 | High | No ecosystem-compatible RPC exists | Ethereum, Solana and Aptos route slices open (#72, #83, #89); SVM-state and Move reads still refused |
| BLG-263 | High | The pool pays by three shares | PR #39 slice open, storage/repair payouts owed |
| BLG-280 | High | BudZero contract budget above the block gas limit | closed in code by PR #79; CI evidence outstanding |
| BLG-281..BLG-287 | High | Worker ABI correction chain and stack collisions | recorded open by PR #77 and PR #80; the #38 -> #54 -> #64 checkpoint exists twice (BLG-292) |
| BLG-288 | High | `THE_BUDLUM_DIREKTIF.md` tracked in the tree | closed by this pull request (removal commit); also removed by #42, #63, #77, #78, #86, #87 |
| BLG-289 | High | `docs/work/PACKAGES.md` has 25 concurrent editors | closed by this pull request: one integrator, one register |
| BLG-290 | High | `docs/audit/FINDINGS.md` has 11 concurrent editors | closed by this pull request: one integrator, one ledger |
| BLG-291 | Medium | High fan-in files are outside the shared-append list | open; a merge train ordered by directive 15.7 is the proposed fix |
| BLG-292 | High | PR #77 and PR #80 carry the same ABI checkpoint | open; de-duplicate at integration, neither PR closed |
| BLG-293 | High | `main` is red across CI | open; this pull request closes the tree-attributable causes it can prove and records the rest |
| BLG-294 | Medium | No T-Expansion package claimed | partially addressed by #86 (WP-55, 1/N); ten packages remain unowned |
| BLG-295 | Medium | `src/object_layer/` is partial (header V9, reads, challenges, Sepolia run absent) | open |
| BLG-296 | Medium | PR #13 exceeds the 1,500 changed-line cap | open; owner action |
| BLG-297 | Medium | Stale "52 open PRs" number across the docs | open; the live count is 70 |
| BLG-298 | Critical | PR #8 and PR #9 ship syntactically invalid Rust | open; PR #81 re-roots #9, PR #8 has no successor (this file, section 3) |
| BLG-298 | High | "Reserved" as four empty mobile ids by PR #88 | duplicate allocation; see BLG-313 |
| BLG-299 | High | Nothing catches the broken-blob class of defect | open; WP-42 territory |
| BLG-301 | High | Two presence-message digests for the same window | PR #91 defines one wire shape, node call sites stay open |
| BLG-302 | High | PR #70 `presence.rs` does not type-check | open; outside PR #91's lock |
| BLG-303 | High | Turkish characters and Unicode dashes in PR #44 | fixed inside PR #44, not on `main` |
| BLG-304 | High | `tree_is_english` cannot pass while the directive and `arena_claude.py` are tracked | partially closed here (directive removal); `arena_claude.py` recorded in BLG-310 |

## 2. New findings (BLG-305 and up)

| ID | Severity | Finding | Evidence | State |
|---|---|---|---|---|
| BLG-305 | Critical | One clippy lint makes `main` red in four jobs: `manual_div_ceil` at `src/storage/bud3/dedup_index.rs:83` | CI run 42050659038, jobs `Budlum Core PQ build`, `Budlum Core library test`, `Budlum Core quality` and `Network Hardening`: "could not compile `budlum-core` (lib) due to 1 previous error" | **closed in code here**, CI run number owed |
| BLG-306 | High | `cargo fmt --all -- --check` fails with three hunks | CI run 42050659038, `Budlum Core quality`: `crates/bud-codec/src/lib.rs:304`, `src/storage/bud3/bof1.rs:278`, `src/tests/bud3_door.rs:242` | **closed in code here**, CI run number owed |
| BLG-307 | High | `no_out_of_block_consensus_writes` refuses the pure `required_fee` quote in `chain_actor.rs` | CI run 42050659038, `Gates` annotation: "canary: an unmodified copy was refused" | **closed in code here**, carried from #42/#63/#74, CI run number owed |
| BLG-308 | High | `indexing-is-not-new` refuses two runtime indexes outside its baseline | CI run 42050659038: `src/bin/support/http.rs:37`, `src/storage/bud3/dedup_index.rs:56` | **closed in code here**, carried from PR #79, CI run number owed |
| BLG-309 | High | `dead-public-api-is-ratcheted` reports 182 against 173, and `guards-are-reachable` reports 5 against 3 | PR #79 `docs/audit/GATE_DEBT_2026-11-06.md` names all ten dead functions and both new guards; CI run 42050659038 repeats the counts | open; wiring proposal in section 4, no baseline was raised |
| BLG-310 | High | `arena_claude.py` carries Turkish text in an English-only tree, and five open PRs edit it | `git grep -n` on `main`; #24, #34, #43, #45, #60 | open; deliberately not rewritten here, it is another package's lock path |
| BLG-311 | High | The open stack cannot be integrated as-is: PR #86's probe merged 14 of 68 cleanly and 54 conflicted, on the shared ledgers, `ci.yml`, `xtask/gates`, `src/tests/mod.rs` | PR #86 addendum, reproducible with `git merge-tree` | open; a merge train ordered by directive 15.7 is owed |
| BLG-312 | High | `Cargo Deny (root)`, `Cargo Deny (fuzz)`, `Security Audit`, `Determinism`, `Watchdog`, `OSV Scanner`, `Semgrep` and `Audit Guard` fail on `main` independently of the four Gates findings | `gh run list --branch main` plus `gh run view 42050659038 --json jobs` | open; fix after the tree is green, one workflow at a time |
| BLG-313 | Medium | Finding ids are allocated twice: BLG-298..BLG-301 appear in PR #86, PR #88 and PR #91 with different meanings | PR bodies, live `gh pr view` | open; the single ledger in this file is the proposed allocator |

## 3. Syntax audit of the two broken branches (method)

PR #86 records BLG-298 from a hand inspection. This integrator repeated the
check mechanically with the tree-sitter Rust grammar (version 0.26, grammar
`tree_sitter_rust`) over every changed `.rs` file on PR #8 and PR #9. Files with
`ERROR` or `MISSING` nodes are listed in
`docs/audit/STACK_INTEGRATION_AUDIT_2026-11-06.md`, section 5. The result is a
syntax finding, not a type-check: no crate registry is reachable in this
workspace, so `cargo check` was not run. No other PR's branch was modified.

## 4. What closing BLG-309 requires

The two gates are ratchets. Raising either baseline is forbidden by the
directive's "no softening" rule (0.3.1). The ten dead public functions and the
two `admit_*` guards are the B.U.D. 3.0 object-lifecycle helpers written by the
placement, limits, registry and segmentation packages. They must be called from
a production admission path (WP-21) rather than exempted with prose. The
proposed path is named in the integration audit; closing the finding needs that
path plus a CI run showing both counts at or below their baselines.

## 5. Evidence boundary

No finding in this file is claimed fully closed. "Closed in code" means the
tree change is present in a named commit of this branch; directive 0.3.5 still
requires a CI run number, and `main` is red at the live base. No Rust toolchain
exists in this workspace; `cargo`, `rustc`, `rustfmt` and `clippy` were not run
locally. The evidence quoted above comes from live GitHub Actions annotations
and job logs, which were readable through the API and the log host.

## 6. Session integrator (PR #96): mechanically reproduced findings

Source: `ops/scripts/stack_compatibility_audit.py`, run over the live snapshot
`docs/audit/OPEN_PR_SNAPSHOT_2026-11-06.json` (75 open PRs). Full data:
`docs/audit/STACK_COMPATIBILITY_DATA_2026-11-06.json`; readable report:
`docs/audit/STACK_COMPATIBILITY_AUDIT_2026-11-06.md`. Every changed `.rs` blob
on every open PR head was parsed with the tree-sitter Rust grammar; 1,522 blobs
scanned, 11 with syntax findings, on three branches. Counts are Git observations,
not measurements (directive 0.5).

| ID | Severity | Finding | Evidence | State |
|---|---|---|---|---|
| BLG-314 | High | A third open PR ships syntactically invalid Rust: PR #55 `src/storage/bud3/private_dedup.rs` has a `MISSING` node at line 545 | mechanical audit, section 1 of the compatibility report | open; extends BLG-298, the branch is not modified here |
| BLG-315 | Critical | The WP-46 rehearsal ceremony in PR #92 accepts empty `Full` claims, accepts eight duplicate records, publishes any `private_key` field and interpolates record filenames into Python source | PR #94 `tests/review/rehearsal_ceremony_regressions.py`, four failing checks against #92 head `9d532a8a`; source inspection of `ops/rehearsal/genesis_rehearsal.sh` | open; repaired on this branch, see slice 3/N |
| BLG-316 | High | 497 paths are edited by more than one open PR and 103 new files are implemented more than once with different bytes | mechanical audit, sections 2 and 3 | open; this branch's carry-over policy is recorded in the compatibility report |
| BLG-317 | High | The presence message has four different declared constant/digest shapes across `crates/budlum-types`, `mobile/core`, `src/registry` and `src/validators` (6/4/4/4 distinct lines) | mechanical audit, section 4; PR #91's BLG-301 | open; one canonical shape owed in slice 6/N |
| BLG-318 | High | No gate in the tree can reject a syntactically broken `.rs` blob before it merges (BLG-299 unowned) | `xtask/gates/src/gates/` inventory; three broken branches in the live stack | owed: `rust_syntax_is_parseable`, slice 2/N |
| BLG-319 | Medium | The single package register misstates WP-36/37/46 as unowned and WP-61 as T-Expansion | live `gh pr list` (PR #92) and directive 15.7 | closed in the register by slice 1/N |
| BLG-320 | High | WP-28 2/2, WP-31 2/N and WP-32 2/N (subscriptions, SVM-state reads, Move worker, BCS, `Foreign::Aptos`, 0xBD alias) have no owner | PR #83, #89 and #93 section 3 bodies | owed: slice 5/N |

Finding ids BLG-314 and up are allocated by this single ledger (BLG-313). No
other PR was closed, merged, retargeted or edited.
