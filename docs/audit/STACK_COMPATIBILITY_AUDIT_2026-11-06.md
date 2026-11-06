# Live open-PR stack compatibility audit

| Field | Value |
|---|---|
| Generated (UTC) | `2026-11-06T10:55:06.515439+00:00` |
| Base | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` |
| Open PRs in snapshot | 75 |
| PR heads available locally | 75 |
| Changed `.rs` files parsed | 1522 |
| `.rs` files with syntax errors | 11 |
| Branches carrying broken Rust | 3 |
| Paths edited by >1 PR | 497 |
| New files implemented more than once | 103 |
| Integrated-tree `.rs` files parsed | 908 |
| Integrated-tree syntax errors | 0 |

Method: every path of every open PR head is read as a Git blob and every
`.rs` blob is parsed with the tree-sitter Rust grammar. This is a
syntax check, not a type check. No branch was checked out, pushed,
closed, merged or retargeted.

## 1. Branches that ship syntactically invalid Rust


### PR #8 (`arena/b7784c85-budlum` at `a5f30fb8`)

| File | First parse findings |
|---|---|
| `src/chain/blockchain.rs` | error@7914, error@7907, error@7743, error@4407, error@4216 |
| `src/persistence/db.rs` | error@2092, missing@431, missing@179, missing@145, error@135, error@131, error@128, error@123 |
| `src/persistence/traits.rs` | error@227, error@223 |
| `src/rpc/tests.rs` | error@445 |
| `src/storage/bud3/content_ref.rs` | error@239 |
| `src/tests/priority_findings.rs` | missing@164, missing@136, missing@133, missing@130 |
| `src/tests/regression_ai_storage.rs` | missing@373, missing@372, missing@365, missing@361 |
| `src/tests/regression_chain.rs` | missing@334, missing@325, missing@281 |

### PR #9 (`arena/5b54fce9-budlum` at `3c5bb36d`)

| File | First parse findings |
|---|---|
| `crates/bud-codec/src/container.rs` | missing@508 |
| `src/tests/integration.rs` | error@763, missing@758, error@758, error@512, missing@507, error@507 |

### PR #55 (`arena/442cedfb-budlum` at `4d7983b4`)

| File | First parse findings |
|---|---|
| `src/storage/bud3/private_dedup.rs` | missing@545 |

## 2. Conflict magnets (paths edited by more than one open PR)

| Path | PRs | Count |
|---|---|---|
| `docs/work/PACKAGES.md` | #13, #14, #16, #20, #29, #30, #31, #35, #36, #41, #47, #48, ... | 33 |
| `THE_BUDLUM_DIREKTIF.md` | #8, #9, #11, #14, #24, #34, #36, #42, #43, #45, #51, #58, ... | 26 |
| `.github/workflows/ci.yml` | #8, #9, #24, #29, #30, #31, #40, #44, #51, #56, #59, #60, ... | 23 |
| `xtask/gates/src/main.rs` | #8, #9, #13, #24, #29, #30, #31, #36, #40, #45, #51, #56, ... | 22 |
| `src/rpc/server.rs` | #8, #9, #11, #34, #41, #53, #58, #60, #62, #66, #71, #72, ... | 17 |
| `docs/audit/FINDINGS.md` | #13, #31, #35, #36, #41, #44, #48, #50, #68, #77, #80, #88, ... | 16 |
| `src/tests/mod.rs` | #8, #11, #12, #16, #18, #35, #52, #55, #56, #59, #60, #62, ... | 16 |
| `src/core/account.rs` | #8, #9, #11, #24, #36, #39, #51, #59, #60, #62, #66, #67, ... | 15 |
| `src/execution/executor.rs` | #8, #24, #39, #43, #44, #49, #51, #60, #62, #66, #67, #70, ... | 15 |
| `src/storage/bud3/mod.rs` | #8, #9, #40, #45, #55, #56, #57, #59, #60, #65, #69, #71, ... | 15 |
| `config/naming/concept_map.toml` | #8, #9, #20, #24, #31, #43, #50, #51, #60, #62, #66, #68, ... | 13 |
| `src/chain/blockchain.rs` | #8, #9, #11, #31, #40, #59, #60, #62, #66, #67, #70, #75, ... | 13 |
| `src/crypto/domain_tags.rs` | #8, #9, #24, #36, #45, #51, #52, #55, #70, #75, #76, #81, ... | 13 |
| `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs` | #24, #42, #51, #60, #62, #63, #66, #74, #75, #76, #93, #95, ... | 13 |
| `.github/concept-names-baseline.txt` | #8, #9, #11, #31, #43, #45, #50, #60, #62, #66, #68, #73 | 12 |
| `xtask/gates/tests/repository_locks.rs` | #8, #42, #60, #62, #63, #66, #73, #74, #75, #93, #95, #96 | 12 |
| `arena_claude.py` | #24, #34, #43, #45, #51, #58, #60, #62, #66, #75, #76 | 11 |
| `src/rpc/mod.rs` | #24, #36, #51, #53, #56, #72, #75, #76, #83, #89, #95 | 11 |
| `README.md` | #35, #46, #51, #55, #61, #69, #71, #73, #75, #78 | 10 |
| `src/main.rs` | #8, #9, #11, #53, #59, #60, #62, #66, #89, #95 | 10 |
| `src/rpc/compat/mod.rs` | #24, #36, #51, #56, #72, #75, #76, #83, #89, #95 | 10 |
| `.github/idle-code-baseline.txt` | #8, #9, #11, #45, #48, #60, #62, #66, #73 | 9 |
| `README.tr.md` | #35, #46, #61, #69, #71, #73, #75, #78, #87 | 9 |
| `src/cli/commands.rs` | #11, #24, #43, #51, #53, #60, #62, #66, #76 | 9 |
| `src/network/node.rs` | #8, #9, #11, #48, #53, #60, #62, #66, #81 | 9 |
| `src/rpc/method_class.rs` | #8, #41, #53, #60, #71, #72, #75, #83, #95 | 9 |
| `src/storage/bud3/bof1.rs` | #45, #55, #60, #62, #66, #79, #93, #95, #96 | 9 |
| `xtask/gates/src/gates/tree_is_english.rs` | #24, #43, #50, #51, #60, #62, #66, #73, #76 | 9 |
| `Cargo.toml` | #8, #36, #44, #46, #61, #75, #78, #91 | 8 |
| `src/execution/coordinator/mod.rs` | #24, #36, #46, #51, #61, #75, #76, #78 | 8 |

## 3. Duplicate new-file implementations

| Path | Distinct versions | PRs |
|---|---|---|
| `docs/work/PACKAGES.md` | 29 | #13, #14, #16, #20, #29, #30, #31, #35, #36, #41, #47, #48 ... |
| `docs/audit/FINDINGS.md` | 14 | #13, #31, #35, #36, #41, #44, #48, #50, #68, #77, #80, #88 ... |
| `src/rpc/compat/mod.rs` | 9 | #24, #36, #51, #56, #72, #75, #76, #83, #89, #95 |
| `src/rpc/compat/ethereum/mod.rs` | 5 | #24, #51, #56, #72, #75, #76 |
| `xtask/gates/src/gates/no_float_in_consensus_paths.rs` | 5 | #24, #29, #30, #31, #51, #76, #84 |
| `docs/audit/live/lane-c.md` | 4 | #12, #16, #68, #87 |
| `docs/audit/live/lane-d.md` | 4 | #18, #35, #68, #87 |
| `mobile/core/src/duty.rs` | 4 | #82, #85, #88, #91 |
| `mobile/core/src/lib.rs` | 4 | #82, #85, #88, #91 |
| `src/execution/coordinator/foreign/mod.rs` | 4 | #24, #36, #51, #76 |
| `src/storage/bud3/content_ref.rs` | 4 | #8, #45, #69, #71, #75, #84 |
| `xtask/gates/src/gates/workflows_cover_every_workspace.rs` | 4 | #24, #29, #30, #31, #51, #76 |
| `.github/no-legacy-storage-baseline.txt` | 3 | #69, #71, #75, #84 |
| `docs/EXECUTION.md` | 3 | #24, #36, #51, #76 |
| `docs/EXECUTION_LIMITS.md` | 3 | #36, #45, #79 |
| `docs/audit/LIVE_STATUS.md` | 3 | #35, #68, #87 |
| `docs/audit/REVIEW_2.md` | 3 | #36, #60, #77 |
| `docs/audit/live/lane-a.md` | 3 | #12, #68, #87 |
| `docs/audit/live/lane-b.md` | 3 | #12, #68, #87 |
| `mobile/core/src/store.rs` | 3 | #82, #85, #88, #91 |
| `src/bin/bud-migrate.rs` | 3 | #36, #46, #61, #75, #78 |
| `src/chain/state_recovery/mod.rs` | 3 | #8, #9, #11, #60, #62, #66, #84 |
| `src/cross_domain/evm/account_proof.rs` | 3 | #36, #46, #61, #75, #78 |
| `src/execution/coordinator/foreign/ethereum.rs` | 3 | #24, #36, #51, #76 |
| `src/execution/coordinator/migration/mod.rs` | 3 | #36, #46, #61, #75, #78 |
| `src/mempool/lanes.rs` | 3 | #24, #36, #51, #76 |
| `src/persistence/mod.rs` | 3 | #8, #9, #11, #60, #62, #66, #84 |
| `src/rpc/compat/ethereum/filters.rs` | 3 | #24, #51, #75, #76 |
| `src/storage/bud3/repair.rs` | 3 | #45, #59, #60 |
| `src/storage/bud3/volume.rs` | 3 | #45, #55, #57 |

## 4. Presence-message wire-shape drift

- `crates/budlum-types/src/presence.rs`: 6 distinct constant/digest lines across the stack.
- `mobile/core/src/presence.rs`: 4 distinct constant/digest lines across the stack.
- `src/registry/presence.rs`: 4 distinct constant/digest lines across the stack.
- `src/validators/presence.rs`: 4 distinct constant/digest lines across the stack.

## 5. Integrated tree

The current working branch parses 908 `.rs` files with 0 syntax findings. A zero here is necessary, not sufficient: semantic compatibility is checked by the wired gates and by CI, which is the compiler and test verifier for this workspace.

## 6. Evidence boundary

No Rust toolchain, crate registry, rustfmt or clippy exists in this workspace. No Rust test was run locally. Counts are live Git and GitHub observations, not performance measurements (directive 0.5). No green CI run is claimed (directive 0.3 item 5).
