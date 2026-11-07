# Work-package ledger

> **Integration context (2026-11-07):** the table below is PR #73's dated
> 2026-11-06 snapshot of the GitHub `main`/`cccf1da` queue, not a claim that the
> later local integration merges are on GitHub `main`. The integration branch
> retains the snapshot as evidence and records its own ancestry separately.
> No CI, rehearsal, hardware validation or independent-review success is inferred
> from a merge commit or from a row below.

One row per work package of the directive (section 15.7). A row is written only
from evidence: a path in the tree, a live open pull request, or a command quoted
in the row (section 0.4). The file is the claim record until the issue tracker is
available (section 15.3 items 1-2; GitHub issues are disabled on this repository),
and it is the status record required by section 15.5 item 7.

Package ids are `WP-NN`, the directive's `İP-NN` with the same number (section 15.3
item 1). Status vocabulary: `not started`, `in progress`, `in review`, `merged`,
`blocked`. "In review" means at least one open pull request claims the package; it
does not mean the package's closing condition is believed to hold anywhere. `main`
is `cccf1da` ("Add files via upload"); no package has merged to `main`.

Written against the live state read 2026-11-06 (52 open pull requests). The
concurrent-PR collision map for these rows is `docs/audit/PR_STACK_AUDIT_2026-11-06.md`
(`STACK-NN` references below). Rows whose pull requests sit on the pre-`cccf1da`
timeline are marked `legacy` (STACK-01): they cannot merge to `main` as they are.

| Package | Title | Lane | Layer | Status | Pull requests | Evidence |
|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Launch | in review | #12, #68 | `docs/audit/live/lane-a.md` claimed by both (STACK-06 shape) |
| WP-02 | Live verification: storage | B | T-Launch | in review | #12, #68 | `docs/audit/live/lane-b.md`, `src/tests/audit_lane_b.rs` in #12 |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Launch | in review | #12, #16, #68 | `docs/audit/live/lane-c.md`, `engine-inventory.md` in #16 |
| WP-04 | Live verification: clients, operations, CI, documents | D | T-Launch | in review | #18, #35, #68 | `docs/audit/live/lane-d.md` in #18/#35 |
| WP-05 | Concept name map and counter gate | D | T-Launch | in review | #20, #24, #31, #50, #68 | `config/naming/concept_map.toml` owner/counter work; #68's baseline is unparseable (STACK-04) |
| WP-06 | Persistence and state-recovery migration | B | T-Launch | in review | #11, #60 (→#11) | `src/persistence/` in #11; lock-set file `src/core/account.rs` shared by eight PRs |
| WP-07 | Removal of the legacy storage systems | B | T-Launch | in review | #69 (1/N), #71 (2/N, →#69) | `no_legacy_storage` gate in #69; legacy RPC removal in #71 |
| WP-08 | Validator classes and one registry | A | T-Launch | in review | #31, #40 | Mobile duty lane in #31/#40; class split in `src/validators/` |
| WP-09 | Execution environment interface | C | T-Launch | in review | #38, #54 (→#38), #64 (→#54) | Worker handshake/ABI canaries in #38/#54/#64 |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | in review | #56 | `src/storage/bud3/` skeleton + wire contract in #56 |
| WP-11 | Mobile core and light client | D | T-Launch | in review | #44 | absence never slashes surface in #44 |
| WP-12 | Committee finality, instant seat handover, consensus hardening | A | T-Launch | in review | #9 (→#8, legacy) | STACK-01: no merge base with `main` |
| WP-13 | Presence protocol and suspension | A | T-Launch | in review | #45, #70 | `src/registry/liveness.rs` in #45/#70 |
| WP-14 | Instant task reassignment and disaster mode | A | T-Launch | in review | #60 | stacked on #11 (→#60) |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Launch | in review | #48 | `src/network/node.rs` in #48 |
| WP-16 | Genesis, ceremony tool and economics | A | T-Launch | in review | #34, #37, #39, #52 | STACK-10: four carriers, one surface |
| WP-17 | State transition and chain hardening | A | T-Launch | in review | #60, #62 (→#60), #66 (→#62), #67 (→`main`) | STACK-09: two divergent WP-17 lines into `src/chain/blockchain.rs`, `src/core/account.rs`, `src/execution/executor.rs` |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Launch | in review | #43, #47 | `src/storage/bud3/fountain.rs` in #43/#47 |
| WP-19 | BOF-1 object format, QR presentation, video commitment | B | T-Launch | in review | #45, #55 | `src/storage/bud3/bof1.rs` in #45/#55 |
| WP-20 | Class-aware placement, custody proof, repair | B | T-Launch | in review | #13, #59 | `xtask/gates/src/gates/bud3_{placement,custody_proofs,repair_fires}.rs` in #13/#45 |
| WP-21 | Upload, view, `StorageTx` v3 and RPC | B | T-Launch | in review | #57 | aggregation volume in #57 |
| WP-22 | Dedup, references, deletion, sealed content, permissions | B | T-Launch | in review | #45 | sealed/grants work in #45 |
| WP-23 | B.U.D. 3.0 migration of the dependent modules | B | T-Launch | not started | none | no open pull request touches the dependent-module trees (`src/bns/`, `src/socialfi/` and the data-market and education-domain modules) for this migration |
| WP-24 | A0 codec register and access layer | B | T-Launch | in review | #65 (1/3, base `main`), #8 (legacy) | STACK-01; two non-mergeable carriers |
| WP-25 | Storage fee, storage endowment, custody rewards | B | T-Launch | in review | #40, #45 | `src/storage/bud3/fees.rs` in #40/#45 |
| WP-26 | Execution coordinator and EE workers | C | T-Launch | in review | #24, #36 | STACK-07: same eleven files, divergent implementations |
| WP-27 | EVM execution environment and foreign envelope | C | T-Launch | in review (claimed) | #24 | claim only; #36 carries the shared files (STACK-07) |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Launch | in review | #24, #56, #72 (1/2) | three claimants of `src/rpc/compat/**` (STACK-07) |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | T-Launch | in review (claimed) | #24 | claim only |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Launch | in review (claimed) | #24 | claim only |
| WP-31 | SVM and Solana RPC subset | C | T-Launch | not started | none | no open pull request |
| WP-32 | Move (Aptos) and Aptos REST subset | C | T-Launch | not started | none | no open pull request |
| WP-33 | BudZero execution environment and BudZero soundness | C | T-Launch | in review (claimed) | #24 | claim only; shares `execution/budzero/` with #36 (STACK-07) |
| WP-34 | Migration kit | C | T-Launch | in review | #46, #61 (→#46) | `bud-migrate` in #46/#61 |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Launch | not started | none | no open pull request; needs WP-27…WP-33 first |
| WP-36 | Android validator application | D | T-Launch | not started | none | no `mobile/` tree exists yet |
| WP-37 | Mobile device matrix and field test | D | T-Launch | not started | none | depends on WP-36; none started |
| WP-38 | iOS opportunistic application | D | T-Launch | not started | none | depends on WP-11 (in review); none started |
| WP-39 | Wallet core and CLI | D | T-Launch | in review | #43, #44 | `crates/wallet-core/` in #43/#44 |
| WP-40 | Explorer and indexer | D | T-Launch | in progress | #73 | slice 1/N: the browser-core crate and its gates and CI wiring move to the `budlum-explorer` name (`crates/budlum-explorer/`, `explorer-name-rule-parity`, `explorer-patchset`); remainder gated on WP-21/WP-26 outputs |
| WP-41 | Faucet and operations | D | T-Launch | in review | #34, #52, #58 (→#34), #59 | STACK-10 |
| WP-42 | CI, gates and supply chain | D | T-Launch | in review | #24, #29, #30, #31, #42, #63 | directive removal in #42/#63 (STACK-02); gates in #29/#30 |
| WP-43 | Documents, README and the launch report | D | T-Launch | in review | #51 (→#24) | README gates in #51 |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Launch | in review | #14, #60 | `src/settlement/testnet_features.rs` in #14 |
| WP-45 | Privacy, AI and account abstraction: testnet boundary | B | T-Launch | in review | #43, #44, #49 | three PRs share `src/execution/executor.rs` and the AI boundary |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Launch | not started | none | depends on M4; not started |
| WP-47 | Independent review 1: core and storage | X (C or D) | T-Launch | not started | none | depends on M4; rule 15.8: the reviewer lane must not have written the code under review |
| WP-48 | Independent review 2: execution, mobile and clients | X (A or B) | T-Launch | not started | none | depends on M4 |
| WP-49 | Universal Object Layer | A | T-Expand | not started | none | frozen until M7 (section 15.5 item 9) |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expand | not started | none | frozen until M7 |
| WP-51 | Cairo execution environment | C | T-Expand | not started | none | frozen until M7 |
| WP-52 | SVM and Move markers | C | T-Expand | not started | none | frozen until M7 |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expand | not started | none | frozen until M7 |
| WP-54 | Shared compression context, extra codecs, private dedup | B | T-Expand | not started | none | frozen until M7 |
| WP-55 | Live streaming | B | T-Expand | not started | none | frozen until M7 |
| WP-56 | BudZero privacy core, predicates, consent, PTP-1 | B | T-Expand | not started | none | frozen until M7 |
| WP-57 | AI Verification Layer | A | T-Expand | not started | none | frozen until M7 |
| WP-58 | F-Droid and reproducible Android builds | D | T-Expand | not started | none | frozen until M7 |
| WP-59 | Parallel execution | C | T-Expand | not started | none | frozen until M7 |
| WP-60 | BudZero recursion, RV32, precompiles, domain proofs, batch proofs | C | T-Expand | not started | none | frozen until M7 |
| WP-61 | RPC and cryptography hardening | D | T-Launch | in review | #34, #41, #53 | `src/rpc/method_class.rs` ratchet in #41/#53 |
| WP-62 | Universal Object Layer: CosmWasm and Cosmos SDK family | A | T-Expand | not started | none | frozen until M7 |
| WP-63 | Universal Object Layer: SVM family | A | T-Expand | not started | none | frozen until M7 |
| WP-64 | Universal Object Layer: Move family | A | T-Expand | not started | none | frozen until M7 |

## Reading the table honestly

- `in review` is a statement about pull requests, not about package completeness.
  Twenty pull requests exceed the 1,500 changed-line cap (section 15.5 item 2);
  see `docs/audit/PR_STACK_AUDIT_2026-11-06.md` STACK-13.
- No package has `merged`. `main` is the single imported commit.
- The T-Expand rows are frozen by rule, not by oversight.
- Counting only open pull requests that target `main`: 41. The eleven stacked ones
  are listed with their parents in STACK-11.


## PR #72: opening Ethereum namespace (delivery note, not package completion)

This integration retains the existing full compatibility-lane gateway in
`src/rpc/compat/ethereum.rs`. The independently reviewed opening namespace,
class table and named-refusal checks live below it as
`src/rpc/compat/ethereum/opening.rs`; the main `RpcServer` uses that `opening`
table. Keeping the two scopes explicit avoids two files claiming the same Rust
module and does not present the opening delivery as completed WP-27/WP-28
conformance.

| Delivered surface | Evidence in the tree | Boundary |
|---|---|---|
| Complete opening namespace and class-table agreement | `eth_rpc_method_table_is_complete`, `eth_served_set_matches_the_declared_api`, `eth_class_table_matches_the_gateway_table` | Static table/API agreement is not runtime or third-party client conformance. |
| Honest chain reads | `chain_read_answers_are_hex_or_boolean` and the main RPC behavior tests | These tests read the local chain; they do not claim EVM execution. |
| Named EVM/MPT refusals | `eth_refusals_name_an_existing_door` and the main RPC refusal test | Unsupported execution methods fail rather than returning fabricated balances, receipts or call results. |
| Operator-only debug methods | `eth_debug_methods_are_operator_only` and the listener-column tests | Operator configuration and live listener behavior still need their normal CI/integration verification. |
| `eth_getProof` returns `-32601` | `eth_get_proof_returns_method_not_found` | The native account-proof door is `bud_getAccountProof`; execution proofs are not implied. |
| Bounded filters and subscriptions | Not delivered by PR #72; their rows remain pending | No filter or subscription readiness claim is made here. |
| Foundry, Hardhat, viem and ethers tests | Not delivered | No green CI or client-conformance claim is made here. |

The coordination measurement added by PR #72 is retained separately in
`docs/work/PR_COORDINATION.md` and `ops/scripts/pr_coordination.py`. It is a
point-in-time report and a set of decisions for maintainers, not merge history,
CI evidence or authorization to combine unrelated branches.


## PR #75: bounded Ethereum filters and the integration audit

PR #75's bounded filter pool is integrated as
`src/rpc/compat/ethereum/filters.rs`, a child of the canonical Ethereum module
and re-exported to the opening RPC table. It does not replace or share mutable
state with the older standalone `EthFilterRegistry`. Filter creation returns a
plain JSON hex-string quantity. `eth_newFilter`, `eth_newBlockFilter` and
`eth_uninstallFilter` are `LocalAdmin`; `eth_getFilterChanges` and
`eth_getFilterLogs` validate through the pool but remain `Refused` because WP-27
log data is unavailable. The two subscription rows stay pending.

The declared testnet defaults are 128 total filters, 8 per connection, a
300-second idle TTL and a 16-KiB serialized filter specification. They are not
measurements. `ops/scripts/integration_audit.py` replays 14 cross-file checks,
including extension signatures, exhaustive gateway answer matches, canonical
module wiring, filter result shape and the legacy-storage ratchet. Both its
self-test and plain run pass locally; this is Python static evidence, not a Rust
build, CI verdict, client-conformance result or package-completion claim.
