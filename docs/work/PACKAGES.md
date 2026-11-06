# Work package status

This file is the package registry required by directive section 15.5.7. It is
updated by the package owner's PR. The directive file itself is not part of the
repository (directive section 0.1.5).

## Current state of `main`

- `main` contains no merged work package. Milestone M0 (WP-01 to WP-04 merged)
  is not reached.
- The status below is derived from the titles of the open pull requests. A
  package listed as "Open PR(s), unmerged" is not complete until its PR merges
  and its acceptance criteria pass in CI.
- The package PR numbers use the open PR numbers at the time of writing. Several
  PRs carry the same package (overlaps). Consolidation is an open task (see
  below).

## Packages

| Package | Title | Lane | Tier | TLG gate | Dependencies | Milestone | Status | PRs (by title) |
|---|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Open | Yes | - | M0 | Open PR(s), unmerged | #12 |
| WP-02 | Live verification: storage | B | T-Open | Yes | - | M0 | Open PR(s), unmerged | #12 |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Open | Yes | - | M0 | Open PR(s), unmerged | #16, #12 |
| WP-04 | Live verification: clients, OS, CI, docs, consolidated status | D | T-Open | Yes | - | M0 | Open PR(s), unmerged | #35, #18 |
| WP-05 | Concept name map and naming gate | D | T-Open | Yes | WP-04 | M1 | Open PR(s), unmerged | #50, #31, #24, #20 |
| WP-06 | Persistence and state recovery migration | B | T-Open | Yes | WP-02 | M1 | Open PR(s), unmerged | #60, #11 |
| WP-07 | Removal of legacy storage systems | B | T-Open | Yes | WP-06 | M1 | No PR yet | none |
| WP-08 | Validator classes and single registry | A | T-Open | Yes | WP-01 | M1 | Open PR(s), unmerged | #40 |
| WP-09 | Execution environment interface | C | T-Open | Yes | WP-03 | M1 | Open PR(s), unmerged | #54, #38 |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Open | Yes | WP-07 | M2 | Open PR(s), unmerged | #56 |
| WP-11 | Mobile core and light client | D | T-Open | Yes | WP-10,12,13,15,20 | M4 | Open PR(s), unmerged | #44 |
| WP-12 | Committee finality | A | T-Open | Yes | WP-01 | M2 | Open PR(s), unmerged | #9 |
| WP-13 | Presence protocol and suspension | A | T-Open | Yes | WP-12 | M3 | Open PR(s), unmerged | #45 |
| WP-14 | Instant task handover and disaster mode | A | T-Open | Yes | WP-12,13,20,21 | M4 | Open PR(s), unmerged | #60 |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Open | Yes | WP-01 | M2 | Open PR(s), unmerged | #48 |
| WP-16 | Genesis, ceremony tool and economy | A | T-Open | Yes | WP-08 | M3 | Open PR(s), unmerged | #52, #39, #37, #34 |
| WP-17 | State transition and chain hardening | A | T-Open | Yes | WP-01,06 | M2 | Open PR(s), unmerged | #60 |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Open | Yes | WP-10 | M3 | Open PR(s), unmerged | #47, #43 |
| WP-19 | BOF-1 object format, QR presentation, video commitment | B | T-Open | Yes | WP-10,24 | M3 | Open PR(s), unmerged | #55, #45 |
| WP-20 | Class-aware placement, custody proof, repair | B | T-Open | Yes | WP-08,18 | M3 | Open PR(s), unmerged | #59, #13 |
| WP-21 | Upload, view, StorageTx v3, RPC | B | T-Open | Yes | WP-18,19,20 | M3 | Open PR(s), unmerged | #57 |
| WP-22 | Dedup, refcount, delete, sealed content, grants | B | T-Open | Yes | WP-21 | M3 | Open PR(s), unmerged | #45 |
| WP-23 | Dependent modules move to B.U.D. 3.0 | B | T-Open | Yes | WP-22 | M4 | No PR yet | none |
| WP-24 | A0 codec registry and access layer | B | T-Open | Yes | WP-10 | M3 | No PR yet | none |
| WP-25 | Storage fee, storage foundation, storage rewards | B | T-Open | Yes | WP-16,21 | M4 | Open PR(s), unmerged | #45, #40 |
| WP-26 | Execution Coordinator and EE workers | C | T-Open | Yes | WP-07,09 | M2 | Open PR(s), unmerged | #36, #24 |
| WP-27 | EVM execution environment and foreign envelope | C | T-Open | Yes | WP-26 | M3 | No PR yet | none |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Open | Yes | WP-27 | M4 | No PR yet | none |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | T-Open | Yes | WP-26 | M3 | No PR yet | none |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Open | Yes | WP-27,29 | M4 | No PR yet | none |
| WP-31 | SVM and Solana RPC subset | C | T-Open | Yes | WP-26 | M4 | No PR yet | none |
| WP-32 | Move (Aptos) and Aptos REST subset | C | T-Open | Yes | WP-26 | M4 | No PR yet | none |
| WP-33 | BudZero execution environment and hardening | C | T-Open | Yes | WP-26 | M3 | Open PR(s), unmerged | #24 |
| WP-34 | Migration kit | C | T-Open | No (Beta) | WP-28 | - | Open PR(s), unmerged | #61, #46 |
| WP-35 | Compliance, gas calibration, cross-architecture | C | T-Open | Yes | WP-27,29,31,32,33 | M4 | No PR yet | none |
| WP-36 | Android validator app | D | T-Open | Yes | WP-11 | M4 | No PR yet | none |
| WP-37 | Mobile device matrix and field test | D | T-Open | Yes | WP-36 | M4 | No PR yet | none |
| WP-38 | iOS opportunistic app | D | T-Open | No (Beta) | WP-11 | - | No PR yet | none |
| WP-39 | Wallet core and CLI | D | T-Open | Yes | WP-08,21,27 | M4 | Open PR(s), unmerged | #43 |
| WP-40 | Explorer and indexer | D | T-Open | Yes | WP-21,26 | M4 | No PR yet | none |
| WP-41 | Faucet and operations | D | T-Open | Yes | WP-16 | M4 | Open PR(s), unmerged | #59, #58, #52, #34 |
| WP-42 | CI, gates and supply chain | D | T-Open | Yes | WP-04 | M2 | Open PR(s), unmerged | #42, #31, #30, #29, #24 |
| WP-43 | Documentation, README and TLG report | D | T-Open | Yes | WP-46,47,48 | M6 | Open PR(s), unmerged | #51 |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Open | Yes | WP-01 | M4 | Open PR(s), unmerged | #60, #14 |
| WP-45 | Privacy, AI and account abstraction: testnet boundary | B | T-Open | Yes | WP-22 | M4 | Open PR(s), unmerged | #49, #44, #43 |
| WP-46 | Genesis rehearsal, rehearsal network, measurements | D | T-Open | Yes | M4 | M5 | No PR yet | none |
| WP-47 | Independent review 1: core and storage | Cross (C or D) | T-Open | Yes | M4 | M5 | No PR yet | none |
| WP-48 | Independent review 2: execution, mobile, clients | Cross (A or B) | T-Open | Yes | M4 | M5 | No PR yet | none |
| WP-49 | Universal Object Layer | A | T-Expansion | No | M7,WP-30,WP-44 | - | No PR yet | none |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | No | WP-35 | - | No PR yet | none |
| WP-51 | Cairo execution environment | C | T-Expansion | No | WP-35 | - | No PR yet | none |
| WP-52 | SVM and Move pointers | C | T-Expansion | No | WP-30,31,32 | - | No PR yet | none |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expansion | No | WP-35 | - | No PR yet | none |
| WP-54 | Shared compression context, extra codecs, private dedup | B | T-Expansion | No | WP-22,24 | - | No PR yet | none |
| WP-55 | Live streaming | B | T-Expansion | No | WP-21 | - | No PR yet | none |
| WP-56 | BudZero privacy core, predicate proofs, consent, PTP-1 | B | T-Expansion | No | WP-22,33 | - | No PR yet | none |
| WP-57 | AI verification layer | A | T-Expansion | No | WP-45,56 | - | No PR yet | none |
| WP-58 | F-Droid and reproducible Android build | D | T-Expansion | No | WP-36 | - | No PR yet | none |
| WP-59 | Parallel execution | C | T-Expansion | No | WP-35 | - | No PR yet | none |
| WP-60 | BudZero recursion, RV32, precompiles, domain proofs, block batch proofs | C | T-Expansion | No | WP-56 | - | No PR yet | none |
| WP-61 | RPC and crypto hardening | D | T-Open | Yes | WP-01 | M2 | Open PR(s), unmerged | #53, #41, #34 |
| WP-62 | Universal Object Layer: CosmWasm and Cosmos SDK family | A | T-Expansion | No | WP-49,29 | - | No PR yet | none |
| WP-63 | Universal Object Layer: SVM family | A | T-Expansion | No | WP-49,31 | - | No PR yet | none |
| WP-64 | Universal Object Layer: Move family | A | T-Expansion | No | WP-49,32 | - | No PR yet | none |

## Known overlaps and open consolidation

- WP-03: PRs #12 and #16 both carry lane C work.
- WP-04: PRs #18 and #35 both carry lane D ledger work.
- WP-16, WP-34, WP-41, WP-61: several PRs carry the same package.
- WP-42: PRs #29, #30, #31 and #42 carry CI gate work. This branch removes the
  directive file and fixes the `required_fee` read classification in the
  consensus-write gate.
- Stacked PRs that delete `THE_BUDLUM_DIREKTIF.md` carry the same removal as
  this branch. Rebasing those stacks drops the duplicate removal.

## Packages with no PR at the time of writing

WP-07, WP-23, WP-24, WP-27, WP-28, WP-29, WP-30, WP-31, WP-32, WP-35, WP-36,
WP-37, WP-38, WP-40, WP-46, WP-47, WP-48, WP-49 to WP-60, WP-62, WP-63 and
WP-64. Their rows in the table show "No PR yet".

## Integrated delivery detail (from the merged stacks)

## WP-28: Ethereum JSON-RPC gateway

Delivery 1/2 of the card. What is in the tree and what it proves:

| Card item | State | Evidence |
|---|---|---|
| Method table, in the `method_class.rs` pattern | delivered | `src/rpc/compat/ethereum/mod.rs`, `eth_rpc_method_table_is_complete` |
| Every Section 8.11.2 method present in the table | delivered | `eth_rpc_method_table_is_complete` compares the table to the directive list |
| The table, `api.rs` and `method_class.rs` agree | delivered | `eth_served_set_matches_the_declared_api`, `eth_class_table_matches_the_gateway_table`, and the startup check `method_class::check_served_methods` |
| `eth_getProof` answers `-32601` | delivered | `eth_get_proof_returns_method_not_found` |
| Every refusal names a door that exists | delivered | `eth_refusals_name_an_existing_door` |
| `debug_traceTransaction` and `debug_traceCall` are operator only | delivered | `eth_debug_methods_are_operator_only`, and the Budlum listener test `the_listener_column_matches_the_handlers` |
| Listeners on `127.0.0.1:18547` (HTTP and WebSocket) | 2/2 | not in this delivery |
| Bounded filters, timeouts, per-peer quota | 2/2 | `eth_subscribe` and `eth_unsubscribe` are table rows marked pending; the startup check refuses to serve them |
| Block and receipt shapes with `stateRoot = execution_root` | 2/2 | needs the `GlobalBlockHeader` v8 field of WP-27 |
| Foundry, Hardhat, viem, ethers tool tests (nightly) | 2/2 | they cannot pass before WP-27; no green claim is made |

The read side is honest about the dependency: WP-28 depends on WP-27 in Section
15.7, and the EVM execution environment is not merged. Serving state methods
before it would be the `eth_getBalance`-returns-a-Budlum-balance mistake, which
is why those answers are refusals with a named door rather than numbers.

## WP-04: the open pull request coordination report

`docs/work/PR_COORDINATION.md` measures where the 52 open pull requests collide,
which is the question Section 15.1 and Section 15.3 assume away by allowing only
four agents and one owner per lock path. The measurement is reproducible:

```sh
python3 ops/scripts/pr_coordination.py
```

It found three things worth a human decision rather than a commit:

1. **Two histories.** Three open pull requests (#8, #9, #71) have no common
   ancestor with `main`; #8's own diff is 344 files and 94 617 deleted lines.
   The directive's analysis base lives in that second history too. Which tree
   is the repository of record is a decision (Section 0.3 item 2), and the
   report names it rather than taking it.
2. **44 new files implemented twice or more with different content**, including
   one gate implemented four ways across five pull requests.
3. **332 paths shared by two or more pull requests**, 12 of them among the
   directive's own append-only list and the rest lock collisions that are still
   rebase work because nothing is merged.

The report also records what was verified about `main` itself, so the queue is
not blamed for defects the base does not have: the method-class table (218
methods, declaration order), the operator-gate column, gate registration (142 of
142), the required test names (241 across 14 gates) and metric writes (122) all
pass when replayed.
