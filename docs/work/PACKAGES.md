# Work packages

The status register the directive asks every package's last pull request to
update: package, lane, status, dependency, pull request list, last commit,
CI runs and the findings it closed. English, one line per package.

## How to read the status column

- `not started` - no commit on `main` and no open branch carries the
  package's locked paths.
- `in progress` - a branch carries work; the parenthetical names it.
- `merged` - the package's last pull request is on `main`, with the commit
  and the CI run recorded here.
- `blocked` - a stop condition from the directive's agent rules; the reason
  is written in the row.

## Register

This repository has GitHub issues disabled - `gh issue list` answers that
issues are turned off for it - so the one issue per package that the queue
rules ask for cannot be opened. The owner name is not written out here either:
the concept-name map bans a substring of it, and a register that trips the
gate measuring it is a register nobody trusts. This table is the register
instead, and each row carries what the issue body would have carried.

| WP | Title | Lane | Layer | TLG | Depends on | Milestone | Status | PRs | Closed findings |
|---|---|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Launch | yes | none | M0 | not started | - | - |
| WP-02 | Live verification: storage | B | T-Launch | yes | none | M0 | not started | - | - |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Launch | yes | none | M0 | not started | - | - |
| WP-04 | Live verification: clients, operations, CI, documentation and the unified status | D | T-Launch | yes | none | M0 | in progress (this branch, PR #152, 1/2) | #152 | none yet |
| WP-05 | Concept-name map and counter gate | D | T-Launch | yes | WP-04 | M1 | in progress (this branch, PR #152, 1/1) | #152 | none yet |
| WP-06 | Persistence and state-recovery move | B | T-Launch | yes | WP-02 | M1 | not started | - | - |
| WP-07 | Removal of the legacy storage systems | B | T-Launch | yes | WP-06 | M1 | not started | - | - |
| WP-08 | Validator classes and one registry | A | T-Launch | yes | WP-01 | M1 | not started | - | - |
| WP-09 | Execution-environment interface | C | T-Launch | yes | WP-03 | M1 | not started | - | - |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | yes | WP-07 | M2 | not started | - | - |
| WP-11 | Mobile core and light client | D | T-Launch | yes | WP-10, WP-12, WP-13, WP-15, WP-20 | M4 | not started | - | - |
| WP-12 | Committee finality, Instant Seat Handoff, consensus hardening | A | T-Launch | yes | WP-08 | M2 | not started | - | - |
| WP-13 | Presence protocol and suspension | A | T-Launch | yes | WP-12 | M3 | not started | - | - |
| WP-14 | Instant Duty Handoff and disaster mode | A | T-Launch | yes | WP-12, WP-13, WP-20, WP-21 | M4 | not started | - | - |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Launch | yes | WP-01 | M2 | not started | - | - |
| WP-16 | Genesis, ceremony tool and economics | A | T-Launch | yes | WP-08 | M3 | not started | - | - |
| WP-17 | State transition and chain hardening | A | T-Launch | yes | WP-01, WP-06 | M2 | not started | - | - |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Launch | yes | WP-10 | M3 | not started | - | - |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Launch | yes | WP-10, WP-24 | M3 | not started | - | - |
| WP-20 | Class-aware placement, custody proof and repair | B | T-Launch | yes | WP-08, WP-18 | M3 | not started | - | - |
| WP-21 | Upload, view, StorageTx v3 and RPC | B | T-Launch | yes | WP-18, WP-19, WP-20 | M3 | not started | - | - |
| WP-22 | Deduplication, reference, deletion, sealed content and grants | B | T-Launch | yes | WP-21 | M3 | not started | - | - |
| WP-23 | Dependent modules move to B.U.D. 3.0 | B | T-Launch | yes | WP-22 | M4 | not started | - | - |
| WP-24 | A0 codec registry and access tiering | B | T-Launch | yes | WP-10 | M3 | not started | - | - |
| WP-25 | Storage fee, Custody Foundation and custody rewards | B | T-Launch | yes | WP-16, WP-21 | M4 | not started | - | - |
| WP-26 | Execution Coordinator and EE workers | C | T-Launch | yes | WP-07, WP-09 | M2 | not started | - | - |
| WP-27 | EVM execution environment and foreign envelope | C | T-Launch | yes | WP-26 | M3 | not started | - | - |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Launch | yes | WP-27 | M4 | not started | - | - |
| WP-29 | WASM (CosmWasm ABI) and the Cosmos RPC subset | C | T-Launch | yes | WP-26 | M3 | not started | - | - |
| WP-30 | Universal Call and the Universal Asset Registry | C | T-Launch | yes | WP-27, WP-29 | M4 | not started | - | - |
| WP-31 | SVM and the Solana RPC subset | C | T-Launch | yes | WP-26 | M4 | not started | - | - |
| WP-32 | Move (Aptos) and the Aptos REST subset | C | T-Launch | yes | WP-26 | M4 | not started | - | - |
| WP-33 | BudZero execution environment and BudZero soundness | C | T-Launch | yes | WP-26 | M3 | not started | - | - |
| WP-34 | Migration Kit | C | T-Launch | no (beta) | WP-28 | not a gate condition | not started | - | - |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Launch | yes | WP-27, WP-29, WP-31, WP-32, WP-33 | M4 | not started | - | - |
| WP-36 | Android validator app | D | T-Launch | yes | WP-11 | M4 | not started | - | - |
| WP-37 | Mobile device matrix and field test | D | T-Launch | yes | WP-36 | M4 | not started | - | - |
| WP-38 | iOS opportunistic app | D | T-Launch | no (beta) | WP-11 | not a gate condition | not started | - | - |
| WP-39 | Wallet core and CLI | D | T-Launch | yes | WP-08, WP-21, WP-27 | M4 | not started | - | - |
| WP-40 | Explorer and indexer | D | T-Launch | yes | WP-21, WP-26 | M4 | not started | - | - |
| WP-41 | Faucet and operations | D | T-Launch | yes | WP-16 | M4 | not started | - | - |
| WP-42 | CI, gates and supply chain | D | T-Launch | yes | WP-04 | M2 | not started | - | - |
| WP-43 | Documentation, README and the TLG report | D | T-Launch | yes | WP-46, WP-47, WP-48 | M6 | not started | - | - |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Launch | yes | WP-01 | M4 | not started | - | - |
| WP-45 | Privacy, AI and account abstraction: the testnet boundary | B | T-Launch | yes | WP-22 | M4 | not started | - | - |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Launch | yes | M4 (every M4 package merged) | M5 | not started | - | - |
| WP-47 | Independent review 1: core and storage | cross (C or D) | T-Launch | yes | M4 (every M4 package merged) | M5 | not started | - | - |
| WP-48 | Independent review 2: execution, mobile and clients | cross (A or B) | T-Launch | yes | M4 (every M4 package merged) | M5 | not started | - | - |
| WP-49 | Universal Object Layer | A | T-Expansion | no | M7, WP-30, WP-44 | - | not started | - | - |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | no | WP-35 | - | not started | - | - |
| WP-51 | Cairo execution environment | C | T-Expansion | no | WP-35 | - | not started | - | - |
| WP-52 | SVM and Move pointers | C | T-Expansion | no | WP-30, WP-31, WP-32 | - | not started | - | - |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expansion | no | WP-35 | - | not started | - | - |
| WP-54 | Shared compression context, extra codecs, private deduplication | B | T-Expansion | no | WP-22, WP-24 (the private-deduplication part also needs WP-56) | - | not started | - | - |
| WP-55 | Live streaming | B | T-Expansion | no | WP-21 | - | not started | - | - |
| WP-56 | BudZero privacy core, predicate proofs, consent and PTP-1 | B | T-Expansion | no | WP-22, WP-33 | - | not started | - | - |
| WP-57 | AI Verification Layer | A | T-Expansion | no | WP-45, WP-56 | - | not started | - | - |
| WP-58 | F-Droid and reproducible Android build | D | T-Expansion | no | WP-36 | - | not started | - | - |
| WP-59 | Parallel execution | C | T-Expansion | no | WP-35 | - | not started | - | - |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof, block aggregate proof | C | T-Expansion | no | WP-56 | - | not started | - | - |
| WP-61 | RPC and cryptography hardening | D | T-Launch | yes | WP-01 | M2 | not started | - | - |
| WP-62 | Universal Object Layer: CosmWasm and the Cosmos SDK family | A | T-Expansion | no | WP-49, WP-29 | - | not started | - | - |
| WP-63 | Universal Object Layer: the SVM family | A | T-Expansion | no | WP-49, WP-31 | - | not started | - | - |
| WP-64 | Universal Object Layer: the Move family | A | T-Expansion | no | WP-49, WP-32 | - | not started | - | - |

## Lane D detail (this branch)

| WP | Deliverable | Where | State |
|---|---|---|---|
| WP-05 | `config/naming/concept_map.toml`, the `concept-names` gate, `.github/concept-names-baseline.txt`, `docs/NAMING.md` | PR #152 | written, gate wired into `ci.yml` |
| WP-04 | `docs/audit/live/lane-d.md`, `docs/audit/LIVE_STATUS.md`, `docs/audit/FINDINGS.md`, `docs/work/PACKAGES.md` | PR #152 | this file and the three others |
| WP-04 | 64 GitHub issues, one per package | - | blocked: the repository has issues disabled |
| WP-04 | `src/tests/audit_lane_d.rs`, the permanent regressions for the previously fixed lane-D findings | PR #152 | see the lane file for which findings they cover |

## Milestones

| Milestone | Condition | State |
|---|---|---|
| M0 live status | WP-01, WP-02, WP-03, WP-04 merged | not reached: WP-01, WP-02 and WP-03 have no branch; WP-04 is on this branch |
| M1 structure | WP-05, WP-06, WP-07, WP-08, WP-09 merged | not reached |
| M2 core | WP-10, WP-12, WP-15, WP-17, WP-26, WP-42, WP-61 merged | not reached |
| M3 function | WP-13, WP-16, WP-18, WP-19, WP-20, WP-21, WP-22, WP-24, WP-27, WP-29, WP-33 merged | not reached |
| M4 completeness | the remaining TLG-blocked T-Launch packages | not reached |
| M5 verification | WP-46, WP-47, WP-48 merged | not reached |
| M6 documentation and TLG | WP-43 merged, `docs/audit/TLG_REPORT.md` green on every item | not reached |
| M7 launch | the launch steps of section 17 | not reached |

The dependency table's freeze rule is recorded here so nobody reads M5 as
permission to merge: from the first M5 package until launch, `main` accepts
T-Launch fixes and TLG work only. WP-34 and WP-38 may merge in that window
if they do not touch the consensus path or stay behind a flag the testnet
chain id keeps off.

