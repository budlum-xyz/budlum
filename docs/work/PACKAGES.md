# Work package register (single integrator)
| Field | Value |
|---|---|
| Document | `docs/work/PACKAGES.md`, required by directive 15.5.7 and 15.6 (M0) |
| Owner | this integration pull request (BLG-289: one named integrator) |
| Live base | `main` = `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` |
| Live snapshot | 70 open pull requests, 2026-11-06 |
| Status words | `open` = no delivery merged; `partial` = a slice is open in a PR; `undone` = no owner at all; `merged` = on `main` |
| Rule | a row changes only in the pull request that owns the package; append-only shared file, resolved by rebase (15.3.4) |

The `PRs` column is a live claim map, not a completion claim. Every PR in it is open; none is merged into `main`. A `partial` row names the work still owed.

## Packages

| WP | Title | Lane | Layer | TLG | Depends | Open PRs | State | Remaining work |
|---|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Launch | yes | none | #12, #68, #87 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-02 | Live verification: storage | B | T-Launch | yes | none | #12, #68, #87 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-03 | Live verification: execution, BudZero, domains, privacy and AI | C | T-Launch | yes | none | #12, #16, #68, #87 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-04 | Live verification: clients, operations, CI, documents and combined status | D | T-Launch | yes | none | #18, #35, #68, #75, #77, #87 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-05 | Concept-name map and counter gate | D | T-Launch | yes | WP-04 | #20, #24, #31, #50, #68 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-06 | Persistence and state-recovery move | B | T-Launch | yes | WP-02 | #11, #60, #84 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-07 | Legacy storage removal | B | T-Launch | yes | WP-06 | #69, #71, #84 | partial | WP-07, 3/N: removal is still WIP on the integrated stacks |
| WP-08 | Validator classes and single registry | A | T-Launch | yes | WP-01 | #31, #40 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-09 | Execution environment interface | C | T-Launch | yes | WP-03 | #38, #54, #64, #77, #80 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-10 | B.U.D. 3.0 skeleton and common types | B | T-Launch | yes | WP-07 | #56 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-11 | Mobile core and light client | D | T-Launch | yes | WP-10, WP-12, WP-13, WP-15, WP-20 | #44, #82, #85, #88, #91 | partial | WP-11 jobs 2-9: signed releases, durable ids, unauthenticated placement roots |
| WP-12 | Committee finality, Instant Seat Handover and consensus hardening | A | T-Launch | yes | WP-08 | #9, #81 | partial | WP-12, 2/N: HCLE shadow mode and the 10,000-block measurement |
| WP-13 | Presence protocol and suspension | A | T-Launch | yes | WP-12 | #45, #70 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-14 | Instant Duty Handover and disaster mode | A | T-Launch | yes | WP-12, WP-13, WP-20, WP-21 | #60 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Launch | yes | WP-01 | #48 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-16 | Genesis, ceremony tool and economy | A | T-Launch | yes | WP-08 | #34, #37, #39, #52 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-17 | State transition and chain hardening | A | T-Launch | yes | WP-01, WP-06 | #60, #62, #66, #67 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Launch | yes | WP-10 | #43, #47 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Launch | yes | WP-10, WP-24 | #45, #55 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-20 | Class-aware placement, custody proof and repair | B | T-Launch | yes | WP-08, WP-18 | #13, #59 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-21 | Upload, view, StorageTx v3 and RPC | B | T-Launch | yes | WP-18, WP-19, WP-20 | #57 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-22 | Dedup, references, deletion, sealed content and permissions | B | T-Launch | yes | WP-21 | #45 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-23 | Dependent modules migrate to B.U.D. 3.0 | B | T-Launch | yes | WP-22 | #43 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-24 | A0 codec register and access layer | B | T-Launch | yes | WP-10 | #65 | partial | WP-24, 2/3 and 3/3: access tiering and codec acceptance |
| WP-25 | Storage fee, Custody Endowment and storage rewards | B | T-Launch | yes | WP-16, WP-21 | #40, #45 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-26 | Execution Coordinator and EE workers | C | T-Launch | yes | WP-07, WP-09 | #24, #36 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-27 | EVM execution environment and foreign envelope | C | T-Launch | yes | WP-26 | #24, #78, #87 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Launch | yes | WP-27 | #24, #56, #72, #75, #76 | partial | WP-28, 2/2: subscriptions and filter delivery |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | T-Launch | yes | WP-26 | #24 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Launch | yes | WP-27, WP-29 | #24 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-31 | SVM and Solana RPC subset | C | T-Launch | yes | WP-26 | #51, #83 | partial | WP-31, 2/N: subscriptions and SVM-state reads |
| WP-32 | Move (Aptos) and Aptos REST subset | C | T-Launch | yes | WP-26 | #89 | partial | WP-32, 2/N: Move worker, account namespace, BCS and SDK conformance |
| WP-33 | BudZero execution environment and BudZero robustness | C | T-Launch | yes | WP-26 | #24, #43 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-34 | Migration Kit | C | T-Launch | no | WP-28 | #46, #61 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Launch | yes | WP-27, WP-29, WP-31, WP-32, WP-33 | #79 | partial | WP-35, 2/3 and 3/3: measured calibration and the five conformance suites |
| WP-36 | Android validator application | D | T-Launch | yes | WP-11 | none | undone | no owner; package not started in the live stack |
| WP-37 | Mobile device matrix and field test | D | T-Launch | yes | WP-36 | none | undone | no owner; package not started in the live stack |
| WP-38 | iOS opportunistic application | D | T-Launch | no | WP-11 | none | undone | no owner; package not started in the live stack |
| WP-39 | Wallet core and CLI | D | T-Launch | yes | WP-08, WP-21, WP-27 | #43 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-40 | Explorer and indexer | D | T-Launch | yes | WP-21, WP-26 | #43, #73 | partial | WP-40, 2/N: explorer pages and indexer events |
| WP-41 | Faucet and operations | D | T-Launch | yes | WP-16 | #34, #52, #58, #59 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-42 | CI, gates and supply chain | D | T-Launch | yes | WP-04 | #24, #29, #30, #31, #42, #63, #74, #75, #84 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-43 | Documents, README and TLG report | D | T-Launch | yes | WP-46, WP-47, WP-48 | #51 | partial | WP-43, 2/N: README numbers and the TLG report |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Launch | yes | WP-01 | #14, #43, #60 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-45 | Privacy, AI and account abstraction: testnet boundary | B | T-Launch | yes | WP-22 | #43, #44, #49 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Launch | yes | M4 | none | undone | no owner; package not started in the live stack |
| WP-47 | Independent review 1: core and storage | Cross | T-Launch | yes | M4 | #56 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-48 | Independent review 2: execution, mobile and clients | Cross | T-Launch | yes | M4 | none | undone | no owner; package not started in the live stack |
| WP-49 | Universal Object Layer | A | T-Expansion | no | M7, WP-30, WP-44 | none | undone | no owner; package not started in the live stack |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | no | WP-35 | none | undone | no owner; package not started in the live stack |
| WP-51 | Cairo execution environment | C | T-Expansion | no | WP-35 | none | undone | no owner; package not started in the live stack |
| WP-52 | SVM and Move pointers | C | T-Expansion | no | WP-30, WP-31, WP-32 | none | undone | no owner; package not started in the live stack |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script and Plutus | C | T-Expansion | no | WP-35 | none | undone | no owner; package not started in the live stack |
| WP-54 | Shared compression context, extra codecs and private dedup | B | T-Expansion | no | WP-22, WP-24 | none | undone | no owner; package not started in the live stack |
| WP-55 | Live streaming | B | T-Expansion | no | WP-21 | #86 | partial | WP-55, 2/N: broadcast driver, gateway door and activation height |
| WP-56 | BudZero privacy core, load proofs, consent and PTP-1 | B | T-Expansion | no | WP-22, WP-33 | none | undone | no owner; package not started in the live stack |
| WP-57 | AI Verification Layer | A | T-Expansion | no | WP-45, WP-56 | none | undone | no owner; package not started in the live stack |
| WP-58 | F-Droid and reproducible Android build | D | T-Expansion | no | WP-36 | none | undone | no owner; package not started in the live stack |
| WP-59 | Parallel execution | C | T-Expansion | no | WP-35 | none | undone | no owner; package not started in the live stack |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof and block aggregate proof | C | T-Expansion | no | WP-56 | none | undone | no owner; package not started in the live stack |
| WP-61 | RPC and crypto hardening | D | T-Expansion | no | WP-01 | #34, #41, #53 | partial | package completion evidence: final SHA, CI run number, every card item |
| WP-62 | Universal Object Layer: CosmWasm and Cosmos SDK family | A | T-Expansion | no | WP-49, WP-29 | none | undone | no owner; package not started in the live stack |
| WP-63 | Universal Object Layer: SVM family | A | T-Expansion | no | WP-49, WP-31 | none | undone | no owner; package not started in the live stack |
| WP-64 | Universal Object Layer: Move family | A | T-Expansion | no | WP-49, WP-32 | none | undone | no owner; package not started in the live stack |

## Delivery slices in this pull request

| Slice | WP | Content | Commit |
|---|---|---|---|
| WP-42, 1/N | WP-42, WP-04 | directive out of the tree, single integrator ledgers, live stack audit | first commit |

## Evidence boundary

No CI run number is claimed here. `main` is red at the live base, so a green PR run would not be attributable to a branch. The register is a live-tree record, not a completion claim (directive 0.3.5).

## Session integrator continuation (PR #96, branch `arena/0c480ae6-budlum`)

The register above is the single owner (BLG-289/BLG-290). This section is the
append-only continuation of that same register for the slices delivered on this
session branch. Directive 15.5.2 asks for one PR per slice; the fixed session
branch cannot host several open PRs, so each row is a commit boundary.

| Slice | WP | Carried from | Content | State |
|---|---|---|---|---|
| 0/N | WP-42, WP-04 | #93 | live integrator base: four red `main` causes, directive out of tree, single ledgers | merged into this branch |
| 1/N | WP-42, WP-04 | live stack | mechanical compatibility audit over all open PR heads; conflict matrix; duplicate implementations; wire drift | delivered |
| 2/N | WP-42 | BLG-299 | `rust_syntax_is_parseable` gate with canaries, wired into the gate registry | delivered |
| 3/N | WP-36, WP-37, WP-46 | #92, #94 | Android/rehearsal scaffolding carried over; ceremony defects repaired with a green black-box harness | delivered |
| 4/N | WP-55 | #86 | live stream core carried over; 2/N broadcast driver, gateway door and activation height | delivered |
| 5/N | WP-28, WP-31, WP-32 | #72, #83, #89 | compatibility namespaces carried over; subscriptions and the Move refusal surface | owed |
| 6/N | WP-11, WP-13, WP-42 | #91, #79 | mobile core/types carried over; one canonical presence wire shape; gate-debt wiring | owed |

Corrections to the live claim map above, from the mechanical audit
(`docs/audit/STACK_COMPATIBILITY_DATA_2026-11-06.json`):

- WP-36, WP-37 and WP-46 are **partial**, not `undone`: PR #92 delivers their
  scaffolding. The register row at the time of #93's snapshot predates #92.
- WP-61 is a T-Launch package (directive 15.7), not T-Expansion; the row above
  mislabels its layer.
- The live open-PR count at this session's snapshot is 75, not 70 (BLG-297).
