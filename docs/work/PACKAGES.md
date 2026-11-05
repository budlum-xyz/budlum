# Work packages WP-01 to WP-64

Source: directive section 15.7 (dependency table), translated to English. A package starts only when every package in its "Depends on" column has merged to `main`. `M0` to `M7` are milestones: a dependency on `M4` means every package of milestone M4 has merged (directive 15.7 note).

Tier: `T-Opening` is the testnet opening tier, `T-Expansion` is the post-opening expansion tier. TLG: whether the package blocks the testnet launch gate (`No (Beta)` marks a beta feature that is not a launch condition). Lane `Cross` is an independent-review lane.

Status vocabulary: `not-started`, `in-progress (PR #n)`, `merged`. WP-01 to WP-04 are verification-only work delivered in one shared PR.

| Package | Title | Lane | Tier | TLG | Depends on | Status | PR list |
|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Opening | Yes | None | in-progress (PR #2) | #2 |
| WP-02 | Live verification: storage | B | T-Opening | Yes | None | in-progress (PR #2) | #2 |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Opening | Yes | None | in-progress (PR #2) | #2 |
| WP-04 | Live verification: clients, operations, CI, documents and combined status | D | T-Opening | Yes | None | in-progress (PR #2) | #2 |
| WP-05 | Concept name map and counter gate | D | T-Opening | Yes | WP-04 | not-started | - |
| WP-06 | Persistence and state recovery move | B | T-Opening | Yes | WP-02 | not-started | - |
| WP-07 | Removal of the legacy storage systems | B | T-Opening | Yes | WP-06 | not-started | - |
| WP-08 | Validator classes and single registry | A | T-Opening | Yes | WP-01 | not-started | - |
| WP-09 | Execution environment interface | C | T-Opening | Yes | WP-03 | not-started | - |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Opening | Yes | WP-07 | not-started | - |
| WP-11 | Mobile core and light client | D | T-Opening | Yes | WP-10, WP-12, WP-13, WP-15, WP-20 | not-started | - |
| WP-12 | Committee-based finality, Instant Seat Handoff, consensus hardening | A | T-Opening | Yes | WP-08 | not-started | - |
| WP-13 | Presence protocol and suspension | A | T-Opening | Yes | WP-12 | not-started | - |
| WP-14 | Instant Duty Handoff and disaster mode | A | T-Opening | Yes | WP-12, WP-13, WP-20, WP-21 | not-started | - |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Opening | Yes | WP-01 | not-started | - |
| WP-16 | Genesis, ceremony tool and economy | A | T-Opening | Yes | WP-08 | not-started | - |
| WP-17 | State transition and chain hardening | A | T-Opening | Yes | WP-01, WP-06 | not-started | - |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Opening | Yes | WP-10 | not-started | - |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Opening | Yes | WP-10, WP-24 | not-started | - |
| WP-20 | Class-aware placement, retention proof and repair | B | T-Opening | Yes | WP-08, WP-18 | not-started | - |
| WP-21 | Upload, display, `StorageTx` v3 and RPC | B | T-Opening | Yes | WP-18, WP-19, WP-20 | not-started | - |
| WP-22 | Deduplication, reference, deletion, sealed content and permissions | B | T-Opening | Yes | WP-21 | not-started | - |
| WP-23 | B.U.D. 3.0 migration of dependent modules | B | T-Opening | Yes | WP-22 | not-started | - |
| WP-24 | A0 codec registry and access layer | B | T-Opening | Yes | WP-10 | not-started | - |
| WP-25 | Storage fee, Retention Foundation and retention rewards | B | T-Opening | Yes | WP-16, WP-21 | not-started | - |
| WP-26 | Execution Coordinator and EE workers | C | T-Opening | Yes | WP-07, WP-09 | not-started | - |
| WP-27 | EVM execution environment and foreign envelope | C | T-Opening | Yes | WP-26 | not-started | - |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Opening | Yes | WP-27 | not-started | - |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | T-Opening | Yes | WP-26 | not-started | - |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Opening | Yes | WP-27, WP-29 | not-started | - |
| WP-31 | SVM and Solana RPC subset | C | T-Opening | Yes | WP-26 | not-started | - |
| WP-32 | Move (Aptos) and Aptos REST subset | C | T-Opening | Yes | WP-26 | not-started | - |
| WP-33 | BudZero execution environment and BudZero soundness | C | T-Opening | Yes | WP-26 | not-started | - |
| WP-34 | Migration Kit | C | T-Opening | No (Beta) | WP-28 | not-started | - |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Opening | Yes | WP-27, WP-29, WP-31, WP-32, WP-33 | not-started | - |
| WP-36 | Android validator app | D | T-Opening | Yes | WP-11 | not-started | - |
| WP-37 | Mobile device matrix and field test | D | T-Opening | Yes | WP-36 | not-started | - |
| WP-38 | iOS opportunistic app | D | T-Opening | No (Beta) | WP-11 | not-started | - |
| WP-39 | Wallet core and CLI | D | T-Opening | Yes | WP-08, WP-21, WP-27 | not-started | - |
| WP-40 | Explorer and indexer | D | T-Opening | Yes | WP-21, WP-26 | not-started | - |
| WP-41 | Faucet and operations | D | T-Opening | Yes | WP-16 | not-started | - |
| WP-42 | CI, gates and supply chain | D | T-Opening | Yes | WP-04 | not-started | - |
| WP-43 | Documents, README and TLG report | D | T-Opening | Yes | WP-46, WP-47, WP-48 | not-started | - |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Opening | Yes | WP-01 | not-started | - |
| WP-45 | Privacy, AI and account abstraction: testnet boundary | B | T-Opening | Yes | WP-22 | not-started | - |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Opening | Yes | M4 | not-started | - |
| WP-47 | Independent review 1: core and storage | Cross (C or D) | T-Opening | Yes | M4 | not-started | - |
| WP-48 | Independent review 2: execution, mobile and clients | Cross (A or B) | T-Opening | Yes | M4 | not-started | - |
| WP-49 | Universal Object Layer | A | T-Expansion | No | M7, WP-30, WP-44 | not-started | - |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | No | WP-35 | not-started | - |
| WP-51 | Cairo execution environment | C | T-Expansion | No | WP-35 | not-started | - |
| WP-52 | SVM and Move pointers | C | T-Expansion | No | WP-30, WP-31, WP-32 | not-started | - |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expansion | No | WP-35 | not-started | - |
| WP-54 | Shared compression context, extra codecs, confidential deduplication | B | T-Expansion | No | WP-22, WP-24 (confidential deduplication part also WP-56) | not-started | - |
| WP-55 | Live streaming | B | T-Expansion | No | WP-21 | not-started | - |
| WP-56 | BudZero privacy core, predicate proofs, consent and PTP-1 | B | T-Expansion | No | WP-22, WP-33 | not-started | - |
| WP-57 | AI Verification Layer | A | T-Expansion | No | WP-45, WP-56 | not-started | - |
| WP-58 | F-Droid and reproducible Android build | D | T-Expansion | No | WP-36 | not-started | - |
| WP-59 | Parallel execution | C | T-Expansion | No | WP-35 | not-started | - |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof, block batch proof | C | T-Expansion | No | WP-56 | not-started | - |
| WP-61 | RPC and cryptography hardening | D | T-Opening | Yes | WP-01 | not-started | - |
| WP-62 | Universal Object Layer: CosmWasm and Cosmos SDK family | A | T-Expansion | No | WP-49, WP-29 | not-started | - |
| WP-63 | Universal Object Layer: SVM family | A | T-Expansion | No | WP-49, WP-31 | not-started | - |
| WP-64 | Universal Object Layer: Move family | A | T-Expansion | No | WP-49, WP-32 | not-started | - |
