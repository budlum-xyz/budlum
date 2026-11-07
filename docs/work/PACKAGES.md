# Work package register

Directive section 15.5 rule 7 asks for this register: for every package, the
package id, its lane, its layer, its TLG gate, its dependencies, the pull
requests that carry it, the last commit SHA, the CI run numbers and the findings
it closes. The register is English because the repository is English
(`tree_is_english`).

The binding directive lives outside this repository and is Turkish. This file is
not a translation of it: it is the record the directive asks for, written in the
repository's language, and it carries the same identifiers the directive uses as
`İP-NN` (section 15.3 rule 1: one package, one id, in the repository and on
GitHub).

## How to read a row

| Column | Meaning |
|---|---|
| `WP` | The package id. Never reused and never renumbered. |
| `Title` | English title of the package card in section 15.8. |
| `Lane` | The home lane from section 15.2. Packages 47 and 48 are cross-lane by design: an agent from a lane that did not write the code under review runs them. |
| `Layer` | `opening` (`T-Açılış`) or `expansion` (`T-Genişleme`). An expansion pull request does not merge before the testnet opens (section 15.5 rule 9). |
| `TLG` | Whether the package sits behind the testnet launch gate. |
| `Depends on` | What must be complete before the package may start (section 15.7): a package id, a milestone (`M0` to `M7`), or both. `none` where the directive writes `Yok`. |
| `Milestone` | The milestone the package is expected to land by (section 15.6). `empty` where the package has none. |
| `Status` | One of the five values below. |
| `Open PRs` | Every pull request open for this package on 2026-11-07, from `gh pr list`. A package's final pull request replaces this column with the merged list. `empty` means no pull request is open. |
| `Closes` | Findings this package closes. No row carries a finding until the closing pull request merged, because a closed finding needs a commit SHA and a CI run number (section 14.1 rule 5). |

## Status vocabulary

| Status | Meaning |
|---|---|
| `not started` | No pull request and no work in the tree. |
| `in progress` | At least one pull request is open. Nothing is claimed as merged. |
| `in review` | The work is complete on its branch and is waiting for the second pair of eyes section 15.5 rule 6 requires. |
| `blocked` | Waiting on a human step (section 17.1). A blocked package keeps its locks for 24 hours and then releases them (section 15.3 rule 9). |
| `closed` | The final pull request merged. The row must then carry the final commit SHA, the CI run numbers and the closed findings. |

No row is `closed` in this first version. A `closed` row without a merged commit
and a CI run number would be a self-report, and self-report is not evidence
(section 0.3 item 5).

## The 64 packages

| WP | Title | Lane | Layer | TLG | Depends on | Milestone | Status | Open PRs | Closes |
|---|---|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | opening | yes | none | M0 | in progress | #123, #124, #125, #131, #137, #138, #146, #148, #153 | empty |
| WP-02 | Live verification: storage | B | opening | yes | none | M0 | in progress | #117, #141 | empty |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | opening | yes | none | M0 | not started | empty | empty |
| WP-04 | Live verification: clients, operations, CI, documentation and unified status | D | opening | yes | none | M0 | in progress | #77, #118, #139 | empty |
| WP-05 | Concept-name map and counter gate | D | opening | yes | WP-04 | M1 | in progress | #24, #120, #122, #126, #127, #145, #152 | empty |
| WP-06 | Persistence and state-recovery migration | B | opening | yes | WP-02 | M1 | in progress | #60, #84 | empty |
| WP-07 | Removal of the legacy storage systems | B | opening | yes | WP-06 | M1 | in progress | #69, #71 | empty |
| WP-08 | Validator classes and the single register | A | opening | yes | WP-01 | M1 | in progress | #40 | empty |
| WP-09 | Execution environment interface | C | opening | yes | WP-03 | M1 | in progress | #38, #54, #64, #80 | empty |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | opening | yes | WP-07 | M2 | in progress | #56 | empty |
| WP-11 | Mobile core and light client | D | opening | yes | WP-10, WP-12, WP-13, WP-15, WP-20 | M4 | in progress | #82, #85, #88, #91 | empty |
| WP-12 | Committee-based finality, instant seat handover and consensus hardening | A | opening | yes | WP-08 | M2 | in progress | #81 | empty |
| WP-13 | Asset protocol and suspension | A | opening | yes | WP-12 | M3 | in progress | #70 | empty |
| WP-14 | Instant duty handover and disaster mode | A | opening | yes | WP-12, WP-13, WP-20, WP-21 | M4 | not started | empty | empty |
| WP-15 | Network: NAT traversal and P2P hardening | A | opening | yes | WP-01 | M2 | in progress | #48 | empty |
| WP-16 | Genesis, ceremony tool and economy | A | opening | yes | WP-08 | M3 | in progress | #37, #39, #52 | empty |
| WP-17 | State transition and chain hardening | A | opening | yes | WP-01, WP-06 | M2 | in progress | #62, #66, #67, #133, #134, #142, #143, #144, #147, #151 | empty |
| WP-18 | Segmentation and RFC 6330 fountain code | B | opening | yes | WP-10 | M3 | in progress | #47 | empty |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | opening | yes | WP-10, WP-24 | M3 | in progress | #55 | empty |
| WP-20 | Class-sensitive placement, custody proof and repair | B | opening | yes | WP-08, WP-18 | M3 | in progress | #13 | empty |
| WP-21 | Upload, viewing, StorageTx v3 and RPC | B | opening | yes | WP-18, WP-19, WP-20 | M3 | in progress | #57, #105 | empty |
| WP-22 | Deduplication, reference, deletion, sealed content and permissions | B | opening | yes | WP-21 | M3 | not started | empty | empty |
| WP-23 | Migration of the dependent modules to B.U.D. 3.0 | B | opening | yes | WP-22 | M4 | not started | empty | empty |
| WP-24 | A0 codec registry and access layer | B | opening | yes | WP-10 | M3 | in progress | #65 | empty |
| WP-25 | Storage fee, custody fund and custody rewards | B | opening | yes | WP-16, WP-21 | M4 | not started | empty | empty |
| WP-26 | Execution Coordinator and EE workers | C | opening | yes | WP-07, WP-09 | M2 | not started | empty | empty |
| WP-27 | EVM execution environment and foreign envelope | C | opening | yes | WP-26 | M3 | not started | empty | empty |
| WP-28 | Ethereum JSON-RPC gateway | C | opening | yes | WP-27 | M4 | in progress | #72, #75, #76 | empty |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | opening | yes | WP-26 | M3 | not started | empty | empty |
| WP-30 | Universal Call and Universal Asset Registry | C | opening | yes | WP-27, WP-29 | M4 | not started | empty | empty |
| WP-31 | SVM (Solana) execution environment and Solana RPC subset | C | opening | yes | WP-26 | M4 | in progress | #83 | empty |
| WP-32 | Move (Aptos) execution environment and Aptos REST subset | C | opening | yes | WP-26 | M4 | in progress | #89 | empty |
| WP-33 | Compatibility RPC hardening and ecosystem tooling | C | opening | yes | WP-26 | M3 | not started | empty | empty |
| WP-34 | Compliance and tooling: execution environments and ecosystem tools | C | opening | no | WP-28 | Koşul değil | in progress | #46, #61 | empty |
| WP-35 | Execution gas calibration and determinism | C | opening | yes | WP-27, WP-29, WP-31, WP-32, WP-33 | M4 | in progress | #79 | empty |
| WP-36 | Wallet core, CLI and the developer desk | D | opening | yes | WP-11 | M4 | in progress | #92, #97 | empty |
| WP-37 | Mobile applications and device testing | D | opening | yes | WP-36 | M4 | not started | empty | empty |
| WP-38 | Operations, release and the testnet plan | D | opening | no | WP-11 | Koşul değil | in progress | #100 | empty |
| WP-39 | RPC hardening and the public surface | D | opening | yes | WP-08, WP-21, WP-27 | M4 | in progress | #132 | empty |
| WP-40 | Explorer parity and patchset | D | opening | yes | WP-21, WP-26 | M4 | in progress | #73 | empty |
| WP-41 | Deployment units, secrets and core dumps | D | opening | yes | WP-16 | M4 | in progress | #58, #59 | empty |
| WP-42 | CI gates, the coverage latch and the workflow inventory | D | opening | yes | WP-04 | M2 | in progress | #29, #30, #42, #63, #74, #93, #95, #96, #98, #101, #103, #106, #107, #109, #116, #119, #121, #129, #130, #135, #136 | empty |
| WP-43 | README definition block, naming and the repository's language | D | opening | yes | WP-46, WP-47, WP-48 | M6 | in progress | #51, #150 | empty |
| WP-44 | Bridge, domains and cross-domain invariants | A | opening | yes | WP-01 | M4 | in progress | #14 | empty |
| WP-45 | AI boundary: agent ranking without floats | B | opening | yes | WP-22 | M4 | in progress | #44, #49, #128 | empty |
| WP-46 | Rehearsal network and the drills | D | opening | yes | M4 | M5 | in progress | #99, #102 | empty |
| WP-47 | Independent review 1: core and storage | Çapraz (C veya D) | opening | yes | M4 | M5 | not started | empty | empty |
| WP-48 | Independent review 2: execution, mobile and clients | Çapraz (A veya B) | opening | yes | M4 | M5 | not started | empty | empty |
| WP-49 | Universal Object Layer | A | expansion | no | M7, WP-30, WP-44 | empty | not started | empty | empty |
| WP-50 | Move (Sui dialect) execution environment | C | expansion | no | WP-35 | empty | not started | empty | empty |
| WP-51 | Cairo execution environment | C | expansion | no | WP-35 | empty | not started | empty | empty |
| WP-52 | SVM and Move pointers | C | expansion | no | WP-30, WP-31, WP-32 | empty | not started | empty | empty |
| WP-53 | Cross-environment account abstraction | C | expansion | no | WP-35 | empty | not started | empty | empty |
| WP-54 | B.U.D. 3.0 privacy: proof classes and witness separation | B | expansion | no | WP-22, WP-24 (gizli tekilleştirme kısmı ayrıca WP-56) | empty | not started | empty | empty |
| WP-55 | B.U.D. 3.0: storage proofs and coded chunks | B | expansion | no | WP-21 | empty | in progress | #86 | empty |
| WP-56 | BudZero privacy gates and measurement | B | expansion | no | WP-22, WP-33 | empty | not started | empty | empty |
| WP-57 | Universal consensus: committee rotation at scale | A | expansion | no | WP-45, WP-56 | empty | not started | empty | empty |
| WP-58 | Mobile: iOS and the device matrix | D | expansion | no | WP-36 | empty | not started | empty | empty |
| WP-59 | Execution: unconstrained AIR columns | C | expansion | no | WP-35 | empty | not started | empty | empty |
| WP-60 | Execution: AIR mutants and constraint coverage | C | expansion | no | WP-56 | empty | not started | empty | empty |
| WP-61 | Cryptography: PQ API, PKCS#11 and key files | D | opening | yes | WP-01 | M2 | in progress | #34, #41, #53 | empty |
| WP-62 | Universal domains: settlement guarantees | A | expansion | no | WP-49, WP-29 | empty | not started | empty | empty |
| WP-63 | Universal registry: identity without open identifiers | A | expansion | no | WP-49, WP-31 | empty | not started | empty | empty |
| WP-64 | Universal Object Layer: the Move family | A | expansion | no | WP-49, WP-32 | empty | not started | empty | empty |

## Shared append-only files

Section 15.3 rule 4 lists the files no package may lock, because every package
appends to them and a conflict is resolved by rebase rather than by waiting:

| File | What a package may add |
|---|---|
| `src/core/transaction.rs` | A `TransactionType` variant and its wire-encoding row. |
| `src/rpc/method_class.rs` | An RPC method and its class. |
| `src/crypto/domain_tags.rs` | A domain tag. |
| `xtask/gates/src/main.rs` | A gate module and its registry entry. |
| `.github/workflows/ci.yml` | A step in the job list. |
| `Cargo.toml` | A workspace member or a dependency-policy line. |
| `docs/audit/FINDINGS.md` | A finding, or the status of an existing one. |
| `docs/work/PACKAGES.md` | This register's own rows. |
| `config/naming/concept_map.toml` | A concept and its aliases. |
| `.github/concept-names-baseline.txt` | Nothing. The count may only fall. |

The directive names `xtask/gates/src/gates/mod.rs` as the gate registry. That file
does not exist in this tree; the modules and the registry table are declared
inline in `xtask/gates/src/main.rs`. The row above names the file that exists, so
a package looking for the append point finds it rather than creating a second
registry.

## Locks

A package's lock paths are the paths in its card's `Kilit yolları` field (section
15.3 rule 3). This register does not copy them: the card is the authority and a
second copy would drift. What the register records is who works where right now -
the `Open PRs` column - and the paths a package added to its lock with a
`LOCK-ADD` comment (section 15.3 rule 7).

## Measurements

Section 15.5 rule 4 item 4 asks for the measurement hardware next to any
measurement. The only numbers here are counts of open pull requests, taken on
2026-11-07 with `gh pr list`. They are not hardware measurements and no hardware
is claimed for them.
