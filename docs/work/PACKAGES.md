# Work packages WP-01 to WP-64

This is the package status ledger. The package ids are `WP-NN` in the tree and
on GitHub; the directive names the same packages `İP-NN`. The dependency table,
the lanes and the launch-gate flags come from the directive section 15.7. A
package starts only when every package in its "Depends on" column has merged to
`main` and none of its lock paths is held by another open package (section
15.3). `M0` to `M7` are milestones. A dependency on `M4` means every package of
milestone M4 has merged.

Tier: `T-Opening` is required for the testnet opening, `T-Expansion` enters the
live testnet through an activation height after the opening. TLG records whether
the package blocks the Testnet Launch Gate. `No (Beta)` marks a beta feature
that is not a launch condition. Lane `Cross` is an independent-review lane.

Status vocabulary:

| Status | Meaning |
|---|---|
| `merged` | the package's code is on `main` |
| `partial on main` | some of the package's work is on `main`; the card is not complete |
| `in-progress (PR #n)` | an open pull request owns the package's lock paths |
| `blocked` | a dependency or a lock path held by an open pull request prevents a start |
| `not-started` | no code, no open pull request |

This file was derived from the live branch, the live `main` history and the live
pull request list. Commit SHAs and CI run numbers are recorded by the **last**
pull request of each package (section 15.5.7). A blank evidence cell means that
no such record exists yet; it is not a claim that a check ran.

## Package table

| Package | Title | Lane | Tier | TLG | Depends on | Status | PR list | Last commit SHA | CI run | Closed findings |
|---|---|---|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Opening | Yes | None | merged | #2, #4 | | | |
| WP-02 | Live verification: storage | B | T-Opening | Yes | None | merged | #2, #4 | | | |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Opening | Yes | None | merged | #2, #4 | | | |
| WP-04 | Live verification: clients, operations, CI, documents and combined status | D | T-Opening | Yes | None | merged | #2, #4 | | | |
| WP-05 | Concept name map and counter gate | D | T-Opening | Yes | WP-04 | merged | #4, #150 | c49b76cc | | BLG-276 |
| WP-06 | Persistence and state recovery move | B | T-Opening | Yes | WP-02 | in-progress (PR #8) | #8 | | | |
| WP-07 | Removal of the legacy storage systems | B | T-Opening | Yes | WP-06 | in-progress (PR #150) | #8, #150 | 7b49d7bc | | |
| WP-08 | Validator classes and single registry | A | T-Opening | Yes | WP-01 | merged | #4 | | | |
| WP-09 | Execution environment interface | C | T-Opening | Yes | WP-03 | merged | #4 | | | |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Opening | Yes | WP-07 | partial on main | #5, #6 | | | |
| WP-11 | Mobile core and light client | D | T-Opening | Yes | WP-10, WP-12, WP-13, WP-15, WP-20 | blocked | - | | | |
| WP-12 | Committee-based finality, Instant Seat Handoff, consensus hardening | A | T-Opening | Yes | WP-08 | in-progress (PR #9) | #9 | | | |
| WP-13 | Presence protocol and suspension | A | T-Opening | Yes | WP-12 | blocked | - | | | |
| WP-14 | Instant Duty Handoff and disaster mode | A | T-Opening | Yes | WP-12, WP-13, WP-20, WP-21 | blocked | - | | | |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Opening | Yes | WP-01 | blocked | - | | | |
| WP-16 | Genesis, ceremony tool and economy | A | T-Opening | Yes | WP-08 | blocked | - | | | |
| WP-17 | State transition and chain hardening | A | T-Opening | Yes | WP-01, WP-06 | blocked | - | | | |
| WP-18 | Segmentation and RFC 6330 fountain code | B | T-Opening | Yes | WP-10 | partial on main | #5, #6 | | | |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Opening | Yes | WP-10, WP-24 | partial on main | #5, #6 | | | |
| WP-20 | Class-aware placement, retention proof and repair | B | T-Opening | Yes | WP-08, WP-18 | partial on main | #5, #6 | | | |
| WP-21 | Upload, display, `StorageTx` v3 and RPC | B | T-Opening | Yes | WP-18, WP-19, WP-20 | partial on main | #5, #6 | | | |
| WP-22 | Deduplication, reference, deletion, sealed content and permissions | B | T-Opening | Yes | WP-21 | blocked | - | | | |
| WP-23 | B.U.D. 3.0 migration of dependent modules | B | T-Opening | Yes | WP-22 | blocked | - | | | |
| WP-24 | A0 codec registry and access layer | B | T-Opening | Yes | WP-10 | in-progress (PR #8) | #6, #8 | | | |
| WP-25 | Storage fee, Retention Foundation and retention rewards | B | T-Opening | Yes | WP-16, WP-21 | blocked | - | | | |
| WP-26 | Execution Coordinator and EE workers | C | T-Opening | Yes | WP-07, WP-09 | blocked | - | | | |
| WP-27 | EVM execution environment and foreign envelope | C | T-Opening | Yes | WP-26 | blocked | - | | | |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Opening | Yes | WP-27 | blocked | - | | | |
| WP-29 | WASM (CosmWasm ABI) and Cosmos RPC subset | C | T-Opening | Yes | WP-26 | blocked | - | | | |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Opening | Yes | WP-27, WP-29 | blocked | - | | | |
| WP-31 | SVM and Solana RPC subset | C | T-Opening | Yes | WP-26 | blocked | - | | | |
| WP-32 | Move (Aptos) and Aptos REST subset | C | T-Opening | Yes | WP-26 | blocked | - | | | |
| WP-33 | BudZero execution environment and BudZero soundness | C | T-Opening | Yes | WP-26 | partial on main | #3, #4 | | | |
| WP-34 | Migration Kit | C | T-Opening | No (Beta) | WP-28 | blocked | - | | | |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Opening | Yes | WP-27, WP-29, WP-31, WP-32, WP-33 | blocked | - | | | |
| WP-36 | Android validator app | D | T-Opening | Yes | WP-11 | blocked | - | | | |
| WP-37 | Mobile device matrix and field test | D | T-Opening | Yes | WP-36 | blocked | - | | | |
| WP-38 | iOS opportunistic app | D | T-Opening | No (Beta) | WP-11 | blocked | - | | | |
| WP-39 | Wallet core and CLI | D | T-Opening | Yes | WP-08, WP-21, WP-27 | blocked | - | | | |
| WP-40 | Explorer and indexer | D | T-Opening | Yes | WP-21, WP-26 | blocked | - | | | |
| WP-41 | Faucet and operations | D | T-Opening | Yes | WP-16 | blocked | - | | | |
| WP-42 | CI, gates and supply chain | D | T-Opening | Yes | WP-04 | merged | #4, #150 | 7b49d7bc | | |
| WP-43 | Documents, README and TLG report | D | T-Opening | Yes | WP-46, WP-47, WP-48 | in-progress (PR #150) | #150 | 7b49d7bc | | |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Opening | Yes | WP-01 | in-progress | this PR | | | |
| WP-45 | Privacy, AI and account abstraction: testnet boundary | B | T-Opening | Yes | WP-22 | blocked | - | | | |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Opening | Yes | M4 | blocked | - | | | |
| WP-47 | Independent review 1: core and storage | Cross (C or D) | T-Opening | Yes | M4 | blocked | - | | | |
| WP-48 | Independent review 2: execution, mobile and clients | Cross (A or B) | T-Opening | Yes | M4 | blocked | - | | | |
| WP-49 | Universal Object Layer | A | T-Expansion | No | M7, WP-30, WP-44 | partial on main | #3, #4 | | | |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | No | WP-35 | not-started | - | | | |
| WP-51 | Cairo execution environment | C | T-Expansion | No | WP-35 | not-started | - | | | |
| WP-52 | SVM and Move pointers | C | T-Expansion | No | WP-30, WP-31, WP-32 | not-started | - | | | |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expansion | No | WP-35 | not-started | - | | | |
| WP-54 | Shared compression context, extra codecs, confidential deduplication | B | T-Expansion | No | WP-22, WP-24 | not-started | - | | | |
| WP-55 | Live streaming | B | T-Expansion | No | WP-21 | not-started | - | | | |
| WP-56 | BudZero privacy core, predicate proofs, consent and PTP-1 | B | T-Expansion | No | WP-22, WP-33 | not-started | - | | | |
| WP-57 | AI Verification Layer | A | T-Expansion | No | WP-45, WP-56 | partial on main | #3, #4 | | | |
| WP-58 | F-Droid and reproducible Android build | D | T-Expansion | No | WP-36 | not-started | - | | | |
| WP-59 | Parallel execution | C | T-Expansion | No | WP-35 | merged (before freeze) | #3, #4 | | | |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof, block batch proof | C | T-Expansion | No | WP-56 | partial on main | #3, #4 | | | |
| WP-61 | RPC and cryptography hardening | D | T-Opening | Yes | WP-01 | merged | #4 | | | |
| WP-62 | Universal Object Layer: CosmWasm and Cosmos SDK family | A | T-Expansion | No | WP-49, WP-29 | partial on main | #3, #4 | | | |
| WP-63 | Universal Object Layer: SVM family | A | T-Expansion | No | WP-49, WP-31 | partial on main | #3, #4 | | | |
| WP-64 | Universal Object Layer: Move family | A | T-Expansion | No | WP-49, WP-32 | partial on main | #3, #4 | | | |

## Why the ready packages are marked blocked

A package is ready only when its dependencies have merged **and** its lock
paths are free (section 15.3). Three packages have all their dependencies on
`main` but their lock paths are held by the two open pull requests:

| Package | Held lock path | Held by |
|---|---|---|
| WP-15 | `src/network/protocol.rs`, `src/network/proto_conversions.rs`, `src/network/node.rs` | PR #9 |
| WP-16 | `src/chain/genesis.rs` | PR #9 |
| WP-22 | `src/storage/bud3/mod.rs`, `src/storage/bud3/registry.rs` | PR #8 |

WP-44 is the smallest-numbered launch-gate package whose own lock paths are
free. This pull request delivers its first slice. The remaining slices follow
as separate pull requests, each within the 1500-line cap (section 15.5.2).

## Freeze

T-Expansion pull requests wait on their own branches until the opening (M7).
Their code is refused on the testnet chain id and opens with an activation
height. The rows above that say `partial on main` describe code that landed
before the freeze; none of it is enabled on the testnet by this ledger.

## Gate register (directive 16.3)

Directive section 16.3 lists the gates the tree must have. This table is that list, measured
against `xtask/gates/src/main.rs`, the gate module directory and `.github/workflows/` at
commit `0e31c3d7`. It records what a reader can verify rather than what a package claimed.

| Gate | Package | State | Registry name and CI |
| --- | --- | --- | --- |
| `no_legacy_storage` | WP-07 | `no-legacy-storage`, with its own CI step |
| `concept_names` | WP-05 | `concept-names`, with its own CI step |
| `canonical_programs_reproduce` | WP-06 | `canonical-programs-reproduce`, with its own CI step |
| `zkvm_refuses_untrusted_proofs` | WP-06 | `zkvm-refuses-untrusted-proofs`, with its own CI step |
| `state_recovery_door` | WP-06 | `state-recovery-door`, with its own CI step |
| `bud3_forbidden_phrases` | WP-10 | `bud3-forbidden-phrases`, canary in the whole-registry step |
| `bud3_object_is_universal` | WP-19 | **not written** |
| `bud3_qr_is_presentation` | WP-19 | **not written** |
| `bud3_placement` | WP-20 | `bud3-placement`, canary in the whole-registry step |
| `bud3_repair_fires` | WP-20 | `bud3-repair-fires`, canary in the whole-registry step |
| `bud3_custody_proofs` | WP-20 | `bud3-custody-proofs`, canary in the whole-registry step |
| `bud3_paid_view` | WP-21 | **not written** |
| `bud_e2e` | WP-21 | module only, **not registered** |
| `content_encryption_is_declared_and_bound` | WP-22 | `content-encryption-bound`, with its own CI step |
| `derived_content` | WP-24 | `derived-content-stays-byte-exact`, with its own CI step |
| `bud3_fee_uses_physical_bytes` | WP-25 | **not written** |
| `bud3_custody_rewards` | WP-25 | **not written** |
| `ee_workers_build_with_unwind` | WP-26 | `ee-workers-build-with-unwind`, canary in the whole-registry step |
| `economy_invariants` | WP-26 | module only, **not registered** |
| `classical_crypto_is_paired` | WP-27 | `classical-crypto-is-paired`, with its own CI step |
| `explorer_parity` | WP-40 | `explorer-parity`, with its own CI step |
| `explorer_patchset` | WP-40 | `explorer-patchset`, with its own CI step |
| `no_float_in_consensus_paths` | WP-42 | `no-float-in-consensus-paths`, with its own CI step |
| `workflows_cover_every_workspace` | WP-42 | `workflows-cover-every-workspace`, with its own CI step |
| `readme_definition_block_is_verbatim` | WP-43 | `readme-definition-block-is-verbatim`, with its own CI step |
| `readme_has_no_placeholders` | WP-43 | `readme-has-no-placeholders`, with its own CI step |
| `readme_claims_are_wired` | WP-43 | **not written** |
| `proof_class_matches_witness` | WP-56 | **not written** |
| `no_64bit_commitments` | WP-56 | **not written** |
| `no_witness_in_public_inputs` | WP-56 | **not written** |
| `commitments_carry_hash_suite` | WP-56 | **not written** |
| `privacy_claims_cite_tests` | WP-56 | **not written** |
| `no_unconstrained_air_columns` | WP-56 | **not written** |
| `key_release_needs_consent_proof` | WP-56 | **not written** |
| `consent_records_have_no_open_identities` | WP-56 | **not written** |

21 of 35 gates are present. Not written: `bud3_object_is_universal`, `bud3_qr_is_presentation`, `bud3_paid_view`, `bud3_fee_uses_physical_bytes`, `bud3_custody_rewards`, `readme_claims_are_wired`, `proof_class_matches_witness`, `no_64bit_commitments`, `no_witness_in_public_inputs`, `commitments_carry_hash_suite`, `privacy_claims_cite_tests`, `no_unconstrained_air_columns`, `key_release_needs_consent_proof`, `consent_records_have_no_open_identities`.

Seven gates that section 16.3 retires were deleted in `8e93b507` and five were renamed in
`c2047d49`; both changes are recorded in the pull request for this branch, and the old names
do not appear in this table because they are gone from the tree.
