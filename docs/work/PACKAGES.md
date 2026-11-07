# Work Package Registry

The register of the 64 work packages of the binding directive, in the repository
language. Section 15.5 item 7 makes this file the status record of every package:
one row per package, carrying the card's fixed fields plus the evidence this
repository can show for it.

Measured on 2026-11-07 on a branch based on `main` at `20140e87`. The directive
itself is not part of this tree (directive 0.1 item 5), so the package identity,
lane, layer, Testnet Launch Gate flag, dependency, milestone and closing-finding
count below are the directive's own fields. The remaining columns are measured on
the tree, not copied from a card.

## How the live columns are produced

- **Card paths present** is the number of the lock paths the card names that exist
  in this tree, over the number it names. It is a fact about the tree, not a
  verdict on the package.
- **Tree status** is that fact in words: `none present`, `some present`, `all
  present`, or `card without lock paths` for the four packages whose card names no
  lock path this file could read.
- **Closing findings** is the count of finding identities the card claims.
- **Open pull requests** lists the open pull requests whose title names the
  package, as measured on 2026-11-07. A package with `none` has no open pull
  request that names it.

Two readings are inverted on purpose and must not be taken as progress. WP-07 and
WP-23 are removal packages: their cards name paths that must *stop* existing, so a
present path there is work not done, and the row says so.

No package is marked complete. Directive 15.5 item 10 requires a final commit SHA
and a CI run number for that claim, and directive 0.3 item 5 says self-declaration
is not evidence.

## Summary

| Tree status | Packages |
|---|---|
| none present | 29 |
| some present | 31 |
| all present | 4 |
| total | 64 |

## Registry

| WP | Title | Lane | Layer | TLG | Depends on | Milestone | Card paths present | Closing findings | Open pull requests | Tree status |
|---|---|---|---|---|---|---|---|---|---|---|
| WP-01 | Live validation: core | A | T-Launch | yes | none | M0 | 0/2 | 0 | #123, #124, #125, #129, #131 | none present |
| WP-02 | Live validation: storage | B | T-Launch | yes | none | M0 | 0/2 | 0 | #117 | none present |
| WP-03 | Live validation: execution, BudZero, domains, privacy, AI | C | T-Launch | yes | none | M0 | 0/3 | 0 | #129 | none present |
| WP-04 | Live validation: clients, operations, CI, documents and the combined status | D | T-Launch | yes | none | M0 | 2/5 | 0 | #75, #77, #96, #118, #129 | some present |
| WP-05 | Concept-name map and counter gate | D | T-Launch | yes | WP-04 | M1 | 2/4 | 1 | #24, #120, #122, #126, #127, #135 | some present |
| WP-06 | Persistence and state-recovery move | B | T-Launch | yes | WP-02 | M1 | 12/14 | 0 | #60, #84 | some present |
| WP-07 | Removal of the legacy storage systems | B | T-Launch | yes | WP-06 | M1 | 15/18 | 27 | #69, #71, #104 | some present (removal package: a present path is work not done) |
| WP-08 | Validator classes and the single registry | A | T-Launch | yes | WP-01 | M1 | 5/6 | 4 | #40 | some present |
| WP-09 | Execution-environment interface | C | T-Launch | yes | WP-03 | M1 | 0/2 | 0 | #36, #38, #54, #64, #80 | none present |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | yes | WP-07 | M2 | 0/5 | 0 | #56 | none present |
| WP-11 | Mobile core and light client | D | T-Launch | yes | WP-10, WP-12, WP-13, WP-15, WP-20 | M4 | 1/3 | 3 | #44, #82, #85, #88, #91 | some present |
| WP-12 | Committee-based finality, instant seat transfer, consensus hardening | A | T-Launch | yes | WP-08 | M2 | 4/5 | 23 | #81 | some present |
| WP-13 | Presence protocol and suspension | A | T-Launch | yes | WP-12 | M3 | 3/5 | 1 | #45, #70 | some present |
| WP-14 | Instant Duty Transfer and disaster mode | A | T-Launch | yes | WP-12, WP-13, WP-20, WP-21 | M4 | 1/5 | 0 | none | some present |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Launch | yes | WP-01 | M2 | 3/4 | 6 | #48 | some present |
| WP-16 | Genesis, ceremony tool and economy | A | T-Launch | yes | WP-08 | M3 | 7/7 | 13 | #34, #37, #39, #52 | all present |
| WP-17 | State transition and chain hardening | A | T-Launch | yes | WP-01, WP-06 | M2 | 7/8 | 44 | #62, #66, #67, #133, #134 | some present |
| WP-18 | Segmentation and the RFC 6330 fountain code | B | T-Launch | yes | WP-10 | M3 | 2/5 | 2 | #47 | some present |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Launch | yes | WP-10, WP-24 | M3 | 14/23 | 10 | #45, #55 | some present |
| WP-20 | Class-aware placement, custody proof and repair | B | T-Launch | yes | WP-08, WP-18 | M3 | 2/13 | 1 | #13, #59 | some present |
| WP-21 | Upload, view, StorageTx v3 and RPC | B | T-Launch | yes | WP-18, WP-19, WP-20 | M3 | 12/20 | 4 | #57, #105 | some present |
| WP-22 | Deduplication, reference, delete, sealed content and grants | B | T-Launch | yes | WP-21 | M3 | 5/11 | 5 | #45 | some present |
| WP-23 | Dependent modules moved to B.U.D. 3.0 | B | T-Launch | yes | WP-22 | M4 | 6/9 | 7 | #36 | some present (removal package: a present path is work not done) |
| WP-24 | A0 codec registry and access layer | B | T-Launch | yes | WP-10 | M3 | 5/9 | 4 | #65 | some present |
| WP-25 | Storage fee, Custody Fund and custody rewards | B | T-Launch | yes | WP-16, WP-21 | M4 | 2/5 | 1 | #40, #45 | some present |
| WP-26 | Execution Coordinator and EE workers | C | T-Launch | yes | WP-07, WP-09 | M2 | 5/7 | 4 | #24, #36 | some present |
| WP-27 | EVM execution environment and the foreign envelope | C | T-Launch | yes | WP-26 | M3 | 1/4 | 1 | #78 | some present |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Launch | yes | WP-27 | M4 | 0/2 | 1 | #56, #72, #75, #76 | none present |
| WP-29 | WASM (CosmWasm ABI) and the Cosmos RPC subset | C | T-Launch | yes | WP-26 | M3 | 0/3 | 1 | none | none present |
| WP-30 | Universal Call and the Universal Asset Registry | C | T-Launch | yes | WP-27, WP-29 | M4 | 0/5 | 0 | none | none present |
| WP-31 | SVM and the Solana RPC subset | C | T-Launch | yes | WP-26 | M4 | 0/3 | 1 | #51, #83 | none present |
| WP-32 | Move (Aptos) and the Aptos REST subset | C | T-Launch | yes | WP-26 | M4 | 0/4 | 1 | #89 | none present |
| WP-33 | BudZero execution environment and BudZero soundness | C | T-Launch | yes | WP-26 | M3 | 2/4 | 22 | #24 | some present |
| WP-34 | Migration Kit | C | T-Launch | no | WP-28 | not a milestone | 0/3 | 0 | #46, #61 | none present |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Launch | yes | WP-27, WP-29, WP-31, WP-32, WP-33 | M4 | 0/3 | 0 | #24, #36, #79 | none present |
| WP-36 | Android validator application | D | T-Launch | yes | WP-11 | M4 | 0/2 | 2 | #92, #97 | none present |
| WP-37 | Mobile device matrix and field test | D | T-Launch | yes | WP-36 | M4 | 0/3 | 0 | #92 | none present |
| WP-38 | iOS opportunistic application | D | T-Launch | no | WP-11 | not a milestone | 0/2 | 0 | #100 | none present |
| WP-39 | Wallet core and CLI | D | T-Launch | yes | WP-08, WP-21, WP-27 | M4 | 5/6 | 4 | #132, #135 | some present |
| WP-40 | Explorer and indexer | D | T-Launch | yes | WP-21, WP-26 | M4 | 4/5 | 4 | #73 | some present |
| WP-41 | Faucet and operations | D | T-Launch | yes | WP-16 | M4 | 4/4 | 5 | #34, #52, #58, #59 | all present |
| WP-42 | CI, gates and supply chain | D | T-Launch | yes | WP-04 | M2 | 6/7 | 32 | #24, #29, #30, #42, #63, #74, #75, #93, #95, #96, #98, #101, #103, #104, #106, #107, #109, #116, #119, #120, #121, #122, #129, #130, #132, #135 | some present |
| WP-43 | Documents, README and the TLG report | D | T-Launch | yes | WP-46, WP-47, WP-48 | M6 | 7/10 | 8 | #51 | some present |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Launch | yes | WP-01 | M4 | 9/11 | 29 | #14 | some present |
| WP-45 | Privacy, AI and account abstraction: the testnet boundary | B | T-Launch | yes | WP-22 | M4 | 9/9 | 31 | #44, #49, #128 | all present |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Launch | yes | M4 | M5 | 0/3 | 1 | #92, #99, #102 | none present |
| WP-47 | Independent review 1: core and storage | cross (C or D) | T-Launch | yes | M4 | M5 | 0/1 | 0 | #56 | none present |
| WP-48 | Independent review 2: execution, mobile and clients | cross (A or B) | T-Launch | yes | M4 | M5 | 0/1 | 0 | #36, #43, #100 | none present |
| WP-49 | Universal Object Layer | A | T-Expansion | no | M7, WP-30, WP-44 | after M7 | 5/8 | 0 | none | some present |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | no | WP-35 | after M7 | 0/2 | 0 | none | none present |
| WP-51 | Cairo execution environment | C | T-Expansion | no | WP-35 | after M7 | 0/2 | 0 | none | none present |
| WP-52 | SVM and Move pointers | C | T-Expansion | no | WP-30, WP-31, WP-32 | after M7 | 0/3 | 0 | none | none present |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | C | T-Expansion | no | WP-35 | after M7 | 0/5 | 0 | none | none present |
| WP-54 | Shared compression context, extra codecs, confidential deduplication | B | T-Expansion | no | WP-22, WP-24 (the confidential deduplication slice is also WP-56) | after M7 | 0/3 | 0 | none | none present |
| WP-55 | Live stream | B | T-Expansion | no | WP-21 | after M7 | 0/2 | 0 | #86 | none present |
| WP-56 | BudZero privacy core, predicate proofs, consent and PTP-1 | B | T-Expansion | no | WP-22, WP-33 | after M7 | 7/12 | 11 | none | some present |
| WP-57 | AI Verification Layer | A | T-Expansion | no | WP-45, WP-56 | after M7 | 4/4 | 5 | none | all present |
| WP-58 | F-Droid and a reproducible Android build | D | T-Expansion | no | WP-36 | after M7 | 0/2 | 0 | none | none present |
| WP-59 | Parallel execution | C | T-Expansion | no | WP-35 | after M7 | 0/1 | 0 | none | none present |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof, block aggregate proof | C | T-Expansion | no | WP-56 | after M7 | 6/7 | 4 | none | some present |
| WP-61 | RPC and cryptography hardening | D | T-Launch | yes | WP-01 | M2 | 2/3 | 13 | #34, #41, #53 | some present |
| WP-62 | Universal Object Layer: the CosmWasm and Cosmos SDK family | A | T-Expansion | no | WP-49, WP-29 | after M7 | 0/2 | 0 | none | none present |
| WP-63 | Universal Object Layer: the SVM family | A | T-Expansion | no | WP-49, WP-31 | after M7 | 0/2 | 0 | none | none present |
| WP-64 | Universal Object Layer: the Move family | A | T-Expansion | no | WP-49, WP-32 | after M7 | 0/2 | 0 | #131 | none present |

## Card paths this tree does not have

The same measurement read the other way round: the paths a card names that no commit
has created. For an addition package these are the paths the package still has to
create; for WP-07 and WP-23 they are the paths that are already gone.

| WP | Missing card paths |
|---|---|
| WP-01 | `docs/audit/live/lane-a.md`, `src/tests/audit_lane_a.rs` |
| WP-02 | `docs/audit/live/lane-b.md`, `src/tests/audit_lane_b.rs` |
| WP-03 | `docs/audit/live/lane-c.md`, `src/tests/audit_lane_c.rs`, `budzero/tests/audit_lane_c.rs` |
| WP-04 | `docs/audit/live/lane-d.md`, `docs/audit/FINDINGS.md`, `src/tests/audit_lane_d.rs` |
| WP-05 | `xtask/gates/src/gates/concept_names.rs`, `.github/concept-names-baseline.txt` |
| WP-06 | `src/persistence/`, `src/chain/state_recovery/` |
| WP-07 | `crates/bud-codec/`, `tests/vectors/bud3/corpus/`, `docs/STORAGE.md` |
| WP-08 | `src/validators/` |
| WP-09 | `crates/uel-abi/`, `proto/budlum/execution/v1/ee.proto` |
| WP-10 | `src/storage/bud3/`, `crates/bud-codec/`, `proto/budlum/storage/v3/bud3.proto`, `tests/vectors/bud3/`, `xtask/gates/src/gates/bud3_forbidden_phrases.rs` |
| WP-11 | `mobile/core/`, `crates/budlum-types/` |
| WP-12 | `src/validators/committee.rs` |
| WP-13 | `src/validators/presence.rs`, `/budlum/presence/1` |
| WP-14 | `src/validators/handover.rs`, `src/storage/bud3/custody.rs`, `src/storage/bud3/repair.rs`, `tests/churn/` |
| WP-15 | `config/*.toml` |
| WP-17 | `src/persistence/` |
| WP-18 | `src/storage/bud3/segment.rs`, `src/storage/bud3/fountain.rs`, `tests/vectors/bud3/fountain/` |
| WP-19 | `src/storage/bud3/object.rs`, `src/storage/bud3/bof1.rs`, `src/storage/bud3/frame.rs`, `src/storage/bud3/qr.rs`, `src/storage/bud3/video.rs`, `src/storage/bud3/two_path.rs`, `tests/vectors/bud3/bof1/`, `xtask/gates/src/gates/bud3_object_is_universal.rs`, `xtask/gates/src/gates/bud3_qr_is_presentation.rs` |
| WP-20 | `src/storage/bud3/placement.rs`, `src/storage/bud3/custody.rs`, `src/storage/bud3/repair.rs`, `src/storage/bud3/maintenance.rs`, `src/storage/bud3/symbol_protocol.rs`, `xtask/tools/src/placement_table.rs`, `tests/vectors/bud3/placement/`, `tests/vectors/bud3/custody/`, `xtask/gates/src/gates/bud3_placement.rs`, `xtask/gates/src/gates/bud3_repair_fires.rs`, `xtask/gates/src/gates/bud3_custody_proofs.rs` |
| WP-21 | `src/storage/bud3/upload.rs`, `src/storage/bud3/view.rs`, `src/storage/bud3/volume.rs`, `src/storage/bud3/tx.rs`, `src/storage/bud3/rpc.rs`, `src/storage/bud3/content_gateway.rs`, `src/storage/bud3/content_ref.rs`, `xtask/gates/src/gates/bud3_paid_view.rs` |
| WP-22 | `src/storage/bud3/dedup.rs`, `src/storage/bud3/refcount.rs`, `src/storage/bud3/delete.rs`, `src/storage/bud3/seal.rs`, `src/storage/bud3/keys.rs`, `src/storage/bud3/grants.rs` |
| WP-23 | `src/data_market/`, `src/education_domain/`, `src/app_registry/` |
| WP-24 | `crates/bud-codec/`, `src/storage/bud3/access_tiering.rs`, `src/storage/bud3/replace.rs`, `tests/vectors/bud3/codec/` |
| WP-25 | `src/storage/bud3/fees.rs`, `xtask/gates/src/gates/bud3_fee_uses_physical_bytes.rs`, `xtask/gates/src/gates/bud3_custody_rewards.rs` |
| WP-26 | `src/execution/coordinator/`, `execution/` |
| WP-27 | `execution/evm/`, `src/execution/coordinator/foreign/`, `contracts/uel/` |
| WP-28 | `src/rpc/compat/ethereum/`, `config/*.toml` |
| WP-29 | `execution/wasm/`, `src/execution/coordinator/foreign/cosmos.rs`, `src/rpc/compat/cosmos/` |
| WP-30 | `src/execution/coordinator/universal_call.rs`, `src/execution/coordinator/assets/`, `execution/evm/src/precompile_universal.rs`, `execution/wasm/src/budlum_msg.rs`, `contracts/uel/` |
| WP-31 | `execution/svm/`, `src/execution/coordinator/foreign/solana.rs`, `src/rpc/compat/solana/` |
| WP-32 | `execution/move/`, `src/execution/coordinator/foreign/aptos.rs`, `src/rpc/compat/aptos/`, `execution/move/deny.toml` |
| WP-33 | `execution/budzero/`, `src/execution/budzero_ee/` |
| WP-34 | `src/cross_domain/evm/account_proof.rs`, `src/execution/coordinator/migration/`, `src/bin/bud-migrate.rs` |
| WP-35 | `execution/conformance/`, `.github/workflows/conformance-nightly.yml`, `docs/EXECUTION_LIMITS.md` |
| WP-36 | `mobile/android/`, `.github/workflows/mobile.yml` |
| WP-37 | `mobile/android/devicetests/`, `mobile/tools/log-analyzer/`, `docs/MOBILE_DEVICE_MATRIX.md` |
| WP-38 | `mobile/ios/`, `.github/workflows/mobile-ios.yml` |
| WP-39 | `src/project_manifest.rs` |
| WP-40 | `crates/budlum-explorer/` |
| WP-42 | `deny.toml` |
| WP-43 | `xtask/gates/src/gates/readme_definition_block_is_verbatim.rs`, `xtask/gates/src/gates/readme_has_no_placeholders.rs`, `xtask/gates/src/gates/readme_claims_are_wired.rs` |
| WP-44 | `docs/SHARED_SECURITY.md`, `docs/APP_BINDING.md` |
| WP-46 | `ops/rehearsal/`, `docs/rehearsal/`, `config/rehearsal-genesis.json` |
| WP-47 | `docs/audit/REVIEW_1.md` |
| WP-48 | `docs/audit/REVIEW_2.md` |
| WP-49 | `src/object_layer/`, `contracts/object-layer/`, `src/sdk/object_layer/` |
| WP-50 | `execution/move-sui/`, `src/rpc/compat/sui/` |
| WP-51 | `execution/cairo/`, `src/rpc/compat/starknet/` |
| WP-52 | `src/execution/coordinator/assets/`, `execution/svm/src/pointer/`, `execution/move/src/pointer/` |
| WP-53 | `execution/near/`, `execution/polkavm/`, `execution/tvm/`, `execution/utxo/`, `execution/plutus/` |
| WP-54 | `crates/bud-codec/`, `src/storage/bud3/compression_context.rs`, `src/storage/bud3/private_dedup.rs` |
| WP-55 | `src/storage/bud3/live.rs`, `src/storage/bud3/bof1.rs` |
| WP-56 | `budzero/predicates/`, `src/storage/bud3/seal.rs`, `src/storage/bud3/grants.rs`, `src/storage/bud3/consent.rs`, `src/storage/bud3/escrow.rs` |
| WP-58 | `mobile/android/fdroid/`, `mobile/android/build.gradle.kts` |
| WP-59 | `src/execution/coordinator/scheduler/` |
| WP-60 | `budzero/bud-sigagg/` |
| WP-61 | `compat/` |
| WP-62 | `src/object_layer/family/<aile>.rs`, `contracts/object-layer/<aile>/` |
| WP-63 | `src/object_layer/family/<aile>.rs`, `contracts/object-layer/<aile>/` |
| WP-64 | `src/object_layer/family/<aile>.rs`, `contracts/object-layer/<aile>/` |

## What this registry does not contain

1. No completion claim and no CI run number for any package: no package has the
   evidence the directive asks for.
2. No GitHub record per package. This repository has issues disabled, so directive
   15.3 item 1 (one record per package) cannot be satisfied here; the register in
   the tree is the only record. The blocked step is recorded in
   `docs/audit/LIVE_STATUS.md`.
3. No finding-level status. That belongs to `docs/audit/FINDINGS.md`, which this
   tree does not have; the gap is recorded in `docs/audit/LIVE_STATUS.md`.
