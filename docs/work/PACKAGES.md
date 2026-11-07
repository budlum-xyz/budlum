# Work package registry

Status of the 64 work packages of the binding directive, kept in the
repository because the directive itself does not enter it (section 0.1.5).
`WP-NN` here is the directive's `IP-NN`: same package, English identifier,
the form the repository and GitHub use (section 15.3.1).

Each row carries the package's lane, layer, Testnet Launch Gate (TLG)
obligation, dependencies, milestone, the pull requests that carry it today
and its status. The rule that keeps this file honest is section 15.5.7:
the final pull request of a package updates the row with the package state,
the PR list, the last commit SHA, the CI run numbers and the findings it
closes. A row without a merged PR is not a finished package, whatever the
PR says.

## Status vocabulary

| Status | Meaning |
|---|---|
| `not started` | No pull request references the package in its title. |
| `in progress` | At least one open pull request references the package. Not merged, not proved. |
| `blocked` | The package hit a stop condition and a stop report exists. The row names the blocker. |
| `merged` | The final pull request is merged and the close-out evidence is cited in the row. |

A row marked `merged` must cite the last commit SHA and the CI run number.
Self-declaration is not evidence (section 0.3.5). The registry was last
reconciled against the live pull-request stack on 2026-11-07.

## Registry

| WP | Package | Lane | Layer | TLG | Depends on | Milestone | Live PRs | Status |
|---|---|---|---|---|---|---|---|---|
| WP-01 | Live validation: core | A | T-Launch | Yes | None | M0 | #129 (slice 1/N) | in progress |
| WP-02 | Live validation: storage | B | T-Launch | Yes | None | M0 | #117 (draft) | in progress |
| WP-03 | Live validation: execution, BudZero, domains, privacy, AI | C | T-Launch | Yes | None | M0 | #129 (slice 1/N) | in progress |
| WP-04 | Live validation: clients, operations, CI, docs and the combined state | D | T-Launch | Yes | None | M0 | #75, #77, #96, #118 | in progress |
| WP-05 | Concept name map and counter gate | D | T-Launch | Yes | WP-04 | M1 | #24, #120, #122 | in progress |
| WP-06 | Persistence and state-recovery migration | B | T-Launch | Yes | WP-02 | M1 | #60, #84 | in progress |
| WP-07 | Removal of the legacy storage systems | B | T-Launch | Yes | WP-06 | M1 | #69, #71, #104 | in progress |
| WP-08 | Validator classes and the single registry | A | T-Launch | Yes | WP-01 | M1 | #40 | in progress |
| WP-09 | Execution environment interface | C | T-Launch | Yes | WP-03 | M1 | #36, #38, #54, #64, #80 | in progress |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | Yes | WP-07 | M2 | #56 | in progress |
| WP-11 | Mobile core and light client | D | T-Launch | Yes | WP-10, WP-12, WP-13, WP-15, WP-20 | M4 | #44, #82, #85, #88, #91 | in progress |
| WP-12 | Committee-based finality, Instant Seat Handover and consensus hardening | A | T-Launch | Yes | WP-08 | M2 | #81 | in progress |
| WP-13 | Asset protocol and suspension | A | T-Launch | Yes | WP-12 | M3 | #45, #70 | in progress |
| WP-14 | Instant Duty Handover and disaster mode | A | T-Launch | Yes | WP-12, WP-13, WP-20, WP-21 | M4 | - | not started |
| WP-15 | Network: NAT traversal and P2P hardening | A | T-Launch | Yes | WP-01 | M2 | #48 | in progress |
| WP-16 | Genesis, ceremony tool and economy | A | T-Launch | Yes | WP-08 | M3 | #34, #37 (draft), #39, #52 | in progress |
| WP-17 | State transition and chain hardening | A | T-Launch | Yes | WP-01, WP-06 | M2 | #62, #66, #67 | in progress |
| WP-18 | Segmentation and the RFC 6330 fountain code | B | T-Launch | Yes | WP-10 | M3 | #47 | in progress |
| WP-19 | BOF-1 object format, QR presentation and video commitment | B | T-Launch | Yes | WP-10, WP-24 | M3 | #45, #55 | in progress |
| WP-20 | Class-sensitive placement, custody proof and repair | B | T-Launch | Yes | WP-08, WP-18 | M3 | #13, #59 | in progress |
| WP-21 | Upload, view, StorageTx v3 and RPC | B | T-Launch | Yes | WP-18, WP-19, WP-20 | M3 | #57, #105 | in progress |
| WP-22 | Deduplication, reference, deletion, sealed content and permissions | B | T-Launch | Yes | WP-21 | M3 | #45 | in progress |
| WP-23 | Migration of the dependent modules to B.U.D. 3.0 | B | T-Launch | Yes | WP-22 | M4 | #36 | in progress |
| WP-24 | A0 codec registry and access layer | B | T-Launch | Yes | WP-10 | M3 | #65 | in progress |
| WP-25 | Storage fee, Retention Fund and custody rewards | B | T-Launch | Yes | WP-16, WP-21 | M4 | #40, #45 | in progress |
| WP-26 | Execution Coordinator and EE workers | C | T-Launch | Yes | WP-07, WP-09 | M2 | #24, #36 | in progress |
| WP-27 | EVM execution environment and the foreign envelope | C | T-Launch | Yes | WP-26 | M3 | #78 | in progress |
| WP-28 | Ethereum JSON-RPC gateway | C | T-Launch | Yes | WP-27 | M4 | #56, #72, #75, #76 | in progress |
| WP-29 | WASM (CosmWasm ABI) and the Cosmos RPC subset | C | T-Launch | Yes | WP-26 | M3 | - | not started |
| WP-30 | Universal Call and the Universal Asset Registry | C | T-Launch | Yes | WP-27, WP-29 | M4 | - | not started |
| WP-31 | SVM and the Solana RPC subset | C | T-Launch | Yes | WP-26 | M4 | #51, #83 | in progress |
| WP-32 | Move (Aptos dialect) and the Aptos REST subset | C | T-Launch | Yes | WP-26 | M4 | #89 | in progress |
| WP-33 | BudZero execution environment and BudZero robustness | C | T-Launch | Yes | WP-26 | M3 | #24 | in progress |
| WP-34 | Migration Kit | C | T-Launch | No (Beta) | WP-28 | Not a condition | #46, #61 | in progress |
| WP-35 | Conformance, gas calibration and cross-architecture | C | T-Launch | Yes | WP-27, WP-29, WP-31, WP-32, WP-33 | M4 | #24, #36, #79 | in progress |
| WP-36 | Android validator application | D | T-Launch | Yes | WP-11 | M4 | #92, #97 (draft) | in progress |
| WP-37 | Mobile device matrix and field test | D | T-Launch | Yes | WP-36 | M4 | #92 | in progress |
| WP-38 | iOS opportunistic application | D | T-Launch | No (Beta) | WP-11 | Not a condition | #100 | in progress |
| WP-39 | Wallet core and CLI | D | T-Launch | Yes | WP-08, WP-21, WP-27 | M4 | - | not started |
| WP-40 | Explorer and indexer | D | T-Launch | Yes | WP-21, WP-26 | M4 | #73 | in progress |
| WP-41 | Faucet and operations | D | T-Launch | Yes | WP-16 | M4 | #34, #52, #58, #59 | in progress |
| WP-42 | CI, gates and supply chain | D | T-Launch | Yes | WP-04 | M2 | #24, #29, #30, #42, #63, #74, #75, #93, #95, #96, #98, #101, #103, #104, #106, #107, #109, #116, #119, #120, #121, #122 | in progress |
| WP-43 | Documentation, README and the TLG report | D | T-Launch | Yes | WP-46, WP-47, WP-48 | M6 | #51 | in progress |
| WP-44 | Domains, bridge, settlement and contracts | A | T-Launch | Yes | WP-01 | M4 | #14 | in progress |
| WP-45 | Privacy, AI and account abstraction: the testnet boundary | B | T-Launch | Yes | WP-22 | M4 | #44, #49 | in progress |
| WP-46 | Ceremony rehearsal, rehearsal network and measurements | D | T-Launch | Yes | M4 | M5 | #92, #99, #102 (draft) | in progress |
| WP-47 | Independent review 1: core and storage | Cross (C or D) | T-Launch | Yes | M4 | M5 | #56 | in progress |
| WP-48 | Independent review 2: execution, mobile and clients | Cross (A or B) | T-Launch | Yes | M4 | M5 | #36, #43, #100 | in progress |
| WP-49 | Universal Object Layer | A | T-Expansion | No | M7, WP-30, WP-44 | - | - | not started |
| WP-50 | Move (Sui dialect) execution environment | C | T-Expansion | No | WP-35 | - | - | not started |
| WP-51 | Cairo execution environment | C | T-Expansion | No | WP-35 | - | - | not started |
| WP-52 | SVM and Move pointers | C | T-Expansion | No | WP-30, WP-31, WP-32 | - | - | not started |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO script and Plutus | C | T-Expansion | No | WP-35 | - | - | not started |
| WP-54 | Shared compression context, extra codecs and confidential deduplication | B | T-Expansion | No | WP-22, WP-24 (confidential dedup part is WP-56) | - | - | not started |
| WP-55 | Live streaming | B | T-Expansion | No | WP-21 | - | #86 | in progress |
| WP-56 | BudZero privacy core, witness proofs, consent and PTP-1 | B | T-Expansion | No | WP-22, WP-33 | - | - | not started |
| WP-57 | AI Verification Layer | A | T-Expansion | No | WP-45, WP-56 | - | - | not started |
| WP-58 | F-Droid and the reproducible Android build | D | T-Expansion | No | WP-36 | - | - | not started |
| WP-59 | Parallel execution | C | T-Expansion | No | WP-35 | - | - | not started |
| WP-60 | BudZero recursion, RV32, precompiles, domain finality proof and block aggregate proof | C | T-Expansion | No | WP-56 | - | - | not started |
| WP-61 | RPC and cryptography hardening | D | T-Launch | Yes | WP-01 | M2 | #34, #41, #53 | in progress |
| WP-62 | Universal Object Layer: the CosmWasm and Cosmos SDK family | A | T-Expansion | No | WP-49, WP-29 | - | - | not started |
| WP-63 | Universal Object Layer: the SVM family | A | T-Expansion | No | WP-49, WP-31 | - | - | not started |
| WP-64 | Universal Object Layer: the Move family | A | T-Expansion | No | WP-49, WP-32 | - | - | not started |

## Lock paths

Section 15.3 makes the lock paths of an open package binding: another
package does not change a locked path while the package is open. The paths
are kept here verbatim so that the rule survives the directive leaving the
tree. A package with no entry locks only what its pull requests touch.

- **WP-01**: `docs/audit/live/lane-a.md`, `src/tests/audit_lane_a.rs`
- **WP-02**: `docs/audit/live/lane-b.md`, `src/tests/audit_lane_b.rs`
- **WP-03**: `docs/audit/live/lane-c.md`, `src/tests/audit_lane_c.rs`, `budzero/tests/audit_lane_c.rs`
- **WP-04**: `docs/audit/live/lane-d.md`, `docs/audit/LIVE_STATUS.md`, `docs/audit/FINDINGS.md`, `docs/work/PACKAGES.md`, `src/tests/audit_lane_d.rs`
- **WP-05**: `config/naming/concept_map.toml`, `xtask/gates/src/gates/concept_names.rs`, `.github/concept-names-baseline.txt`, `docs/NAMING.md`
- **WP-06**: `src/storage/{db,traits,merkle_trie,pruning,witness_retention}.rs`, `src/persistence/`, `src/domain/{regeneration_stage,regen_health,regen_mempool}.rs`, `src/network/regen_health_tick.rs`, `src/chain/state_recovery/`, `xtask/gates/src/gates/{regeneration,zkvm_immune_regeneration,regen_health_door}.rs`
- **WP-07**: `bud/`, `budzero/bud-node/`, `src/storage/`, `src/domain/{storage_deal,storage_params,deal_open,storage_tx}.rs`, `src/chain/{storage_economics_tests,storage_maintenance}.rs`, `src/execution/executor.rs`, `StorageTx`, `src/rpc/server.rs`, `proto/budlum/network/protocol.proto`, `xtask/gates/src/gates/`, `crates/bud-codec/`, `tests/vectors/bud3/corpus/`, `docs/BUD_STORAGE_ROADMAP.md`, `docs/BUD_CONTENT_ENCRYPTION.md`, `docs/STORAGE.md`
- **WP-08**: `src/validators/`, `src/registry/{role,permissionless}.rs`, `src/core/account.rs`, `src/core/chain_config.rs`, `min_stake`, `src/mempool/`
- **WP-09**: `crates/uel-abi/`, `proto/budlum/execution/v1/ee.proto`
- **WP-10**: `src/storage/bud3/`, `crates/bud-codec/`, `proto/budlum/storage/v3/bud3.proto`, `tests/vectors/bud3/`, `xtask/gates/src/gates/bud3_forbidden_phrases.rs`
- **WP-11**: `mobile/core/`, `crates/budlum-types/`, `src/light_client/`
- **WP-12**: `src/consensus/`, `src/chain/finality.rs`, `src/chain/blockchain.rs`, `src/security/`, `src/validators/committee.rs`
- **WP-13**: `src/validators/presence.rs`, `src/registry/liveness.rs`, `src/network/`, `/budlum/presence/1`, `src/chain/blockchain.rs`
- **WP-14**: `src/validators/handover.rs`, `src/storage/bud3/{custody,repair}.rs`, `src/consensus/pos.rs`, `tests/churn/`
- **WP-15**: `src/network/`, `Cargo.toml`, `config/*.toml`, `[relay]`, `src/core/chain_config.rs`, `SecurityConfig`
- **WP-16**: `src/chain/genesis.rs`, `src/tokenomics/`, `config/testnet-genesis.json`, `config/testnet.toml`, `config/archive.toml`, `xtask/tools/src/`, `testnet-genesis`, `src/registry/`
- **WP-17**: `src/chain/`, `src/core/`, `src/mempool/`, `src/execution/executor.rs`, `src/sharding/`, `src/main.rs`, `src/persistence/`, `src/tests/`
- **WP-18**: `src/storage/bud3/{segment,fountain}.rs`, `src/storage/qr_carousel.rs`, `tests/vectors/bud3/fountain/`, `Cargo.toml`, `raptorq`
- **WP-19**: `src/storage/bud3/{object,bof1,frame,qr,video,two_path}.rs`, `src/storage/{qr_payload,qr_recipe,three_recipe,qr_reemit,emit,three_pipe,qr_frame,qr_encode,qr_matrix,qr_png,qr_receive,qr_verify,qr_verify_indep,qr_video}.rs`, `tests/vectors/bud3/bof1/`, `xtask/gates/src/gates/{bud3_object_is_universal,bud3_qr_is_presentation}.rs`
- **WP-20**: `src/storage/bud3/{placement,custody,repair,maintenance,symbol_protocol}.rs`, `src/storage/assignment.rs`, `xtask/tools/src/placement_table.rs`, `config/testnet-genesis.json`, `placement_table`, `tests/vectors/bud3/{placement,custody}/`, `xtask/gates/src/gates/{bud3_placement,bud3_repair_fires,bud3_custody_proofs}.rs`
- **WP-21**: `src/storage/bud3/{upload,view,volume,tx,rpc,content_gateway}.rs`, `src/storage/bud3/content_ref.rs`, `src/storage/{three_nft,three_rpc,three_reveal,reveal_gateway,three_gate,three_hooks,three_meter,three_visibility,content_id}.rs`, `src/domain/storage_tx.rs`, `src/rpc/`, `xtask/gates/src/gates/{bud3_paid_view,bud_e2e}.rs`
- **WP-22**: `src/storage/bud3/{dedup,refcount,delete,seal,keys,grants}.rs`, `src/storage/{key_package,payload_crypt,view_grant,social_delete}.rs`, `xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs`
- **WP-23**: `src/bns/`, `src/socialfi/`, `src/pollen/`, `src/data_market/`, `src/deed/`, `src/education_domain/`, `src/budlumxyz/`, `src/app_registry/`, `src/gateway/`
- **WP-24**: `crates/bud-codec/`, `src/storage/bud3/{access_tiering,replace}.rs`, `src/storage/{transformed,dictionary,derived,living_threshold}.rs`, `tests/vectors/bud3/codec/`, `xtask/gates/src/gates/derived_content.rs`
- **WP-25**: `src/storage/bud3/fees.rs`, `src/storage/three_regime.rs`, `src/tokenomics/`, `xtask/gates/src/gates/{bud3_fee_uses_physical_bytes,bud3_custody_rewards}.rs`
- **WP-26**: `src/execution/coordinator/`, `src/execution/executor.rs`, `Execute`, `Foreign`, `src/core/account.rs`, `frac_attos`, `src/core/transaction.rs`, `src/mempool/`, `execution/`, `src/settlement/global_block.rs`, `execution_root`
- **WP-27**: `execution/evm/`, `src/execution/coordinator/foreign/`, `xtask/gates/src/gates/classical_crypto_is_paired.rs`, `contracts/uel/`
- **WP-28**: `src/rpc/compat/ethereum/`, `config/*.toml`, `[compat.ethereum]`
- **WP-29**: `execution/wasm/`, `src/execution/coordinator/foreign/cosmos.rs`, `src/rpc/compat/cosmos/`
- **WP-30**: `src/execution/coordinator/universal_call.rs`, `src/execution/coordinator/assets/`, `execution/evm/src/precompile_universal.rs`, `execution/wasm/src/budlum_msg.rs`, `contracts/uel/`
- **WP-31**: `execution/svm/`, `src/execution/coordinator/foreign/solana.rs`, `src/rpc/compat/solana/`
- **WP-32**: `execution/move/`, `src/execution/coordinator/foreign/aptos.rs`, `src/rpc/compat/aptos/`, `execution/move/deny.toml`
- **WP-33**: `budzero/`, `bud-node`, `execution/budzero/`, `src/execution/zkvm.rs`, `src/execution/budzero_ee/`
- **WP-34**: `src/cross_domain/evm/account_proof.rs`, `src/execution/coordinator/migration/`, `src/bin/bud-migrate.rs`
- **WP-35**: `execution/conformance/`, `.github/workflows/conformance-nightly.yml`, `docs/EXECUTION_LIMITS.md`
- **WP-36**: `mobile/android/`, `.github/workflows/mobile.yml`
- **WP-37**: `mobile/android/devicetests/`, `mobile/tools/log-analyzer/`, `docs/MOBILE_DEVICE_MATRIX.md`
- **WP-38**: `mobile/ios/`, `.github/workflows/mobile-ios.yml`
- **WP-39**: `crates/wallet-core/`, `src/wallet/`, `src/cli/`, `src/bin/bud.rs`, `src/developer_os.rs`, `src/project_manifest.rs`
- **WP-40**: `crates/budscan/`, `crates/budlum-explorer/`, `src/bin/budlum-indexer*`, `xtask/gates/src/gates/{budscan_parity,budscan_patchset}.rs`, `explorer_parity`, `explorer_patchset`
- **WP-41**: `src/bin/budlum-faucet*`, `ops/`, `config/testnet.toml`, `release/`
- **WP-42**: `.github/workflows/`, `xtask/`, `fuzz/`, `kani/`, `benches/`, `supply-chain/`, `deny.toml`
- **WP-43**: `docs/`, `README.md`, `README.tr.md`, `assets/`, `budzero/ARCHITECTURE.md`, `budzero/README.md`, `xtask/gates/src/gates/{readme_definition_block_is_verbatim,readme_has_no_placeholders,readme_claims_are_wired,badges_current}.rs`
- **WP-44**: `src/domain/`, `src/cross_domain/`, `src/settlement/`, `src/relayer/`, `src/registry/{identity,poa_}*`, `contracts/`, `docs/{MIKORIZA,GRAFT}.md`, `docs/SHARED_SECURITY.md`, `docs/APP_BINDING.md`
- **WP-45**: `src/privacy/`, `src/account_abstraction/`, `src/prover/`, `src/ai/`, `src/ai_inference/`, `crates/ai-inference/`, `crates/note-packing/`, `crates/bpqs/`, `src/execution/executor.rs`, `privacy_transfers_enabled`
- **WP-46**: `ops/rehearsal/`, `docs/rehearsal/`, `config/rehearsal-genesis.json`
- **WP-47**: `docs/audit/REVIEW_1.md`
- **WP-48**: `docs/audit/REVIEW_2.md`
- **WP-49**: `src/object_layer/`, `src/settlement/{registries,global_block}.rs`, `src/cross_domain/external/{spec,profile}.rs`, `src/domain/types.rs`, `charter`, `contracts/object-layer/`, `src/sdk/object_layer/`
- **WP-50**: `execution/move-sui/`, `src/rpc/compat/sui/`
- **WP-51**: `execution/cairo/`, `src/rpc/compat/starknet/`
- **WP-52**: `src/execution/coordinator/assets/`, `execution/svm/src/pointer/`, `execution/move/src/pointer/`
- **WP-53**: `execution/{near,polkavm,tvm,utxo,plutus}/`
- **WP-54**: `crates/bud-codec/`, `src/storage/bud3/{compression_context,private_dedup}.rs`
- **WP-55**: `src/storage/bud3/live.rs`, `src/storage/bud3/bof1.rs`
- **WP-56**: `budzero/bud-proof/`, `budzero/bud-vm/`, `budzero/bud-isa/`, `budzero/bud-state/`, `crates/note-packing/`, `budzero/predicates/`, `src/storage/bud3/{seal,grants,consent,escrow}.rs`, `src/privacy/`, `crates/wallet-core/`
- **WP-57**: `src/ai/`, `src/ai_inference/`, `crates/ai-inference/`, `budzero/`, `VerifyInference`
- **WP-58**: `mobile/android/fdroid/`, `mobile/android/build.gradle.kts`
- **WP-59**: `src/execution/coordinator/scheduler/`
- **WP-60**: `budzero/`, `budzero/bud-sigagg/`, `budzero/bud-pul/`, `src/cross_domain/external/zkvm_proof.rs`, `src/cross_domain/evm/sync_committee.rs`, `src/settlement/`, `src/light_client/`
- **WP-61**: `src/rpc/`, `compat/`, `src/crypto/`

Shared append-only files (section 15.3.4) are never locked: a package adds
to them and conflicts are solved by rebase. They are
`src/core/transaction.rs` (`TransactionType` and the wire table),
`src/rpc/method_class.rs`, `src/crypto/domain_tags.rs`,
`xtask/gates/src/main.rs` and the gate registry, the `ci.yml` job list, the
`Cargo.toml` workspace member list, this file, `docs/audit/FINDINGS.md`,
`config/naming/concept_map.toml` and `.github/concept-names-baseline.txt`.

## Live gaps this reconciliation found

These are recorded so the next package does not rediscover them. None of
them is closed by this pull request.

1. **20 packages have no pull request.** No open PR title names
   them, so no lane has started them: WP-01, WP-03, WP-14, WP-29, WP-30, WP-39, WP-49, WP-50, WP-51, WP-52, WP-53, WP-54, WP-56, WP-57, WP-58, WP-59, WP-60, WP-62, WP-63, WP-64.
   WP-01 and WP-03 are the two lane audits that gate M0 and have no
   dependency, so they are the cheapest of the set to start.
2. **`docs/audit/LIVE_STATUS.md` does not exist.** Section 14.1.4 makes it
   the output of WP-01 to WP-04 and the only live status of the 267
   findings. Lane D's baseline note exists on an open branch only
   (`docs/audit/live/lane-d.md`, PR #118), so the file is missing from
   `main` and the finding ledger in `docs/audit/FINDINGS.md` therefore
   records closures only.
3. **Two of the three lane documents are added by this slice.**
   `docs/audit/live/lane-a.md` (WP-01: 54 records in scope, 6 revalidated, one
   stop report) and `docs/audit/live/lane-c.md` (WP-03: 48 records in scope, 1
   revalidated) plus `docs/audit/live/engine-inventory.md`. `lane-b.md` still
   does not exist; it is the lock path of WP-02, and PR #117 is the only lane B
   work in the stack.
4. **31 registered gates never run in a workflow.** `xtask/gates` exposes
   them and `ci.yml` invokes neither each one nor `--all`, so they are
   registered protection that proves nothing on a commit. This slice wired two
   of the original 33, each with its canary, after reproducing the gate from its
   source and measuring the tree: `chain-id-is-not-hardcoded` (430 files under
   `src/`, `budzero/` and `crates/`, no literal `chain_id` outside tests) and
   `no-new-shell-gates` (0 shell scripts in the tree, migration list empty). The
   31 that remain are wired one at a time, because a gate that fails on `main`
   the first time it runs turns the whole job red and this environment cannot
   run them to find out:
   `ai-inference-prompt-is-true`, `ai-inference-zk`, `ast-security-gates`,
   `bns-names`, `bridge-dual-tree`,
   `consensus-state-only-changes-in-blocks`, `every-fuzz-target-is-run`,
   `fixture-integrity`, `fsf-import-boundaries`, `gas-calibration`,
   `gates-do-not-panic`, `gov-slash-evidence-validator-only`,
   `image-builds-the-manifest`, `mempool-mev-free`, `mermaid`,
   `minting-paths-are-counted`, `multi-ratio-consensus`,
   `no-out-of-block-consensus-writes`, `one-house-guards`,
   `parallel-execution`, `proof-deps-are-exactly-pinned`, `quantum-account`,
   `regen-health-door`, `release-profile-pins`, `security-scans-can-fail`,
   `suppressions-are-justified`, `tee-trust-boundary-structural`,
   `transcript-mirrors`, `workflows-produce-jobs`,
   `zero-address-sender-verified`, `zkvm-immune-regeneration`.
5. **Two gates named by the directive do not exist yet:**
   `workflows_cover_every_workspace` (section 16.2.3) and
   `no_float_in_consensus_paths` (WP-42 item 4). Both are static scans over
   the tree, so neither needs a running node.

