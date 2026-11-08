# Independent Review 2: Execution, Foreign Compatibility Lane, Mobile Authority, and Clients (`WP-48`)

Scope: `WP-09`, `WP-11` (light-client execution proof surface), `WP-26` through `WP-41`
(Universal Execution Layer, five execution environments, foreign Compatibility Lane, RPC
compatibility gateways, conformance/gas calibration), and `WP-61` RPC safety bounds.

All Critical and High findings uncovered during this review (`BLG-277`, `BLG-278`, `BLG-280`)
plus `BLG-279` (Medium) are fixed and regression-tested in PR `#36`.

---

## 1. Invariant Audit (`Y-1..Y-7`, `K-1..K-4`, `G-2`, `G-3`, `G-4`)

| Invariant | Verdict | Implementation Surface | Verification Test / Gate |
|---|---|---|---|
| `Y-1` Unmodified bytecode | Pass | `evm_ee.rs` (Prague opcodes), `wasm_ee.rs` (CosmWasm Wasm binary), `svm_ee.rs` (SBF ELF + SPL), `move_ee.rs` (Move `0xa11ceb0b` modules), `budzero_ee/mod.rs` (`bud-isa` bytecode) | `uel_conformance_{evm,wasm,svm,move,budzero}` |
| `Y-2` Single state, single order | Pass | `ExecutionState::execution_root` (`BDLM_UEL_ROOT_V1` over 7 sparse 256-bit Merkle subtrees) + sequential `execute_uel_block` | `execution_root_binds_every_namespace`, `uel_cross_arch_roots_equal` |
| `Y-3` Atomicity | Pass | `TxOverlay` per-frame journal + `push_universal_frame` / `rollback_universal_frame` across nested `UniversalCall` hops | `coordinator_overlay_rolls_back_frame`, `uel_evm_calls_wasm_atomically` |
| `Y-4` Single BUD ledger | Pass | `AccountState::{balances, frac_attos}` (`1 BUD = 10^6` atoms, `10^18` attoBUD) scaled by `BudEnvUnit` (`BLG-256`) | `uel_bud_conservation`, `review_2_random_cross_ee_bud_conservation_holds` |
| `Y-5` Zero-balance pointers | Pass | `src/execution/coordinator/assets/mod.rs` (`uel/assets` + immutable `POINTER_BYTECODE_PREFIX` routing to home EE) | `uel_pointer_holds_no_balance`, `pointer_allowance_lives_at_home` |
| `Y-6` Worker isolation | Pass | `execution/*` (`panic = "unwind"`), `WorkerSupervisor`, `OutcomeStatus::Fault` deterministic error receipt (`BLG-250`) | `uel_worker_panic_yields_fault_receipt`, `review_2_risk_matrix_r01_r08_r18_r21_and_rpc_isolation` |
| `Y-7` Visible quantum class | Pass (after `BLG-278` fix) | `AccountQuantumClass::{PostQuantum, Classical, Contract}`, `ForeignLaneState::authorize_holding_access`, signed PQ alias binding | `foreign_account_cannot_touch_pq_holdings`, `review_2_quantum_alert_level2_spoofed_recipient_refused_blg_278` |
| `K-1` Backed crypto claims | Pass | Testnet closes unverified `VerifyMerkle` (`BLG-223`) and `VerifyInference` (`BLG-226`) opcodes; proof claims carry named tests | `verify_merkle_is_closed_on_testnet`, `verify_inference_is_closed_on_testnet`, gate `pq_claims_are_backed` |
| `K-2` Consent is the single door | Pass | Storage/privacy key unsealing stays behind `src/storage/bud3/` consent types; UEL EEs have zero side-channel read access outside canonical UEL namespaces | `RootGroup::for_namespace` strict allowlist |
| `K-3` Classical crypto paired | Pass (after `BLG-278` fix) | Category `"f"` allowlisted in `docs/pq/classical_allowlist.toml`; `AdoptForeignAccountTx` requires dual ML-DSA-87 + classical proof (`BLG-267`) | `adopt_moves_holdings_once`, gate `classical-crypto-is-paired` |
| `K-4` Single primitive definition | Pass | Foreign envelopes reuse `crate::crypto::{pq, primitives, secp256k1_recover}` and `core::hash::hash_fields_bytes` | Gate `domain_tags`, `uel_foreign_tx_replay_refused` |
| `G-2` Determinism | Pass | Interpreter-only EEs (`svm_jit_is_disabled`, `wasm_float_code_refused`), `BTreeMap`/`BTreeSet` state maps, zero floats in consensus | `uel_cross_arch_roots_equal`, `review_2_random_cross_ee_bud_conservation_holds` |
| `G-3` Fixed supply (no minting) | Pass | `total_bud_committed_attos() + burned_total * ATTOS_PER_ATOM` conserved across all 5 EEs, Universal Calls, and `Adopt` | `review_2_random_cross_ee_bud_conservation_holds`, gate `economy-invariants` |
| `G-4` Refusals do not mutate state | Pass (after `BLG-277` fix) | Foreign admission validates nonce, `account_number`, quantum alert policy, and balance transfers before mutating `ForeignLaneState` | `review_2_refused_foreign_txs_never_mutate_state_blg_277`, gate `refusals_no_mutate` |

---

## 2. Section 13 Risk Attack Matrix

| Risk | Threat Scenario | Mitigation & Attack Coverage | Status |
|---|---|---|---|
| `R-01` | EE worker panic crashes all validators | `catch_unwind` in `budlum-ee-*` workers + `Fault` receipt rollback (`review_2_risk_matrix_r01_r08_r18_r21_and_rpc_isolation`) | Verified |
| `R-05` | Mobile OS battery manager kills background service | Long audit window + suspension without stake slashing (`V-4`, `src/validators/mod.rs`); mobile holds zero finality seats (`V-2`) | Verified |
| `R-07` | NAT traversal failure on mobile validators | Relay v2 / AutoNAT connectivity layer + presence-only suspension (`V-4`) keeps finality unaffected | Verified |
| `R-08` | Public / compatibility RPC load attack | 256 KiB request body ceiling, bounded filter table (`MAX_ACTIVE_ETH_FILTERS = 256`), read-only `&AccountState` handlers (`review_2_risk_matrix_r01_r08_r18_r21_and_rpc_isolation`) | Verified |
| `R-11` | Cross-architecture (`x86_64` vs `aarch64`) state root divergence | Interpreter-only execution, float ban, canonical sparse Merkle tree (`uel_cross_arch_roots_equal`, CI `windows-latest` + Linux matrix) | Verified |
| `R-12` | EVM / foreign lane state and memory bloat | `SSTORE` gas + `namespace_bytes` metering (`evm_state_growth_is_metered`) + 150-blockhash Solana signature eviction (`BLG-279`) | Verified |
| `R-15` | Faucet bot draining | PoW challenge + per-IP and per-address rate caps in `src/bin/budlum-faucet.rs` | Verified |
| `R-16` | Stolen mobile `operator_key` attempts stake theft or rotation | `ValidatorTx::{ChangeClass, RotateOperatorKey}` require `tx.from == owner`; `operator_key` only signs `UpdateCustodyQuota` (`validator_classes.rs:397`, `BLG-281` noted below) | Verified |
| `R-18` | Underpriced EE gas exceeds 2 s block budget | `calibrate_bgu_schedule` (`<= 16 ns / BGU` p95) + `SOFT_EE_BGU_CAP = 40_000_000 BGU` (`uel_gas_calibration_bound`) | Verified |
| `R-19` | Cross-EE reentrancy or static-call spoofing steals assets | Per-EE reentrancy frame lock + depth cap 8 + `BLG-280` `STATIC_PREFIX` spoofing refusal (`review_2_static_prefix_spoofing_refused_blg_280`) | Verified |
| `R-20` | Tooling incompatibility on unsupported RPC/opcodes | Explicit refusal matrix in `docs/EXECUTION_LIMITS.md` + `bud_getExecutionProof` sparse Merkle alternative (`uel_execution_proof_verifies_inclusion_and_absence`) | Verified |
| `R-21` | Maintenance freeze on one EE stalls chain | `ExecutionState::set_deploy_enabled(ee, false)` returns `DeployFrozen` while existing contracts and other 4 EEs continue (`review_2_risk_matrix_r01_r08_r18_r21_and_rpc_isolation`) | Verified |
| `R-36` | Classical foreign envelopes erode PQ security boundary | `QuantumAlertLevel` (`0..=3`) + signed PQ recipient verification (`BLG-278`) + irreversible `AdoptForeignAccountTx` | Verified |

---

## 3. Foreign Replay, Chain-ID, Cross-Scheme Confusion & Cross-EE Conservation

1. **Foreign replay & chain-ID confusion (`uel_foreign_tx_replay_refused`, `review_2_foreign_cross_scheme_signature_and_chain_id_confusion`):**
   - Ethereum (`chain_id = 45261`, EIP-1559/legacy/2930/7702; type-3 blob refused), Solana (150-blockhash window + per-blockhash signature replay set), Aptos (`chain_id = 205`, expiration + sequence number), Cosmos (`chain_id = "budlum-testnet-1"`, `SIGN_MODE_DIRECT`, `account_number` + `sequence`), and `Adopt` (`chain_id = 45261`, one-time `adopted_into` lock) all reject replayed transactions, wrong chain IDs, high-`s` ECDSA malleability, and cross-scheme `ClassicalAdoptProof` pairings.
2. **Randomized cross-EE BUD conservation (`review_2_random_cross_ee_bud_conservation_holds`):**
   - Deterministic `SplitMix64` workload deploys contracts across EVM, WASM, Move, and BudZero plus SVM Memo calls and zero-balance asset pointers, then executes 48 mixed cross-EE value/call/OOG transactions. After every block, `total_bud_committed_attos() + burned_total * ATTOS_PER_ATOM` equals the exact initial supply to `1` attoBUD (`10^-18` BUD), pointer contracts hold `0` balance (`Y-5`), and two independent runs produce identical `execution_root` digests.
3. **Mobile operator-key authority (`src/core/account.rs:2788`, `src/validators/mod.rs:550`):**
   - Owner stake, reward destination, `ChangeClass`, and `RotateOperatorKey` are gated strictly by the ML-DSA-87 owner account (`tx.from`), never by the hot `ML-DSA-65` mobile `operator_key` (`UpdateCustodyQuota` only).

---

## 4. Findings Opened in Review 2 (`BLG-277`..`BLG-281`)

| ID | Severity | Location | Summary | Status |
|---|---|---|---|---|
| `BLG-277` | High | `src/execution/coordinator/foreign/mod.rs` | `ForeignLaneState::process_foreign_tx` inserted `ForeignAccountRecord` and bumped `next_cosmos_account_number` / `next_nonce` before validating nonce, `account_number`, or direct-transfer balance (`G-4` violation). Fixed by read-only `foreign_account_expectation` preflight and post-transfer commit. | Closed (`review_2_refused_foreign_txs_never_mutate_state_blg_277`) |
| `BLG-278` | Critical | `src/execution/coordinator/foreign/mod.rs` | Under `QuantumAlertLevel::Level2Restricted`, outer `direct_native_pq_recipient` metadata was accepted without verifying that the recipient is `PostQuantum` and bound to the signed payload's canonical alias (`EVM`/`SVM`/`Move`/`WASM`), enabling Level-2 restriction bypass (`Y-7`, `K-3`, `R-36`). Fixed by `ensure_direct_pq_target` and per-envelope signed alias binding. | Closed (`review_2_quantum_alert_level2_spoofed_recipient_refused_blg_278`) |
| `BLG-279` | Medium | `src/execution/coordinator/{state.rs,foreign/mod.rs}` | Registered native alias collision checks covered only EVM (`check_evm_alias_collision`), and `seen_solana_signatures` retained signatures after their `recent_blockhash` left the 150-block window (`R-12`). Fixed via `has_registered_alias_collision` across all 4 foreign EEs and `solana_sigs_by_blockhash` lockstep eviction. | Closed (`review_2_cross_ee_alias_collision_and_bounded_solana_window_blg_279`) |
| `BLG-280` | High | `src/execution/coordinator/{universal_call.rs,wasm_ee.rs}` | External non-static `IBudlumUniversal.call(...)` and `BudlumMsg::UniversalCall` payloads starting with `BDLM_UCALL_STATIC_V1` (`STATIC_PREFIX`) were misclassified by `HostBridge::universal_call` as `is_static = true` with 20 bytes stripped from user calldata. Fixed by `has_reserved_static_prefix` refusal on non-static entrypoints. | Closed (`review_2_static_prefix_spoofing_refused_blg_280`) |
| `BLG-281` | Medium | `src/validators/mod.rs:556`, `src/core/account.rs:2758` | `request_operator_rotation` and `ValidatorTx::Register` check `r.operator_key == key` against active keys but do not check `r.pending_operator_key`, allowing two same-epoch transactions to queue the same `ML-DSA-65` operator key for `epoch + 1`. Deferred from this commit because `src/validators/mod.rs` is locked by open PR `#70` (`WP-13`, `R-25`). | Open (assigned to `WP-13` follow-up after `#70`) |

---

<!-- Review passes preserved during integration; neither pass is independent live-network completion evidence. -->

# Independent Security Review 2: Execution, Mobile, and Client Surfaces (WP-48)

## 1. Scope and Methodology

This independent review covers the execution, mobile/validator authority, cryptography, RPC gateway, and client-facing proof surfaces defined for **WP-48**:

- **Execution & state transition**: `src/execution/{executor.rs,zkvm.rs,ee.rs,coordinator/}`, `crates/uel-abi/`.
- **Validator & mobile operator-key separation**: `src/validators/mod.rs`, `src/core/account.rs`.
- **Post-quantum cryptography & account abstraction**: `src/crypto/{pq.rs,scheme.rs,ctx.rs,domain_tags.rs}`, `src/account_abstraction/`.
- **RPC listener classes, rate limiting, and client proof bundles**: `src/rpc/{method_class.rs,server.rs}`, `src/gateway/{passport.rs,atlas.rs}`, `crates/wallet-core/`, `crates/budlum-explorer/`.

Every invariant (`Y-1` through `Y-7`, `K-1` through `K-4`, `G-2`, `G-3`, `G-4`) and Section 13 pre-mortem risk (`R-01`, `R-05`, `R-07`, `R-08`, `R-11`, `R-12`, `R-15`, `R-16`, `R-18`, `R-19`, `R-20`, `R-36`) was audited directly against live repository source and regression-locked by executable tests.

---

## 2. Invariant Audit Matrix

| Invariant | Requirement | Code Surface & Verification | Status |
|---|---|---|---|
| **G-2** | Determinism: no consensus-path floating point, ordered collections (`BTreeMap`/`BTreeSet`) in hashed state, identical state roots across `x86_64` and `aarch64`. | `AccountState::calculate_state_root`, `ValidatorDirectory::root`, `Bud3Registry::state_root`, `ObjectLayerRegistry`, `no_float` / `serialize_map_keys_are_strings` gates. | Verified |
| **G-3** | Zero new minting: fixed `100,000,000 BUD` supply ceiling; every balance credit is an account transfer, escrow settlement, or reward-pool payout. | `minting_paths_are_counted` gate, `economy_invariants` gate, `Executor::apply_block_candidate_checked`, `review2_randomized_bud_supply_conservation_and_atomic_rollback`, `BLG-284` fix. | Verified |
| **G-4** | Refusals do not mutate state (`refusals_no_mutate`). | `Executor::apply_block_checked` failure-atomic clone-and-commit (`a_refused_later_transaction_rolls_back_the_whole_block`), `Executor::apply_transaction_checked` (`BLG-284` rollback on failed seat installation). | Verified |
| **Y-1** | Unmodified bytecode execution per environment without custom Budlum recompilation steps. | `crates/uel-abi/` worker protocol & `src/execution/zkvm.rs` ELF/ISA entry points. | Verified |
| **Y-2** | Single state root, single total transaction order per block. | `Blockchain::apply_block_effects_with_unfreezes` sequential `Executor::apply_block_candidate_checked` execution; `coordinator::scheduler` equality-tested against sequential execution. | Verified |
| **Y-3** | All-or-nothing atomicity across multi-step calls and blocks. | `Executor::apply_block_checked` + `ObjectLayerRegistry` composite call ceiling (`MAX_COMPOSITE_CALLS = 16`) + `review2_randomized_bud_supply_conservation_and_atomic_rollback`. | Verified |
| **Y-4** | Single native BUD balance ledger shared across execution surfaces. | `AccountState::accounts` is the sole native BUD ledger; no environment-private BUD minting table exists. | Verified |
| **Y-5** | No wrapped representation minting; assets live under home-environment rules. | `src/object_layer/` (`ObjectLayerRegistry`, `minting_paths_are_counted` transfer-only enforcement). | Verified |
| **Y-6** | Worker/VM fault isolation: execution faults produce deterministic refusal/error receipts and never panic the node (`#![forbid(unsafe_code)]`, `unwrap_used = "deny"`). | `Cargo.toml` `[lints.clippy]`, `crates/uel-abi` frame bounds (`uel_abi_frame` fuzz target), `vm_execute` fuzz target. | Verified |
| **Y-7** | Classical-signature origin visibility and isolation from post-quantum accounts. | `SchemeStatusRegistry`, `QuantumClass`, `account_abstraction::quantum_account`, `classical_crypto_is_paired` gate. | Verified |
| **K-1** | Every privacy / zero-knowledge / proof claim is backed by a named test (`pq_claims_are_backed`, `binding_claims`). | `xtask/gates` static claim-verification gates; unverified testnet surfaces explicitly closed (`WP-44`, `WP-45`). | Verified |
| **K-2** | Consent-gated key/plaintext access enforced at the type boundary. | `pollen::content_gate::ProtectedContent`, `paid_content` gate (`gateway_guard_calls >= 2`). | Verified |
| **K-3** | Classical cryptography never moves post-quantum account assets unilaterally (`classical_crypto_is_paired`). | `crypto::pq::verify_in` + `SchemeStatusRegistry` + ML-DSA-87 wallet / ML-DSA-65 validator separation. | Verified |
| **K-4** | Single canonical cryptographic primitive definitions shared across node, wallet, and VM. | `src/crypto/{pq.rs,scheme.rs,ctx.rs,domain_tags.rs}` (`domain_tags` inventory gate). | Verified |

---

## 3. Section 13 Pre-Mortem Risk & Adversarial Verification

| Risk ID | Failure Scenario | Mitigation & Detection Audited | Adversarial / Regression Lock |
|---|---|---|---|
| **R-01** | Execution environment panic crashes all validator nodes. | `#![forbid(unsafe_code)]`, `unwrap_used = "deny"`, `uel-abi` process boundary, bounded VM gas/instruction meters. | `fuzz/fuzz_targets/vm_execute.rs`, `fuzz/fuzz_targets/uel_abi_frame.rs` |
| **R-05** | Mobile OS kills background validator app, causing missed audits. | Longer Mobile audit window (`24` epochs vs Full `2` epochs), `MOBILE_MISSES_TO_LOSS = 3`, zero stake slashing on absence (`V-4`). | `all_mobile_departure_does_not_touch_finality` |
| **R-07** | Phones behind symmetric NAT fail to accept inbound connections. | Full-validator `RelayOffer` directory (`MAX_RELAY_ADDRESSES = 8`), immediate relay handover (`DutyKind::RelayReservation`). | `handover_table_covers_all_nine_duties_and_bounds` |
| **R-08** | Public JSON-RPC flood / admin-surface exposure. | `src/rpc/method_class.rs` (`Public` vs `Operator` listener table verified at `RpcServer::run` startup), `budlum_rpc_rate_limited_total` counter. | `rpc::method_class` startup & exhaustiveness tests |
| **R-11** | Cross-architecture (`x86_64` vs `aarch64`) execution divergence. | Interpreter-only execution, integer-only consensus state (`no_float`), canonical LE encoding. | `review2_randomized_bud_supply_conservation_and_atomic_rollback` |
| **R-12** | Unbounded contract/registry state growth exhausts disk. | Hard collection caps (`MAX_NAMES = 100_000`, `MAX_NFTS_PER_OWNER = 100_000`, `MAX_ATLAS_DOMAIN_SUMMARIES = 1_024`, per-tx/per-block contract gas caps). | `Executor::check_block_contract_gas`, `blg_129_active_domain_survives_stale_summary_eviction` |
| **R-15** | Automated faucet draining. | Rate-limited public submission & operator/faucet per-address / per-IP controls. | `rpc::tests` rate-limit coverage |
| **R-16** | Compromised mobile `operator_key` on a stolen phone. | Strict owner vs operator key split (`ValidatorTx::UpdateCustodyQuota` is the sole operator-signed action, bound to `chain_id`, `owner`, `seq`, and `ctx::VALIDATOR_V1`), plus **immediate freeze of `UpdateCustodyQuota` while `RotateOperatorKey` is pending (`BLG-283`)**. | `blg_283_stolen_operator_key_frozen_during_rotation_window`, `review2_quantum_class_and_chain_id_replay_separation` |
| **R-18** | Mispriced execution gas stalls block production. | `Executor::check_block_contract_gas` hard block gas ceiling + per-call meter bounds. | `a_refused_later_transaction_rolls_back_the_whole_block` |
| **R-19** | Cross-environment reentrancy steals assets. | Sequential single-ledger execution, `MAX_COMPOSITE_CALLS = 16`, failure-atomic state rollback on any sub-step refusal. | `review2_randomized_bud_supply_conservation_and_atomic_rollback` |
| **R-20** | Compatibility surface silently accepts unsupported calls. | Explicit named refusals (`Effect::Refused` in `rpc/method_class.rs` and `ACTIVATION` gates). | `wp44_domains_bridge_settlement` & `rpc::method_class` |
| **R-36** | Foreign/classical envelopes weaken post-quantum guarantees. | `SchemeStatusRegistry`, `ctx::VALIDATOR_V1` context binding, cross-chain & cross-owner replay rejection. | `review2_quantum_class_and_chain_id_replay_separation` |

---

## 4. Fuzz Parser Coverage Inventory

All 18 fuzz targets under `fuzz/fuzz_targets/` were audited against untrusted network, storage, and execution inputs:

1. `block_deserialize.rs` - untrusted block wire decoding.
2. `transaction_deserialize.rs` - untrusted transaction envelope & witness decoding.
3. `snapshot_deserialize.rs` - V1/V2 snapshot parser resilience.
4. `fuzz_blockchain_serialize.rs` - round-trip chain persistence encoding.
5. `consensus_validate.rs` - header/proposer/QC validation inputs.
6. `consensus_state_transition.rs` - arbitrary transaction sequence execution.
7. `bud3_bof1_decode.rs` - B.U.D. 3.0 BOF-1 binary header & varint parser.
8. `bud3_symbol_decode.rs` - RFC 6330 fountain symbol decoder.
9. `uel_abi_frame.rs` - UEL worker IPC frame decoder.
10. `evm_rlp_decode.rs` - EVM RLP transaction/header decoder.
11. `evm_mpt_verify.rs` - Ethereum Merkle-Patricia proof verifier.
12. `vm_execute.rs` - BudZero VM bytecode decoder & meter boundaries.
13. `budl_compile.rs` & `budl_compile_then_run.rs` - BudL compiler front-end & execution.
14. `zk_verifier.rs` - STARK/receipt proof parser & verifier.
15. `bpqs_wots_reject.rs` - BPQS WOTS+ malformed signature rejection.
16. `relayer_escrow.rs` - relayer bid/intent/escrow state transitions.
17. `reputation.rs` - integer reputation scoring bounds.

---

## 5. Findings Discovered and Closed in This Review

All Critical and High findings uncovered during Independent Review 2 (together with legacy gateway finding `BLG-129`) are **closed and regression-locked in this commit**:

| ID | Severity | Component | Description | Resolution & Regression Test |
|---|---|---|---|---|
| **BLG-284** | **Critical** | `src/core/account.rs`, `src/execution/executor.rs` | (1) `AccountState::check_validator_tx` omitted `check_seat_keys` on `ValidatorTx::ChangeClass { new_class: Full, seat }`, admitting malformed/zero VRF keys into consensus state and charging fees for doomed upgrades (`G-7`). (2) `install_full_validator` inserted into `AccountState::validators` before validating leader-commitment epoch bounds, risking stake double-counting (`G-3`) or partial state mutation (`G-4`) on failure; `ValidatorTx::Register` also left `validator_directory` mutated if `install_full_validator` failed. | Added `check_seat_keys` and duplicate-consensus-set checks to `check_validator_tx` on `ChangeClass`; pre-validated commitment bounds and added rollback in `install_full_validator` and `Executor::apply_transaction_checked`. Locked by `blg_284_change_class_validates_seat_keys_and_failed_install_rolls_back`. |
| **BLG-281** | **High** | `src/validators/mod.rs` | Concurrent `pending_class` and `pending_quota` in the same epoch bypassed `MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES` (`8 GiB`): `request_class_change` ignored `pending_quota` and `request_quota_increase` ignored `pending_class`, activating an opportunistic validator above `8 GiB` at `E + 1`. | Both `request_class_change` and `request_quota_increase` now check effective (`current` + `pending`) class and quota against `MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES`. Locked by `blg_281_opportunistic_quota_cap_enforced_across_pending_class_and_quota`. |
| **BLG-282** | **High** | `src/validators/mod.rs`, `src/core/account.rs` | Operator-key uniqueness checks inspected `record.operator_key` only and ignored `record.pending_operator_key`, allowing two validators to claim the same ML-DSA-65 `operator_key` in one epoch and collide upon activation. | Added `ValidatorDirectory::operator_key_in_use` covering both active and pending operator keys and enforced it across `register`, `request_operator_rotation`, and `check_validator_tx`. Locked by `blg_282_pending_operator_key_cannot_be_claimed_twice`. |
| **BLG-283** | **High** | `src/validators/mod.rs`, `src/core/account.rs` | During the 1-epoch `RotateOperatorKey` delay (`R-16`), a compromised phone `operator_key` could still sign `UpdateCustodyQuota` transactions and inflate the validator's storage obligation before key replacement took effect. | `UpdateCustodyQuota` is now refused (`validator_rotation_pending`) whenever `pending_operator_key.is_some()`. Locked by `blg_283_stolen_operator_key_frozen_during_rotation_window`. |
| **BLG-129** | **High** | `src/gateway/passport.rs`, `src/gateway/atlas.rs` | (1) `PassportProofBundle` omitted `address`, `storage_root`, `storage_domain_id`, `content_id`, `is_expired`, `manifest`, and lineage counts from `bundle_root` and silently truncated `> 64` evidence items. (2) Profile and wallet-context summaries counted revoked `DataAsset`/`AccessGrant` and exhausted `SaleAuthorization` entries. (3) `AtlasQueryEngine::upsert_domain_summary` evicted `DomainId(1)` unconditionally via `BTreeMap::keys().next()` instead of evicting the least-recently-committed domain. | Folded all profile fields into `bundle_root`, enforced `validate_public` and exact item length in `validate_against_profile`, filtered revoked/exhausted lineage entries, and changed `upsert_domain_summary` eviction to `(last_commit_epoch, domain_id)`. Locked by `blg_129_bundle_commits_all_fields_and_excludes_revoked_lineage` and `blg_129_active_domain_survives_stale_summary_eviction`. |
