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
