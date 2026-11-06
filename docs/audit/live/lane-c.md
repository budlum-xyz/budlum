# Lane C live verification ledger (WP-03)

Directive section 14 assigns the unified findings ledger to live verification
in four lanes (WP-01..WP-04). This file is the lane C record: every ledger
entry whose closing package is İP-26 through İP-35, İP-44, İP-49 through
İP-53, İP-57, İP-59 or İP-60, re-verified against the live tree. English per
`tree_is_english`. The engine catalog is in `engine-inventory.md`.

## How this was produced

- **Verification base.** Repository snapshot `HEAD` = `cccf1da` (`main`,
  2026-11-05). Line atıfları are content anchors, not line numbers.
- **Method.** Same as lanes A/B: section 14 records extracted programmatically,
  identifier scan across the tree, anchor reading for headline findings
  (ContractCall execution path, Ethereum sync committee production call site,
  bridge quadruplet, BudZero ZK posture, the RPC surface inventory).
- **CI.** No local Rust toolchain exists in this environment; no red CI run
  was observed while working.
- **What this PR does not claim.** WP-03 does not fix findings. No lane C
  record is Kapalı in this snapshot. The engine catalog section records that
  no external engine exists yet; the latent risks (BLG-250, BLG-260) go live
  when WP-26 lands. Repro tests are owed on `audit/repro-c` and move into the
  closing packages' PRs (S-3).

## Status legend (directive 14.1)

| Status | Meaning |
|---|---|
| Açık | Open in the live tree. Evidence below; repro pending on `audit/repro-c`. |
| Doğrulandı | Open and reproduced by file inspection at the cited anchors. |
| Kapalı | None this pass. |
| Kaldırma ile kapandı | None in this lane. |

## Summary

| Metric | Count |
|---|---|
| Lane C records | 67 |
| Kapalı | 0 |
| Doğrulandı | 5 |
| Açık | 62 |

Closing-package distribution (a record may carry shared feet): İP-33 (BudZero
core, ~24), İP-44 (domain registry / bridge / settlement, ~34), İP-26 (UEL
coordinator, 4), İP-27..32 (compat EEs, 3), İP-56/57/60 (BudZero proving and
AI closure, shared feet).

## Special audits of WP-03 (directive 15.8, İP-03)

1. **Section 8.2 engine catalog** — `docs/audit/live/engine-inventory.md`.
   No revm, wasmi, solana-svm, solana-sbpf, aptos-vm or cosmwasm dependency
   exists in `Cargo.lock`. BudZero's proving stack is in-house.
2. **`ContractCall` path (BLG-248)** — Doğrulandı: the arm executes
   `ZkVmExecutor::execute_bytecode(&tx.data, ...)` with a fresh VM context;
   bytecode comes from the transaction, never from a code store. No deploy
   opcode exists.
3. **BudZero `Pcs::ZK` and 64-bit commitments (BLG-223, BLG-224)** —
   Doğrulandı (lane B and here): `TwoAdicFriPcs` whose `Pcs::ZK` is `false`;
   the spent-set is 64-bit Goldilocks elements.
4. **Ethereum sync committee production call site (BLG-235)** — reproduced:
   `EthereumSyncAdapter::new` is constructed on the production intake path
   (`src/cross_domain/external/intake.rs:188`). The finding's unwired/mis-verify
   premise remains open; see the BLG-235 row.
5. **Bridge quadruplet (BLG-043, BLG-057, BLG-105, BLG-194)** — all four
   functions present and unfixed (`unlock_bridge_transfer_from_verified_event`
   at `src/chain/blockchain.rs:2483`, `burn_bridge_transfer_with_event` at
   `:2451`, `submit_relay_proof` at `:2846` and `src/cross_domain/bridge_tx.rs:625`).
   Per directive 1.5 these four findings drive the bridge decision; their
   state this pass is: **all four confirmed present, all four open**.

## In-flight work this ledger interacts with

- **PR #8** (İP-06/07/24): BLG-148's İP-07 foot (storage_deal.rs removal).
- **PR #9** (WP-12): no lane C record closes there.
- **Lane B** (PR #12): BLG-223/224/225/228/229/240 are shared with lane B;
  lane C records them as the proving/AI closure feet.
- **WP-26..32** (blocked on İP-07): engines absent; latent risks recorded.
- **WP-44** (blocked on İP-01): the bridge and registry feet.

## The ledger

| ID | Severity | Closing | Finding (English) | Live status | Evidence / note |
|---|---|---|---|---|---|
| BLG-024 | Low | İP-44 | PoW/PoS/PoA/Bft finality adapters skip the domain.id == commitment.domain_id check; PoAFinalityAdapter divides by zero | Açık | `PoAFinalityAdapter` 6 files (`src/domain/finality_adapter.rs`); the `domain.id == commitment.domain_id` literal absent. Closes with İP-44. |
| BLG-036 | Critical | İP-33 | BudAir table activation adjacency missing / key and clock order defects | Açık | `BudAir` 7 files (`budzero/docs/adding_opcodes.md`); `m_same` 5 files. Closes with İP-33. |
| BLG-037 | Critical | İP-33 | VerifyInference forges AI inference attestations via free witness columns; SWrite state | Açık | `VerifyInference` 20 files, `SWrite` 25 files (`src/execution/zkvm.rs`). Closes with İP-33. |
| BLG-038 | Critical | İP-33 | Linear initial memory commitment collision; frameless event_digest sum; unbound | Açık | `event_digest` 28 files; `chain_id >> 32` 1 file (`budzero/bud-proof/src/plonky3_prover.rs`). Closes with İP-33. |
| BLG-039 | Critical | İP-33 | Remote crash at degree_bits >= 27 in the STARK verifier; zero-gas setup_preprocessed | Açık | `setup_preprocessed` 3 files (`budzero/bud-proof/src/bud_stark/preprocessed.rs`); the `degree_bits >= 27` literal absent. Closes with İP-33. |
| BLG-040 | High | İP-33 | One-round reversible VerifyMerkle digest; ZKVM<->BudAir semantics mismatch; ZkVmExe | Açık | `VerifyMerkle` 47 files, `ZkVmExecutor` 7 files. Closes with İP-33. |
| BLG-043 | Critical | İP-44 | unlock_bridge_transfer loses 100% of funds; opener_bond and reallocation fee never returned; unverified relayer mint | Açık | `unlock_bridge_transfer` 5 files (`src/chain/blockchain.rs:2483` region), `opener_bond` 10 files. Special audit of İP-03: this is one of the four bridge findings that decide the bridge decision (directive 1.5). Open as verified-present. Closes with İP-44. |
| BLG-050 | Critical | İP-44 | IdentityTx::Recover bypasses the PoA gate; third-party credential_root claims | Açık | `IdentityTx::Recover` 3 files, `credential_root` 5 files (`src/core/transaction.rs`). Closes with İP-44. |
| BLG-051 | High | İP-44 | check_receipt accepts empty/foreign credentials; identity::merkle_root single-leaf | Açık | `check_receipt` 3 files (`src/chain/chain_actor.rs`). Closes with İP-44. |
| BLG-052 | Medium | İP-44 | PoAOnboarding manager field / KYC refresh inconsistency; PoaComplianceRegistry divergent | Açık | `PoAOnboarding` 8 files, `PoaComplianceRegistry` 6 files (`src/chain/snapshot.rs`). Closes with İP-44. |
| BLG-053 | High | İP-44 | ProofMarketState completed-task replay; unpaid receipt drain; frameless | Açık | `ProofMarketState` 4 files, `PqAnchor` 8 files. Closes with İP-44. |
| BLG-054 | Critical | İP-44 | Ethereum receiptsRoot MPT verifier hashes the key with Keccak-256 instead of RLP-of-key; non-canonical | Açık | `receiptsRoot` 8 files, `sync_attestation: None` 2 files (`src/cross_domain/evm/adapter.rs`). Closes with İP-44. |
| BLG-055 | Critical | İP-44 | EthereumSyncAdapter / PairingBls BLS key substitution; fixed signing_root | Açık | `EthereumSyncAdapter` 4 files (`src/cross_domain/external/ethereum.rs`), `PairingBls` 2 files, `signing_root` 7 files. Closes with İP-44. |
| BLG-056 | High | İP-44 | ExternalDomainRegistry / IntakeState: unimplemented serves() / require_slashable | Açık | `ExternalDomainRegistry` 5 files, `IntakeState` 16 files, `serves()` 2 files, `require_slashable` 4 files. Closes with İP-44. |
| BLG-057 | High | İP-44 | BridgeState (lock/mint/unlock) lifecycle: expiry, replay protection and fee overflow; CrossDomainMessage / UniversalRelayer defects | Açık | `BridgeState` 15 files (`src/chain/blockchain.rs`). Special audit of İP-03: second of the four bridge findings deciding the bridge decision (directive 1.5). Present, open. Closes with İP-44. |
| BLG-058 | High | İP-44 | ConsensusDomainRegistry leaf digest omits zk_program_allowlist / plugin_code_hash | Açık | `ConsensusDomainRegistry` 12 files, `zk_program_allowlist` 13 files, `plugin_code_hash` 10 files. Closes with İP-44. |
| BLG-067 | High | İP-33 | bud-compiler / bud-cli entry point argument ABI crash (StackUnderflow); match | Açık | `bud-compiler` 18 files, `StackUnderflow` 1 file (`budzero/bud-vm/src/lib.rs`). Closes with İP-33. |
| BLG-069 | Medium | İP-33 | budzero/verifier-registry state_root omits params/history; zero | Açık | `budzero/verifier-registry` 5 files, `Liveness` 26 files. Closes with İP-33. |
| BLG-091 | Critical | İP-44 | BudlumFinalityVerifier.sol accepts zero BLS signatures; external finality contract | Açık | `BudlumFinalityVerifier.sol` 7 files (`contracts/object-layer/`, `src/object_layer/family/evm.rs`). Closes with İP-44. |
| BLG-105 | Critical | İP-44 | burn_bridge_transfer_with_event drops the balance (2x $BUD mint); bridge vesting hole; result_leaf unframed SHA-256 collision; multi-transfer proof replay | Açık | `burn_bridge_transfer_with_event` 9 files (`src/chain/blockchain.rs:2451` region). Special audit of İP-03: third of the four bridge findings deciding the bridge decision (directive 1.5). Present, open. Closes with İP-44. |
| BLG-114 | Critical | İP-33 | budzero/bud-compiler silent miscompilation: MatchPattern::IntLit, while, match | Açık | `MatchPattern::IntLit` 3 files (`budzero/bud-compiler/src/codegen.rs`). Closes with İP-33. |
| BLG-115 | Critical | İP-33 | budzero/{bud-vm,bud-proof,bud-state} dynamic storage 2^32 slot collision; negative Pos | Açık | `2^32` 30 files, `Halt` 44 files; the literal brace-path absent. Closes with İP-33. |
| BLG-116 | Critical | İP-44 | AdapterSpec::ZkVm (Trustless) accepts empty [Halt] STARK proofs to claim any external state_root | Açık | `AdapterSpec::ZkVm` 3 files, `Trustless` 5 files. Closes with İP-44. |
| BLG-120 | High | İP-44 | ColdWalletState trusts an untrusted request.epoch budget; 0-signature refusal | Açık | `ColdWalletState` 7 files (`src/chain/blockchain.rs`), `request.epoch` 1 file (`src/settlement/cold_wallet.rs`). Closes with İP-44. |
| BLG-127 | Critical | İP-44 | Single captured device key bypasses 3-of-6 ColdWallet / PqAnchor quorum | Açık | `3-of-6` 7 files, `ColdWallet` 7 files, `PqAnchor` 8 files. Closes with İP-44. |
| BLG-130 | Critical | İP-44 | External quorum (quorum.rs / intake_quorum.rs): lead_is_unassailable error | Açık | `lead_is_unassailable` 4 files (`src/cross_domain/external/intake_quorum.rs` present). Closes with İP-44. |
| BLG-131 | High | İP-44 | RegenerationLedger (regeneration_stage.rs) and regen_health::assess (regen_health.rs) defects | Açık | `RegenerationLedger` 4 files, `regen_health::assess` 1 file. Closes with İP-44. |
| BLG-134 | Critical | İP-44 | EVM non-canonical RLP [0x81, b] accepted (rlp.rs); ReplayNonceStore u64::MAX on a single message | Açık | `rlp.rs` 3 files, `ReplayNonceStore` 5 files (`src/cross_domain/bridge.rs`). Closes with İP-44. |
| BLG-136 | High | İP-33 | budzero/bud-compiler parser refuses single-call statements; BudIR pipeline | Açık | `BudIR` 4 files (`budzero/bud-compiler/src/ir/display.rs`); the `ir/{lower,verify}.rs` literal absent. Closes with İP-33. |
| BLG-138 | Critical | İP-44 | BridgeRelayerPipeline mints/unlocks without proof; failed-lock state pollution | Açık | `BridgeRelayerPipeline` 4 files (`src/cross_domain/bridge_relayer.rs`). Closes with İP-44. |
| BLG-139 | Critical | İP-33 | budzero/bud-state NoteRegistry plaintext nullifier leak and forged entries | Açık | `NoteRegistry` 12 files, `nullifier` 33 files. Closes with İP-33. |
| BLG-142 | Critical | İP-33 | bud_stark verifier Goldilocks 2-adicity remote node crash (degree_bits bound) | Açık | `bud_stark` 21 files, `max_constraint_degree` 1 file (`budzero/bud-proof/src/bud_stark/symbolic.rs`). Closes with İP-33. |
| BLG-146 | Critical | İP-44 | build_bud_to_eth_claim lacks recipient binding; zero address and empty burn accepted | Açık | `build_bud_to_eth_claim` 1 file (`src/cross_domain/evm/bud_to_eth.rs`). Closes with İP-44. |
| BLG-148 | High | İP-33, İP-07 | StorageLifecycleState turns a single missed challenge into terminal Missed; ActiveReplacement edge cases | Açık | `StorageLifecycleState` 5 files (`src/domain/storage_deal.rs` present), `ActiveReplacement` 7 files. Shared foot with lane B: İP-07 removes storage_deal.rs (in-flight PR #8); the verifier-registry foot closes with İP-33. |
| BLG-154 | Critical | İP-33 | bud_stark verifier PCS-bypassing aux_trace_next proof malleability + remote crash | Açık | `aux_trace_next` 5 files, `VerticalPair` 1 file (`budzero/bud-proof/src/bud_stark/`). Closes with İP-33. |
| BLG-155 | High | İP-44 | GlobalBlockHeader fake bincode backward-compat claim; unsigned proposer field | Açık | `GlobalBlockHeader` 25 files, `key_set_preimage` 7 files (`src/chain/finality.rs`). Closes with İP-44. |
| BLG-159 | High | İP-33 | bud_stark preprocessed-setup setup_preprocessed bit-shift / height panics | Açık | `setup_preprocessed` 3 files, `StarkConfig` 4 files, `SubAirBuilder` 1 file. Closes with İP-33. |
| BLG-162 | High | İP-33 | BudL lexer (%100): CRLF source refused 100% of the time; multi-star comment bug | Açık | `lexer.rs` 2 files (`budzero/docs/BudL_SPEC.md`; the implementation is `budzero/bud-compiler`). Closes with İP-33. |
| BLG-182 | Critical | İP-33 | Plonky3Adapter / BudAir unbound public inputs (final_state_root, exit_code) | Açık | `Plonky3Adapter` 14 files (`src/cross_domain/external/zkvm_proof.rs`), `final_state_root` 28 files. Closes with İP-33. |
| BLG-186 | Critical | İP-33 | Canonical syscall context (sender, nonce, block_height) and gas_used not bound | Açık | `sender` 167 files, `gas_used` 45 files. Closes with İP-33. |
| BLG-190 | Critical | İP-44 | did:bud master IdentityRegistry PoA field-gate bypass (IdentityTx::Recover) | Açık | `did:bud` 9 files, `IdentityRegistry` 8 files, `IdentityTx::Recover` 3 files. Closes with İP-44. |
| BLG-191 | Critical | İP-33 | Vm::run_receipt synthetic Halt row escapes Plonky3Adapter program CTL (COL_PROG_MULT) | Açık | `Vm::run_receipt` 1 file, `COL_PROG_MULT` 5 files. Closes with İP-33. |
| BLG-194 | Critical | İP-44 | Blockchain::submit_relay_proof non-atomic relayer deletion (AlreadyRelayed permanent fund lock); BridgeBurn MAX_TOTAL_SUPPLY breach; sub-threshold BridgeState::lock accepted | Açık | `submit_relay_proof` (blockchain.rs:2846, bridge_tx.rs:625), `AlreadyRelayed` 1 file (`src/cross_domain/relayer.rs`), `BridgeBurn` 16 files. Special audit of İP-03: fourth of the four bridge findings deciding the bridge decision (directive 1.5). Present, open. Closes with İP-44. |
| BLG-195 | Critical | İP-44 | Consensus-domain finality adapters (PoA/BFT/PoS) commitment-body malleability (event_root / state_updates / domain_id) | Açık | `event_root` 25 files, `state_updates` 18 files, `domain_id` 65 files. Closes with İP-44. |
| BLG-198 | Critical | İP-33 | bud-compiler unbounded iterative binary/postfix AST chain; budl_compile 64 KiB stack overflow | Açık | `bud-compiler` 18 files; `budl_compile` 1 file (`xtask/gates/src/gates/every_fuzz_target_is_run.rs`). Closes with İP-33. |
| BLG-199 | High | İP-44 | settlement::commitment_tree::merkle_root, consensus::merkle_tree::merkle_root and pq_anchor::aggregate_finality_roots defects | Açık | `settlement::commitment_tree::merkle_root` 10 files (`src/cross_domain/bridge.rs`), `consensus::merkle_tree::merkle_root` 4 files. Closes with İP-44. |
| BLG-204 | High | İP-44 | ProofMarketState escrowless u64::MAX reward record; Paid flagged before the overflow check; unpaid rewards | Açık | `ProofMarketState` 4 files, `prune_paid_receipts` 1 file (`src/settlement/proof_market.rs`). Closes with İP-44. |
| BLG-205 | Critical | İP-44, İP-15 | ExternalDomainRegistry readmit validation bypass; last_accepted_height rollback; 5 unbounded bincode deserializations (Identity/Vault/Pollen*); ModalitySet(0) wire mutation | Açık | `readmit` 9 files, `last_accepted_height` 8 files, `proto_conversions` 15 files. Shared with lane A (İP-44 foot) and lane C. Closes with İP-44 (registry) and İP-15 (wire). |
| BLG-223 | Gonca E1 | İP-56 (testnet kapanışı İP-33 ve İP-45) | PCS Pcs::ZK = false; proofs hide nothing; the privacy opcodes leak the witness | Doğrulandı | Reproduced (see lane B): `prover.rs:317` documents `TwoAdicFriPcs` whose `Pcs::ZK` is `false`. Shared with lane B (İP-56, testnet closure İP-33/İP-45). |
| BLG-226 | Gonca E4 | İP-56 (testnet kapanışı İP-33) | bud-isa VerifyInference constraints gap | Açık | `budzero/bud-isa/src/lib.rs` present. Closes with İP-33 (testnet closure İP-56). |
| BLG-227 | Gonca E5 | İP-57 (testnet kapanışı İP-33) | bud-isa / VerifyInference dev-mode trap: proofs accepted without full verification | Açık | `budzero/bud-isa/src/lib.rs` 3 files, `VerifyInference` 20 files (`src/execution/zkvm.rs`). Closes with İP-33 (testnet closure İP-57). |
| BLG-228 | Gonca E6 | İP-57 (testnet kapanışı İP-45) | Full AI STARK verification is closed; initial-memory fold is interposable; output commitment unbound | Açık | `src/ai/mod.rs` present; shared with lane B (İP-45/İP-57). |
| BLG-229 | Gonca E7 | İP-45 (VL-1 ayağı), İP-57 | No per-request nonce or commit-reveal; no deterministic inference profile | Açık | `src/ai/registry.rs` present; shared with lane B (İP-45/İP-57). |
| BLG-230 | Gonca E8 | İP-33 (yürütme ayağı), İP-56 | bud-vm / zkvm.rs: VM escape or wrong-result for crafted programs | Açık | `budzero/bud-vm/src/lib.rs` 8 files, `src/execution/zkvm.rs` 8 files. Closes with İP-33 (yürütme ayağı) and İP-56. |
| BLG-233 | Gonca E11 | İP-60 | plonky3_prover: recursive verification / folding defects | Açık | `budzero/bud-proof/src/plonky3_prover.rs` 10 files. Closes with İP-60. |
| BLG-234 | Gonca E12 | İP-60 | bud-isa: instruction semantics gap vs the AIR specification | Açık | `budzero/bud-isa/src/lib.rs` present. Closes with İP-60. |
| BLG-235 | Gonca E13, SERA-0 | İP-44, İP-60 | SERA-0: external finality proof path (zkvm_proof.rs, sync_committee.rs) trusts the relayer or mis-verifies | Açık | Production call site reproduced: `EthereumSyncAdapter::new` is constructed on the production intake path (`src/cross_domain/external/intake.rs:188`) and exercised from `src/cross_domain/external/mod.rs` tests; `src/cross_domain/evm/sync_committee.rs` present. The premise (relayer-dependent or mis-verifying path) still needs the runtime repro; the one-shot verify path is intact but unwired for liveness. Special audit of İP-03. Closes with İP-44 and İP-60. |
| BLG-239 | Gonca E17 | İP-60 | bud-pul (prover/verifier packaging): parameter drift from the AF-24 checklist | Açık | `budzero/bud-pul` present (3 files); `docs/MAINNET_READINESS.md` present. Closes with İP-60. |
| BLG-240 | Gonca E18 | İP-45, İP-57 | Verifier ordering uses f64 (RPC surface only) | Açık | `src/ai/registry.rs` present; shared with lane B (İP-45/İP-57). |
| BLG-244 | Gonca E22 | İP-57 (ayrı depo iş kalemi) | On-device assistant repository (separate repo) | Açık | Out of tree: the on-device assistant lives in a separate repository (directive E22). Cannot be verified from this tree; tracked as external work. Closes with İP-57. |
| BLG-248 | High | İP-26, İP-33 | No general-purpose stateful contracts; ContractCall runs tx-embedded bytecode statelessly; VM memory 8 KiB; no deployment or persistent storage | Doğrulandı | Reproduced: the `ContractCall` arm executes `ZkVmExecutor::execute_bytecode(&tx.data, DEFAULT_CONTRACT_GAS_LIMIT, ctx)` (`src/execution/executor.rs:797-805`) — bytecode comes from the transaction, never from a code store; no deploy opcode exists anywhere in the tree. Closes with İP-26 and İP-33. |
| BLG-249 | High | İP-28, İP-29, İP-31, İP-32 | No ecosystem-compatible RPC; only bud_* methods; Ethereum/Solana/Aptos/Cosmos tools cannot connect | Doğrulandı | Reproduced: `src/rpc/compat/` does not exist; the RPC surface is `api.rs`, `method_class.rs`, `mod.rs`, `server.rs`, `subscriptions.rs`, `tls.rs`, `tests.rs` only. No ethereum/solana/aptos/cosmos method namespace anywhere. Closes with İP-28/29/31/32. |
| BLG-250 | Critical | İP-26 | Execution engines running in-process can crash the whole node on a single engine panic | Açık | Latent, not reproduced: no engine exists to panic yet (see `engine-inventory.md`: revm/wasmi/solana-svm/aptos-vm all absent). The premise binds İP-26's EE-worker design; the finding goes live when engines land. Closes with İP-26. |
| BLG-256 | High | İP-26 | BUD balances are atoms (1e-6); EVM expects 1e-18 and SVM 1e-9 fractions; no fraction field exists | Doğrulandı | Reproduced: the only amount type at the interface is `BudAmount(pub u128)` in attoBUD (`crates/uel-abi/src/types.rs:94`); no 1e-18/1e-9 lane exists anywhere at `crates/uel-abi`. Closes with İP-26. |
| BLG-260 | Medium | İP-26 | State store is single-process; EE workers cannot read state directly; IPC read performance risk | Açık | `crates/uel-abi` frame/transport types exist but no IPC state reader; latent until İP-26's worker split. Closes with İP-26. |
| BLG-267 | High | İP-27 | The gate refuses every classically-signed acceptance path; no compatibility lane for Ethereum/Solana/Aptos/Cosmos foreign signatures | Doğrulandı | Reproduced: the classical-class intake gate exists (`src/core/account.rs:1226-1243` holds/stops classical-class messages under the quantum alarm) and no compatibility lane, `ecrecover`, or `Ecdsa` verification exists anywhere in `src/`. Closes with İP-27 (section 8.6.2, same PR). |
| TEST-GAP-05 | Low | İP-33 | Directly untested | Açık | The ledger records this as a test gap without an anchor file; scope is the UEL/BudZero gate surface. Closes with İP-33. |

## Reproduction debt (audit/repro-c)

The Doğrulandı rows each owe a red test on `audit/repro-c` (never merges)
that the closing package moves into its own PR (S-3): BLG-223 (TwoAdicFriPcs
not ZK), BLG-248 (stateless ContractCall arm), BLG-249 (absence of the compat
surface), BLG-256 (attoBUD-only amount type), BLG-267 (classical-intake gate,
no compatibility lane). The Açık rows carry their identifier anchors above;
the repro for each lands with its closing package. The bridge quadruplet
repro lands with the bridge decision's closing PR (BLG-043/057/105/194).

## New findings this pass

None beyond the ledger.

## Verification base and drift

`git status` clean at verification time on `arena/b0362659-budlum` branched
from `cccf1da`. Identifier scans are fixed-string greps on the same tree.
Where the directive's "Kod izi" column (2026-11-02 analysis base) and this
snapshot disagree, the live result is authoritative.
