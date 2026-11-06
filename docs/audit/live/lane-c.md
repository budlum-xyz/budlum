# Live Verification Status - Lane C

Lane C findings verified on the live branch (main@cccf1da) by IP-01..04 (M0). Statuses per Directive 14.1 item 4; closure packages per Directive 14.3. Source of truth: docs/audit/LIVE_STATUS.md. Total records: 35.

| ID | Severity | Area | Live status | Reproduction test | Proof (file:line) | Closes with |
|---|---|---|---|---|---|---|
| BLG-036 | Critical | ZK / Circuit soundness | Open | blg_036_budair_active_bit | budzero/bud-proof/ (15/15 traces) | IP-33|
| BLG-037 | Critical | ZK / Circuit soundness | Open | blg_037_verify_inference_fake_witness | budzero/bud-vm/, src/privacy/ (12/13 traces) | IP-33|
| BLG-038 | Critical | ZK / Cryptography | Open | blg_038_linear_memory_chain_id | budzero/ (17/18 traces) | IP-33|
| BLG-039 | Critical | ZK validator / Remote DoS | Open | blg_039_stark_degree_bits_27 | budzero/bud-proof/ (6/6 traces) | IP-33|
| BLG-040 | High | ZKVM / Consensus execution | Open | blg_040_verify_merkle_one_round | src/execution/zkvm.rs, budzero/ (13/15 traces) | IP-33|
| BLG-067 | High | Compiler / ZK toolchain | Open | blg_067_bud_compiler_entry_abi | budzero/bud-compiler/ (30/30 traces) | IP-33|
| BLG-069 | High | Validator registry / Cross-check | Open | blg_069_verifier_registry_state_root | budzero/verifier-registry/ (9/9 traces) | IP-33|
| BLG-114 | Critical | zkVM compiler | Open | blg_114_bud_compiler_match_intlit | budzero/bud-compiler/ (10/10 traces) | IP-33|
| BLG-115 | Critical | ZKVM / Cryptography / State tree | Open | blg_115_budzero_dynamic_storage | budzero/bud-vm/, bud-proof/, bud-state/ (13/19 traces) | IP-33|
| BLG-136 | High | Smart contract compiler | Open | blg_136_bud_compiler_parser_single_call | budzero/bud-compiler/parser.rs (30/32 traces) | IP-33|
| BLG-139 | Critical | Privacy note state tree | Open | blg_139_note_registry_nullifier_leak | budzero/bud-state/ (17/22 traces) | IP-33|
| BLG-142 | Critical | zkVM STARK soundness / Proof flexibility | Open | blg_142_bud_stark_goldilocks_2_adic | budzero/bud-proof/src/bud_stark/ (23/25 traces) | IP-33|
| BLG-148 | High | B.U.D. agreement lifecycle / Registry echo | Open - split IP-07 / IP-33 | blg_148_storage_lifecycle_missed_terminal | src/storage/lifecycle.rs (IP-07 part); budzero/verifier-registry/ (IP-33 part; 17/19 traces) | IP-33, IP-07|
| BLG-154 | Critical | STARK validator soundness / DoS | Open | blg_154_bud_stark_aux_trace_next | budzero/bud-proof/src/bud_stark/ (19/21 traces) | IP-33|
| BLG-159 | High | Zero-knowledge proof system | Open | blg_159_bud_stark_setup_preprocessed | budzero/bud-proof/src/bud_stark/ (14/17 traces) | IP-33|
| BLG-162 | High | BudZero smart contract compiler | Open | blg_162_budl_lexer_crlf_reject | budzero/bud-compiler/lexer.rs (13/16 traces) | IP-33|
| BLG-182 | Critical | ZKVM STARK soundness / Sender/nonce canonicality | Open | blg_182_plonky3_adapter_unbound_public_inputs | budzero/ (19/21 traces) | IP-33|
| BLG-186 | Critical | ZKVM STARK field canon / Sender nonce height | Open | blg_186_proof_envelope_degree_bits | budzero/ (17/19 traces) | IP-33|
| BLG-191 | Critical | ZKVM completeness & soundness / STARK program search | Open | blg_191_vm_run_receipt_synthetic_halt | budzero/ (20/22 traces) | IP-33|
| BLG-198 | Critical | zkVM compiler stack safety / Proof baseline | Open - partial removal | blg_198_bud_compiler_recursive_sigabrt | budzero/bud-compiler/ (10/12 traces) | IP-33|
| BLG-223 | High | Gonca E1 | Open | blg_223_bud_stark_pcs_zk_false | budzero/bud-proof/src/bud_stark/prover.rs | IP-56 (testnet closure IP-33, IP-45)|
| BLG-226 | High | Gonca E4 | Open | blg_226_verify_merkle_single_round | budzero/bud-isa/src/lib.rs | IP-56 (testnet closure IP-33)|
| BLG-227 | Medium | Gonca E5 | Open | blg_227_verify_inference_summary_only | src/ai/mod.rs; docs/AI_VERIFICATION_STATUS.md | IP-57 (testnet closure IP-33)|
| BLG-230 | Medium | Gonca E8 | Open | blg_230_sender_64bit_vs_address_256bit | budzero/bud-vm/src/lib.rs; src/execution/zkvm.rs | IP-33 (execution leg), IP-56|
| BLG-233 | Medium | Gonca E11 | Open | blg_233_mmcs_keccak_no_recursion | budzero/bud-proof/src/plonky3_prover.rs | IP-60|
| BLG-234 | Medium | Gonca E12 | Open | blg_234_only_budl_isa | budzero/bud-isa/src/lib.rs | IP-60|
| BLG-235 | High | Gonca E13, SERA-0 | Open | blg_235_zkvm_proof_only_zk_domain | src/cross_domain/external/zkvm_proof.rs; evm sync committee | IP-44, IP-60|
| BLG-239 | Medium | Gonca E17 | Open | blg_239_sigagg_proof_not_bound_in_air | docs/MAINTAINCE?; budzero/bud-pul | IP-60|
| BLG-248 | High | src/execution/executor.rs / zkvm.rs | Open | blg_248_no_general_purpose_contract | src/execution/executor.rs ContractCall stateless; CONTRACT_VM_MEMORY_BYTES = 8192 | IP-26, IP-33|
| BLG-249 | High | src/rpc/method_class.rs | Open | blg_249_only_bud_rpc_methods | src/rpc/method_class.rs (all 180 methods bud_ prefixed; no eth/solana/aptos/cosmos gateways) | IP-28, IP-29, IP-31, IP-32|
| BLG-250 | Critical | Cargo.toml [profile.release] panic="abort" | Open | blg_250_release_panic_abort_ee_isolation | Cargo.toml:395 `panic = "abort"`; execution environments run in node process | IP-26|
| BLG-256 | High | src/core/account.rs (balance: u64) | Open | blg_256_budget_no_fraction_field | src/core/account.rs (atom 10^-6 BUD; no frac_attos field; 18-decimal EVM / 9-decimal SVM exact transfer impossible) | IP-26|
| BLG-260 | Medium | src/storage/db.rs (sled) | Open | blg_260_single_process_state_store | src/storage/db.rs (single-process sled; execution workers cannot read state directly; IPC read performance risk) | IP-26|
| BLG-267 | High | xtask/gates/classical_crypto_is_paired.rs | Open | blg_267_foreign_tx_compliance_shim | xtask/gates/src/gates/classical_crypto_is_paired.rs (rejects all classical signatures; no compliance shim per 8.6.2) | IP-27|
| TEST-GAP-05 | Medium | budzero folder.rs, ir/mod.rs | Open | - | - | IP-33|
