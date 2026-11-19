# Findings register: closure evidence

Inspection baseline: `81db9a2ada639beca443e6e2ebef4d29023ebbb0`. This is a mechanical index of directive F-001 through F-267, not a live audit. Unknown / unverified is not fixed, open, removed, or invalid. F-005 was called closed in an older ledger but lacks current-run confirmation. No closure SHA, CI run, approval, or testnet rejection result was verified. See [LIVE_STATUS.md](LIVE_STATUS.md) for severity, directive source line and planned package.

For closure, record named reproduction test and pre-fix red result (or permanent regression test for a previously fixed finding), post-fix green result, merged SHA, CI run ID and independent reviewer. Removal also requires a removed-path list and green `no-legacy-storage`. An unclosed Critical/High finding requires a tested feature closure on chain 45261. Do not issue F-268 or higher for an issue duplicating a directive ID.

| ID | Disposition | Reproduction test / red evidence | Closure or removal evidence | Merged SHA | CI run | Closed-feature test | Reviewer |
|---|---|---|---|---|---|---|---|
| F-001 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-002 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-003 | Fixed in tree. Issuance is checked as one total: allocations, distribution, validator stake and the reward pool, with the stake and pool required to fit inside the ecosystem share. | tests::regression_chain::genesis_issuance_is_checked_as_one_total | src/chain/genesis.rs:481 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-004 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-005 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-006 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-007 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-008 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-009 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-010 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-011 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-012 | Fixed in tree. The total line is read, and a NaN baseline is refused by the parser. | xtask gates coverage self-test: the_total_is_read_not_the_first_file | xtask/gates/src/gates/coverage.rs:44 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-013 | Fixed in this round. The helper now runs the same clippy invocation CI runs, without the combination that cannot build. | xtask::tools budlum_tools prepush::tests::the_clippy_check_matches_the_ci_invocation | xtask/tools/src/prepush.rs:36 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-014 | Fixed in tree. The restore exit code and the integrity exit code are both refused, and the integrity line is parsed, not substring matched. | xtask tools backup drill self-test | xtask/tools/src/backup_drill.rs:216 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-015 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-016 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-017 | Fixed in tree. Every peer string reaches a log through a character-counted prefix; no byte slice of a peer string is left. | network::node::tests::log_prefix_survives_multibyte_input; network::node::tests::no_byte_slice_of_checkpoint_hash_in_logs | src/network/node.rs:405 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-018 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-019 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-020 | Fixed in tree. Selection runs on a disposable candidate, and the block path demands the exact account nonce before any arm runs. | tests::regression_chain::producer_executes_on_a_disposable_candidate_state; tests::regression_chain::a_block_transaction_must_carry_the_exact_account_nonce | src/chain/blockchain.rs:4618; src/execution/executor.rs:4672 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-021 | Fixed in tree. A role bond is additive and settled inside the block, and the out-of-block RPC bond doors are refused. | tests::regression_chain::role_bond_is_additive_and_rpc_doors_are_refused | src/core/account.rs:2927 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-022 | Fixed in tree. Closed-form walk, no loop. | light_client::tests::next_checkpoint_height_is_closed_form; tests::regression_ops_crypto::next_checkpoint_height_terminates_at_the_u64_edge (both green, local run 2026-11-16) | src/light_client/mod.rs:689 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-023 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-024 | Fixed in this round. A zero denominator requires every authority instead of calling div_ceil(0). | domain::finality_adapter::tests::a_poa_adapter_with_a_zero_denominator_requires_every_authority (green, local run 2026-11-16) | src/domain/finality_adapter.rs:815 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-025 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-026 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-027 | Invalid as reported. A validator is bound to its registered ML-DSA-65 consensus key, and a V5 wallet address is a user account, not a validator identity. The binding is enforced on every validator transaction. | core::account::tests::a_v7_validator_transaction_verifies_from_its_ed25519_address; core::account::tests::a_self_signed_key_registration_before_registration_is_refused | src/core/account.rs:2079 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-028 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-029 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-030 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-031 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-032 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-033 | Fixed in tree. Every unbounded P2P decode goes through a byte-limited decoder. | network::bounded_bincode::tests (green in the lib run that carries this row) | src/network/bounded_bincode.rs:459 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-034 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-035 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-036 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-037 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet; execution::budzero_ee::tests::verify_inference_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet; execution::budzero_ee::tests::verify_inference_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-038 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-039 | Fixed in tree. A claimed degree above the verifier ceiling is refused before any shift. | budzero bud-proof verifier: degree_bits_ceiling_guards_goldilocks_two_adicity (green in the budzero crate run) | budzero/bud-proof/src/bud_stark/verifier.rs:359 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-040 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-041 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-042 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-043 | Fixed in tree. The unlock door re-derives the payload, refuses a zero recorded debit, checks the owner credit for overflow, and refuses a mismatched domain, sender or recipient. | cross_domain::bridge_tx tests around the unlock door | src/cross_domain/bridge_tx.rs:630 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-044 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-045 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-046 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-047 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-048 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-049 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-050 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-051 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-052 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-053 | Fixed in tree. A task cannot be completed twice: the receipt check and the retired-id set both refuse it. | settlement::proof_market tests | src/settlement/proof_market.rs:1032 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-054 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-055 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-056 | Fixed in tree. The bridge enforces `require_slashable` for every external domain it admits. | cross_domain::external::domain_bridge::tests::require_slashable_is_enforced_at_the_bridge | src/cross_domain/external/domain_bridge.rs:163 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-057 | Fixed in tree. The bridge transfer carries a bounded expiry, the expiry queue is keyed by height, and the replay store refuses a second delivery. | cross_domain bridge lifecycle tests | src/cross_domain/bridge.rs:270 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-058 | Fixed in tree. The domain leaf check consults the ZK program allow list, so a program that is not listed cannot settle. | settlement domain leaf tests | src/settlement/domains.rs:1269 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-059 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-060 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-061 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-062 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-063 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; tests::testnet_closed_features::note_registry_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; tests::testnet_closed_features::note_registry_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-064 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-065 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-066 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-067 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-068 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-069 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-070 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-071 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-072 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-073 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-074 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-075 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-076 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-077 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-078 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-079 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-080 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-081 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-082 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-083 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-084 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-085 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-086 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-087 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-088 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-089 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-090 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-091 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-092 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-093 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-094 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-095 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-096 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-097 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-098 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-099 | Fixed in tree. No self comparison on a length mismatch. | tests::hardening_h4_locks::constant_time_eq_str_correctness; tests::regression_ops_crypto (spec assertion) (green, local run 2026-11-16) | src/rpc/server.rs:1290 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-100 | Fixed in tree. Liquid cost is fee-only for fee-only doors, so a fully staked validator can unstake; admission, projection and execution share the classification. | tests::tokenomics::fee_gate_respects_vesting_lock | src/core/transaction.rs:2481; src/core/account.rs:2183 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-101 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-102 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-103 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-104 | Fixed in tree. The byte budget is charged after the count check and before the replacement is removed, so a refusal cannot delete a transaction it does not replace. | mempool::pool tests (byte budget and replacement refusal) | src/mempool/pool.rs:528 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-105 | Fixed in tree. The burn records the debit it made, and the claim pays the recorded debit rather than the gross amount. | cross_domain::evm::bud_to_eth tests | src/cross_domain/evm/bud_to_eth.rs:135 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-106 | Fixed in tree. The execution dims width is bounded to 2..=32 layers and no layer may be zero before any allocation. | ai::types dims bounds test | src/ai/types.rs:308 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-107 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-108 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-109 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-110 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-111 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-112 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-113 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-114 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-115 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-116 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-117 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-118 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-119 | Fixed in tree. A full unstake cannot escape the queue, and a slash sweeps every other role the account holds. | core::account::tests::slash_validator_counts_cross_role_sweep_in_burned_total | src/core/account.rs:2981; src/registry/permissionless.rs:938 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-120 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-121 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-122 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-123 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-124 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-125 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-126 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-127 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-128 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-129 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-130 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-131 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-132 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-133 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-134 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-135 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-136 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-137 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-138 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-139 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-140 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-141 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-142 | Fixed in tree. Same ceiling guard as F-039; the proof bytes cannot choose a domain size. | budzero bud-proof verifier: degree_bits_ceiling_guards_goldilocks_two_adicity | budzero/bud-proof/src/bud_stark/verifier.rs:359 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-143 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-144 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-145 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-146 | Fixed in tree. The recipient comes from the burn, a zero address and an empty proof are refused, and the amount is the burned debit capped by the bridge cap. | cross_domain::evm::bud_to_eth tests around `build_bud_to_eth_claim` | src/cross_domain/evm/bud_to_eth.rs:155 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-147 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-148 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-149 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-150 | Fixed in tree. Each signed object carries its own context tag. | tests::regression_ops_crypto::vote_signatures_are_domain_separated_from_block (green, local run 2026-11-16) | src/consensus/block_signature.rs:58 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-151 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-152 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-153 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-154 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-155 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-156 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-157 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-158 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-159 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-160 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-161 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-162 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-163 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-164 | Fixed in tree. A height that does not fit the u32 epoch is refused, not truncated. | crates/bpqs epoch tests (green in the bpqs crate run) | crates/bpqs/src/epoch.rs:26 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-165 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-166 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-167 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-168 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-169 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-170 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-171 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-172 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-173 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-174 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-175 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-176 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-177 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-178 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-179 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-180 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-181 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-182 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-183 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-184 | Fixed in tree. Candidate execution, contract-call count and the serialized-size budget are all charged only for included transactions, so a failed transaction cannot buy block room. | tests::regression_chain::producer_executes_on_a_disposable_candidate_state | src/chain/blockchain.rs:4606 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-185 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-186 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-187 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-188 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-189 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-190 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-191 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-192 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-193 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-194 | Fixed in tree. The relay ledger is snapshotted and restored when a bridge effect refuses, and every check runs before the first mutation. | cross_domain bridge relay tests | src/cross_domain/bridge_tx.rs:736 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-195 | Fixed in tree. The commitment digest binds event root and the state updates map, the adapters refuse a foreign domain id, and PoW work saturates at the documented ceiling. | tests::fork_choice_locks::a_longer_chain_still_wins_at_the_difficulty_that_used_to_saturate | src/domain/finality_adapter.rs:533,1066; src/consensus/pow.rs:194 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-196 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-197 | Fixed in tree. Cost paths use the checked classification; `total_cost` survives only as a documented compatibility estimate and is read by tests alone. | core::transaction tests around `total_cost`; tests::proptest_core | src/core/transaction.rs:2491 | 11th-round head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-198 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-199 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-200 | Fixed in tree. The zero scalar and the identity public key are refused. | tests::regression_ops_crypto::bls_from_bytes_refuses_zero_secret (green, local run 2026-11-16) | src/crypto/primitives.rs:152 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-201 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-202 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-203 | Fixed in tree. The proof length, element width, zero root and high index bits are all refused. | consensus::qc tests (green in the lib run that carries this row) | src/consensus/qc.rs:691 | 36959d6b54f3783cfd997d93b93449dd0c159ff0 | 43811629332 (queued at write time) | Not needed, the feature is on and the test is green | Self review of the live source, not an independent reviewer |
| F-204 | Fixed in tree. The reward is escrowed before the task exists, the deadline span is bounded, and the payout total is computed before the receipt changes state. | settlement::proof_market tests | src/settlement/proof_market.rs:1055,1160 | fb4c7b596da3af0b2fc534e14a546d0c5a9ab306 | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-205 | Fixed in tree. `readmit` demands an admitted, golden-verified report whose every test passed and whose adapter version matches the record. | cross_domain::external::registry tests: readmit_reopens_a_faulted_domain_but_is_not_an_edit | src/cross_domain/external/registry.rs:355 | e3d384085f0aa506ff37b84fc8d7a3656053256a | 43821954493 (queued at write time) | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-206 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-207 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-208 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-209 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-210 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-211 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-212 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-213 | Fixed in this round for the frame container. The raw-frame mux refuses a frame or a frame count that does not fit its 32-bit field instead of truncating it. | storage::qr_codec::field_width_tests::a_container_field_wider_than_32_bits_is_refused | src/storage/qr_codec.rs:126 | next head, see the plan log | queued at write time | Not needed, the feature is on and its test is green | Self review of the live source, not an independent reviewer |
| F-214 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-215 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-216 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-217 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-218 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-219 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-220 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-221 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-222 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-223 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-224 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-225 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-226 | Open. Feature closed on testnet; the closure is proven by a named test. | execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-227 | Open. Feature closed on testnet; the closure is proven by a named test. | execution::budzero_ee::tests::verify_inference_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | execution::budzero_ee::tests::verify_inference_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-228 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-229 | Open. Feature closed on testnet; the closure is proven by a named test. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | The feature is refused on chain 45261; the code path is unreachable there. | Open | queued at write time | tests::testnet_closed_features::ai_layer_is_closed_on_testnet | Self review of the live source, not an independent reviewer |
| F-230 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-231 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-232 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-233 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-234 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-235 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-236 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-237 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-238 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-239 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-240 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-241 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-242 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-243 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-244 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-245 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-246 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-247 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-248 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-249 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-250 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-251 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-252 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-253 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-254 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-255 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-256 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-257 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-258 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-259 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-260 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-261 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-262 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-263 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-264 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-265 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-266 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |
| F-267 | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |

## New-issue triage

No F-268 or later is allocated by this source inventory. For the testnet RPC
authentication conflict, first compare F-008, F-030 and F-098; for
hard-coded Android owner/faucet onboarding, compare F-257. Faucet PoW and
state-file work still needs tests and a shipped commit, not a guessed fixed
status. An uncommitted RPC-auth split is not shipped evidence. Distinct issues
may receive new IDs only after documenting their non-overlap and reproducing
them against the current branch.
