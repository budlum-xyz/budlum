# Live Verification Status - Lane A

Lane A findings verified on the live branch (main@cccf1da) by IP-01..04 (M0). Statuses per Directive 14.1 item 4; closure packages per Directive 14.3. Source of truth: docs/audit/LIVE_STATUS.md. Total records: 123.

| ID | Severity | Area | Live status | Reproduction test | Proof (file:line) | Closes with |
|---|---|---|---|---|---|---|
| BLG-001 | Critical | Consensus | Open | blg_001_leader_round_skip | src/consensus/filiz.rs, src/consensus/handoff.rs (MAX_LEADER_ROUNDS, affordable_leader_round; snapshot kod izi 2/2) | IP-12|
| BLG-002 | High | Consensus | Open | blg_002_testnet_genesis_template | config/testnet-genesis.json, ops/ (snapshot: 4/4 traces; template has no validator/tokenomics) | IP-16|
| BLG-003 | High | Tokenomics | Open | blg_003_genesis_supply_cap | src/chain/genesis.rs, src/tokenomics/ (snapshot: 6/7 traces) | IP-16|
| BLG-005 | Medium | Build/CI | Closed | — | Source ledger record (defter kaydi) | IP-16|
| BLG-006 | Medium | Tokenomics | Open | blg_006_reward_pool_epoch_pay | src/tokenomics/reward_pool.rs (pay_epoch; snapshot 2/2 traces; extended by 11.4 / BLG-263) | IP-16|
| BLG-007 | Medium | Consensus | Open | blg_007_global_block_header_commitment | src/chain/, src/consensus/ (snapshot 3/3 traces; PQ block budget JSON) | IP-17|
| BLG-008 | Medium | RPC | Verified | blg_008_rpc_auth_required | config/testnet.toml:50 `auth_required = true`; docs/TESTNET.md documents keyed reads (snapshot: 5/5 traces, open verified) | IP-16|
| BLG-017 | Critical | Network/P2P | Open | blg_017_p2p_utf8_finality_panic | src/network/ (snapshot 8/8 traces: Prevote/Precommit/FinalityCert) | IP-15|
| BLG-018 | Critical | Consensus | Open | blg_018_hybrid_finality_stall | src/consensus/ (snapshot 13/13 traces; finalized_height) | IP-12|
| BLG-019 | Critical | State transition | Open | blg_019_state_update_retired | src/core/transaction.rs (StateUpdate retired; snapshot 4/5 traces, fix trace present) | IP-17|
| BLG-020 | Critical | Consensus / State transition | Open | blg_020_collect_block_transactions_temp_state | src/core/transaction.rs (snapshot 24/25 traces; candidate state copy) | IP-17|
| BLG-021 | Critical | Tokenomics | Open | blg_021_role_bond_burn | src/core/account.rs, src/registry/ (bond_relayer/bond_prover/bond_storage_operator; 12/12 traces) | IP-17|
| BLG-023 | Medium | State transition | Open | blg_023_relayer_result_domain_event_tree | src/execution/ (snapshot 8/8 traces; RELAYER bond lookup) | IP-17|
| BLG-024 | Low | Consensus | Open | blg_024_finality_adapter_domain_check | src/consensus/ (PoW/PoS/PoA/BFT adaptors; 8/8 traces; PoAFinalityAdapter zero divisor) | IP-44|
| BLG-027 | High | Consensus | Open | blg_027_v5_wallet_address_incompatibility | src/registry/, src/crypto/ (ML-DSA-87 V5; 13/13 traces) | IP-12|
| BLG-028 | High | Storage | Open | blg_028_snapshot_v2_apply_atomic | src/chain/ (StateSnapshotV2::from_bytes; 4/4 traces) | IP-17|
| BLG-031 | Low | Consensus | Open | blg_031_governance_proposals_cap | src/registry/ (snapshot 10/10 traces; bpqs::EpochWindow u32 truncation) | IP-17|
| BLG-033 | Critical | Network / Serialization | Verified | blg_033_unbounded_bincode_p2p | proto_conversions.rs:1279-1410 per snapshot note (unbounded bincode::deserialize on unauthenticated P2P frame); 13/14 traces | IP-15|
| BLG-034 | High | Network / P2P | Open | blg_034_p2p_subnet_diversity_ipv6 | src/network/ (snapshot 12/12 traces) | IP-15|
| BLG-041 | Critical | Consensus / Chain state | Open | blg_041_settlement_root_replay | src/chain/ (29/34 traces) | IP-17|
| BLG-042 | Critical | Consensus security / Slashing | Open | blg_042_failed_bls_slash_accounting | src/consensus/, src/core/account.rs (10/11 traces) | IP-17|
| BLG-043 | Critical | Bridge / Storage accounting | Open | blg_043_unlock_bridge_transfer | src/settlement/, src/cross_domain/ (14/19 traces) | IP-44|
| BLG-044 | Medium | Consensus / Persistence | Open | blg_044_import_qc_blob_cache | src/chain/ (14/16 traces) | IP-17|
| BLG-050 | Critical | Security / Identity / State root | Open | blg_050_identity_recover_poa_gate | src/registry/ (16/16 traces) | IP-44|
| BLG-051 | High | Security / Selective disclosure | Open | blg_051_check_receipt_foreign_credential | src/registry/identity* (9/9 traces) | IP-44|
| BLG-052 | Medium | Consensus / PoA compliance | Open | blg_052_poa_onboarding_hashmap | src/consensus/poa.rs (15/16 traces) | IP-44|
| BLG-053 | High | Economy / Settlement security | Open | blg_053_proof_market_replay | src/settlement/ (16/16 traces) | IP-44|
| BLG-054 | Critical | Cryptography / Bridge / Consensus | Open | blg_054_ethereum_receiptsroot_mpt | src/cross_domain/evm/ (15/19 traces) | IP-44|
| BLG-055 | Critical | Cryptography / External finality | Open | blg_055_pairing_bls_signing_root | src/cross_domain/ (17/18 traces) | IP-44|
| BLG-056 | High | Consensus / Economy / DoS | Open | blg_056_external_domain_freeze | src/registry/ (29/30 traces) | IP-44|
| BLG-057 | High | Consensus / Bridge accounting | Open | blg_057_bridge_state_lifecycle | src/settlement/ (17/17 traces) | IP-44|
| BLG-058 | High | Consensus / State root / Determinism | Open | blg_058_domain_registry_leaf_digest | src/consensus/ (19/19 traces) | IP-44|
| BLG-065 | High | Application state / Consensus integrity | Open | blg_065_nfttag_fee_burn | src/socialfi/, src/bns/, src/sharding/ (27/27 traces) | IP-17|
| BLG-066 | High | Node runtime / Persistence / CLI | Open | blg_066_cli_chain_id_mainnet | src/main.rs (bud CLI hardcoded Mainnet chain_id; 19/20 traces) | IP-17|
| BLG-088 | Medium | Test quality / Regression locks | Open | blg_088_integration_test_stubs | src/tests/ (14/14 traces; 8/11 lockfiles skipped; fixed TCP port collisions) | IP-17|
| BLG-089 | High | Storage soundness / Consensus state root | Open - partial removal | blg_089_coding_audit_column_binding | src/storage/ (16/17 traces) | IP-17|
| BLG-090 | Medium | Test package integrity / Build coverage | Open - partial removal | blg_090_cfg_false_settlement_prod | src/bin/budlum-domain-producer.rs settlement_prod.rs cfg(false); domain_throughput.rs (12/14 traces; 15 files with Turkish remnants) | IP-17|
| BLG-091 | Critical | External-domain contract / Cryptography | Open | blg_091_budlum_finality_verifier_zero_bls | contracts/ (18/22 traces) | IP-44|
| BLG-094 | High | Configuration / Operations / CI gate | Open | blg_094_archive_chain_id_42 | config/archive.toml has chain_id = 42; ops/docker-compose.yml pow --difficulty=0; ops/Dockerfile Turkish text (3/3 traces) | IP-16|
| BLG-096 | High | Consensus / Finality / Slashing | Open | blg_096_invalidate_finality_orphan_cert | src/consensus/ (21/22 traces) | IP-12|
| BLG-100 | Critical | Consensus | Open | blg_100_unstake_amount_plus_fee_lock | src/core/account.rs, src/execution/executor.rs (32/33 traces) | IP-17|
| BLG-101 | Critical | Consensus state root / Snapshot | Open | blg_101_snapshot_v2_restore_poa_lock | src/chain/ (27/30 traces) | IP-17|
| BLG-102 | Critical | Consensus fork choice | Open | blg_102_try_reorg_bridge_state_leak | src/chain/ (17/19 traces) | IP-17|
| BLG-103 | Critical | On-chain governance / Slashing | Open | blg_103_governance_slashed_voter_weight | src/registry/ (26/27 traces) | IP-17|
| BLG-104 | Critical | Mempool admission / Block building | Open | blg_104_mempool_poolbytesfull_rbf | src/mempool/ (24/28 traces; sled stale transaction leak) | IP-17|
| BLG-105 | Critical | Consensus / Bridge / Tokenomics / Crypto | Open | blg_105_burn_bridge_transfer_double_mint | src/settlement/ (15/17 traces) | IP-44|
| BLG-107 | Critical | Consensus / Storage market / SocialFi / Tokenom | Open - partial removal | blg_107_nftboost_produce_block_hang | src/socialfi/ (16/17 traces) | IP-17|
| BLG-108 | Critical | Network | Open | blg_108_gossipsub_unauthenticated_ban | src/network/ (22/24 traces) | IP-15|
| BLG-113 | Critical | Persistent storage | Open | blg_113_sled_recover_interrupted_commit | src/storage/db.rs (sled; 19/19 traces) | IP-17|
| BLG-116 | Critical | Cross-domain bridge / ZK verification / RPC | Open | blg_116_adapter_spec_zkvm_empty_stark | src/cross_domain/, src/rpc/ (27/31 traces) | IP-44|
| BLG-118 | Critical | Consensus / Transaction witness / Quantum AA | Open | blg_118_tx_root_witness_blindness | src/core/transaction.rs, src/execution/executor.rs (26/27 traces) | IP-17|
| BLG-119 | Critical | PoS security / Slashing accounting | Open | blg_119_unstake_slashing_escape | src/consensus/pos.rs (31/33 traces) | IP-17|
| BLG-120 | High | Settlement security / Cold wallet / Quantum anchor | Open | blg_120_cold_wallet_epoch_budget | src/settlement/, crates/bpqs/ (29/33 traces) | IP-44|
| BLG-125 | Critical | Consensus state boundary / Storage privacy | Open - partial removal | blg_125_storage_rpc_zero_cost_split | src/storage/, src/gateway/ (48/58 traces) | IP-17|
| BLG-127 | Critical | Consensus / Cryptography / Settlement capacity / Bridge | Open | blg_127_cold_wallet_3_of_6_anchor | src/settlement/, crates/bpqs/ (35/37 traces) | IP-44|
| BLG-128 | High | Light client proofs / Storage shard assignment | Open | blg_128_merkle_trie_proof_no_cap | src/chain/, src/storage/assignment.rs (25/26 traces) | IP-17|
| BLG-130 | Critical | Consensus / Cross-domain bridge finality / Crypto | Open | blg_130_lead_is_unassailable_early_decision | src/settlement/ (31/35 traces) | IP-44|
| BLG-131 | High | Node health / Event rollback | Open | blg_131_regeneration_ledger_medusa_cycle | src/chain/state_recovery/ (moved from regeneration_stage.rs per 5.2; 17/19 traces) | IP-44|
| BLG-132 | High | Consensus | Open | blg_132_pow_engine_block_index_skip | src/consensus/pow.rs (27/29 traces) | IP-12|
| BLG-134 | Critical | Cross-domain bridge / EVM canonical encoding | Open | blg_134_evm_rlp_0x81_b | src/cross_domain/evm/rlp.rs (18/22 traces) | IP-44|
| BLG-138 | Critical | Cross-domain bridge pipe / External chain observer | Open | blg_138_bridge_relayer_pipeline_mint_unlock | src/settlement/ (21/23 traces) | IP-44|
| BLG-140 | High | Storage provider boundary / Governance & liveness | Open - partial removal | blg_140_inmemory_storage_provider_proof_bytes | src/storage/provider.rs (32/34 traces) | IP-16|
| BLG-146 | Critical | Cross-chain bridge claim verification / Quantum | Open | blg_146_build_bud_to_eth_claim_receiver | src/cross_domain/ (21/23 traces; bpqs poseidon2; note-packing Goldilocks wrapping) | IP-44|
| BLG-147 | High | State serialization canon / K3-K4 quarantine | Open | blg_147_core_map_keys_bincode_postcard | src/core/ (20/22 traces) | IP-17|
| BLG-151 | High | Wire protocol canonical encoding / Address parsing | Open | blg_151_core_encoding_nul_collision | src/core/encoding.rs, address.rs (32/35 traces) | IP-17|
| BLG-155 | High | GlobalBlockHeader persistence / Validators | Open | blg_155_global_block_bincode_compatibility | src/chain/ (15/17 traces) | IP-44|
| BLG-158 | High | Consensus fork choice / PQ multi-signature | Open | blg_158_split_resolver_empty_chain | src/consensus/split_resolver.rs, threshold_mldsa (10/12 traces) | IP-12|
| BLG-167 | High | B.U.D. storage encoding | Open - partial removal | blg_167_lrc_msr_division_by_zero | src/storage/lrc.rs, msr.rs (24/28 traces) | IP-17|
| BLG-183 | Critical | Storage economy / Supply accounting / RPC signature | Open - partial removal | blg_183_storage_deal_double_debt | src/storage/, src/core/account.rs (15/21 traces) | IP-17|
| BLG-184 | Critical | Block production / Execution gas accounting / Mempool | Open | blg_184_collect_block_transactions_zero_cost_dos | src/mempool/, src/core/transaction.rs (14/15 traces) | IP-17|
| BLG-190 | Critical | Consensus field isolation / Quantum identity | Open | blg_190_did_bud_identity_recover_poa_gate | src/registry/ (30/31 traces) | IP-44|
| BLG-194 | Critical | Cross-domain bridge / Universal relay atomicity | Open | blg_194_submit_relay_proof_atomic | src/settlement/ (18/21 traces) | IP-44|
| BLG-195 | Critical | Multi-consensus finality verification / Cross-domain | Open | blg_195_finality_adapter_commitment_body | src/consensus/ (26/26 traces) | IP-44|
| BLG-196 | High | State root consistency / Block processing scale | Open | blg_196_account_state_incremental_merkle | src/core/account.rs (13/15 traces) | IP-17|
| BLG-197 | Critical | Transaction execution supply accounting / Partial-write | Open | blg_197_executor_apply_transaction_checked_saturating_add | src/execution/executor.rs (23/25 traces) | IP-17|
| BLG-199 | High | Cryptographic Merkle tree second-preimage | Open | blg_199_merkle_root_leaf_internal_confusion | src/settlement/commitment_tree.rs, src/consensus/merkle_tree.rs (8/8 traces) | IP-44|
| BLG-202 | Critical | Node startup security / DB migration / Backup | Open | blg_202_main.rs_retention_count_zero_backup_delete | src/main.rs (12/13 traces) | IP-17|
| BLG-203 | Critical | Hybrid finality fault proof | Open | blg_203_qc_fault_proof_leaf_index | src/consensus/qc.rs, src/light_client/ (27/28 traces) | IP-12|
| BLG-204 | High | Proof market accounting atomics / Ethereum bridge | Open | blg_204_proof_market_unpaid_receipt_delete | src/settlement/ (20/23 traces) | IP-44|
| BLG-205 | Critical | External domain registry consensus integrity | Open | blg_205_external_domain_readmit_bypass | src/registry/, src/network/proto_conversions.rs (5 unbounded bincode::deserialize; 30/30 traces) | IP-44, IP-15|
| BLG-206 | Critical | PoA consensus validation / Snapshot integrity | Open | blg_206_poa_engine_validators_file_fork | src/consensus/poa.rs (24/25 traces) | IP-12|
| BLG-207 | Critical | PoS double-signature slashing | Open | blg_207_pos_engine_verify_evidence | src/consensus/pos.rs (11/12 traces) | IP-12|
| BLG-227 | Medium | Gonca E5 | Open | blg_227_verify_inference_summary_only | src/ai/mod.rs; docs/AI_VERIFICATION_STATUS.md | IP-57 (testnet closure IP-33)|
| BLG-228 | High | Gonca E6 | Open | blg_228_ai_stark_verification_closed | src/ai/mod.rs | IP-57 (testnet closure IP-45)|
| BLG-229 | High | Gonca E7 | Open | blg_229_ai_registry_no_lottery | src/ai/registry.rs | IP-45 (VL-1 leg), IP-57|
| BLG-235 | High | Gonca E13, SERA-0 | Open | blg_235_zkvm_proof_only_zk_domain | src/cross_domain/external/zkvm_proof.rs; evm sync committee | IP-44, IP-60|
| BLG-240 | Low | Gonca E18 | Open | blg_240_validator_ordering_f64 | src/ai/registry.rs | IP-45, IP-57|
| BLG-244 | Low | Gonca E23 | Open | blg_244_off_device_assistant_bytes | Off-device assistant repository (separate repo work item) | IP-57|
| BLG-246 | Critical | src/chain/finality.rs | Open | blg_246_quorum_stake_plus_count | src/chain/finality.rs:119-129, :878-902 (quorum_count AND quorum_stake both required) | IP-12|
| BLG-247 | High | Cargo.toml libp2p features / chain_config.rs | Open | blg_247_no_nat_circuit_relay | Cargo.toml libp2p features lack relay/dcutr/autonat; config/testnet.toml enable_circuit_relay = false | IP-15|
| BLG-251 | High | src/registry/liveness.rs | Open | blg_251_liveness_slashing_report | src/registry/liveness.rs (record_epoch returns SlashingReport; no absence-without-slash for mobile) | IP-13|
| BLG-252 | Medium | src/registry/role.rs | Open | blg_252_separate_storage_roles | src/registry/role.rs (STORAGE_OPERATOR=5, CONTENT_VALIDATOR=9; contradicts V-5 single registry) | IP-08|
| BLG-253 | Medium | src/storage/mobile_self.rs, server_admission.rs, src/network/mobile.rs | Open - removal (IP-07, IP-08) | blg_253_mobile_self_bud1_hosting | src/storage/mobile_self.rs exists; MobileSelfProfile::calculate_leaf length-unprefixed hashes | IP-07, IP-08|
| BLG-259 | Medium | src/chain/finality.rs, src/consensus/qc.rs | Open | blg_259_checkpoint_certificate_420kb | src/chain/finality.rs, src/consensus/qc.rs (128 seats x 3309 bytes ~ 420 KB; light client burden; security model undocumented) | IP-12, IP-11|
| BLG-263 | Medium | src/tokenomics/reward_pool.rs, src/chain/blockchain.rs | Open | blg_263_security_pool_no_storage_share | src/tokenomics/reward_pool.rs (pay_epoch stake-weighted only; no storage-task share) | IP-16|
| BLG-264 | High | src/consensus/filiz.rs, handoff.rs | Open | blg_264_hash_chain_election_not_wired | src/consensus/filiz.rs, handoff.rs (election and handoff not on production path; WIRING markers present) | IP-12|
| BLG-266 | Medium | src/core/chain_config.rs (min_stake) | Open | blg_266_single_min_stake_no_class_split | src/core/chain_config.rs (one min_stake; no class split; 1000 BUD testnet barrier for phone users) | IP-08, IP-16|
| BULGU-001 | S2 | src/consensus/pos.rs | Open | - | - | IP-12|
| BULGU-002 | S2 | src/consensus/pos.rs | Open | - | - | IP-12|
| BULGU-003 | S3 | src/consensus/pos.rs | Open | - | - | IP-12|
| BULGU-004 | S3 | src/consensus/pos.rs, consensus/mod.rs | Open | - | - | IP-12|
| BULGU-005 | S3 | src/chain/blockchain.rs | Open | - | - | IP-17|
| BULGU-006 | S3 | src/chain/blockchain.rs | Open | - | - | IP-17|
| BULGU-007 | S3 | src/chain/blockchain.rs | Open | - | - | IP-17|
| BULGU-008 | S3 | src/chain/blockchain.rs | Open | - | - | IP-17|
| BULGU-009 | S3 | src/chain/blockchain.rs | Open | - | - | IP-17|
| BULGU-010 | S3 | src/core/transaction.rs | Open | - | - | IP-17|
| BULGU-013 | S3 | src/execution/executor.rs | Open | - | - | IP-17|
| BULGU-014 | S2 | src/network/node.rs | Open | - | - | IP-12|
| BULGU-015 | S3 | src/chain/chain_actor.rs | Open | - | - | IP-17|
| BULGU-016 | S3 | src/core/account.rs | Open | - | - | IP-17|
| BULGU-018 | S3 | src/chain/genesis.rs | Open | - | - | IP-16|
| BULGU-019 | S3 | src/core/account.rs, src/execution/executor.rs | Open | - | - | IP-16|
| BULGU-020 | S3 | Fee gate class (nine members) | Open | - | - | IP-16|
| BULGU-021 | S3 | src/sharding/mod.rs | Open | - | - | IP-17|
| BULGU-022 | S3 | RoleBond gate | Open | - | - | IP-08|
| BULGU-023 | S2 | src/consensus/pos.rs, src/chain/blockchain.rs | Open | - | - | IP-12|
| BULGU-024 | S3 | src/chain/blockchain.rs, src/consensus/pos.rs | Open | - | - | IP-12|
| BULGU-025 | S3 | src/consensus/pos.rs | Open | - | - | IP-12|
| BULGU-026 | S3 | src/chain/blockchain.rs | Open | - | - | IP-12|
| BULGU-027 | S3 | src/chain/blockchain.rs | Open | - | - | IP-12|
| TEST-GAP-01 | High | src/core/account.rs | Open | - | - | IP-16|
| TEST-GAP-08 | Medium | Proof retention window | Open | - | - | IP-12|
