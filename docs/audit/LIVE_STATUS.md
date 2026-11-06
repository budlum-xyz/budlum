# Live Verification Status (M0)

Source: THE BUDLUM DİREKTIF, Bölüm 14 (Birleşik bulgu defteri), analysis snapshot `testnet-quantum` (2026-11-02).
Live branch verified: `main` at `cccf1da` ("Add files via upload").
Produced by: IP-01 (lane A: core), IP-02 (lane B: storage), IP-03 (lane C: execution), IP-04 (lane D: clients/ops/CI/docs).
Directive reference: 14.1 madde 4 (canlı doğrulama), 15.6 (M0 Canlı durum), 0.4 (canlı durum kuralu).

## Status legend

| Status | Meaning |
|---|---|
| Open | Finding present on the live branch; reproduction test still to be written by IP-01..04 (S-3: test red before fix). |
| Verified | Finding confirmed on the live branch (tree inspection plus the directive snapshot note). |
| Closed | Already closed in the source ledger record; carried as history. |
| Invalid | Condition no longer exists on the live branch; proven by inspection. |
| Open - removal (IP-07) | Finding lives in legacy storage code slated for deletion by IP-07; closes when `no_legacy_storage` is green and the files are gone. |
| Open - partial removal | Partly closed by removal; remainder carried on the named package's card. |

## Verification basis

CI could not be executed in this environment (no Rust toolchain; crates.io is not reachable from this sandbox), so per the directive CI is run only when it turns red while work is in progress. Every status below was therefore determined by direct inspection of the live tree (`src/`, `crates/`, `budzero/`, `bud/`, `config/`, `ops/`, `xtask/`, `.github/`) against the directive snapshot note. The snapshot's "Kod izi" / "Konum" pointers are cited where available. Exact line numbers marked `:` were not mechanically confirmed and are to be locked when IP-01..04 write the reproduction tests.

## Finding register (BLG-001 .. BLG-267)

| ID | Severity | Area | Live status | Reproduction test | Proof (file:line) | Closes with |
|---|---|---|---|---|---|---|
| BLG-001 | Critical | Consensus | Open | blg_001_leader_round_skip | src/consensus/filiz.rs, src/consensus/handoff.rs (MAX_LEADER_ROUNDS, affordable_leader_round; snapshot kod izi 2/2) | IP-12 |
| BLG-002 | High | Consensus | Open | blg_002_testnet_genesis_template | config/testnet-genesis.json, ops/ (snapshot: 4/4 traces; template has no validator/tokenomics) | IP-16 |
| BLG-003 | High | Tokenomics | Open | blg_003_genesis_supply_cap | src/chain/genesis.rs, src/tokenomics/ (snapshot: 6/7 traces) | IP-16 |
| BLG-004 | Medium | Cryptography | Open | blg_004_key_file_permissions | src/crypto/ (snapshot: 8/10 traces) | IP-61 |
| BLG-005 | Medium | Build/CI | Closed | — | Source ledger record (defter kaydi) | IP-16 |
| BLG-006 | Medium | Tokenomics | Open | blg_006_reward_pool_epoch_pay | src/tokenomics/reward_pool.rs (pay_epoch; snapshot 2/2 traces; extended by 11.4 / BLG-263) | IP-16 |
| BLG-007 | Medium | Consensus | Open | blg_007_global_block_header_commitment | src/chain/, src/consensus/ (snapshot 3/3 traces; PQ block budget JSON) | IP-17 |
| BLG-008 | Medium | RPC | Verified | blg_008_rpc_auth_required | config/testnet.toml:50 `auth_required = true`; docs/TESTNET.md documents keyed reads (snapshot: 5/5 traces, open verified) | IP-16 |
| BLG-009 | Medium | Cryptography | Open | blg_009_pq_api_fips_context | src/crypto/ (snapshot 3/3 traces) | IP-61 |
| BLG-010 | Medium | Cryptography | Open | blg_0010_pkcs11_key_label | src/crypto/ (snapshot 2/4 traces) | IP-61 |
| BLG-011 | Medium | RPC/Operations | Open | blg_011_ops_service_rpc_credentials | ops/budlum-core.service (snapshot 1/3 traces; LimitCORE=infinity) | IP-41 |
| BLG-012 | High | Build/CI | Open | blg_012_coverage_rs_first_file_percent | xtask/gates/src/gates/coverage.rs (snapshot 1/1 traces) | IP-42 |
| BLG-013 | Medium | Build/CI | Open | blg_013_prepush_all_features | ops/scripts/prepush (snapshot 1/1 traces) | IP-42 |
| BLG-014 | Medium | Storage | Open | blg_014_backup_drill_exit_code | ops/scripts/backup_drill.rs (snapshot 2/2 traces) | IP-42 |
| BLG-015 | Medium | Build/CI | Open | blg_015_standalone_crate_tests | crates/wallet-core, crates/ai-inference, crates/bpqs (snapshot 3/3 traces) | IP-42 |
| BLG-016 | High | Build/CI / Supply chain | Open | blg_016_rustsec_advisories | Cargo.lock files (snapshot 4/4 traces; part closable by removal) | IP-42 |
| BLG-017 | Critical | Network/P2P | Open | blg_017_p2p_utf8_finality_panic | src/network/ (snapshot 8/8 traces: Prevote/Precommit/FinalityCert) | IP-15 |
| BLG-018 | Critical | Consensus | Open | blg_018_hybrid_finality_stall | src/consensus/ (snapshot 13/13 traces; finalized_height) | IP-12 |
| BLG-019 | Critical | State transition | Open | blg_019_state_update_retired | src/core/transaction.rs (StateUpdate retired; snapshot 4/5 traces, fix trace present) | IP-17 |
| BLG-020 | Critical | Consensus / State transition | Open | blg_020_collect_block_transactions_temp_state | src/core/transaction.rs (snapshot 24/25 traces; candidate state copy) | IP-17 |
| BLG-021 | Critical | Tokenomics | Open | blg_021_role_bond_burn | src/core/account.rs, src/registry/ (bond_relayer/bond_prover/bond_storage_operator; 12/12 traces) | IP-17 |
| BLG-022 | Medium | Consensus | Open | blg_022_light_client_checkpoint_loop | src/light_client/ (snapshot 4/4 traces; u64::MAX bound) | IP-11 |
| BLG-023 | Medium | State transition | Open | blg_023_relayer_result_domain_event_tree | src/execution/ (snapshot 8/8 traces; RELAYER bond lookup) | IP-17 |
| BLG-024 | Low | Consensus | Open | blg_024_finality_adapter_domain_check | src/consensus/ (PoW/PoS/PoA/BFT adaptors; 8/8 traces; PoAFinalityAdapter zero divisor) | IP-44 |
| BLG-025 | Medium | Cryptography | Open | blg_025_quantum_account_guardian_root | src/account_abstraction/ (QuantumAccount; 6/6 traces) | IP-45 |
| BLG-026 | Medium | Build/CI | Open | blg_026_wallet_core_ai_inference_ci_gap | crates/wallet-core, crates/ai-inference (fmt/clippy/--locked; 4/4 traces; 12-word/NFKD seed path) | IP-39 |
| BLG-027 | High | Consensus | Open | blg_027_v5_wallet_address_incompatibility | src/registry/, src/crypto/ (ML-DSA-87 V5; 13/13 traces) | IP-12 |
| BLG-028 | High | Storage | Open | blg_028_snapshot_v2_apply_atomic | src/chain/ (StateSnapshotV2::from_bytes; 4/4 traces) | IP-17 |
| BLG-029 | High | RPC | Open | blg_029_extract_client_ip_xff | src/rpc/ (snapshot 3/3 traces; rightmost XFF / next_back fix trace present) | IP-61 |
| BLG-030 | Critical | RPC | Open | blg_030_public_rpc_consensus_write | src/rpc/ (snapshot 22/23 traces; faucet part is IP-41) | IP-61, IP-41 |
| BLG-031 | Low | Consensus | Open | blg_031_governance_proposals_cap | src/registry/ (snapshot 10/10 traces; bpqs::EpochWindow u32 truncation) | IP-17 |
| BLG-032 | Medium | RPC | Open | blg_032_budgateway_pollen_cache_nonce | src/gateway/, src/rpc/ (snapshot 24/24 traces; 14 Prepare templates) | IP-61 |
| BLG-033 | Critical | Network / Serialization | Verified | blg_033_unbounded_bincode_p2p | proto_conversions.rs:1279-1410 per snapshot note (unbounded bincode::deserialize on unauthenticated P2P frame); 13/14 traces | IP-15 |
| BLG-034 | High | Network / P2P | Open | blg_034_p2p_subnet_diversity_ipv6 | src/network/ (snapshot 12/12 traces) | IP-15 |
| BLG-035 | Medium | Storage | Open - removal (IP-07) | blg_035_bitswap_memory_store | budzero/bud-node/ exists; src/storage/mobile_self.rs, server_admission.rs exist (7/7 traces) | IP-07 |
| BLG-036 | Critical | ZK / Circuit soundness | Open | blg_036_budair_active_bit | budzero/bud-proof/ (15/15 traces) | IP-33 |
| BLG-037 | Critical | ZK / Circuit soundness | Open | blg_037_verify_inference_fake_witness | budzero/bud-vm/, src/privacy/ (12/13 traces) | IP-33 |
| BLG-038 | Critical | ZK / Cryptography | Open | blg_038_linear_memory_chain_id | budzero/ (17/18 traces) | IP-33 |
| BLG-039 | Critical | ZK validator / Remote DoS | Open | blg_039_stark_degree_bits_27 | budzero/bud-proof/ (6/6 traces) | IP-33 |
| BLG-040 | High | ZKVM / Consensus execution | Open | blg_040_verify_merkle_one_round | src/execution/zkvm.rs, budzero/ (13/15 traces) | IP-33 |
| BLG-041 | Critical | Consensus / Chain state | Open | blg_041_settlement_root_replay | src/chain/ (29/34 traces) | IP-17 |
| BLG-042 | Critical | Consensus security / Slashing | Open | blg_042_failed_bls_slash_accounting | src/consensus/, src/core/account.rs (10/11 traces) | IP-17 |
| BLG-043 | Critical | Bridge / Storage accounting | Open | blg_043_unlock_bridge_transfer | src/settlement/, src/cross_domain/ (14/19 traces) | IP-44 |
| BLG-044 | Medium | Consensus / Persistence | Open | blg_044_import_qc_blob_cache | src/chain/ (14/16 traces) | IP-17 |
| BLG-045 | Critical | Security / Storage proofs | Open - removal (IP-07) | blg_045_storage_registry_open_challenge | src/storage/ (10/10 traces) | IP-07 |
| BLG-046 | Critical | Economy / Storage accounting | Open - removal (IP-07) | blg_046_open_deal_prune_content | src/storage/ (12/14 traces) | IP-07 |
| BLG-047 | High | Consensus / Storage integrity | Open - removal (IP-07) | blg_047_storage_registry_root_commitment | src/storage/manifest.rs (10/10 traces) | IP-07 |
| BLG-048 | High | Correctness / Determinism | Open - partial removal | blg_048_storage_render_f64_sqrt | src/storage/render.rs (25/25 traces) | IP-19 |
| BLG-049 | Medium | Security / Correctness | Open - partial removal | blg_049_erasure_reconstruct_multi | src/storage/erasure.rs (11/12 traces) | IP-22 |
| BLG-050 | Critical | Security / Identity / State root | Open | blg_050_identity_recover_poa_gate | src/registry/ (16/16 traces) | IP-44 |
| BLG-051 | High | Security / Selective disclosure | Open | blg_051_check_receipt_foreign_credential | src/registry/identity* (9/9 traces) | IP-44 |
| BLG-052 | Medium | Consensus / PoA compliance | Open | blg_052_poa_onboarding_hashmap | src/consensus/poa.rs (15/16 traces) | IP-44 |
| BLG-053 | High | Economy / Settlement security | Open | blg_053_proof_market_replay | src/settlement/ (16/16 traces) | IP-44 |
| BLG-054 | Critical | Cryptography / Bridge / Consensus | Open | blg_054_ethereum_receiptsroot_mpt | src/cross_domain/evm/ (15/19 traces) | IP-44 |
| BLG-055 | Critical | Cryptography / External finality | Open | blg_055_pairing_bls_signing_root | src/cross_domain/ (17/18 traces) | IP-44 |
| BLG-056 | High | Consensus / Economy / DoS | Open | blg_056_external_domain_freeze | src/registry/ (29/30 traces) | IP-44 |
| BLG-057 | High | Consensus / Bridge accounting | Open | blg_057_bridge_state_lifecycle | src/settlement/ (17/17 traces) | IP-44 |
| BLG-058 | High | Consensus / State root / Determinism | Open | blg_058_domain_registry_leaf_digest | src/consensus/ (19/19 traces) | IP-44 |
| BLG-059 | Critical | Cryptography / Verifiable AI | Open | blg_059_ai_execution_proof_binding | src/ai_inference/, src/prover/ (17/17 traces) | IP-45 |
| BLG-060 | Critical | Consensus / Economy / Escrow | Open | blg_060_ai_attach_execution_fee_loss | src/ai_inference/ (12/12 traces) | IP-45 |
| BLG-061 | High | Authorization / State integrity | Open | blg_061_ai_agent_payment_gaps | src/ai_inference/ (23/23 traces) | IP-45 |
| BLG-062 | High | Consensus / State root / Arithmetic | Open | blg_062_ai_registry_weights_digest | src/ai/ (17/17 traces; AiVerifierQos u64 overflow) | IP-45 |
| BLG-063 | Critical | Privacy / Cryptography / Consensus | Verified | blg_063_testnet_private_transfers | config/testnet-genesis.json chain_id 45261; `privacy_transfers_enabled` present on testnet (25/25 traces; IP-45 closes) | IP-45 |
| BLG-064 | High | Data sovereignty / Cryptography / Economy | Open | blg_064_pollen_protected_content_bridge | src/pollen/, src/socialfi/ (20/21 traces) | IP-23 |
| BLG-065 | High | Application state / Consensus integrity | Open | blg_065_nfttag_fee_burn | src/socialfi/, src/bns/, src/sharding/ (27/27 traces) | IP-17 |
| BLG-066 | High | Node runtime / Persistence / CLI | Open | blg_066_cli_chain_id_mainnet | src/main.rs (bud CLI hardcoded Mainnet chain_id; 19/20 traces) | IP-17 |
| BLG-067 | High | Compiler / ZK toolchain | Open | blg_067_bud_compiler_entry_abi | budzero/bud-compiler/ (30/30 traces) | IP-33 |
| BLG-068 | High | Explorer verification core | Open | blg_068_budscan_verified_badge | crates/budscan/ (23/23 traces) | IP-40 |
| BLG-069 | High | Validator registry / Cross-check | Open | blg_069_verifier_registry_state_root | budzero/verifier-registry/ (9/9 traces) | IP-33 |
| BLG-070 | High | Privacy / Closed-circuit masking | Open | blg_070_ai_knowledge_redact_json | src/ai/ (14/14 traces) | IP-45 |
| BLG-071 | High | AI inference bridge / Cryptographic binding | Open | blg_071_ai_core_manifest_digest | src/ai/ (27/27 traces) | IP-45 |
| BLG-072 | Medium | Information extraction / Cost | Open | blg_072_ai_knowledge_turkish_split | src/ai_inference/ (16/16 traces; NaN/negative float) | IP-45 |
| BLG-073 | Critical | Cryptography / Data integrity | Open - removal (IP-07) | blg_073_bud_v2_content_id_triple | src/storage/content_id.rs, bud/ (.bud v1 pq_public_key; 31/31 traces) | IP-07 |
| BLG-074 | High | Consensus / Cryptographic proof / Erasure | Open - removal (IP-07) | blg_074_bud_cauchy_ldrc | bud/ (25/25 traces) | IP-07 |
| BLG-075 | High | Lossless compression / Parser security | Open - removal (IP-07) | blg_075_bud_columnar_panic | bud/ (32/33 traces) | IP-07 |
| BLG-076 | Medium | Economy / Gate validation / Arithmetic | Open - removal (IP-07) | blg_076_bud_fidelity_gate | bud/ (22/22 traces) | IP-07 |
| BLG-077 | Critical | Post-quantum crypto / Identity binding | Open - removal (IP-07) | blg_077_bud_quantum_chain | bud/ (15/19 traces) | IP-07 |
| BLG-078 | High | Container integrity / Memory safety | Open - removal (IP-07) | blg_078_bud_cli_decode_container | bud/ (28/28 traces) | IP-07 |
| BLG-079 | High | Privacy / Secret masking / Binding | Open - removal (IP-07) | blg_079_bud_securededup_plaintext | bud/ (21/21 traces) | IP-07 |
| BLG-080 | Medium | Indexing / QR derivative / Economy | Open - removal (IP-07) | blg_080_bud_pgm_search_range | bud/ (21/21 traces) | IP-07 |
| BLG-081 | High | CI security gates / coverage gaps | Open | blg_081_xtask_gates_wallet_core_root | xtask/gates/src/gates/ (8/8 traces; nonexistent "wallet-core" root; bud/ out of scope) | IP-42 |
| BLG-082 | High | Static security analysis / AST validation | Open | blg_082_ast_security_gates | xtask/gates/src/gates/ast_security_gates.rs (24/25 traces) | IP-42 |
| BLG-083 | Medium | Economy / Quality gates | Open | blg_083_supply_count_rate_consensus | xtask/gates/src/gates/economy_invariants.rs (20/20 traces) | IP-42 |
| BLG-084 | High | CI security / integrity gates | Open | blg_084_relay_fail_open_regeneration | xtask/gates/src/gates/relay.rs, regeneration.rs (7/7 traces) | IP-42 |
| BLG-085 | High | Build hardening / gate scope | Open | blg_085_gates_release_profile | xtask/gates/ (15/15 traces; missing [profile.release] hardening in independent workspaces) | IP-42 |
| BLG-086 | Medium | Gate reliability / CWE-377 / Language | Open | blg_086_turkish_strings_in_gates | xtask/gates/src/gates/ (19/19 traces; Turkish strings remain in gates) | IP-42 |
| BLG-087 | High | Fuzzing / Formal verification / Benchmarks | Open | blg_087_fuzz_targets_consensus | fuzz/, kani/ (29/32 traces; unbounded bincode::deserialize OOM; empty consensus_validate target) | IP-42 |
| BLG-088 | Medium | Test quality / Regression locks | Open | blg_088_integration_test_stubs | src/tests/ (14/14 traces; 8/11 lockfiles skipped; fixed TCP port collisions) | IP-17 |
| BLG-089 | High | Storage soundness / Consensus state root | Open - partial removal | blg_089_coding_audit_column_binding | src/storage/ (16/17 traces) | IP-17 |
| BLG-090 | Medium | Test package integrity / Build coverage | Open - partial removal | blg_090_cfg_false_settlement_prod | src/bin/budlum-domain-producer.rs settlement_prod.rs cfg(false); domain_throughput.rs (12/14 traces; 15 files with Turkish remnants) | IP-17 |
| BLG-091 | Critical | External-domain contract / Cryptography | Open | blg_091_budlum_finality_verifier_zero_bls | contracts/ (18/22 traces) | IP-44 |
| BLG-092 | High | Documentation-code match / Operational security | Open - partial (KR-21) | blg_092_readme_definition_block | README.md lines 1-14 verified verbatim against Ek A (SHA-256 dd9be520...); --priv-key argv example removed from README.tr.md (leak closed); remaining items are README.tr.md localization, the permitted Turkish document (KR-21 keeps the definition block verbatim) | IP-43 |
| BLG-093 | High | License integrity / Supply chain | Open | blg_093_ai_inference_license | crates/ai-inference/LICENSE.md MIT vs root PolyForm Shield 1.0.0 | IP-45 |
| BLG-094 | High | Configuration / Operations / CI gate | Open | blg_094_archive_chain_id_42 | config/archive.toml has chain_id = 42; ops/docker-compose.yml pow --difficulty=0; ops/Dockerfile Turkish text (3/3 traces) | IP-16 |
| BLG-095 | Medium | Build/CI / Supply chain / Governance | Open | blg_095_codeowners_dependabot_lockfiles | .cargo/audit.toml, CODEOWNERS, workflows (3/3 traces; deleted Turkish branches/steps) | IP-41 |
| BLG-096 | High | Consensus / Finality / Slashing | Open | blg_096_invalidate_finality_orphan_cert | src/consensus/ (21/22 traces) | IP-12 |
| BLG-097 | High | CI | Open - partial removal | blg_097_kani_bud_fuzz_cargo_lock | kani/, bud/fuzz/ (14/14 traces; missing Cargo.lock; orphan kani_bud_format.rs; crates/budscan CI gap) | IP-42 |
| BLG-098 | Critical | Security | Open | blg_098_node_config_rpc_auth | src/main.rs (NodeConfig #[arg(skip)] resets RPC auth/IP allowlist defaults; 23/25 traces) | IP-39 |
| BLG-099 | High | Security | Open | blg_099_constant_time_eq_self_compare | src/crypto/ (constant_time_eq_str a_b.ct_eq(a_b); 4/6 traces) | IP-61 |
| BLG-100 | Critical | Consensus | Open | blg_100_unstake_amount_plus_fee_lock | src/core/account.rs, src/execution/executor.rs (32/33 traces) | IP-17 |
| BLG-101 | Critical | Consensus state root / Snapshot | Open | blg_101_snapshot_v2_restore_poa_lock | src/chain/ (27/30 traces) | IP-17 |
| BLG-102 | Critical | Consensus fork choice | Open | blg_102_try_reorg_bridge_state_leak | src/chain/ (17/19 traces) | IP-17 |
| BLG-103 | Critical | On-chain governance / Slashing | Open | blg_103_governance_slashed_voter_weight | src/registry/ (26/27 traces) | IP-17 |
| BLG-104 | Critical | Mempool admission / Block building | Open | blg_104_mempool_poolbytesfull_rbf | src/mempool/ (24/28 traces; sled stale transaction leak) | IP-17 |
| BLG-105 | Critical | Consensus / Bridge / Tokenomics / Crypto | Open | blg_105_burn_bridge_transfer_double_mint | src/settlement/ (15/17 traces) | IP-44 |
| BLG-106 | Critical | AI / Consensus / DoS | Open | blg_106_ai_model_spec_execution_dims | src/ai/ (15/16 traces) | IP-45 |
| BLG-107 | Critical | Consensus / Storage market / SocialFi / Tokenom | Open - partial removal | blg_107_nftboost_produce_block_hang | src/socialfi/ (16/17 traces) | IP-17 |
| BLG-108 | Critical | Network | Open | blg_108_gossipsub_unauthenticated_ban | src/network/ (22/24 traces) | IP-15 |
| BLG-109 | Critical | Data sovereignty / B.U.D. storage / SocialFi | Open - partial removal | blg_109_nft_mint_burn_manifest_delete | src/socialfi/, src/bns/ (15/16 traces) | IP-23 |
| BLG-110 | Critical | Consensus state root / BNS / Privacy | Open | blg_110_bns_registry_default_base_cost | src/bns/ (23/23 traces; L1NoteRegistry MAX_LIVE_COMMITMENTS; XSS) | IP-23 |
| BLG-111 | Critical | Post-quantum cryptography | Open | blg_111_bpqs_debug_release_divergence | crates/bpqs/ (13/14 traces; Q_MAX=1 WOTS reuse; saltless chain digest) | IP-45 |
| BLG-112 | Critical | AI inference layer / Pollen data market / Consensus | Open | blg_112_ai_model_id_determinism | src/ai_inference/ (23/23 traces; declare_effort_ceiling deadlock) | IP-45 |
| BLG-113 | Critical | Persistent storage | Open | blg_113_sled_recover_interrupted_commit | src/storage/db.rs (sled; 19/19 traces) | IP-17 |
| BLG-114 | Critical | zkVM compiler | Open | blg_114_bud_compiler_match_intlit | budzero/bud-compiler/ (10/10 traces) | IP-33 |
| BLG-115 | Critical | ZKVM / Cryptography / State tree | Open | blg_115_budzero_dynamic_storage | budzero/bud-vm/, bud-proof/, bud-state/ (13/19 traces) | IP-33 |
| BLG-116 | Critical | Cross-domain bridge / ZK verification / RPC | Open | blg_116_adapter_spec_zkvm_empty_stark | src/cross_domain/, src/rpc/ (27/31 traces) | IP-44 |
| BLG-117 | Critical | Wallet cryptography / Privacy / Social recovery | Open | blg_117_wallet_core_four_round_poseidon | crates/wallet-core/ (28/31 traces; recipient_tag i32 truncation; 64-bit spending secret entropy) | IP-39 |
| BLG-118 | Critical | Consensus / Transaction witness / Quantum AA | Open | blg_118_tx_root_witness_blindness | src/core/transaction.rs, src/execution/executor.rs (26/27 traces) | IP-17 |
| BLG-119 | Critical | PoS security / Slashing accounting | Open | blg_119_unstake_slashing_escape | src/consensus/pos.rs (31/33 traces) | IP-17 |
| BLG-120 | High | Settlement security / Cold wallet / Quantum anchor | Open | blg_120_cold_wallet_epoch_budget | src/settlement/, crates/bpqs/ (29/33 traces) | IP-44 |
| BLG-121 | High | Verifiable explorer / Light client / Patch | Open | blg_121_budscan_ens_arweave_ns | crates/budscan/ (25/26 traces) | IP-40 |
| BLG-122 | High | B.U.D. consensus / Storage proofs / PACT | Open - removal (IP-07) | blg_122_bud_ratio_consensus_nan | bud/ (42/43 traces) | IP-07 |
| BLG-123 | Medium | B.U.D. format converters / Losslessness / Ona | Open - removal (IP-07) | blg_123_bud_store_json_columnar | bud/ (22/23 traces) | IP-07 |
| BLG-124 | High | AI inference / Information layer / Presentation | Open | blg_124_ai_inference_websocket_auth | src/ai_inference/ (28/29 traces) | IP-45 |
| BLG-125 | Critical | Consensus state boundary / Storage privacy | Open - partial removal | blg_125_storage_rpc_zero_cost_split | src/storage/, src/gateway/ (48/58 traces) | IP-17 |
| BLG-126 | Critical | Security / Data sovereignty / AI-Pollen closed | Open | blg_126_ai_inference_request_access_grant | src/ai_inference/, src/pollen/ (21/24 traces) | IP-45 |
| BLG-127 | Critical | Consensus / Cryptography / Settlement capacity / Bridge | Open | blg_127_cold_wallet_3_of_6_anchor | src/settlement/, crates/bpqs/ (35/37 traces) | IP-44 |
| BLG-128 | High | Light client proofs / Storage shard assignment | Open | blg_128_merkle_trie_proof_no_cap | src/chain/, src/storage/assignment.rs (25/26 traces) | IP-17 |
| BLG-129 | High | Gateway proofs | Open | blg_129_dweb_passport_proof_bundle | src/gateway/, src/budlumxyz/ (36/37 traces) | IP-23 |
| BLG-130 | Critical | Consensus / Cross-domain bridge finality / Crypto | Open | blg_130_lead_is_unassailable_early_decision | src/settlement/ (31/35 traces) | IP-44 |
| BLG-131 | High | Node health / Event rollback | Open | blg_131_regeneration_ledger_medusa_cycle | src/chain/state_recovery/ (moved from regeneration_stage.rs per 5.2; 17/19 traces) | IP-44 |
| BLG-132 | High | Consensus | Open | blg_132_pow_engine_block_index_skip | src/consensus/pow.rs (27/29 traces) | IP-12 |
| BLG-133 | Medium | Storage state management | Open - partial removal | blg_133_dictionary_registry_immortal_record | src/storage/dictionary.rs, derived.rs, mobile_self.rs, transformed.rs (44/46 traces) | IP-24 |
| BLG-134 | Critical | Cross-domain bridge / EVM canonical encoding | Open | blg_134_evm_rlp_0x81_b | src/cross_domain/evm/rlp.rs (18/22 traces) | IP-44 |
| BLG-135 | High | Storage economy | Open - partial removal | blg_135_living_threshold_half_life | src/storage/living_threshold.rs, storage_deal.rs (29/31 traces) | IP-24 |
| BLG-136 | High | Smart contract compiler | Open | blg_136_bud_compiler_parser_single_call | budzero/bud-compiler/parser.rs (30/32 traces) | IP-33 |
| BLG-137 | High | B.U.D. 2.0/3.0 storage pipe / Kademlia DHT | Open - partial removal | blg_137_bud3_qr_video_stream | src/storage/qr_*.rs, three_nft.rs (45/48 traces) | IP-19 |
| BLG-138 | Critical | Cross-domain bridge pipe / External chain observer | Open | blg_138_bridge_relayer_pipeline_mint_unlock | src/settlement/ (21/23 traces) | IP-44 |
| BLG-139 | Critical | Privacy note state tree | Open | blg_139_note_registry_nullifier_leak | budzero/bud-state/ (17/22 traces) | IP-33 |
| BLG-140 | High | Storage provider boundary / Governance & liveness | Open - partial removal | blg_140_inmemory_storage_provider_proof_bytes | src/storage/provider.rs (32/34 traces) | IP-16 |
| BLG-141 | Medium | B.U.D. 2.0 format engines | Open - removal (IP-07) | blg_141_bud_lowrank_matrix_coder | bud/ (25/28 traces) | IP-07 |
| BLG-142 | Critical | zkVM STARK soundness / Proof flexibility | Open | blg_142_bud_stark_goldilocks_2_adic | budzero/bud-proof/src/bud_stark/ (23/25 traces) | IP-33 |
| BLG-143 | High | Verifiable explorer content verification | Open | blg_143_budscan_bdlm_manifest_v4_refused | crates/budscan/fetch.rs (25/28 traces) | IP-40 |
| BLG-144 | High | B.U.D. 1.0/3.0 custody accounting / Optical recipe | Open - partial removal | blg_144_single_screen_view_contract_digest | src/storage/one_view.rs, qr_recipe.rs (20/23 traces) | IP-19 |
| BLG-145 | Medium | B.U.D. 2.0 derivation / Optical transfer / Zstd | Open - partial removal | blg_145_crop_derivation_aligned_true | bud/ (17/19 traces) | IP-45 |
| BLG-146 | Critical | Cross-chain bridge claim verification / Quantum | Open | blg_146_build_bud_to_eth_claim_receiver | src/cross_domain/ (21/23 traces; bpqs poseidon2; note-packing Goldilocks wrapping) | IP-44 |
| BLG-147 | High | State serialization canon / K3-K4 quarantine | Open | blg_147_core_map_keys_bincode_postcard | src/core/ (20/22 traces) | IP-17 |
| BLG-148 | High | B.U.D. agreement lifecycle / Registry echo | Open - split IP-07 / IP-33 | blg_148_storage_lifecycle_missed_terminal | src/storage/lifecycle.rs (IP-07 part); budzero/verifier-registry/ (IP-33 part; 17/19 traces) | IP-33, IP-07 |
| BLG-149 | Medium | B.U.D. 2.0 dedup / pricing / AI operations | Open - partial removal | blg_149_pow_challenge_salt_digest | bud/ (26/29 traces) | IP-45 |
| BLG-150 | Critical | Consensus signature field separation / HSM | Open | blg_150_consensus_signer_sign_prevote | src/crypto/, src/chain/chain_actor.rs (23/25 traces) | IP-61 |
| BLG-151 | High | Wire protocol canonical encoding / Address parsing | Open | blg_151_core_encoding_nul_collision | src/core/encoding.rs, address.rs (32/35 traces) | IP-17 |
| BLG-152 | Medium | B.U.D. fidelity core / Tiny object block pack | Open - removal (IP-07) | blg_152_fidelity_core_thumbnail_bytes | bud/ (15/17 traces) | IP-07 |
| BLG-153 | Medium | B.U.D. optical/log templating / Genomic reference | Open - removal (IP-07) | blg_153_optical_gates_k_bud_optical | bud/ (16/18 traces) | IP-07 |
| BLG-154 | Critical | STARK validator soundness / DoS | Open | blg_154_bud_stark_aux_trace_next | budzero/bud-proof/src/bud_stark/ (19/21 traces) | IP-33 |
| BLG-155 | High | GlobalBlockHeader persistence / Validators | Open | blg_155_global_block_bincode_compatibility | src/chain/ (15/17 traces) | IP-44 |
| BLG-156 | Medium | Quantum policy gate / .bud wire evolution / Po | Open - removal (IP-07) | blg_156_quantum_suite_substring_escape | bud/ (17/19 traces) | IP-07 |
| BLG-157 | Medium | B.U.D. database delta / Converter gates | Open - partial removal | blg_157_dbd_digest_page_boundary | bud/ (16/18 traces) | IP-45 |
| BLG-158 | High | Consensus fork choice / PQ multi-signature | Open | blg_158_split_resolver_empty_chain | src/consensus/split_resolver.rs, threshold_mldsa (10/12 traces) | IP-12 |
| BLG-159 | High | Zero-knowledge proof system | Open | blg_159_bud_stark_setup_preprocessed | budzero/bud-proof/src/bud_stark/ (14/17 traces) | IP-33 |
| BLG-160 | Medium | Closed-loop AI data governance / Training | Open | blg_160_ai_dataset_storage_deal_validation | src/ai/ (15/17 traces) | IP-45 |
| BLG-161 | Medium | B.U.D. storage integrity / Multi-tenant QoS / S | Open - partial removal | blg_161_bud_format_scrub_bit_rot | bud/ (23/25 traces) | IP-21 |
| BLG-162 | High | BudZero smart contract compiler | Open | blg_162_budl_lexer_crlf_reject | budzero/bud-compiler/lexer.rs (13/16 traces) | IP-33 |
| BLG-163 | High | B.U.D. 3.0 optical storage / QR matrix / PNG codec | Open | blg_163_qr_matrix_u32_overflow | src/storage/qr_matrix.rs, qr_png.rs, qr_encode.rs (8/10 traces) | IP-19 |
| BLG-164 | High | Post-quantum cryptography | Open | blg_164_bpqs_epoch_of_u32_truncation | crates/bpqs/ (10/13 traces; PROTOC="" build failure) | IP-45 |
| BLG-165 | Medium | Offline AI localization / Accessibility | Open | blg_165_ai_inference_i18n_bcp47 | src/ai_inference/i18n.rs (10/13 traces) | IP-45 |
| BLG-166 | Critical | Decentralized AI consensus | Open | blg_166_ai_registry_single_min_verifier_stake | src/ai/ (27/31 traces) | IP-45 |
| BLG-167 | High | B.U.D. storage encoding | Open - partial removal | blg_167_lrc_msr_division_by_zero | src/storage/lrc.rs, msr.rs (24/28 traces) | IP-17 |
| BLG-168 | Medium | B.U.D. 3.0 three-layer gate / Session opening | Open - partial removal | blg_168_refuse_durable_derivative_bypass | src/storage/ (20/25 traces) | IP-21 |
| BLG-169 | Medium | Developer SDK | Open | blg_169_budlum_toml_dropped_sections | src/sdk/ (14/16 traces) | IP-40 |
| BLG-170 | High | Security gates / Static analysis | Open | blg_170_ast_security_gates_bypass | xtask/gates/src/gates/ (25/27 traces) | IP-42 |
| BLG-171 | High | CI security gates / Supply chain | Open | blg_171_security_scans_can_fail | xtask/gates/src/gates/ (16/19 traces) | IP-42 |
| BLG-172 | Medium | Developer and operations tools | Open | blg_172_budlum_tools_poa_validators_json | xtask/tools/, ops/ (15/17 traces) | IP-42 |
| BLG-173 | Medium | Side-channel validation canary / Fuzz infra | Open | blg_173_dudect_poseidon2_detached | crates/bpqs/, fuzz/ (10/15 traces) | IP-45 |
| BLG-174 | High | ZK/STARK soundness gates | Open | blg_174_accumulators_pinned_first_row | xtask/gates/src/gates/ (18/20 traces) | IP-42 |
| BLG-175 | High | Supply chain / Build integrity gates | Open | blg_175_git_dep_audited_cargo_vet | xtask/gates/src/gates/ (15/17 traces) | IP-42 |
| BLG-176 | Medium | Benchmark accuracy / Module hygiene | Open | blg_176_bench_internal_pipeline_tps_chain_id | benches/ (8/10 traces; chain_id=1337 vs 45262) | IP-42 |
| BLG-177 | Medium | Address agreement gate / Storage admission / Role | Open - partial removal | blg_177_wallet_node_address_agree_extra_digest | src/crypto/primitives.rs vs crates/wallet-core (20/22 traces) | IP-42 |
| BLG-178 | High | ZKVM soundness / Gas calibration / Regression tests | Open | blg_178_zero_tests_witness_skip | xtask/gates/src/gates/ (16/18 traces) | IP-42 |
| BLG-179 | Critical | Snapshot serialization / Genesis schema / Slash | Open | blg_179_serialize_map_keys_enum | xtask/gates/src/gates/ (21/26 traces) | IP-42 |
| BLG-180 | Medium | Storage manifest / Coding audit / AI system | Open | blg_180_content_encryption_gate_tuple_key | xtask/gates/src/gates/ (16/20 traces) | IP-42 |
| BLG-181 | Medium | Fuzz coverage / Module coverage gate / CI shell gate | Open | blg_181_evm_mpt_verify_fixed_128 | fuzz/, xtask/gates/ (13/16 traces) | IP-42 |
| BLG-182 | Critical | ZKVM STARK soundness / Sender/nonce canonicality | Open | blg_182_plonky3_adapter_unbound_public_inputs | budzero/ (19/21 traces) | IP-33 |
| BLG-183 | Critical | Storage economy / Supply accounting / RPC signature | Open - partial removal | blg_183_storage_deal_double_debt | src/storage/, src/core/account.rs (15/21 traces) | IP-17 |
| BLG-184 | Critical | Block production / Execution gas accounting / Mempool | Open | blg_184_collect_block_transactions_zero_cost_dos | src/mempool/, src/core/transaction.rs (14/15 traces) | IP-17 |
| BLG-185 | Medium | Quantum signature cost model / Concurrency validation | Open - partial removal | blg_185_bpqs_wire_size_cost_model | crates/bpqs/ (16/21 traces) | IP-45 |
| BLG-186 | Critical | ZKVM STARK field canon / Sender nonce height | Open | blg_186_proof_envelope_degree_bits | budzero/ (17/19 traces) | IP-33 |
| BLG-187 | High | Fuzz validation coverage / Reorg bound / Bridge acct | Open | blg_187_consensus_state_transition_fuzz | fuzz/ (19/20 traces) | IP-42 |
| BLG-188 | High | Storage slashing security gate / MEV-free mempool | Open | blg_188_uncheckable_proof_false_true_flip | xtask/gates/src/gates/ (11/13 traces) | IP-42 |
| BLG-189 | Medium | Storage/Transfer pricing gates / Shard placement | Open | blg_189_storage_priced_gate_blindness | xtask/gates/src/gates/ (19/20 traces) | IP-42 |
| BLG-190 | Critical | Consensus field isolation / Quantum identity | Open | blg_190_did_bud_identity_recover_poa_gate | src/registry/ (30/31 traces) | IP-44 |
| BLG-191 | Critical | ZKVM completeness & soundness / STARK program search | Open | blg_191_vm_run_receipt_synthetic_halt | budzero/ (20/22 traces) | IP-33 |
| BLG-192 | High | JSON-RPC fee estimate / Wallet-SDK compatibility | Open | blg_192_bud_estimateGas_transfer_fee_ppm | src/rpc/server.rs (12/13 traces) | IP-61 |
| BLG-193 | Medium | CI quality/security gates / Syntax scanner | Open - partial removal | blg_193_gates_comment_syntax_bypass | xtask/gates/src/gates/ (41/42 traces) | IP-42 |
| BLG-194 | Critical | Cross-domain bridge / Universal relay atomicity | Open | blg_194_submit_relay_proof_atomic | src/settlement/ (18/21 traces) | IP-44 |
| BLG-195 | Critical | Multi-consensus finality verification / Cross-domain | Open | blg_195_finality_adapter_commitment_body | src/consensus/ (26/26 traces) | IP-44 |
| BLG-196 | High | State root consistency / Block processing scale | Open | blg_196_account_state_incremental_merkle | src/core/account.rs (13/15 traces) | IP-17 |
| BLG-197 | Critical | Transaction execution supply accounting / Partial-write | Open | blg_197_executor_apply_transaction_checked_saturating_add | src/execution/executor.rs (23/25 traces) | IP-17 |
| BLG-198 | Critical | zkVM compiler stack safety / Proof baseline | Open - partial removal | blg_198_bud_compiler_recursive_sigabrt | budzero/bud-compiler/ (10/12 traces) | IP-33 |
| BLG-199 | High | Cryptographic Merkle tree second-preimage | Open | blg_199_merkle_root_leaf_internal_confusion | src/settlement/commitment_tree.rs, src/consensus/merkle_tree.rs (8/8 traces) | IP-44 |
| BLG-200 | High | BLS12-381 consensus cryptography / false-green | Open | blg_200_bls_keypair_from_seed_zero | src/crypto/ (13/13 traces) | IP-61 |
| BLG-201 | High | AI STARK DoS protection / Executor atomicity / B.U.D. | Open - partial removal | blg_201_ai_attach_execution_proof_size_gate | src/ai_inference/, src/execution/ (17/18 traces) | IP-45 |
| BLG-202 | Critical | Node startup security / DB migration / Backup | Open | blg_202_main.rs_retention_count_zero_backup_delete | src/main.rs (12/13 traces) | IP-17 |
| BLG-203 | Critical | Hybrid finality fault proof | Open | blg_203_qc_fault_proof_leaf_index | src/consensus/qc.rs, src/light_client/ (27/28 traces) | IP-12 |
| BLG-204 | High | Proof market accounting atomics / Ethereum bridge | Open | blg_204_proof_market_unpaid_receipt_delete | src/settlement/ (20/23 traces) | IP-44 |
| BLG-205 | Critical | External domain registry consensus integrity | Open | blg_205_external_domain_readmit_bypass | src/registry/, src/network/proto_conversions.rs (5 unbounded bincode::deserialize; 30/30 traces) | IP-44, IP-15 |
| BLG-206 | Critical | PoA consensus validation / Snapshot integrity | Open | blg_206_poa_engine_validators_file_fork | src/consensus/poa.rs (24/25 traces) | IP-12 |
| BLG-207 | Critical | PoS double-signature slashing | Open | blg_207_pos_engine_verify_evidence | src/consensus/pos.rs (11/12 traces) | IP-12 |
| BLG-208 | High | BUD3 H1 | Open - removal (IP-07, IP-21) | blg_208_bud_storage_edition_three | src/storage/generated.rs (BudStorageEdition::Three admits_body() false) | IP-07, IP-21 |
| BLG-209 | High | BUD3 H2 | Open - removal (IP-07, IP-25) | blg_209_three_regime_zero_fee | src/storage/three_regime.rs | IP-07, IP-25 |
| BLG-210 | High | BUD3 H3 | Open | blg_210_video_recipe_content_bytes | src/storage/three_recipe.rs | IP-19 |
| BLG-211 | Medium | BUD3 H4 | Open | blg_211_three_recipe_models | src/storage/qr_recipe.rs, three_recipe.rs, three_nft.rs | IP-19 |
| BLG-212 | Critical | BUD3 H5 | Open | blg_212_bud_storage_qr_feed_preview | src/rpc/server.rs (bud_storageQrFeed*); three_reveal.rs, three_nft.rs | IP-21, IP-23 |
| BLG-213 | High | BUD3 H6 | Open | blg_213_emit_u32_length_silent_trunc | src/storage/emit.rs, qr_payload.rs, qr_carousel.rs | IP-18 |
| BLG-214 | Medium | BUD3 H7 | Open | blg_214_video_id_deflate_not_stable | src/storage/qr_video.rs, qr_png.rs | IP-19 |
| BLG-215 | High | BUD3 H8 | Open | blg_215_no_object_from_video | src/storage/ (no video-to-object extraction; two paths missing) | IP-19 |
| BLG-216 | High | BUD3 H9 | Open | blg_216_qr_carousel_low_degree_xor | src/storage/qr_carousel.rs | IP-18 |
| BLG-217 | Medium | BUD3 H10 | Open - removal (IP-07) | blg_217_bud_second_bud3_implementation | bud/ exists (112 files; second 3.0 implementation) | IP-07 |
| BLG-218 | Low | BUD3 H11 | Open | blg_218_three_pipe_fixed_size_test_name | src/storage/three_pipe.rs | IP-19 |
| BLG-219 | Medium | BUD3 H12 | Open | blg_219_transformed_zlib_only | src/storage/transformed.rs | IP-24 |
| BLG-220 | Critical | BUD3 H13 | Open | blg_220_no_redundancy_bud3_object | src/storage/erasure.rs, README (2.0 schema 10,16 vs 256 shard cap) | IP-20 |
| BLG-221 | Medium | BUD3 H14 | Open | blg_221_no_dedup_reference_count | src/storage/ | IP-22 |
| BLG-222 | Medium | BUD3 H15 | Open | blg_222_dictionary_derived_not_bud3 | src/storage/dictionary.rs, living_threshold.rs, derived.rs | IP-24 |
| BLG-223 | High | Gonca E1 | Open | blg_223_bud_stark_pcs_zk_false | budzero/bud-proof/src/bud_stark/prover.rs | IP-56 (testnet closure IP-33, IP-45) |
| BLG-224 | High | Gonca E2 | Open | blg_224_note_commitment_nullifier_64bit | crates/note-packing/src/lib.rs; budzero/bud-state/src/note.rs; budzero/bud-vm/src/lib.rs | IP-56 (testnet closure IP-45) |
| BLG-225 | High | Gonca E3 | Open | blg_225_private_transfer_no_proofs | src/execution/executor.rs, src/privacy/submit.rs | IP-45, IP-56 |
| BLG-226 | High | Gonca E4 | Open | blg_226_verify_merkle_single_round | budzero/bud-isa/src/lib.rs | IP-56 (testnet closure IP-33) |
| BLG-227 | Medium | Gonca E5 | Open | blg_227_verify_inference_summary_only | src/ai/mod.rs; docs/AI_VERIFICATION_STATUS.md | IP-57 (testnet closure IP-33) |
| BLG-228 | High | Gonca E6 | Open | blg_228_ai_stark_verification_closed | src/ai/mod.rs | IP-57 (testnet closure IP-45) |
| BLG-229 | High | Gonca E7 | Open | blg_229_ai_registry_no_lottery | src/ai/registry.rs | IP-45 (VL-1 leg), IP-57 |
| BLG-230 | Medium | Gonca E8 | Open | blg_230_sender_64bit_vs_address_256bit | budzero/bud-vm/src/lib.rs; src/execution/zkvm.rs | IP-33 (execution leg), IP-56 |
| BLG-231 | Medium | Gonca E9 | Open | blg_231_recursive_aggregation_doc_vs_code | budzero/bud-state/src/lib.rs; budzero/ARCHITECTURE.md | IP-43 |
| BLG-232 | Medium | Gonca E10 | Open | blg_232_single_air_1073_columns | budzero/bud-proof/src/plonky3_air.rs | IP-56 |
| BLG-233 | Medium | Gonca E11 | Open | blg_233_mmcs_keccak_no_recursion | budzero/bud-proof/src/plonky3_prover.rs | IP-60 |
| BLG-234 | Medium | Gonca E12 | Open | blg_234_only_budl_isa | budzero/bud-isa/src/lib.rs | IP-60 |
| BLG-235 | High | Gonca E13, SERA-0 | Open | blg_235_zkvm_proof_only_zk_domain | src/cross_domain/external/zkvm_proof.rs; evm sync committee | IP-44, IP-60 |
| BLG-236 | Medium | Gonca E14 | Open | blg_236_no_plaintext_bound_commitment | docs/BUD_CONTENT_ENCRYPTION.md; src/storage/payload_crypt.rs | IP-56 |
| BLG-237 | High | Gonca E15 | Open | blg_237_view_grant_cleartext_row | src/storage/view_grant.rs (consent leg IP-56) | IP-22 |
| BLG-238 | Medium | Gonca E16 | Open | blg_238_hpke_key_package_not_production | src/storage/key_package.rs | IP-22 |
| BLG-239 | Medium | Gonca E17 | Open | blg_239_sigagg_proof_not_bound_in_air | docs/MAINTAINCE?; budzero/bud-pul | IP-60 |
| BLG-240 | Low | Gonca E18 | Open | blg_240_validator_ordering_f64 | src/ai/registry.rs | IP-45, IP-57 |
| BLG-241 | Low | Gonca E19 | Open | blg_241_interpret_poseidon_width_12 | budzero/bud-isa/src/lib.rs; budzero/bud-vm/src/lib.rs | IP-43 |
| BLG-242 | Medium | Gonca E20 | Open | blg_242_commitment_no_team_hash | All commitment types | IP-56 |
| BLG-243 | Medium | Gonca E22 | Open | blg_243_event_accumulation_32bit_sum | budzero/README.md; docs/AI_VERIFICATION_STATUS.md | IP-56 |
| BLG-244 | Low | Gonca E23 | Open | blg_244_off_device_assistant_bytes | Off-device assistant repository (separate repo work item) | IP-57 |
| BLG-245 | Medium | Gonca E23 | Open | blg_245_sealed_object_full_size_visible | Manifest size fields; read fee model | IP-22 (Padme), IP-56 |
| BLG-246 | Critical | src/chain/finality.rs | Open | blg_246_quorum_stake_plus_count | src/chain/finality.rs:119-129, :878-902 (quorum_count AND quorum_stake both required) | IP-12 |
| BLG-247 | High | Cargo.toml libp2p features / chain_config.rs | Open | blg_247_no_nat_circuit_relay | Cargo.toml libp2p features lack relay/dcutr/autonat; config/testnet.toml enable_circuit_relay = false | IP-15 |
| BLG-248 | High | src/execution/executor.rs / zkvm.rs | Open | blg_248_no_general_purpose_contract | src/execution/executor.rs ContractCall stateless; CONTRACT_VM_MEMORY_BYTES = 8192 | IP-26, IP-33 |
| BLG-249 | High | src/rpc/method_class.rs | Open | blg_249_only_bud_rpc_methods | src/rpc/method_class.rs (all 180 methods bud_ prefixed; no eth/solana/aptos/cosmos gateways) | IP-28, IP-29, IP-31, IP-32 |
| BLG-250 | Critical | Cargo.toml [profile.release] panic="abort" | Open | blg_250_release_panic_abort_ee_isolation | Cargo.toml:395 `panic = "abort"`; execution environments run in node process | IP-26 |
| BLG-251 | High | src/registry/liveness.rs | Open | blg_251_liveness_slashing_report | src/registry/liveness.rs (record_epoch returns SlashingReport; no absence-without-slash for mobile) | IP-13 |
| BLG-252 | Medium | src/registry/role.rs | Open | blg_252_separate_storage_roles | src/registry/role.rs (STORAGE_OPERATOR=5, CONTENT_VALIDATOR=9; contradicts V-5 single registry) | IP-08 |
| BLG-253 | Medium | src/storage/mobile_self.rs, server_admission.rs, src/network/mobile.rs | Open - removal (IP-07, IP-08) | blg_253_mobile_self_bud1_hosting | src/storage/mobile_self.rs exists; MobileSelfProfile::calculate_leaf length-unprefixed hashes | IP-07, IP-08 |
| BLG-254 | High | xtask/gates three_is_recipe_only, zero_storage_frozen, generated_content | Open | blg_254_gates_force_recipe_model | xtask/gates/src/gates/three_is_recipe_only.rs, zero_storage_frozen.rs, generated_content.rs | IP-07, IP-42 |
| BLG-255 | Low | Code-wide | Open | blg_255_concept_name_ratchet | Filiz 15 files, Mikoriza 13, Graft 24, Pollen 44 files (grep count) | IP-05, IP-43 and every package |
| BLG-256 | High | src/core/account.rs (balance: u64) | Open | blg_256_budget_no_fraction_field | src/core/account.rs (atom 10^-6 BUD; no frac_attos field; 18-decimal EVM / 9-decimal SVM exact transfer impossible) | IP-26 |
| BLG-257 | High | src/main.rs MobileNodeProfile DeviceType::Phone | Open | blg_257_no_mobile_validator_app | src/main.rs (mobile profile is only a CLI flag; no mobile validator application) | IP-11, IP-36 |
| BLG-258 | Medium | budzero/bud-node/ | Open - removal (IP-07) | blg_258_bud_node_bitswap_content_node | budzero/bud-node/ exists (Bitswap, Kademlia, MemoryContentStore; content gateway depends on it) | IP-07 |
| BLG-259 | Medium | src/chain/finality.rs, src/consensus/qc.rs | Open | blg_259_checkpoint_certificate_420kb | src/chain/finality.rs, src/consensus/qc.rs (128 seats x 3309 bytes ~ 420 KB; light client burden; security model undocumented) | IP-12, IP-11 |
| BLG-260 | Medium | src/storage/db.rs (sled) | Open | blg_260_single_process_state_store | src/storage/db.rs (single-process sled; execution workers cannot read state directly; IPC read performance risk) | IP-26 |
| BLG-261 | Low | src/deed/mod.rs | Open | blg_261_deed_register_manifest_breaks | src/deed/mod.rs (RegisterManifest breaks when 2.0 removed) | IP-23 |
| BLG-262 | Medium | src/gateway/service.rs | Open | blg_262_content_gateway_bitswap_sled | src/gateway/service.rs (gateway serves via Bitswap + local sled; not bound to B.U.D. 3.0 symbol path) | IP-23 |
| BLG-263 | Medium | src/tokenomics/reward_pool.rs, src/chain/blockchain.rs | Open | blg_263_security_pool_no_storage_share | src/tokenomics/reward_pool.rs (pay_epoch stake-weighted only; no storage-task share) | IP-16 |
| BLG-264 | High | src/consensus/filiz.rs, handoff.rs | Open | blg_264_hash_chain_election_not_wired | src/consensus/filiz.rs, handoff.rs (election and handoff not on production path; WIRING markers present) | IP-12 |
| BLG-265 | Medium | src/network/mobile.rs | Open | blg_265_mobile_profile_no_android_power_model | src/network/mobile.rs (no Android 15 dataSync 6h/24h power model) | IP-36 |
| BLG-266 | Medium | src/core/chain_config.rs (min_stake) | Open | blg_266_single_min_stake_no_class_split | src/core/chain_config.rs (one min_stake; no class split; 1000 BUD testnet barrier for phone users) | IP-08, IP-16 |
| BLG-267 | High | xtask/gates/classical_crypto_is_paired.rs | Open | blg_267_foreign_tx_compliance_shim | xtask/gates/src/gates/classical_crypto_is_paired.rs (rejects all classical signatures; no compliance shim per 8.6.2) | IP-27 |

## Defterarşiv aileleri (14.6)

| ID | Severity | Area | Live status | Closes with |
|---|---|---|---|---|
| BULGU-001 | S2 | src/consensus/pos.rs | Open | IP-12 |
| BULGU-002 | S2 | src/consensus/pos.rs | Open | IP-12 |
| BULGU-003 | S3 | src/consensus/pos.rs | Open | IP-12 |
| BULGU-004 | S3 | src/consensus/pos.rs, consensus/mod.rs | Open | IP-12 |
| BULGU-005 | S3 | src/chain/blockchain.rs | Open | IP-17 |
| BULGU-006 | S3 | src/chain/blockchain.rs | Open | IP-17 |
| BULGU-007 | S3 | src/chain/blockchain.rs | Open | IP-17 |
| BULGU-008 | S3 | src/chain/blockchain.rs | Open | IP-17 |
| BULGU-009 | S3 | src/chain/blockchain.rs | Open | IP-17 |
| BULGU-010 | S3 | src/core/transaction.rs | Open | IP-17 |
| BULGU-011 | S3 | src/rpc/server.rs | Open | IP-61 |
| BULGU-012 | S3 | src/rpc/server.rs | Open | IP-61 |
| BULGU-013 | S3 | src/execution/executor.rs | Open | IP-17 |
| BULGU-014 | S2 | src/network/node.rs | Open | IP-12 |
| BULGU-015 | S3 | src/chain/chain_actor.rs | Open | IP-17 |
| BULGU-016 | S3 | src/core/account.rs | Open | IP-17 |
| BULGU-017 | S3 | src/domain/storage_deal.rs | Open - removal (IP-07) | IP-07 |
| BULGU-018 | S3 | src/chain/genesis.rs | Open | IP-16 |
| BULGU-019 | S3 | src/core/account.rs, src/execution/executor.rs | Open | IP-16 |
| BULGU-020 | S3 | Fee gate class (nine members) | Open | IP-16 |
| BULGU-021 | S3 | src/sharding/mod.rs | Open | IP-17 |
| BULGU-022 | S3 | RoleBond gate | Open | IP-08 |
| BULGU-023 | S2 | src/consensus/pos.rs, src/chain/blockchain.rs | Open | IP-12 |
| BULGU-024 | S3 | src/chain/blockchain.rs, src/consensus/pos.rs | Open | IP-12 |
| BULGU-025 | S3 | src/consensus/pos.rs | Open | IP-12 |
| BULGU-026 | S3 | src/chain/blockchain.rs | Open | IP-12 |
| BULGU-027 | S3 | src/chain/blockchain.rs | Open | IP-12 |
| TEST-GAP-01 | High | src/core/account.rs | Open | IP-16 |
| TEST-GAP-02 | Medium | kani/ | Open | IP-42 |
| TEST-GAP-03 | Medium | QR video parser | Open | IP-19 |
| TEST-GAP-04 | Low | src/bin/budlum-domain-producer.rs | Open | IP-42 |
| TEST-GAP-05 | Medium | budzero folder.rs, ir/mod.rs | Open | IP-33 |
| TEST-GAP-06 | Medium | bud/kani | Open - removal (IP-07) | IP-07 |
| TEST-GAP-07 | Low | src/rpc | Open | IP-61 |
| TEST-GAP-08 | Medium | Proof retention window | Open | IP-12 |
| DOC-GAP-01 | S1 | config/testnet.toml, src/main.rs, ops/ | Open | IP-41 |
| DOC-GAP-02 | S3 | CLI, profile, compose, systemd | Open | IP-43 |
| DOC-GAP-03 | S3 | README, CONTRIBUTING, ops/scripts | Open | IP-43 |
| DOC-GAP-04 | S3 | ops/budlum-core.service | Open | IP-41 |
| DOC-GAP-05 | S3 | docs/VALIDATOR_GUIDE.md, docs/TESTNET.md, docs/OPERATIONS.md | Open | IP-43 |
| DOC-GAP-06 | S3 | docs/TESTNET.md, docs/VALIDATOR_GUIDE.md | Open | IP-46 |
| DOC-GAP-07 | Invalid | Cargo.toml | Invalid | IP-42 |
| DOC-GAP-08 | S3 | src/bin/bud.rs | Open | IP-39 |
| DOC-GAP-09 | S3 | Finding ledger table | Open | IP-43 |

### Notes

- DOC-GAP-07 (`budlum-indexer` missing binary record) is INVALID: `src/bin/budlum-indexer.rs` exists on the live branch.
- BLG-008, BLG-033, BLG-063 carry "Verified" statuses per the directive snapshot notes and the inspection points above.
- All "Open - removal (IP-07)" findings close when IP-07 deletes the legacy storage code and `no_legacy_storage` is green (14.1 madde 6).
- Counts per package (from the ledger): IP-07: 18, IP-11: 1, IP-12: 9, IP-15: 4, IP-16: 7, IP-17: 34, IP-19: 4, IP-21: 2, IP-22: 1, IP-23: 4, IP-24: 2, IP-33: 20, IP-39: 3, IP-40: 4, IP-41: 2, IP-42: 28, IP-43: 1, IP-44: 28, IP-45: 25, IP-61: 10. Severity distribution: Critical 73, High 80, Medium 51, Low 3; 18 findings close by removal.

## Next steps (per directive)

1. IP-04 takes this file next (lane D: clients, operations, CI, documents, unified state) — it has no dependencies and opens M0.
2. Each package writes its reproduction tests first (S-3), red output recorded here, then the fix, then "Closed" with commit SHA + CI run number.
3. TLG-01 requires no open Critical/High finding at testnet launch; any feature whose finding stays open must be closed on testnet with a `<feature>_is_closed_on_testnet` test (1.5).
