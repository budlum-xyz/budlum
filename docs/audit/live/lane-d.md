# Live Verification Status - Lane D

Lane D findings verified on the live branch (main@cccf1da) by IP-01..04 (M0). Statuses per Directive 14.1 item 4; closure packages per Directive 14.3. Source of truth: docs/audit/LIVE_STATUS.md. Total records: 70.

| ID | Severity | Area | Live status | Reproduction test | Proof (file:line) | Closes with |
|---|---|---|---|---|---|---|
| BLG-004 | Medium | Cryptography | Open | blg_004_key_file_permissions | src/crypto/ (snapshot: 8/10 traces) | IP-61|
| BLG-009 | Medium | Cryptography | Open | blg_009_pq_api_fips_context | src/crypto/ (snapshot 3/3 traces) | IP-61|
| BLG-010 | Medium | Cryptography | Open | blg_0010_pkcs11_key_label | src/crypto/ (snapshot 2/4 traces) | IP-61|
| BLG-011 | Medium | RPC/Operations | Open | blg_011_ops_service_rpc_credentials | ops/budlum-core.service (snapshot 1/3 traces; LimitCORE=infinity) | IP-41|
| BLG-012 | High | Build/CI | Open | blg_012_coverage_rs_first_file_percent | xtask/gates/src/gates/coverage.rs (snapshot 1/1 traces) | IP-42|
| BLG-013 | Medium | Build/CI | Open | blg_013_prepush_all_features | ops/scripts/prepush (snapshot 1/1 traces) | IP-42|
| BLG-014 | Medium | Storage | Open | blg_014_backup_drill_exit_code | ops/scripts/backup_drill.rs (snapshot 2/2 traces) | IP-42|
| BLG-015 | Medium | Build/CI | Open | blg_015_standalone_crate_tests | crates/wallet-core, crates/ai-inference, crates/bpqs (snapshot 3/3 traces) | IP-42|
| BLG-016 | High | Build/CI / Supply chain | Open | blg_016_rustsec_advisories | Cargo.lock files (snapshot 4/4 traces; part closable by removal) | IP-42|
| BLG-022 | Medium | Consensus | Open | blg_022_light_client_checkpoint_loop | src/light_client/ (snapshot 4/4 traces; u64::MAX bound) | IP-11|
| BLG-026 | Medium | Build/CI | Open | blg_026_wallet_core_ai_inference_ci_gap | crates/wallet-core, crates/ai-inference (fmt/clippy/--locked; 4/4 traces; 12-word/NFKD seed path) | IP-39|
| BLG-029 | High | RPC | Open | blg_029_extract_client_ip_xff | src/rpc/ (snapshot 3/3 traces; rightmost XFF / next_back fix trace present) | IP-61|
| BLG-030 | Critical | RPC | Open | blg_030_public_rpc_consensus_write | src/rpc/ (snapshot 22/23 traces; faucet part is IP-41) | IP-61, IP-41|
| BLG-032 | Medium | RPC | Open | blg_032_budgateway_pollen_cache_nonce | src/gateway/, src/rpc/ (snapshot 24/24 traces; 14 Prepare templates) | IP-61|
| BLG-068 | High | Explorer verification core | Open | blg_068_budscan_verified_badge | crates/budscan/ (23/23 traces) | IP-40|
| BLG-081 | High | CI security gates / coverage gaps | Open | blg_081_xtask_gates_wallet_core_root | xtask/gates/src/gates/ (8/8 traces; nonexistent "wallet-core" root; bud/ out of scope) | IP-42|
| BLG-082 | High | Static security analysis / AST validation | Open | blg_082_ast_security_gates | xtask/gates/src/gates/ast_security_gates.rs (24/25 traces) | IP-42|
| BLG-083 | Medium | Economy / Quality gates | Open | blg_083_supply_count_rate_consensus | xtask/gates/src/gates/economy_invariants.rs (20/20 traces) | IP-42|
| BLG-084 | High | CI security / integrity gates | Open | blg_084_relay_fail_open_regeneration | xtask/gates/src/gates/relay.rs, regeneration.rs (7/7 traces) | IP-42|
| BLG-085 | High | Build hardening / gate scope | Open | blg_085_gates_release_profile | xtask/gates/ (15/15 traces; missing [profile.release] hardening in independent workspaces) | IP-42|
| BLG-086 | Medium | Gate reliability / CWE-377 / Language | Open | blg_086_turkish_strings_in_gates | xtask/gates/src/gates/ (19/19 traces; Turkish strings remain in gates) | IP-42|
| BLG-087 | High | Fuzzing / Formal verification / Benchmarks | Open | blg_087_fuzz_targets_consensus | fuzz/, kani/ (29/32 traces; unbounded bincode::deserialize OOM; empty consensus_validate target) | IP-42|
| BLG-092 | High | Documentation-code match / Operational security | Open - partial (KR-21) | blg_092_readme_definition_block | README.md lines 1-14 verified verbatim against Ek A (SHA-256 dd9be520...); --priv-key argv example removed from README.tr.md (leak closed); remaining items are README.tr.md localization, the permitted Turkish document (KR-21 keeps the definition block verbatim) | IP-43|
| BLG-095 | Medium | Build/CI / Supply chain / Governance | Open | blg_095_codeowners_dependabot_lockfiles | .cargo/audit.toml, CODEOWNERS, workflows (3/3 traces; deleted Turkish branches/steps) | IP-41|
| BLG-097 | High | CI | Open - partial removal | blg_097_kani_bud_fuzz_cargo_lock | kani/, bud/fuzz/ (14/14 traces; missing Cargo.lock; orphan kani_bud_format.rs; crates/budscan CI gap) | IP-42|
| BLG-098 | Critical | Security | Open | blg_098_node_config_rpc_auth | src/main.rs (NodeConfig #[arg(skip)] resets RPC auth/IP allowlist defaults; 23/25 traces) | IP-39|
| BLG-099 | High | Security | Open | blg_099_constant_time_eq_self_compare | src/crypto/ (constant_time_eq_str a_b.ct_eq(a_b); 4/6 traces) | IP-61|
| BLG-117 | Critical | Wallet cryptography / Privacy / Social recovery | Open | blg_117_wallet_core_four_round_poseidon | crates/wallet-core/ (28/31 traces; recipient_tag i32 truncation; 64-bit spending secret entropy) | IP-39|
| BLG-121 | High | Verifiable explorer / Light client / Patch | Open | blg_121_budscan_ens_arweave_ns | crates/budscan/ (25/26 traces) | IP-40|
| BLG-143 | High | Verifiable explorer content verification | Open | blg_143_budscan_bdlm_manifest_v4_refused | crates/budscan/fetch.rs (25/28 traces) | IP-40|
| BLG-150 | Critical | Consensus signature field separation / HSM | Open | blg_150_consensus_signer_sign_prevote | src/crypto/, src/chain/chain_actor.rs (23/25 traces) | IP-61|
| BLG-169 | Medium | Developer SDK | Open | blg_169_budlum_toml_dropped_sections | src/sdk/ (14/16 traces) | IP-40|
| BLG-170 | High | Security gates / Static analysis | Open | blg_170_ast_security_gates_bypass | xtask/gates/src/gates/ (25/27 traces) | IP-42|
| BLG-171 | High | CI security gates / Supply chain | Open | blg_171_security_scans_can_fail | xtask/gates/src/gates/ (16/19 traces) | IP-42|
| BLG-172 | Medium | Developer and operations tools | Open | blg_172_budlum_tools_poa_validators_json | xtask/tools/, ops/ (15/17 traces) | IP-42|
| BLG-174 | High | ZK/STARK soundness gates | Open | blg_174_accumulators_pinned_first_row | xtask/gates/src/gates/ (18/20 traces) | IP-42|
| BLG-175 | High | Supply chain / Build integrity gates | Open | blg_175_git_dep_audited_cargo_vet | xtask/gates/src/gates/ (15/17 traces) | IP-42|
| BLG-176 | Medium | Benchmark accuracy / Module hygiene | Open | blg_176_bench_internal_pipeline_tps_chain_id | benches/ (8/10 traces; chain_id=1337 vs 45262) | IP-42|
| BLG-177 | Medium | Address agreement gate / Storage admission / Role | Open - partial removal | blg_177_wallet_node_address_agree_extra_digest | src/crypto/primitives.rs vs crates/wallet-core (20/22 traces) | IP-42|
| BLG-178 | High | ZKVM soundness / Gas calibration / Regression tests | Open | blg_178_zero_tests_witness_skip | xtask/gates/src/gates/ (16/18 traces) | IP-42|
| BLG-179 | Critical | Snapshot serialization / Genesis schema / Slash | Open | blg_179_serialize_map_keys_enum | xtask/gates/src/gates/ (21/26 traces) | IP-42|
| BLG-180 | Medium | Storage manifest / Coding audit / AI system | Open | blg_180_content_encryption_gate_tuple_key | xtask/gates/src/gates/ (16/20 traces) | IP-42|
| BLG-181 | Medium | Fuzz coverage / Module coverage gate / CI shell gate | Open | blg_181_evm_mpt_verify_fixed_128 | fuzz/, xtask/gates/ (13/16 traces) | IP-42|
| BLG-187 | High | Fuzz validation coverage / Reorg bound / Bridge acct | Open | blg_187_consensus_state_transition_fuzz | fuzz/ (19/20 traces) | IP-42|
| BLG-188 | High | Storage slashing security gate / MEV-free mempool | Open | blg_188_uncheckable_proof_false_true_flip | xtask/gates/src/gates/ (11/13 traces) | IP-42|
| BLG-189 | Medium | Storage/Transfer pricing gates / Shard placement | Open | blg_189_storage_priced_gate_blindness | xtask/gates/src/gates/ (19/20 traces) | IP-42|
| BLG-192 | High | JSON-RPC fee estimate / Wallet-SDK compatibility | Open | blg_192_bud_estimateGas_transfer_fee_ppm | src/rpc/server.rs (12/13 traces) | IP-61|
| BLG-193 | Medium | CI quality/security gates / Syntax scanner | Open - partial removal | blg_193_gates_comment_syntax_bypass | xtask/gates/src/gates/ (41/42 traces) | IP-42|
| BLG-200 | High | BLS12-381 consensus cryptography / false-green | Open | blg_200_bls_keypair_from_seed_zero | src/crypto/ (13/13 traces) | IP-61|
| BLG-231 | Medium | Gonca E9 | Open | blg_231_recursive_aggregation_doc_vs_code | budzero/bud-state/src/lib.rs; budzero/ARCHITECTURE.md | IP-43|
| BLG-241 | Low | Gonca E19 | Open | blg_241_interpret_poseidon_width_12 | budzero/bud-isa/src/lib.rs; budzero/bud-vm/src/lib.rs | IP-43|
| BLG-254 | High | xtask/gates three_is_recipe_only, zero_storage_frozen, generated_content | Open | blg_254_gates_force_recipe_model | xtask/gates/src/gates/three_is_recipe_only.rs, zero_storage_frozen.rs, generated_content.rs | IP-07, IP-42|
| BLG-255 | Low | Code-wide | Open | blg_255_concept_name_ratchet | Filiz 15 files, Mikoriza 13, Graft 24, Pollen 44 files (grep count) | IP-05, IP-43 and every package|
| BLG-257 | High | src/main.rs MobileNodeProfile DeviceType::Phone | Open | blg_257_no_mobile_validator_app | src/main.rs (mobile profile is only a CLI flag; no mobile validator application) | IP-11, IP-36|
| BLG-259 | Medium | src/chain/finality.rs, src/consensus/qc.rs | Open | blg_259_checkpoint_certificate_420kb | src/chain/finality.rs, src/consensus/qc.rs (128 seats x 3309 bytes ~ 420 KB; light client burden; security model undocumented) | IP-12, IP-11|
| BLG-265 | Medium | src/network/mobile.rs | Open | blg_265_mobile_profile_no_android_power_model | src/network/mobile.rs (no Android 15 dataSync 6h/24h power model) | IP-36|
| BULGU-011 | S3 | src/rpc/server.rs | Open | - | - | IP-61|
| BULGU-012 | S3 | src/rpc/server.rs | Open | - | - | IP-61|
| TEST-GAP-02 | Medium | kani/ | Open | - | - | IP-42|
| TEST-GAP-04 | Low | src/bin/budlum-domain-producer.rs | Open | - | - | IP-42|
| TEST-GAP-07 | Low | src/rpc | Open | - | - | IP-61|
| DOC-GAP-01 | S1 | config/testnet.toml, src/main.rs, ops/ | Open | - | - | IP-41|
| DOC-GAP-02 | S3 | CLI, profile, compose, systemd | Open | - | - | IP-43|
| DOC-GAP-03 | S3 | README, CONTRIBUTING, ops/scripts | Open | - | - | IP-43|
| DOC-GAP-04 | S3 | ops/budlum-core.service | Open | - | - | IP-41|
| DOC-GAP-05 | S3 | docs/VALIDATOR_GUIDE.md, docs/TESTNET.md, docs/OPERATIONS.md | Open | - | - | IP-43|
| DOC-GAP-06 | S3 | docs/TESTNET.md, docs/VALIDATOR_GUIDE.md | Open | - | - | IP-46|
| DOC-GAP-07 | Invalid | Cargo.toml | Invalid | - | - | IP-42|
| DOC-GAP-08 | S3 | src/bin/bud.rs | Open | - | - | IP-39|
| DOC-GAP-09 | S3 | Finding ledger table | Open | - | - | IP-43|
