# Live Verification Status - Lane B

Lane B findings verified on the live branch (main@cccf1da) by IP-01..04 (M0). Statuses per Directive 14.1 item 4; closure packages per Directive 14.3. Source of truth: docs/audit/LIVE_STATUS.md. Total records: 95.

| ID | Severity | Area | Live status | Reproduction test | Proof (file:line) | Closes with |
|---|---|---|---|---|---|---|
| BLG-025 | Medium | Cryptography | Open | blg_025_quantum_account_guardian_root | src/account_abstraction/ (QuantumAccount; 6/6 traces) | IP-45|
| BLG-035 | Medium | Storage | Open - removal (IP-07) | blg_035_bitswap_memory_store | budzero/bud-node/ exists; src/storage/mobile_self.rs, server_admission.rs exist (7/7 traces) | IP-07|
| BLG-045 | Critical | Security / Storage proofs | Open - removal (IP-07) | blg_045_storage_registry_open_challenge | src/storage/ (10/10 traces) | IP-07|
| BLG-046 | Critical | Economy / Storage accounting | Open - removal (IP-07) | blg_046_open_deal_prune_content | src/storage/ (12/14 traces) | IP-07|
| BLG-047 | High | Consensus / Storage integrity | Open - removal (IP-07) | blg_047_storage_registry_root_commitment | src/storage/manifest.rs (10/10 traces) | IP-07|
| BLG-048 | High | Correctness / Determinism | Open - partial removal | blg_048_storage_render_f64_sqrt | src/storage/render.rs (25/25 traces) | IP-19|
| BLG-049 | Medium | Security / Correctness | Open - partial removal | blg_049_erasure_reconstruct_multi | src/storage/erasure.rs (11/12 traces) | IP-22|
| BLG-059 | Critical | Cryptography / Verifiable AI | Open | blg_059_ai_execution_proof_binding | src/ai_inference/, src/prover/ (17/17 traces) | IP-45|
| BLG-060 | Critical | Consensus / Economy / Escrow | Open | blg_060_ai_attach_execution_fee_loss | src/ai_inference/ (12/12 traces) | IP-45|
| BLG-061 | High | Authorization / State integrity | Open | blg_061_ai_agent_payment_gaps | src/ai_inference/ (23/23 traces) | IP-45|
| BLG-062 | High | Consensus / State root / Arithmetic | Open | blg_062_ai_registry_weights_digest | src/ai/ (17/17 traces; AiVerifierQos u64 overflow) | IP-45|
| BLG-063 | Critical | Privacy / Cryptography / Consensus | Verified | blg_063_testnet_private_transfers | config/testnet-genesis.json chain_id 45261; `privacy_transfers_enabled` present on testnet (25/25 traces; IP-45 closes) | IP-45|
| BLG-064 | High | Data sovereignty / Cryptography / Economy | Open | blg_064_pollen_protected_content_bridge | src/pollen/, src/socialfi/ (20/21 traces) | IP-23|
| BLG-070 | High | Privacy / Closed-circuit masking | Open | blg_070_ai_knowledge_redact_json | src/ai/ (14/14 traces) | IP-45|
| BLG-071 | High | AI inference bridge / Cryptographic binding | Open | blg_071_ai_core_manifest_digest | src/ai/ (27/27 traces) | IP-45|
| BLG-072 | Medium | Information extraction / Cost | Open | blg_072_ai_knowledge_turkish_split | src/ai_inference/ (16/16 traces; NaN/negative float) | IP-45|
| BLG-073 | Critical | Cryptography / Data integrity | Open - removal (IP-07) | blg_073_bud_v2_content_id_triple | src/storage/content_id.rs, bud/ (.bud v1 pq_public_key; 31/31 traces) | IP-07|
| BLG-074 | High | Consensus / Cryptographic proof / Erasure | Open - removal (IP-07) | blg_074_bud_cauchy_ldrc | bud/ (25/25 traces) | IP-07|
| BLG-075 | High | Lossless compression / Parser security | Open - removal (IP-07) | blg_075_bud_columnar_panic | bud/ (32/33 traces) | IP-07|
| BLG-076 | Medium | Economy / Gate validation / Arithmetic | Open - removal (IP-07) | blg_076_bud_fidelity_gate | bud/ (22/22 traces) | IP-07|
| BLG-077 | Critical | Post-quantum crypto / Identity binding | Open - removal (IP-07) | blg_077_bud_quantum_chain | bud/ (15/19 traces) | IP-07|
| BLG-078 | High | Container integrity / Memory safety | Open - removal (IP-07) | blg_078_bud_cli_decode_container | bud/ (28/28 traces) | IP-07|
| BLG-079 | High | Privacy / Secret masking / Binding | Open - removal (IP-07) | blg_079_bud_securededup_plaintext | bud/ (21/21 traces) | IP-07|
| BLG-080 | Medium | Indexing / QR derivative / Economy | Open - removal (IP-07) | blg_080_bud_pgm_search_range | bud/ (21/21 traces) | IP-07|
| BLG-093 | High | License integrity / Supply chain | Open | blg_093_ai_inference_license | crates/ai-inference/LICENSE.md MIT vs root PolyForm Shield 1.0.0 | IP-45|
| BLG-106 | Critical | AI / Consensus / DoS | Open | blg_106_ai_model_spec_execution_dims | src/ai/ (15/16 traces) | IP-45|
| BLG-109 | Critical | Data sovereignty / B.U.D. storage / SocialFi | Open - partial removal | blg_109_nft_mint_burn_manifest_delete | src/socialfi/, src/bns/ (15/16 traces) | IP-23|
| BLG-110 | Critical | Consensus state root / BNS / Privacy | Open | blg_110_bns_registry_default_base_cost | src/bns/ (23/23 traces; L1NoteRegistry MAX_LIVE_COMMITMENTS; XSS) | IP-23|
| BLG-111 | Critical | Post-quantum cryptography | Open | blg_111_bpqs_debug_release_divergence | crates/bpqs/ (13/14 traces; Q_MAX=1 WOTS reuse; saltless chain digest) | IP-45|
| BLG-112 | Critical | AI inference layer / Pollen data market / Consensus | Open | blg_112_ai_model_id_determinism | src/ai_inference/ (23/23 traces; declare_effort_ceiling deadlock) | IP-45|
| BLG-122 | High | B.U.D. consensus / Storage proofs / PACT | Open - removal (IP-07) | blg_122_bud_ratio_consensus_nan | bud/ (42/43 traces) | IP-07|
| BLG-123 | Medium | B.U.D. format converters / Losslessness / Ona | Open - removal (IP-07) | blg_123_bud_store_json_columnar | bud/ (22/23 traces) | IP-07|
| BLG-124 | High | AI inference / Information layer / Presentation | Open | blg_124_ai_inference_websocket_auth | src/ai_inference/ (28/29 traces) | IP-45|
| BLG-126 | Critical | Security / Data sovereignty / AI-Pollen closed | Open | blg_126_ai_inference_request_access_grant | src/ai_inference/, src/pollen/ (21/24 traces) | IP-45|
| BLG-129 | High | Gateway proofs | Open | blg_129_dweb_passport_proof_bundle | src/gateway/, src/budlumxyz/ (36/37 traces) | IP-23|
| BLG-133 | Medium | Storage state management | Open - partial removal | blg_133_dictionary_registry_immortal_record | src/storage/dictionary.rs, derived.rs, mobile_self.rs, transformed.rs (44/46 traces) | IP-24|
| BLG-135 | High | Storage economy | Open - partial removal | blg_135_living_threshold_half_life | src/storage/living_threshold.rs, storage_deal.rs (29/31 traces) | IP-24|
| BLG-137 | High | B.U.D. 2.0/3.0 storage pipe / Kademlia DHT | Open - partial removal | blg_137_bud3_qr_video_stream | src/storage/qr_*.rs, three_nft.rs (45/48 traces) | IP-19|
| BLG-141 | Medium | B.U.D. 2.0 format engines | Open - removal (IP-07) | blg_141_bud_lowrank_matrix_coder | bud/ (25/28 traces) | IP-07|
| BLG-144 | High | B.U.D. 1.0/3.0 custody accounting / Optical recipe | Open - partial removal | blg_144_single_screen_view_contract_digest | src/storage/one_view.rs, qr_recipe.rs (20/23 traces) | IP-19|
| BLG-145 | Medium | B.U.D. 2.0 derivation / Optical transfer / Zstd | Open - partial removal | blg_145_crop_derivation_aligned_true | bud/ (17/19 traces) | IP-45|
| BLG-148 | High | B.U.D. agreement lifecycle / Registry echo | Open - split IP-07 / IP-33 | blg_148_storage_lifecycle_missed_terminal | src/storage/lifecycle.rs (IP-07 part); budzero/verifier-registry/ (IP-33 part; 17/19 traces) | IP-33, IP-07|
| BLG-149 | Medium | B.U.D. 2.0 dedup / pricing / AI operations | Open - partial removal | blg_149_pow_challenge_salt_digest | bud/ (26/29 traces) | IP-45|
| BLG-152 | Medium | B.U.D. fidelity core / Tiny object block pack | Open - removal (IP-07) | blg_152_fidelity_core_thumbnail_bytes | bud/ (15/17 traces) | IP-07|
| BLG-153 | Medium | B.U.D. optical/log templating / Genomic reference | Open - removal (IP-07) | blg_153_optical_gates_k_bud_optical | bud/ (16/18 traces) | IP-07|
| BLG-156 | Medium | Quantum policy gate / .bud wire evolution / Po | Open - removal (IP-07) | blg_156_quantum_suite_substring_escape | bud/ (17/19 traces) | IP-07|
| BLG-157 | Medium | B.U.D. database delta / Converter gates | Open - partial removal | blg_157_dbd_digest_page_boundary | bud/ (16/18 traces) | IP-45|
| BLG-160 | Medium | Closed-loop AI data governance / Training | Open | blg_160_ai_dataset_storage_deal_validation | src/ai/ (15/17 traces) | IP-45|
| BLG-161 | Medium | B.U.D. storage integrity / Multi-tenant QoS / S | Open - partial removal | blg_161_bud_format_scrub_bit_rot | bud/ (23/25 traces) | IP-21|
| BLG-163 | High | B.U.D. 3.0 optical storage / QR matrix / PNG codec | Open | blg_163_qr_matrix_u32_overflow | src/storage/qr_matrix.rs, qr_png.rs, qr_encode.rs (8/10 traces) | IP-19|
| BLG-164 | High | Post-quantum cryptography | Open | blg_164_bpqs_epoch_of_u32_truncation | crates/bpqs/ (10/13 traces; PROTOC="" build failure) | IP-45|
| BLG-165 | Medium | Offline AI localization / Accessibility | Open | blg_165_ai_inference_i18n_bcp47 | src/ai_inference/i18n.rs (10/13 traces) | IP-45|
| BLG-166 | Critical | Decentralized AI consensus | Open | blg_166_ai_registry_single_min_verifier_stake | src/ai/ (27/31 traces) | IP-45|
| BLG-168 | Medium | B.U.D. 3.0 three-layer gate / Session opening | Open - partial removal | blg_168_refuse_durable_derivative_bypass | src/storage/ (20/25 traces) | IP-21|
| BLG-173 | Medium | Side-channel validation canary / Fuzz infra | Open | blg_173_dudect_poseidon2_detached | crates/bpqs/, fuzz/ (10/15 traces) | IP-45|
| BLG-185 | Medium | Quantum signature cost model / Concurrency validation | Open - partial removal | blg_185_bpqs_wire_size_cost_model | crates/bpqs/ (16/21 traces) | IP-45|
| BLG-201 | High | AI STARK DoS protection / Executor atomicity / B.U.D. | Open - partial removal | blg_201_ai_attach_execution_proof_size_gate | src/ai_inference/, src/execution/ (17/18 traces) | IP-45|
| BLG-208 | High | BUD3 H1 | Open - removal (IP-07, IP-21) | blg_208_bud_storage_edition_three | src/storage/generated.rs (BudStorageEdition::Three admits_body() false) | IP-07, IP-21|
| BLG-209 | High | BUD3 H2 | Open - removal (IP-07, IP-25) | blg_209_three_regime_zero_fee | src/storage/three_regime.rs | IP-07, IP-25|
| BLG-210 | High | BUD3 H3 | Open | blg_210_video_recipe_content_bytes | src/storage/three_recipe.rs | IP-19|
| BLG-211 | Medium | BUD3 H4 | Open | blg_211_three_recipe_models | src/storage/qr_recipe.rs, three_recipe.rs, three_nft.rs | IP-19|
| BLG-212 | Critical | BUD3 H5 | Open | blg_212_bud_storage_qr_feed_preview | src/rpc/server.rs (bud_storageQrFeed*); three_reveal.rs, three_nft.rs | IP-21, IP-23|
| BLG-213 | High | BUD3 H6 | Open | blg_213_emit_u32_length_silent_trunc | src/storage/emit.rs, qr_payload.rs, qr_carousel.rs | IP-18|
| BLG-214 | Medium | BUD3 H7 | Open | blg_214_video_id_deflate_not_stable | src/storage/qr_video.rs, qr_png.rs | IP-19|
| BLG-215 | High | BUD3 H8 | Open | blg_215_no_object_from_video | src/storage/ (no video-to-object extraction; two paths missing) | IP-19|
| BLG-216 | High | BUD3 H9 | Open | blg_216_qr_carousel_low_degree_xor | src/storage/qr_carousel.rs | IP-18|
| BLG-217 | Medium | BUD3 H10 | Open - removal (IP-07) | blg_217_bud_second_bud3_implementation | bud/ exists (112 files; second 3.0 implementation) | IP-07|
| BLG-218 | Low | BUD3 H11 | Open | blg_218_three_pipe_fixed_size_test_name | src/storage/three_pipe.rs | IP-19|
| BLG-219 | Medium | BUD3 H12 | Open | blg_219_transformed_zlib_only | src/storage/transformed.rs | IP-24|
| BLG-220 | Critical | BUD3 H13 | Open | blg_220_no_redundancy_bud3_object | src/storage/erasure.rs, README (2.0 schema 10,16 vs 256 shard cap) | IP-20|
| BLG-221 | Medium | BUD3 H14 | Open | blg_221_no_dedup_reference_count | src/storage/ | IP-22|
| BLG-222 | Medium | BUD3 H15 | Open | blg_222_dictionary_derived_not_bud3 | src/storage/dictionary.rs, living_threshold.rs, derived.rs | IP-24|
| BLG-223 | High | Gonca E1 | Open | blg_223_bud_stark_pcs_zk_false | budzero/bud-proof/src/bud_stark/prover.rs | IP-56 (testnet closure IP-33, IP-45)|
| BLG-224 | High | Gonca E2 | Open | blg_224_note_commitment_nullifier_64bit | crates/note-packing/src/lib.rs; budzero/bud-state/src/note.rs; budzero/bud-vm/src/lib.rs | IP-56 (testnet closure IP-45)|
| BLG-225 | High | Gonca E3 | Open | blg_225_private_transfer_no_proofs | src/execution/executor.rs, src/privacy/submit.rs | IP-45, IP-56|
| BLG-226 | High | Gonca E4 | Open | blg_226_verify_merkle_single_round | budzero/bud-isa/src/lib.rs | IP-56 (testnet closure IP-33)|
| BLG-228 | High | Gonca E6 | Open | blg_228_ai_stark_verification_closed | src/ai/mod.rs | IP-57 (testnet closure IP-45)|
| BLG-229 | High | Gonca E7 | Open | blg_229_ai_registry_no_lottery | src/ai/registry.rs | IP-45 (VL-1 leg), IP-57|
| BLG-230 | Medium | Gonca E8 | Open | blg_230_sender_64bit_vs_address_256bit | budzero/bud-vm/src/lib.rs; src/execution/zkvm.rs | IP-33 (execution leg), IP-56|
| BLG-232 | Medium | Gonca E10 | Open | blg_232_single_air_1073_columns | budzero/bud-proof/src/plonky3_air.rs | IP-56|
| BLG-236 | Medium | Gonca E14 | Open | blg_236_no_plaintext_bound_commitment | docs/BUD_CONTENT_ENCRYPTION.md; src/storage/payload_crypt.rs | IP-56|
| BLG-237 | High | Gonca E15 | Open | blg_237_view_grant_cleartext_row | src/storage/view_grant.rs (consent leg IP-56) | IP-22|
| BLG-238 | Medium | Gonca E16 | Open | blg_238_hpke_key_package_not_production | src/storage/key_package.rs | IP-22|
| BLG-240 | Low | Gonca E18 | Open | blg_240_validator_ordering_f64 | src/ai/registry.rs | IP-45, IP-57|
| BLG-242 | Medium | Gonca E20 | Open | blg_242_commitment_no_team_hash | All commitment types | IP-56|
| BLG-243 | Medium | Gonca E22 | Open | blg_243_event_accumulation_32bit_sum | budzero/README.md; docs/AI_VERIFICATION_STATUS.md | IP-56|
| BLG-245 | Medium | Gonca E23 | Open | blg_245_sealed_object_full_size_visible | Manifest size fields; read fee model | IP-22 (Padme), IP-56|
| BLG-253 | Medium | src/storage/mobile_self.rs, server_admission.rs, src/network/mobile.rs | Open - removal (IP-07, IP-08) | blg_253_mobile_self_bud1_hosting | src/storage/mobile_self.rs exists; MobileSelfProfile::calculate_leaf length-unprefixed hashes | IP-07, IP-08|
| BLG-254 | High | xtask/gates three_is_recipe_only, zero_storage_frozen, generated_content | Open | blg_254_gates_force_recipe_model | xtask/gates/src/gates/three_is_recipe_only.rs, zero_storage_frozen.rs, generated_content.rs | IP-07, IP-42|
| BLG-258 | Medium | budzero/bud-node/ | Open - removal (IP-07) | blg_258_bud_node_bitswap_content_node | budzero/bud-node/ exists (Bitswap, Kademlia, MemoryContentStore; content gateway depends on it) | IP-07|
| BLG-261 | Low | src/deed/mod.rs | Open | blg_261_deed_register_manifest_breaks | src/deed/mod.rs (RegisterManifest breaks when 2.0 removed) | IP-23|
| BLG-262 | Medium | src/gateway/service.rs | Open | blg_262_content_gateway_bitswap_sled | src/gateway/service.rs (gateway serves via Bitswap + local sled; not bound to B.U.D. 3.0 symbol path) | IP-23|
| BULGU-017 | S3 | src/domain/storage_deal.rs | Open - removal (IP-07) | - | - | IP-07|
| TEST-GAP-03 | Medium | QR video parser | Open | - | - | IP-19|
| TEST-GAP-06 | Medium | bud/kani | Open - removal (IP-07) | - | - | IP-07|
