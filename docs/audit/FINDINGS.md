# Findings ledger

The repository's copy of the unified findings ledger: identity, severity,
area, English title, live status, regression test name and closing package.
New findings found during work are appended here from `BLG-268` onwards.

The four lane files under `docs/audit/live/` carry the evidence for each
status; this page is the index. `docs/audit/LIVE_STATUS.md` summarises it.

## Statuses

- `open - live verification pending` - the ledger's snapshot note stands and
  no lane has reproduced or refuted it on this branch yet.
- `open - verified` - reproduced on this branch by reading the live tree;
  the evidence line is in the lane file.
- `closed - previously fixed` - the analysis snapshot already carried the
  fix. The permanent regression test named in the row is what keeps it
  closed; the lane file names the evidence.
- `closed by removal` - every location is gone from the tree. The evidence
  is the absence plus the `no_legacy_storage` gate output once WP-07 lands.
- `open - not re-scanned` - needs a tool run this workspace cannot make.

## Severity

`critical`, `high`, `medium`, `low` are the ledger's own severities. The
archive families below carry the old ledger's `S1`, `S2`, `S3` codes; they
are reproduced unchanged because re-grading them is WP-01 to WP-04 work and
a silent re-grade would break the comparison with the source ledger.

## Counts

| Source | Identities | Rows |
|---|---|---|
| The findings ledger (`main` `c5b06799`) | BLG-001..BLG-207 | 207 |
| B.U.D. 3.0 single-recipe directive, code errors H1..H15 | BLG-208..BLG-222 | 15 |
| BudZero bud directive, findings E1..E23 | BLG-223..BLG-245 | 23 |
| This directive's own review | BLG-246..BLG-267 | 22 |
| Ledger archive families | BULGU-001..027, TEST-GAP-01..08, DOC-GAP-01..09 | 44 |
| This pass | BLG-268..BLG-270 | 3 |
| **Total** | | **314** |

The 207 ledger rows split 73 critical, 80 high, 51 medium, 3 low, which is
the summary table's own split recomputed from the rows: they agree.

## Ledger

| Identity | Severity | Area | Title | Live status | Regression test | Closing package |
|---|---|---|---|---|---|---|
| BLG-001 | critical | consensus | PoS leader election cannot skip an empty height, so block production locks permanently | open - live verification pending | `blg_pos_leader_election` | WP-12 |
| BLG-002 | high | consensus | The shipped testnet profile is not launch-ready: no key ceremony, no peer source, no tokenomics | open - live verification pending | `blg_shipped_testnet_profile` | WP-16 |
| BLG-003 | high | economics | Genesis supply validation does not check extra allocations and bootstrap stake against the 100M cap together | open - live verification pending | `blg_genesis_supply_validation` | WP-16 |
| BLG-004 | medium | cryptography | Rewriting the key file does not narrow permissions that are already wide | open - live verification pending | `blg_rewriting_key_file` | WP-61 |
| BLG-005 | medium | build and CI | The default secret and data directories are not excluded by Git | closed - previously fixed | `audit_lane_d_locks::blg_005_the_secrets_and_data_directories_never_reach_git` | WP-16 |
| BLG-006 | medium | economics | The verification reward pool is not bound to the production epoch transition | open - live verification pending | `blg_verification_reward_pool` | WP-16 |
| BLG-007 | medium | consensus | GlobalBlockHeader is still not the common consensus commitment; the PQ block budget stayed JSON | open - live verification pending | `blg_globalblockheader_still_common` | WP-17 |
| BLG-008 | medium | RPC | The testnet open-RPC acceptance condition contradicts the shipped profile, which requires a key for every call | open - live verification pending | `blg_testnet_open_rpc` | WP-16 |
| BLG-009 | medium | cryptography | The PQ API on main does not meet the registered mandatory FIPS context and explicit schema identifier rules | open - live verification pending | `blg_api_main_does` | WP-61 |
| BLG-010 | medium | cryptography | The PKCS#11 key label is applied after the constructor binds the single unlabelled key | open - live verification pending | `blg_pkcs_key_label` | WP-61 |
| BLG-011 | medium | RPC | The shipped budlum-core.service unit does not provide the RPC credential the runtime reads and sets LimitCORE=infinity | closed - previously fixed | `audit_lane_d_locks::blg_011_the_validator_unit_dumps_no_core_and_reads_the_key_by_name` | WP-41 |
| BLG-012 | high | build and CI | The global coverage ratchet reads the first file's percentage instead of the total and lets a NaN baseline through | closed - previously fixed | `gates::coverage::the_total_is_read_not_the_first_file` | WP-42 |
| BLG-013 | medium | build and CI | The documented prepush helper always runs the deliberately disabled all-features combination | closed by removal | `audit_lane_d_locks::blg_013_no_script_directory_is_the_documented_workflow` | WP-42 |
| BLG-014 | medium | storage | The backup drill ignores the check-db exit code and accepts a substring match as success | closed - previously fixed | `audit_lane_d_locks::blg_014_a_failed_integrity_check_fails_the_drill` | WP-42 |
| BLG-015 | medium | build and CI | Unit tests of three standalone Rust crates are not run by the root cargo test --workspace | open - partly fixed | `blg_unit_tests_three` | WP-42 |
| BLG-016 | high | build and CI | A fresh RustSec scan finds patchable advisories in 6 of the 11 tracked Cargo.lock files | open - not re-scanned | `blg_fresh_rustsec_scan` | WP-42 |
| BLG-017 | critical | network | UTF-8 byte slicing on unauthenticated P2P Prevote, Precommit and FinalityCert messages panics the node down | open - live verification pending | `blg_utf_byte_slicing` | WP-15 |
| BLG-018 | critical | consensus | Hybrid finality cannot advance on a live network because of four independent breaks | open - live verification pending | `blg_hybrid_finality_cannot` | WP-12 |
| BLG-019 | critical | state transition | TransactionType::StateUpdate lets any account's nonce be written without authority or a commitment binding | open - live verification pending | `blg_transactiontype_stateupdate_lets` | WP-17 |
| BLG-020 | critical | consensus | Pre-rejection temp_state mutation plus missing nonce and signature checks in the Executor produce a permanent chain split from two mempool transactions | open - live verification pending | `blg_pre_rejection_temp` | WP-17 |
| BLG-021 | critical | economics | Role bonding burns funds, overwrites bonds, pierces vesting and writes state outside a block | open - live verification pending | `blg_role_bonding_burns` | WP-17 |
| BLG-022 | medium | consensus | LightClient::next_checkpoint_height loops forever at the u64 boundary and burns O(interval) CPU on large intervals | open - live verification pending | `blg_lightclient_next_checkpoint` | WP-11 |
| BLG-023 | medium | state transition | Executor::RelayerResult rejects valid DomainEventTree proofs for single-event external blocks and does not require the relayer bond | open - live verification pending | `blg_executor_relayerresult_rejects` | WP-17 |
| BLG-024 | low | consensus | PoW, PoS, PoA and BFT finality adapters do not check domain identity themselves and PoAFinalityAdapter panics on a zero denominator | open - live verification pending | `blg_pow_pos_poa` | WP-44 |
| BLG-025 | low | cryptography | QuantumAccount::validate_all and the registry accept duplicate guardian keys and an inconsistent guardian root | open - live verification pending | `blg_quantumaccount_validate_registry` | WP-45 |
| BLG-026 | medium | build and CI | Sub-workspaces have no fmt, clippy or locked CI, an empty assert gate test, and a 12-word non-NFKD wallet seed path | open - live verification pending | `blg_sub_workspaces_fmt` | WP-39 |
| BLG-027 | high | consensus | V5 (ML-DSA-87) wallet addresses are incompatible with PoS block production, slashing proofs and storage challenge signatures | open - live verification pending | `blg_dsa_wallet_addresses` | WP-12 |
| BLG-028 | high | storage | StateSnapshotV2::from_bytes skips digest verification, apply_v2_snapshot skips finality bounds and save_snapshot_v2 is not atomic | open - live verification pending | `blg_statesnapshotv2_bytes_skips` | WP-17 |
| BLG-029 | high | RPC | extract_client_ip trusts the leftmost X-Forwarded-For address and the rate limiter evicts FIFO, so IP quotas and allowlists are bypassed | closed - previously fixed | `audit_findings_locks::forwarded_headers_are_ignored_without_a_trusted_proxy` | WP-61 |
| BLG-030 | critical | RPC | Public RPC endpoints mutate consensus state outside block execution and the developer faucet stays open on the testnet chain id | open - live verification pending | `blg_public_rpc_endpoints` | WP-61, WP-41 |
| BLG-031 | low | consensus | GovernanceState::proposals keeps past proposals without bound, growing the state root cost every block | open - live verification pending | `blg_governancestate_proposals_keeps` | WP-17 |
| BLG-032 | medium | RPC | The BudGateway Pollen guard check and the content fetch key diverge, and the production cache resets on every request | open - live verification pending | `blg_budgateway_pollen_guard` | WP-61 |
| BLG-033 | critical | network | Unbounded bincode::deserialize on the unauthenticated P2P wire frame is an OOM bomb, and AiModelRegister loses fields | open - live verification pending | `blg_unbounded_bincode_deserialize` | WP-15 |
| BLG-034 | high | network | P2P subnetwork diversity is bypassable over IPv6, Kademlia is private-IP poisonable, tokio::spawn is unbounded and Bitswap has no resource limit | open - live verification pending | `blg_p2p_subnetwork_diversity` | WP-15 |
| BLG-035 | medium | storage | The bud-node BitswapCodec silently truncates frames and MemoryContentStore has byte-limit and eviction defects | open - live verification pending | `blg_bud_node_bitswapcodec` | WP-07 |
| BLG-036 | critical | network | BudAir register and memory sorted tables lack activity adjacency, key and clock ordering, and m_same transitions | open - live verification pending | `blg_budair_register_memory` | WP-33 |
| BLG-037 | critical | network | VerifyInference allows forged AI inference acceptance over free witness columns, and SWrite state digest limbs are not canonical | open - live verification pending | `blg_verifyinference_allows_forged` | WP-33 |
| BLG-038 | critical | cryptography | Linear initial-memory commitment collision, unframed event digest sum, unbound chain_id shift and silent truncation | open - live verification pending | `blg_linear_initial_memory` | WP-33 |
| BLG-039 | critical | ZK and STARK | The STARK verifier panics remotely on degree_bits >= 27 and setup_preprocessed costs unbounded memory and CPU at zero gas | open - live verification pending | `blg_stark_verifier_panics` | WP-33 |
| BLG-040 | high | consensus | One-round reversible VerifyMerkle digest, ZKVM to BudAir semantic mismatches and ZkVmExecutor verifier issues | open - live verification pending | `blg_round_reversible_verifymerkle` | WP-33 |
| BLG-041 | critical | consensus | settlement_root replay divergence and out-of-block AccountState mutation break deterministic consensus | open - live verification pending | `blg_settlement_root_replay` | WP-17 |
| BLG-042 | critical | consensus | Failed BLS-signed Prevote and Precommit messages create an out-of-block state root split and slash innocent validators | open - live verification pending | `blg_failed_bls_signed` | WP-17 |
| BLG-043 | critical | storage | Bridge unlock loses 100 percent of the funds and does not refund the opener bond or the reallocation fee | open - live verification pending | `blg_bridge_unlock_loses` | WP-44 |
| BLG-044 | medium | consensus | import_qc_blob majority is unweighted, ProofTrieCache goes stale at equal height, and reorg and bootstrap persistence is lost | open - live verification pending | `blg_import_blob_majority` | WP-17 |
| BLG-045 | critical | storage | StorageRegistry::open_challenge is permanently immune for one atom and the challenge proof is not verified | open - live verification pending | `blg_storageregistry_open_challenge` | WP-07 |
| BLG-046 | critical | storage | open_deal bypasses source and dictionary validation and prune_content locks bonds and escrow permanently | open - live verification pending | `blg_open_deal_bypasses` | WP-07 |
| BLG-047 | high | consensus | StorageRegistry::root() commitment is missing and unframed, and cooldown, shard ceiling, replica uniqueness and yield rules are not enforced | open - live verification pending | `blg_storageregistry_root_commitment` | WP-07 |
| BLG-048 | high | unclassified | storage::render breaks RGB and greyscale geometry, the commitment path calls f64::sqrt and VideoRecipe does not reproduce | open - live verification pending | `blg_storage_render_breaks` | WP-19 |
| BLG-049 | medium | security | erasure::reconstruct_object mishandles multiple corrupt shares, ViewGrant collides at epoch 0 and OneShare quota is wrong | open - live verification pending | `blg_erasure_reconstruct_object` | WP-22 |
| BLG-050 | critical | state root | IdentityTx::Recover bypasses the PoA gate and cannot express key loss; a third party can overwrite credential_root and the identity registry root is missing | open - live verification pending | `blg_identitytx_recover_bypasses` | WP-44 |
| BLG-051 | high | build and CI | check_receipt accepts an empty or foreign credential and identity::merkle_root allows single-leaf duplication forgery | open - live verification pending | `blg_check_receipt_accepts` | WP-44 |
| BLG-052 | medium | consensus | PoAOnboarding admin field and KYC refresh are inconsistent and PoaComplianceRegistry is not deterministic | open - live verification pending | `blg_poaonboarding_admin_field` | WP-44 |
| BLG-053 | high | settlement | ProofMarketState allows completed-job replay, evicts unpaid receipts, and its root is unframed | open - live verification pending | `blg_proofmarketstate_allows_completed` | WP-44 |
| BLG-054 | critical | consensus | The Ethereum receiptsRoot MPT verifier hashes keys with Keccak-256 and accepts non-canonical HP and envelope encodings | open - live verification pending | `blg_ethereum_receiptsroot_mpt` | WP-44 |
| BLG-055 | critical | cryptography | BLS key substitution in EthereumSyncAdapter and PairingBls plus a fixed signing root let one random signature pass | open - live verification pending | `blg_bls_key_substitution` | WP-44 |
| BLG-056 | high | consensus | serves() and require_slashable rules are not enforced in ExternalDomainRegistry and IntakeState, and bindings are missing | open - live verification pending | `blg_serves_require_slashable` | WP-44 |
| BLG-057 | high | consensus | BridgeState lock, mint and unlock lifecycle has expiry, replay-protection and fee-overflow holes | open - live verification pending | `blg_bridgestate_lock_mint` | WP-44 |
| BLG-058 | high | consensus | The ConsensusDomainRegistry leaf digest omits the zk program allowlist and plugin code hash, and DomainForkChoice is unsound | open - live verification pending | `blg_consensusdomainregistry_leaf_digest` | WP-44 |
| BLG-059 | critical | cryptography | AiExecutionProof STARK verification does not bind input, output or weights, and host and guest arithmetic diverge | open - live verification pending | `blg_aiexecutionproof_stark_verification` | WP-45 |
| BLG-060 | critical | consensus | AiAttachExecutionProof deferred finalisation loses the escrowed fee permanently and AiFeeReclaim lacks an authority check | open - live verification pending | `blg_aiattachexecutionproof_deferred_finalisation` | WP-45 |
| BLG-061 | high | authorisation | Ghost verifier stakes keep authority after AiOperatorUnbond and Withdraw, and the per-operator EffortTier ceiling is bypassable | open - live verification pending | `blg_ghost_verifier_stakes` | WP-45 |
| BLG-062 | high | consensus | AiRegistry::state_root and its leaf digests omit execution_dims, modalities and weights_digest, and arithmetic is unchecked | open - live verification pending | `blg_airegistry_state_root` | WP-45 |
| BLG-063 | critical | consensus | Unbacked and unauthorised L1 private note mint and spend on the testnet chain id, with an inconsistent nullifier digest | open - live verification pending | `blg_unbacked_unauthorised_private` | WP-45 |
| BLG-064 | high | cryptography | The Pollen ProtectedContent paywall bridge is not wired into production, and Signature64 is incompatible with V5 quantum addresses | open - live verification pending | `blg_pollen_protectedcontent_paywall` | WP-23 |
| BLG-065 | high | consensus | NftTag silently burns the fee, NftBurn leaves a ghost Vault folder, and the BNS registry lifecycle is defective | open - live verification pending | `blg_nfttag_silently_burns` | WP-17 |
| BLG-066 | high | operations | budlum-core stores B.U.D. content in volatile RAM, PoA and BFT bootstrap state drifts, and CLI to TOML precedence is inverted | open - live verification pending | `blg_budlum_core_stores` | WP-17 |
| BLG-067 | high | build and CI | bud-compiler and bud-cli entrypoint argument ABI collapses with StackUnderflow, match integers are truncated | open - live verification pending | `blg_bud_compiler_bud` | WP-33 |
| BLG-068 | high | explorer | budscan gives a Verified badge to an unverified storage_root fallback and bud:// ContentId lookup is unbounded | open - live verification pending | `blg_budscan_gives_verified` | WP-40 |
| BLG-069 | medium | bridge and domains | The budzero verifier registry state root omits parameters and history, and Liveness expects zero | open - live verification pending | `blg_budzero_verifier_registry` | WP-33 |
| BLG-070 | high | privacy | ai-knowledge secret redaction skips JSON keys, leaks multi-field lines and mishandles the LLM path | open - live verification pending | `blg_knowledge_secret_redaction` | WP-45 |
| BLG-071 | high | cryptography | ai-core, ai-data and ai-serve carry a non-cryptographic LoRaManifest digest and an inconsistent B.U.D. binding | open - live verification pending | `blg_core_data_serve` | WP-45 |
| BLG-072 | medium | unclassified | ai-knowledge::embed splits Turkish characters wrongly, and PromptWallet and EvalGate accept NaN and negative floats | open - live verification pending | `blg_knowledge_embed_splits` | WP-45 |
| BLG-073 | critical | lossless codecs | The .bud v1 pq_public_key is lost on serialisation, HuffmanCoder overflows a 32-bit code length, and BudV2File mishandles multi-part bodies | open - live verification pending | `blg_bud_public_key` | WP-07 |
| BLG-074 | high | consensus | bud consensus, DAS Merkle and erasure-coding defects: single-leaf second-preimage forgery and a broken Cauchy MDS matrix | open - live verification pending | `blg_bud_consensus_das` | WP-07 |
| BLG-075 | high | lossless codecs | Lossless roundtrip failures: columnar sort panics without a transition, office rejects DEFLATE, and double bodies inflate | open - live verification pending | `blg_lossless_roundtrip_failures` | WP-07 |
| BLG-076 | medium | gates | bud economics, fidelity gate and fixed-point bounds are fail-open: holds_honest and classify_lossy accept what they must refuse | open - live verification pending | `blg_bud_economics_fidelity` | WP-07 |
| BLG-077 | critical | cryptography | pq_pub_hash binding is skipped in quantum_chain and bud_format_shamir, the DualWallet address derives from the private seed, and ShamirShare::combine bypasses the threshold at x = 0 | open - live verification pending | `blg_pub_hash_binding` | WP-07 |
| BLG-078 | high | unclassified | BudCli::decode_container corrupts compressed parts, videopipe proves production with reversed arguments, and TimeSeries is unsound | open - live verification pending | `blg_budcli_decode_container` | WP-07 |
| BLG-079 | high | cryptography | bud privacy, secret redaction and secure deduplication defects: SecretRedactor leaks symbol-split passwords | open - live verification pending | `blg_bud_privacy_secret` | WP-07 |
| BLG-080 | medium | optical storage | bud indexing, QR derivative and cost-model errors: pgm::search_range misses offsets and ux confuses GiB units | open - live verification pending | `blg_bud_indexing_derivative` | WP-07 |
| BLG-081 | high | build and CI | The xtask/gates security gates have workspace and first-party crate blind spots, including a nonexistent wallet-core root | open - live verification pending | `blg_xtask_gates_security` | WP-42 |
| BLG-082 | high | security | ast_security_gates skips while and for decoys, gates_do_not_panic panics on UTF-8 slicing, and guards are unchecked | open - live verification pending | `blg_ast_security_gates` | WP-42 |
| BLG-083 | medium | gates | Supply counting, rate consensus, metrics, indexing, badge and actionlint gates all under-verify | open - live verification pending | `blg_supply_counting_rate` | WP-42 |
| BLG-084 | high | build and CI | The relay gate returns Ok on an invalid signature or digest mismatch, and the regeneration gate is fail-open | open - live verification pending | `blg_relay_gate_returns` | WP-42 |
| BLG-085 | high | build and CI | Seven more xtask/gates gates use a nonexistent wallet-core root, and standalone workspaces lack release profiles | open - live verification pending | `blg_seven_more_xtask` | WP-42 |
| BLG-086 | medium | gates | no_upstream_brands has a UTF-8 panic, CWE-377 predictable /tmp directories, and named_tests matches the substring ok | open - live verification pending | `blg_upstream_brands_utf` | WP-42 |
| BLG-087 | high | fuzz and formal | Fuzz, Kani and benchmark runs under-verify: unbounded bincode::deserialize OOM targets and unrun proofs | open - live verification pending | `blg_fuzz_kani_benchmark` | WP-42 |
| BLG-088 | medium | test quality | Integration tests carry fake or empty security assertions, and the audit step skips 8 of 11 Cargo.lock files | open - live verification pending | `blg_integration_tests_carry` | WP-17 |
| BLG-089 | high | consensus | The coding audit answer binds no column, so an operator answers for the column it chooses | open - live verification pending | `blg_coding_audit_answer` | WP-17 |
| BLG-090 | medium | build and CI | settlement_prod.rs (2208 lines, 52 compile errors) and domain_throughput.rs (60 errors) are compiled out with cfg(false) | open - live verification pending | `blg_settlement_prod_2208` | WP-17 |
| BLG-091 | critical | cryptography | The external-chain finality verifier contract accepts the zero BLS infinity point and a cofactor-unsafe pairing | open - live verification pending | `blg_external_chain_finality` | WP-44 |
| BLG-092 | high | documentation | The K15 public framing rule is violated across README, CONTRIBUTING, SECURITY and NOTICE | closed - previously fixed | `audit_lane_d_locks::blg_092_the_readme_states_no_mainnet_and_no_audit` | WP-43 |
| BLG-093 | high | build and CI | crates/ai-inference/LICENSE.md carries an unrestricted MIT licence against the root PolyForm Shield and its own manifest | open - live verification pending | `blg_crates_inference_license` | WP-45 |
| BLG-094 | high | build and CI | config/archive.toml carries the wrong chain_id 42 and the lock test skips that profile; ops compose is inconsistent | open - live verification pending | `blg_config_archive_toml` | WP-16 |
| BLG-095 | medium | build and CI | Supply-chain scripts and Dependabot skip most of the 11 lockfiles and .cargo/audit.toml holds stale exceptions | open - live verification pending | `blg_supply_chain_scripts` | WP-41 |
| BLG-096 | high | consensus | invalidate_finality_from_height misses the checkpoint grid and leaves orphan certificates on disk | open - live verification pending | `blg_invalidate_finality_height` | WP-12 |
| BLG-097 | high | build and CI | The kani and bud/fuzz workspaces lack a Cargo.lock so --locked fails, and kani/src/lib.rs has an unexpected attribute | open - live verification pending | `blg_kani_bud_fuzz` | WP-42 |
| BLG-098 | critical | security | NodeConfig's arg(skip) derive zeroes the RPC authentication and IP allowlist defaults | open - live verification pending | `blg_nodeconfig_arg_skip` | WP-39 |
| BLG-099 | high | security | constant_time_eq_str self-compares on a length mismatch, so opt-level 3 folds it into a constant true | closed - previously fixed | `blg_constant_time_str` | WP-61 |
| BLG-100 | critical | consensus | validate_transaction demands a liquid balance of amount plus fee for Unstake, so a validator cannot unbond its own stake | open - live verification pending | `blg_validate_transaction_demands` | WP-17 |
| BLG-101 | critical | consensus | StateSnapshotV2 restore and calculate_state_root have integrity defects, including a permitted PoA chain lock | open - live verification pending | `blg_statesnapshotv2_restore_calculate` | WP-17 |
| BLG-102 | critical | consensus | try_reorg and validate_candidate_chain have branch-switch defects: sled leaks the old branch's bridge state into state_root | open - live verification pending | `blg_try_reorg_validate` | WP-17 |
| BLG-103 | critical | build and CI | On-chain governance can be captured and locked for 115 days: a slashed validator keeps its voting weight | open - live verification pending | `blg_chain_governance_can` | WP-17 |
| BLG-104 | critical | mempool and state | Mempool admits free transactions, evicts by parent-nonce and RBF zombies, and starves blocks on stale sled reads | open - live verification pending | `blg_mempool_admits_free` | WP-17 |
| BLG-105 | critical | consensus | burn_bridge_transfer_with_event does not lower the balance, mints 2x BUD, and breaks bridge vesting locks | open - live verification pending | `blg_burn_bridge_transfer` | WP-44 |
| BLG-106 | critical | consensus | Unbounded AiModelSpec.execution_dims lets one transaction demand 532.56 GiB of layers | open - live verification pending | `blg_unbounded_aimodelspec_execution` | WP-45 |
| BLG-107 | critical | consensus | NftBoost and distribute_bud_boost_share_in_state make produce_block return None permanently | open - live verification pending | `blg_nftboost_distribute_bud` | WP-17 |
| BLG-108 | critical | network | Unvalidated gossipsub forwarding lets an attacker ban honest validators, and RBF races corrupt the pool | open - live verification pending | `blg_unvalidated_gossipsub_forwarding` | WP-15 |
| BLG-109 | critical | storage | NftMint and NftBurn have no ownership check, so a third party can destroy another owner's B.U.D. manifest | open - live verification pending | `blg_nftmint_nftburn_ownership` | WP-23 |
| BLG-110 | critical | consensus | BnsRegistry::default() carries base_cost 0, splits the state root, and misreads current_epoch plus duration | open - live verification pending | `blg_bnsregistry_default_carries` | WP-23 |
| BLG-111 | high | cryptography | budlum-bpqs verification diverges between debug and release: verify_at_height panics in debug only | open - live verification pending | `blg_budlum_bpqs_verification` | WP-45 |
| BLG-112 | critical | AI | The AI inference layer allows deterministic AiModelId hijacking and an unbound declare_execution | open - live verification pending | `blg_inference_layer_allows` | WP-45 |
| BLG-113 | critical | storage | Sled recover_interrupted_commit rolls back partially and corrupts account and global-header keys | open - live verification pending | `blg_sled_recover_interrupted` | WP-17 |
| BLG-114 | critical | build and CI | budzero/bud-compiler miscompiles silently, starting with MatchPattern integer arms | open - live verification pending | `blg_budzero_bud_compiler` | WP-33 |
| BLG-115 | critical | cryptography | budzero dynamic storage collides at 2^32 slots and accepts a negative program counter | open - live verification pending | `blg_budzero_dynamic_storage` | WP-33 |
| BLG-116 | critical | RPC | AdapterSpec::ZkVm (Trustless) accepts an empty Halt STARK proof for an arbitrary external state root | open - live verification pending | `blg_adapterspec_zkvm_trustless` | WP-44 |
| BLG-117 | critical | cryptography | budlum-wallet-core has a four-round Poseidon shift and truncates the i32 recipient tag | open - live verification pending | `blg_budlum_wallet_core` | WP-39 |
| BLG-118 | critical | consensus | Uncommitted block and transaction witness flexibility lets two bodies share one block hash | open - live verification pending | `blg_uncommitted_block_transaction` | WP-17 |
| BLG-119 | critical | slashing | Unstake escapes validator and cross-role slashing entirely, and Stake takes effect after one atom | open - live verification pending | `blg_unstake_escapes_validator` | WP-17 |
| BLG-120 | high | post-quantum crypto | ColdWalletState trusts request.epoch to overrun the epoch budget and refuses with zero signatures | open - live verification pending | `blg_coldwalletstate_trusts_request` | WP-44 |
| BLG-121 | high | build and CI | budscan ENS arweave-ns confuses a 32-byte tx id with a 48-byte data root and refuses every verification | open - live verification pending | `blg_budscan_ens_arweave` | WP-40 |
| BLG-122 | high | consensus | The bud BFT ratio vote does not bind content_id or chain_id and certifies a NaN ratio | open - live verification pending | `blg_bud_bft_ratio` | WP-07 |
| BLG-123 | medium | storage | store_json_columnar corrupts container reload and ModelFloatSplit is endianness-dependent | open - live verification pending | `blg_store_json_columnar` | WP-07 |
| BLG-124 | high | AI | ai-inference promotes an unidentified WebSocket to Authenticated, corrupts symbols and overflows u32 | open - live verification pending | `blg_inference_promotes_unidentified` | WP-45 |
| BLG-125 | critical | consensus | Out-of-block storage and confidential-body RPC mutations split the state root at zero cost | open - live verification pending | `blg_out_block_storage` | WP-17 |
| BLG-126 | critical | AI | The Pollen AccessGrant paywall is bypassable in both directions on AiInferenceRequest | open - live verification pending | `blg_pollen_accessgrant_paywall` | WP-45 |
| BLG-127 | critical | consensus | One captured device key defeats the 3-of-6 ColdWallet and PqAnchor quorum | open - live verification pending | `blg_captured_device_key` | WP-44 |
| BLG-128 | high | storage | MerkleTrie account proofs are not anchored to a block header and ProofTrieCache goes stale after a reorg | open - live verification pending | `blg_merkletrie_account_proofs` | WP-17 |
| BLG-129 | high | network | The D-Web PassportProofBundle leaves profile fields outside the commitment and silently truncates at 64 records | open - live verification pending | `blg_web_passportproofbundle_leaves` | WP-23 |
| BLG-130 | critical | consensus | lead_is_unassailable in the external quorum paths lets one participant decide finality alone | open - live verification pending | `blg_lead_unassailable_external` | WP-44 |
| BLG-131 | high | network | RegenerationLedger and regen_health::assess accept a recovery that did not happen | open - live verification pending | `blg_regenerationledger_regen_health` | WP-44 |
| BLG-132 | high | consensus | PoWEngine skips block indices and its can_reorg and select_best rules are unsound | open - live verification pending | `blg_powengine_skips_block` | WP-12 |
| BLG-133 | medium | storage | DictionaryRegistry, DerivedSpec, MasterRegistry and MobileSelfProfile custody dictionaries are unbound | open - live verification pending | `blg_dictionaryregistry_derivedspec_masterregistry` | WP-24 |
| BLG-134 | critical | storage coding | The EVM path accepts non-canonical RLP 0x81 and ReplayNonceStore is defeated by a single message | open - live verification pending | `blg_evm_path_accepts` | WP-44 |
| BLG-135 | high | storage | The consensus storage demand signal half-lives without a floor and misprices the deal | open - live verification pending | `blg_consensus_storage_demand` | WP-24 |
| BLG-136 | high | build and CI | The budzero/bud-compiler parser rejects a valid single-call statement | open - live verification pending | `blg_budzero_bud_compiler` | WP-33 |
| BLG-137 | high | storage | The B.U.D. 3.0 optical and QR video pipe validates streams with 32-bit arithmetic | open - live verification pending | `blg_optical_video_pipe` | WP-19 |
| BLG-138 | critical | build and CI | BridgeRelayerPipeline mints and unlocks without a proof and poisons state on a failed lock | open - live verification pending | `blg_bridgerelayerpipeline_mints_unlocks` | WP-44 |
| BLG-139 | critical | network | budzero/bud-state NoteRegistry leaks the plaintext nullifier and accepts a forged one | open - live verification pending | `blg_budzero_bud_state` | WP-33 |
| BLG-140 | high | storage | InMemoryStorageProvider accepts unverified proof bytes and a zero-knowledge out-of-range agreement | open - live verification pending | `blg_inmemorystorageprovider_accepts_unverified` | WP-16 |
| BLG-141 | medium | storage | The bud low-rank matrix encoder deflates without a guard and loses data | open - live verification pending | `blg_bud_low_rank` | WP-07 |
| BLG-142 | critical | network | The bud_stark verifier can be crashed remotely through Goldilocks two-adicity on degree | open - live verification pending | `blg_bud_stark_verifier` | WP-33 |
| BLG-143 | high | explorer | The budscan explorer core accepts a real ContentManifest identity it never verifies | open - live verification pending | `blg_budscan_explorer_core` | WP-40 |
| BLG-144 | high | storage | SingleScreenView overruns the cumulative device quota and omits contract_digest | open - live verification pending | `blg_singlescreenview_overruns_cumulative` | WP-19 |
| BLG-145 | medium | storage | CropDerivation claims aligned = true on an unaligned crop and accepts 0x0 | open - live verification pending | `blg_cropderivation_claims_aligned` | WP-45 |
| BLG-146 | critical | post-quantum crypto | build_bud_to_eth_claim does not bind the recipient and accepts the zero address and an empty burn proof | open - live verification pending | `blg_build_bud_eth` | WP-44 |
| BLG-147 | high | unclassified | core::map_keys accepts duplicate and unordered keys when deserialising from bincode and postcard | open - live verification pending | `blg_core_map_keys` | WP-17 |
| BLG-148 | high | storage | The StorageLifecycleState machine treats one missed challenge and a second one the same | open - live verification pending | `blg_storagelifecyclestate_machine_treats` | WP-33, WP-07 |
| BLG-149 | medium | storage | PowChallenge is bypassable with a digest-only ownership proof and BloomDedupIndex is unsound | open - live verification pending | `blg_powchallenge_bypassable_digest` | WP-45 |
| BLG-150 | critical | consensus | ConsensusSigner has no domain separation: sign_prevote, sign_precommit and sign_block are the same call | closed - previously fixed | `audit_lane_d_locks::blg_150_prevote_precommit_and_block_signatures_are_not_interchangeable` | WP-61 |
| BLG-151 | high | storage coding | The NUL-separated wire framing in core::encoding collides on unparsable input and drops fields | open - live verification pending | `blg_nul_separated_wire` | WP-17 |
| BLG-152 | medium | storage | FidelityCore::render returns full-size raw bytes on the thumbnail path and accepts 0x0 | open - live verification pending | `blg_fidelitycore_render_returns` | WP-07 |
| BLG-153 | medium | storage | OpticalGates::k_bud_optical compares itself to itself, and LogTemplateMiner is unbounded | open - live verification pending | `blg_opticalgates_bud_optical` | WP-07 |
| BLG-154 | critical | network | The bud_stark verifier accepts a PCS-bypassing aux_trace_next witness and can be crashed remotely | open - live verification pending | `blg_bud_stark_verifier` | WP-33 |
| BLG-155 | high | unclassified | GlobalBlockHeader claims bincode backwards compatibility it does not have and leaves the proposer field unsigned | open - live verification pending | `blg_globalblockheader_claims_bincode` | WP-44 |
| BLG-156 | medium | storage | QuantumSuite::is_quantum_resistant is bypassable by substring and accepts kem: None | open - live verification pending | `blg_quantumsuite_quantum_resistant` | WP-07 |
| BLG-157 | medium | storage | dbd_digest collides across a page boundary and BashTranspile is not deterministic | open - live verification pending | `blg_dbd_digest_collides` | WP-45 |
| BLG-158 | high | consensus | The equal-weight fork resolver accepts an empty chain and a fake-height chain | open - live verification pending | `blg_equal_weight_fork` | WP-12 |
| BLG-159 | high | unclassified | The bud_stark setup_preprocessed step panics on a bit shift and on height | open - live verification pending | `blg_bud_stark_setup` | WP-33 |
| BLG-160 | medium | AI | The L1 AiDatasetStorageDeal has no closed-loop verification, and ai-core accepts zero targets | open - live verification pending | `blg_aidatasetstoragedeal_closed_loop` | WP-45 |
| BLG-161 | medium | storage | The .bud bit-rot scanner misses 100 percent of field-tag mismatches | open - live verification pending | `blg_bud_bit_rot` | WP-21 |
| BLG-162 | high | storage | The BudL lexer refuses 100 percent of CRLF sources and mishandles multi-star comments | open - live verification pending | `blg_budl_lexer_refuses` | WP-33 |
| BLG-163 | high | storage | The B.U.D. 3.0 optical QR layer overflows u32 multiplication in qr_matrix, qr_png and qr_encode | open - live verification pending | `blg_optical_layer_overflows` | WP-19 |
| BLG-164 | high | cryptography | budlum-bpqs epoch_of truncates to u32, so signatures repeat after 2^32 epochs | open - live verification pending | `blg_budlum_bpqs_epoch` | WP-45 |
| BLG-165 | medium | AI | The offline AI localisation layer mishandles BCP-47 and schema URIs | open - live verification pending | `blg_offline_localisation_layer` | WP-45 |
| BLG-166 | critical | consensus | Rotating one MIN_VERIFIER_STAKE in AiRegistry allows a Sybil consensus takeover with slashed validators | open - live verification pending | `blg_rotating_min_verifier` | WP-45 |
| BLG-167 | high | storage | The storage LRC and MSR layers divide by zero on empty fields | open - live verification pending | `blg_storage_lrc_msr` | WP-17 |
| BLG-168 | medium | storage | refuse_durable_derivative is bypassable by a packed payload, and RevealSession is unbound | open - live verification pending | `blg_refuse_durable_derivative` | WP-21 |
| BLG-169 | medium | build and CI | BudlumToml silently swallows removed sections and budscan punycode handling is unsound | open - live verification pending | `blg_budlumtoml_silently_swallows` | WP-40 |
| BLG-170 | high | gates | The AST and source-scanning security gates are bypassable by comments and syntax shapes | open - live verification pending | `blg_ast_source_scanning` | WP-42 |
| BLG-171 | high | build and CI | The CI workflow security gates under-verify: scans cannot fail, guards are absent, pins are unchecked | open - live verification pending | `blg_workflow_security_gates` | WP-42 |
| BLG-172 | medium | build and CI | The budlum-tools developer tools accept an invalid PoA validators.json and collide on the RPC port | open - live verification pending | `blg_budlum_tools_developer` | WP-42 |
| BLG-173 | medium | fuzz and formal | The dudect_poseidon2 constant-time run is disconnected from the real budlum_bpqs code | open - live verification pending | `blg_dudect_poseidon2_constant` | WP-45 |
| BLG-174 | high | network | The ZK and AIR soundness gates under-verify: pinned accumulators, bit decompositions and LogUp multipliers | open - live verification pending | `blg_air_soundness_gates` | WP-42 |
| BLG-175 | high | build and CI | The supply-chain, Docker toolchain and domain-tag gates under-verify | open - live verification pending | `blg_supply_chain_docker` | WP-42 |
| BLG-176 | medium | benchmarks | The bench_internal_pipeline_tps benchmark binary refuses 100 percent of transactions on chain id 1337 | open - live verification pending | `blg_bench_internal_pipeline` | WP-42 |
| BLG-177 | medium | storage | The wallet_node_address_agree gate is blind to an extra digest input, and admit_device_as_self is unchecked | open - live verification pending | `blg_wallet_node_address` | WP-42 |
| BLG-178 | high | network | zero_tests_witness is bypassable by a zero-constraint AIR, and gas_calibration is comment-shadowed | open - live verification pending | `blg_zero_tests_witness` | WP-42 |
| BLG-179 | high | state snapshot | serialize_map_keys_are_strings is blind to enums and tuple structs, and genesis_schema under-checks | open - live verification pending | `blg_serialize_map_keys` | WP-42 |
| BLG-180 | medium | storage | The content_encryption, coding_audit, ai_inference_prompt_is_true and no_idle_code gates under-verify | open - live verification pending | `blg_content_encryption_coding` | WP-42 |
| BLG-181 | medium | build and CI | The evm_mpt_verify fuzz target is blind to a fixed 128-byte split, and module_coverage miscounts | open - live verification pending | `blg_evm_mpt_verify` | WP-42 |
| BLG-182 | critical | ZK and STARK | Plonky3Adapter and BudAir leave public inputs unbound: final_state_root and exit_code among them | open - live verification pending | `blg_plonky3adapter_budair_leave` | WP-33 |
| BLG-183 | critical | storage | Storage bond slashing double-charges 2x, escrow and supply drift, and the challenge path is wrong | open - live verification pending | `blg_storage_bond_slashing` | WP-17 |
| BLG-184 | critical | mempool and state | collect_block_transactions does not count failed transactions against block gas and admits zero-cost work | open - live verification pending | `blg_collect_block_transactions` | WP-17 |
| BLG-185 | medium | post-quantum crypto | The bpqs wire-size cost model is inconsistent, the loom lock-order canary is absent, and contracts diverge | open - live verification pending | `blg_bpqs_wire_size` | WP-45 |
| BLG-186 | critical | build and CI | The canonical system-call context binds sender, nonce and block_height, and gas_used, wrongly | open - live verification pending | `blg_canonical_system_call` | WP-33 |
| BLG-187 | high | fuzz and formal | The consensus_state_transition, relayer_escrow, vm_execute, bpqs_wots_reject and snapshot gates under-verify | open - live verification pending | `blg_consensus_state_transition` | WP-42 |
| BLG-188 | high | storage | The uncheckable_proof gate inverts its verdict at runtime, and mempool_mev_free is unenforced | open - live verification pending | `blg_uncheckable_proof_gate` | WP-42 |
| BLG-189 | medium | storage | The storage_priced, storage_penalties, threshold_rates, value_transfers and shard_placement gates under-verify | open - live verification pending | `blg_storage_priced_storage` | WP-42 |
| BLG-190 | critical | consensus | The did:bud main IdentityRegistry lets IdentityTx::Recover bypass the PoA domain gate and accept a forged credential root | open - live verification pending | `blg_did_bud_main` | WP-44 |
| BLG-191 | critical | network | The synthetic Halt row in Vm::run_receipt breaks the Plonky3Adapter program CTL | open - live verification pending | `blg_synthetic_halt_row` | WP-33 |
| BLG-192 | high | RPC | bud_estimateGas does not include the proportional transfer fee | open - live verification pending | `blg_bud_estimategas_does` | WP-61 |
| BLG-193 | medium | build and CI | The remaining xtask/gates verification modules are bypassable by comments, syntax and fake test output | open - live verification pending | `blg_remaining_xtask_gates` | WP-42 |
| BLG-194 | critical | bridge and domains | Blockchain::submit_relay_proof deletes the relay non-atomically and leaves the AlreadyRelayed marker | open - live verification pending | `blg_blockchain_submit_relay` | WP-44 |
| BLG-195 | critical | consensus | The PoA, BFT and PoS finality adapters accept a flexible commitment body | open - live verification pending | `blg_poa_bft_pos` | WP-44 |
| BLG-196 | high | state root | The incremental Merkle cache on the public accounts map diverges from the state root | open - live verification pending | `blg_incremental_merkle_cache` | WP-17 |
| BLG-197 | critical | execution | Executor::apply_transaction_checked and apply_block_checked mishandle tx.total_cost() | open - live verification pending | `blg_executor_apply_transaction` | WP-17 |
| BLG-198 | critical | build and CI | budl_compile spends 64 MiB on a depth-unbounded iterative binary and suffix AST chain | open - live verification pending | `blg_budl_compile_spends` | WP-33 |
| BLG-199 | high | cryptography | settlement, consensus and pq Merkle roots are computed by three different rules | open - live verification pending | `blg_settlement_consensus_merkle` | WP-44 |
| BLG-200 | high | consensus | BlsKeypair accepts a zero secret key and the unit point, FinalityAggregator is identity-signature poisonable, and a test is falsely green | open - live verification pending | `blg_blskeypair_accepts_zero` | WP-61 |
| BLG-201 | high | ZK and STARK | AiAttachExecutionProof has no size gate after STARK verification and accepts a 40 MiB zero-weight model | open - live verification pending | `blg_aiattachexecutionproof_size_gate` | WP-45 |
| BLG-202 | critical | node runtime | The production startup layer deletes a fresh backup when retention_count is zero under --migrate | open - live verification pending | `blg_production_startup_layer` | WP-17 |
| BLG-203 | critical | consensus | QcFaultProof::verify_inclusion accepts an out-of-range leaf index and a one-byte sibling | open - live verification pending | `blg_qcfaultproof_verify_inclusion` | WP-12 |
| BLG-204 | high | proof market | ProofMarketState records a u64::MAX reward with no escrow and marks Paid before the overflow | open - live verification pending | `blg_proofmarketstate_records_u64` | WP-44 |
| BLG-205 | critical | consensus | ExternalDomainRegistry readmit bypasses validation with zero probes and a mismatched version | open - live verification pending | `blg_externaldomainregistry_readmit_bypasses` | WP-44, WP-15 |
| BLG-206 | critical | consensus | The PoAEngine operator-local validators file splits leadership, and validate_block accepts extra validators | open - live verification pending | `blg_poaengine_operator_local` | WP-12 |
| BLG-207 | critical | slashing | PoSEngine::verify_evidence slashes honest validators on a cross-chain testnet-to-mainnet proof | open - live verification pending | `blg_posengine_verify_evidence` | WP-12 |
| BLG-208 | high | unclassified | BudStorageEdition::Three admits only generative recipes, so original content cannot enter 3.0 | open - live verification pending | `blg_budstorageedition_three_admits` | WP-07, WP-21 |
| BLG-209 | high | unclassified | The bytes held and the rent for Three both return zero, against the document's own claim | open - live verification pending | `blg_bytes_held_rent` | WP-07, WP-25 |
| BLG-210 | high | build and CI | VideoRecipe carries the content in content_bytes, and reemit and frame_stream ask for an external body | open - live verification pending | `blg_videorecipe_carries_content` | WP-19 |
| BLG-211 | medium | optical storage | Three separate recipe models exist while the header claims it produces without holding the body | open - live verification pending | `blg_three_separate_recipe` | WP-19 |
| BLG-212 | critical | storage | The preview endpoints ask for the content as data_hex on every call, the view session opens with the caller's packet, and the NFT registry is an in-memory map | open - live verification pending | `blg_preview_endpoints_ask` | WP-21, WP-23 |
| BLG-213 | high | optical storage | The ceilings (1 MiB preview, 64 MiB packet, k <= 4096, 50000 frames) truncate u32 lengths silently above 4 GiB | open - live verification pending | `blg_ceilings_mib_preview` | WP-18 |
| BLG-214 | medium | optical storage | The video id is the digest of a blob holding PNG bytes, and deflate output is not stable across versions | open - live verification pending | `blg_video_digest_blob` | WP-19 |
| BLG-215 | high | unclassified | There is no object extraction from video and no two-path or roundtrip gate | open - live verification pending | `blg_there_object_extraction` | WP-19 |
| BLG-216 | high | optical storage | Low-degree random XOR repair does not cover losses in a large segment | open - live verification pending | `blg_low_degree_random` | WP-18 |
| BLG-217 | medium | storage | A second 3.0 implementation exists under bud/src with a no-storage-concept and STORAGE-ZERO claim | open - live verification pending | `blg_second_implementation_exists` | WP-07 |
| BLG-218 | low | unclassified | A test name claims a fixed-size recipe that the code does not implement | open - live verification pending | `blg_test_name_claims` | WP-19 |
| BLG-219 | medium | unclassified | A0 applies zlib only when it shrinks, so the codec choice is not declared | open - live verification pending | `blg_applies_zlib_only` | WP-24 |
| BLG-220 | critical | documentation | The 3.0 object has no redundancy at all: a single copy is lost at the first disk failure | open - live verification pending | `blg_object_redundancy_single` | WP-20 |
| BLG-221 | medium | unclassified | There is no deduplication and no reference counter | open - live verification pending | `blg_there_deduplication_reference` | WP-22 |
| BLG-222 | medium | unclassified | dictionary, living_threshold and derived are bound to the production path, not to the 3.0 object | open - live verification pending | `blg_dictionary_living_threshold` | WP-24 |
| BLG-223 | high | storage | Pcs::ZK is false, so proofs do not hide the witness and privacy opcodes can leak it | open - live verification pending | `blg_pcs_false_proofs` | WP-56 (testnet closure: WP-33 and WP-45) |
| BLG-224 | high | storage | The note commitment and the nullifier are 64-bit; a general collision needs about 2^32 transactions | open - live verification pending | `blg_note_commitment_nullifier` | WP-56 (testnet closure: WP-45) |
| BLG-225 | high | unclassified | Private transfer binds no ownership, conservation or membership proof, and spent commitments are written in the clear | open - live verification pending | `blg_private_transfer_binds` | WP-45, WP-56 |
| BLG-226 | high | storage | The VerifyMerkle node hash is a single round and carries no capacity | open - live verification pending | `blg_verifymerkle_node_hash` | WP-56 (testnet closure: WP-33) |
| BLG-227 | medium | storage | VerifyInference checks one digest equality, so its name over-promises | open - live verification pending | `blg_verifyinference_checks_digest` | WP-57 (testnet closure: WP-33) |
| BLG-228 | high | AI | Full AI STARK verification is off, the initial-memory folding is collision-prone, and the output commitment is not bound to the proof | open - live verification pending | `blg_full_stark_verification` | WP-57 (testnet closure: WP-45) |
| BLG-229 | high | AI | There is no per-request draw, no commit-reveal and no deterministic inference profile | open - live verification pending | `blg_there_per_request` | WP-45 (the VL-1 leg), WP-57 |
| BLG-230 | medium | storage | sender is 64-bit in the VM context while a Budlum address is 256-bit | open - live verification pending | `blg_sender_bit_context` | WP-33 (the execution leg), WP-56 |
| BLG-231 | medium | storage | The document claims recursive aggregation and the code has no recursion | open - live verification pending | `blg_document_claims_recursive` | WP-43 |
| BLG-232 | medium | storage | One AIR of 1073 columns makes a simple program pay for the widest opcode | open - live verification pending | `blg_air_1073_columns` | WP-56 |
| BLG-233 | medium | storage | MMCS and the challenger are Keccak-256 and there is no recursion | open - live verification pending | `blg_mmcs_challenger_keccak` | WP-60 |
| BLG-234 | medium | storage | Only the BudL ISA exists, so adapters written in Rust cannot be proven | open - live verification pending | `blg_only_budl_isa` | WP-60 |
| BLG-235 | high | ZK and STARK | Only the ZK domain uses a BudZero proof, the Ethereum sync committee module is unwired and counts two-thirds participation as final, and there is no finality branch | open - live verification pending | `blg_only_domain_uses` | WP-44, WP-60 |
| BLG-236 | medium | storage | No commitment is bound to the plaintext, so no property of sealed content is provable | open - live verification pending | `blg_commitment_bound_plaintext` | WP-56 |
| BLG-237 | high | unclassified | The view grant is a plaintext on-chain row of content id, issuer and grantee, so the social graph leaks | open - live verification pending | `blg_view_grant_plaintext` | WP-22 (private consent: WP-56) |
| BLG-238 | medium | unclassified | The HPKE key package is not bound into the production path | open - live verification pending | `blg_hpke_key_package` | WP-22 |
| BLG-239 | medium | storage | The signature-aggregation proof expressions do not bind inside the AIR | open - live verification pending | `blg_signature_aggregation_proof` | WP-60 |
| BLG-240 | low | AI | Validator ordering uses f64, on the RPC path only | open - live verification pending | `blg_validator_ordering_uses` | WP-45, WP-57 |
| BLG-241 | low | storage | The comment says Poseidon width 8 and the code uses 12 | open - live verification pending | `blg_comment_says_poseidon` | WP-43 |
| BLG-242 | medium | unclassified | Commitments do not carry a hash-suite identity | open - live verification pending | `blg_commitments_carry_hash` | WP-56 |
| BLG-243 | medium | storage | Event accumulation is bound with 32-bit sums and the Log output is not binding | open - live verification pending | `blg_event_accumulation_bound` | WP-56 |
| BLG-244 | low | build and CI | Quotes are bound to a byte digest and an answer is not bound to a BudZero proof | open - live verification pending | `blg_quotes_bound_byte` | WP-57 (a separate repository work item) |
| BLG-245 | medium | economics | The sealed object's full size is visible and the read fee binds the reader to the content | open - live verification pending | `blg_sealed_object_full` | WP-22 (Padme), WP-56 |
| BLG-246 | critical | AI | Finality requires a count quorum over the whole validator set as well as a stake quorum, so liveness is tied to phones | open - live verification pending | `blg_finality_requires_count` | WP-12 |
| BLG-247 | high | network | There is no NAT traversal: relay, dcutr and autonat are not features and the testnet profile disables the circuit relay | open - live verification pending | `blg_there_nat_traversal` | WP-15 |
| BLG-248 | high | ZK and STARK | There is no general-purpose stateful contract; ContractCall runs in-transaction bytecode statelessly in 8 KiB | open - live verification pending | `blg_there_general_purpose` | WP-26, WP-33 |
| BLG-249 | high | RPC | There is no ecosystem-compatible RPC: all 180 methods are bud_-prefixed, so no external tool can connect | open - live verification pending | `blg_there_ecosystem_compatible` | WP-28, WP-29, WP-31, WP-32 |
| BLG-250 | critical | unclassified | The release profile aborts on panic, so one engine panic in the node process stops the chain | open - live verification pending | `blg_release_profile_aborts` | WP-26 |
| BLG-251 | high | unclassified | The liveness tracker emits slashing reports for consecutive missed epochs; there is no penalty-free suspension | open - live verification pending | `blg_liveness_tracker_emits` | WP-13 |
| BLG-252 | medium | unclassified | The storage roles sit apart from the validator, against the model that the validator is what stores content | open - live verification pending | `blg_storage_roles_sit` | WP-08 |
| BLG-253 | medium | mobile | The mobile modules implement host-your-own-content with no validator duty, and calculate_leaf hashes fields without length prefixes | open - live verification pending | `blg_mobile_modules_implement` | WP-07, WP-08 |
| BLG-254 | high | build and CI | CI gates enforce the wrong recipe-only model of 3.0, so the correct model cannot merge | open - verified | `blg_gates_enforce_wrong` | WP-07, WP-42 |
| BLG-255 | low | unclassified | Concept names are spread through the code: 15 files, 13, 24 and 44 for four of them | open - verified and ratcheted | `blg_concept_names_spread` | WP-05, WP-43 and her paket |
| BLG-256 | high | unclassified | The BUD balance is a u64 of atoms with no fractional field for the 18 decimals EVM and 9 SVM expect | open - live verification pending | `blg_bud_balance_u64` | WP-26 |
| BLG-257 | high | AI | There is no mobile client application; the mobile profile is a node command-line flag | open - verified | `blg_there_mobile_client` | WP-11, WP-36 |
| BLG-258 | medium | storage | A separate B.U.D. P2P content node exists and the content gateway is bound to it, breaking the single-storage rule | open - live verification pending | `blg_separate_p2p_content` | WP-07 |
| BLG-259 | medium | AI | A 128-seat checkpoint certificate is about 420 KB of ML-DSA-65 signatures, and the trust model is undocumented | open - live verification pending | `blg_128_seat_checkpoint` | WP-12, WP-11 |
| BLG-260 | medium | unclassified | The state store is single-process, so execution-environment workers cannot read state directly | open - live verification pending | `blg_state_store_single` | WP-26 |
| BLG-261 | low | unclassified | The education domain records work bytes with RegisterManifest and breaks when 2.0 is removed | open - live verification pending | `blg_education_domain_records` | WP-23 |
| BLG-262 | medium | unclassified | The content gateway serves content through Bitswap and a local sled lookup, not the 3.0 symbol path | open - live verification pending | `blg_content_gateway_serves` | WP-23 |
| BLG-263 | medium | AI | The security pool distributes by stake weight only, with no share for custody duty | open - live verification pending | `blg_security_pool_distributes` | WP-16 |
| BLG-264 | high | unclassified | Hash-chain leader election and the handoff committee are not bound into the production path | open - live verification pending | `blg_hash_chain_leader` | WP-12 |
| BLG-265 | medium | mobile | The mobile power and challenge model ignores the Android foreground-service limits | open - live verification pending | `blg_mobile_power_challenge` | WP-36 |
| BLG-266 | medium | AI | One min_stake parameter does not distinguish classes, and 1000 BUD is a high barrier for a phone user | open - verified | `blg_min_stake_parameter` | WP-08, WP-16 |
| BLG-267 | high | ZK and STARK | The gate refuses every classical-signature acceptance path, so no compatibility lane is defined for foreign transactions | open - live verification pending | `blg_gate_refuses_every` | WP-27 |
| BULGU-001 | S2 | unclassified | The block validity decision depends on the local wall clock | open - live verification pending | `bulgu_block_validity_decision` | WP-12 |
| BULGU-002 | S2 | unclassified | The checkpoint guard falls to the allow side on a poisoned lock | open - live verification pending | `bulgu_checkpoint_guard_falls` | WP-12 |
| BULGU-003 | S3 | unclassified | A proof is built with an empty signature on an unsigned block | open - live verification pending | `bulgu_proof_built_empty` | WP-12 |
| BULGU-004 | S3 | unclassified | The proof and block budgets are measured in JSON | open - live verification pending | `bulgu_proof_block_budgets` | WP-12 |
| BULGU-005 | S3 | AI | Genesis time is taken from the wall clock on an empty chain | open - live verification pending | `bulgu_genesis_time_taken` | WP-17 |
| BULGU-006 | S2 | AI | A discontinuity error is swallowed silently | open - live verification pending | `bulgu_discontinuity_error_swallowed` | WP-17 |
| BULGU-007 | S3 | AI | Storage errors are swallowed during reorg and pruning | open - live verification pending | `bulgu_storage_errors_swallowed` | WP-17 |
| BULGU-008 | S3 | AI | Replay slices without a bound check | open - live verification pending | `bulgu_replay_slices_without` | WP-17 |
| BULGU-009 | S3 | AI | An expect on the production path | open - live verification pending | `bulgu_expect_production_path` | WP-17 |
| BULGU-010 | S3 | unclassified | A serialisation error falls to a fixed tag | open - live verification pending | `bulgu_serialisation_error_falls` | WP-17 |
| BULGU-011 | S3 | RPC | The CORS wildcard reflects the request header | open - live verification pending | `bulgu_cors_wildcard_reflects` | WP-61 |
| BULGU-012 | S3 | RPC | A serialisation error returns a silent null response | open - live verification pending | `bulgu_serialisation_error_returns` | WP-61 |
| BULGU-013 | S3 | unclassified | A lock error is swallowed | open - live verification pending | `bulgu_lock_error_swallowed` | WP-17 |
| BULGU-014 | S2 | unclassified | A corrupt vote history restarts from zero, which risks a double signature | open - live verification pending | `bulgu_corrupt_vote_history` | WP-12 |
| BULGU-015 | S3 | AI | An actor channel error returns silent read defaults | open - live verification pending | `bulgu_actor_channel_error` | WP-17 |
| BULGU-016 | S3 | unclassified | The validator state root drops an empty array | open - live verification pending | `bulgu_validator_state_root` | WP-17 |
| BULGU-017 | S3 | bridge and domains | The on-chain storage proof is structural only | open - live verification pending | `bulgu_chain_storage_proof` | WP-07 (by removal) |
| BULGU-018 | S3 | AI | A corrupt PoA bootstrap address is dropped silently | open - live verification pending | `bulgu_corrupt_poa_bootstrap` | WP-16 |
| BULGU-019 | S3 | unclassified | The external-domain bond lock skips the vesting gate | open - live verification pending | `bulgu_external_domain_bond` | WP-16 |
| BULGU-020 | S3 | gates | Nine money gates read the raw balance and skip the vesting gate | open - live verification pending | `bulgu_nine_money_gates` | WP-16 |
| BULGU-021 | S3 | unclassified | The cross-shard transfer reads the raw balance gate (unreachable) | open - live verification pending | `bulgu_cross_shard_transfer` | WP-17 |
| BULGU-022 | S3 | gates | Three RoleBond transaction types have no application arm | open - live verification pending | `bulgu_three_rolebond_transaction` | WP-08 |
| BULGU-023 | S2 | AI | The double-signature proof is deleted in the second epoch | open - live verification pending | `bulgu_double_signature_proof` | WP-12 |
| BULGU-024 | S3 | AI | Branches taken by a reorg are not written to seen_blocks | open - live verification pending | `bulgu_branches_taken_reorg` | WP-12 |
| BULGU-025 | S3 | unclassified | Checkpoints have no deletion or repair path | open - live verification pending | `bulgu_checkpoints_deletion_repair` | WP-12 |
| BULGU-026 | S3 | AI | A reorg deletes pending discontinuity proofs | open - live verification pending | `bulgu_reorg_deletes_pending` | WP-12 |
| BULGU-027 | S3 | AI | The invalidate_finality_from_height loop is not aligned to the grid | open - live verification pending | `bulgu_invalidate_finality_height` | WP-12 |
| TEST-GAP-01 | high | unclassified | There is no regression lock for BULGU-019 | open - live verification pending | `test_gap_there_regression_lock` | WP-16 |
| TEST-GAP-02 | medium | fuzz and formal | Kani covers a quarter of the targets SECURITY.md names | open - live verification pending | `test_gap_kani_covers_quarter` | WP-42 |
| TEST-GAP-03 | medium | optical storage | The QR video parser is outside fuzz coverage | open - live verification pending | `test_gap_video_parser_outside` | WP-19 |
| TEST-GAP-04 | low | storage | The domain producer binary has no test | open - live verification pending | `test_gap_domain_producer_binary` | WP-42 |
| TEST-GAP-05 | low | storage | Two budzero modules have no direct test | open - live verification pending | `test_gap_two_budzero_modules` | WP-33 |
| TEST-GAP-06 | medium | storage | Three Kani runs in bud/kani do not run in CI | open - live verification pending | `test_gap_three_kani_runs` | WP-07 (by removal) |
| TEST-GAP-07 | low | RPC | Direct test coverage of the RPC endpoints is low | open - live verification pending | `test_gap_direct_test_coverage` | WP-61 |
| TEST-GAP-08 | medium | custody | The existing test locks pruning, which is the BULGU-023 leg of the proof retention window | open - live verification pending | `test_gap_existing_test_locks` | WP-12 |
| DOC-GAP-01 | S1 | AI | The testnet first run is blocked: the SoftHSM configuration is missing | open - live verification pending | `doc_gap_testnet_first_run` | WP-41 |
| DOC-GAP-02 | S3 | unclassified | Port documentation disagrees across the four modes | open - live verification pending | `doc_gap_port_documentation_disagrees` | WP-43 |
| DOC-GAP-03 | S3 | documentation | Script references in the README, CONTRIBUTING and ops/scripts are broken | open - live verification pending | `doc_gap_script_references_readme` | WP-43 |
| DOC-GAP-04 | S3 | storage | The systemd unit names the wrong repository and omits the HSM context | open - live verification pending | `doc_gap_systemd_unit_names` | WP-41 |
| DOC-GAP-05 | S3 | test quality | The validator, testnet and operations guides carry unfinished sentences | open - live verification pending | `doc_gap_validator_testnet_operations` | WP-43 |
| DOC-GAP-06 | S3 | test quality | The resource measurement tables in the testnet and validator guides are empty | open - live verification pending | `doc_gap_resource_measurement_tables` | WP-46 |
| DOC-GAP-07 | S3 | unclassified | There is no declared binary entry for budlum-indexer in Cargo.toml | open - live verification pending | `doc_gap_there_declared_binary` | WP-42 |
| DOC-GAP-08 | S3 | storage | The CLI fee default does not match the network base | open - live verification pending | `doc_gap_cli_fee_default` | WP-39 |
| DOC-GAP-09 | S3 | unclassified | The ledger table row is verified inside WP-04 | open - live verification pending | `doc_gap_ledger_table_row` | WP-43 |
| BLG-268 | high | build and CI | The binding directive sits in the tree as a Turkish file the English gate does not allow | open - verified | `blg_268_directive_file_is_exempt_with_reason` | WP-42, WP-43 |
| BLG-269 | low | process | The repository has GitHub issues disabled, so the one issue per package cannot exist | open - verified | `blg_269_package_register_is_in_the_tree` | WP-04 |
| BLG-270 | medium | build and CI | No workflow on main has ever completed, so no gate has produced a verdict on this history | open - verified | `blg_270_first_completed_run_is_recorded` | WP-42 |

## Archive families and their BLG overlap

The archive rows above overlap the BLG register in places. The overlaps that
this branch could confirm by reading the tree:

| Archive | Overlaps | Note |
|---|---|---|
| BULGU-023 | BLG-119, TEST-GAP-08 | the double-signature proof and its retention window |
| BULGU-019 | BLG-021, TEST-GAP-01 | the bond lock that skips the vesting gate |
| BULGU-017 | BLG-047 | the structural-only storage proof |
| BULGU-027 | BLG-096 | the finality invalidation grid |
| TEST-GAP-06 | BLG-217 | the second 3.0 implementation under `bud/` |

The remaining overlaps are WP-01 to WP-03 work and are marked as such in the
lane files rather than guessed here.

