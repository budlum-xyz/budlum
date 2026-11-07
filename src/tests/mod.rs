#[cfg(test)]
pub mod bridge_lifecycle;
#[cfg(test)]
pub mod block_door_harness;
#[cfg(test)]
pub mod global_header_sequence;
pub mod regression_canaries;
#[cfg(test)]
pub mod conformance_locks;
#[cfg(test)]
pub mod bench_performance;
#[cfg(test)]
pub mod block_reward;
#[cfg(test)]
pub mod audit_lane_a;
// State-machine sharding (Whitepaper v1.3): block-level shards commitment
// production/validation and atomic cross-shard transfers.
#[cfg(test)]
pub mod bns;
#[cfg(test)]
pub mod deed;
#[cfg(test)]
pub mod sharding_e2e;
#[cfg(test)]
pub mod bud_e2e;
#[cfg(test)]
pub mod byzantine_settlement;
#[cfg(test)]
pub mod chaos;
#[cfg(test)]
pub mod distributed_settlement;
#[cfg(test)]
pub mod fork_choice_locks;
#[cfg(test)]
pub mod manifest_commitment_locks;
#[cfg(test)]
pub mod multi_consensus_locks;
pub mod operator_kill_chaos;
#[cfg(test)]
pub mod consensus_round_boundaries;
#[cfg(test)]
pub mod poisoned_lock_locks;
#[cfg(test)]
pub mod qcblob_quorum;
#[cfg(test)]
pub mod wall_clock_locks;
#[cfg(test)]
pub mod ai_inference_runtime;
#[cfg(test)]
pub mod disaster_recovery;
#[cfg(test)]
pub mod finality_adversarial;
#[cfg(test)]
pub mod finality_live_path;
#[cfg(test)]
pub mod hardening;
#[cfg(test)]
pub mod identity_tx_door;
#[cfg(test)]
pub mod integration;
#[cfg(test)]
pub mod liveness_consensus;
pub mod migration_v2;
#[cfg(test)]
pub mod permissionless;
#[cfg(test)]
pub mod permissionless_e2e;
#[cfg(test)]
pub mod persistence;
pub mod poa_isolation;
#[cfg(test)]
pub mod pollen_ai_data_rights;
#[cfg(test)]
pub mod ported_slice_redteam;
#[cfg(test)]
pub mod pow_light_client;
pub mod privacy_ai_execution;
pub mod private_transfer_fee_market;
#[cfg(test)]
pub mod prover;
#[cfg(test)]
pub mod state_recovery;
#[cfg(test)]
pub mod relayer_liveness;
#[cfg(test)]
pub mod relayer_gates;
#[cfg(test)]
pub mod relayer_worker_locks;
#[cfg(test)]
pub mod settlement_prod;
#[cfg(test)]
pub mod storage_tx_door;
#[cfg(test)]
pub mod tokenomics;
pub mod tokenomics_proptest;
#[cfg(test)]
pub mod vault_tx_door;
#[cfg(test)]
pub mod zkvm;
#[cfg(test)]
pub mod adversarial_p2p;
#[cfg(test)]
pub mod bns_expanded;
#[cfg(test)]
pub mod consensus_expanded;
#[cfg(test)]
pub mod consensus_lock_order_loom;
#[cfg(test)]
pub mod constitution_engine;
#[cfg(test)]
pub mod hard_prune;
#[cfg(test)]
pub mod load_test;
#[cfg(test)]
pub mod proptest_core;
#[cfg(test)]
pub mod relayer_e2e;
#[cfg(test)]
pub mod replay_audit;
#[cfg(test)]
pub mod security_auditor;
#[cfg(test)]
pub mod socialfi;
#[cfg(test)]
pub mod target_700;
#[cfg(test)]
pub mod bridge_negatives;
pub mod domain_edge_cases;
#[cfg(test)]
pub mod encryption_dao;
#[cfg(test)]
pub mod evm_finality_contract;
pub mod poa_onboarding_matrix;
#[cfg(test)]
pub mod snapshot_chaos;
#[cfg(test)]
pub mod advisory_reachability;
#[cfg(test)]
pub mod ai_verification_status_locks;
pub mod security_invariant_tests;
#[cfg(test)]
pub mod consensus_rounds;
#[cfg(test)]
pub mod hardening_h2_locks;
#[cfg(test)]
pub mod hardening_h4_locks;
#[cfg(test)]
pub mod hardening_h5_h7_locks;
#[cfg(test)]
pub mod hardening_locks;
pub mod mempool_dos_locks;
pub mod network_hardening_locks;
#[cfg(test)]
pub mod protocol_guardrails;
#[cfg(test)]
pub mod regression_lock;
pub mod slashing_matrix;
pub mod consensus_digest;
#[cfg(test)]
pub mod genesis_repro;
#[cfg(test)]
pub mod hash_input_serialize_locks;
pub mod blockchair_fixture_locks;
#[cfg(test)]
pub mod chain_id_registry_locks;
pub mod consensus_bypass_locks;
#[cfg(test)]
pub mod block_clock;
#[cfg(test)]
pub mod real_chain_fixtures;
// Effect-asserting locks for the slashing matrix and the overflow rule.
#[cfg(test)]
pub mod refusal_locks;

// Regression locks for fixes already in the tree, one module per area.
#[cfg(test)]
pub mod regression_ai_storage;
#[cfg(test)]
pub mod regression_bridge;
#[cfg(test)]
pub mod regression_chain;
#[cfg(test)]
pub mod regression_ops_crypto;

// Validator classes and the single registration door.
#[cfg(test)]
pub mod validator_classes;

// The B.U.D. 3.0 storage door end to end.
#[cfg(test)]
pub mod bud3_door;

// Prometheus alert rules may only name metrics the node exports.
#[cfg(test)]
pub mod alert_rules_reference_existing_metrics;
#[cfg(test)]
pub mod alerts_have_runbook_entries;

// Derived object-layer measurement rings and counters.
#[cfg(test)]
pub mod object_layer_metrics;

// Readiness series and the operational surfaces that scrape and alert on them.
#[cfg(test)]
pub mod backup_covers_persisted_paths;
#[cfg(test)]
pub mod caddy_edges_match_the_services;
#[cfg(test)]
pub mod compose_topology_matches_services;
#[cfg(test)]
pub mod readiness_metrics;
#[cfg(test)]
pub mod scrape_topology_covers_the_rules;

// The persistence move is behaviour-neutral.
#[cfg(test)]
pub mod persistence_move;

// State transition, vesting, staking, governance, sharding, and snapshot hardening.
#[cfg(test)]
pub mod state_hardening;

// Domains, cross-domain bridge, settlement, and testnet feature-matrix locks.
#[cfg(test)]
pub mod domains_bridge_settlement;

// Instant Duty Handover and finality recovery.
#[cfg(test)]
pub mod handover_recovery;

// Ceremony rehearsal and protocol drills.
#[cfg(test)]
pub mod ceremony_and_drills;

// Security, conservation, and privilege-boundary regressions.
#[cfg(test)]
pub mod security_review;
// Object replacement: the second representation of one content id
// (section 6.14).
#[cfg(test)]
pub mod bud3_replace;
