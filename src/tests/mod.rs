// Bridge lifecycle integration test (security audit §3). The
// `bud_lockBridgeTransfer` RPC is removed; the full lock → mint → burn →
// Unlock happy path is now exercised through the *internal*
// `Blockchain::lock_bridge_transfer` system path, plus the
// `apply_bridge_sweep` expiry-sweep.
#[cfg(test)]
pub mod bridge_lifecycle;
pub mod v95_v98_canaries;
// QcBlob quorum-check unit tests (security audit §4). The
// `import_qc_blob` minimum-signature count contract is verified by
// Replaying the same arithmetic the production code uses, against
// 3-validator snapshots.
#[cfg(test)]
pub mod bench_performance;
#[cfg(test)]
pub mod block_reward;
// State-machine sharding (Whitepaper v1.3): block-level shards commitment
// production/validation and atomic cross-shard transfers.
#[cfg(test)]
pub mod bns;
#[cfg(test)]
pub mod deed;
#[cfg(test)]
pub mod sharding_e2e;
// Plus: the B.U.D. end-to-end test and the module-independence invariants.
// A three-actor scenario (operator A, operator B and observer C) with 9
// permissionless, whitelist and data-sovereignty invariants (plan section 0.5
// + §4 kabul kriterleri).
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
#[cfg(test)]
pub mod poisoned_lock_locks;
#[cfg(test)]
pub mod qcblob_quorum;
#[cfg(test)]
pub mod wall_clock_locks;
// Re-enabled (was `#![cfg(false)]`'d ghost-hunting).
// The permissionless-registry / liveness / invalid-vote state was reinstated
// On `AccountState`, so these test files now exercise the real code paths
// Again. They were the regression tests for patch series.
#[cfg(test)]
pub mod disaster_recovery;
#[cfg(test)]
pub mod finality_adversarial;
#[cfg(test)]
pub mod finality_live_path;
#[cfg(test)]
pub mod hardening;
#[cfg(test)]
pub mod integration;
#[cfg(test)]
pub mod liveness_consensus;
#[cfg(test)]
pub mod lubot_runtime;
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
pub mod pow_light_client;
pub mod privacy_ai_execution;
pub mod private_transfer_fee_market;
#[cfg(test)]
pub mod prover;
#[cfg(test)]
pub mod relayer_liveness;
// L1 relayer proof kripto-doorulama + M5 budlumxyz fee + M4 BNS fee
// Regresyon kapilari (Q-A, 2026-07-16).
#[cfg(test)]
pub mod relayer_gates;
// A relayer may stay silent; it may not sign an external outcome it never
// observed. Pins the worker's refusal paths.
#[cfg(test)]
pub mod relayer_worker_locks;
#[cfg(test)]
pub mod settlement_prod;
#[cfg(test)]
pub mod tokenomics;
pub mod tokenomics_proptest;
#[cfg(test)]
pub mod zkvm;
// The F4 seal (2026-07-17): the SocialFi boost 4 percent B.U.D. operator
// distribution, remainder determinism, and the operator-less burn fallback
// regressions.
#[cfg(test)]
pub mod adversarial_p2p;
// The F1 seal (2026-07-17): NftBurn -> storage manifest hard
// Prune chain-level regression lock (the produce_block path).
#[cfg(test)]
pub mod bns_expanded;
// Universal Relayer E2E integration tests.
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
// A P0 mainnet gap (2026-07-18): the bridge negative suite - forgery,
// Replay / anchor-substitution / inactive-relayer / unknown-message reddi.
// It verifies only the refusal paths already defined; protocol behaviour does
// not change.
#[cfg(test)]
pub mod bridge_negatives;
pub mod domain_edge_cases;
#[cfg(test)]
pub mod encryption_dao;
// The PoA participant onboarding lifecycle, the whitelist requirement and the
// KYC expiry test matrix. The isolation seal lives in poa_isolation.rs.
pub mod poa_onboarding_matrix;
// P0 mainnet-gap 3/3 (2026-07-19): snapshot-corruption +
// The crash-recovery chaos suite. Two _gap pins deliberately seal today's
// behaviour (no snapshot authenticity, v1/v2 cross-shadowing and a silent boot
// rollback); they are inverted when the product fix is ordered.
#[cfg(test)]
pub mod snapshot_chaos;
// P5 regression lock (2026-07-19): ZK finality fail-open +
// The relayer escrow silent-failure security seals, which break CI.
// Reachability premises behind the accepted dependency advisories. These fail
// when a routine dependency change makes a carried CVE live again.
// External review pass: locks for the findings that were real, plus the ones
// that were already handled and should not have to be re-derived.
#[cfg(test)]
pub mod advisory_reachability;
#[cfg(test)]
pub mod ai_verification_status_locks;
pub mod audit_findings_locks;
#[cfg(test)]
pub mod f20_priority_findings;
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
pub mod regression_lock;
pub mod slashing_matrix;
// (2026-07-21) cross-platform consensus determinism digest'i.
// determinism.yml collects the CONSENSUS_DIGEST line produced by the test in
// this module across three operating systems and requires byte equality.
pub mod consensus_digest;
// (2026-07-21) CI expansion item 1 - the genesis reproducibility probe
// (`genesis_hash_deterministic`, see determinism.yml).
#[cfg(test)]
pub mod genesis_repro;
// A serialize failure must not fold into empty bytes on a path that feeds a
// hash: two different values would then commit to the same digest.
#[cfg(test)]
pub mod hash_input_serialize_locks;
// Chain ids must not collide with another chain's registry entry.
pub mod blockchair_fixture_locks;
#[cfg(test)]
pub mod chain_id_registry_locks;
pub mod consensus_bypass_locks;
// Differential tests against real chain fixtures (merkle, RLP, halving).
// The fixture is the single source: config/fixtures/real-chain.json, and the
// xtask `fixture-integrity` gate verifies the same file.
#[cfg(test)]
pub mod real_chain_fixtures;
