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
#[cfg(test)]
pub mod bns;
#[cfg(test)]
pub mod deed;
// +: B.U.D. E2E test + modül-bağımsızlık invariantları.
// 3-aktör (operatör A + operatör B + izleyici C) senaryosu + 9 adet
// Permissionless/whitelist/data-sovereignty invariantı (plan §0.5
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
pub mod qcblob_quorum;
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
// L1 relayer proof kripto-doorulama + M5 hub fee + M4 BNS fee
// Regresyon kapilari (kullanici karari Q-A, 2026-07-16).
#[cfg(test)]
pub mod relayer_gates;
#[cfg(test)]
pub mod settlement_prod;
#[cfg(test)]
pub mod tokenomics;
pub mod tokenomics_proptest;
#[cfg(test)]
pub mod zkvm;
// / F4 mühürü (2026-07-17): SocialFi boost %4 B.U.D. operatör
// Dağıtımı + remainder determinizmi + operatörsüz burn fallback regresyonları.
#[cfg(test)]
pub mod adversarial_p2p;
// / F1 mühürü (2026-07-17): NftBurn -> storage manifest hard
// Prune zincir-seviyesi regresyon kilidi (produce_block yolu).
#[cfg(test)]
pub mod bns_expanded;
// Universal Relayer E2E integration tests.
#[cfg(test)]
pub mod consensus_expanded;
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
// P0 mainnet-gap (2026-07-18): bridge negatif süiti — forgery /
// Replay / anchor-substitution / inactive-relayer / unknown-message reddi.
// Yalnızca mevcut tanımlı red yollarını doğrular; protokol davranışı değişmez.
#[cfg(test)]
pub mod bridge_negatives;
pub mod domain_edge_cases;
#[cfg(test)]
pub mod encryption_dao;
//: PoA katılımcı onboarding yaşam-döngüsü + whitelist
// Zorunluluğu + KYC expiry test matrisi. İzolasyon mührü poa_isolation.rs'de.
pub mod poa_onboarding_matrix;
// P0 mainnet-gap 3/3 (2026-07-19): snapshot-corruption +
// Crash-recovery kaos süiti. İki _gap pini bilinçli olarak bugünkü davranışı
// Mühürler (snapshot authenticity yok + v1/v2 çapraz-gölgeleme + boot
// Sessiz-rollback); ürün düzeltmesi emirle geldiğinde ters çevrilir.
#[cfg(test)]
pub mod snapshot_chaos;
// P5 regresyon kilidi (2026-07-19): ZK finality fail-open +
// Relayer escrow silent-failure CI kırıcı güvenlik mühürleri.
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
pub mod hardening_h2_locks;
#[cfg(test)]
pub mod hardening_h4_locks;
#[cfg(test)]
pub mod hardening_h5_h7_locks;
#[cfg(test)]
pub mod hardening_locks;
pub mod network_hardening_locks;
#[cfg(test)]
pub mod regression_lock;
pub mod slashing_matrix;
// (2026-07-21) cross-platform consensus determinism digest'i.
// Determinism.yml bu modüldeki testten üretilen CONSENSUS_DIGEST satırını üç
// Işletim sisteminde toplayıp byte-eşitlik ister.
pub mod consensus_digest;
// (2026-07-21) CI Genişletme Madde 1 — genesis
// Reproducibility sondası (`genesis_hash_deterministic`, bkz. determinism.yml).
#[cfg(test)]
pub mod genesis_repro;
