// Phase 0.10: bridge lifecycle integration test (security audit §3). The
// `bud_lockBridgeTransfer` RPC is removed; the full lock → mint → burn →
// unlock happy path is now exercised through the *internal*
// `Blockchain::lock_bridge_transfer` system path, plus the
// `apply_bridge_sweep` expiry-sweep.
#[cfg(test)]
pub mod bridge_lifecycle;
// Phase 0.12: QcBlob quorum-check unit tests (security audit §4). The
// `import_qc_blob` minimum-signature count contract is verified by
// replaying the same arithmetic the production code uses, against
// 3-validator snapshots.
#[cfg(test)]
pub mod bench_performance;
#[cfg(test)]
pub mod block_reward;
#[cfg(test)]
pub mod bns;
// Phase 0.38, Faz 1-2 + Faz 5: B.U.D. E2E test + ekip-bağımsızlık invariantları.
// 3-aktör (operatör A + operatör B + izleyici C) senaryosu + 9 adet
// permissionless/whitelist/data-sovereignty invariantı (Phase 0.39 plan §0.5
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
// Phase 0.08: re-enabled (was `#![cfg(false)]`'d during Phase 0.02 ghost-hunting).
// The permissionless-registry / liveness / invalid-vote state was reinstated
// on `AccountState`, so these test files now exercise the real code paths
// again. They were the regression tests for the Phase 0-19 patch series.
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
#[cfg(test)]
pub mod prover;
#[cfg(test)]
pub mod relayer_liveness;
// Phase 8.9 / Dalga 5: L1 relayer proof kripto-doorulama + M5 hub fee + M4 BNS fee
// regresyon kapilari (kullanici karari Q-A, 2026-07-16).
#[cfg(test)]
pub mod relayer_gates;
#[cfg(test)]
pub mod settlement_prod;
#[cfg(test)]
pub mod tokenomics;
pub mod tokenomics_proptest;
#[cfg(test)]
pub mod zkvm;
// Phase 9 / F4 mühürü (ARENA3, 2026-07-17): SocialFi boost %4 B.U.D. operatör
// dağıtımı + remainder determinizmi + operatörsüz burn fallback regresyonları.
#[cfg(test)]
pub mod adversarial_p2p;
// Phase 9 / F1 mühürü (ARENA3, 2026-07-17): NftBurn -> storage manifest hard
// prune zincir-seviyesi regresyon kilidi (produce_block yolu).
#[cfg(test)]
pub mod bns_expanded;
// ADIM5 §5.1: Universal Relayer E2E integration tests (ARENA1).
#[cfg(test)]
pub mod consensus_expanded;
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
// P0 mainnet-gap (ARENA3, 2026-07-18): bridge negatif süiti — forgery /
// replay / anchor-substitution / inactive-relayer / unknown-message reddi.
// Yalnızca mevcut tanımlı red yollarını doğrular; protokol davranışı değişmez.
#[cfg(test)]
pub mod bridge_negatives;
pub mod domain_edge_cases;
// P0 mainnet-gap 3/3 (ARENA3, 2026-07-19): snapshot-corruption +
// crash-recovery kaos süiti. İki _gap pini bilinçli olarak bugünkü davranışı
// mühürler (snapshot authenticity yok + v1/v2 çapraz-gölgeleme + boot
// sessiz-rollback); ürün düzeltmesi emirle geldiğinde ters çevrilir.
#[cfg(test)]
pub mod snapshot_chaos;
// P5 regresyon kilidi (ARENA2, 2026-07-19): ZK finality fail-open +
// relayer escrow silent-failure CI kırıcı güvenlik mühürleri.
#[cfg(test)]
pub mod hardening_locks;
#[cfg(test)]
pub mod regression_lock;
pub mod slashing_matrix;
