// Tur 6: bridge lifecycle integration test (security audit §3). The
// `bud_lockBridgeTransfer` RPC is removed; the full lock → mint → burn →
// unlock happy path is now exercised through the *internal*
// `Blockchain::lock_bridge_transfer` system path, plus the
// `apply_bridge_sweep` expiry-sweep.
#[cfg(test)]
pub mod bridge_lifecycle;
#[cfg(test)]
pub mod bench_performance;
#[cfg(test)]
pub mod block_reward;
#[cfg(test)]
pub mod byzantine_settlement;
#[cfg(test)]
pub mod chaos;
#[cfg(test)]
pub mod distributed_settlement;
// Tur 5: re-enabled (was `#![cfg(false)]`'d during Tur 2 ghost-hunting).
// The permissionless-registry / liveness / invalid-vote state was reinstated
// on `AccountState`, so these test files now exercise the real code paths
// again. They were the regression tests for the Tur 1-19 patch series.
#[cfg(test)]
pub mod finality_adversarial;
#[cfg(test)]
pub mod hardening;
#[cfg(test)]
pub mod integration;
#[cfg(test)]
pub mod liveness_consensus;
#[cfg(test)]
pub mod permissionless;
#[cfg(test)]
pub mod persistence;
#[cfg(test)]
pub mod prover;
#[cfg(test)]
pub mod relayer_liveness;
#[cfg(test)]
pub mod settlement_prod;
#[cfg(test)]
pub mod tokenomics;
#[cfg(test)]
pub mod zkvm;
