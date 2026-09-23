//! Epoch semantics - the "self-timestamping" half of the design.
//!
//! Decisions pinned (user, 2026-09-19): the epoch index is derived from the
//! **chain tempo**, not a wall clock: `t = floor(h / W)` with `W` the
//! settlement finality window (chosen by the anchor integration; the
//! reference surface keeps it an input called [`EpochWindow`]). A signer can
//! never "run ahead" of the chain, and stale signatures pinned to old epochs
//! cannot be played forward, because the verifier re-derives the epoch from
//! chain height instead of trusting any timestamp inside the signature.

use crate::domains;
use crate::error::BpqsError;
use crate::hash::BpqsHash;

/// Length of one epoch in blocks. Must be chosen once by the integration;
/// `floor(height / W)` flips exactly once per window, and the anchor flow
/// emits at most one anchor per window - so the few-time quota is naturally
/// respected, with headroom (q_max = 4) for legitimate re-attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochWindow(pub u64);

/// Self-timestamping derivation: `t = floor(h / W)`.
///
/// Refusal class: a zero window is a configuration error and must be told
/// loudly instead of dividing silently.
pub fn epoch_of(height: u64, window: EpochWindow) -> Result<u32, BpqsError> {
    if window.0 == 0 {
        return Err(BpqsError::BadEpochWindow);
    }
    Ok((height / window.0) as u32)
}

/// Pseudorandom per-epoch seed, drawn from the member's long-term root seed
/// (32 bytes at every security level: the seed budget is an operational
/// choice independent of lane width). This is the private-ceremony
/// counterpart of the self-timestamping rule: with nothing but the root seed
/// and any height in the epoch, the device reproduces the epoch's key
/// material - no counter, no mutable chain state.
pub fn prf_epoch_seed<H: BpqsHash>(root_seed: &[u8; 32], epoch: u32) -> [u8; 32] {
    H::digest32(domains::PRF_EPOCH_SEED, &[root_seed, &epoch.to_le_bytes()])
}

#[cfg(test)]
mod epoch_tests {
    use super::*;
    use crate::hash::Sha3_256Hash;

    #[test]
    fn epoch_flips_exactly_at_the_window_boundary() {
        let w = EpochWindow(64);
        assert_eq!(epoch_of(0, w), Ok(0));
        assert_eq!(epoch_of(63, w), Ok(0));
        assert_eq!(epoch_of(64, w), Ok(1));
        assert_eq!(epoch_of(127, w), Ok(1));
        assert_eq!(epoch_of(128, w), Ok(2));
    }

    #[test]
    fn zero_window_is_a_loud_config_refusal() {
        assert_eq!(epoch_of(12, EpochWindow(0)), Err(BpqsError::BadEpochWindow));
    }

    #[test]
    fn prf_is_deterministic_and_epoch_separated() {
        let seed = [7u8; 32];
        let a = prf_epoch_seed::<Sha3_256Hash>(&seed, 9);
        let a2 = prf_epoch_seed::<Sha3_256Hash>(&seed, 9);
        let b = prf_epoch_seed::<Sha3_256Hash>(&seed, 10);
        assert_eq!(a, a2, "same epoch, same seed");
        assert_ne!(a, b, "different epochs must decorrelate");
    }
}
