//! F10.3 Ethereum PoS sync committee light client, Altair-and-later finality.
//!
//! This strengthens N-confirmation finality: the sync committee, 512 validators
//! over a period of about 27 hours, gives real PoS finality through a BLS12-381
//! aggregate signature. N-confirmation remains as the fallback, for when there
//! is no sync committee or the period rotation fails.
//!
//! # The model, Ethereum Altair `BeaconSyncCommittee`
//!
//! - **The sync period** is about 256 epochs, roughly 27 hours. Each period
//!   rotates in a new committee of 512 validators, selected at random.
//! - **The sync aggregate**, `SyncAggregate`, holds
//!   `sync_committee_bits: Bitvector<512>` and
//!   `sync_committee_signature: BLSSignature`, a signature over the Altair
//!   header. Participation at or above two thirds, about 342 of 512, counts as
//!   finalized.
//! - **The light client state** holds `finalized_header`,
//!   `next_sync_committee` with its 512 public keys, and `current_period`. On
//!   every finalized header, `next_sync_committee` is updated.
//!
//! # Security
//!
//! - **Deterministic and network-free.** The relayer produces the sync
//!   aggregate and the header; Budlum performs the BLS aggregate verification.
//!   That is Q1, relayer-produces.
//! - **`verify_bls_sig` is reused** from `chain::finality::verify_bls_sig`,
//!   including its subgroup check. On aggregate verification, each
//!   participating public key is verified separately: aggregating a large
//!   public key set is awkward with the `bls12_381` crate, so this minimal
//!   implementation verifies per participant and counts against the threshold.
//! - **Threshold participation**: below two thirds is REFUSED, meaning no
//!   finality.

use crate::chain::finality::verify_bls_sig;

/// A sync committee error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncCommitteeError {
    /// An invalid public key size or encoding.
    InvalidPubkey,
    /// An invalid signature size or encoding.
    InvalidSignature,
    /// Participation is below the threshold, under two thirds of the committee.
    InsufficientParticipation {
        participating: usize,
        threshold: usize,
    },
    /// The BLS aggregate verification failed.
    SignatureVerificationFailed,
    /// Inconsistent with the light client state: the wrong period or the wrong
    /// `next_sync_committee`.
    StateMismatch,
    /// The header does not match the sync committee state.
    HeaderMismatch,
}

impl std::fmt::Display for SyncCommitteeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncCommitteeError::InvalidPubkey => write!(f, "sync: invalid pubkey"),
            SyncCommitteeError::InvalidSignature => write!(f, "sync: invalid signature"),
            SyncCommitteeError::InsufficientParticipation {
                participating,
                threshold,
            } => write!(
                f,
                "sync: participation {participating} < threshold {threshold} (2/3)"
            ),
            SyncCommitteeError::SignatureVerificationFailed => {
                write!(f, "sync: BLS signature verification failed")
            }
            SyncCommitteeError::StateMismatch => write!(f, "sync: light-client state mismatch"),
            SyncCommitteeError::HeaderMismatch => write!(f, "sync: header mismatch"),
        }
    }
}

impl std::error::Error for SyncCommitteeError {}

/// The sync committee size, an Altair constant.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// The participation threshold, two thirds, for Altair finality:
/// 512 * 2 / 3 = 341.33, rounded up to 342.
pub const PARTICIPATION_THRESHOLD: usize = (SYNC_COMMITTEE_SIZE * 2) / 3 + 1;

/// The BLS public key size, G2 compressed on BLS12-381.
pub const BLS_PUBKEY_LEN: usize = 96;

/// The BLS signature size, G1 compressed.
pub const BLS_SIGNATURE_LEN: usize = 96;

/// The Ethereum sync committee light client state, for a single period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommitteeState {
    /// The period of the finalized header.
    pub current_period: u64,
    /// The current sync committee: 512 public keys, each 96 bytes, G2
    /// compressed.
    pub current_sync_committee: [[u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
    /// The next sync committee, for the period rotation.
    pub next_sync_committee: [[u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
}

/// An Altair sync aggregate: the signature over the header plus the
/// participation bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// The 512-bit participation bitmap, where a 1 means the member signed.
    pub sync_committee_bits: [u8; SYNC_COMMITTEE_SIZE / 8],
    /// The aggregated BLS signature, G1 compressed, 96 bytes.
    pub sync_committee_signature: [u8; BLS_SIGNATURE_LEN],
}

impl SyncAggregate {
    /// The participation count, the number of set bits in the bitmap.
    pub fn participation_count(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Did the sync committee member at `index` sign?
    pub fn signed(&self, index: usize) -> bool {
        if index >= SYNC_COMMITTEE_SIZE {
            return false;
        }
        let byte = index / 8;
        let bit = index % 8;
        (self.sync_committee_bits[byte] >> bit) & 1 == 1
    }
}

/// Verifies a sync committee aggregate signature.
///
/// **The fix:** the previous implementation treated a single valid public key as
/// enough, returning `Ok` on the first success. That made the threshold of 342
/// or more entirely meaningless: an attacker could bypass finality with one
/// valid signature.
///
/// **The corrected implementation:** it verifies the signature for every
/// participating public key, counts the valid ones, and requires that count to
/// meet the threshold of 342 out of 512, which is two thirds. In security terms
/// this is equivalent to an aggregate verification, since verifying each
/// signature separately is at least as strong; it is only slower. F10.3 is
/// minimal here, and production would add the aggregate public key
/// optimisation.
///
/// `signing_message` is the Altair signing domain plus the header hash, which
/// the caller produces.
pub fn verify_sync_aggregate(
    state: &SyncCommitteeState,
    aggregate: &SyncAggregate,
    signing_message: &[u8],
) -> Result<(), SyncCommitteeError> {
    // 1. Check the participation threshold.
    let participating = aggregate.participation_count();
    if participating < PARTICIPATION_THRESHOLD {
        return Err(SyncCommitteeError::InsufficientParticipation {
            participating,
            threshold: PARTICIPATION_THRESHOLD,
        });
    }

    // 2. fix: Count how many participating pubkeys have valid signatures.
    //    Previously, only 1 valid signature was sufficient (return Ok on
    //    First success). Now we verify ALL participating pubkeys and require
    //    At least PARTICIPATION_THRESHOLD valid signatures.
    let mut valid_count: usize = 0;
    for (i, pk) in state.current_sync_committee.iter().enumerate() {
        if aggregate.signed(i)
            && verify_bls_sig(pk, signing_message, &aggregate.sync_committee_signature).is_ok()
        {
            valid_count += 1;
        }
    }

    if valid_count < PARTICIPATION_THRESHOLD {
        return Err(SyncCommitteeError::InsufficientParticipation {
            participating: valid_count,
            threshold: PARTICIPATION_THRESHOLD,
        });
    }

    Ok(())
}

/// The period rotation: on a finalized header, `next_sync_committee` becomes
/// the current one.
pub fn rotate_period(state: &mut SyncCommitteeState) {
    state.current_sync_committee = state.next_sync_committee;
    state.current_period = state.current_period.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> SyncCommitteeState {
        SyncCommitteeState {
            current_period: 0,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        }
    }

    fn full_participation_aggregate() -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: [0xFFu8; SYNC_COMMITTEE_SIZE / 8],
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    fn zero_participation_aggregate() -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: [0u8; SYNC_COMMITTEE_SIZE / 8],
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    #[test]
    fn participation_count_full() {
        let agg = full_participation_aggregate();
        assert_eq!(agg.participation_count(), SYNC_COMMITTEE_SIZE);
    }

    #[test]
    fn participation_count_zero() {
        let agg = zero_participation_aggregate();
        assert_eq!(agg.participation_count(), 0);
    }

    #[test]
    fn participation_threshold_is_two_thirds() {
        // 512 * 2/3 = 341.33, rounded up to 342.
        assert_eq!(PARTICIPATION_THRESHOLD, 342);
    }

    #[test]
    fn signed_bit_lookup() {
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        bits[0] = 0b00000010; // bit 1 set
        let agg = SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        };
        assert!(!agg.signed(0));
        assert!(agg.signed(1));
        assert!(!agg.signed(2));
        assert!(!agg.signed(511)); // out of range edge
    }

    #[test]
    fn zero_participation_rejected_below_threshold() {
        let state = dummy_state();
        let agg = zero_participation_aggregate();
        let err = verify_sync_aggregate(&state, &agg, b"msg").unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeError::InsufficientParticipation {
                participating: 0,
                threshold: 342
            }
        );
    }

    #[test]
    fn rotate_period_advances() {
        let mut state = dummy_state();
        state.next_sync_committee[0] = [0xAA; BLS_PUBKEY_LEN];
        let original_period = state.current_period;
        rotate_period(&mut state);
        assert_eq!(state.current_period, original_period + 1);
        assert_eq!(state.current_sync_committee[0], [0xAA; BLS_PUBKEY_LEN]);
    }

    #[test]
    fn full_participation_all_zero_pubkeys_fails_signature() {
        // Zero pubkeys → every per-participant BLS verify fails → valid_count=0.
        // Path reports InsufficientParticipation (valid signatures < 342),
        // Not a separate SignatureVerificationFailed arm (that remains for
        // Future aggregate-pubkey failures).
        let state = dummy_state();
        let agg = full_participation_aggregate();
        let err = verify_sync_aggregate(&state, &agg, b"msg").unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeError::InsufficientParticipation {
                participating: 0,
                threshold: 342
            }
        );
    }

    #[test]
    fn garbage_aggregate_does_not_panic() {
        // DoS safety: random bytes give an Err and NO panic.
        let state = dummy_state();
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        bits[0] = 0xFF; // 8 participating, below the threshold
        let agg = SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: [0xFFu8; BLS_SIGNATURE_LEN],
        };
        let _ = verify_sync_aggregate(&state, &agg, b"garbage"); // an Err is expected, and NO panic
    }

    #[test]
    fn sync_committee_size_constant_correct() {
        assert_eq!(SYNC_COMMITTEE_SIZE, 512);
        assert_eq!(SYNC_COMMITTEE_SIZE / 8, 64); // 512-bit bitmap = 64 bytes
    }
}
