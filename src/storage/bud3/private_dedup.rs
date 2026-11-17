//! Private cross-owner deduplication experiments.
//!
//! Both `threshold` and `committee` are experimental transcript APIs and
//! closed on testnet `45261`. Their hash-derived shares are not a threshold
//! OPRF; a plaintext challenge transcript is not a private ownership proof.
//! `TESTNET_PRIVATE_DEDUP_ENABLED` and `ACTIVATION` stay closed until real
//! cryptographic primitives and a production admission path exist.

pub mod committee;
pub mod threshold;

pub use committee::{
    padme_bucket_bytes, OprfPartialShare, OwnershipProof, PrivateDedupActivation,
    PublicEpochDedupSummary, PublicSealedNftView, ThresholdOprfCommittee, ACTIVATION,
    DEFAULT_OPRF_RATE_LIMIT_PER_EPOCH, MIN_SEALED_BUCKET_BYTES, PRIVATE_DEDUP_OPRF_TAG,
    PRIVATE_DEDUP_OWNERSHIP_TAG, PRIVATE_DEDUP_RECORD_TAG,
};
pub use threshold::{
    combine_threshold_oprf_shares, BlindedDedupRecord, OwnershipProofBundle, PrivateDedupEngine,
    PrivateDedupError, SealedDedupSubmission, ThresholdOprfShare, DEFAULT_OPRF_THRESHOLD,
    MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH, TESTNET_PRIVATE_DEDUP_ENABLED,
};

#[cfg(test)]
mod tests {
    use super::{ACTIVATION, TESTNET_PRIVATE_DEDUP_ENABLED};

    /// A closed feature refuses on the testnet chain id. This pins the two
    /// switches that keep the experimental private-dedup helpers closed. The
    /// request and upload doors, and the proof that a closed request spends no
    /// quota, are in `committee::tests` and `threshold::tests`.
    #[test]
    fn private_dedup_is_closed_on_testnet() {
        // `black_box` keeps the lint that rejects asserts on constants out of
        // the way without weakening the assertion: the flag is read as data.
        assert!(!std::hint::black_box(TESTNET_PRIVATE_DEDUP_ENABLED));
        assert_eq!(ACTIVATION.height, None);
        assert!(!ACTIVATION.is_active(0));
        assert!(!ACTIVATION.is_active(u64::MAX));
    }
}
