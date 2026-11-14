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
