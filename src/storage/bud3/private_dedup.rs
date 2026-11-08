//! Private cross-owner deduplication experiments.
//!
//! `threshold` retains the existing fail-closed transcript API. `committee`
//! preserves the source branch's separate committee/epoch-batch model. Neither
//! model is a production OPRF or ownership-proof authorization boundary, and
//! testnet submission remains closed.

pub mod committee;
pub mod threshold;

pub use threshold::{
    combine_threshold_oprf_shares, BlindedDedupRecord, OwnershipProofBundle,
    PrivateDedupEngine, PrivateDedupError, SealedDedupSubmission, ThresholdOprfShare,
    DEFAULT_OPRF_THRESHOLD, MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH,
    TESTNET_PRIVATE_DEDUP_ENABLED,
};
pub use committee::{
    padme_bucket_bytes, OprfPartialShare, OwnershipProof, PrivateDedupActivation,
    PublicEpochDedupSummary, PublicSealedNftView, ThresholdOprfCommittee, ACTIVATION,
    MIN_SEALED_BUCKET_BYTES,
    DEFAULT_OPRF_RATE_LIMIT_PER_EPOCH, PRIVATE_DEDUP_OPRF_TAG,
    PRIVATE_DEDUP_OWNERSHIP_TAG, PRIVATE_DEDUP_RECORD_TAG,
};
