//! Slashing evidence format shared across the whole node.
//!
//! This is the single, canonical shape in which a proven offence is reported to
//! the [`PermissionlessRegistry`](super::permissionless::PermissionlessRegistry).
//! The consensus layer produces it, the RPC `slash-evidence-submit` endpoint
//! accepts it, and future domains reuse it verbatim — so the format lives here,
//! not in any one producer.
//!
//! ## Design
//! An evidence item says: *"account `offender`, acting in `role`, committed
//! `condition`, and here is the proof."* The proof is carried as an opaque,
//! condition-specific `proof` payload plus a `verified` provenance flag.
//!
//! Verification is intentionally layered:
//! - Structural validation ([`SlashingReport::validate_shape`]) is
//!   domain-agnostic and always runs.
//! - Cryptographic/consensus validation is done by the *producer* that has the
//!   context to do it (e.g. `PoSEngine::verify_evidence` checks the two block
//!   headers' signatures) which then sets [`ProofProvenance::ConsensusVerified`].
//!   The registry only applies a slash for reports whose provenance it trusts,
//!   so it never has to understand every consensus flavour.

use crate::core::address::Address;
use crate::registry::permissionless::SlashingCondition;
use crate::registry::role::{roles, RoleId};
use serde::{Deserialize, Serialize};

/// Where a piece of evidence's cryptographic verification came from.
///
/// The registry uses this to decide whether it may act on a report without
/// re-implementing consensus-specific checks it cannot perform generically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofProvenance {
    /// Verified by the local consensus engine (signatures/quorum checked).
    ConsensusVerified,
    /// Submitted externally (e.g. via RPC or a remote domain) and NOT yet
    /// cryptographically verified. The registry must not slash on this alone.
    Unverified,
}

/// Opaque, condition-specific proof payload.
///
/// Kept as an enum of the offences we understand today, each carrying the
/// minimal data needed to (re)check the claim. `Other` keeps the format
/// forward-compatible for domains that define new proofs without changing this
/// crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingProof {
    /// Two conflicting signed headers at the same height (equivocation).
    DoubleSign {
        height: u64,
        block_hash_1: String,
        block_hash_2: String,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
    },
    /// Missed duties over a window. `missed`/`expected` bound the fault.
    Liveness {
        window_start_epoch: u64,
        window_end_epoch: u64,
        missed: u64,
        expected: u64,
    },
    /// A domain-defined proof the core does not model; carried opaquely so
    /// other domains can reuse the same envelope.
    Other { tag: String, data: Vec<u8> },
    /// Repeated invalid-signature votes within a single epoch (Task 0.40).
    ///
    /// The consensus layer rejects each cryptographically-invalid vote at
    /// ingest; this proof attests that a validator crossed the per-epoch
    /// `threshold` of such rejected votes — i.e. it is spamming garbage
    /// signatures. `count`/`threshold` bound the offence.
    InvalidSignatureSpam {
        epoch: u64,
        count: u64,
        threshold: u64,
    },
}

impl SlashingProof {
    /// The [`SlashingCondition`] this proof attests to.
    pub fn condition(&self) -> SlashingCondition {
        match self {
            SlashingProof::DoubleSign { .. } => SlashingCondition::DoubleSign,
            SlashingProof::Liveness { .. } => SlashingCondition::LivenessFault,
            SlashingProof::Other { .. } => SlashingCondition::MaliciousBehaviour,
            // Repeated invalid-signature spam is treated as provable malicious
            // behaviour (Task 0.40, approved severity decision: reuse the existing
            // MaliciousBehaviour ratio rather than adding a new one).
            SlashingProof::InvalidSignatureSpam { .. } => SlashingCondition::MaliciousBehaviour,
        }
    }
}

/// A complete, self-describing slashing report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingReport {
    /// Account to be slashed.
    pub offender: Address,
    /// Role under which the offence was committed (validator/verifier/relayer/…).
    pub role: RoleId,
    /// The proof of the offence.
    pub proof: SlashingProof,
    /// Provenance of the proof's verification.
    pub provenance: ProofProvenance,
    /// Who reported it (audit trail; not trusted for authorization).
    pub reporter: Option<Address>,
}

/// Reasons a report is structurally invalid (before any crypto check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The offender address is the zero address.
    ZeroOffender,
    /// A double-sign proof references identical hashes (not conflicting).
    NonConflictingHashes,
    /// A double-sign proof is missing a signature.
    MissingSignature,
    /// A liveness proof claims more missed than expected slots.
    ImpossibleLivenessWindow,
    /// An `Other` proof carries no tag.
    EmptyProofTag,
    /// An invalid-signature-spam proof does not actually cross its threshold
    /// (or the threshold is zero).
    InsufficientInvalidVoteCount,
    /// The registry was asked to act on an unverified report.
    Unverified,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceError::ZeroOffender => write!(f, "offender is the zero address"),
            EvidenceError::NonConflictingHashes => {
                write!(f, "double-sign proof references identical block hashes")
            }
            EvidenceError::MissingSignature => write!(f, "double-sign proof missing a signature"),
            EvidenceError::ImpossibleLivenessWindow => {
                write!(f, "liveness proof claims more missed than expected")
            }
            EvidenceError::EmptyProofTag => write!(f, "opaque proof has an empty tag"),
            EvidenceError::InsufficientInvalidVoteCount => {
                write!(
                    f,
                    "invalid-signature-spam proof does not cross its threshold"
                )
            }
            EvidenceError::Unverified => {
                write!(f, "cannot slash on an unverified evidence report")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

impl SlashingReport {
    pub fn new(
        offender: Address,
        role: RoleId,
        proof: SlashingProof,
        provenance: ProofProvenance,
        reporter: Option<Address>,
    ) -> Self {
        Self {
            offender,
            role,
            proof,
            provenance,
            reporter,
        }
    }

    /// Convenience: a consensus-verified double-sign against the validator role.
    pub fn consensus_double_sign(
        offender: Address,
        height: u64,
        block_hash_1: String,
        block_hash_2: String,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::VALIDATOR,
            SlashingProof::DoubleSign {
                height,
                block_hash_1,
                block_hash_2,
                signature_1,
                signature_2,
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// Convenience: a consensus-verified liveness (downtime) fault.
    #[allow(clippy::too_many_arguments)]
    pub fn consensus_liveness(
        offender: Address,
        role: RoleId,
        window_start_epoch: u64,
        window_end_epoch: u64,
        missed: u64,
        expected: u64,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            role,
            SlashingProof::Liveness {
                window_start_epoch,
                window_end_epoch,
                missed,
                expected,
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// Convenience: a consensus-verified invalid-signature-spam fault (Task 0.40).
    ///
    /// Provenance is `ConsensusVerified` because the node's own consensus layer
    /// cryptographically rejected every one of the `count` votes at ingest — the
    /// count is the node's first-hand observation, not an external claim.
    pub fn consensus_invalid_signature_spam(
        offender: Address,
        role: RoleId,
        epoch: u64,
        count: u64,
        threshold: u64,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            role,
            SlashingProof::InvalidSignatureSpam {
                epoch,
                count,
                threshold,
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// D4/D1: Relayer invalid proof — griefing/fronting/yanlış-relay.
    /// Uses `Other` with tag `relayer_invalid_proof` and maps to MaliciousBehaviour (100% slash in default params).
    /// Per decision reuse_malicious to avoid semver break.
    pub fn consensus_invalid_relay_proof(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::RELAYER,
            SlashingProof::Other {
                tag: "relayer_invalid_proof".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// D4: Attester invalid attestation — supply-chain forged attestation.
    pub fn consensus_invalid_attester_proof(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::ATTESTER,
            SlashingProof::Other {
                tag: "attester_invalid_attestation".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// D4: Content validator invalid validation — SocialFi content forgery.
    pub fn consensus_invalid_content_validation(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::CONTENT_VALIDATOR,
            SlashingProof::Other {
                tag: "content_validator_malicious".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// The condition this report attests to.
    pub fn condition(&self) -> SlashingCondition {
        self.proof.condition()
    }

    /// Domain-agnostic structural validation. Always safe to run anywhere.
    pub fn validate_shape(&self) -> Result<(), EvidenceError> {
        if self.offender == Address::zero() {
            return Err(EvidenceError::ZeroOffender);
        }
        match &self.proof {
            SlashingProof::DoubleSign {
                block_hash_1,
                block_hash_2,
                signature_1,
                signature_2,
                ..
            } => {
                if block_hash_1 == block_hash_2 {
                    return Err(EvidenceError::NonConflictingHashes);
                }
                if signature_1.is_empty() || signature_2.is_empty() {
                    return Err(EvidenceError::MissingSignature);
                }
            }
            SlashingProof::Liveness {
                missed, expected, ..
            } => {
                if missed > expected {
                    return Err(EvidenceError::ImpossibleLivenessWindow);
                }
            }
            SlashingProof::Other { tag, .. } => {
                if tag.is_empty() {
                    return Err(EvidenceError::EmptyProofTag);
                }
            }
            SlashingProof::InvalidSignatureSpam {
                count, threshold, ..
            } => {
                // A spam proof must actually cross its own threshold, and the
                // threshold must be meaningful (non-zero).
                if *threshold == 0 || *count < *threshold {
                    return Err(EvidenceError::InsufficientInvalidVoteCount);
                }
            }
        }
        Ok(())
    }

    /// Whether the registry is allowed to act on this report: it must be both
    /// structurally valid AND consensus-verified. Externally-submitted
    /// (`Unverified`) reports pass structural checks but are not actioned until
    /// the consensus layer confirms them — this is what keeps the permissionless
    /// `slash-evidence-submit` endpoint safe without a whitelist.
    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;
        match self.provenance {
            ProofProvenance::ConsensusVerified => Ok(()),
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn double_sign_shape_ok() {
        let r = SlashingReport::consensus_double_sign(
            addr(1),
            10,
            "aa".into(),
            "bb".into(),
            vec![1],
            vec![2],
            None,
        );
        assert!(r.validate_shape().is_ok());
        assert_eq!(r.condition(), SlashingCondition::DoubleSign);
        assert!(r.is_actionable().is_ok());
    }

    #[test]
    fn identical_hashes_rejected() {
        let r = SlashingReport::consensus_double_sign(
            addr(1),
            10,
            "aa".into(),
            "aa".into(),
            vec![1],
            vec![2],
            None,
        );
        assert_eq!(r.validate_shape(), Err(EvidenceError::NonConflictingHashes));
    }

    #[test]
    fn unverified_is_not_actionable_but_shape_ok() {
        let r = SlashingReport::new(
            addr(1),
            roles::VALIDATOR,
            SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 10,
                missed: 5,
                expected: 10,
            },
            ProofProvenance::Unverified,
            Some(addr(2)),
        );
        assert!(r.validate_shape().is_ok());
        assert_eq!(r.is_actionable(), Err(EvidenceError::Unverified));
    }

    #[test]
    fn zero_offender_rejected() {
        let r = SlashingReport::consensus_double_sign(
            Address::zero(),
            10,
            "aa".into(),
            "bb".into(),
            vec![1],
            vec![2],
            None,
        );
        assert_eq!(r.validate_shape(), Err(EvidenceError::ZeroOffender));
    }

    /// Task 0.17 (security audit §6): pin the invariant that
    /// `SlashingProof::DoubleSign` is labeled as
    /// `SlashingCondition::DoubleSign` and `SlashingProof::Liveness`
    /// is labeled as `SlashingCondition::LivenessFault`, and that
    /// the two helpers (`consensus_double_sign`,
    /// `consensus_liveness`) never cross-wire the proof kind and
    /// the condition label. A regression in either direction
    /// would either under-slash (DoubleSign labeled as
    /// LivenessFault would slash 1% instead of 50%) or over-slash
    /// (Liveness labeled as DoubleSign would slash 50% instead of
    /// 1%).
    #[test]
    fn slashing_proof_condition_invariant_double_sign_vs_liveness() {
        let offender = addr(0x42);
        let r = SlashingReport::consensus_double_sign(
            offender,
            100,
            "h1".into(),
            "h2".into(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            None,
        );
        assert_eq!(r.condition(), SlashingCondition::DoubleSign);

        let r2 =
            SlashingReport::consensus_liveness(offender, roles::VALIDATOR, 10, 20, 5, 10, None);
        assert_eq!(r2.condition(), SlashingCondition::LivenessFault);
    }
}
