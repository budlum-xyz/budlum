//! Slashing evidence format.
//!
//! The single, canonical shape in which a proven offence is reported.
//! Carries an opaque, condition-specific proof payload plus a verified
//! provenance flag.

use crate::address::Address;
use crate::registry::SlashingCondition;
use crate::role::RoleId;
use serde::{Deserialize, Serialize};

/// Where a piece of evidence's verification came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofProvenance {
    /// Verified by the local consensus engine.
    ConsensusVerified,
    /// Submitted externally and NOT yet verified. The registry must not slash.
    Unverified,
}

/// Opaque, condition-specific proof payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingProof {
    /// Two conflicting signed headers at the same height.
    DoubleSign {
        height: u64,
        block_hash_1: String,
        block_hash_2: String,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
    },
    /// Missed duties over a window.
    Liveness {
        window_start_epoch: u64,
        window_end_epoch: u64,
        missed: u64,
        expected: u64,
    },
    /// A domain-defined proof carried opaquely.
    Other { tag: String, data: Vec<u8> },
    /// Repeated invalid-signature votes within a single epoch.
    InvalidSignatureSpam {
        epoch: u64,
        count: u64,
        threshold: u64,
    },
}

impl SlashingProof {
    pub fn condition(&self) -> SlashingCondition {
        match self {
            SlashingProof::DoubleSign { .. } => SlashingCondition::DoubleSign,
            SlashingProof::Liveness { .. } => SlashingCondition::LivenessFault,
            SlashingProof::Other { .. } => SlashingCondition::MaliciousBehaviour,
            SlashingProof::InvalidSignatureSpam { .. } => SlashingCondition::MaliciousBehaviour,
        }
    }
}

/// A complete, self-describing slashing report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingReport {
    pub offender: Address,
    pub role: RoleId,
    pub proof: SlashingProof,
    pub provenance: ProofProvenance,
    pub reporter: Option<Address>,
}

/// Reasons a report is structurally invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    ZeroOffender,
    NonConflictingHashes,
    MissingSignature,
    ImpossibleLivenessWindow,
    EmptyProofTag,
    InsufficientInvalidVoteCount,
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
            EvidenceError::InsufficientInvalidVoteCount => write!(
                f,
                "invalid-signature-spam proof does not cross its threshold"
            ),
            EvidenceError::Unverified => write!(f, "cannot slash on an unverified evidence report"),
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

    pub fn condition(&self) -> SlashingCondition {
        self.proof.condition()
    }

    /// Domain-agnostic structural validation.
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
                if *threshold == 0 || *count < *threshold {
                    return Err(EvidenceError::InsufficientInvalidVoteCount);
                }
            }
        }
        Ok(())
    }

    /// Whether the registry is allowed to act on this report.
    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;
        match self.provenance {
            ProofProvenance::ConsensusVerified => Ok(()),
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),
        }
    }

    /// D4/D1: Relayer invalid proof — griefing/fronting/wrong-relay
    pub fn consensus_invalid_relay_proof(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            crate::role::roles::RELAYER,
            SlashingProof::Other {
                tag: "relayer_invalid_proof".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// D4: Attester invalid attestation
    pub fn consensus_invalid_attester_proof(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            crate::role::roles::ATTESTER,
            SlashingProof::Other {
                tag: "attester_invalid_attestation".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// D4: Content validator invalid validation
    pub fn consensus_invalid_content_validation(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            crate::role::roles::CONTENT_VALIDATOR,
            SlashingProof::Other {
                tag: "content_validator_malicious".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::roles;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn double_sign_shape_ok() {
        let r = SlashingReport::new(
            addr(1),
            roles::MASTER_VERIFIER,
            SlashingProof::DoubleSign {
                height: 10,
                block_hash_1: "aa".into(),
                block_hash_2: "bb".into(),
                signature_1: vec![1],
                signature_2: vec![2],
            },
            ProofProvenance::ConsensusVerified,
            None,
        );
        assert!(r.validate_shape().is_ok());
        assert!(r.is_actionable().is_ok());
        assert_eq!(r.condition(), SlashingCondition::DoubleSign);
    }

    #[test]
    fn identical_hashes_rejected() {
        let r = SlashingReport::new(
            addr(1),
            roles::MASTER_VERIFIER,
            SlashingProof::DoubleSign {
                height: 10,
                block_hash_1: "aa".into(),
                block_hash_2: "aa".into(),
                signature_1: vec![1],
                signature_2: vec![2],
            },
            ProofProvenance::ConsensusVerified,
            None,
        );
        assert_eq!(r.validate_shape(), Err(EvidenceError::NonConflictingHashes));
    }

    #[test]
    fn unverified_is_not_actionable() {
        let r = SlashingReport::new(
            addr(1),
            roles::ATTESTER,
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
        let r = SlashingReport::new(
            Address::zero(),
            roles::RELAYER,
            SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 10,
                missed: 5,
                expected: 10,
            },
            ProofProvenance::ConsensusVerified,
            None,
        );
        assert_eq!(r.validate_shape(), Err(EvidenceError::ZeroOffender));
    }
}
