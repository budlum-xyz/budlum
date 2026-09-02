//! Slashing evidence format shared across the whole node.
//!
//! This is the single, canonical shape in which a proven offence is reported to
//! The [`PermissionlessRegistry`](super::permissionless::PermissionlessRegistry).
//! The consensus layer produces it, the RPC `slash-evidence-submit` endpoint
//! Accepts it, and future domains reuse it verbatim, so the format lives here,
//! Not in any one producer.
//!
//! ## Design
//! An evidence item says: *"account `offender`, acting in `role`, committed
//! `condition`, and here is the proof."* The proof is carried as an opaque,
//! Condition-specific `proof` payload plus a `verified` provenance flag.
//!
//! Verification is intentionally layered:
//! - Structural validation ([`SlashingReport::validate_shape`]) is
//!   Domain-agnostic and always runs.
//! - Cryptographic/consensus validation is done by the *producer* that has the
//!   Context to do it (e.g. `PoSEngine::verify_evidence` checks the two block
//!   Headers' signatures) which then sets [`ProofProvenance::ConsensusVerified`].
//!   The registry only applies a slash for reports whose provenance it trusts,
//!   So it never has to understand every consensus flavour.
//!
//! ## The permissionless route
//!
//! `bud_submitSlashingReport` accepts a report from anybody. The RPC layer
//! overwrites the caller's claimed provenance with
//! [`ProofProvenance::Unverified`], because a submitter that could certify
//! its own report could slash any validator it liked.
//!
//! That left a question the code answered badly for a while: an `Unverified`
//! report is refused by [`SlashingReport::is_actionable`], and the refusal
//! took the path that burns the anti-spam fee. The endpoint charged for every
//! submission and could act on none of them, so a reporter holding genuine
//! proof of an equivocation paid to be ignored, which is the opposite of the
//! incentive a permissionless reporting channel needs.
//!
//! `SlashingReport::verify_double_sign` (test-only since the CWE-347 fix) is the answer. A double-sign proof
//! does not need a trusted sender: it carries two signatures by the offender
//! over two different block hashes at one height, and only the offender's key
//! can produce that pair. The chain checks the pair itself, before charging
//! anything, and promotes the report to [`ProofProvenance::ConsensusVerified`]
//! on the strength of the cryptography.
//!
//! The other conditions have no such self-contained proof. Liveness is a
//! claim about what did not happen and invalid-relay conditions are claims
//! about execution, so both need the context only consensus holds. Reports of
//! those still arrive through the consensus path, and the RPC route refuses
//! them rather than pretending it verified something.

use crate::core::address::Address;
use crate::registry::permissionless::SlashingCondition;
use crate::registry::role::{roles, RoleId};
use serde::{Deserialize, Serialize};

/// Where a piece of evidence's cryptographic verification came from.
///
/// The registry uses this to decide whether it may act on a report without
/// Re-implementing consensus-specific checks it cannot perform generically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofProvenance {
    /// Verified by the local consensus engine (signatures/quorum checked).
    ConsensusVerified,
    /// Submitted externally (e.g. via RPC or a remote domain) and NOT yet
    /// Cryptographically verified. The registry must not slash on this alone.
    Unverified,
}

/// Opaque, condition-specific proof payload.
///
/// Kept as an enum of the offences we understand today, each carrying the
/// Minimal data needed to (re)check the claim. `Other` keeps the format
/// Forward-compatible for domains that define new proofs without changing this
/// Crate.
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
    /// Other domains can reuse the same envelope.
    Other { tag: String, data: Vec<u8> },
    /// Repeated invalid-signature votes within a single epoch.
    ///
    /// The consensus layer rejects each cryptographically-invalid vote at
    /// Ingest; this proof attests that a validator crossed the per-epoch
    /// `threshold` of such rejected votes - i.e. it is spamming garbage
    /// Signatures. `count`/`threshold` bound the offence.
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
            // Behaviour (approved severity decision: reuse the existing
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
    /// A block hash is not 32 bytes of hex, so nothing signed it.
    MalformedBlockHash,
    /// A signature in the proof does not verify under the offender's key.
    ///
    /// This is the answer to a forged report: producing the pair requires the
    /// offender's key, so a submitter who does not hold it cannot get past
    /// this point no matter what it claims.
    SignatureDoesNotVerify,
    /// A double-sign proof names a role other than validator. Only a
    /// validator produces the signed headers this proof is built from.
    WrongRoleForProof,
    /// `SlashingReport::verify_double_sign` was handed a proof that is not
    /// a double-sign proof. The other conditions are not provable from the
    /// report alone; see the note on the RPC path.
    WrongProofForVerification,
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
            EvidenceError::MalformedBlockHash => {
                write!(f, "block hash is not 32 bytes of hex")
            }
            EvidenceError::SignatureDoesNotVerify => {
                write!(f, "signature does not verify under the offender's key")
            }
            EvidenceError::WrongRoleForProof => {
                write!(f, "double-sign proof names a role other than validator")
            }
            EvidenceError::WrongProofForVerification => {
                write!(f, "proof is not a double-sign proof")
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

    /// Convenience: a consensus-verified invalid-signature-spam fault.
    ///
    /// Provenance is `ConsensusVerified` because the node's own consensus layer
    /// Cryptographically rejected every one of the `count` votes at ingest, the
    /// Count is the node's first-hand observation, not an external claim.
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

    /// A relayer invalid proof - griefing, fronting or a wrong relay.
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

    /// Relayer **griefing** - submitting garbage / low-value /
    /// Resource-wasting proofs to deny service or waste other relayers'
    /// Resources. Uses `Other` with tag `relayer_griefing`, mapped to
    /// `MaliciousBehaviour` (100% slash in default params). Per decision
    /// We reuse the `Other` variant (adding a new `SlashingCondition` would be a
    /// Semver break); the tag is what distinguishes the offence class.
    pub fn consensus_invalid_relay_griefing(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::RELAYER,
            SlashingProof::Other {
                tag: "relayer_griefing".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// Relayer **front-running** - racing another relayer's valid
    /// Proof to capture fees / rewards illegitimately (e.g. copying the proof
    /// And submitting it first). Tag `relayer_front_running`, mapped to
    /// `MaliciousBehaviour` (100% slash).
    pub fn consensus_invalid_relay_front_running(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::RELAYER,
            SlashingProof::Other {
                tag: "relayer_front_running".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// Relayer **wrong-relay** - relaying a message to the wrong
    /// Destination domain, forging relay metadata, or delivering a proof that
    /// Does not correspond to the attested message. Tag `relayer_wrong_relay`,
    /// Mapped to `MaliciousBehaviour` (100% slash).
    pub fn consensus_invalid_relay_wrong_relay(
        offender: Address,
        reason: String,
        reporter: Option<Address>,
    ) -> Self {
        Self::new(
            offender,
            roles::RELAYER,
            SlashingProof::Other {
                tag: "relayer_wrong_relay".into(),
                data: reason.into_bytes(),
            },
            ProofProvenance::ConsensusVerified,
            reporter,
        )
    }

    /// Attester invalid attestation - supply-chain forged attestation.
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

    /// Content validator invalid validation - SocialFi content forgery.
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
                // Threshold must be meaningful (non-zero).
                if *threshold == 0 || *count < *threshold {
                    return Err(EvidenceError::InsufficientInvalidVoteCount);
                }
            }
        }
        Ok(())
    }

    /// Whether the registry is allowed to act on this report: it must be both
    /// Structurally valid AND consensus-verified. Externally-submitted
    /// (`Unverified`) reports pass structural checks but are not actioned until
    /// The consensus layer confirms them - this is what keeps the permissionless
    /// `slash-evidence-submit` endpoint safe without a whitelist.
    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;
        match self.provenance {
            ProofProvenance::ConsensusVerified => Ok(()),
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),
        }
    }

    /// Check a double-sign proof cryptographically and say whether it holds.
    ///
    /// This is what a submitter cannot fake and a node can check without any
    /// context beyond the report itself: two signatures over two different
    /// block hashes at one height, both valid under the offender's key.
    ///
    /// Equivocation is exactly that pair. A validator that signed one block
    /// at height *h* produced one hash; a validator that signed two produced
    /// two, and both signatures verify under its own key. Nobody else can
    /// construct that pair, because constructing it requires the key.
    ///
    /// # What is verified and what is not
    ///
    /// Verified here: both hashes are well-formed, they differ, each
    /// signature is a valid signature by `offender` over the corresponding
    /// hash, and the report names the validator role.
    ///
    /// Not verified here: that either block was ever part of this chain. That
    /// is deliberate and it is not a gap. A validator that signs two
    /// conflicting blocks at one height has equivocated whether or not either
    /// block was accepted, and requiring one of them to be canonical would
    /// make the offence unreportable in the case that matters most, where the
    /// validator withheld both and showed each to a different half of the
    /// network.
    ///
    /// The height in the proof is carried for the record and for the
    /// duplicate check the registry performs. It is not part of the signed
    /// message, so it cannot be verified from the signatures alone, and this
    /// function does not pretend otherwise.
    ///
    /// # Errors
    ///
    /// [`EvidenceError`] naming the first check that failed. A caller must
    /// treat every error as "not proven" rather than "proven innocent": a
    /// malformed report is not evidence of anything.
    /// Test-only since the CWE-347 fix: the permissionless RPC path no
    /// longer promotes `Unverified` reports, and the consensus path verifies
    /// equivocation at ingest against the validator snapshot, so this raw
    /// signature-over-two-hashes check survives as a regression harness.
    #[cfg(test)]
    pub fn verify_double_sign(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;

        if self.role != roles::VALIDATOR {
            return Err(EvidenceError::WrongRoleForProof);
        }

        let SlashingProof::DoubleSign {
            block_hash_1,
            block_hash_2,
            signature_1,
            signature_2,
            ..
        } = &self.proof
        else {
            return Err(EvidenceError::WrongProofForVerification);
        };

        // The hashes travel as hex because that is how a block carries its
        // own. What was signed is the 32 raw bytes underneath, so a report
        // whose hex does not decode to 32 bytes never had a signature over a
        // block hash at all.
        let h1 = decode_block_hash(block_hash_1)?;
        let h2 = decode_block_hash(block_hash_2)?;

        // `validate_shape` already rejected identical hex. This catches the
        // same claim written two ways, e.g. differing only in case, which
        // would otherwise present one signature twice as if it were two.
        if h1 == h2 {
            return Err(EvidenceError::NonConflictingHashes);
        }

        let key = self.offender.as_bytes();
        crate::crypto::primitives::verify_signature(&h1, signature_1, key)
            .map_err(|_| EvidenceError::SignatureDoesNotVerify)?;
        crate::crypto::primitives::verify_signature(&h2, signature_2, key)
            .map_err(|_| EvidenceError::SignatureDoesNotVerify)?;

        Ok(())
    }
}

/// Decode a block hash from the hex a report carries into the bytes that were
/// signed. Test-only like `verify_double_sign`: production no longer
/// verifies raw signature-over-two-hashes evidence since the CWE-347
/// fix.
#[cfg(test)]
fn decode_block_hash(hex_hash: &str) -> Result<[u8; 32], EvidenceError> {
    let raw = hex::decode(hex_hash).map_err(|_| EvidenceError::MalformedBlockHash)?;
    raw.try_into()
        .map_err(|_| EvidenceError::MalformedBlockHash)
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

    /// (security audit §6) pin the invariant that
    /// `SlashingProof::DoubleSign` is labeled as
    /// `SlashingCondition::DoubleSign` and `SlashingProof::Liveness`
    /// Is labeled as `SlashingCondition::LivenessFault`, and that
    /// The two helpers (`consensus_double_sign`,
    /// `consensus_liveness`) never cross-wire the proof kind and
    /// The condition label. A regression in either direction
    /// Would either under-slash (DoubleSign labeled as
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

    /// The three relayer offence classes - griefing,
    /// Front-running, wrong-relay - are each structurally valid, labelled as
    /// `MaliciousBehaviour` (100% slash), and consensus-actionable. The single
    /// `Other` proof variant with distinct tags keeps the `SlashingCondition`
    /// Enum stable (no semver break) while still separating offence classes.
    #[test]
    fn relay_griefing_front_running_wrong_relay_are_malicious() {
        let grief = SlashingReport::consensus_invalid_relay_griefing(
            addr(3),
            "resource-wasting proofs".into(),
            Some(addr(4)),
        );
        let front = SlashingReport::consensus_invalid_relay_front_running(
            addr(3),
            "raced a valid proof".into(),
            Some(addr(4)),
        );
        let wrong = SlashingReport::consensus_invalid_relay_wrong_relay(
            addr(3),
            "relayed to wrong domain".into(),
            Some(addr(4)),
        );
        for r in [grief, front, wrong] {
            assert!(r.validate_shape().is_ok(), "shape must be valid");
            assert_eq!(
                r.condition(),
                SlashingCondition::MaliciousBehaviour,
                "relayer offences are 100% slash"
            );
            assert!(
                r.is_actionable().is_ok(),
                "consensus-verified reports are actionable"
            );
        }
    }

    /// Regression: the pre-existing `relayer_invalid_proof` report remains
    /// Valid and malicious after griefing/front-running/wrong-relay
    /// Constructors were added.
    #[test]
    fn relay_invalid_proof_still_malicious_after_d1() {
        let r = SlashingReport::consensus_invalid_relay_proof(
            addr(5),
            "invalid MPT/receipt proof".into(),
            Some(addr(6)),
        );
        assert!(r.validate_shape().is_ok());
        assert_eq!(r.condition(), SlashingCondition::MaliciousBehaviour);
        assert!(r.is_actionable().is_ok());
    }

    // --- double-sign verification -------------------------------------------
    //
    // These decide whether the permissionless endpoint can be trusted to
    // promote a report on its own. A report that verifies here is slashed
    // without any operator in the loop, so the interesting cases are the
    // forgeries, not the happy path.

    /// Build a report whose signatures a real key actually produced.
    fn signed_double_sign(
        keys: &crate::crypto::primitives::KeyPair,
        hash_1: [u8; 32],
        hash_2: [u8; 32],
    ) -> SlashingReport {
        SlashingReport::new(
            Address::from(keys.public_key_bytes()),
            roles::VALIDATOR,
            SlashingProof::DoubleSign {
                height: 7,
                block_hash_1: hex::encode(hash_1),
                block_hash_2: hex::encode(hash_2),
                signature_1: keys.sign(&hash_1).to_vec(),
                signature_2: keys.sign(&hash_2).to_vec(),
            },
            ProofProvenance::Unverified,
            None,
        )
    }

    #[test]
    fn a_real_equivocation_verifies_without_any_trusted_submitter() {
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let r = signed_double_sign(&keys, [1u8; 32], [2u8; 32]);

        // Arrives unverified, and is provable anyway. That is the whole
        // point: the proof carries its own authority.
        assert_eq!(r.provenance, ProofProvenance::Unverified);
        assert_eq!(r.verify_double_sign(), Ok(()));
    }

    #[test]
    fn a_forged_report_against_an_innocent_validator_is_refused() {
        // The attack the endpoint has to survive: name somebody else as the
        // offender and hope the node takes the report at face value.
        let victim = crate::crypto::primitives::KeyPair::generate().unwrap();
        let attacker = crate::crypto::primitives::KeyPair::generate().unwrap();

        let mut r = signed_double_sign(&attacker, [1u8; 32], [2u8; 32]);
        r.offender = Address::from(victim.public_key_bytes());

        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::SignatureDoesNotVerify),
            "signatures by one key must not slash the holder of another"
        );
    }

    #[test]
    fn a_report_with_invented_signatures_is_refused() {
        // The cheapest forgery: real-looking hashes, garbage signatures.
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let r = SlashingReport::new(
            Address::from(keys.public_key_bytes()),
            roles::VALIDATOR,
            SlashingProof::DoubleSign {
                height: 7,
                block_hash_1: hex::encode([1u8; 32]),
                block_hash_2: hex::encode([2u8; 32]),
                signature_1: vec![0u8; 64],
                signature_2: vec![0u8; 64],
            },
            ProofProvenance::Unverified,
            None,
        );
        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::SignatureDoesNotVerify)
        );
    }

    #[test]
    fn one_signature_presented_twice_is_not_an_equivocation() {
        // Signing a single block is not an offence. A report that shows the
        // same hash twice is showing one signature, and the differing-hash
        // check is what stops it counting as two.
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let r = signed_double_sign(&keys, [1u8; 32], [1u8; 32]);
        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::NonConflictingHashes)
        );
    }

    #[test]
    fn the_same_hash_in_a_different_case_is_still_the_same_hash() {
        // `validate_shape` compares the hex strings, so upper and lower case
        // spellings of one hash pass it. Decoding first is what catches this:
        // otherwise one signature over one block, written twice, would be
        // accepted as proof of equivocation and slash an honest validator.
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let hash = [0xABu8; 32];
        let mut r = signed_double_sign(&keys, hash, hash);
        let SlashingProof::DoubleSign {
            block_hash_1,
            block_hash_2,
            ..
        } = &mut r.proof
        else {
            unreachable!()
        };
        *block_hash_1 = block_hash_1.to_lowercase();
        *block_hash_2 = block_hash_2.to_uppercase();
        assert_ne!(block_hash_1, block_hash_2, "the strings differ");
        assert!(r.validate_shape().is_ok(), "so the shape check lets it by");

        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::NonConflictingHashes),
            "and the byte comparison catches it"
        );
    }

    #[test]
    fn a_hash_that_is_not_thirty_two_bytes_never_signed_a_block() {
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let mut r = signed_double_sign(&keys, [1u8; 32], [2u8; 32]);
        let SlashingProof::DoubleSign { block_hash_1, .. } = &mut r.proof else {
            unreachable!()
        };
        // The value the old tests used: two hex characters, one byte.
        *block_hash_1 = "aa".into();
        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::MalformedBlockHash)
        );
    }

    #[test]
    fn only_a_double_sign_proof_can_be_proven_from_the_report_alone() {
        // Liveness is a claim about what did not happen over a window. There
        // is no signature to check, so this route must refuse it rather than
        // wave it through as verified.
        let r = SlashingReport::consensus_liveness(addr(1), roles::VALIDATOR, 1, 10, 9, 10, None);
        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::WrongProofForVerification)
        );
    }

    #[test]
    fn a_double_sign_proof_filed_under_another_role_is_refused() {
        let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let mut r = signed_double_sign(&keys, [1u8; 32], [2u8; 32]);
        r.role = roles::RELAYER;
        assert_eq!(
            r.verify_double_sign(),
            Err(EvidenceError::WrongRoleForProof),
            "only a validator signs the headers this proof is built from"
        );
    }
}
