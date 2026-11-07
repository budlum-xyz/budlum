//! `B.U.D. 3.0` sealed-object predicate catalogue (`YK1..YK11`), proof-class
//! witness binding, and blinded consent release checks.
//!
//! WIRING: unwired - staged for post-launch T-Expansion activation (WP-56).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical public testnet chain id where post-launch predicate doors stay closed.
pub const PUBLIC_TESTNET_CHAIN_ID: u64 = 45_261;

/// Domain tag for predicate code-region commitments.
pub const PREDICATE_CODE_DOMAIN: &str = "BDLM_BUD3_PREDICATE_CODE_V1";

/// Domain tag for predicate proof envelopes.
pub const PREDICATE_PROOF_DOMAIN: &str = "BDLM_BUD3_PREDICATE_PROOF_V1";

/// Standard `YK1..YK11` predicate family identifiers for `B.U.D. 3.0` sealed objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PredicateCatalogueId {
    /// `YK1`: payload byte-size range check.
    Yk1ByteSizeRange,
    /// `YK2`: container / file magic signature check.
    Yk2FormatSignature,
    /// `YK3`: raster image dimension check.
    Yk3ImageDimensions,
    /// `YK4`: internal object structural consistency check.
    Yk4ObjectConsistency,
    /// `YK5`: equality against an external digest.
    Yk5ExternalDigestEquality,
    /// `YK6`: non-membership in a prohibited hash list (mandatory before unsealing to public).
    Yk6OutsideDenylist,
    /// `YK7`: dataset tabular/JSON schema conformance.
    Yk7DatasetSchema,
    /// `YK8`: aggregate statistic over sealed rows without revealing plaintext.
    Yk8AggregateStatistic,
    /// `YK9`: origin / hardware capture signature check.
    Yk9OriginSignature,
    /// `YK10`: bounded citation span existence inside plaintext commitment root.
    Yk10CitationSpanExists,
    /// `YK11`: AI model weight Merkle root binding.
    Yk11WeightRootBinding,
}

impl PredicateCatalogueId {
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub const fn code_index(self) -> u8 {
        match self {
            Self::Yk1ByteSizeRange => 1,
            Self::Yk2FormatSignature => 2,
            Self::Yk3ImageDimensions => 3,
            Self::Yk4ObjectConsistency => 4,
            Self::Yk5ExternalDigestEquality => 5,
            Self::Yk6OutsideDenylist => 6,
            Self::Yk7DatasetSchema => 7,
            Self::Yk8AggregateStatistic => 8,
            Self::Yk9OriginSignature => 9,
            Self::Yk10CitationSpanExists => 10,
            Self::Yk11WeightRootBinding => 11,
        }
    }

    /// Computes the deterministic 256-bit code-region identity for this standard predicate.
    ///
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn code_region_root(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PREDICATE_CODE_DOMAIN.as_bytes());
        hasher.update([self.code_index()]);
        hasher.finalize().into()
    }
}

/// Proof class governing polynomial commitment hiding vs open public traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateProofClass {
    /// Public witness only; never permitted when a private witness is attached.
    Open,
    /// Zero-knowledge hiding PCS required whenever sealed plaintext or secret witness is read.
    Hiding,
}

/// Explicit hash-suite identifier carried alongside every 256-bit commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentHashSuite {
    PoseidonG12V1,
    Sha3_256V1,
}

impl CommitmentHashSuite {
    const fn tag(self) -> u8 {
        match self {
            Self::PoseidonG12V1 => 1,
            Self::Sha3_256V1 => 2,
        }
    }
}

/// 256-bit suite-tagged commitment (never truncated to 64 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteBoundCommitment256 {
    pub suite: CommitmentHashSuite,
    pub digest: [u8; 32],
}

/// Predicate proof envelope binding a `B.U.D. 3.0` sealed object commitment,
/// predicate code root, chain context, and proof class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateProofEnvelope {
    pub chain_id: u64,
    pub request_nonce: [u8; 32],
    pub predicate: PredicateCatalogueId,
    pub code_root: [u8; 32],
    pub proof_class: PredicateProofClass,
    pub touches_private_witness: bool,
    pub object_commitment: SuiteBoundCommitment256,
    pub public_output_commitment: SuiteBoundCommitment256,
    pub proof_seal: [u8; 32],
}

impl PredicateProofEnvelope {
    /// Computes the expected domain-separated seal for deterministic replay/tamper checks.
    ///
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn expected_seal(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PREDICATE_PROOF_DOMAIN.as_bytes());
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.request_nonce);
        hasher.update([self.predicate.code_index()]);
        hasher.update(self.code_root);
        let class_byte = match self.proof_class {
            PredicateProofClass::Open => 0_u8,
            PredicateProofClass::Hiding => 1_u8,
        };
        hasher.update([class_byte, u8::from(self.touches_private_witness)]);
        hasher.update([self.object_commitment.suite.tag()]);
        hasher.update(self.object_commitment.digest);
        hasher.update([self.public_output_commitment.suite.tag()]);
        hasher.update(self.public_output_commitment.digest);
        hasher.finalize().into()
    }
}

/// Checks whether a predicate proof envelope satisfies proof-class, hash-suite,
/// replay-context, and chain-gate rules.
///
/// WIRING: exposed for post-launch T-Expansion activation.
pub fn verify_predicate_envelope(
    active_chain_id: u64,
    activation_enabled: bool,
    envelope: &PredicateProofEnvelope,
) -> Result<(), &'static str> {
    if active_chain_id == PUBLIC_TESTNET_CHAIN_ID && !activation_enabled {
        return Err("predicate_door_closed_on_testnet");
    }
    if envelope.chain_id != active_chain_id {
        return Err("predicate_chain_id_mismatch");
    }
    if envelope.touches_private_witness && envelope.proof_class != PredicateProofClass::Hiding {
        return Err("proof_class_mismatch_for_private_witness");
    }
    if envelope.code_root != envelope.predicate.code_region_root() {
        return Err("predicate_code_root_mismatch");
    }
    if envelope.object_commitment.digest == [0_u8; 32]
        || envelope.public_output_commitment.digest == [0_u8; 32]
    {
        return Err("zero_commitment_rejected");
    }
    if envelope.proof_seal != envelope.expected_seal() {
        return Err("predicate_proof_seal_invalid");
    }
    Ok(())
}

/// Enforces that transitioning a sealed object to public visibility carries a
/// verified `YK6` (`Yk6OutsideDenylist`) proof, and key release carries a
/// blinded consent commitment with no open identity bytes.
///
/// WIRING: exposed for post-launch T-Expansion activation.
pub fn check_unseal_or_key_release_guard(
    is_public_transition: bool,
    yk6_verified: bool,
    blinded_consent_commitment: Option<&SuiteBoundCommitment256>,
    open_identity_attached: bool,
) -> Result<(), &'static str> {
    if open_identity_attached {
        return Err("consent_record_contains_open_identity");
    }
    if is_public_transition && !yk6_verified {
        return Err("public_transition_requires_yk6_proof");
    }
    let Some(consent) = blinded_consent_commitment else {
        return Err("key_release_requires_blinded_consent_proof");
    };
    if consent.digest == [0_u8; 32] {
        return Err("empty_blinded_consent_commitment");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope(predicate: PredicateCatalogueId, chain_id: u64) -> PredicateProofEnvelope {
        let mut env = PredicateProofEnvelope {
            chain_id,
            request_nonce: [0x42; 32],
            predicate,
            code_root: predicate.code_region_root(),
            proof_class: PredicateProofClass::Hiding,
            touches_private_witness: true,
            object_commitment: SuiteBoundCommitment256 {
                suite: CommitmentHashSuite::PoseidonG12V1,
                digest: [0xAA; 32],
            },
            public_output_commitment: SuiteBoundCommitment256 {
                suite: CommitmentHashSuite::PoseidonG12V1,
                digest: [0xBB; 32],
            },
            proof_seal: [0_u8; 32],
        };
        env.proof_seal = env.expected_seal();
        env
    }

    #[test]
    fn yk1_to_yk11_code_roots_are_distinct_and_closed_on_testnet_by_default() {
        let all = [
            PredicateCatalogueId::Yk1ByteSizeRange,
            PredicateCatalogueId::Yk2FormatSignature,
            PredicateCatalogueId::Yk3ImageDimensions,
            PredicateCatalogueId::Yk4ObjectConsistency,
            PredicateCatalogueId::Yk5ExternalDigestEquality,
            PredicateCatalogueId::Yk6OutsideDenylist,
            PredicateCatalogueId::Yk7DatasetSchema,
            PredicateCatalogueId::Yk8AggregateStatistic,
            PredicateCatalogueId::Yk9OriginSignature,
            PredicateCatalogueId::Yk10CitationSpanExists,
            PredicateCatalogueId::Yk11WeightRootBinding,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i].code_region_root(), all[j].code_region_root());
            }
        }

        let env_testnet = sample_envelope(
            PredicateCatalogueId::Yk8AggregateStatistic,
            PUBLIC_TESTNET_CHAIN_ID,
        );
        assert_eq!(
            verify_predicate_envelope(PUBLIC_TESTNET_CHAIN_ID, false, &env_testnet),
            Err("predicate_door_closed_on_testnet")
        );
        assert!(verify_predicate_envelope(PUBLIC_TESTNET_CHAIN_ID, true, &env_testnet).is_ok());
    }

    #[test]
    fn proof_class_witness_binding_and_consent_key_release_guards_hold() {
        let mut bad_class = sample_envelope(PredicateCatalogueId::Yk6OutsideDenylist, 999);
        bad_class.proof_class = PredicateProofClass::Open;
        bad_class.proof_seal = bad_class.expected_seal();
        assert_eq!(
            verify_predicate_envelope(999, true, &bad_class),
            Err("proof_class_mismatch_for_private_witness")
        );

        let mut replayed = sample_envelope(PredicateCatalogueId::Yk8AggregateStatistic, 999);
        assert!(verify_predicate_envelope(999, true, &replayed).is_ok());
        assert_eq!(
            verify_predicate_envelope(1000, true, &replayed),
            Err("predicate_chain_id_mismatch")
        );
        replayed.public_output_commitment.digest[0] ^= 0x01;
        assert_eq!(
            verify_predicate_envelope(999, true, &replayed),
            Err("predicate_proof_seal_invalid")
        );

        let consent = SuiteBoundCommitment256 {
            suite: CommitmentHashSuite::PoseidonG12V1,
            digest: [0x77; 32],
        };
        assert_eq!(
            check_unseal_or_key_release_guard(true, false, Some(&consent), false),
            Err("public_transition_requires_yk6_proof")
        );
        assert_eq!(
            check_unseal_or_key_release_guard(false, false, None, false),
            Err("key_release_requires_blinded_consent_proof")
        );
        assert_eq!(
            check_unseal_or_key_release_guard(false, false, Some(&consent), true),
            Err("consent_record_contains_open_identity")
        );
        assert!(check_unseal_or_key_release_guard(true, true, Some(&consent), false).is_ok());
    }
}
