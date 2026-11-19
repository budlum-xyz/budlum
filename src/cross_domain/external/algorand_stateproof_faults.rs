//! WIRING: unwired - standalone Algorand `StateProof` double-signing equivocation
//! verifier awaits the governance-gated external slashing intake door.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{
    algorand_pubkey_commitment, algorand_voter_leaf_hash, fold_checked_merkle,
    stateproof_sign_digest, AlgorandStateProofMessage, AlgorandVoterLeaf, AlgorandVoterReveal,
    PinnedAlgorandVerifier, VOTER_NODE_TAG,
};
use crate::cross_domain::external::spec::AdapterError;

/// Accountable equivocation evidence showing a committed voter signed two
/// conflicting `StateProof` messages over overlapping rounds in one interval.
///
/// WIRING: exposed for Algorand double-signing slashing intake surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorandEquivocationProof {
    /// First signed `StateProof` message.
    pub message_a: AlgorandStateProofMessage,
    /// Voter reveal + ML-DSA-65 signature over `message_a`.
    pub reveal_a: AlgorandVoterReveal,
    /// Conflicting second `StateProof` message.
    pub message_b: AlgorandStateProofMessage,
    /// ML-DSA-65 signature by the exact same voter key over `message_b`.
    pub sig_b: Vec<u8>,
}

/// Verify an [`AlgorandEquivocationProof`] against `pinned`, returning the
/// equivocating voter's proven stake weight (`upper - lower`) on success.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the messages do not conflict, do not overlap
/// in attested rounds, fail voter Merkle membership, or fail ML-DSA-65 checks.
///
/// Convenience: exposed for governance-gated Algorand equivocation slashing.
pub fn verify_algorand_equivocation(
    network: &str,
    pinned: &PinnedAlgorandVerifier,
    proof: &AlgorandEquivocationProof,
) -> Result<u128, AdapterError> {
    let a = &proof.message_a;
    let b = &proof.message_b;
    if !bool::from(
        a.genesis_hash
            .as_slice()
            .ct_eq(pinned.genesis_hash.as_slice()),
    ) || !bool::from(
        b.genesis_hash
            .as_slice()
            .ct_eq(pinned.genesis_hash.as_slice()),
    ) || a.interval_index != pinned.interval_index
        || b.interval_index != pinned.interval_index
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation messages do not match pinned genesis/interval".into(),
        });
    }
    if a.first_attested_round > a.last_attested_round
        || b.first_attested_round > b.last_attested_round
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation message has inverted round range".into(),
        });
    }
    let overlaps = a.first_attested_round <= b.last_attested_round
        && b.first_attested_round <= a.last_attested_round;
    if !overlaps {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation messages cover disjoint round intervals".into(),
        });
    }
    let digest_a = a.digest();
    let digest_b = b.digest();
    if bool::from(digest_a.as_slice().ct_eq(digest_b.as_slice())) {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation proof submits identical messages".into(),
        });
    }

    let rev = &proof.reveal_a;
    if rev.lower_weight >= rev.upper_weight || rev.upper_weight > pinned.total_weight {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation reveal has invalid weight bounds".into(),
        });
    }
    let leaf = AlgorandVoterLeaf {
        position: rev.position,
        lower_weight: rev.lower_weight,
        upper_weight: rev.upper_weight,
        key_first_round: rev.key_first_round,
        key_last_round: rev.key_last_round,
        pubkey_commitment: algorand_pubkey_commitment(&rev.mldsa65_pubkey),
    };
    let voter_count =
        usize::try_from(pinned.voter_count).map_err(|_| AdapterError::ConsensusRule {
            rule: "Algorand voter_count overflows usize".into(),
        })?;
    let pos = usize::try_from(rev.position).map_err(|_| AdapterError::ConsensusRule {
        rule: "Algorand voter position overflows usize".into(),
    })?;
    let root = fold_checked_merkle(
        VOTER_NODE_TAG,
        voter_count,
        pos,
        algorand_voter_leaf_hash(&leaf),
        &rev.merkle_path,
    )
    .ok_or_else(|| AdapterError::ConsensusRule {
        rule: "invalid Algorand equivocation Merkle path".into(),
    })?;
    if !bool::from(root.as_slice().ct_eq(pinned.voters_commitment.as_slice())) {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand equivocation voter not committed in voters_commitment".into(),
        });
    }

    let sign_a = stateproof_sign_digest(network, a);
    let sign_b = stateproof_sign_digest(network, b);
    crate::crypto::primitives::PqKeyPair::verify(
        &rev.mldsa65_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &sign_a,
        &rev.mldsa65_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid first ML-DSA-65 signature in Algorand equivocation proof".into(),
    })?;
    crate::crypto::primitives::PqKeyPair::verify(
        &rev.mldsa65_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &sign_b,
        &proof.sig_b,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid second ML-DSA-65 signature in Algorand equivocation proof".into(),
    })?;

    Ok(rev.upper_weight - rev.lower_weight)
}
