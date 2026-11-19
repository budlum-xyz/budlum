//! WIRING: unwired - HotStuff pacemaker timeout-certificate and double-vote
//! equivocation verifiers await the governance-gated external slashing intake door.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{
    hotstuff_timeout_sign_bytes, hotstuff_vote_sign_bytes, HotStuffTimeoutCertificate,
    HotStuffVoteSig, PinnedHotStuffCommittee, MAX_HOTSTUFF_COMMITTEE,
};
use crate::cross_domain::external::spec::AdapterError;

/// Verify a `HotStuffTimeoutCertificate` against `pinned` and return the
/// verified `(max_high_qc_view, signed_stake, all_pq)` tuple.
///
/// # Errors
///
/// Returns [`AdapterError`] if epoch, view, committee bounds, signer
/// uniqueness, Ed25519 or ML-DSA-65 signatures, `max_high_qc_view`, or the
/// strict 2/3 stake threshold fail.
///
/// Convenience: exposed for HotStuff view-change safety auditing and bridges.
pub fn verify_hotstuff_timeout_certificate(
    network: &str,
    pinned: &PinnedHotStuffCommittee,
    tc: &HotStuffTimeoutCertificate,
) -> Result<(u64, u128, bool), AdapterError> {
    if tc.epoch != pinned.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC epoch mismatches pinned committee epoch".into(),
        });
    }
    if tc.view == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC view must be non-zero".into(),
        });
    }
    if pinned.members.is_empty() || pinned.members.len() > MAX_HOTSTUFF_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff committee size outside valid bounds".into(),
        });
    }
    if tc.votes.is_empty() || tc.votes.len() > pinned.members.len() {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC vote count outside [1, committee.len()]".into(),
        });
    }
    let mut member_map = BTreeMap::new();
    let mut total_stake = 0u128;
    for m in &pinned.members {
        if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff committee contains zero pubkey or zero weight".into(),
            });
        }
        if member_map.insert(m.ed25519_pubkey, m).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff committee contains duplicate pubkey".into(),
            });
        }
        total_stake = total_stake
            .checked_add(u128::from(m.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HotStuff committee total stake overflows u128".into(),
            })?;
    }

    let mut seen = BTreeSet::new();
    let mut signed_stake = 0u128;
    let mut observed_max_high_qc = 0u64;
    let mut all_pq = true;

    for v in &tc.votes {
        if !seen.insert(v.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in HotStuff TimeoutCertificate".into(),
            });
        }
        if v.high_qc_view >= tc.view {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff timeout vote high_qc_view must be strictly below timed-out view"
                    .into(),
            });
        }
        let member =
            member_map
                .get(&v.signer_pubkey)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "non-committee signer in HotStuff TimeoutCertificate".into(),
                })?;
        let digest = hotstuff_timeout_sign_bytes(network, tc.epoch, tc.view, v.high_qc_view);
        crate::crypto::primitives::verify_signature(&digest, &v.ed25519_sig, &v.signer_pubkey)
            .map_err(|_| AdapterError::Crypto {
                what: "invalid Ed25519 signature in HotStuff TimeoutCertificate".into(),
            })?;
        if member.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if v.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature in HotStuff TC".into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &digest,
                &v.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in HotStuff TC".into(),
            })?;
        }
        observed_max_high_qc = observed_max_high_qc.max(v.high_qc_view);
        signed_stake = signed_stake
            .checked_add(u128::from(member.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HotStuff TC signed stake overflows u128".into(),
            })?;
    }

    if observed_max_high_qc != tc.max_high_qc_view {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC declared max_high_qc_view mismatches signed votes".into(),
        });
    }
    if signed_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC signed stake does not exceed strict 2/3".into(),
        });
    }
    Ok((observed_max_high_qc, signed_stake, all_pq))
}

/// Cryptographic misbehaviour bundle proving that a HotStuff validator signed
/// two distinct blocks in the exact same `(epoch, view)`.
///
/// WIRING: exposed for HotStuff double-vote slashing intake surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffEquivocationProof {
    /// Shared epoch of the double-vote.
    pub epoch: u64,
    /// Shared view of the double-vote.
    pub view: u64,
    /// First voted block hash (non-zero, distinct from `block_hash_b`).
    pub block_hash_a: [u8; 32],
    /// Second voted block hash (non-zero, distinct from `block_hash_a`).
    pub block_hash_b: [u8; 32],
    /// Vote signature on `block_hash_a`.
    pub vote_a: HotStuffVoteSig,
    /// Vote signature on `block_hash_b` by the exact same validator.
    pub vote_b: HotStuffVoteSig,
}

/// Verify a `HotStuffEquivocationProof` (including mandatory ML-DSA-65 co-sigs
/// so a classical forgery cannot frame a PQ-enrolled validator) and return the
/// slashable `(validator_pubkey, voting_weight)`.
///
/// # Errors
///
/// Returns [`AdapterError`] if the proof epoch mismatches `pinned`, block
/// hashes are zero or equal, votes are from different or unknown signers, or
/// any Ed25519 or ML-DSA-65 signature check fails.
///
/// Convenience: exposed for HotStuff slashing and `ConsensusSentry` freeze hooks.
pub fn verify_hotstuff_equivocation(
    network: &str,
    pinned: &PinnedHotStuffCommittee,
    proof: &HotStuffEquivocationProof,
) -> Result<([u8; 32], u64), AdapterError> {
    if proof.epoch != pinned.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof epoch mismatches pinned committee".into(),
        });
    }
    if proof.block_hash_a == [0u8; 32] || proof.block_hash_b == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof contains zero block_hash".into(),
        });
    }
    if bool::from(proof.block_hash_a.ct_eq(&proof.block_hash_b)) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof names identical block hashes".into(),
        });
    }
    if !bool::from(
        proof
            .vote_a
            .signer_pubkey
            .ct_eq(&proof.vote_b.signer_pubkey),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation votes belong to different validators".into(),
        });
    }
    let member = pinned
        .members
        .iter()
        .find(|m| bool::from(m.ed25519_pubkey.ct_eq(&proof.vote_a.signer_pubkey)))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "HotStuff equivocation signer is not in pinned committee".into(),
        })?;
    if member.ed25519_pubkey == [0u8; 32] || member.voting_weight == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation committee record has zero key or weight".into(),
        });
    }

    for (blk_hash, vote) in [
        (&proof.block_hash_a, &proof.vote_a),
        (&proof.block_hash_b, &proof.vote_b),
    ] {
        let msg = hotstuff_vote_sign_bytes(network, proof.epoch, proof.view, blk_hash);
        crate::crypto::primitives::verify_signature(
            &msg,
            &vote.ed25519_sig,
            &member.ed25519_pubkey,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid Ed25519 signature in HotStuff equivocation proof".into(),
        })?;
        if !member.pq_pubkey.is_empty() {
            if vote.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature in HotStuff equivocation"
                        .into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &msg,
                &vote.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in HotStuff equivocation".into(),
            })?;
        }
    }

    Ok((member.ed25519_pubkey, member.voting_weight))
}
