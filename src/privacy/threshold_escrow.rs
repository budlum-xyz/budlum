//! Threshold escrow unlock (`n = 7`, `t = 4`) for confidential transfers.
//!
//! Binds a 7-member ML-DSA-65 escrow committee with a 4-of-7 quorum requirement,
//! replay-protected `(escrow_id, chain_id, epoch, nonce)` signing domain,
//! duplicate-signer refusal, and `PredicateKind::Yk6ThresholdQuorum` STARK
//! verification against BudZero.
//!
//! Convenience: exposed for confidential n-of-t threshold escrow lifecycle callers.

use crate::core::address::Address;
use crate::crypto::ctx::PRIVATE_TRANSFER_V1;
use crate::crypto::pq::{
    ml_dsa_public_key, ml_dsa_sign, validate_public_key, verify_in, ML_DSA_SEED_LEN,
};
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use bud_proof::predicates::{
    prove_predicate, verify_predicate, PredicateKind, PredicateProof, PredicateStatement,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

/// Committee size (`n = 7`).
pub const THRESHOLD_ESCROW_N: usize = 7;

/// Minimum valid distinct member signatures required to unlock (`t = 4`).
pub const THRESHOLD_ESCROW_T: usize = 4;

/// A single member seat in a 7-of-4 threshold escrow committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowMember {
    pub index: u8,
    pub public_key: Vec<u8>,
}

/// Seven-member ML-DSA-65 committee descriptor for a confidential escrow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowCommittee {
    pub escrow_id: [u8; 32],
    pub chain_id: u64,
    pub epoch: u64,
    pub nonce: u64,
    pub members: Vec<EscrowMember>,
}

impl EscrowCommittee {
    /// Validate committee arity (`n = 7`), distinct indices (`0..7`), distinct
    /// ML-DSA-65 keys, and well-formed public keys.
    ///
    /// Convenience: exposed for escrow committee validation callers.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdEscrowError`] if committee shape or member keys are invalid.
    pub fn validate(&self) -> Result<(), ThresholdEscrowError> {
        if self.members.len() != THRESHOLD_ESCROW_N {
            return Err(ThresholdEscrowError::InvalidCommitteeSize {
                got: self.members.len(),
                expected: THRESHOLD_ESCROW_N,
            });
        }
        let mut seen_indices = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        for member in &self.members {
            if usize::from(member.index) >= THRESHOLD_ESCROW_N {
                return Err(ThresholdEscrowError::UnknownMember(member.index));
            }
            if !seen_indices.insert(member.index) {
                return Err(ThresholdEscrowError::DuplicateCommitteeMember(member.index));
            }
            if validate_public_key(SchemeId::ML_DSA_65, &member.public_key).is_err() {
                return Err(ThresholdEscrowError::InvalidMemberKey(member.index));
            }
            if !seen_keys.insert(member.public_key.clone()) {
                return Err(ThresholdEscrowError::DuplicateCommitteeKey);
            }
        }
        Ok(())
    }

    /// Derive member descriptor for `index` from a 32-byte ML-DSA-65 seed.
    ///
    /// Convenience: exposed for deterministic threshold escrow committee setup.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdEscrowError`] if key derivation fails or `index >= 7`.
    pub fn member_from_seed(
        index: u8,
        seed: &[u8; ML_DSA_SEED_LEN],
    ) -> Result<EscrowMember, ThresholdEscrowError> {
        if usize::from(index) >= THRESHOLD_ESCROW_N {
            return Err(ThresholdEscrowError::UnknownMember(index));
        }
        let public_key = ml_dsa_public_key(SchemeId::ML_DSA_65, seed)
            .map_err(|_| ThresholdEscrowError::InvalidMemberKey(index))?;
        Ok(EscrowMember { index, public_key })
    }
}

/// One committee member's ML-DSA-65 unlock authorization share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowUnlockShare {
    pub member_index: u8,
    pub signature: Vec<u8>,
}

/// Errors emitted while creating or unlocking a `7-of-4` threshold escrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdEscrowError {
    InvalidCommitteeSize { got: usize, expected: usize },
    UnknownMember(u8),
    DuplicateCommitteeMember(u8),
    DuplicateCommitteeKey,
    InvalidMemberKey(u8),
    AlreadyUnlocked,
    DuplicateSigner(u8),
    InvalidShareSignature(u8),
    InsufficientShares { got: usize, need: usize },
    WrongQuorumChain { got: u64, expected: u64 },
    InvalidQuorumStatement,
    InvalidQuorumStark(String),
    SigningFailed,
}

/// Confidential escrow locked by a 7-member ML-DSA-65 committee (`t = 4`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEscrow {
    pub committee: EscrowCommittee,
    pub amount_commitment: [u8; 32],
    pub unlocked: bool,
    pub unlock_receipt_digest: Option<[u8; 32]>,
}

impl ThresholdEscrow {
    /// Open a new `n = 7, t = 4` confidential threshold escrow.
    ///
    /// Convenience: exposed for confidential escrow creation callers.
    ///
    /// # Errors
    ///
    /// Refuses malformed or duplicate committees.
    pub fn open(
        committee: EscrowCommittee,
        amount_commitment: [u8; 32],
    ) -> Result<Self, ThresholdEscrowError> {
        committee.validate()?;
        Ok(Self {
            committee,
            amount_commitment,
            unlocked: false,
            unlock_receipt_digest: None,
        })
    }

    /// Canonical domain-separated preimage signed by committee shares.
    ///
    /// Convenience: exposed for external committee signer tools.
    #[must_use]
    pub fn signing_message(
        committee: &EscrowCommittee,
        recipient: &Address,
        amount_commitment: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_THRESHOLD_ESCROW_UNLOCK_V1");
        h.update(committee.escrow_id);
        h.update(committee.chain_id.to_le_bytes());
        h.update(committee.epoch.to_le_bytes());
        h.update(committee.nonce.to_le_bytes());
        h.update(recipient.as_bytes());
        h.update(amount_commitment);
        h.finalize().into()
    }

    /// Sign an unlock share using a member's 32-byte ML-DSA-65 seed.
    ///
    /// Convenience: exposed for committee member share signing callers.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdEscrowError::SigningFailed`] if signing fails.
    pub fn sign_share(
        &self,
        member_index: u8,
        seed: &[u8; ML_DSA_SEED_LEN],
        recipient: &Address,
    ) -> Result<EscrowUnlockShare, ThresholdEscrowError> {
        let msg = Self::signing_message(&self.committee, recipient, &self.amount_commitment);
        let signature =
            ml_dsa_sign(SchemeId::ML_DSA_65, seed, &msg, PRIVATE_TRANSFER_V1, &[0u8; 32])
                .map_err(|_| ThresholdEscrowError::SigningFailed)?;
        Ok(EscrowUnlockShare {
            member_index,
            signature,
        })
    }

    /// Prove a `PredicateKind::Yk6ThresholdQuorum` STARK statement for
    /// `verified_signers` against `THRESHOLD_ESCROW_T` on `self.committee.chain_id`.
    ///
    /// Convenience: exposed for quorum STARK predicate proof generation.
    ///
    /// # Errors
    ///
    /// Refuses proving when `verified_signers < THRESHOLD_ESCROW_T`.
    pub fn prove_quorum_predicate(
        &self,
        verified_signers: usize,
        recipient: &Address,
    ) -> Result<PredicateProof, ThresholdEscrowError> {
        let msg = Self::signing_message(&self.committee, recipient, &self.amount_commitment);
        let aux = u64::from_le_bytes(
            msg.get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        )
        .max(1);
        let stmt = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: u64::try_from(verified_signers).unwrap_or(u64::MAX),
            rhs: u64::try_from(THRESHOLD_ESCROW_T).unwrap_or(u64::MAX),
            aux,
            chain_id: self.committee.chain_id,
        };
        prove_predicate(&stmt)
            .map_err(|e| ThresholdEscrowError::InvalidQuorumStark(format!("{e:?}")))
    }

    /// Verify `>= 4` distinct valid ML-DSA-65 member shares AND a matching
    /// `Yk6ThresholdQuorum` STARK predicate proof, then permanently unlock.
    ///
    /// Convenience: exposed for direct threshold escrow verification callers.
    ///
    /// # Errors
    ///
    /// Fails closed on replay (`AlreadyUnlocked`), duplicate signers, invalid
    /// ML-DSA-65 share signatures, fewer than `t = 4` valid shares, or invalid
    /// `Yk6ThresholdQuorum` STARK verification.
    pub fn unlock(
        &mut self,
        recipient: &Address,
        shares: &[EscrowUnlockShare],
        quorum_proof: &PredicateProof,
    ) -> Result<[u8; 32], ThresholdEscrowError> {
        if self.unlocked {
            return Err(ThresholdEscrowError::AlreadyUnlocked);
        }
        self.committee.validate()?;
        if quorum_proof.statement.chain_id != self.committee.chain_id {
            return Err(ThresholdEscrowError::WrongQuorumChain {
                got: quorum_proof.statement.chain_id,
                expected: self.committee.chain_id,
            });
        }
        let msg = Self::signing_message(&self.committee, recipient, &self.amount_commitment);
        let expected_aux = u64::from_le_bytes(
            msg.get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([1u8; 8]),
        )
        .max(1);
        let threshold_u64 = u64::try_from(THRESHOLD_ESCROW_T).unwrap_or(u64::MAX);
        if quorum_proof.statement.kind != PredicateKind::Yk6ThresholdQuorum
            || quorum_proof.statement.rhs != threshold_u64
            || quorum_proof.statement.aux != expected_aux
            || quorum_proof.statement.lhs < threshold_u64
        {
            return Err(ThresholdEscrowError::InvalidQuorumStatement);
        }

        let scheme_registry = SchemeStatusRegistry::genesis();
        let mut seen_signers = BTreeSet::new();
        for share in shares {
            if !seen_signers.insert(share.member_index) {
                return Err(ThresholdEscrowError::DuplicateSigner(share.member_index));
            }
            let member = self
                .committee
                .members
                .iter()
                .find(|m| m.index == share.member_index)
                .ok_or(ThresholdEscrowError::UnknownMember(share.member_index))?;
            verify_in(
                &scheme_registry,
                SchemeId::ML_DSA_65,
                &member.public_key,
                &msg,
                PRIVATE_TRANSFER_V1,
                &share.signature,
            )
            .map_err(|_| ThresholdEscrowError::InvalidShareSignature(share.member_index))?;
        }
        if seen_signers.len() < THRESHOLD_ESCROW_T {
            return Err(ThresholdEscrowError::InsufficientShares {
                got: seen_signers.len(),
                need: THRESHOLD_ESCROW_T,
            });
        }
        if quorum_proof.statement.lhs != seen_signers.len() as u64 {
            return Err(ThresholdEscrowError::InvalidQuorumStatement);
        }
        verify_predicate(quorum_proof)
            .map_err(|e| ThresholdEscrowError::InvalidQuorumStark(format!("{e:?}")))?;

        let mut h = Sha3_256::new();
        h.update(b"BDLM_THRESHOLD_ESCROW_RECEIPT_V1");
        h.update(msg);
        h.update((seen_signers.len() as u64).to_le_bytes());
        let receipt: [u8; 32] = h.finalize().into();
        self.unlocked = true;
        self.unlock_receipt_digest = Some(receipt);
        Ok(receipt)
    }
}
