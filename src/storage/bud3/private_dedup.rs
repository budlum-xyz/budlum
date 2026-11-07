//! Private cross-owner deduplication for sealed B.U.D. 3.0 objects (Section 6.20.2.6; WP-54).
//! exposed for expansion-tier sealed deduplication, threshold OPRF evaluation, and epoch-batched reference settlement.
//!
//! The cryptographic verifier and threshold OPRF are not integrated. The
//! transcript helpers in this module are not a STARK or an OPRF and must not
//! be used to authorize cross-owner matches. Submission remains closed even
//! when an engine is constructed with `enabled` set to true.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;

use super::seal::padme_padded_len;

/// Testnet launch posture: cross-owner private dedup is closed at genesis (`Section 6.20.1`).
/// Convenience: exposed for launch configuration gates.
pub const TESTNET_PRIVATE_DEDUP_ENABLED: bool = false;

/// Maximum private deduplication OPRF queries per account per epoch (`Section 6.20.2.6`).
/// Convenience: exposed for rate-limiter inspection and tests.
pub const MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH: u32 = 16;

/// Minimum threshold OPRF committee shares required to finalize a dedup tag.
/// Convenience: exposed for committee setup.
pub const DEFAULT_OPRF_THRESHOLD: usize = 3;

const OPRF_SHARE_DOMAIN: &[u8] = b"budlum/bud3/private-dedup/oprf-share/v1";
const OPRF_FINAL_DOMAIN: &[u8] = b"budlum/bud3/private-dedup/oprf-final/v1";
const OWNERSHIP_PROOF_DOMAIN: &[u8] = b"budlum/bud3/private-dedup/budzero-ownership/v1";
const BLINDED_NFT_DOMAIN: &[u8] = b"budlum/bud3/private-dedup/blinded-nft/v1";

/// Errors raised by private cross-owner sealed deduplication.
/// Convenience: exposed for upload gateway and RPC callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateDedupError {
    /// Subsystem disabled in current network epoch.
    Disabled,
    /// Per-account per-epoch query quota exceeded (`Section 6.20.2.6`).
    RateLimitExceeded {
        account: Address,
        epoch: u64,
        limit: u32,
    },
    /// Insufficient or duplicate threshold OPRF shares.
    InsufficientOprfShares { got: usize, threshold: usize },
    /// Missing or invalid BudZero ownership proof (`Section 6.20.2.6`).
    InvalidOwnershipProof(&'static str),
}

/// Experimental transcript share, not a threshold OPRF evaluation.
/// Convenience: exposed for threshold OPRF committee messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdOprfShare {
    pub member_index: u16,
    pub partial_tag: [u8; 32],
}

impl ThresholdOprfShare {
    /// Produce a deterministic transcript hash; this is not an OPRF.
    /// Convenience: exposed for committee signer nodes.
    #[must_use]
    pub fn evaluate(member_index: u16, member_secret_share: &[u8; 32], blinded_input: &[u8; 32]) -> Self {
        let partial_tag = hash_fields_bytes(&[
            OPRF_SHARE_DOMAIN,
            &member_index.to_le_bytes(),
            member_secret_share,
            blinded_input,
        ]);
        Self {
            member_index,
            partial_tag,
        }
    }
}

/// Combine distinct transcript shares. This is not a threshold OPRF.
/// Convenience: exposed for threshold OPRF aggregation.
///
/// # Errors
///
/// Returns [`PrivateDedupError::InsufficientOprfShares`] when fewer than `threshold`
/// distinct committee members contributed.
pub fn combine_threshold_oprf_shares(
    blinded_input: &[u8; 32],
    shares: &[ThresholdOprfShare],
    threshold: usize,
) -> Result<[u8; 32], PrivateDedupError> {
    let required = threshold.max(1);
    let mut by_member: BTreeMap<u16, [u8; 32]> = BTreeMap::new();
    for s in shares {
        by_member.entry(s.member_index).or_insert(s.partial_tag);
    }
    if by_member.len() < required {
        return Err(PrivateDedupError::InsufficientOprfShares {
            got: by_member.len(),
            threshold: required,
        });
    }
    let mut folded = Vec::with_capacity(required.saturating_mul(34));
    for (idx, tag) in by_member.into_iter().take(required) {
        folded.extend_from_slice(&idx.to_le_bytes());
        folded.extend_from_slice(&tag);
    }
    Ok(hash_fields_bytes(&[OPRF_FINAL_DOMAIN, blinded_input, &folded]))
}

/// Experimental ownership transcript. This is not a BudZero STARK proof.
/// Convenience: exposed for upload prover and verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipProofBundle {
    pub claimant: Address,
    pub epoch: u64,
    pub oprf_tag: [u8; 32],
    pub padme_bucket_bytes: u64,
    pub stark_witness_commitment: [u8; 32],
    pub stark_proof_bytes: Vec<u8>,
}

impl OwnershipProofBundle {
    /// Construct a transcript from plaintext. It does not prove ownership.
    /// Convenience: exposed for client-side BudZero prover integration.
    #[must_use]
    pub fn prove_plaintext_ownership(
        claimant: Address,
        epoch: u64,
        oprf_tag: [u8; 32],
        plaintext: &[u8],
    ) -> Self {
        let len_u64 = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
        let padme_bucket_bytes = padme_padded_len(len_u64);
        let stark_witness_commitment = hash_fields_bytes(&[
            OWNERSHIP_PROOF_DOMAIN,
            claimant.as_bytes(),
            &epoch.to_le_bytes(),
            &oprf_tag,
            &padme_bucket_bytes.to_le_bytes(),
            plaintext,
        ]);
        let mut stark_proof_bytes = Vec::with_capacity(64);
        stark_proof_bytes.extend_from_slice(b"BZOWN1::");
        stark_proof_bytes.extend_from_slice(& hash_fields_bytes(&[
            OWNERSHIP_PROOF_DOMAIN,
            &stark_witness_commitment,
            claimant.as_bytes(),
            &epoch.to_le_bytes(),
        ]));
        Self {
            claimant,
            epoch,
            oprf_tag,
            padme_bucket_bytes,
            stark_witness_commitment,
            stark_proof_bytes,
        }
    }

    fn verify_statement(
        &self,
        expected_claimant: &Address,
        expected_epoch: u64,
        expected_oprf_tag: &[u8; 32],
        expected_bucket_bytes: u64,
    ) -> Result<(), PrivateDedupError> {
        if &self.claimant != expected_claimant {
            return Err(PrivateDedupError::InvalidOwnershipProof("claimant mismatch"));
        }
        if self.epoch != expected_epoch {
            return Err(PrivateDedupError::InvalidOwnershipProof("epoch mismatch"));
        }
        if &self.oprf_tag != expected_oprf_tag {
            return Err(PrivateDedupError::InvalidOwnershipProof("oprf_tag mismatch"));
        }
        if self.padme_bucket_bytes != expected_bucket_bytes {
            return Err(PrivateDedupError::InvalidOwnershipProof("padme bucket mismatch"));
        }
        if self.stark_witness_commitment == [0u8; 32] {
            return Err(PrivateDedupError::InvalidOwnershipProof("zero witness commitment"));
        }
        if self.stark_proof_bytes.len() != 40 || !self.stark_proof_bytes.starts_with(b"BZOWN1::") {
            return Err(PrivateDedupError::InvalidOwnershipProof("malformed BudZero proof envelope"));
        }
        let expected_seal = hash_fields_bytes(&[
            OWNERSHIP_PROOF_DOMAIN,
            &self.stark_witness_commitment,
            self.claimant.as_bytes(),
            &self.epoch.to_le_bytes(),
        ]);
        if self.stark_proof_bytes.get(8..) != Some(expected_seal.as_slice()) {
            return Err(PrivateDedupError::InvalidOwnershipProof("forged BudZero proof transcript"));
        }
        Err(PrivateDedupError::InvalidOwnershipProof(
            "BudZero ownership verifier is not integrated",
        ))
    }
}

/// Publicly visible NFT storage descriptor emitted for every sealed upload (`Section 6.20.2.6`).
///
/// Notice what is intentionally ABSENT:
/// - No `matched_existing: bool` flag,
/// - No shared `object_commitment` linking two owners' NFTs,
/// - Uniform `charged_fee_atoms` drawn from the sealed pool average (`sealed_pool_average_fee_atoms`),
/// - Reference counts are updated only inside [`PrivateDedupEngine::flush_epoch_batch`].
/// Convenience: exposed for Deed/NFT minting records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedDedupRecord {
    pub blinded_nft_slot: [u8; 32],
    pub padme_bucket_bytes: u64,
    pub charged_fee_atoms: u64,
}

/// Request parameters for [`PrivateDedupEngine::submit_sealed_upload`].
/// Convenience: exposed for upload validator admission.
#[derive(Debug, Clone)]
pub struct SealedDedupSubmission {
    pub caller: Address,
    pub epoch: u64,
    pub oprf_tag: [u8; 32],
    pub caller_blinding_nonce: [u8; 32],
    pub padme_bucket_bytes: u64,
    pub ownership_proof: Option<OwnershipProofBundle>,
}

/// Private cross-owner deduplication coordinator (`Section 6.20.2.6`).
/// Convenience: exposed for upload validators and expansion storage state.
#[derive(Debug, Clone)]
pub struct PrivateDedupEngine {
    pub enabled: bool,
    pub max_queries_per_epoch: u32,
    pub sealed_pool_average_fee_atoms: u64,
    rate_counters: BTreeMap<(u64, Address), u32>,
    known_tags: BTreeSet<[u8; 32]>,
    committed_ref_counts: BTreeMap<[u8; 32], u64>,
    pending_epoch_deltas: BTreeMap<[u8; 32], u64>,
}

impl PrivateDedupEngine {
    /// Create a new [`PrivateDedupEngine`].
    /// Convenience: exposed for storage state initialization.
    #[must_use]
    pub fn new(enabled: bool, sealed_pool_average_fee_atoms: u64) -> Self {
        Self {
            enabled,
            max_queries_per_epoch: MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH,
            sealed_pool_average_fee_atoms,
            rate_counters: BTreeMap::new(),
            known_tags: BTreeSet::new(),
            committed_ref_counts: BTreeMap::new(),
            pending_epoch_deltas: BTreeMap::new(),
        }
    }

    /// Publicly observable reference count snapshot (updated ONLY at epoch flush boundaries).
    /// Convenience: exposed for epoch audit inspection.
    #[must_use]
    pub fn public_epoch_ref_total(&self) -> u64 {
        self.committed_ref_counts.values().copied().sum()
    }

    const fn cryptography_available() -> bool {
        false
    }

    /// Process a sealed upload through private deduplication (`Section 6.20.2.6`).
    ///
    /// Rejects requests until an actual BudZero ownership verifier and threshold
    /// OPRF are integrated. A transcript hash alone does not prove ownership.
    /// Convenience: exposed for sealed upload pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateDedupError`] if disabled, rate-limited, or missing a valid ownership proof.
    pub fn submit_sealed_upload(
        &mut self,
        req: SealedDedupSubmission,
    ) -> Result<BlindedDedupRecord, PrivateDedupError> {
        if !self.enabled || !Self::cryptography_available() {
            return Err(PrivateDedupError::Disabled);
        }

        let used = self.rate_counters.entry((req.epoch, req.caller)).or_insert(0);
        if *used >= self.max_queries_per_epoch {
            return Err(PrivateDedupError::RateLimitExceeded {
                account: req.caller,
                epoch: req.epoch,
                limit: self.max_queries_per_epoch,
            });
        }
        *used += 1;

        let proof = req
            .ownership_proof
            .as_ref()
            .ok_or(PrivateDedupError::InvalidOwnershipProof(
                "BudZero ownership proof is required",
            ))?;
        proof.verify_statement(
            &req.caller,
            req.epoch,
            &req.oprf_tag,
            req.padme_bucket_bytes,
        )?;

        self.known_tags.insert(req.oprf_tag);
        let delta = self.pending_epoch_deltas.entry(req.oprf_tag).or_insert(0);
        *delta = delta.saturating_add(1);

        let blinded_nft_slot = hash_fields_bytes(&[
            BLINDED_NFT_DOMAIN,
            req.caller.as_bytes(),
            &req.epoch.to_le_bytes(),
            &req.caller_blinding_nonce,
            &req.oprf_tag,
        ]);

        Ok(BlindedDedupRecord {
            blinded_nft_slot,
            padme_bucket_bytes: req.padme_bucket_bytes,
            charged_fee_atoms: self.sealed_pool_average_fee_atoms,
        })
    }

    /// Flush batched reference counts at epoch boundary (`Section 6.20.2.6`).
    /// Convenience: exposed for end-of-epoch storage settlement.
    pub fn flush_epoch_batch(&mut self) -> usize {
        let touched = self.pending_epoch_deltas.len();
        let drained: Vec<([u8; 32], u64)> = self
            .pending_epoch_deltas
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        self.pending_epoch_deltas.clear();
        for (tag, delta) in drained {
            let entry = self.committed_ref_counts.entry(tag).or_insert(0);
            *entry = entry.saturating_add(delta);
        }
        touched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dedup_refuses_unverified_ownership_even_if_enabled() {
        let claimant = Address([0x11; 32]);
        let tag = [0x22; 32];
        let plaintext = b"sensitive content";
        let proof = OwnershipProofBundle::prove_plaintext_ownership(claimant, 7, tag, plaintext);
        let mut engine = PrivateDedupEngine::new(true, 5_000);
        let request = SealedDedupSubmission {
            caller: claimant,
            epoch: 7,
            oprf_tag: tag,
            caller_blinding_nonce: [0x33; 32],
            padme_bucket_bytes: proof.padme_bucket_bytes,
            ownership_proof: Some(proof),
        };
        assert_eq!(engine.submit_sealed_upload(request), Err(PrivateDedupError::Disabled));
        assert_eq!(engine.public_epoch_ref_total(), 0);
        assert_eq!(engine.flush_epoch_batch(), 0);
    }
}
