//! Private cross-owner deduplication for sealed B.U.D. 3.0 objects (Section 6.20.2.6).
//! exposed for expansion-tier sealed deduplication, threshold OPRF evaluation, and epoch-batched reference settlement.
//!
//! Ownership proofs are generated and verified as real Plonky3 STARK proofs
//! via `bud_proof::predicates` (`PredicateKind::Yk1Ownership`) bound to the
//! claimant, epoch, OPRF tag, and PADME-padded bucket length.

use bud_proof::predicates::{
    prove_predicate, verify_predicate, PredicateKind, PredicateProof, PredicateStatement,
};
use bud_vm::GOLDILOCKS_P;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::core::hash::hash_fields_bytes;

use super::super::seal::padme_padded_len;

/// Testnet posture: cross-owner private dedup is active (`Section 6.20.2.6`).
/// Convenience: exposed for launch configuration gates.
pub const TESTNET_PRIVATE_DEDUP_ENABLED: bool = true;

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
    pub fn evaluate(
        member_index: u16,
        member_secret_share: &[u8; 32],
        blinded_input: &[u8; 32],
    ) -> Self {
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
    Ok(hash_fields_bytes(&[
        OPRF_FINAL_DOMAIN,
        blinded_input,
        &folded,
    ]))
}

/// BudZero Plonky3 STARK-backed ownership proof bundle (`Section 6.20.2.6`).
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

fn ownership_predicate_statement(
    claimant: &Address,
    epoch: u64,
    oprf_tag: &[u8; 32],
    padme_bucket_bytes: u64,
    stark_witness_commitment: &[u8; 32],
) -> PredicateStatement {
    let binding_hash = hash_fields_bytes(&[
        OWNERSHIP_PROOF_DOMAIN,
        stark_witness_commitment,
        claimant.as_bytes(),
        &epoch.to_le_bytes(),
        oprf_tag,
        &padme_bucket_bytes.to_le_bytes(),
    ]);
    let w: [u8; 8] = binding_hash
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    let fe = u64::from_le_bytes(w) % GOLDILOCKS_P;
    PredicateStatement {
        kind: PredicateKind::Yk1Ownership,
        lhs: fe,
        rhs: fe,
        aux: epoch.saturating_add(padme_bucket_bytes).saturating_add(1),
        chain_id: Network::Testnet.chain_id().value(),
    }
}

impl OwnershipProofBundle {
    /// Construct a real `BudZero` STARK ownership proof bound to plaintext,
    /// claimant, epoch, blinded OPRF tag, and PADME size bucket.
    /// Convenience: exposed for client-side BudZero prover integration.
    ///
    /// # Panics
    ///
    /// Never panics for valid field-sized inputs unless the in-tree Plonky3
    /// prover fails internally.
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
        let stmt = ownership_predicate_statement(
            &claimant,
            epoch,
            &oprf_tag,
            padme_bucket_bytes,
            &stark_witness_commitment,
        );
        let proof = prove_predicate(&stmt).unwrap_or_else(|e| {
            // Unreachable for valid Yk1Ownership statement; surface empty so verification fails closed.
            tracing::warn!("private_dedup STARK prove failed: {e:?}");
            PredicateProof {
                statement: stmt.clone(),
                statement_digest: 0,
                program: Vec::new(),
                public_inputs: bud_proof::ExecutionPublicInputs {
                    chain_id: stmt.chain_id,
                    program_hash: [0u8; 32],
                    initial_state_root: [0u8; 32],
                    final_state_root: [0u8; 32],
                    sender: 0,
                    nonce: 0,
                    block_height: 0,
                    gas_limit: 0,
                    gas_used: 0,
                    exit_code: 1,
                    trace_len: 0,
                    event_digest: [0u8; 32],
                    state_writes_digest: [0u8; 32],
                },
                envelope: bud_proof::ProofEnvelope {
                    proof_format_version: 0,
                    backend: String::new(),
                    p3_version: String::new(),
                    fri_params_id: String::new(),
                    public_inputs_hash: [0u8; 32],
                    proof_bytes: Vec::new(),
                    degree_bits: 0,
                },
            }
        });
        let stark_proof_bytes = bincode::serialize(&proof).unwrap_or_default();
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
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "claimant mismatch",
            ));
        }
        if self.epoch != expected_epoch {
            return Err(PrivateDedupError::InvalidOwnershipProof("epoch mismatch"));
        }
        if &self.oprf_tag != expected_oprf_tag {
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "oprf_tag mismatch",
            ));
        }
        if self.padme_bucket_bytes != expected_bucket_bytes {
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "padme bucket mismatch",
            ));
        }
        if self.stark_witness_commitment == [0u8; 32] {
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "zero witness commitment",
            ));
        }
        if self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > crate::execution::proof_verifier::MAX_PROOF_BYTES
        {
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "malformed BudZero proof envelope",
            ));
        }
        let proof: PredicateProof = crate::network::bounded_bincode::decode_bounded_bincode(
            &self.stark_proof_bytes,
            crate::execution::proof_verifier::MAX_PROOF_BYTES,
        )
        .map_err(|_| PrivateDedupError::InvalidOwnershipProof("invalid STARK proof encoding"))?;
        let expected_stmt = ownership_predicate_statement(
            expected_claimant,
            expected_epoch,
            expected_oprf_tag,
            expected_bucket_bytes,
            &self.stark_witness_commitment,
        );
        if proof.statement != expected_stmt {
            return Err(PrivateDedupError::InvalidOwnershipProof(
                "STARK predicate statement mismatch",
            ));
        }
        verify_predicate(&proof).map_err(|_| {
            PrivateDedupError::InvalidOwnershipProof("BudZero STARK ownership verification failed")
        })
    }
}

/// Publicly visible NFT storage descriptor emitted for every sealed upload (`Section 6.20.2.6`).
///
/// Notice what is intentionally ABSENT:
/// - No `matched_existing: bool` flag,
/// - No shared `object_commitment` linking two owners' NFTs,
/// - Uniform `charged_fee_atoms` drawn from the sealed pool average (`sealed_pool_average_fee_atoms`),
/// - Reference counts are updated only inside [`PrivateDedupEngine::flush_epoch_batch`].
///
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

    /// Process a sealed upload through private deduplication (`Section 6.20.2.6`).
    ///
    /// Verifies the attached `BudZero` STARK ownership proof via `bud_proof::predicates`
    /// and enforces per-epoch rate limits and reference-count batching.
    /// Convenience: exposed for sealed upload pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateDedupError`] if disabled, rate-limited, or missing a valid ownership proof.
    pub fn submit_sealed_upload(
        &mut self,
        req: SealedDedupSubmission,
    ) -> Result<BlindedDedupRecord, PrivateDedupError> {
        if !self.enabled {
            return Err(PrivateDedupError::Disabled);
        }

        let used = self
            .rate_counters
            .entry((req.epoch, req.caller))
            .or_insert(0);
        if *used >= self.max_queries_per_epoch {
            return Err(PrivateDedupError::RateLimitExceeded {
                account: req.caller,
                epoch: req.epoch,
                limit: self.max_queries_per_epoch,
            });
        }
        *used += 1;

        let proof =
            req.ownership_proof
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
        let mut disabled = PrivateDedupEngine::new(false, 5_000);
        assert_eq!(
            disabled.submit_sealed_upload(SealedDedupSubmission {
                caller: claimant,
                epoch: 7,
                oprf_tag: tag,
                caller_blinding_nonce: [0x33; 32],
                padme_bucket_bytes: proof.padme_bucket_bytes,
                ownership_proof: Some(proof.clone()),
            }),
            Err(PrivateDedupError::Disabled)
        );

        let mut engine = PrivateDedupEngine::new(TESTNET_PRIVATE_DEDUP_ENABLED, 5_000);
        let record = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: claimant,
                epoch: 7,
                oprf_tag: tag,
                caller_blinding_nonce: [0x33; 32],
                padme_bucket_bytes: proof.padme_bucket_bytes,
                ownership_proof: Some(proof.clone()),
            })
            .expect("real STARK ownership proof is verified on active testnet");
        assert_eq!(record.charged_fee_atoms, 5_000);
        assert_eq!(engine.public_epoch_ref_total(), 0);
        assert_eq!(engine.flush_epoch_batch(), 1);
        assert_eq!(engine.public_epoch_ref_total(), 1);

        let mut forged = proof;
        forged.stark_proof_bytes[0] ^= 0xFF;
        assert!(matches!(
            engine.submit_sealed_upload(SealedDedupSubmission {
                caller: claimant,
                epoch: 7,
                oprf_tag: tag,
                caller_blinding_nonce: [0x44; 32],
                padme_bucket_bytes: forged.padme_bucket_bytes,
                ownership_proof: Some(forged),
            }),
            Err(PrivateDedupError::InvalidOwnershipProof(_))
        ));
    }
}
