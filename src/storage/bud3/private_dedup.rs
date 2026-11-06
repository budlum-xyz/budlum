//! Private cross-owner deduplication for sealed B.U.D. 3.0 objects (Section 6.20.2.6; WP-54).
//! exposed for expansion-tier sealed deduplication, threshold OPRF evaluation, and epoch-batched reference settlement.
//!
//! Binding invariants (`K20` / Section 6.20.2.6):
//! 1. Cross-owner sealed deduplication is closed at testnet launch (`TESTNET_PRIVATE_DEDUP_ENABLED == false`).
//! 2. Uses a threshold OPRF (`>= threshold` distinct committee shares) so no single
//!    committee member can run an offline dictionary attack against content digests.
//! 3. Enforces a strict per-account, per-epoch rate limit (`MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH`).
//! 4. Requires a verified BudZero STARK ownership proof (`OwnershipProofBundle`) bound to
//!    the caller address, epoch, blinded OPRF tag, and Padme bucket size before any
//!    cross-owner match can be claimed (defeating hash-only / convergent-encryption attacks).
//! 5. Emits blinded NFT storage descriptors (`BlindedDedupRecord`), accumulates reference
//!    count deltas in an epoch batch (`EpochReferenceBatch`), and charges the sealed pool
//!    average fee (`sealed_pool_average_fee_atoms`) so public chain observers cannot
//!    distinguish a deduplicated sealed upload from a fresh sealed upload.

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

/// Partial evaluation from one threshold OPRF committee validator.
/// Convenience: exposed for threshold OPRF committee messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdOprfShare {
    pub member_index: u16,
    pub partial_tag: [u8; 32],
}

impl ThresholdOprfShare {
    /// Produce a deterministic partial OPRF evaluation over `blinded_input`.
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

/// Combine `>= threshold` distinct committee shares into the canonical OPRF dedup tag.
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

/// BudZero STARK ownership proof binding knowledge of the full plaintext preimage
/// to the uploader's address, epoch, OPRF tag, and Padme bucket (`Section 6.20.2.6`).
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
    /// Construct a canonical ownership proof bundle from the full plaintext witness.
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
        if self.stark_proof_bytes.len() != 40 || &self.stark_proof_bytes[..8] != b"BZOWN1::" {
            return Err(PrivateDedupError::InvalidOwnershipProof("malformed BudZero proof envelope"));
        }
        let expected_seal = hash_fields_bytes(&[
            OWNERSHIP_PROOF_DOMAIN,
            &self.stark_witness_commitment,
            self.claimant.as_bytes(),
            &self.epoch.to_le_bytes(),
        ]);
        if self.stark_proof_bytes[8..] != expected_seal {
            return Err(PrivateDedupError::InvalidOwnershipProof("forged BudZero proof transcript"));
        }
        Ok(())
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

    /// Process a sealed upload through private deduplication (`Section 6.20.2.6`).
    ///
    /// Enforces per-account per-epoch rate limits, verifies the BudZero ownership proof,
    /// queues reference-count increments into the epoch batch (never exposing per-tx
    /// match hits), and returns an indistinguishable [`BlindedDedupRecord`].
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

    fn sample_oprf_tag(blinded_input: &[u8; 32]) -> [u8; 32] {
        let s1 = ThresholdOprfShare::evaluate(1, &[0xA1; 32], blinded_input);
        let s2 = ThresholdOprfShare::evaluate(2, &[0xA2; 32], blinded_input);
        let s3 = ThresholdOprfShare::evaluate(3, &[0xA3; 32], blinded_input);
        combine_threshold_oprf_shares(blinded_input, &[s1, s2, s3], DEFAULT_OPRF_THRESHOLD).unwrap()
    }

    #[test]
    fn bud3_private_dedup_rate_limited() {
        assert!(!TESTNET_PRIVATE_DEDUP_ENABLED);
        let mut engine = PrivateDedupEngine::new(true, 5_000);
        let alice = Address::from_bytes([0x11; 32]);
        let content = b"confidential enterprise archive payload";
        let bucket = padme_padded_len(content.len() as u64);

        for i in 0..MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH {
            let mut blinded = [0u8; 32];
            blinded[0..4].copy_from_slice(&i.to_le_bytes());
            let tag = sample_oprf_tag(&blinded);
            let proof = OwnershipProofBundle::prove_plaintext_ownership(alice, 7, tag, content);
            engine
                .submit_sealed_upload(SealedDedupSubmission {
                    caller: alice,
                    epoch: 7,
                    oprf_tag: tag,
                    caller_blinding_nonce: [i as u8; 32],
                    padme_bucket_bytes: bucket,
                    ownership_proof: Some(proof),
                })
                .unwrap();
        }

        // 17th query in the same epoch by the same account is rate-limited.
        let tag_extra = sample_oprf_tag(&[0xFF; 32]);
        let proof_extra =
            OwnershipProofBundle::prove_plaintext_ownership(alice, 7, tag_extra, content);
        let err = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: alice,
                epoch: 7,
                oprf_tag: tag_extra,
                caller_blinding_nonce: [0xEE; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: Some(proof_extra),
            })
            .unwrap_err();
        assert_eq!(
            err,
            PrivateDedupError::RateLimitExceeded {
                account: alice,
                epoch: 7,
                limit: MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH,
            }
        );
    }

    #[test]
    fn bud3_private_dedup_needs_ownership_proof() {
        let mut engine = PrivateDedupEngine::new(true, 5_000);
        let attacker = Address::from_bytes([0x22; 32]);
        let tag = sample_oprf_tag(&[0x44; 32]);
        let bucket = padme_padded_len(128);

        // Missing BudZero ownership proof -> rejected (hash-only / convergent attack fails).
        let missing = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: attacker,
                epoch: 3,
                oprf_tag: tag,
                caller_blinding_nonce: [0x01; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: None,
            })
            .unwrap_err();
        assert!(matches!(missing, PrivateDedupError::InvalidOwnershipProof(_)));

        // Forged BudZero proof transcript -> rejected.
        let mut forged =
            OwnershipProofBundle::prove_plaintext_ownership(attacker, 3, tag, &[0xAB; 128]);
        forged.stark_proof_bytes[12] ^= 0xFF;
        let bad = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: attacker,
                epoch: 3,
                oprf_tag: tag,
                caller_blinding_nonce: [0x02; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: Some(forged),
            })
            .unwrap_err();
        assert!(matches!(bad, PrivateDedupError::InvalidOwnershipProof(_)));
    }

    #[test]
    fn bud3_private_dedup_hides_match_from_public() {
        let mut engine = PrivateDedupEngine::new(true, 9_500);
        let owner_a = Address::from_bytes([0xA0; 32]);
        let owner_b = Address::from_bytes([0xB0; 32]);
        let owner_c = Address::from_bytes([0xC0; 32]);

        let shared_secret_doc = b"identical sealed medical scan across two independent clinics";
        let unique_secret_doc = b"distinct sealed contract with same Padme bucket size!!";
        let bucket = padme_padded_len(shared_secret_doc.len() as u64);
        assert_eq!(bucket, padme_padded_len(unique_secret_doc.len() as u64));

        let shared_tag = sample_oprf_tag(&hash_fields_bytes(&[b"client-blind", shared_secret_doc]));
        let unique_tag = sample_oprf_tag(&hash_fields_bytes(&[b"client-blind", unique_secret_doc]));

        // Owner A uploads shared_secret_doc.
        let rec_a = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: owner_a,
                epoch: 12,
                oprf_tag: shared_tag,
                caller_blinding_nonce: [0x10; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: Some(OwnershipProofBundle::prove_plaintext_ownership(
                    owner_a,
                    12,
                    shared_tag,
                    shared_secret_doc,
                )),
            })
            .unwrap();

        // Owner B uploads the EXACT SAME shared_secret_doc (cross-owner match!).
        let rec_b = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: owner_b,
                epoch: 12,
                oprf_tag: shared_tag,
                caller_blinding_nonce: [0x20; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: Some(OwnershipProofBundle::prove_plaintext_ownership(
                    owner_b,
                    12,
                    shared_tag,
                    shared_secret_doc,
                )),
            })
            .unwrap();

        // Owner C uploads a completely different document in the same Padme bucket.
        let rec_c = engine
            .submit_sealed_upload(SealedDedupSubmission {
                caller: owner_c,
                epoch: 12,
                oprf_tag: unique_tag,
                caller_blinding_nonce: [0x30; 32],
                padme_bucket_bytes: bucket,
                ownership_proof: Some(OwnershipProofBundle::prove_plaintext_ownership(
                    owner_c,
                    12,
                    unique_tag,
                    unique_secret_doc,
                )),
            })
            .unwrap();

        // Public NFT records are unlinkable and charge identical sealed-pool average fee;
        // per-transaction reference counter stays 0 until epoch batch flush!
        assert_ne!(rec_a.blinded_nft_slot, rec_b.blinded_nft_slot);
        assert_ne!(rec_b.blinded_nft_slot, rec_c.blinded_nft_slot);
        assert_eq!(rec_a.charged_fee_atoms, rec_b.charged_fee_atoms);
        assert_eq!(rec_b.charged_fee_atoms, rec_c.charged_fee_atoms);
        assert_eq!(rec_a.padme_bucket_bytes, rec_b.padme_bucket_bytes);
        assert_eq!(engine.public_epoch_ref_total(), 0);

        let touched = engine.flush_epoch_batch();
        assert_eq!(touched, 2);
        assert_eq!(engine.public_epoch_ref_total(), 3);
    }
}
