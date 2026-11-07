//! B.U.D. 3.0 private cross-owner deduplication for sealed content (WP-54).
//!
//! Sealed uploads across distinct owners never consult the public deduplication
//! index. Instead, post-activation private deduplication combines:
//! 1. Threshold OPRF token derivation with per-account, per-epoch rate limits.
//! 2. Proof of plaintext ownership bound to `(uploader, epoch, oprf_token,
//!    challenge_nonce)` so possession of a digest alone cannot probe or claim
//!    another owner's sealed object.
//! 3. Unlinkable blinded NFT fields, Padme-bucketed sizes, sealed-pool average
//!    pricing, and epoch-batched submission counters so public state never
//!    reveals whether two owners hold the same sealed bytes.
//!
//! WIRING: unwired - post-launch T-Expansion private cross-owner deduplication
//! (WP-54); closed on testnet 45261 until activation height is set by
//! governance.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::address::Address;

/// Domain tag for threshold OPRF partial share derivation and aggregation.
pub const PRIVATE_DEDUP_OPRF_TAG: &[u8] = b"BDLM_BUD3_PRIVATE_DEDUP_OPRF_V1";
/// Domain tag for plaintext ownership proof transcripts.
pub const PRIVATE_DEDUP_OWNERSHIP_TAG: &[u8] = b"BDLM_BUD3_PRIVATE_DEDUP_OWNERSHIP_V1";
/// Domain tag for blinded NFT field commitments.
pub const PRIVATE_DEDUP_RECORD_TAG: &[u8] = b"BDLM_BUD3_PRIVATE_DEDUP_RECORD_V1";

/// Default per-account OPRF evaluation cap per epoch.
pub const DEFAULT_OPRF_RATE_LIMIT_PER_EPOCH: u32 = 8;
/// Minimum Padme bucket size for sealed envelopes (bytes).
pub const MIN_SEALED_BUCKET_BYTES: u64 = 256;

/// Activation gate for private cross-owner deduplication on chain `45261`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDedupActivation {
    /// First block height at which private cross-owner deduplication is open,
    /// or `None` when closed (default at testnet launch).
    pub height: Option<u64>,
}

/// Testnet launch configuration: closed per Section 1.5 and KR-36.
pub const ACTIVATION: PrivateDedupActivation = PrivateDedupActivation { height: None };

impl PrivateDedupActivation {
    /// Whether private cross-owner deduplication is active at `block_height`.
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub const fn is_active(&self, block_height: u64) -> bool {
        match self.height {
            Some(active_at) => block_height >= active_at,
            None => false,
        }
    }
}

/// Why a private deduplication request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateDedupError {
    /// Feature is closed at the current block height.
    ClosedOnNetwork,
    /// Account exceeded its per-epoch OPRF token quota.
    RateLimited {
        account: Address,
        epoch: u64,
        limit: u32,
    },
    /// Fewer distinct committee shares than required by threshold `t`.
    InsufficientOprfShares { got: usize, threshold: usize },
    /// Plaintext ownership proof is missing, forged, or bound to a different
    /// uploader/epoch/challenge.
    OwnershipProofInvalid,
    /// Account lacks balance for the sealed-pool average fee.
    InsufficientFeeBalance,
}

/// Padme padded byte bucket (Section 6.21.4 item 1), floored at
/// [`MIN_SEALED_BUCKET_BYTES`].
/// WIRING: exposed for post-launch T-Expansion activation.
#[must_use]
pub const fn padme_bucket_bytes(raw_len: u64) -> u64 {
    if raw_len <= MIN_SEALED_BUCKET_BYTES {
        return MIN_SEALED_BUCKET_BYTES;
    }
    let exp = 63u32.saturating_sub(raw_len.leading_zeros());
    let exp_bits = 32u32.saturating_sub(exp.leading_zeros());
    let low_bits = exp.saturating_sub(exp_bits);
    if low_bits == 0 {
        return raw_len;
    }
    let mask = (1u64 << low_bits).saturating_sub(1);
    match raw_len.checked_add(mask) {
        Some(sum) => sum & !mask,
        None => u64::MAX & !mask,
    }
}

/// One validator's partial evaluation in the threshold OPRF committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OprfPartialShare {
    /// Committee seat index.
    pub member_index: u16,
    /// Deterministic partial evaluation over the blinded content digest.
    pub evaluation: [u8; 32],
}

/// Deterministic `t`-of-`n` threshold OPRF committee model.
///
/// In production deployment each validator holds only its secret scalar share;
/// any `threshold` seats produce identical reconstructed tokens via canonical
/// epoch key derivation, while fewer than `threshold` shares reveal nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdOprfCommittee {
    epoch_secret_seed: [u8; 32],
    threshold: usize,
    committee_size: u16,
}

impl ThresholdOprfCommittee {
    /// Create a committee for `committee_size` seats with `threshold` minimum
    /// partial shares.
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn new(epoch_secret_seed: [u8; 32], threshold: usize, committee_size: u16) -> Self {
        let bounded_threshold = threshold.max(1).min(usize::from(committee_size.max(1)));
        Self {
            epoch_secret_seed,
            threshold: bounded_threshold,
            committee_size: committee_size.max(1),
        }
    }

    /// Produce seat `member_index`'s partial evaluation for `content_digest`.
    #[must_use]
    pub fn partial_evaluate(
        &self,
        member_index: u16,
        content_digest: &[u8; 32],
    ) -> OprfPartialShare {
        let mut h = Sha256::new();
        h.update(PRIVATE_DEDUP_OPRF_TAG);
        h.update(b"share");
        h.update(self.epoch_secret_seed);
        h.update(member_index.to_le_bytes());
        h.update(content_digest);
        OprfPartialShare {
            member_index,
            evaluation: h.finalize().into(),
        }
    }

    /// Finalize a canonical 32-byte OPRF token once at least `threshold`
    /// authentic distinct committee shares are supplied.
    ///
    /// # Errors
    ///
    /// Refuses duplicate, out-of-range, forged, or below-threshold share sets.
    /// WIRING: exposed for post-launch T-Expansion activation.
    pub fn finalize_token(
        &self,
        content_digest: &[u8; 32],
        shares: &[OprfPartialShare],
    ) -> Result<[u8; 32], PrivateDedupError> {
        let mut seen = BTreeSet::new();
        for share in shares {
            if share.member_index >= self.committee_size {
                return Err(PrivateDedupError::OwnershipProofInvalid);
            }
            let expected = self.partial_evaluate(share.member_index, content_digest);
            if share.evaluation != expected.evaluation {
                return Err(PrivateDedupError::OwnershipProofInvalid);
            }
            seen.insert(share.member_index);
        }
        if seen.len() < self.threshold {
            return Err(PrivateDedupError::InsufficientOprfShares {
                got: seen.len(),
                threshold: self.threshold,
            });
        }
        let mut h = Sha256::new();
        h.update(PRIVATE_DEDUP_OPRF_TAG);
        h.update(b"token");
        h.update(self.epoch_secret_seed);
        h.update(content_digest);
        Ok(h.finalize().into())
    }
}

/// Proof of plaintext ownership bound to uploader, epoch, OPRF token and
/// verifier challenge nonce.
///
/// Knowing only `SHA-256(plaintext)` or `oprf_token` is insufficient to construct
/// [`OwnershipProof`] because `sampled_chunk_mac` absorbs challenge-selected
/// windows of the raw plaintext bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// Plain SHA-256 digest of the plaintext proven by the uploader.
    pub plaintext_sha256: [u8; 32],
    /// Declared plaintext byte length before Padme bucket padding.
    pub plaintext_len: u64,
    /// Challenge nonce bound into the proof transcript.
    pub challenge_nonce: [u8; 32],
    /// Transcript commitment over challenge-sampled plaintext windows.
    pub sampled_chunk_mac: [u8; 32],
}

impl OwnershipProof {
    /// Construct an ownership proof from the full `plaintext`.
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn prove(
        plaintext: &[u8],
        uploader: &Address,
        epoch: u64,
        oprf_token: &[u8; 32],
        challenge_nonce: [u8; 32],
    ) -> Self {
        let plaintext_sha256: [u8; 32] = Sha256::digest(plaintext).into();
        let sampled_chunk_mac =
            ownership_transcript(plaintext, uploader, epoch, oprf_token, &challenge_nonce);
        Self {
            plaintext_sha256,
            plaintext_len: plaintext.len() as u64,
            challenge_nonce,
            sampled_chunk_mac,
        }
    }

    /// True iff `self` matches the transcript computed over `plaintext` for
    /// `(uploader, epoch, oprf_token, expected_challenge)`.
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn is_authentic(
        &self,
        plaintext: &[u8],
        uploader: &Address,
        epoch: u64,
        oprf_token: &[u8; 32],
        expected_challenge: &[u8; 32],
    ) -> bool {
        if &self.challenge_nonce != expected_challenge {
            return false;
        }
        if self.plaintext_len != plaintext.len() as u64 {
            return false;
        }
        let actual_sha: [u8; 32] = Sha256::digest(plaintext).into();
        if self.plaintext_sha256 != actual_sha {
            return false;
        }
        let expected_mac =
            ownership_transcript(plaintext, uploader, epoch, oprf_token, expected_challenge);
        self.sampled_chunk_mac == expected_mac
    }
}

fn ownership_transcript(
    plaintext: &[u8],
    uploader: &Address,
    epoch: u64,
    oprf_token: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PRIVATE_DEDUP_OWNERSHIP_TAG);
    h.update(uploader.as_bytes());
    h.update(epoch.to_le_bytes());
    h.update(oprf_token);
    h.update(challenge_nonce);
    h.update((plaintext.len() as u64).to_le_bytes());
    // Absorb 4 deterministic challenge-indexed 64-byte windows from plaintext
    // so a bare SHA-256 digest cannot forge the proof without holding the bytes.
    if !plaintext.is_empty() {
        for slot in 0..4usize {
            let hi = challenge_nonce.get(slot * 2).copied().unwrap_or(0) as usize;
            let lo = challenge_nonce.get(slot * 2 + 1).copied().unwrap_or(0) as usize;
            let offset = ((hi << 8) | lo) % plaintext.len();
            let end = offset.saturating_add(64).min(plaintext.len());
            if let Some(window) = plaintext.get(offset..end) {
                h.update((offset as u64).to_le_bytes());
                h.update(window);
            }
        }
    }
    h.finalize().into()
}

/// Publicly observable NFT registration view produced by a sealed upload.
///
/// Contains only unlinkable commitments and Padme bucket metadata; never
/// reveals whether an internal OPRF match occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSealedNftView {
    /// Unlinkable blinded object pointer (`SHA-256(tag || nft_id || blind || oprf_token)`).
    pub blinded_object_field: [u8; 32],
    /// Padme-bucketed byte size (`content_len` is never exposed in the clear).
    pub padded_bucket_bytes: u64,
    /// Uniform fee charged using the sealed-pool average rate.
    pub fee_charged: u64,
}

/// Epoch-batched public summary emitted at epoch boundary (Section 6.20.2 item 6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEpochDedupSummary {
    /// Epoch number.
    pub epoch: u64,
    /// Total sealed uploads processed in the epoch (hits + misses combined).
    pub total_sealed_submissions: u64,
    /// Total Padme-bucketed bytes billed at the sealed-pool average rate.
    pub total_billed_bucket_bytes: u64,
}

/// Private validator-side state for rate-limited cross-owner sealed dedup.
#[derive(Debug, Clone)]
pub struct PrivateDedupEngine {
    /// Maximum OPRF token queries allowed per `(epoch, account)`.
    pub max_queries_per_epoch: u32,
    /// Sealed-pool average fee per Padme-bucketed byte (uniform across hits and
    /// misses so fees never leak deduplication status).
    pub sealed_pool_fee_per_bucket_byte: u64,
    /// Per-`(epoch, account)` OPRF query counter.
    oprf_queries: BTreeMap<(u64, Address), u32>,
    /// Internal sealed table mapping `oprf_token -> canonical_object_commitment`.
    /// Never exposed via public RPC or per-tx state diffs.
    sealed_index: BTreeMap<[u8; 32], [u8; 32]>,
    /// Epoch-batched public counters.
    epoch_summaries: BTreeMap<u64, PublicEpochDedupSummary>,
    /// Sealed storage endowment pool balance.
    pub sealed_endowment_pool: u64,
}

impl Default for PrivateDedupEngine {
    fn default() -> Self {
        Self {
            max_queries_per_epoch: DEFAULT_OPRF_RATE_LIMIT_PER_EPOCH,
            sealed_pool_fee_per_bucket_byte: 2,
            oprf_queries: BTreeMap::new(),
            sealed_index: BTreeMap::new(),
            epoch_summaries: BTreeMap::new(),
            sealed_endowment_pool: 0,
        }
    }
}

impl PrivateDedupEngine {
    /// Request a rate-limited threshold OPRF token for `(account, epoch)`.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateDedupError::RateLimited`] once `account` reaches
    /// `max_queries_per_epoch` in `epoch`.
    /// WIRING: exposed for post-launch T-Expansion activation.
    pub fn request_oprf_token(
        &mut self,
        committee: &ThresholdOprfCommittee,
        account: Address,
        epoch: u64,
        content_digest: &[u8; 32],
        shares: &[OprfPartialShare],
    ) -> Result<[u8; 32], PrivateDedupError> {
        let used = self.oprf_queries.entry((epoch, account)).or_insert(0);
        if *used >= self.max_queries_per_epoch {
            return Err(PrivateDedupError::RateLimited {
                account,
                epoch,
                limit: self.max_queries_per_epoch,
            });
        }
        *used = used.saturating_add(1);
        committee.finalize_token(content_digest, shares)
    }

    /// Submit a sealed upload with mandatory plaintext ownership proof.
    ///
    /// Both cross-owner hits and brand-new sealed objects charge the exact same
    /// Padme-bucketed sealed-pool average fee, emit a fresh unlinkable
    /// `blinded_object_field`, and update only the epoch-batched public summary.
    ///
    /// # Errors
    ///
    /// Refuses invalid ownership proofs or insufficient fee balances.
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_sealed_upload(
        &mut self,
        uploader: Address,
        payer_balance: &mut u64,
        epoch: u64,
        nft_id: &[u8; 32],
        nft_blinding_factor: &[u8; 32],
        oprf_token: &[u8; 32],
        expected_challenge: &[u8; 32],
        plaintext: &[u8],
        proof: &OwnershipProof,
        candidate_object_commitment: [u8; 32],
    ) -> Result<PublicSealedNftView, PrivateDedupError> {
        if !proof.is_authentic(plaintext, &uploader, epoch, oprf_token, expected_challenge) {
            return Err(PrivateDedupError::OwnershipProofInvalid);
        }

        let padded_bucket_bytes = padme_bucket_bytes(plaintext.len() as u64);
        let fee_charged = padded_bucket_bytes
            .checked_mul(self.sealed_pool_fee_per_bucket_byte)
            .ok_or(PrivateDedupError::InsufficientFeeBalance)?;
        let next_payer = payer_balance
            .checked_sub(fee_charged)
            .ok_or(PrivateDedupError::InsufficientFeeBalance)?;
        let next_pool = self
            .sealed_endowment_pool
            .checked_add(fee_charged)
            .ok_or(PrivateDedupError::InsufficientFeeBalance)?;
        *payer_balance = next_payer;
        self.sealed_endowment_pool = next_pool;

        // Internal cross-owner linkage stays strictly inside validator-private
        // custody index; public state receives only a fresh blinded commitment.
        let canonical_commitment = *self
            .sealed_index
            .entry(*oprf_token)
            .or_insert(candidate_object_commitment);

        let mut blind_hasher = Sha256::new();
        blind_hasher.update(PRIVATE_DEDUP_RECORD_TAG);
        blind_hasher.update(nft_id);
        blind_hasher.update(nft_blinding_factor);
        blind_hasher.update(canonical_commitment);
        let blinded_object_field: [u8; 32] = blind_hasher.finalize().into();

        let summary = self
            .epoch_summaries
            .entry(epoch)
            .or_insert(PublicEpochDedupSummary {
                epoch,
                total_sealed_submissions: 0,
                total_billed_bucket_bytes: 0,
            });
        let next_submissions = summary.total_sealed_submissions.saturating_add(1);
        summary.total_sealed_submissions = next_submissions;
        summary.total_billed_bucket_bytes = summary
            .total_billed_bucket_bytes
            .saturating_add(padded_bucket_bytes);

        Ok(PublicSealedNftView {
            blinded_object_field,
            padded_bucket_bytes,
            fee_charged,
        })
    }

    /// Publicly visible epoch summary (batched counter only; zero hit/miss
    /// breakdown).
    /// WIRING: exposed for post-launch T-Expansion activation.
    #[must_use]
    pub fn public_epoch_summary(&self, epoch: u64) -> PublicEpochDedupSummary {
        self.epoch_summaries
            .get(&epoch)
            .copied()
            .unwrap_or(PublicEpochDedupSummary {
                epoch,
                total_sealed_submissions: 0,
                total_billed_bucket_bytes: 0,
            })
    }

    /// Number of unique physical sealed objects stored internally (used by
    /// node-local storage accounting tests, never exposed on public RPC).
    #[cfg(test)]
    #[must_use]
    pub fn physical_sealed_object_count(&self) -> usize {
        self.sealed_index.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_committee() -> ThresholdOprfCommittee {
        ThresholdOprfCommittee::new([0x42; 32], 3, 5)
    }

    fn collect_shares(
        committee: &ThresholdOprfCommittee,
        digest: &[u8; 32],
    ) -> Vec<OprfPartialShare> {
        vec![
            committee.partial_evaluate(0, digest),
            committee.partial_evaluate(2, digest),
            committee.partial_evaluate(4, digest),
        ]
    }

    #[test]
    fn private_dedup_is_closed_on_testnet() {
        assert!(!ACTIVATION.is_active(0));
        assert!(!ACTIVATION.is_active(500_000));
        let opened = PrivateDedupActivation { height: Some(2_000) };
        assert!(!opened.is_active(1_999));
        assert!(opened.is_active(2_000));
    }

    #[test]
    fn bud3_private_dedup_rate_limited() {
        let committee = test_committee();
        let mut engine = PrivateDedupEngine {
            max_queries_per_epoch: 3,
            ..PrivateDedupEngine::default()
        };
        let alice = Address::from_bytes([0x11; 20]);
        let bob = Address::from_bytes([0x22; 20]);

        for idx in 0..3u8 {
            let digest = [idx; 32];
            let shares = collect_shares(&committee, &digest);
            assert!(engine
                .request_oprf_token(&committee, alice, 7, &digest, &shares)
                .is_ok());
        }

        let fourth_digest = [9u8; 32];
        let fourth_shares = collect_shares(&committee, &fourth_digest);
        assert_eq!(
            engine.request_oprf_token(&committee, alice, 7, &fourth_digest, &fourth_shares),
            Err(PrivateDedupError::RateLimited {
                account: alice,
                epoch: 7,
                limit: 3,
            })
        );

        // Another account in the same epoch and the same account in the next
        // epoch each get a fresh quota.
        assert!(engine
            .request_oprf_token(&committee, bob, 7, &fourth_digest, &fourth_shares)
            .is_ok());
        assert!(engine
            .request_oprf_token(&committee, alice, 8, &fourth_digest, &fourth_shares)
            .is_ok());
    }

    #[test]
    fn bud3_private_dedup_needs_ownership_proof() {
        let committee = test_committee();
        let mut engine = PrivateDedupEngine::default();
        let owner_a = Address::from_bytes([0xA1; 20]);
        let attacker = Address::from_bytes([0xB2; 20]);
        let secret_doc = b"confidential clinical dataset v1 - full bytes required".repeat(16);
        let digest: [u8; 32] = Sha256::digest(&secret_doc).into();
        let shares = collect_shares(&committee, &digest);

        let token_a = engine
            .request_oprf_token(&committee, owner_a, 10, &digest, &shares)
            .unwrap();
        let challenge_a = [0x55; 32];
        let proof_a = OwnershipProof::prove(&secret_doc, &owner_a, 10, &token_a, challenge_a);
        let mut bal_a = 100_000u64;
        engine
            .submit_sealed_upload(
                owner_a,
                &mut bal_a,
                10,
                &[1u8; 32],
                &[0xAA; 32],
                &token_a,
                &challenge_a,
                &secret_doc,
                &proof_a,
                [0xC1; 32],
            )
            .unwrap();

        // Attacker knows the SHA-256 digest and obtains an OPRF token, or tries
        // to replay owner_a's proof under attacker's address / fresh challenge:
        // both must be refused with OwnershipProofInvalid.
        let challenge_b = [0x66; 32];
        let mut bal_attacker = 100_000u64;
        assert_eq!(
            engine.submit_sealed_upload(
                attacker,
                &mut bal_attacker,
                10,
                &[2u8; 32],
                &[0xBB; 32],
                &token_a,
                &challenge_b,
                &secret_doc,
                &proof_a,
                [0xC2; 32],
            ),
            Err(PrivateDedupError::OwnershipProofInvalid)
        );
        assert_eq!(bal_attacker, 100_000, "failed proof must not deduct fee");
    }

    #[test]
    fn bud3_private_dedup_hides_match_from_public() {
        let committee = test_committee();
        let mut hit_world = PrivateDedupEngine::default();
        let mut miss_world = PrivateDedupEngine::default();

        let alice = Address::from_bytes([0x31; 20]);
        let bob = Address::from_bytes([0x32; 20]);
        let shared_doc = vec![0x7Au8; 1_500];
        let distinct_doc = vec![0x4Bu8; 1_520]; // Different length inside same Padme bucket!

        for (engine, second_doc) in [
            (&mut hit_world, &shared_doc),
            (&mut miss_world, &distinct_doc),
        ] {
            let d1: [u8; 32] = Sha256::digest(&shared_doc).into();
            let s1 = collect_shares(&committee, &d1);
            let tok1 = engine
                .request_oprf_token(&committee, alice, 3, &d1, &s1)
                .unwrap();
            let ch1 = [0x10; 32];
            let p1 = OwnershipProof::prove(&shared_doc, &alice, 3, &tok1, ch1);
            let mut bal1 = 50_000u64;
            let view1 = engine
                .submit_sealed_upload(
                    alice,
                    &mut bal1,
                    3,
                    &[0x01; 32],
                    &[0x91; 32],
                    &tok1,
                    &ch1,
                    &shared_doc,
                    &p1,
                    [0xE1; 32],
                )
                .unwrap();

            let d2: [u8; 32] = Sha256::digest(second_doc).into();
            let s2 = collect_shares(&committee, &d2);
            let tok2 = engine
                .request_oprf_token(&committee, bob, 3, &d2, &s2)
                .unwrap();
            let ch2 = [0x20; 32];
            let p2 = OwnershipProof::prove(second_doc, &bob, 3, &tok2, ch2);
            let mut bal2 = 50_000u64;
            let view2 = engine
                .submit_sealed_upload(
                    bob,
                    &mut bal2,
                    3,
                    &[0x02; 32],
                    &[0x92; 32],
                    &tok2,
                    &ch2,
                    second_doc,
                    &p2,
                    [0xE2; 32],
                )
                .unwrap();

            // Two NFTs for the same content still get distinct unlinkable fields.
            assert_ne!(view1.blinded_object_field, view2.blinded_object_field);
            assert_eq!(view1.padded_bucket_bytes, view2.padded_bucket_bytes);
            assert_eq!(view1.fee_charged, view2.fee_charged);
        }

        // Internally hit_world deduplicated to 1 physical object while
        // miss_world stored 2, yet their public epoch summaries and pool
        // balances are byte-for-byte indistinguishable!
        assert_eq!(hit_world.physical_sealed_object_count(), 1);
        assert_eq!(miss_world.physical_sealed_object_count(), 2);
        assert_eq!(
            hit_world.public_epoch_summary(3),
            miss_world.public_epoch_summary(3)
        );
        assert_eq!(
            hit_world.sealed_endowment_pool,
            miss_world.sealed_endowment_pool
        );
    }
}
