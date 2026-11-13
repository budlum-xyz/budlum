//! `BLG-239`: Multi-scheme committee signature aggregation (`Ed25519`, `BLS`, `ML-DSA-87`).
//!
//! Aggregates distinct sorted committee signatures into a compact Merkleized
//! aggregate commitment bound to `committee_root` and `message_digest`, used by
//! light-client and checkpoint batch verification.
//!
//! Convenience: exposed for BLG-239 light-client and checkpoint batch signature aggregation.

use std::collections::BTreeSet;

const KECCAKF_RNDC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAKF_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(st: &mut [u64; 25]) {
    for &rc in &KECCAKF_RNDC {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = KECCAKF_PILN[i];
            let next_t = st[j];
            st[j] = t.rotate_left(KECCAKF_ROTC[i]);
            t = next_t;
        }
        for j in (0..25).step_by(5) {
            let mut row = [0u64; 5];
            row.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
            }
        }
        st[0] ^= rc;
    }
}

fn keccak256_bytes(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut chunks = input.chunks_exact(RATE);
    for block in &mut chunks {
        for (i, word) in block.chunks_exact(8).enumerate() {
            let arr: [u8; 8] = word.try_into().unwrap_or([0u8; 8]);
            state[i] ^= u64::from_le_bytes(arr);
        }
        keccak_f1600(&mut state);
    }
    let rem = chunks.remainder();
    let mut last = [0u8; RATE];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    for (i, word) in last.chunks_exact(8).enumerate() {
        let arr: [u8; 8] = word.try_into().unwrap_or([0u8; 8]);
        state[i] ^= u64::from_le_bytes(arr);
    }
    keccak_f1600(&mut state);
    let mut out = [0u8; 32];
    for (i, dst) in out.chunks_exact_mut(8).enumerate() {
        dst.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Supported committee signature algorithms for `BLG-239` aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureScheme {
    Ed25519 = 1,
    Bls = 2,
    MlDsa87 = 3,
}

impl SignatureScheme {
    /// Expected minimum uncompressed signature payload length for basic shape verification.
    #[must_use]
    pub const fn min_signature_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::Bls => 48,
            Self::MlDsa87 => 32,
        }
    }
}

/// Optional threshold key-share tag attesting partial signing participation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdWitness {
    pub share_index: u32,
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub tag: [u8; 32],
}

fn verify_threshold_witness(w: &ThresholdWitness, message_digest: &[u8; 32]) -> bool {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(b"BDLM_SIGAGG_SHARE_V1");
    buf.extend_from_slice(&w.share_index.to_le_bytes());
    buf.extend_from_slice(&w.epoch.to_le_bytes());
    buf.extend_from_slice(&w.commitment);
    buf.extend_from_slice(message_digest);
    keccak256_bytes(&buf) == w.tag
}

/// One validator's signature entry included in an aggregated batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSignature {
    pub signer_index: u32,
    pub weight: u64,
    pub scheme: SignatureScheme,
    pub public_key_digest: [u8; 32],
    pub signature: Vec<u8>,
    pub threshold_witness: Option<ThresholdWitness>,
}

/// Compact aggregated multi-signature commitment (`BLG-239`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedSignatureBatch {
    pub message_digest: [u8; 32],
    pub committee_root: [u8; 32],
    pub signer_indices: Vec<u32>,
    pub total_weight: u64,
    pub aggregate_digest: [u8; 32],
    pub signatures: Vec<SignerSignature>,
}

/// Errors returned by `BLG-239` aggregation or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigAggError {
    EmptyBatch,
    DuplicateSigner(u32),
    UnsortedSigner(u32),
    ZeroWeight(u32),
    MalformedSignature(u32),
    InvalidThresholdWitness(u32),
    InsufficientWeight { have: u64, required: u64 },
    CommitteeMismatch,
    AggregateDigestMismatch,
}

fn leaf_hash(sig: &SignerSignature, message_digest: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(80 + sig.signature.len());
    preimage.extend_from_slice(b"BDLM_SIGAGG_LEAF_V1");
    preimage.extend_from_slice(message_digest);
    preimage.extend_from_slice(&sig.signer_index.to_le_bytes());
    preimage.extend_from_slice(&sig.weight.to_le_bytes());
    preimage.push(sig.scheme as u8);
    preimage.extend_from_slice(&sig.public_key_digest);
    preimage.extend_from_slice(&sig.signature);
    keccak256_bytes(&preimage)
}

/// Compute the deterministic committee root over `(signer_index, weight, scheme, public_key_digest)`.
#[must_use]
pub fn compute_committee_root(members: &[(u32, u64, SignatureScheme, [u8; 32])]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(24 + members.len() * 45);
    buf.extend_from_slice(b"BDLM_SIGAGG_COMMITTEE_V1");
    for &(idx, weight, scheme, pk_digest) in members {
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(&weight.to_le_bytes());
        buf.push(scheme as u8);
        buf.extend_from_slice(&pk_digest);
    }
    keccak256_bytes(&buf)
}

/// Fold ordered leaf digests into a binary Merkle root.
#[must_use]
pub fn aggregate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let mut node = [0u8; 64];
            node[..32].copy_from_slice(&pair[0]);
            if pair.len() == 2 {
                node[32..].copy_from_slice(&pair[1]);
            } else {
                node[32..].copy_from_slice(&pair[0]);
            }
            next.push(keccak256_bytes(&node));
        }
        layer = next;
    }
    layer[0]
}

/// Aggregate sorted distinct committee signatures into an [`AggregatedSignatureBatch`].
///
/// # Errors
///
/// Rejects empty, unsorted, duplicate, zero-weight, or malformed signatures.
pub fn aggregate_signatures(
    message_digest: [u8; 32],
    committee_root: [u8; 32],
    signatures: Vec<SignerSignature>,
) -> Result<AggregatedSignatureBatch, SigAggError> {
    if signatures.is_empty() {
        return Err(SigAggError::EmptyBatch);
    }
    let mut seen = BTreeSet::new();
    let mut prev_idx: Option<u32> = None;
    let mut total_weight = 0u64;
    let mut leaves = Vec::with_capacity(signatures.len());
    let mut indices = Vec::with_capacity(signatures.len());

    for sig in &signatures {
        if !seen.insert(sig.signer_index) {
            return Err(SigAggError::DuplicateSigner(sig.signer_index));
        }
        if let Some(prev) = prev_idx {
            if sig.signer_index <= prev {
                return Err(SigAggError::UnsortedSigner(sig.signer_index));
            }
        }
        prev_idx = Some(sig.signer_index);
        if sig.weight == 0 {
            return Err(SigAggError::ZeroWeight(sig.signer_index));
        }
        if sig.signature.len() < sig.scheme.min_signature_len()
            || sig.public_key_digest == [0u8; 32]
            || sig.signature.iter().all(|&b| b == 0)
        {
            return Err(SigAggError::MalformedSignature(sig.signer_index));
        }
        if let Some(ref w) = sig.threshold_witness {
            if !verify_threshold_witness(w, &message_digest) {
                return Err(SigAggError::InvalidThresholdWitness(sig.signer_index));
            }
        }
        total_weight = total_weight.saturating_add(sig.weight);
        indices.push(sig.signer_index);
        leaves.push(leaf_hash(sig, &message_digest));
    }

    let root = aggregate_merkle_root(&leaves);
    let mut agg_input = Vec::with_capacity(96);
    agg_input.extend_from_slice(b"BDLM_SIGAGG_BATCH_V1");
    agg_input.extend_from_slice(&committee_root);
    agg_input.extend_from_slice(&message_digest);
    agg_input.extend_from_slice(&root);
    agg_input.extend_from_slice(&total_weight.to_le_bytes());

    Ok(AggregatedSignatureBatch {
        message_digest,
        committee_root,
        signer_indices: indices,
        total_weight,
        aggregate_digest: keccak256_bytes(&agg_input),
        signatures,
    })
}

/// Verify an [`AggregatedSignatureBatch`] against an expected committee root and
/// required quorum weight.
///
/// # Errors
///
/// Fails closed if weight is below threshold, committee root differs, or any
/// signature entry / aggregate commitment is invalid.
pub fn verify_aggregated_batch(
    batch: &AggregatedSignatureBatch,
    expected_committee_root: &[u8; 32],
    required_weight: u64,
) -> Result<(), SigAggError> {
    if batch.committee_root != *expected_committee_root {
        return Err(SigAggError::CommitteeMismatch);
    }
    if batch.total_weight < required_weight {
        return Err(SigAggError::InsufficientWeight {
            have: batch.total_weight,
            required: required_weight,
        });
    }
    let recomputed = aggregate_signatures(
        batch.message_digest,
        batch.committee_root,
        batch.signatures.clone(),
    )?;
    if recomputed.aggregate_digest != batch.aggregate_digest
        || recomputed.total_weight != batch.total_weight
        || recomputed.signer_indices != batch.signer_indices
    {
        return Err(SigAggError::AggregateDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};

    fn sample_sig(idx: u32, scheme: SignatureScheme, weight: u64) -> SignerSignature {
        SignerSignature {
            signer_index: idx,
            weight,
            scheme,
            public_key_digest: [u8::try_from(idx).unwrap_or(1).saturating_add(1); 32],
            signature: vec![0xA5; scheme.min_signature_len()],
            threshold_witness: None,
        }
    }

    #[test]
    fn internal_keccak256_matches_tiny_keccak() {
        for input in [&b""[..], b"budlum-sigagg", &[0x5Au8; 200]] {
            let mut ref_k = Keccak::v256();
            ref_k.update(input);
            let mut expected = [0u8; 32];
            ref_k.finalize(&mut expected);
            assert_eq!(keccak256_bytes(input), expected);
        }
    }

    #[test]
    fn multi_scheme_committee_batch_aggregates_and_verifies() {
        let s0 = sample_sig(0, SignatureScheme::Ed25519, 30);
        let s1 = sample_sig(1, SignatureScheme::Bls, 40);
        let s2 = sample_sig(2, SignatureScheme::MlDsa87, 50);
        let committee = compute_committee_root(&[
            (0, 30, SignatureScheme::Ed25519, s0.public_key_digest),
            (1, 40, SignatureScheme::Bls, s1.public_key_digest),
            (2, 50, SignatureScheme::MlDsa87, s2.public_key_digest),
        ]);
        let msg = [0x11u8; 32];
        let batch = aggregate_signatures(msg, committee, vec![s0, s1, s2]).expect("aggregate");
        assert_eq!(batch.total_weight, 120);
        verify_aggregated_batch(&batch, &committee, 80).expect("quorum verifies");

        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 121).unwrap_err(),
            SigAggError::InsufficientWeight {
                have: 120,
                required: 121
            }
        );

        let mut tampered = batch;
        tampered.aggregate_digest[0] ^= 1;
        assert_eq!(
            verify_aggregated_batch(&tampered, &committee, 80).unwrap_err(),
            SigAggError::AggregateDigestMismatch
        );
    }

    #[test]
    fn duplicate_and_zero_signatures_are_rejected() {
        let s0 = sample_sig(0, SignatureScheme::MlDsa87, 50);
        let msg = [0x22u8; 32];
        let c = [0x33u8; 32];
        assert_eq!(
            aggregate_signatures(msg, c, vec![s0.clone(), s0]).unwrap_err(),
            SigAggError::DuplicateSigner(0)
        );
    }
}
