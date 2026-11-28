//! Multi-scheme committee signature aggregation (`Ed25519`, `BLS`, `ML-DSA-87`).
//!
//! Aggregates distinct sorted committee signatures into a compact Merkleized
//! aggregate commitment bound to `committee_root` and `message_digest`, used by
//! light-client and checkpoint batch verification.
//!
//! Convenience: exposed for light-client and checkpoint batch signature aggregation.

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

/// Supported committee signature algorithms for committee batch aggregation.
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

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_threshold_witness(
    w: &ThresholdWitness,
    expected_signer_index: u32,
    message_digest: &[u8; 32],
) -> bool {
    if w.share_index != expected_signer_index || w.commitment == [0u8; 32] {
        return false;
    }
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(b"BDLM_SIGAGG_SHARE_V1");
    buf.extend_from_slice(&w.share_index.to_le_bytes());
    buf.extend_from_slice(&w.epoch.to_le_bytes());
    buf.extend_from_slice(&w.commitment);
    buf.extend_from_slice(message_digest);
    ct_eq_32(&keccak256_bytes(&buf), &w.tag)
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

/// Compact aggregated multi-signature commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedSignatureBatch {
    pub message_digest: [u8; 32],
    pub committee_root: [u8; 32],
    pub signer_indices: Vec<u32>,
    pub total_weight: u64,
    pub aggregate_digest: [u8; 32],
    pub signatures: Vec<SignerSignature>,
}

/// Errors returned by committee signature aggregation or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigAggError {
    EmptyBatch,
    DuplicateSigner(u32),
    UnsortedSigner(u32),
    ZeroWeight(u32),
    MalformedSignature(u32),
    InvalidThresholdWitness(u32),
    InsufficientWeight {
        have: u64,
        required: u64,
    },
    CommitteeMismatch,
    AggregateDigestMismatch,
    /// The signature of this signer does not verify for the batch's message.
    InvalidSignature(u32),
}

fn leaf_hash(sig: &SignerSignature, message_digest: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(160 + sig.signature.len());
    preimage.extend_from_slice(b"BDLM_SIGAGG_LEAF_V1");
    preimage.extend_from_slice(message_digest);
    preimage.extend_from_slice(&sig.signer_index.to_le_bytes());
    preimage.extend_from_slice(&sig.weight.to_le_bytes());
    preimage.push(sig.scheme as u8);
    preimage.extend_from_slice(&sig.public_key_digest);
    preimage.extend_from_slice(&(sig.signature.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&sig.signature);
    match &sig.threshold_witness {
        None => preimage.push(0),
        Some(w) => {
            preimage.push(1);
            preimage.extend_from_slice(&w.share_index.to_le_bytes());
            preimage.extend_from_slice(&w.epoch.to_le_bytes());
            preimage.extend_from_slice(&w.commitment);
            preimage.extend_from_slice(&w.tag);
        }
    }
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

/// Fold ordered leaf digests into a domain-separated binary Merkle root.
///
/// Leaves are prefixed with `0x00`, internal pairs with `0x01`, and odd lone
/// nodes with `0x02` (never duplicated) to prevent CVE-2012-2459 odd-leaf
/// collisions and leaf/internal second-preimage ambiguity.
#[must_use]
pub fn aggregate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut buf = [0u8; 33];
            buf[0] = 0x00;
            buf[1..].copy_from_slice(leaf);
            keccak256_bytes(&buf)
        })
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            if let [left, right] = pair {
                let mut node = [0u8; 65];
                node[0] = 0x01;
                node[1..33].copy_from_slice(left);
                node[33..].copy_from_slice(right);
                next.push(keccak256_bytes(&node));
            } else if let [lone] = pair {
                let mut node = [0u8; 33];
                node[0] = 0x02;
                node[1..].copy_from_slice(lone);
                next.push(keccak256_bytes(&node));
            }
        }
        layer = next;
    }
    layer.first().copied().unwrap_or([0u8; 32])
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
            if !verify_threshold_witness(w, sig.signer_index, &message_digest) {
                return Err(SigAggError::InvalidThresholdWitness(sig.signer_index));
            }
        }
        total_weight = total_weight
            .checked_add(sig.weight)
            .ok_or(SigAggError::MalformedSignature(sig.signer_index))?;
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

/// A committee member as the verifier knows it, not as a batch claims it:
/// `(signer_index, weight, scheme, public_key_digest)`, the tuple [`compute_committee_root`]
/// commits to.
pub type CommitteeMember = (u32, u64, SignatureScheme, [u8; 32]);

/// Verify an [`AggregatedSignatureBatch`] against the committee the verifier trusts.
///
/// A batch carries its own committee root, per-signer weights and key digests, so none of
/// that authenticates anything: a batch built from filler bytes re-hashes cleanly. The
/// verifier therefore supplies the committee and the signature check, and nothing the batch
/// says is taken as given:
///
/// * the committee root is derived from `committee`, and the batch must carry it;
/// * every signature entry must match a member of `committee` in index, weight, scheme and
///   key digest, so a batch cannot name a signer the committee does not contain or declare a
///   weight of its own;
/// * `verify_signature(entry, message_digest)` must accept every signature, and one that does
///   not fails the whole batch;
/// * the quorum is the weight of the signers whose signatures verified. The batch's own
///   `total_weight` is only checked against the recomputed one.
///
/// # Errors
///
/// [`SigAggError::CommitteeMismatch`] when the root or an entry does not match `committee`,
/// the errors of [`aggregate_signatures`] for a malformed batch,
/// [`SigAggError::AggregateDigestMismatch`] when a commitment was altered,
/// [`SigAggError::InvalidSignature`] when `verify_signature` refuses an entry, and
/// [`SigAggError::InsufficientWeight`] when the verified weight is below `required_weight`.
pub fn verify_aggregated_batch<F>(
    batch: &AggregatedSignatureBatch,
    committee: &[CommitteeMember],
    required_weight: u64,
    verify_signature: F,
) -> Result<(), SigAggError>
where
    F: Fn(&SignerSignature, &[u8; 32]) -> bool,
{
    if required_weight == 0 {
        return Err(SigAggError::InsufficientWeight {
            have: 0,
            required: 0,
        });
    }
    if committee.is_empty() {
        return Err(SigAggError::CommitteeMismatch);
    }
    let mut seen_committee = BTreeSet::new();
    for &(idx, weight, _, key) in committee {
        if !seen_committee.insert(idx) || weight == 0 || key == [0u8; 32] {
            return Err(SigAggError::CommitteeMismatch);
        }
    }
    if !ct_eq_32(&batch.committee_root, &compute_committee_root(committee)) {
        return Err(SigAggError::CommitteeMismatch);
    }
    for sig in &batch.signatures {
        let Some(&(_, weight, scheme, key)) = committee.iter().find(|m| m.0 == sig.signer_index)
        else {
            return Err(SigAggError::CommitteeMismatch);
        };
        if sig.weight != weight || sig.scheme != scheme || sig.public_key_digest != key {
            return Err(SigAggError::CommitteeMismatch);
        }
    }
    let recomputed = aggregate_signatures(
        batch.message_digest,
        batch.committee_root,
        batch.signatures.clone(),
    )?;
    if !ct_eq_32(&recomputed.aggregate_digest, &batch.aggregate_digest)
        || recomputed.total_weight != batch.total_weight
        || recomputed.signer_indices != batch.signer_indices
    {
        return Err(SigAggError::AggregateDigestMismatch);
    }
    let mut verified_weight = 0u64;
    for sig in &batch.signatures {
        if !verify_signature(sig, &batch.message_digest) {
            return Err(SigAggError::InvalidSignature(sig.signer_index));
        }
        verified_weight = verified_weight
            .checked_add(sig.weight)
            .ok_or(SigAggError::MalformedSignature(sig.signer_index))?;
    }
    if verified_weight < required_weight {
        return Err(SigAggError::InsufficientWeight {
            have: verified_weight,
            required: required_weight,
        });
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

    /// What a signature is worth in these tests: the key digest and the message, hashed, repeated
    /// to the length of the scheme. A stand-in for a real verifier, which the caller supplies.
    fn sign(key: &[u8; 32], message: &[u8; 32], scheme: SignatureScheme) -> Vec<u8> {
        let mut preimage = Vec::from(&key[..]);
        preimage.extend_from_slice(message);
        let digest = keccak256_bytes(&preimage);
        digest
            .iter()
            .copied()
            .cycle()
            .take(scheme.min_signature_len())
            .collect()
    }

    fn verifies(entry: &SignerSignature, message: &[u8; 32]) -> bool {
        entry.signature == sign(&entry.public_key_digest, message, entry.scheme)
    }

    fn committee() -> Vec<CommitteeMember> {
        vec![
            (0, 30, SignatureScheme::Ed25519, [1u8; 32]),
            (1, 40, SignatureScheme::Bls, [2u8; 32]),
            (2, 50, SignatureScheme::MlDsa87, [3u8; 32]),
        ]
    }

    fn honest(member: &CommitteeMember, message: &[u8; 32]) -> SignerSignature {
        SignerSignature {
            signer_index: member.0,
            weight: member.1,
            scheme: member.2,
            public_key_digest: member.3,
            signature: sign(&member.3, message, member.2),
            threshold_witness: None,
        }
    }

    fn batch_of(
        committee: &[CommitteeMember],
        message: [u8; 32],
        entries: Vec<SignerSignature>,
    ) -> AggregatedSignatureBatch {
        aggregate_signatures(message, compute_committee_root(committee), entries).unwrap()
    }

    #[test]
    fn multi_scheme_committee_batch_aggregates_and_verifies() {
        let committee = committee();
        let msg = [0x11u8; 32];
        let entries: Vec<_> = committee.iter().map(|m| honest(m, &msg)).collect();
        let batch = batch_of(&committee, msg, entries);
        assert_eq!(batch.total_weight, 120);
        verify_aggregated_batch(&batch, &committee, 80, verifies).expect("quorum verifies");

        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 121, verifies).unwrap_err(),
            SigAggError::InsufficientWeight {
                have: 120,
                required: 121
            }
        );

        let mut tampered = batch;
        tampered.aggregate_digest[0] ^= 1;
        assert_eq!(
            verify_aggregated_batch(&tampered, &committee, 80, verifies).unwrap_err(),
            SigAggError::AggregateDigestMismatch
        );
    }

    /// The batch used to be re-hashed and nothing else: filler bytes of the right length, the
    /// committee's own root and weights, and a quorum passed. No signature was ever verified.
    #[test]
    fn a_fabricated_batch_is_refused() {
        let committee = committee();
        let msg = [0x44u8; 32];
        let entries: Vec<_> = committee
            .iter()
            .map(|m| SignerSignature {
                signature: vec![0xA5; m.2.min_signature_len()],
                ..honest(m, &msg)
            })
            .collect();
        let batch = batch_of(&committee, msg, entries);
        assert_eq!(batch.total_weight, 120);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::InvalidSignature(0)
        );
    }

    #[test]
    fn a_signature_over_another_message_is_refused() {
        let committee = committee();
        let signed_message = [0x55u8; 32];
        let batch_message = [0x66u8; 32];
        let entries: Vec<_> = committee
            .iter()
            .map(|m| honest(m, &signed_message))
            .collect();
        let batch = batch_of(&committee, batch_message, entries);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::InvalidSignature(0)
        );
    }

    /// One bad signature fails the batch, even when the others are a quorum on their own.
    #[test]
    fn a_signature_that_does_not_verify_fails_a_batch_that_is_a_quorum_without_it() {
        let committee = committee();
        let msg = [0x77u8; 32];
        let mut entries: Vec<_> = committee.iter().map(|m| honest(m, &msg)).collect();
        entries[2].signature = vec![0xA5; SignatureScheme::MlDsa87.min_signature_len()];
        let batch = batch_of(&committee, msg, entries);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 60, verifies).unwrap_err(),
            SigAggError::InvalidSignature(2)
        );
    }

    /// The quorum is the committee weight of the verified signers. A batch used to declare its
    /// own weight: the sum of the weights its entries claimed.
    #[test]
    fn a_batch_cannot_declare_its_own_weight() {
        let committee = committee();
        let msg = [0x88u8; 32];
        let mut entry = honest(&committee[0], &msg);
        entry.weight = 1_000_000;
        let batch = batch_of(&committee, msg, vec![entry]);
        assert_eq!(batch.total_weight, 1_000_000);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch
        );
        // The honest weight of the same signer is below the quorum.
        let honest_batch = batch_of(&committee, msg, vec![honest(&committee[0], &msg)]);
        assert_eq!(
            verify_aggregated_batch(&honest_batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::InsufficientWeight {
                have: 30,
                required: 80
            }
        );
    }

    #[test]
    fn a_batch_cannot_name_a_signer_the_committee_does_not_contain() {
        let committee = committee();
        let msg = [0x99u8; 32];
        let outsider: CommitteeMember = (7, 500, SignatureScheme::Ed25519, [9u8; 32]);
        let batch = batch_of(&committee, msg, vec![honest(&outsider, &msg)]);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch
        );
    }

    /// A member's scheme and key are the committee's. An attacker's own key, with a signature
    /// that is valid under it, must not stand in for the member.
    #[test]
    fn a_batch_cannot_switch_the_scheme_or_the_key_of_a_member() {
        let committee = committee();
        let msg = [0xAAu8; 32];
        let own_key: CommitteeMember = (0, committee[0].1, committee[0].2, [0xEEu8; 32]);
        let batch = batch_of(&committee, msg, vec![honest(&own_key, &msg)]);
        assert!(
            verifies(&batch.signatures[0], &msg),
            "valid under its own key"
        );
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 1, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch
        );

        let other_scheme: CommitteeMember =
            (0, committee[0].1, SignatureScheme::MlDsa87, committee[0].3);
        let batch = batch_of(&committee, msg, vec![honest(&other_scheme, &msg)]);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 1, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch
        );
    }

    /// The root is the verifier's: a batch built over a committee of its own is refused.
    #[test]
    fn a_batch_cannot_carry_a_committee_root_the_verifier_did_not_derive() {
        let committee = committee();
        let msg = [0xBBu8; 32];
        let mut forged_committee = committee.clone();
        forged_committee[0].1 = 10_000;
        let forged_entry = honest(&forged_committee[0], &msg);
        let batch = batch_of(&forged_committee, msg, vec![forged_entry]);
        assert_eq!(
            verify_aggregated_batch(&batch, &committee, 80, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch
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

    #[test]
    fn budprf02_sigagg_refuses_merkle_malleability_witness_strip_mismatch_and_bad_committee() {
        // 1. CVE-2012-2459: odd-leaf duplication must NOT collide [a, b, c] with [a, b, c, c].
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        assert_ne!(
            aggregate_merkle_root(&[a, b, c]),
            aggregate_merkle_root(&[a, b, c, c]),
            "odd-leaf duplication must not collide 3-leaf and 4-leaf Merkle roots"
        );
        // Domain separation: 2-leaf internal node must not collide with 1-leaf raw digest.
        let mut concat_ab = [0u8; 64];
        concat_ab[..32].copy_from_slice(&a);
        concat_ab[32..].copy_from_slice(&b);
        assert_ne!(
            aggregate_merkle_root(&[a, b]),
            aggregate_merkle_root(&[keccak256_bytes(&concat_ab)]),
            "leaf and internal Merkle nodes must be domain-separated"
        );

        // 2. ThresholdWitness must be bound into aggregate_digest, match signer_index, and
        // carry a non-zero commitment.
        let committee = committee();
        let msg = [0x7Au8; 32];
        let make_witness = |share_index: u32, epoch: u64, commitment: [u8; 32]| {
            let mut buf = Vec::with_capacity(96);
            buf.extend_from_slice(b"BDLM_SIGAGG_SHARE_V1");
            buf.extend_from_slice(&share_index.to_le_bytes());
            buf.extend_from_slice(&epoch.to_le_bytes());
            buf.extend_from_slice(&commitment);
            buf.extend_from_slice(&msg);
            ThresholdWitness {
                share_index,
                epoch,
                commitment,
                tag: keccak256_bytes(&buf),
            }
        };

        let mut e0 = honest(&committee[0], &msg);
        e0.threshold_witness = Some(make_witness(0, 7, [0x42u8; 32]));
        let batch = batch_of(&committee, msg, vec![e0, honest(&committee[1], &msg)]);
        verify_aggregated_batch(&batch, &committee, 70, verifies)
            .expect("batch with valid threshold witness verifies");

        // Stripping threshold_witness must break aggregate_digest.
        let mut stripped = batch.clone();
        stripped.signatures[0].threshold_witness = None;
        assert_eq!(
            verify_aggregated_batch(&stripped, &committee, 70, verifies).unwrap_err(),
            SigAggError::AggregateDigestMismatch,
            "stripping threshold_witness must be caught by aggregate_digest"
        );

        // Witness share_index != signer_index must be refused.
        let mut wrong_share = honest(&committee[0], &msg);
        wrong_share.threshold_witness = Some(make_witness(1, 7, [0x42u8; 32]));
        assert_eq!(
            aggregate_signatures(msg, compute_committee_root(&committee), vec![wrong_share])
                .unwrap_err(),
            SigAggError::InvalidThresholdWitness(0),
            "threshold witness with mismatched share_index must be refused"
        );

        // Zero commitment witness must be refused.
        let mut zero_comm = honest(&committee[0], &msg);
        zero_comm.threshold_witness = Some(make_witness(0, 7, [0u8; 32]));
        assert_eq!(
            aggregate_signatures(msg, compute_committee_root(&committee), vec![zero_comm])
                .unwrap_err(),
            SigAggError::InvalidThresholdWitness(0),
            "threshold witness with zero commitment must be refused"
        );

        // 3. Weight overflow must fail closed (no silent saturating_add).
        let mut ov0 = sample_sig(0, SignatureScheme::Ed25519, u64::MAX);
        ov0.signature[0] = 0x99;
        let ov1 = sample_sig(1, SignatureScheme::Bls, 1);
        assert!(
            aggregate_signatures(msg, [0x33u8; 32], vec![ov0, ov1]).is_err(),
            "weight overflow must fail closed instead of saturating"
        );

        // 4. required_weight == 0 and duplicate committee signer_index must fail closed.
        assert!(
            verify_aggregated_batch(&batch, &committee, 0, verifies).is_err(),
            "zero required_weight must be refused"
        );
        let dup_committee = vec![
            (0, 30, SignatureScheme::Ed25519, [1u8; 32]),
            (0, 500, SignatureScheme::Ed25519, [2u8; 32]),
        ];
        let dup_batch = batch_of(&dup_committee, msg, vec![honest(&dup_committee[0], &msg)]);
        assert_eq!(
            verify_aggregated_batch(&dup_batch, &dup_committee, 10, verifies).unwrap_err(),
            SigAggError::CommitteeMismatch,
            "duplicate signer_index in committee must be refused"
        );
    }
}
