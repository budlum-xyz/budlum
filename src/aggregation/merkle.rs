//! The claim tree: a binary Merkle tree over claim digests.
//!
//! A leaf is `H("BDLM_CLAIM_ROOT_V1" || 0x00 || digest)` and an inner node is
//! `H("BDLM_CLAIM_ROOT_V1" || 0x01 || left || right)`, so a leaf never reads
//! as a node. A node left without a sibling moves up one level unchanged. An
//! empty list has no root.
//!
//! WIRING: [`MerkleError`] is what [`claims_root`] returns; [`ClaimMerkleProof`],
//! [`prove_claim_inclusion`], and [`verify_claim_inclusion`] bind segment fraud
//! proofs in [`super::fraud`] and `O(log C)` mobile packets in [`crate::light_client`].

use serde::{Deserialize, Serialize};

use super::hash::{h, TAG_CLAIM_ROOT};
use crate::domain::types::Hash32;

/// The byte a leaf preimage carries after the tag.
pub(super) const LEAF_PREFIX: u8 = 0x00;
/// The byte an inner node preimage carries after the tag.
pub(super) const NODE_PREFIX: u8 = 0x01;
const LEAF: [u8; 1] = [LEAF_PREFIX];
const NODE: [u8; 1] = [NODE_PREFIX];

/// Upper bound on sibling digests in a [`ClaimMerkleProof`] (`2^32` leaves).
pub const MAX_CLAIM_PROOF_DEPTH: usize = 32;

/// Why a root could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The list is empty or the requested leaf index is out of bounds.
    Empty,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "an empty claim list has no root"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Succinct `O(log C)` inclusion opening against a segment's [`claims_root`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMerkleProof {
    /// Exact number of claims committed in the segment (`segment.count`).
    pub segment_count: u32,
    /// Zero-based index of the opened claim digest within the segment.
    pub claim_index: u32,
    /// Bottom-up sibling digests (promoted odd nodes consume no sibling).
    pub siblings: Vec<Hash32>,
}

/// The root of the claim tree over `digests`, in the given order.
///
/// # Errors
///
/// [`MerkleError::Empty`] for an empty list.
pub fn claims_root(digests: &[Hash32]) -> Result<Hash32, MerkleError> {
    let mut level: Vec<Hash32> = digests
        .iter()
        .map(|digest| h(&[TAG_CLAIM_ROOT, &LEAF, digest]))
        .collect();
    loop {
        match level.as_slice() {
            [] => return Err(MerkleError::Empty),
            [root] => return Ok(*root),
            _ => {}
        }
        let (pairs, promoted) = level.as_chunks::<2>();
        let mut next: Vec<Hash32> = pairs
            .iter()
            .map(|[left, right]| h(&[TAG_CLAIM_ROOT, &NODE, left, right]))
            .collect();
        next.extend_from_slice(promoted);
        level = next;
    }
}

/// Builds an `O(log C)` inclusion proof for `digests[claim_index]` against
/// [`claims_root`].
///
/// Convenience: kept for the CLI, fraud-proof builders, and light-client packets.
///
/// # Errors
///
/// Returns [`MerkleError::Empty`] if `digests` is empty, `claim_index` is out
/// of bounds, or `digests.len()` overflows `u32`.
pub fn prove_claim_inclusion(
    digests: &[Hash32],
    claim_index: usize,
) -> Result<ClaimMerkleProof, MerkleError> {
    if digests.is_empty() || claim_index >= digests.len() {
        return Err(MerkleError::Empty);
    }
    let segment_count = u32::try_from(digests.len()).map_err(|_| MerkleError::Empty)?;
    let claim_index_u32 = u32::try_from(claim_index).map_err(|_| MerkleError::Empty)?;
    let mut level: Vec<Hash32> = digests
        .iter()
        .map(|digest| h(&[TAG_CLAIM_ROOT, &LEAF, digest]))
        .collect();
    let mut idx = claim_index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let peer = idx ^ 1;
        if let Some(sibling) = level.get(peer) {
            siblings.push(*sibling);
        }
        let (pairs, promoted) = level.as_chunks::<2>();
        let mut next: Vec<Hash32> = pairs
            .iter()
            .map(|[left, right]| h(&[TAG_CLAIM_ROOT, &NODE, left, right]))
            .collect();
        next.extend_from_slice(promoted);
        level = next;
        idx >>= 1;
    }
    let proof = ClaimMerkleProof {
        segment_count,
        claim_index: claim_index_u32,
        siblings,
    };
    if let (Some(target), Some(root)) = (digests.get(claim_index), level.first()) {
        debug_assert!(verify_claim_inclusion(target, &proof, root));
    }
    Ok(proof)
}

/// Verifies a [`ClaimMerkleProof`] against `segment_claims_root` in `O(log C)` hashes.
#[must_use]
pub fn verify_claim_inclusion(
    claim_digest: &Hash32,
    proof: &ClaimMerkleProof,
    segment_claims_root: &Hash32,
) -> bool {
    if proof.segment_count == 0
        || proof.claim_index >= proof.segment_count
        || proof.siblings.len() > MAX_CLAIM_PROOF_DEPTH
    {
        return false;
    }
    let mut acc = h(&[TAG_CLAIM_ROOT, &LEAF, claim_digest]);
    let mut level_len = proof.segment_count;
    let mut idx = proof.claim_index;
    let mut sib_iter = proof.siblings.iter();
    while level_len > 1 {
        let peer = idx ^ 1;
        if peer < level_len {
            let Some(sibling) = sib_iter.next() else {
                return false;
            };
            acc = if idx & 1 == 0 {
                h(&[TAG_CLAIM_ROOT, &NODE, &acc, sibling])
            } else {
                h(&[TAG_CLAIM_ROOT, &NODE, sibling, &acc])
            };
        }
        idx >>= 1;
        level_len = level_len.div_ceil(2);
    }
    sib_iter.next().is_none() && acc == *segment_claims_root
}
