//! The claim tree: a binary Merkle tree over claim digests.
//!
//! A leaf is `H("BDLM_CLAIM_ROOT_V1" || 0x00 || digest)` and an inner node is
//! `H("BDLM_CLAIM_ROOT_V1" || 0x01 || left || right)`, so a leaf never reads
//! as a node. A node left without a sibling moves up one level unchanged. An
//! empty list has no root.
//!
//! WIRING: [`MerkleError`] is what [`claims_root`] returns; the frame maps
//! it to its own error, so no other file names it.

use super::hash::{h, TAG_CLAIM_ROOT};
use crate::domain::types::Hash32;

const LEAF: [u8; 1] = [0x00];
const NODE: [u8; 1] = [0x01];

/// Why a root could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The list is empty. An empty segment proves nothing.
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
