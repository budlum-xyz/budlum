//! Merkle tree structure shared by QC quorum blobs.
//!
//! The tree shape (sibling selection, layer growth, root extraction, the
//! proof walk) is pure and does not depend on the hash function.
//!
//! The production binding is SHA3-256 ([`combine_sha3`]); the Kani mirror in
//! `kani/src/lib.rs` model-checks the shape on a bounded fixed-array model
//! with an abstract combine, and `qc_merkle_matches_the_kani_mirror` pins the
//! two to each other over concrete vectors. The leaf format is the caller's
//! concern: `QcBlob` feeds the per-entry digest of its signature list in,
//! this module never sees a signature.

use sha3::{Digest, Sha3_256};

/// SHA3-256 node combine, the production hash for QC blob Merkle trees.
///
/// Mirrors the internal-node hash of `QcBlob::merkle_layers` exactly: the two
/// child digests concatenated into one SHA3-256 call, no domain prefix (the
/// tree is already domain-separated by its position in the block).
#[must_use]
pub fn combine_sha3(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

/// Sibling index under the production rule.
///
/// An even node pairs with the next node; when it is the odd tail of its
/// layer it pairs with itself. An odd node pairs with the previous node.
///
/// Precondition: `index < layer_len` and `layer_len >= 1`. The Kani harness
/// `merkle_sibling_index_is_in_bounds` proves the result is always inside the
/// layer under that precondition.
#[must_use]
pub fn merkle_sibling_index(index: usize, layer_len: usize) -> usize {
    if index.is_multiple_of(2) {
        (index + 1).min(layer_len.saturating_sub(1))
    } else {
        index.saturating_sub(1)
    }
}

/// One parent layer from the layer below.
///
/// Nodes are paired left to right; an odd tail is duplicated as its own right
/// child. The Kani harness `every_parent_layer_is_smaller_than_its_child_layer`
/// proves the parent count is strictly smaller for layers of two or more
/// nodes, which is what makes the layer loop terminate.
#[must_use]
pub fn merkle_parent_layer(
    layer: &[[u8; 32]],
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> Vec<[u8; 32]> {
    let mut next_level = Vec::new();
    let mut i = 0;
    while i < layer.len() {
        let left = &layer[i];
        let right = if i + 1 < layer.len() {
            &layer[i + 1]
        } else {
            left
        };
        next_level.push(combine(left, right));
        i += 2;
    }
    next_level
}

/// All layers of the Merkle tree over `leaves`, leaf layer first, root last.
///
/// An empty leaf list produces no layers. A non-empty list always terminates
/// with a single-node layer (proved by the Kani harness
/// `merkle_tree_terminates_with_a_single_root`).
#[must_use]
pub fn merkle_layers(
    leaves: &[[u8; 32]],
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut layers = Vec::new();
    layers.push(leaves.to_vec());
    while layers.last().map_or(0, Vec::len) > 1 {
        let current = layers.last().cloned().unwrap_or_default();
        layers.push(merkle_parent_layer(&current, combine));
    }
    layers
}

/// The root digest, or all zeros for an empty tree.
#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]], combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32]) -> [u8; 32] {
    merkle_layers(leaves, combine)
        .last()
        .and_then(|layer| layer.first())
        .copied()
        .unwrap_or([0u8; 32])
}

/// The sibling digests a verifier needs to rebuild the root from
/// `leaf_index`, in layer order; `None` when the leaf is out of range or the
/// tree is empty.
///
/// The Kani harness `every_merkle_proof_rebuilds_the_root` proves that
/// rebuilding from these digests reproduces the root.
#[must_use]
pub fn merkle_proof(
    leaves: &[[u8; 32]],
    leaf_index: usize,
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> Option<Vec<[u8; 32]>> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let layers = merkle_layers(leaves, combine);
    let mut proof = Vec::new();
    let mut idx = leaf_index;
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        let sibling_idx = merkle_sibling_index(idx, layer.len());
        proof.push(layer[sibling_idx]);
        idx /= 2;
    }
    Some(proof)
}

/// The digest a verifier rebuilds for `leaf_index` by walking the layers
/// with the production sibling rule; `None` when the leaf is out of range or
/// the tree is empty.
///
/// This is the shape the Kani harness `every_merkle_proof_rebuilds_the_root`
/// checks.
///
/// The two children are ordered by position: an even node is the left child,
/// an odd node the right child. This matches `QcFaultProof::verify_inclusion`
/// and is load-bearing for any non-commutative combine, which is why the Kani
/// harness uses a deliberately non-commutative abstract combine.
#[must_use]
pub fn merkle_rebuild_root(
    leaves: &[[u8; 32]],
    leaf_index: usize,
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> Option<[u8; 32]> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let layers = merkle_layers(leaves, combine);
    let mut idx = leaf_index;
    let mut cur = leaves[leaf_index];
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        let sibling_idx = merkle_sibling_index(idx, layer.len());
        let sibling = layer[sibling_idx];
        cur = if idx.is_multiple_of(2) {
            combine(&cur, &sibling)
        } else {
            combine(&sibling, &cur)
        };
        idx /= 2;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = [7u8; 32];
        let root = merkle_root(&[leaf], combine_sha3);
        assert_eq!(root, leaf);
    }

    #[test]
    fn empty_tree_has_no_layers_and_zero_root() {
        assert!(merkle_layers(&[], combine_sha3).is_empty());
        assert_eq!(merkle_root(&[], combine_sha3), [0u8; 32]);
        assert_eq!(merkle_proof(&[], 0, combine_sha3), None);
    }

    #[test]
    fn odd_tail_is_duplicated() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let layers = merkle_layers(&leaves, combine_sha3);
        // Three leaves produce three layers: 3 -> 2 -> 1.
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].len(), 3);
        assert_eq!(layers[1].len(), 2);
        assert_eq!(layers[2].len(), 1);
        let expected = combine_sha3(&leaves[2], &leaves[2]);
        assert_eq!(layers[1][1], expected);
    }

    #[test]
    fn every_proof_rebuilds_the_root() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];
        let root = merkle_root(&leaves, combine_sha3);
        for i in 0..leaves.len() {
            assert_eq!(
                merkle_rebuild_root(&leaves, i, combine_sha3),
                Some(root),
                "leaf {i}"
            );
        }
    }

    /// A non-commutative combine must not break the rebuild.
    ///
    /// `combine_sha3` is already non-commutative, but the dedicated helper
    /// makes the ordering requirement explicit: an odd-indexed child is the
    /// right child, and swapping it with its sibling must change the digest.
    /// The Kani mirror combine (`combine_nodes_u64`), applied per 8-byte
    /// chunk so the u8 leaf type cannot degenerate the rotation the way a
    /// byte-wise rotate-xor does (17 mod 8 and 7 are inverse shifts on a
    /// byte, which made the byte-wise form commutative).
    fn rot_xor(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in 0..4 {
            let l = u64::from_le_bytes(left[chunk * 8..chunk * 8 + 8].try_into().expect("8 bytes"));
            let r =
                u64::from_le_bytes(right[chunk * 8..chunk * 8 + 8].try_into().expect("8 bytes"));
            let combined = l.rotate_left(17) ^ r.rotate_right(7);
            out[chunk * 8..chunk * 8 + 8].copy_from_slice(&combined.to_le_bytes());
        }
        out
    }

    #[test]
    fn rebuild_orders_odd_children_as_right_children() {
        // Non-repeating leaves: uniform bytes (all-0x01, all-0x02) make the
        // rotate-xor combine degenerate and mask the ordering requirement.
        let mut leaf0 = [0u8; 32];
        let mut leaf1 = [0u8; 32];
        let mut leaf2 = [0u8; 32];
        for i in 0..32 {
            leaf0[i] = u8::try_from(i)
                .expect("test index is small")
                .wrapping_mul(7)
                .wrapping_add(1);
            leaf1[i] = 250u8.wrapping_sub(
                u8::try_from(i)
                    .expect("test index is small")
                    .wrapping_mul(5),
            );
            leaf2[i] = u8::try_from(i)
                .expect("test index is small")
                .wrapping_mul(11)
                .wrapping_add(3);
        }
        assert_ne!(
            rot_xor(&leaf0, &leaf1),
            rot_xor(&leaf1, &leaf0),
            "the combine must be order-sensitive"
        );

        // A three-leaf tree: leaf 1 (index 1) is the odd child of the pair
        // (leaf0, leaf1); the rebuild of leaf 1 must order it on the right.
        let leaves = [leaf0, leaf1, leaf2];
        let root = merkle_root(&leaves, rot_xor);
        assert_eq!(
            merkle_rebuild_root(&leaves, 1, rot_xor),
            Some(root),
            "odd-indexed leaf must be rebuilt as the right child"
        );
    }

    #[test]
    fn non_commutative_binding_matches_the_kani_bounded_model_shape() {
        // The Kani mirror model-checks the shape with the same non-commutative
        // rotate-xor combine (`combine_nodes_u64`); this pins that the
        // production tree and the bounded model agree on the same concrete
        // leaves (the mirror test in `qc.rs` runs the sha3 binding against
        // `QcBlob`'s output too).
        let leaves = [
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32],
        ];
        let layers = merkle_layers(&leaves, rot_xor);
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[0].len(), 8);
        assert_eq!(layers[1].len(), 4);
        assert_eq!(layers[2].len(), 2);
        assert_eq!(layers[3].len(), 1);

        let root = merkle_root(&leaves, rot_xor);
        for i in 0..leaves.len() {
            assert_eq!(merkle_rebuild_root(&leaves, i, rot_xor), Some(root));
        }
    }
}
