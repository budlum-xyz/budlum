//! The one Merkle tree primitive the chain commits through.
//!
//! The tree shape (sibling selection, layer growth, root extraction, the
//! proof walk) is pure and does not depend on the hash functions: the
//! caller supplies a binary `combine` for paired nodes and a unary
//! `promote` for an unpaired tail.
//!
//! An unpaired tail is **promoted under its own domain tag, never paired
//! with itself**. The self-pairing made the tail contribute exactly what a
//! duplicated leaf would, so the root of `[a, b, c]` equalled the root of
//! `[a, b, c, c]`: two different commitments, one digest (the F-6 shape,
//! in every tree that used this module's duplicate-tail rule). A promoted
//! digest is produced by `promote` alone, which no `combine` call can
//! reproduce, so the ambiguity is closed at the shape level and every
//! binding inherits it.
//!
//! The production bindings are SHA3-256 for the QC blob trees
//! ([`combine_sha3`] / [`promote_sha3`]); the settlement and event trees
//! bring their own tagged `hash_fields_bytes` binding from
//! `settlement::commitment_tree`. The Kani mirror in `kani/src/lib.rs`
//! model-checks the shape on a bounded fixed-array model with abstract
//! combine and promote functions, and `qc_merkle_matches_the_kani_mirror`
//! pins the two to each other over concrete vectors.

use crate::core::hash::hash_fields_bytes;
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

/// SHA3-256 promotion of an unpaired tail, the production unary hash for
/// QC blob Merkle trees.
///
/// The tag prefix keeps a promoted digest from ever colliding with a paired
/// one: `combine_sha3` hashes exactly 64 bytes, this hashes the tag plus 32
/// bytes, so the two preimage sets are disjoint and no tree can hide a
/// promoted node inside a pair.
#[must_use]
pub fn promote_sha3(node: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_MERKLE_ODD_PROMOTE_V1");
    hasher.update(node);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

/// The sibling value that stands for "no sibling: this digest was promoted".
///
/// An unpaired tail digest is hashed under the promotion function alone, so
/// a verifier has to tell a promoted step from a paired one, and the
/// sibling list (plain digests) needs a marker. This value is the hash of a
/// tag that no leaf, node or promotion domain produces, so no honest tree
/// ever yields it as a real sibling; a forged sentinel in a paired position
/// only produces a root that does not match the committed one.
#[must_use]
pub fn odd_promotion_sentinel() -> [u8; 32] {
    static SENTINEL: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *SENTINEL.get_or_init(|| hash_fields_bytes(&[b"BDLM_MERKLE_ODD_SENTINEL_V1"]))
}

/// Sibling index under the production rule.
///
/// An even node pairs with the next node; an odd node pairs with the
/// previous node. An even node that is the tail of its layer has no sibling
/// at all - it is promoted - and callers detect that case before they ask
/// for a sibling here.
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
/// Nodes are paired left to right; an unpaired tail is promoted through
/// `promote` under its own domain, never paired with itself. The Kani
/// harness `every_parent_layer_is_smaller_than_its_child_layer` proves the
/// parent count is strictly smaller for layers of two or more nodes, which
/// is what makes the layer loop terminate.
#[must_use]
pub fn merkle_parent_layer(
    layer: &[[u8; 32]],
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> Vec<[u8; 32]> {
    let mut next_level = Vec::new();
    let mut i = 0;
    while i < layer.len() {
        if i + 1 < layer.len() {
            next_level.push(combine(&layer[i], &layer[i + 1]));
        } else {
            next_level.push(promote(&layer[i]));
        }
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
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut layers = Vec::new();
    layers.push(leaves.to_vec());
    while layers.last().map_or(0, Vec::len) > 1 {
        let current = layers.last().cloned().unwrap_or_default();
        layers.push(merkle_parent_layer(&current, combine, promote));
    }
    layers
}

/// The root digest, or all zeros for an empty tree.
#[must_use]
pub fn merkle_root(
    leaves: &[[u8; 32]],
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> [u8; 32] {
    merkle_layers(leaves, combine, promote)
        .last()
        .and_then(|layer| layer.first())
        .copied()
        .unwrap_or([0u8; 32])
}

/// The sibling digests a verifier needs to rebuild the root from
/// `leaf_index`, in layer order; `None` when the leaf is out of range or the
/// tree is empty.
///
/// A promoted step records [`odd_promotion_sentinel`] as the sibling: the
/// verifier sees "no sibling here, promote yourself" without needing the
/// layer lengths. The Kani harness `every_merkle_proof_rebuilds_the_root`
/// proves that rebuilding from these digests reproduces the root.
#[must_use]
pub fn merkle_proof(
    leaves: &[[u8; 32]],
    leaf_index: usize,
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> Option<Vec<[u8; 32]>> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let layers = merkle_layers(leaves, combine, promote);
    let mut proof = Vec::new();
    let mut idx = leaf_index;
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        if idx.is_multiple_of(2) && idx + 1 >= layer.len() {
            // The tail of an odd layer has no sibling: it is promoted.
            proof.push(odd_promotion_sentinel());
        } else {
            proof.push(layer[merkle_sibling_index(idx, layer.len())]);
        }
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
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> Option<[u8; 32]> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let layers = merkle_layers(leaves, combine, promote);
    let mut idx = leaf_index;
    let mut cur = leaves[leaf_index];
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        if idx.is_multiple_of(2) && idx + 1 >= layer.len() {
            // The tail of an odd layer is promoted, not paired.
            cur = promote(&cur);
        } else {
            let sibling = layer[merkle_sibling_index(idx, layer.len())];
            cur = if idx.is_multiple_of(2) {
                combine(&cur, &sibling)
            } else {
                combine(&sibling, &cur)
            };
        }
        idx /= 2;
    }
    Some(cur)
}

/// The root a verifier rebuilds from a proof alone: `leaf`, its index, and
/// the sibling list (with [`odd_promotion_sentinel`] marking a promoted
/// step), walked with the same ordering rule as
/// [`merkle_rebuild_root`].
///
/// This is the verifying half of [`merkle_proof`]: a verifier that holds no
/// leaves at all reconstructs the root from exactly what the prover sent.
#[must_use]
pub fn merkle_root_from_proof(
    leaf: &[u8; 32],
    index: usize,
    siblings: &[[u8; 32]],
    combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    promote: fn(&[u8; 32]) -> [u8; 32],
) -> [u8; 32] {
    let mut cur = *leaf;
    let mut idx = index;
    for sibling in siblings {
        cur = if sibling == &odd_promotion_sentinel() {
            // The prover recorded a promotion: this digest had no sibling
            // at this level and was hashed under the promotion function
            // alone.
            promote(&cur)
        } else if idx.is_multiple_of(2) {
            combine(&cur, sibling)
        } else {
            combine(sibling, &cur)
        };
        idx /= 2;
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = [7u8; 32];
        let root = merkle_root(&[leaf], combine_sha3, promote_sha3);
        assert_eq!(root, leaf);
    }

    #[test]
    fn empty_tree_has_no_layers_and_zero_root() {
        assert!(merkle_layers(&[], combine_sha3, promote_sha3).is_empty());
        assert_eq!(merkle_root(&[], combine_sha3, promote_sha3), [0u8; 32]);
        assert_eq!(merkle_proof(&[], 0, combine_sha3, promote_sha3), None);
    }

    /// The ambiguity the promotion exists to kill: under the old
    /// duplicate-tail rule the root of `[a, b, c]` equalled the root of
    /// `[a, b, c, c]`, because the self-paired tail and a real fourth leaf
    /// hashed identically. A promoted tail must differ from a paired one.
    #[test]
    fn odd_tail_is_promoted_never_duplicated() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let layers = merkle_layers(&leaves, combine_sha3, promote_sha3);
        // Three leaves produce three layers: 3 -> 2 -> 1.
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].len(), 3);
        assert_eq!(layers[1].len(), 2);
        assert_eq!(layers[2].len(), 1);
        // The tail is promoted under its own tag, not paired with itself.
        assert_eq!(layers[1][1], promote_sha3(&leaves[2]));
        assert_ne!(
            layers[1][1],
            combine_sha3(&leaves[2], &leaves[2]),
            "a promoted tail must not look like a self-paired one"
        );
        // ...so the three-leaf tree and its duplicated-tail twin cannot
        // share a root.
        assert_ne!(
            merkle_root(&leaves, combine_sha3, promote_sha3),
            merkle_root(
                &[leaves[0], leaves[1], leaves[2], leaves[2]],
                combine_sha3,
                promote_sha3
            ),
            "the three-leaf and duplicated-tail trees must not share a root"
        );
        // A promotion is not reachable as a pair of any digests either.
        let mut leaf = [9u8; 32];
        leaf[0] = 4;
        assert_ne!(
            promote_sha3(&leaf),
            combine_sha3(&leaf, &leaf),
            "promote and combine must be domain-separated"
        );
    }

    #[test]
    fn every_proof_rebuilds_the_root() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];
        let root = merkle_root(&leaves, combine_sha3, promote_sha3);
        for i in 0..leaves.len() {
            assert_eq!(
                merkle_rebuild_root(&leaves, i, combine_sha3, promote_sha3),
                Some(root),
                "leaf {i}"
            );
        }
    }

    /// The proving and verifying halves are one walk: a proof from
    /// [`merkle_proof`] rebuilds the committed root through
    /// [`merkle_root_from_proof`], sentinel steps included, with no access
    /// to the leaves at all.
    #[test]
    fn every_proof_verifies_from_the_proof_alone() {
        for len in 1..9usize {
            let leaves: Vec<[u8; 32]> = (0..len)
                .map(|i| {
                    let mut leaf = [0u8; 32];
                    leaf[0] = u8::try_from(i).expect("len is small");
                    leaf
                })
                .collect();
            let root = merkle_root(&leaves, combine_sha3, promote_sha3);
            for i in 0..leaves.len() {
                let proof = merkle_proof(&leaves, i, combine_sha3, promote_sha3)
                    .unwrap_or_else(|| panic("leaf {i} of {len}"));
                assert_eq!(
                    merkle_root_from_proof(&leaves[i], i, &proof, combine_sha3, promote_sha3),
                    root,
                    "leaf {i} of {len}"
                );
            }
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

    /// The mirror's unary promotion, packed the same way: a rotation the
    /// binary combine cannot reproduce.
    fn rot_promote(node: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in 0..4 {
            let n = u64::from_le_bytes(node[chunk * 8..chunk * 8 + 8].try_into().expect("8 bytes"));
            let promoted = n.rotate_left(13) ^ 0x5A5A_5A5A_5A5A_5A5A;
            out[chunk * 8..chunk * 8 + 8].copy_from_slice(&promoted.to_le_bytes());
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
        let root = merkle_root(&leaves, rot_xor, rot_promote);
        assert_eq!(
            merkle_rebuild_root(&leaves, 1, rot_xor, rot_promote),
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
        let layers = merkle_layers(&leaves, rot_xor, rot_promote);
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[0].len(), 8);
        assert_eq!(layers[1].len(), 4);
        assert_eq!(layers[2].len(), 2);
        assert_eq!(layers[3].len(), 1);

        let root = merkle_root(&leaves, rot_xor, rot_promote);
        for i in 0..leaves.len() {
            assert_eq!(
                merkle_rebuild_root(&leaves, i, rot_xor, rot_promote),
                Some(root)
            );
        }
    }
}
