//! Per-column commitments over a stored shard.
//!
//! A coding audit used to ask an operator for "byte `column` of the audited
//! parity shard" and check only that the answer was consistent with the
//! manifest's Reed-Solomon code. One collected column of *some* codeword
//! answers that question for every column of every object, so the audit could
//! not tell an operator that still holds the shard from one that memorised a
//! consistent column and forgot it. It could judge *consistency*, never
//! *possession*.
//!
//! This module supplies the missing commitment. At manifest build time (where
//! the encoded bytes exist) each parity shard gets a Merkle root over its
//! columns, `hash(BDLM_STORAGE_COLUMN_LEAF_V1 || column_le_u64 || byte)`. The
//! root travels in the manifest and is therefore covered by the manifest id;
//! an audit answer must carry the inclusion path for the byte it claims. A
//! Merkle path cannot be produced without the sibling hashes, and the siblings
//! are hashes of the real shard, so a memorised column of another object
//! cannot answer an audit any more: the operator has to hold the byte the
//! commitment names.
//!
//! # Shape of the tree
//!
//! Leaves are padded to the next power of two with
//! `BDLM_STORAGE_COLUMN_EMPTY_V1`, so every path has the same length, the
//! index arithmetic is a plain bit walk, and a proof for a padded (nonexistent)
//! column cannot be made to pass: the leaf value a caller would have to produce
//! is a domain-tagged constant that `verify` never accepts as a claim about a
//! real byte. Internal nodes are
//! `hash(BDLM_STORAGE_COLUMN_NODE_V1 || left || right)`, and the position is
//! part of the hash through the left/right order, so a path cannot be replayed
//! at another index.
//!
//! # Cost
//!
//! `root` is one hash per byte of the shard plus one per internal node, done
//! once per parity shard when the manifest is built - off the consensus path,
//! where the encoded bytes already live. `verify` is one hash per level, i.e.
//! `log2(shard_len)`, and runs inside block execution.

use crate::core::hash::hash_fields_bytes;

/// The leaf that starts a real column's path: the column index and its byte.
const COLUMN_LEAF_TAG: &[u8] = b"BDLM_STORAGE_COLUMN_LEAF_V1";
/// The internal node: left child then right child.
const COLUMN_NODE_TAG: &[u8] = b"BDLM_STORAGE_COLUMN_NODE_V1";
/// The padding leaf that fills the tree to a power of two.
const COLUMN_EMPTY_TAG: &[u8] = b"BDLM_STORAGE_COLUMN_EMPTY_V1";

/// One column of a shard as a leaf: the index is bound, so a byte cannot be
/// moved to another column and still verify.
#[must_use]
fn column_leaf(column: u64, byte: u8) -> [u8; 32] {
    hash_fields_bytes(&[COLUMN_LEAF_TAG, &column.to_le_bytes(), &[byte]])
}

fn empty_leaf() -> [u8; 32] {
    hash_fields_bytes(&[COLUMN_EMPTY_TAG])
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[COLUMN_NODE_TAG, left, right])
}

/// Smallest power of two `>= n`, at least 1.
fn tree_width(n: usize) -> usize {
    let mut width = 1usize;
    while width < n {
        width = width.saturating_mul(2);
    }
    width
}

/// Leaves of `shard`, padded to the tree width.
fn leaves(shard: &[u8]) -> Vec<[u8; 32]> {
    let width = tree_width(shard.len());
    let mut out = Vec::with_capacity(width);
    for (i, byte) in shard.iter().enumerate() {
        out.push(column_leaf(i as u64, *byte));
    }
    let pad = empty_leaf();
    out.resize(width, pad);
    out
}

/// One level up. Returns the parent level.
fn fold_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len() / 2);
    for pair in level.chunks(2) {
        match pair {
            [left, right] => next.push(node(left, right)),
            // Only reachable for a one-element level, which the caller never
            // folds (a tree of width 1 is a single leaf).
            [only] => next.push(*only),
            _ => {}
        }
    }
    next
}

/// The Merkle root over every column of `shard`.
///
/// An empty shard is impossible (a shard is at least one byte by construction)
/// but is answered with the hash of the empty tag rather than a panic: this is
/// consensus code and a shape that cannot occur must not abort a node.
#[must_use]
pub fn column_root(shard: &[u8]) -> [u8; 32] {
    if shard.is_empty() {
        return empty_leaf();
    }
    let mut level = leaves(shard);
    while level.len() > 1 {
        level = fold_level(&level);
    }
    level.first().copied().unwrap_or_else(empty_leaf)
}

/// Inclusion path for one column: the sibling at every level, bottom up.
///
/// `None` when `column` is not a column of `shard` - a caller asking for a byte
/// that does not exist gets no proof rather than a proof of padding.
#[must_use]
pub fn column_proof(shard: &[u8], column: u64) -> Option<Vec<[u8; 32]>> {
    let index = usize::try_from(column).ok()?;
    if index >= shard.len() {
        return None;
    }
    let mut level = leaves(shard);
    let mut index = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        let sibling = index ^ 1;
        path.push(*level.get(sibling)?);
        level = fold_level(&level);
        index /= 2;
    }
    Some(path)
}

/// Check `byte` against `root` at `column` along `proof`.
///
/// Returns `false` for a wrong byte, a wrong column, a wrong root, a short or
/// long path, and a column outside the tree - all of which are the same answer
/// to the audit: the operator did not prove what it claimed.
#[must_use]
pub fn verify_column_proof(root: &[u8; 32], column: u64, byte: u8, proof: &[[u8; 32]]) -> bool {
    // The path length is determined by the tree width, and the width is
    // determined by the root's own leaf count. A root does not carry that
    // count, so the expected length is recovered from the proof: a tree of
    // width `2^d` has `d` siblings. Anything the caller sends is walked, and a
    // path of the wrong length simply lands on a different root.
    if proof.len() > 64 {
        return false;
    }
    let Ok(index) = usize::try_from(column) else {
        return false;
    };
    // The column must exist in a tree of this depth: with `d` siblings the
    // width is `2^d`, and a column index at or past it addresses padding.
    let depth = proof.len();
    if depth < 64 && (index >> depth) != 0 {
        return false;
    }
    let mut acc = column_leaf(column, byte);
    for (level, sibling) in proof.iter().enumerate() {
        let bit = (index >> level) & 1;
        acc = if bit == 0 {
            node(&acc, sibling)
        } else {
            node(sibling, &acc)
        };
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard() -> Vec<u8> {
        (0..=255u8).collect()
    }

    #[test]
    fn every_column_of_a_shard_proves_against_its_root() {
        let bytes = shard();
        let root = column_root(&bytes);
        for (i, byte) in bytes.iter().enumerate() {
            let proof = column_proof(&bytes, i as u64).expect("a real column has a proof");
            assert!(
                verify_column_proof(&root, i as u64, *byte, &proof),
                "column {i} must verify"
            );
        }
    }

    #[test]
    fn a_wrong_byte_at_the_right_column_is_refused() {
        let bytes = shard();
        let root = column_root(&bytes);
        let proof = column_proof(&bytes, 7).unwrap();
        assert!(!verify_column_proof(&root, 7, bytes[7] ^ 1, &proof));
    }

    #[test]
    fn a_byte_moved_to_another_column_is_refused() {
        let bytes = shard();
        let root = column_root(&bytes);
        let proof = column_proof(&bytes, 7).unwrap();
        // The same byte, claimed at another column, with that column's path.
        let other = column_proof(&bytes, 9).unwrap();
        assert!(!verify_column_proof(&root, 9, bytes[7], &other));
        assert!(!verify_column_proof(&root, 9, bytes[7], &proof));
    }

    #[test]
    fn a_proof_from_another_shard_is_refused() {
        let bytes = shard();
        let mut other = bytes.clone();
        other[7] ^= 0xFF;
        let root = column_root(&bytes);
        let proof = column_proof(&other, 7).unwrap();
        assert!(!verify_column_proof(&root, 7, other[7], &proof));
    }

    #[test]
    fn a_column_past_the_shard_has_no_proof() {
        let bytes = shard();
        assert!(column_proof(&bytes, bytes.len() as u64).is_none());
        assert!(column_proof(&bytes, u64::MAX).is_none());
    }

    /// A short shard pads the tree; a padded column must never verify, even
    /// with a path built from the padding.
    #[test]
    fn a_padded_column_cannot_be_proved() {
        let bytes = b"abc".to_vec();
        let root = column_root(&bytes);
        // Column 3 is padding (tree width 4).
        let mut padded_level = leaves(&bytes);
        let mut index = 3usize;
        let mut path = Vec::new();
        while padded_level.len() > 1 {
            path.push(padded_level[index ^ 1]);
            padded_level = fold_level(&padded_level);
            index /= 2;
        }
        // Proving the padding value at column 3 does not reproduce the root,
        // because the leaf is hashed with its index and the tag of a real leaf.
        let pad_byte = 0u8;
        assert!(!verify_column_proof(&root, 3, pad_byte, &path));
    }

    #[test]
    fn a_truncated_or_extended_path_is_refused() {
        let bytes = shard();
        let root = column_root(&bytes);
        let proof = column_proof(&bytes, 3).unwrap();
        let mut short = proof.clone();
        short.pop();
        let mut long = proof;
        long.push([0u8; 32]);
        assert!(!verify_column_proof(&root, 3, bytes[3], &short));
        assert!(!verify_column_proof(&root, 3, bytes[3], &long));
    }

    #[test]
    fn the_root_changes_with_a_single_byte() {
        let bytes = shard();
        let mut changed = bytes.clone();
        changed[100] ^= 1;
        assert_ne!(column_root(&bytes), column_root(&changed));
    }

    #[test]
    fn a_one_byte_shard_has_an_empty_path() {
        let root = column_root(b"x");
        let proof = column_proof(b"x", 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_column_proof(&root, 0, b'x', &proof));
        assert!(!verify_column_proof(&root, 0, b'y', &proof));
    }
}
