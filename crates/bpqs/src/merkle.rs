//! Epoch Merkle tree. The public anchor of the committee member is the root
//! of a tree whose leaves are the per-epoch verification digests
//! ([`crate::wots::vk_of_chains`]). `2^T_LOG2` epochs of headroom at this
//! height; every signature carries the sibling path from its leaf to the
//! root (LSB-first), and the verifier rebuilds the walk bottom-up.
//!
//! Lane discipline matches `wots`: values are 32-byte wide, meaningful
//! prefix `P::N`, and comparisons happen on that prefix only.
//!
//! Capacity note: signatures reserve room for 16 path entries, matching the
//! largest parameter row (`T_LOG2 = 16`); shorter rows use their prefix.

use alloc::vec::Vec;

use crate::domains;
use crate::error::BpqsError;
use crate::hash::BpqsHash;
use crate::params::BpqsParams;

/// The materialized epoch tree: `levels[0]` is the leaf row,
/// `levels[T_LOG2][0]` is the root.
pub type Levels = alloc::vec::Vec<alloc::vec::Vec<[u8; 32]>>;

/// One Merkle leaf: the committed form of an epoch's Winternitz digest.
pub fn leaf<H: BpqsHash, P: BpqsParams>(vk_digest: &[u8; 32]) -> [u8; 32] {
    let wide = H::digest32(domains::MERKLE_LEAF, &[&vk_digest[..P::N]]);
    let mut out = [0u8; 32];
    out[..P::N].copy_from_slice(&wide[..P::N]);
    out
}

/// One parent node, left||right order committed through the domain.
pub fn node<H: BpqsHash, P: BpqsParams>(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let wide = H::digest32(domains::MERKLE_NODE, &[&left[..P::N], &right[..P::N]]);
    let mut out = [0u8; 32];
    out[..P::N].copy_from_slice(&wide[..P::N]);
    out
}

/// Build the whole tree and return `(root, levels)` where `levels[0]` is the
/// leaf row and `levels[T_LOG2][0]` is the root. The full tree is
/// materialized because the signer answers an auth path on every signature;
/// cold-committee ceremonies pay this cost once per member key and hold it
/// for its at-most-q_max signatures per epoch.
pub fn build_tree<H: BpqsHash, P: BpqsParams>(
    vk_digests: &[[u8; 32]],
) -> Result<([u8; 32], Levels), BpqsError> {
    let leaf_count = 1usize << P::T_LOG2;
    if vk_digests.len() != leaf_count {
        return Err(BpqsError::Malformed(
            "tree leaves do not match the parameter row's epoch headroom",
        ));
    }
    let mut levels: Levels = Vec::new();
    let mut leaves = Vec::with_capacity(leaf_count);
    for digest in vk_digests {
        leaves.push(leaf::<H, P>(digest));
    }
    levels.push(leaves);
    while levels.last().map(|l| l.len()) != Some(1) {
        let lower = &levels[levels.len() - 1];
        let mut upper = Vec::with_capacity(lower.len() / 2);
        for pair in lower.chunks_exact(2) {
            upper.push(node::<H, P>(&pair[0], &pair[1]));
        }
        levels.push(upper);
    }
    let root = levels[levels.len() - 1][0];
    Ok((root, levels))
}

/// The auth path for leaf `index`, LSB-first (sibling at the leaf row first,
/// sibling at the row below the root last). Entries past this row's
/// `T_LOG2` stay zeroed.
pub fn auth_path<P: BpqsParams>(
    levels: &[Vec<[u8; 32]>],
    index: usize,
) -> Result<[[u8; 32]; 16], BpqsError> {
    if P::T_LOG2 > 16 {
        return Err(BpqsError::Malformed("tree height exceeds the path budget"));
    }
    if levels.len() != P::T_LOG2 + 1 || levels[0].len() != (1usize << P::T_LOG2) {
        return Err(BpqsError::Malformed(
            "tree shape does not match the parameter row",
        ));
    }
    if index >= (1usize << P::T_LOG2) {
        return Err(BpqsError::Malformed("leaf index out of epoch headroom"));
    }
    let mut path = [[0u8; 32]; 16];
    let mut cursor = index;
    for h in 0..P::T_LOG2 {
        let sibling = cursor ^ 1;
        if sibling >= levels[h].len() {
            return Err(BpqsError::Malformed("tree level shorter than expected"));
        }
        path[h] = levels[h][sibling];
        cursor /= 2;
    }
    Ok(path)
}

/// Rebuild the walk from a leaf to the root and refuse on any mismatch.
pub fn verify_path<H: BpqsHash, P: BpqsParams>(
    leaf_value: &[u8; 32],
    index: usize,
    path: &[[u8; 32]; 16],
    expected_root: &[u8; 32],
) -> Result<(), BpqsError> {
    let mut cur = leaf::<H, P>(leaf_value);
    let mut cursor = index;
    for sib in path.iter().take(P::T_LOG2.min(16)) {
        cur = if cursor.is_multiple_of(2) {
            node::<H, P>(&cur, sib)
        } else {
            node::<H, P>(sib, &cur)
        };
        cursor /= 2;
    }
    if cur[..P::N] == expected_root[..P::N] {
        Ok(())
    } else {
        Err(BpqsError::BadAuthPath)
    }
}

#[cfg(test)]
mod merkle_tests {
    use super::*;
    use crate::hash::Sha3_256Hash;
    use crate::params::ParamsTestFast;

    type P = ParamsTestFast;

    fn fake_vks() -> Vec<[u8; 32]> {
        let mut v = Vec::with_capacity(1usize << P::T_LOG2);
        for i in 0..(1usize << P::T_LOG2) {
            let wide = Sha3_256Hash::digest32(b"vk", &[&(i as u32).to_le_bytes()]);
            let mut lane = [0u8; 32];
            lane[..P::N].copy_from_slice(&wide[..P::N]);
            v.push(lane);
        }
        v
    }

    #[test]
    fn every_leaf_verifies_against_the_root() {
        let vks = fake_vks();
        let (root, levels) =
            build_tree::<Sha3_256Hash, P>(&vks).unwrap_or_else(|e| panic!("tree: {e}"));
        for (i, vk) in vks.iter().enumerate() {
            let path = auth_path::<P>(&levels, i).unwrap_or_else(|e| panic!("path: {e}"));
            verify_path::<Sha3_256Hash, P>(vk, i, &path, &root)
                .unwrap_or_else(|e| panic!("leaf {i} must verify: {e}"));
        }
    }

    #[test]
    fn a_tampered_sibling_refuses() {
        let vks = fake_vks();
        let (root, levels) =
            build_tree::<Sha3_256Hash, P>(&vks).unwrap_or_else(|e| panic!("tree: {e}"));
        let mut path = auth_path::<P>(&levels, 3).unwrap_or_else(|e| panic!("path: {e}"));
        path[0][0] ^= 0x80;
        assert_eq!(
            verify_path::<Sha3_256Hash, P>(&vks[3], 3, &path, &root),
            Err(BpqsError::BadAuthPath)
        );
    }

    #[test]
    fn epoch_index_out_of_headroom_refuses() {
        let vks = fake_vks();
        let (_, levels) =
            build_tree::<Sha3_256Hash, P>(&vks).unwrap_or_else(|e| panic!("tree: {e}"));
        assert!(auth_path::<P>(&levels, 1 << P::T_LOG2).is_err());
    }

    #[test]
    fn leaf_count_mismatch_refuses() {
        let vks = fake_vks();
        assert_eq!(
            build_tree::<Sha3_256Hash, P>(&vks[..vks.len() - 1]),
            Err(BpqsError::Malformed(
                "tree leaves do not match the parameter row's epoch headroom"
            ))
        );
    }
}
