//! Sparse fixed-depth (256) binary Merkle trie for account state.
//!
//! - Leaf: `SHA-256(0x01 || address || balance_le || nonce_le)`
//! - Internal: `SHA-256(0x00 || left || right)`
//! - Empty subtree: 32 zero bytes
//! - Root: `SHA-256(BDLM_MERKLE_TRIE_V1 || raw_root)`
//!
//! Path bits are MSB-first (address bit 0 = root branch).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TRIE_DEPTH: usize = 256;
const DOMAIN_PREFIX: &[u8] = b"BDLM_MERKLE_TRIE_V1";

/// Merkle proof for one address (present or absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub address: [u8; 32],
    /// Sibling hashes from leaf toward root (`TRIE_DEPTH` entries).
    pub siblings: Vec<[u8; 32]>,
    /// At each step, `true` means the proved node is the right child.
    pub directions: Vec<bool>,
    pub leaf_hash: [u8; 32],
}

impl MerkleProof {
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != TRIE_DEPTH || self.directions.len() != TRIE_DEPTH {
            return false;
        }
        let mut current = self.leaf_hash;
        for i in 0..TRIE_DEPTH {
            let (left, right) = if self.directions[i] {
                (self.siblings[i], current)
            } else {
                (current, self.siblings[i])
            };
            current = combine_nodes(&left, &right);
        }
        &finalize_root(&current) == expected_root
    }
}

/// Sparse binary Merkle trie keyed by 256-bit addresses.
#[derive(Debug, Clone, Default)]
pub struct MerkleTrie {
    leaves: BTreeMap<[u8; 32], (u64, u64)>,
}

impl MerkleTrie {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, address: &[u8; 32], balance: u64, nonce: u64) {
        self.leaves.insert(*address, (balance, nonce));
    }

    pub fn remove(&mut self, address: &[u8; 32]) {
        self.leaves.remove(address);
    }

    pub fn root(&mut self) -> [u8; 32] {
        self.root_ref()
    }

    pub fn root_ref(&self) -> [u8; 32] {
        let leaves: Vec<_> = self.leaves.iter().map(|(a, (b, n))| (*a, *b, *n)).collect();
        finalize_root(&hash_leaves(&leaves, 0))
    }

    pub fn proof(&self, address: &[u8; 32]) -> MerkleProof {
        let leaf_hash = self
            .leaves
            .get(address)
            .map(|(b, n)| hash_leaf(address, *b, *n))
            .unwrap_or([0u8; 32]);

        let mut siblings = Vec::with_capacity(TRIE_DEPTH);
        let mut directions = Vec::with_capacity(TRIE_DEPTH);

        // Leaf → root: step 0 uses address bit 255, step 255 uses bit 0.
        for step in 0..TRIE_DEPTH {
            let bit_index = TRIE_DEPTH - 1 - step;
            let bit = get_bit(address, bit_index);
            directions.push(bit);

            // Sibling = hash of all leaves that share bits [0, bit_index)
            // With `address` and have the opposite bit at `bit_index`.
            let mut side: Vec<([u8; 32], u64, u64)> = Vec::new();
            for (addr, (b, n)) in &self.leaves {
                if !prefix_eq(addr, address, bit_index) {
                    continue;
                }
                if get_bit(addr, bit_index) == bit {
                    continue;
                }
                side.push((*addr, *b, *n));
            }
            siblings.push(hash_leaves(&side, bit_index + 1));
        }

        MerkleProof {
            address: *address,
            siblings,
            directions,
            leaf_hash,
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn bulk_insert(&mut self, entries: &[([u8; 32], u64, u64)]) {
        for (addr, balance, nonce) in entries {
            self.leaves.insert(*addr, (*balance, *nonce));
        }
    }
}

// ─── Hashing ─────────────────────────────────────────────────────────

fn hash_leaf(address: &[u8; 32], balance: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(address);
    h.update(balance.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Sparse rule: two empty children collapse to empty (not H(0||0)).
fn combine_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == [0u8; 32] && *right == [0u8; 32] {
        return [0u8; 32];
    }
    hash_internal(left, right)
}

fn finalize_root(raw: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX);
    h.update(raw);
    h.finalize().into()
}

#[cfg(test)]
fn empty_trie_root() -> [u8; 32] {
    finalize_root(&[0u8; 32])
}

/// Recursively hash a leaf set under a fixed prefix of `from_bit` bits.
fn hash_leaves(leaves: &[([u8; 32], u64, u64)], from_bit: usize) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if from_bit >= TRIE_DEPTH {
        let (addr, b, n) = leaves[0];
        return hash_leaf(&addr, b, n);
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &entry in leaves {
        if get_bit(&entry.0, from_bit) {
            right.push(entry);
        } else {
            left.push(entry);
        }
    }
    let l = hash_leaves(&left, from_bit + 1);
    let r = hash_leaves(&right, from_bit + 1);
    combine_nodes(&l, &r)
}

fn get_bit(address: &[u8; 32], level: usize) -> bool {
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    if byte_idx >= 32 {
        return false;
    }
    (address[byte_idx] >> bit_idx) & 1 == 1
}

fn prefix_eq(a: &[u8; 32], b: &[u8; 32], bits: usize) -> bool {
    for i in 0..bits {
        if get_bit(a, i) != get_bit(b, i) {
            return false;
        }
    }
    true
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    }

    #[test]
    fn empty_trie_has_deterministic_root() {
        let mut trie = MerkleTrie::new();
        let root = trie.root();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(root, empty_trie_root());
        assert_eq!(root, trie.root());
    }

    #[test]
    fn insert_changes_root() {
        let mut trie = MerkleTrie::new();
        let before = trie.root();
        trie.insert(&addr(1), 1000, 5);
        assert_ne!(before, trie.root());
    }

    #[test]
    fn same_entries_same_root() {
        let mut a = MerkleTrie::new();
        let mut b = MerkleTrie::new();
        a.insert(&addr(1), 1000, 5);
        a.insert(&addr(2), 2000, 10);
        b.insert(&addr(1), 1000, 5);
        b.insert(&addr(2), 2000, 10);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn different_order_same_root() {
        let mut a = MerkleTrie::new();
        let mut b = MerkleTrie::new();
        a.insert(&addr(1), 1000, 5);
        a.insert(&addr(2), 2000, 10);
        b.insert(&addr(2), 2000, 10);
        b.insert(&addr(1), 1000, 5);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn update_balance_changes_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        let r1 = trie.root();
        trie.insert(&addr(1), 2000, 5);
        assert_ne!(r1, trie.root());
    }

    #[test]
    fn remove_restores_previous_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        let with = trie.root();
        trie.insert(&addr(2), 2000, 10);
        assert_ne!(with, trie.root());
        trie.remove(&addr(2));
        assert_eq!(with, trie.root());
    }

    #[test]
    fn proof_verifies_correctly() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        trie.insert(&addr(2), 2000, 10);
        trie.insert(&addr(3), 3000, 15);
        let root = trie.root();
        assert!(trie.proof(&addr(2)).verify(&root));
    }

    #[test]
    fn proof_fails_with_wrong_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        assert!(!trie.proof(&addr(1)).verify(&[0xFF; 32]));
    }

    #[test]
    fn proof_fails_with_tampered_sibling() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        trie.insert(&addr(2), 2000, 10);
        let root = trie.root();
        let mut proof = trie.proof(&addr(1));
        proof.siblings[0] = [0xFF; 32];
        assert!(!proof.verify(&root));
    }

    #[test]
    fn bulk_insert_produces_same_root() {
        let mut a = MerkleTrie::new();
        let mut b = MerkleTrie::new();
        let entries: Vec<_> = (0..50)
            .map(|i| (addr(i), (i as u64) * 100, i as u64))
            .collect();
        for (x, y, z) in &entries {
            a.insert(x, *y, *z);
        }
        b.bulk_insert(&entries);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn hundred_accounts_deterministic() {
        let mut a = MerkleTrie::new();
        for i in 0..100u8 {
            a.insert(&addr(i), (i as u64) * 1000, i as u64);
        }
        let r1 = a.root();
        let mut b = MerkleTrie::new();
        for i in (0..100u8).rev() {
            b.insert(&addr(i), (i as u64) * 1000, i as u64);
        }
        assert_eq!(r1, b.root());
    }

    #[test]
    fn proof_for_nonexistent_address() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        let root = trie.root();
        let proof = trie.proof(&addr(99));
        assert!(proof.verify(&root));
    }
}
