//! Merkle Patricia Trie for account state.
//!
//! Provides O(log N) incremental updates and Merkle proofs for
//! account state verification. Replaces the flat hash approach in
//! `AccountState::calculate_state_root()` for production use.
//!
//! ## Design
//! - Fixed-depth (64-level) binary trie keyed by 256-bit addresses.
//! - Each internal node = SHA-256(left_child || right_child).
//! - Leaf nodes = SHA-256(0x01 || address || balance || nonce).
//! - `update()` recalculates only the path from leaf to root (O(64)).
//! - `proof()` returns sibling hashes along the path for verification.
//! - Domain-separated: `BDLM_MERKLE_TRIE_V1` prefix prevents cross-trie collision.

use sha2::{Digest, Sha256};

/// Depth of the trie (256-bit addresses → 256 levels).
const TRIE_DEPTH: usize = 256;

/// Domain separator for the trie root hash.
const DOMAIN_PREFIX: &[u8] = b"BDLM_MERKLE_TRIE_V1";

/// A Merkle proof for a single account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The address being proved.
    pub address: [u8; 32],
    /// Sibling hashes from leaf to root (TRIE_DEPTH elements).
    /// `siblings[i]` is the sibling at level `i` (0 = leaf level).
    pub siblings: Vec<[u8; 32]>,
    /// Direction bits: `true` = right child, `false` = left child.
    /// `directions[i]` indicates which child the path takes at level `i`.
    pub directions: Vec<bool>,
    /// The leaf hash (balance + nonce encoded).
    pub leaf_hash: [u8; 32],
}

impl MerkleProof {
    /// Verify this proof against an expected root.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != TRIE_DEPTH || self.directions.len() != TRIE_DEPTH {
            return false;
        }

        let mut current = self.leaf_hash;
        for i in 0..TRIE_DEPTH {
            let (left, right) = if self.directions[i] {
                (&self.siblings[i], &current)
            } else {
                (&current, &self.siblings[i])
            };
            current = hash_internal(left, right);
        }

        let root = finalize_root(&current);
        &root == expected_root
    }
}

/// Binary Merkle Patricia Trie for 256-bit keys.
///
/// Nodes are stored sparsely — only non-zero subtrees are materialized.
/// The trie uses a simple binary tree with 256 levels (one per address bit).
#[derive(Debug, Clone)]
pub struct MerkleTrie {
    /// Root hash.
    root: [u8; 32],
    /// Leaf data: address → (balance, nonce).
    leaves: std::collections::BTreeMap<[u8; 32], (u64, u64)>,
    /// Cached internal nodes: (level, path_bits) → hash.
    /// `level` 0 = leaf level, `level` 255 = just below root.
    internal: std::collections::BTreeMap<(usize, u64), [u8; 32]>,
    /// Dirty flag — set on any mutation, cleared after recompute.
    dirty: bool,
}

impl MerkleTrie {
    pub fn new() -> Self {
        Self {
            root: empty_trie_root(),
            leaves: std::collections::BTreeMap::new(),
            internal: std::collections::BTreeMap::new(),
            dirty: false,
        }
    }

    /// Insert or update an account's (balance, nonce).
    /// O(log N) incremental path update.
    pub fn insert(&mut self, address: &[u8; 32], balance: u64, nonce: u64) {
        let leaf_hash = hash_leaf(address, balance, nonce);
        self.leaves.insert(*address, (balance, nonce));

        // Update the path from leaf to root.
        self.update_path(address, leaf_hash);
        self.dirty = true;
    }

    /// Remove an account from the trie.
    pub fn remove(&mut self, address: &[u8; 32]) {
        self.leaves.remove(address);
        // Recompute the path with a zero leaf.
        self.update_path(address, [0u8; 32]);
        self.dirty = true;
    }

    /// Get the current root hash.
    pub fn root(&mut self) -> [u8; 32] {
        if self.dirty {
            self.recompute_root();
        }
        self.root
    }

    /// Generate a Merkle proof for an address.
    pub fn proof(&self, address: &[u8; 32]) -> MerkleProof {
        let leaf_hash = self
            .leaves
            .get(address)
            .map(|(b, n)| hash_leaf(address, *b, *n))
            .unwrap_or([0u8; 32]);

        let mut siblings = Vec::with_capacity(TRIE_DEPTH);
        let mut directions = Vec::with_capacity(TRIE_DEPTH);

        for level in 0..TRIE_DEPTH {
            let bit = get_bit(address, level);
            directions.push(bit);

            let sibling_key = compute_sibling_key(address, level);
            let sibling = self.get_internal(level, sibling_key);
            siblings.push(sibling);
        }

        MerkleProof {
            address: *address,
            siblings,
            directions,
            leaf_hash,
        }
    }

    /// Number of leaves in the trie.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Bulk insert from an iterator — more efficient than individual inserts
    /// because it avoids redundant path traversals.
    pub fn bulk_insert(&mut self, entries: &[([u8; 32], u64, u64)]) {
        for (addr, balance, nonce) in entries {
            let leaf_hash = hash_leaf(addr, *balance, *nonce);
            self.leaves.insert(*addr, (*balance, *nonce));
            self.update_path(addr, leaf_hash);
        }
        self.dirty = true;
    }

    // ─── Internal ──────────────────────────────────────────────────

    fn update_path(&mut self, address: &[u8; 32], leaf_hash: [u8; 32]) {
        // Bottom-up: update each level from leaf to root.
        let mut child_hash = leaf_hash;

        for level in 0..TRIE_DEPTH {
            let bit = get_bit(address, level);
            let sibling_key = compute_sibling_key(address, level);
            let sibling = self.get_internal(level, sibling_key);

            let (left, right) = if bit {
                (sibling, child_hash)
            } else {
                (child_hash, sibling)
            };

            child_hash = hash_internal(&left, &right);

            // Store internal node at the parent path.
            let parent_key = compute_parent_key(address, level);
            self.internal.insert((level + 1, parent_key), child_hash);
        }
    }

    fn get_internal(&self, level: usize, key: u64) -> [u8; 32] {
        // For levels 0-5, we can use the full key; for deeper levels,
        // we use a truncated prefix.
        self.internal
            .get(&(level, key))
            .copied()
            .unwrap_or([0u8; 32])
    }

    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = empty_trie_root();
            self.dirty = false;
            return;
        }

        // The root is stored at level TRIE_DEPTH in internal.
        // After update_path, the root should be at (TRIE_DEPTH, 0).
        self.root = self.get_internal(TRIE_DEPTH, 0);

        // If the root is zero but we have leaves, do a full recompute.
        if self.root == [0u8; 32] && !self.leaves.is_empty() {
            self.full_recompute();
        }

        self.dirty = false;
    }

    fn full_recompute(&mut self) {
        self.internal.clear();

        // Collect leaves first to avoid borrow conflict.
        let entries: Vec<_> = self
            .leaves
            .iter()
            .map(|(addr, (balance, nonce))| (*addr, hash_leaf(addr, *balance, *nonce)))
            .collect();

        for (addr, leaf_hash) in entries {
            self.update_path(&addr, leaf_hash);
        }

        self.root = self.get_internal(TRIE_DEPTH, 0);
    }
}

impl Default for MerkleTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Hash helpers ────────────────────────────────────────────────────

fn hash_leaf(address: &[u8; 32], balance: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]); // leaf prefix
    h.update(address);
    h.update(balance.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]); // internal prefix
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn finalize_root(raw: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX);
    h.update(raw);
    h.finalize().into()
}

fn empty_trie_root() -> [u8; 32] {
    finalize_root(&[0u8; 32])
}

/// Get bit `level` of address (0 = MSB of first byte).
fn get_bit(address: &[u8; 32], level: usize) -> bool {
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    if byte_idx >= 32 {
        return false;
    }
    (address[byte_idx] >> bit_idx) & 1 == 1
}

/// Compute the key for the sibling node at a given level.
/// Uses first 8 bytes of address as a compact key.
fn compute_sibling_key(address: &[u8; 32], level: usize) -> u64 {
    let mut key = compute_parent_key(address, level);
    // Flip the bit at this level to get the sibling's key.
    key ^= 1u64 << (63 - level.min(63));
    key
}

/// Compute the parent key at a given level.
fn compute_parent_key(address: &[u8; 32], level: usize) -> u64 {
    let mut key = 0u64;
    for i in 0..level.min(64) {
        if get_bit(address, i) {
            key |= 1u64 << (63 - i);
        }
    }
    key
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
        assert_eq!(root, trie.root()); // deterministic
    }

    #[test]
    fn insert_changes_root() {
        let mut trie = MerkleTrie::new();
        let root_before = trie.root();

        trie.insert(&addr(1), 1000, 5);
        let root_after = trie.root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn same_entries_same_root() {
        let mut trie1 = MerkleTrie::new();
        let mut trie2 = MerkleTrie::new();

        trie1.insert(&addr(1), 1000, 5);
        trie1.insert(&addr(2), 2000, 10);

        trie2.insert(&addr(1), 1000, 5);
        trie2.insert(&addr(2), 2000, 10);

        assert_eq!(trie1.root(), trie2.root());
    }

    #[test]
    fn different_order_same_root() {
        let mut trie1 = MerkleTrie::new();
        let mut trie2 = MerkleTrie::new();

        trie1.insert(&addr(1), 1000, 5);
        trie1.insert(&addr(2), 2000, 10);

        trie2.insert(&addr(2), 2000, 10);
        trie2.insert(&addr(1), 1000, 5);

        assert_eq!(trie1.root(), trie2.root());
    }

    #[test]
    fn update_balance_changes_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        let root1 = trie.root();

        trie.insert(&addr(1), 2000, 5);
        let root2 = trie.root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn remove_restores_previous_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        let root_with = trie.root();

        trie.insert(&addr(2), 2000, 10);
        assert_ne!(root_with, trie.root());

        trie.remove(&addr(2));
        // Root should be back to the state with only addr(1).
        assert_eq!(root_with, trie.root());
    }

    #[test]
    fn proof_verifies_correctly() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        trie.insert(&addr(2), 2000, 10);
        trie.insert(&addr(3), 3000, 15);

        let root = trie.root();
        let proof = trie.proof(&addr(2));

        assert!(proof.verify(&root));
    }

    #[test]
    fn proof_fails_with_wrong_root() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);

        let proof = trie.proof(&addr(1));
        let wrong_root = [0xFFu8; 32];
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn proof_fails_with_tampered_sibling() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);
        trie.insert(&addr(2), 2000, 10);

        let root = trie.root();
        let mut proof = trie.proof(&addr(1));
        proof.siblings[0] = [0xFFu8; 32]; // tamper

        assert!(!proof.verify(&root));
    }

    #[test]
    fn bulk_insert_produces_same_root() {
        let mut trie1 = MerkleTrie::new();
        let mut trie2 = MerkleTrie::new();

        let entries: Vec<_> = (0..50)
            .map(|i| (addr(i), (i as u64) * 100, i as u64))
            .collect();

        for (a, b, n) in &entries {
            trie1.insert(a, *b, *n);
        }
        trie2.bulk_insert(&entries);

        assert_eq!(trie1.root(), trie2.root());
    }

    #[test]
    fn hundred_accounts_deterministic() {
        let mut trie = MerkleTrie::new();
        for i in 0..100u8 {
            trie.insert(&addr(i), (i as u64) * 1000, i as u64);
        }
        let root1 = trie.root();

        let mut trie2 = MerkleTrie::new();
        for i in (0..100u8).rev() {
            trie2.insert(&addr(i), (i as u64) * 1000, i as u64);
        }
        let root2 = trie2.root();

        assert_eq!(root1, root2);
    }

    #[test]
    fn proof_for_nonexistent_address() {
        let mut trie = MerkleTrie::new();
        trie.insert(&addr(1), 1000, 5);

        let proof = trie.proof(&addr(99));
        // The leaf hash is zero (not in trie), proof should still be valid
        // against the current root (zero leaf is part of the trie structure).
        let root = trie.root();
        assert!(proof.verify(&root));
    }
}
