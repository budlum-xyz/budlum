//! Sparse-Merkle state commitment (`execution_root`) over UEL namespaces.
//!
//! Section 8.10 commits all execution-environment state into a single 32-byte
//! `execution_root`:
//!
//! ```text
//! execution_root = H(
//!     BDLM_UEL_ROOT_V1,
//!     evm_root,
//!     wasm_root,
//!     svm_root,
//!     move_root,
//!     budzero_root,
//!     alias_root,
//!     asset_root,
//! )
//! ```
//!
//! Every input to `H` is `u64`-LE length-prefixed (`hash_fields_bytes`), and
//! each sub-root is the root of a 256-depth MSB-first sparse binary Merkle trie
//! over its canonical namespaces.
//! Convenience: public sparse Merkle UEL namespace store and execution_root proof surface (WP-26).

use std::collections::BTreeMap;
use std::fmt;

use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::accounts::{
    alias_namespace_key, derive_asset_id, derive_local_alias, AccountModelError,
};

/// Canonical namespace names (Section 8.10 item 3).
/// Convenience: namespace constant for EVM account state.
pub const NS_EVM_ACCOUNT: &str = "ee/evm/account";
/// Convenience: namespace constant for EVM bytecode.
pub const NS_EVM_CODE: &str = "ee/evm/code";
/// Convenience: namespace constant for EVM contract storage.
pub const NS_EVM_STORAGE: &str = "ee/evm/storage";
/// Convenience: namespace constant for CosmWasm uploaded code.
pub const NS_WASM_CODE: &str = "ee/wasm/code";
/// Convenience: namespace constant for CosmWasm contract metadata.
pub const NS_WASM_CONTRACT: &str = "ee/wasm/contract";
/// Convenience: namespace constant for CosmWasm contract key-value store.
pub const NS_WASM_STORE: &str = "ee/wasm/store";
/// Convenience: namespace constant for SVM account data.
pub const NS_SVM_ACCOUNT: &str = "ee/svm/account";
/// Convenience: namespace constant for Move resources and modules.
pub const NS_MOVE_STATE: &str = "ee/move/state";
/// Convenience: namespace constant for BudZero program commitments.
pub const NS_BUDZERO_PROGRAM: &str = "ee/budzero/program";
/// Convenience: namespace constant for BudZero storage slots.
pub const NS_BUDZERO_STORAGE: &str = "ee/budzero/storage";
/// Convenience: namespace constant for deterministic UEL aliases.
pub const NS_UEL_ALIAS: &str = "uel/alias";
/// Convenience: namespace constant for the Universal Asset Registry.
pub const NS_UEL_ASSETS: &str = "uel/assets";

/// All twelve canonical UEL namespaces committed by `execution_root`.
///
/// Convenience: exposed for namespace inventory and block read cache sweeps.
pub const ALL_UEL_NAMESPACES: &[&str] = &[
    NS_EVM_ACCOUNT,
    NS_EVM_CODE,
    NS_EVM_STORAGE,
    NS_WASM_CODE,
    NS_WASM_CONTRACT,
    NS_WASM_STORE,
    NS_SVM_ACCOUNT,
    NS_MOVE_STATE,
    NS_BUDZERO_PROGRAM,
    NS_BUDZERO_STORAGE,
    NS_UEL_ALIAS,
    NS_UEL_ASSETS,
];

const TRIE_DEPTH: usize = 256;

/// Logical sub-tree owning one or more UEL namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum UelSubTree {
    Evm = 0x01,
    Wasm = 0x02,
    Svm = 0x03,
    Move = 0x04,
    BudZero = 0x05,
    Alias = 0x06,
    Asset = 0x07,
}

impl UelSubTree {
    /// Resolve a canonical namespace string to its owning sub-tree.
    pub fn from_namespace(ns: &str) -> Option<Self> {
        match ns {
            NS_EVM_ACCOUNT | NS_EVM_CODE | NS_EVM_STORAGE => Some(Self::Evm),
            NS_WASM_CODE | NS_WASM_CONTRACT | NS_WASM_STORE => Some(Self::Wasm),
            NS_SVM_ACCOUNT => Some(Self::Svm),
            NS_MOVE_STATE => Some(Self::Move),
            NS_BUDZERO_PROGRAM | NS_BUDZERO_STORAGE => Some(Self::BudZero),
            NS_UEL_ALIAS => Some(Self::Alias),
            NS_UEL_ASSETS => Some(Self::Asset),
            _ => None,
        }
    }
}

/// Refusal reasons when mutating or proving UEL namespace state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentError {
    /// Namespace is not one of the twelve canonical UEL namespaces.
    UnknownNamespace(String),
    /// Alias or asset derivation failed.
    AccountModel(AccountModelError),
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNamespace(ns) => write!(f, "unknown UEL namespace `{ns}`"),
            Self::AccountModel(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CommitmentError {}

impl From<AccountModelError> for CommitmentError {
    fn from(value: AccountModelError) -> Self {
        Self::AccountModel(value)
    }
}

/// Individual sparse-Merkle sub-roots folded into `execution_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UelSubRoots {
    pub evm: [u8; 32],
    pub wasm: [u8; 32],
    pub svm: [u8; 32],
    pub move_vm: [u8; 32],
    pub budzero: [u8; 32],
    pub alias: [u8; 32],
    pub asset: [u8; 32],
}

/// Fixed-depth (256) inclusion or absence proof in a UEL sub-tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UelExecutionProof {
    pub subtree: u8,
    pub key_digest: [u8; 32],
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl UelExecutionProof {
    /// Verify this proof against `expected_sub_root` (`bud_getExecutionProof`).
    ///
    /// Convenience: exposed for RPC proof verification and light-client checks.
    #[must_use]
    pub fn verify(&self, expected_sub_root: &[u8; 32]) -> bool {
        if self.siblings.len() != TRIE_DEPTH {
            return false;
        }
        let mut current = self.leaf_hash;
        for (step, sibling) in self.siblings.iter().enumerate() {
            let depth = TRIE_DEPTH - 1 - step;
            let is_right = bit_at(&self.key_digest, depth);
            let (left, right) = if is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = hash_internal(&left, &right);
        }
        finalize_subtree_root(self.subtree, &current) == *expected_sub_root
    }
}

fn bit_at(bytes: &[u8; 32], bit_index: usize) -> bool {
    let byte_idx = bit_index / 8;
    let bit_offset = 7 - (bit_index % 8);
    bytes
        .get(byte_idx)
        .is_some_and(|b| ((b >> bit_offset) & 1) == 1)
}

fn trie_key_digest(ns: &str, raw_key: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_UEL_SPARSE_TRIE_V1", ns.as_bytes(), raw_key])
}

fn hash_leaf(key_digest: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(key_digest);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
    h.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == [0u8; 32] && *right == [0u8; 32] {
        return [0u8; 32];
    }
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn finalize_subtree_root(subtree_id: u8, raw_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_UEL_SPARSE_TRIE_V1");
    h.update([subtree_id]);
    h.update(raw_root);
    h.finalize().into()
}

fn sparse_subtree_hash(sorted_leaves: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
    if sorted_leaves.is_empty() {
        return [0u8; 32];
    }
    if depth == TRIE_DEPTH {
        return sorted_leaves.first().map_or([0u8; 32], |(_, leaf)| *leaf);
    }
    if sorted_leaves.len() == 1 {
        let mut current = sorted_leaves.first().map_or([0u8; 32], |(_, leaf)| *leaf);
        let key = sorted_leaves.first().map_or([0u8; 32], |(k, _)| *k);
        for d in (depth..TRIE_DEPTH).rev() {
            let (left, right) = if bit_at(&key, d) {
                ([0u8; 32], current)
            } else {
                (current, [0u8; 32])
            };
            current = hash_internal(&left, &right);
        }
        return current;
    }
    let split = sorted_leaves.partition_point(|(k, _)| !bit_at(k, depth));
    let Some((left_slice, right_slice)) = sorted_leaves.split_at_checked(split) else {
        return [0u8; 32];
    };
    let left = sparse_subtree_hash(left_slice, depth + 1);
    let right = sparse_subtree_hash(right_slice, depth + 1);
    hash_internal(&left, &right)
}

fn prove_in_sorted_leaves(
    subtree_id: u8,
    sorted_leaves: &[([u8; 32], [u8; 32])],
    target_key: [u8; 32],
) -> UelExecutionProof {
    let leaf_hash = sorted_leaves
        .binary_search_by_key(&target_key, |(k, _)| *k)
        .ok()
        .and_then(|idx| sorted_leaves.get(idx))
        .map_or([0u8; 32], |(_, lh)| *lh);

    let mut siblings_top_down = Vec::with_capacity(TRIE_DEPTH);
    let mut window = sorted_leaves;
    for depth in 0..TRIE_DEPTH {
        let split = window.partition_point(|(k, _)| !bit_at(k, depth));
        let (left_slice, right_slice) = window.split_at_checked(split).unwrap_or((&[], &[]));
        if bit_at(&target_key, depth) {
            siblings_top_down.push(sparse_subtree_hash(left_slice, depth + 1));
            window = right_slice;
        } else {
            siblings_top_down.push(sparse_subtree_hash(right_slice, depth + 1));
            window = left_slice;
        }
    }
    siblings_top_down.reverse();
    UelExecutionProof {
        subtree: subtree_id,
        key_digest: target_key,
        leaf_hash,
        siblings: siblings_top_down,
    }
}

/// Persistent canonical UEL namespace key-value store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UelNamespaceStore {
    namespaces: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl UelNamespaceStore {
    /// Returns `true` when every namespace holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.values().all(BTreeMap::is_empty)
    }

    /// Read a key from a canonical UEL namespace.
    ///
    /// Convenience: exposed for coordinator read overlays and RPC queries.
    #[must_use]
    pub fn read(&self, ns: &str, key: &[u8]) -> Option<&[u8]> {
        self.namespaces
            .get(ns)
            .and_then(|map| map.get(key))
            .map(Vec::as_slice)
    }

    /// Deterministically iterate `(key, value)` pairs stored in `ns` in ascending key order.
    ///
    /// Convenience: exposed for Universal Asset Registry pointer scans and read overlays.
    pub fn iter_namespace(&self, ns: &str) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.namespaces
            .get(ns)
            .into_iter()
            .flat_map(|map| map.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
    }

    /// Total stored value + key bytes in `ns` (`budlum_state_bytes{ns}`).
    ///
    /// Convenience: exposed for per-namespace state telemetry gauges.
    #[must_use]
    pub fn namespace_bytes(&self, ns: &str) -> u64 {
        self.namespaces.get(ns).map_or(0, |map| {
            map.iter().fold(0u64, |acc, (k, v)| {
                acc.saturating_add(k.len() as u64)
                    .saturating_add(v.len() as u64)
            })
        })
    }

    /// Write (`Some(val)`) or delete (`None`) a key in a canonical UEL namespace.
    ///
    /// Convenience: exposed for overlay commits and coordinator writes.
    pub fn write(
        &mut self,
        ns: &str,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Result<(), CommitmentError> {
        if UelSubTree::from_namespace(ns).is_none() {
            return Err(CommitmentError::UnknownNamespace(ns.to_string()));
        }
        match value {
            Some(val) => {
                self.namespaces
                    .entry(ns.to_string())
                    .or_default()
                    .insert(key, val);
            }
            None => {
                if let Some(map) = self.namespaces.get_mut(ns) {
                    map.remove(&key);
                    if map.is_empty() {
                        self.namespaces.remove(ns);
                    }
                }
            }
        }
        Ok(())
    }

    /// Ensure `local`'s alias in `ee` is recorded in `uel/alias` (Section 8.4.2 item 4).
    ///
    /// Convenience: called by coordinator overlays upon first local-account interaction.
    pub fn ensure_alias_registered(
        &mut self,
        local: &Address,
        ee: EeId,
    ) -> Result<Vec<u8>, CommitmentError> {
        let key = alias_namespace_key(local, ee);
        if let Some(existing) = self.read(NS_UEL_ALIAS, &key) {
            return Ok(existing.to_vec());
        }
        let alias = derive_local_alias(local, ee)?;
        self.write(NS_UEL_ALIAS, key.to_vec(), Some(alias.clone()))?;
        Ok(alias)
    }

    /// Check whether `native_addr` matches any registered local alias in `ee`
    /// (Section 8.4.2 item 3 collision guard).
    ///
    /// Convenience: called by foreign envelope guards before auto-creating accounts.
    #[must_use]
    pub fn is_registered_alias(&self, ee: EeId, native_addr: &[u8]) -> bool {
        let Some(map) = self.namespaces.get(NS_UEL_ALIAS) else {
            return false;
        };
        map.iter()
            .any(|(k, v)| k.get(32).copied() == Some(ee.0) && v.as_slice() == native_addr)
    }

    /// Register a canonical asset metadata blob in `uel/assets` (Section 8.8).
    ///
    /// Convenience: called by the coordinator when registering native EE assets.
    pub fn register_asset(
        &mut self,
        home_ee: EeId,
        home_ref: &[u8],
        record_bytes: Vec<u8>,
    ) -> Result<[u8; 32], CommitmentError> {
        let asset_id = derive_asset_id(home_ee, home_ref)?;
        self.write(NS_UEL_ASSETS, asset_id.to_vec(), Some(record_bytes))?;
        Ok(asset_id)
    }

    fn sorted_leaves_for(&self, subtree: UelSubTree) -> Vec<([u8; 32], [u8; 32])> {
        let mut by_digest: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        for (ns, entries) in &self.namespaces {
            if UelSubTree::from_namespace(ns) != Some(subtree) {
                continue;
            }
            for (raw_key, val) in entries {
                let kd = trie_key_digest(ns, raw_key);
                by_digest.insert(kd, hash_leaf(&kd, val));
            }
        }
        by_digest.into_iter().collect()
    }

    /// Compute the 32-byte sparse-Merkle root of a single UEL sub-tree.
    #[must_use]
    pub fn subtree_root(&self, subtree: UelSubTree) -> [u8; 32] {
        let leaves = self.sorted_leaves_for(subtree);
        let raw = sparse_subtree_hash(&leaves, 0);
        finalize_subtree_root(subtree as u8, &raw)
    }

    /// Generate a 256-depth sparse-Merkle proof for `(ns, key)`.
    ///
    /// Convenience: exposed for `bud_getExecutionProof` callers and light clients.
    pub fn prove(&self, ns: &str, key: &[u8]) -> Result<UelExecutionProof, CommitmentError> {
        let subtree = UelSubTree::from_namespace(ns)
            .ok_or_else(|| CommitmentError::UnknownNamespace(ns.to_string()))?;
        let leaves = self.sorted_leaves_for(subtree);
        let target = trie_key_digest(ns, key);
        Ok(prove_in_sorted_leaves(subtree as u8, &leaves, target))
    }

    /// Compute all seven UEL sub-roots.
    #[must_use]
    pub fn sub_roots(&self) -> UelSubRoots {
        UelSubRoots {
            evm: self.subtree_root(UelSubTree::Evm),
            wasm: self.subtree_root(UelSubTree::Wasm),
            svm: self.subtree_root(UelSubTree::Svm),
            move_vm: self.subtree_root(UelSubTree::Move),
            budzero: self.subtree_root(UelSubTree::BudZero),
            alias: self.subtree_root(UelSubTree::Alias),
            asset: self.subtree_root(UelSubTree::Asset),
        }
    }

    /// Compute `execution_root = H(BDLM_UEL_ROOT_V1, evm, wasm, svm, move, budzero, alias, asset)`.
    #[must_use]
    pub fn execution_root(&self) -> [u8; 32] {
        let r = self.sub_roots();
        hash_fields_bytes(&[
            b"BDLM_UEL_ROOT_V1",
            &r.evm,
            &r.wasm,
            &r.svm,
            &r.move_vm,
            &r.budzero,
            &r.alias,
            &r.asset,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_root_binds_every_namespace() {
        let mut store = UelNamespaceStore::default();
        let baseline = store.execution_root();

        let mut seen = Vec::new();
        for (idx, ns) in ALL_UEL_NAMESPACES.iter().enumerate() {
            let key = vec![idx as u8, 0xAA];
            let val_a = vec![0x01, idx as u8];
            let val_b = vec![0x02, idx as u8];

            store.write(ns, key.clone(), Some(val_a)).unwrap();
            let root_a = store.execution_root();
            assert_ne!(root_a, baseline, "namespace {ns} did not affect execution_root");
            assert!(
                !seen.contains(&root_a),
                "namespace {ns} collided with an earlier namespace root"
            );
            seen.push(root_a);

            // Inclusion proof verifies against the active sub-root.
            let st = UelSubTree::from_namespace(ns).unwrap();
            let proof = store.prove(ns, &key).unwrap();
            assert!(proof.verify(&store.subtree_root(st)));

            // Changing the value changes execution_root.
            store.write(ns, key.clone(), Some(val_b)).unwrap();
            let root_b = store.execution_root();
            assert_ne!(root_a, root_b, "mutating value in {ns} left root unchanged");

            // Deleting the key restores the exact baseline root and verifies absence.
            store.write(ns, key.clone(), None).unwrap();
            assert_eq!(store.execution_root(), baseline);
            let absence = store.prove(ns, &key).unwrap();
            assert_eq!(absence.leaf_hash, [0u8; 32]);
            assert!(absence.verify(&store.subtree_root(st)));
        }
    }

    #[test]
    fn uel_cross_arch_roots_equal() {
        let alice = Address([0x07; 32]);
        let bob = Address([0x19; 32]);

        let mut forward = UelNamespaceStore::default();
        forward.ensure_alias_registered(&alice, EeId::EVM).unwrap();
        forward.ensure_alias_registered(&bob, EeId::SVM).unwrap();
        forward
            .register_asset(EeId::EVM, &[0xAB; 20], b"USDC:6".to_vec())
            .unwrap();
        forward
            .write(NS_EVM_STORAGE, vec![1, 2, 3], Some(vec![9, 9, 9]))
            .unwrap();
        forward
            .write(NS_BUDZERO_STORAGE, vec![4, 5], Some(vec![7, 8]))
            .unwrap();
        forward
            .write(NS_WASM_STORE, b"contract1:k".to_vec(), Some(b"v".to_vec()))
            .unwrap();

        let mut reverse = UelNamespaceStore::default();
        reverse
            .write(NS_WASM_STORE, b"contract1:k".to_vec(), Some(b"v".to_vec()))
            .unwrap();
        reverse
            .write(NS_BUDZERO_STORAGE, vec![4, 5], Some(vec![7, 8]))
            .unwrap();
        reverse
            .write(NS_EVM_STORAGE, vec![1, 2, 3], Some(vec![9, 9, 9]))
            .unwrap();
        reverse
            .register_asset(EeId::EVM, &[0xAB; 20], b"USDC:6".to_vec())
            .unwrap();
        reverse.ensure_alias_registered(&bob, EeId::SVM).unwrap();
        reverse.ensure_alias_registered(&alice, EeId::EVM).unwrap();

        assert_eq!(
            forward.execution_root(),
            reverse.execution_root(),
            "sparse Merkle execution_root must be independent of write order and host word size"
        );
        let evm_alias = forward.ensure_alias_registered(&alice, EeId::EVM).unwrap();
        assert!(forward.is_registered_alias(EeId::EVM, &evm_alias));
        assert!(!forward.is_registered_alias(EeId::SVM, &evm_alias));
    }
}
