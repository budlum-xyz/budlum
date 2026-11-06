//! Execution namespaces, sparse binary Merkle commitments, and `execution_root`.
//!
//! Implements sections 8.8 and 8.10:
//! - Eleven canonical namespaces grouped into seven fixed-depth (256-bit) sparse
//!   binary Merkle subtrees (`evm`, `wasm`, `svm`, `move`, `budzero`, `alias`,
//!   `asset`).
//! - `execution_root = H("BDLM_UEL_ROOT_V1", evm_root, wasm_root, svm_root,
//!   move_root, budzero_root, alias_root, asset_root)` with length-prefixed
//!   fields (`core::hash::hash_fields_bytes`).
//! - Permissionless Universal Asset ID derivation (`BDLM_UEL_ASSET_V1`) and
//!   per-environment deploy feature flags (R-21).

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::alias::{
    alias_storage_key, derive_alias_bytes, ALIAS_NAMESPACE,
};
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// Canonical EVM namespaces.
pub const NS_EVM_ACCOUNT: &str = "ee/evm/account";
pub const NS_EVM_CODE: &str = "ee/evm/code";
pub const NS_EVM_STORAGE: &str = "ee/evm/storage";

/// Canonical WASM (CosmWasm) namespaces.
pub const NS_WASM_CODE: &str = "ee/wasm/code";
pub const NS_WASM_CONTRACT: &str = "ee/wasm/contract";
pub const NS_WASM_STORE: &str = "ee/wasm/store";

/// Canonical SVM namespace.
pub const NS_SVM_ACCOUNT: &str = "ee/svm/account";

/// Canonical Move namespace.
pub const NS_MOVE_STATE: &str = "ee/move/state";

/// Canonical BudZero stateful contract namespaces.
pub const NS_BUDZERO_PROGRAM: &str = "ee/budzero/program";
pub const NS_BUDZERO_STORAGE: &str = "ee/budzero/storage";

/// Canonical Universal Asset Registry namespace.
pub const NS_UEL_ASSETS: &str = "uel/assets";

/// All eleven canonical UEL namespaces in deterministic order.
pub const ALL_NAMESPACES: &[&str] = &[
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
    ALIAS_NAMESPACE,
    NS_UEL_ASSETS,
];

/// Seven root groups folded into `execution_root` in section 8.10 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RootGroup {
    Evm,
    Wasm,
    Svm,
    Move,
    BudZero,
    Alias,
    Asset,
}

impl RootGroup {
    /// Classifies a namespace string into its `execution_root` subtree, or
    /// `None` if the namespace is outside the UEL commitment surface.
    #[must_use]
    pub fn for_namespace(ns: &str) -> Option<Self> {
        match ns {
            NS_EVM_ACCOUNT | NS_EVM_CODE | NS_EVM_STORAGE => Some(Self::Evm),
            NS_WASM_CODE | NS_WASM_CONTRACT | NS_WASM_STORE => Some(Self::Wasm),
            NS_SVM_ACCOUNT => Some(Self::Svm),
            NS_MOVE_STATE => Some(Self::Move),
            NS_BUDZERO_PROGRAM | NS_BUDZERO_STORAGE => Some(Self::BudZero),
            ALIAS_NAMESPACE => Some(Self::Alias),
            NS_UEL_ASSETS => Some(Self::Asset),
            _ => None,
        }
    }
}

/// Derives `asset_id = SHA3-256("BDLM_UEL_ASSET_V1" || home_ee || len_le64 || home_ref)`.
///
/// exposed for: Universal Asset Registry (`WP-30`).
#[must_use]
pub fn derive_uel_asset_id(home_ee: EeId, home_ref: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_UEL_ASSET_V1");
    h.update([home_ee.0]);
    h.update((home_ref.len() as u64).to_le_bytes());
    h.update(home_ref);
    h.finalize().into()
}

/// Committed UEL state held on `AccountState` and persisted in snapshots.
///
/// Map keys use `String` (namespace name -> hex-encoded raw key) so JSON
/// snapshots (`StateSnapshotV2`) and bincode serialize identically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionState {
    /// `namespace -> (hex_key -> value_bytes)`.
    pub namespaces: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
    /// Environments frozen against new contract deployments (R-21).
    /// Existing contracts and state remain readable and callable.
    #[serde(default)]
    pub deploy_frozen_ees: BTreeSet<u8>,
    /// Current UEL EIP-1559 base fee in attoBUD per BGU (`0` means genesis floor).
    #[serde(default)]
    pub base_fee_per_bgu_attos: u128,
}

impl ExecutionState {
    /// Creates an empty UEL execution state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when no UEL namespace entry, freeze flag, or custom base
    /// fee has been written yet, preserving pre-UEL state roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.values().all(BTreeMap::is_empty)
            && self.deploy_frozen_ees.is_empty()
            && self.base_fee_per_bgu_attos == 0
    }

    /// Reads one raw key from a canonical UEL namespace.
    pub fn read(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if RootGroup::for_namespace(ns).is_none() {
            return Err(format!("unknown UEL namespace `{ns}`"));
        }
        let hex_key = hex::encode(key);
        Ok(self
            .namespaces
            .get(ns)
            .and_then(|bucket| bucket.get(&hex_key).cloned()))
    }

    /// Writes (`Some`) or deletes (`None`) one raw key in a canonical namespace.
    pub fn write(&mut self, ns: &str, key: &[u8], value: Option<&[u8]>) -> Result<(), String> {
        if RootGroup::for_namespace(ns).is_none() {
            return Err(format!("unknown UEL namespace `{ns}`"));
        }
        let hex_key = hex::encode(key);
        match value {
            Some(bytes) => {
                self.namespaces
                    .entry(ns.to_string())
                    .or_default()
                    .insert(hex_key, bytes.to_vec());
            }
            None => {
                if let Some(bucket) = self.namespaces.get_mut(ns) {
                    bucket.remove(&hex_key);
                    if bucket.is_empty() {
                        self.namespaces.remove(ns);
                    }
                }
            }
        }
        Ok(())
    }

    /// Sets whether `ee` accepts new contract deployments without halting the chain.
    pub fn set_deploy_enabled(&mut self, ee: EeId, enabled: bool) {
        if enabled {
            self.deploy_frozen_ees.remove(&ee.0);
        } else {
            self.deploy_frozen_ees.insert(ee.0);
        }
    }

    /// Returns `true` if `ee` currently accepts new contract deployments.
    #[must_use]
    pub fn is_deploy_enabled(&self, ee: EeId) -> bool {
        !self.deploy_frozen_ees.contains(&ee.0)
    }

    /// Ensures `addr`'s deterministic alias for `ee` is recorded in `uel/alias`
    /// on first use and returns the alias bytes.
    pub fn ensure_alias_registered(&mut self, addr: &Address, ee: EeId) -> Result<Vec<u8>, String> {
        let key = alias_storage_key(addr, ee);
        if let Some(existing) = self.read(ALIAS_NAMESPACE, &key)? {
            return Ok(existing);
        }
        let alias = derive_alias_bytes(addr, ee)?;
        self.write(ALIAS_NAMESPACE, &key, Some(&alias))?;
        Ok(alias)
    }

    /// Refuses a secp256k1 sender or `CREATE`/`CREATE2` target that collides
    /// with any registered 20-byte EVM alias (section 8.4.2 rule 3).
    ///
    /// exposed for: EVM worker / foreign envelope admission (`WP-27`).
    pub fn check_evm_alias_collision(&self, candidate_evm_addr: &[u8; 20]) -> Result<(), String> {
        let Some(bucket) = self.namespaces.get(ALIAS_NAMESPACE) else {
            return Ok(());
        };
        for (hex_key, val) in bucket {
            let Ok(raw_key) = hex::decode(hex_key) else {
                continue;
            };
            if raw_key.get(32).copied() == Some(EeId::EVM.0)
                && val.as_slice() == candidate_evm_addr
            {
                return Err(String::from(
                    "EVM address collides with a registered native UEL alias",
                ));
            }
        }
        Ok(())
    }

    /// Total stored payload bytes in `ns` (for `budlum_state_bytes{ns}` metering).
    ///
    /// exposed for: state growth metering (`R-12`, `WP-27`).
    #[must_use]
    pub fn namespace_bytes(&self, ns: &str) -> u64 {
        self.namespaces.get(ns).map_or(0, |bucket| {
            bucket.iter().fold(0u64, |acc, (hex_k, v)| {
                let key_len = (hex_k.len() / 2) as u64;
                acc.saturating_add(key_len).saturating_add(v.len() as u64)
            })
        })
    }

    /// Computes the sparse 256-bit binary Merkle root of one `RootGroup`.
    #[must_use]
    pub fn group_root(&self, group: RootGroup) -> [u8; 32] {
        let mut leaves: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        for (ns, bucket) in &self.namespaces {
            if RootGroup::for_namespace(ns) != Some(group) {
                continue;
            }
            for (hex_key, value) in bucket {
                let Ok(raw_key) = hex::decode(hex_key) else {
                    continue;
                };
                let path_key = hash_fields_bytes(&[b"BDLM_UEL_NS_KEY_V1", ns.as_bytes(), &raw_key]);
                let leaf_hash = hash_fields_bytes(&[
                    b"BDLM_UEL_NS_LEAF_V1",
                    ns.as_bytes(),
                    &raw_key,
                    value,
                ]);
                leaves.insert(path_key, leaf_hash);
            }
        }
        let entries: Vec<([u8; 32], [u8; 32])> = leaves.into_iter().collect();
        sparse_merkle_subtree(&entries, 0)
    }

    /// Computes `execution_root = H("BDLM_UEL_ROOT_V1", evm, wasm, svm, move, budzero, alias, asset)`.
    #[must_use]
    pub fn execution_root(&self) -> [u8; 32] {
        let evm = self.group_root(RootGroup::Evm);
        let wasm = self.group_root(RootGroup::Wasm);
        let svm = self.group_root(RootGroup::Svm);
        let mov = self.group_root(RootGroup::Move);
        let budzero = self.group_root(RootGroup::BudZero);
        let alias = self.group_root(RootGroup::Alias);
        let asset = self.group_root(RootGroup::Asset);
        hash_fields_bytes(&[
            b"BDLM_UEL_ROOT_V1",
            &evm,
            &wasm,
            &svm,
            &mov,
            &budzero,
            &alias,
            &asset,
        ])
    }
}

fn bit_at_msb(key: &[u8; 32], depth: usize) -> bool {
    let byte_idx = depth / 8;
    let bit_in_byte = 7 - (depth % 8);
    key.get(byte_idx)
        .is_some_and(|b| ((b >> bit_in_byte) & 1) == 1)
}

/// Exact depth-256 sparse binary Merkle root over sorted `(path_key, leaf_hash)` pairs.
fn sparse_merkle_subtree(entries: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    if depth >= 256 {
        return entries.first().map_or([0u8; 32], |(_, h)| *h);
    }
    let split = entries.partition_point(|(k, _)| !bit_at_msb(k, depth));
    let (left_slice, right_slice) = entries.split_at(split);
    let left = sparse_merkle_subtree(left_slice, depth + 1);
    let right = sparse_merkle_subtree(right_slice, depth + 1);
    if left == [0u8; 32] && right == [0u8; 32] {
        [0u8; 32]
    } else {
        hash_fields_bytes(&[b"BDLM_UEL_NS_NODE_V1", &left, &right])
    }
}
