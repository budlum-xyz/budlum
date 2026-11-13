//! Non-EVM verified state migrations (`8.12.3`: WASM ICS-23, SVM account proof, Move resource proof).
//!
//! Each door verifies finalized source-state inclusion and source-chain deployer/authority
//! cryptography, enforces unoccupied target + alias disjointness, leaves native gas balances
//! at zero (`N-5`), charges [`MigrationFeeSchedule`] before mutating state (`G-4`), and
//! installs state directly into the target execution namespace (`ee/wasm/*`, `ee/svm/account`,
//! `ee/move/state`).
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use std::collections::BTreeSet;

use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;

use crate::core::account::{AccountState, BudEnvUnit};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::alias::derive_contract_account;
use crate::execution::coordinator::foreign::{
    verify_aptos_migration_sig, verify_cosmos_secp256k1_migration_sig,
    verify_solana_ed25519_migration_sig,
};
use crate::execution::coordinator::move_ee::{
    state_key_module, state_key_resource, FORBIDDEN_MOVE_MODULES, MAX_MOVE_BUNDLE_BYTES,
    MOVE_BINARY_MAGIC,
};
use crate::execution::coordinator::state::{
    ExecutionState, NS_MOVE_STATE, NS_SVM_ACCOUNT, NS_WASM_CODE, NS_WASM_CONTRACT, NS_WASM_STORE,
};
use crate::execution::coordinator::svm_ee::{
    SvmAccountData, ELF_MAGIC, FORBIDDEN_SVM_STAKE_PROGRAM_ID, FORBIDDEN_SVM_VOTE_PROGRAM_ID,
    MAX_SBPF_PROGRAM_BYTES, SVM_BPF_LOADER_ID,
};
use crate::execution::coordinator::wasm_ee::{validate_cosmwasm_bytecode, wasm_store_key};
use crate::object_layer::family::encoding::bech32_decode;
use crate::tokenomics::reward_pool::reward_pool_account;

use super::fee::{quote_migration_fee, MigrationFeeQuote, MigrationFeeSchedule, MigrationUsage};
use super::{ImportError, MAX_CHUNK_SLOTS};

/// Maximum Merkle / ICS-23 proof depth accepted by non-EVM migration doors.
const MAX_PROOF_DEPTH: usize = 64;

/// One inner hash folding step in an ICS-23 existence proof (`8.12.3` WASM row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ics23InnerOp {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

/// ICS-23 IAVL/Merkle existence proof committing `(key, value)` to an app hash root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ics23ExistenceProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub leaf_prefix: Vec<u8>,
    pub path: Vec<Ics23InnerOp>,
}

/// Verified CosmWasm contract + storage migration request (`8.12.3` WASM row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMigrationRequest {
    /// Target Budlum chain ID (`45261` on testnet).
    pub chain_id: u64,
    /// Chain ID signed by the source creator (`must == chain_id`).
    pub budlum_chain_id: u64,
    /// Registered source Cosmos domain ID.
    pub source_domain_id: u32,
    /// Finalized source Cosmos height whose `state_root` is proved.
    pub source_block: u64,
    /// Finalized source `app_hash` / IAVL state root.
    pub state_root: [u8; 32],
    /// CosmWasm bech32 contract address to install identically on Budlum.
    pub contract_address: String,
    /// Bech32 address of the contract's creator/admin signer on the source chain.
    pub creator: String,
    /// Compressed 33-byte secp256k1 public key deriving `creator`.
    pub creator_pubkey33: Vec<u8>,
    /// 64-byte low-`s` secp256k1 signature over [`wasm_migration_digest`].
    pub creator_signature64: Vec<u8>,
    /// Contract label recorded in `WasmContractMeta`.
    pub label: String,
    /// Deterministic CosmWasm bytecode (validated identically to `WasmEe::validate_deploy`).
    pub wasm_code: Vec<u8>,
    /// ICS-23 proof binding `(contract_address, creator, code_hash)` to `state_root`.
    pub contract_info_proof: Ics23ExistenceProof,
    /// ICS-23 proofs for every key-value entry migrated into `ee/wasm/store`.
    pub storage_entries: Vec<Ics23ExistenceProof>,
}

/// Verified Solana account migration request (`8.12.3` SVM row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvmMigrationRequest {
    pub chain_id: u64,
    pub budlum_chain_id: u64,
    pub source_domain_id: u32,
    pub source_slot: u64,
    pub accounts_root: [u8; 32],
    pub pubkey: [u8; 32],
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
    /// Lamports held in the proven source snapshot (committed in proof only; installed as `0`).
    pub proven_lamports: u64,
    pub proof_index: usize,
    pub proof_siblings: Vec<[u8; 32]>,
    /// Account or owner upgrade authority signing the migration.
    pub authority_pubkey: [u8; 32],
    pub authority_signature64: Vec<u8>,
}

/// Key selector inside a verified Aptos Move state migration (`8.12.3` Move row).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoveMigrationEntryKind {
    Module(String),
    Resource(String),
}

/// One proven Move module or resource entry inside [`MoveMigrationRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveStateProofEntry {
    pub kind: MoveMigrationEntryKind,
    pub bytes: Vec<u8>,
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Verified Aptos Move account/module/resource migration request (`8.12.3` Move row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveMigrationRequest {
    pub chain_id: u64,
    pub budlum_chain_id: u64,
    pub source_domain_id: u32,
    pub source_version: u64,
    pub state_root: [u8; 32],
    pub account: [u8; 32],
    pub signer_pubkey: [u8; 32],
    pub signature64: Vec<u8>,
    pub entries: Vec<MoveStateProofEntry>,
}

fn push_uvarint(out: &mut Vec<u8>, mut v: usize) {
    loop {
        let low = u8::try_from(v & 0x7f).unwrap_or(0);
        v >>= 7;
        if v == 0 {
            out.push(low);
            break;
        }
        out.push(low | 0x80);
    }
}

/// Computes the ICS-23 SHA-256 leaf hash for `(leaf_prefix, key, value)`.
#[must_use]
pub fn compute_ics23_leaf_hash(leaf_prefix: &[u8], key: &[u8], value: &[u8]) -> [u8; 32] {
    let val_hash: [u8; 32] = Sha256::digest(value).into();
    let mut preimage = Vec::with_capacity(leaf_prefix.len() + key.len() + 48);
    preimage.extend_from_slice(leaf_prefix);
    push_uvarint(&mut preimage, key.len());
    preimage.extend_from_slice(key);
    push_uvarint(&mut preimage, val_hash.len());
    preimage.extend_from_slice(&val_hash);
    Sha256::digest(&preimage).into()
}

/// Verifies an [`Ics23ExistenceProof`] against `expected_root` and returns the node count.
///
/// # Errors
///
/// Returns [`ImportError`] when the path exceeds bounds or the reconstructed root mismatches.
pub fn verify_ics23_existence(
    proof: &Ics23ExistenceProof,
    expected_root: &[u8; 32],
) -> Result<u64, ImportError> {
    if proof.path.len() > MAX_PROOF_DEPTH {
        return Err(ImportError::StateError(String::from(
            "ICS-23 proof depth exceeds bound",
        )));
    }
    let mut current = compute_ics23_leaf_hash(&proof.leaf_prefix, &proof.key, &proof.value);
    for inner in &proof.path {
        let mut buf = Vec::with_capacity(inner.prefix.len() + 32 + inner.suffix.len());
        buf.extend_from_slice(&inner.prefix);
        buf.extend_from_slice(&current);
        buf.extend_from_slice(&inner.suffix);
        current = Sha256::digest(&buf).into();
    }
    if current != *expected_root {
        return Err(ImportError::StorageRootMismatch {
            expected: *expected_root,
            computed: current,
        });
    }
    let nodes = 1u64.saturating_add(u64::try_from(proof.path.len()).map_err(|_| {
        ImportError::StateError(String::from("ICS-23 node count overflow"))
    })?);
    Ok(nodes)
}

/// Computes the domain-separated signing digest for a `8.12.3` WASM migration.
#[must_use]
pub fn wasm_migration_digest(
    budlum_chain_id: u64,
    source_domain_id: u32,
    source_block: u64,
    contract_address: &str,
    code_hash: &[u8; 32],
    state_root: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_WASM_MIGRATION_V1",
        &budlum_chain_id.to_le_bytes(),
        &source_domain_id.to_le_bytes(),
        &source_block.to_le_bytes(),
        contract_address.as_bytes(),
        code_hash,
        state_root,
    ])
}

/// Computes the domain-separated signing digest for a `8.12.3` SVM migration.
#[must_use]
pub fn svm_migration_digest(
    budlum_chain_id: u64,
    source_domain_id: u32,
    source_slot: u64,
    pubkey: &[u8; 32],
    accounts_root: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_SVM_MIGRATION_V1",
        &budlum_chain_id.to_le_bytes(),
        &source_domain_id.to_le_bytes(),
        &source_slot.to_le_bytes(),
        pubkey,
        accounts_root,
    ])
}

/// Computes the SVM account state leaf hash verified under `accounts_root`.
#[must_use]
pub fn svm_account_leaf(
    slot: u64,
    pubkey: &[u8; 32],
    lamports: u64,
    owner: &[u8; 32],
    executable: bool,
    rent_epoch: u64,
    data: &[u8],
) -> [u8; 32] {
    let data_hash: [u8; 32] = Sha256::digest(data).into();
    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(b"BDLM_SVM_ACCOUNT_LEAF_V1");
    preimage.extend_from_slice(&slot.to_le_bytes());
    preimage.extend_from_slice(pubkey);
    preimage.extend_from_slice(&lamports.to_le_bytes());
    preimage.extend_from_slice(owner);
    preimage.push(u8::from(executable));
    preimage.extend_from_slice(&rent_epoch.to_le_bytes());
    preimage.extend_from_slice(&data_hash);
    Sha256::digest(&preimage).into()
}

/// Folds a binary SHA-256 Merkle proof from `leaf` at `index`.
#[must_use]
pub fn fold_sha256_merkle(leaf: [u8; 32], index: usize, siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut cur = leaf;
    let mut idx = index;
    for sib in siblings {
        let mut h = Sha256::new();
        h.update(b"BDLM_SVM_ACCOUNT_NODE_V1");
        if idx & 1 == 0 {
            h.update(cur);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(cur);
        }
        cur = h.finalize().into();
        idx >>= 1;
    }
    cur
}

/// Computes the domain-separated signing digest for a `8.12.3` Move migration.
#[must_use]
pub fn move_migration_digest(
    budlum_chain_id: u64,
    source_domain_id: u32,
    source_version: u64,
    account: &[u8; 32],
    state_root: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_MOVE_MIGRATION_V1",
        &budlum_chain_id.to_le_bytes(),
        &source_domain_id.to_le_bytes(),
        &source_version.to_le_bytes(),
        account,
        state_root,
    ])
}

/// Computes the Move state entry leaf hash verified under `state_root`.
#[must_use]
pub fn move_state_leaf(state_key: &[u8], value: &[u8]) -> [u8; 32] {
    let val_hash: [u8; 32] = Sha3_256::digest(value).into();
    let mut preimage = Vec::with_capacity(32 + state_key.len() + 32);
    preimage.extend_from_slice(b"BDLM_MOVE_STATE_LEAF_V1");
    preimage.extend_from_slice(state_key);
    preimage.extend_from_slice(&val_hash);
    Sha3_256::digest(&preimage).into()
}

/// Folds a binary SHA3-256 Merkle proof from `leaf` at `index`.
#[must_use]
pub fn fold_sha3_merkle(leaf: [u8; 32], index: usize, siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut cur = leaf;
    let mut idx = index;
    for sib in siblings {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_MOVE_STATE_NODE_V1");
        if idx & 1 == 0 {
            h.update(cur);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(cur);
        }
        cur = h.finalize().into();
        idx >>= 1;
    }
    cur
}

fn check_target_unoccupied(
    account_state: &AccountState,
    exec_state: &ExecutionState,
    ee: EeId,
    target_key: &[u8],
    ns: &str,
) -> Result<(), ImportError> {
    if exec_state.has_registered_alias_collision(ee, target_key) {
        return Err(ImportError::AddressOccupied);
    }
    if exec_state
        .read(ns, target_key)
        .map_err(ImportError::StateError)?
        .is_some()
    {
        return Err(ImportError::AddressOccupied);
    }
    let bud_addr = derive_contract_account(ee, target_key);
    if account_state.get_attos_balance(&bud_addr) > 0 {
        return Err(ImportError::AddressOccupied);
    }
    Ok(())
}

fn charge_migration_fee(
    state: &mut AccountState,
    migrator: &Address,
    fee: &MigrationFeeQuote,
) -> Result<(), ImportError> {
    if fee.total_attos > 0 {
        let pool = reward_pool_account();
        state
            .transfer_attos_in_unit(migrator, &pool, fee.total_attos, BudEnvUnit::EvmWei)
            .map_err(ImportError::InsufficientMigratorBalance)?;
    }
    Ok(())
}

pub(crate) fn apply_wasm_migration(
    state: &mut AccountState,
    migrator: &Address,
    req: WasmMigrationRequest,
    fee_schedule: &MigrationFeeSchedule,
) -> Result<([u8; 32], Vec<u8>, usize, MigrationFeeQuote), ImportError> {
    if req.budlum_chain_id != req.chain_id {
        return Err(ImportError::ChainMismatch {
            signed: req.budlum_chain_id,
            expected: req.chain_id,
        });
    }
    if req.storage_entries.len() > MAX_CHUNK_SLOTS {
        return Err(ImportError::ChunkTooLarge {
            slots: req.storage_entries.len(),
            max: MAX_CHUNK_SLOTS,
        });
    }
    let (_, contract_raw) = bech32_decode(&req.contract_address)
        .map_err(|e| ImportError::StateError(format!("invalid CosmWasm contract address: {e}")))?;
    if contract_raw.is_empty() {
        return Err(ImportError::ContractMismatch);
    }
    let (_, creator_raw) = bech32_decode(&req.creator)
        .map_err(|e| ImportError::StateError(format!("invalid CosmWasm creator address: {e}")))?;
    let creator_addr20: [u8; 20] = creator_raw
        .as_slice()
        .try_into()
        .map_err(|_| ImportError::StateError(String::from("Cosmos creator address != 20 bytes")))?;

    validate_cosmwasm_bytecode(&req.wasm_code).map_err(ImportError::StateError)?;
    let code_hash: [u8; 32] = Sha256::digest(&req.wasm_code).into();
    let digest = wasm_migration_digest(
        req.budlum_chain_id,
        req.source_domain_id,
        req.source_block,
        &req.contract_address,
        &code_hash,
        &req.state_root,
    );
    verify_cosmos_secp256k1_migration_sig(
        &digest,
        &req.creator_pubkey33,
        &req.creator_signature64,
        &creator_addr20,
    )
    .map_err(ImportError::StateError)?;

    let mut total_nodes = verify_ics23_existence(&req.contract_info_proof, &req.state_root)?;
    if req.contract_info_proof.key != req.contract_address.as_bytes() {
        return Err(ImportError::ContractMismatch);
    }
    let proven_info: serde_json::Value = serde_json::from_slice(&req.contract_info_proof.value)
        .map_err(|e| ImportError::StateError(format!("invalid CosmWasm contract info: {e}")))?;
    if proven_info.get("code_hash").and_then(|v| v.as_str()) != Some(hex::encode(code_hash).as_str())
        || proven_info.get("creator").and_then(|v| v.as_str()) != Some(req.creator.as_str())
    {
        return Err(ImportError::CodeHashMismatch);
    }

    let mut seen_keys = BTreeSet::new();
    for entry in &req.storage_entries {
        if !seen_keys.insert(entry.key.as_slice()) {
            return Err(ImportError::StateError(String::from(
                "duplicate WASM migration storage key",
            )));
        }
        let nodes = verify_ics23_existence(entry, &req.state_root)?;
        total_nodes = total_nodes.saturating_add(nodes);
    }

    let contract_bytes = req.contract_address.as_bytes().to_vec();
    check_target_unoccupied(
        state,
        &state.execution_state,
        EeId::WASM,
        &contract_bytes,
        NS_WASM_CONTRACT,
    )?;

    let usage = MigrationUsage {
        proof_nodes: total_nodes,
        code_bytes: u64::try_from(req.wasm_code.len()).map_err(|_| super::MigrationFeeOverflow)?,
        storage_slots: u64::try_from(req.storage_entries.len())
            .map_err(|_| super::MigrationFeeOverflow)?,
    };
    let fee = quote_migration_fee(usage, fee_schedule)?;
    let meta = serde_json::json!({
        "code_hash": hex::encode(code_hash),
        "creator": req.creator,
        "label": req.label,
        "imported_from": {
            "domain_id": req.source_domain_id,
            "block": req.source_block,
            "address": req.contract_address,
        }
    });
    let meta_bytes =
        serde_json::to_vec(&meta).map_err(|e| ImportError::StateError(e.to_string()))?;

    charge_migration_fee(state, migrator, &fee)?;

    state
        .execution_state
        .write(NS_WASM_CODE, &code_hash, Some(&req.wasm_code))
        .map_err(ImportError::StateError)?;
    state
        .execution_state
        .write(NS_WASM_CONTRACT, &contract_bytes, Some(&meta_bytes))
        .map_err(ImportError::StateError)?;
    for entry in &req.storage_entries {
        let sk = wasm_store_key(&contract_bytes, &entry.key);
        state
            .execution_state
            .write(NS_WASM_STORE, &sk, Some(&entry.value))
            .map_err(ImportError::StateError)?;
    }
    Ok((code_hash, contract_bytes, req.storage_entries.len(), fee))
}

pub(crate) fn apply_svm_migration(
    state: &mut AccountState,
    migrator: &Address,
    req: SvmMigrationRequest,
    fee_schedule: &MigrationFeeSchedule,
) -> Result<([u8; 32], usize, MigrationFeeQuote), ImportError> {
    if req.budlum_chain_id != req.chain_id {
        return Err(ImportError::ChainMismatch {
            signed: req.budlum_chain_id,
            expected: req.chain_id,
        });
    }
    if req.pubkey == FORBIDDEN_SVM_VOTE_PROGRAM_ID
        || req.pubkey == FORBIDDEN_SVM_STAKE_PROGRAM_ID
        || req.owner == FORBIDDEN_SVM_VOTE_PROGRAM_ID
        || req.owner == FORBIDDEN_SVM_STAKE_PROGRAM_ID
    {
        return Err(ImportError::StateError(String::from(
            "forbidden Solana Vote/Stake program refused",
        )));
    }
    if req.data.len() > MAX_SBPF_PROGRAM_BYTES {
        return Err(ImportError::StateError(String::from(
            "SVM account data exceeds 512 KiB bound",
        )));
    }
    if req.executable
        && req.owner == SVM_BPF_LOADER_ID
        && req.data.get(..4) != Some(&ELF_MAGIC)
    {
        return Err(ImportError::StateError(String::from(
            "executable BPF loader account must carry ELF magic",
        )));
    }
    if req.proof_siblings.len() > MAX_PROOF_DEPTH {
        return Err(ImportError::StateError(String::from(
            "SVM proof depth exceeds bound",
        )));
    }
    if req.authority_pubkey != req.pubkey && req.authority_pubkey != req.owner {
        return Err(ImportError::StateError(String::from(
            "SVM migration authority must match account pubkey or owner",
        )));
    }
    let sig64: [u8; 64] = req
        .authority_signature64
        .as_slice()
        .try_into()
        .map_err(|_| ImportError::StateError(String::from("SVM authority signature != 64 bytes")))?;
    let digest = svm_migration_digest(
        req.budlum_chain_id,
        req.source_domain_id,
        req.source_slot,
        &req.pubkey,
        &req.accounts_root,
    );
    verify_solana_ed25519_migration_sig(&digest, &req.authority_pubkey, &sig64)
        .map_err(ImportError::StateError)?;

    let leaf = svm_account_leaf(
        req.source_slot,
        &req.pubkey,
        req.proven_lamports,
        &req.owner,
        req.executable,
        req.rent_epoch,
        &req.data,
    );
    let computed_root = fold_sha256_merkle(leaf, req.proof_index, &req.proof_siblings);
    if computed_root != req.accounts_root {
        return Err(ImportError::StorageRootMismatch {
            expected: req.accounts_root,
            computed: computed_root,
        });
    }

    check_target_unoccupied(
        state,
        &state.execution_state,
        EeId::SVM,
        &req.pubkey,
        NS_SVM_ACCOUNT,
    )?;

    let data_len = req.data.len();
    let nodes = 1u64.saturating_add(u64::try_from(req.proof_siblings.len()).map_err(|_| {
        ImportError::StateError(String::from("SVM proof node count overflow"))
    })?);
    let usage = MigrationUsage {
        proof_nodes: nodes,
        code_bytes: u64::try_from(data_len).map_err(|_| super::MigrationFeeOverflow)?,
        storage_slots: 1,
    };
    let fee = quote_migration_fee(usage, fee_schedule)?;
    let acc = SvmAccountData {
        // Native lamports never migrate across chains (`N-5`).
        lamports: 0,
        owner: req.owner,
        executable: req.executable,
        rent_epoch: req.rent_epoch,
        data: req.data,
    };
    let acc_bytes = serde_json::to_vec(&acc).map_err(|e| ImportError::StateError(e.to_string()))?;

    charge_migration_fee(state, migrator, &fee)?;

    state
        .execution_state
        .write(NS_SVM_ACCOUNT, &req.pubkey, Some(&acc_bytes))
        .map_err(ImportError::StateError)?;
    Ok((req.pubkey, data_len, fee))
}

fn is_forbidden_move_entry(account: &[u8; 32], kind: &MoveMigrationEntryKind) -> bool {
    let mut framework = [0u8; 32];
    framework[31] = 1;
    let mod_prefix_is_framework = *account == framework;
    match kind {
        MoveMigrationEntryKind::Module(name) => {
            if !mod_prefix_is_framework {
                return false;
            }
            let full = format!("0x1::{name}");
            FORBIDDEN_MOVE_MODULES.contains(&full.as_str())
        }
        MoveMigrationEntryKind::Resource(tag) => FORBIDDEN_MOVE_MODULES
            .iter()
            .any(|m| tag.starts_with(m)),
    }
}

pub(crate) fn apply_move_migration(
    state: &mut AccountState,
    migrator: &Address,
    req: MoveMigrationRequest,
    fee_schedule: &MigrationFeeSchedule,
) -> Result<([u8; 32], usize, MigrationFeeQuote), ImportError> {
    if req.budlum_chain_id != req.chain_id {
        return Err(ImportError::ChainMismatch {
            signed: req.budlum_chain_id,
            expected: req.chain_id,
        });
    }
    if req.entries.is_empty() || req.entries.len() > MAX_CHUNK_SLOTS {
        return Err(ImportError::ChunkTooLarge {
            slots: req.entries.len(),
            max: MAX_CHUNK_SLOTS,
        });
    }
    if state
        .execution_state
        .has_registered_alias_collision(EeId::MOVE, &req.account)
    {
        return Err(ImportError::AddressOccupied);
    }
    let bud_addr = derive_contract_account(EeId::MOVE, &req.account);
    if state.get_attos_balance(&bud_addr) > 0 {
        return Err(ImportError::AddressOccupied);
    }

    let sig64: [u8; 64] = req
        .signature64
        .as_slice()
        .try_into()
        .map_err(|_| ImportError::StateError(String::from("Aptos signature != 64 bytes")))?;
    let digest = move_migration_digest(
        req.budlum_chain_id,
        req.source_domain_id,
        req.source_version,
        &req.account,
        &req.state_root,
    );
    verify_aptos_migration_sig(&digest, &req.signer_pubkey, &sig64, &req.account)
        .map_err(ImportError::StateError)?;

    let mut writes: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(req.entries.len());
    let mut seen_keys = BTreeSet::new();
    let mut total_nodes = 0u64;
    let mut total_bytes = 0u64;

    for entry in &req.entries {
        if entry.siblings.len() > MAX_PROOF_DEPTH {
            return Err(ImportError::StateError(String::from(
                "Move state proof depth exceeds bound",
            )));
        }
        if is_forbidden_move_entry(&req.account, &entry.kind) {
            return Err(ImportError::StateError(String::from(
                "forbidden Aptos staking/governance module refused",
            )));
        }
        let state_key = match &entry.kind {
            MoveMigrationEntryKind::Module(name) => {
                if name.is_empty()
                    || entry.bytes.len() > MAX_MOVE_BUNDLE_BYTES
                    || entry.bytes.get(..4) != Some(&MOVE_BINARY_MAGIC)
                {
                    return Err(ImportError::StateError(String::from(
                        "invalid Move module bytecode",
                    )));
                }
                state_key_module(&req.account, name)
            }
            MoveMigrationEntryKind::Resource(tag) => {
                if tag.is_empty() || entry.bytes.is_empty() {
                    return Err(ImportError::StateError(String::from(
                        "empty Move resource tag or payload",
                    )));
                }
                state_key_resource(&req.account, tag)
            }
        };
        if !seen_keys.insert(state_key.clone()) {
            return Err(ImportError::StateError(String::from(
                "duplicate Move migration state key",
            )));
        }
        if state
            .execution_state
            .read(NS_MOVE_STATE, &state_key)
            .map_err(ImportError::StateError)?
            .is_some()
        {
            return Err(ImportError::AddressOccupied);
        }
        let leaf = move_state_leaf(&state_key, &entry.bytes);
        let computed = fold_sha3_merkle(leaf, entry.index, &entry.siblings);
        if computed != req.state_root {
            return Err(ImportError::StorageRootMismatch {
                expected: req.state_root,
                computed,
            });
        }
        total_nodes = total_nodes
            .saturating_add(1)
            .saturating_add(u64::try_from(entry.siblings.len()).unwrap_or(u64::MAX));
        total_bytes = total_bytes
            .saturating_add(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX));
        writes.push((state_key, entry.bytes.clone()));
    }

    let usage = MigrationUsage {
        proof_nodes: total_nodes,
        code_bytes: total_bytes,
        storage_slots: u64::try_from(writes.len()).map_err(|_| super::MigrationFeeOverflow)?,
    };
    let fee = quote_migration_fee(usage, fee_schedule)?;
    charge_migration_fee(state, migrator, &fee)?;

    for (k, v) in &writes {
        state
            .execution_state
            .write(NS_MOVE_STATE, k, Some(v))
            .map_err(ImportError::StateError)?;
    }
    Ok((req.account, writes.len(), fee))
}
