//! Universal Asset Registry (`uel/assets`) and zero-balance cross-EE pointers.
//!
//! Implements section 8.8 and WP-30 items 5-6:
//! - Every asset lives exclusively in its home environment (`Y-5`).
//! - `asset_id = SHA3-256("BDLM_UEL_ASSET_V1" || home_ee || len_le64 || home_ref)`.
//! - Permissionless `RegisterAsset` reads metadata from the home EE.
//! - `CreatePointer` deploys an immutable deterministic pointer contract in the
//!   target EE (`EVM <-> WASM` at launch: `CW20 -> ERC20`, `CW721 -> ERC721`,
//!   `ERC20 -> CW20`, `ERC721 -> CW721`).
//! - Pointer contracts hold zero balance storage and zero local allowance ledger:
//!   every balance and approval operation executes at home via `UniversalCall`.

use crate::core::account::AccountState;
use crate::execution::coordinator::alias::bech32_contract_addr;
use crate::execution::coordinator::state::{
    derive_uel_asset_id, NS_EVM_ACCOUNT, NS_EVM_CODE, NS_UEL_ASSETS, NS_WASM_CODE,
    NS_WASM_CONTRACT,
};
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256, Sha3_256};
use std::collections::BTreeMap;

/// Bytecode magic identifying an immutable UEL pointer contract in EVM or WASM.
pub const POINTER_BYTECODE_PREFIX: &[u8] = b"BDLM_UEL_PTR_BYTECODE_V1";

/// Token standard classification in `uel/assets` (section 8.8 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStandard {
    /// Fungible token (`ERC-20` on EVM, `CW20` on WASM).
    Fungible,
    /// Non-fungible token (`ERC-721` on EVM, `CW721` on WASM).
    NonFungible,
}

/// Canonical asset record committed under `uel/assets` keyed by `asset_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredAsset {
    pub asset_id: [u8; 32],
    pub home_ee: u8,
    pub home_ref: Vec<u8>,
    pub standard: AssetStandard,
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
    /// `target_ee -> local pointer address bytes` (20-byte EVM address or UTF-8 `bud1...`).
    pub pointers: BTreeMap<u8, Vec<u8>>,
}

/// Descriptor embedded in the immutable code of a deployed pointer contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerDescriptor {
    pub asset_id: [u8; 32],
    pub home_ee: u8,
    pub home_ref: Vec<u8>,
    pub standard: AssetStandard,
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
}

/// Encodes `PointerDescriptor` as deterministic immutable pointer bytecode.
pub fn encode_pointer_bytecode(desc: &PointerDescriptor) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(desc).map_err(|e| format!("pointer descriptor encode: {e}"))?;
    let mut out = Vec::with_capacity(POINTER_BYTECODE_PREFIX.len() + json.len());
    out.extend_from_slice(POINTER_BYTECODE_PREFIX);
    out.extend_from_slice(&json);
    Ok(out)
}

/// Decodes a `PointerDescriptor` if `code` carries [`POINTER_BYTECODE_PREFIX`].
#[must_use]
pub fn decode_pointer_bytecode(code: &[u8]) -> Option<PointerDescriptor> {
    let rest = code.strip_prefix(POINTER_BYTECODE_PREFIX)?;
    serde_json::from_slice(rest).ok()
}

/// Derives the deterministic pointer address for `(asset_id, target_ee)` (8.8 item 5).
///
/// - `EeId::EVM`: 20-byte address `keccak256("BDLM_UEL_POINTER_V1" || asset_id || 0x01)[12..32]`.
/// - `EeId::WASM`: bech32 `bud1...` over `SHA3-256("BDLM_UEL_POINTER_V1" || asset_id || 0x02)`.
pub fn derive_pointer_address(asset_id: &[u8; 32], target_ee: EeId) -> Result<Vec<u8>, String> {
    match target_ee {
        EeId::EVM => {
            let mut h = Keccak256::new();
            h.update(b"BDLM_UEL_POINTER_V1");
            h.update(asset_id);
            h.update([EeId::EVM.0]);
            let digest: [u8; 32] = h.finalize().into();
            let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = digest;
            Ok(tail.to_vec())
        }
        EeId::WASM => {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_UEL_POINTER_V1");
            h.update(asset_id);
            h.update([EeId::WASM.0]);
            let digest: [u8; 32] = h.finalize().into();
            Ok(bech32_contract_addr(&digest).into_bytes())
        }
        other => Err(format!(
            "pointers for EE 0x{:02x} are deferred to T-Expansion (WP-52)",
            other.0
        )),
    }
}

/// Reads a [`RegisteredAsset`] from `uel/assets` if present.
pub fn read_registered_asset(
    state: &AccountState,
    asset_id: &[u8; 32],
) -> Result<Option<RegisteredAsset>, String> {
    let Some(bytes) = state.execution_state.read(NS_UEL_ASSETS, asset_id)? else {
        return Ok(None);
    };
    let parsed: RegisteredAsset =
        serde_json::from_slice(&bytes).map_err(|e| format!("corrupt uel/assets entry: {e}"))?;
    Ok(Some(parsed))
}

/// Permissionless `RegisterAsset { home_ee, home_ref }` registration into `uel/assets`.
pub fn register_asset_entry(
    state: &mut AccountState,
    home_ee: EeId,
    home_ref: &[u8],
    standard: AssetStandard,
    decimals: u8,
    symbol: String,
    name: String,
) -> Result<RegisteredAsset, String> {
    if !matches!(home_ee, EeId::EVM | EeId::WASM) {
        return Err(format!(
            "launch asset registration supports EVM and WASM homes; got 0x{:02x}",
            home_ee.0
        ));
    }
    let asset_id = derive_uel_asset_id(home_ee, home_ref);
    if read_registered_asset(state, &asset_id)?.is_some() {
        return Err(String::from("asset is already registered in uel/assets"));
    }
    let entry = RegisteredAsset {
        asset_id,
        home_ee: home_ee.0,
        home_ref: home_ref.to_vec(),
        standard,
        decimals,
        symbol,
        name,
        pointers: BTreeMap::new(),
    };
    let encoded = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
    state
        .execution_state
        .write(NS_UEL_ASSETS, &asset_id, Some(&encoded))?;
    Ok(entry)
}

/// Deploys an immutable zero-balance pointer contract for `asset_id` in `target_ee`.
pub fn deploy_asset_pointer(
    state: &mut AccountState,
    asset_id: &[u8; 32],
    target_ee: EeId,
) -> Result<Vec<u8>, String> {
    let mut asset = read_registered_asset(state, asset_id)?
        .ok_or_else(|| String::from("asset_id not found in uel/assets"))?;
    if asset.home_ee == target_ee.0 {
        return Err(String::from(
            "cannot create a pointer in the asset's own home environment",
        ));
    }
    if asset.pointers.contains_key(&target_ee.0) {
        return Err(String::from("pointer already exists for target_ee"));
    }
    let ptr_addr = derive_pointer_address(asset_id, target_ee)?;
    let desc = PointerDescriptor {
        asset_id: *asset_id,
        home_ee: asset.home_ee,
        home_ref: asset.home_ref.clone(),
        standard: asset.standard,
        decimals: asset.decimals,
        symbol: asset.symbol.clone(),
        name: asset.name.clone(),
    };
    let code = encode_pointer_bytecode(&desc)?;

    match target_ee {
        EeId::EVM => {
            let addr20: [u8; 20] = ptr_addr
                .as_slice()
                .try_into()
                .map_err(|_| String::from("EVM pointer address != 20 bytes"))?;
            state.execution_state.check_evm_alias_collision(&addr20)?;
            let code_hash: [u8; 32] = Keccak256::digest(&code).into();
            state
                .execution_state
                .write(NS_EVM_CODE, &code_hash, Some(&code))?;
            let acct_meta = serde_json::json!({
                "nonce": 1u64,
                "code_hash": hex::encode(code_hash),
                "immutable_pointer": true,
            });
            let meta_bytes = serde_json::to_vec(&acct_meta).map_err(|e| e.to_string())?;
            state
                .execution_state
                .write(NS_EVM_ACCOUNT, &addr20, Some(&meta_bytes))?;
        }
        EeId::WASM => {
            let code_hash: [u8; 32] = Sha3_256::digest(&code).into();
            state
                .execution_state
                .write(NS_WASM_CODE, &code_hash, Some(&code))?;
            let contract_meta = serde_json::json!({
                "code_hash": hex::encode(code_hash),
                "creator": "uel/assets",
                "admin": serde_json::Value::Null,
                "label": format!("uel-pointer-{}", hex::encode(asset_id)),
                "immutable_pointer": true,
            });
            let meta_bytes = serde_json::to_vec(&contract_meta).map_err(|e| e.to_string())?;
            state
                .execution_state
                .write(NS_WASM_CONTRACT, &ptr_addr, Some(&meta_bytes))?;
        }
        other => {
            return Err(format!(
                "unsupported launch pointer target EE 0x{:02x}",
                other.0
            ));
        }
    }

    asset.pointers.insert(target_ee.0, ptr_addr.clone());
    let updated = serde_json::to_vec(&asset).map_err(|e| e.to_string())?;
    state
        .execution_state
        .write(NS_UEL_ASSETS, asset_id, Some(&updated))?;
    Ok(ptr_addr)
}
