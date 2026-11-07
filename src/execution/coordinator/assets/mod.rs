//! Universal Asset Registry (`uel/assets`) and stateless cross-VM asset pointers
//! (`Section 8.8`, `WP-30`, closing `BLG-252`).
//!
//! Invariants (`Y-5`, `Section 8.8`):
//! 1. Every asset lives exclusively in its `home_ee` (`EVM` or `WASM` in Phase 1).
//! 2. `asset_id = SHA3-256(BDLM_UEL_ASSET_V1 || home_ee || len_le64 || home_ref)`.
//! 3. `CreatePointer { asset_id, target_ee }` derives an immutable, deterministic
//!    pointer contract address in `target_ee`.
//! 4. Pointer contracts hold **zero** local balances and **zero** local allowance
//!    tables: every transfer, approval, and balance/allowance query translates into
//!    a synchronous `UniversalCall` to `(home_ee, home_ref)`.
//! Convenience: public Universal Asset Registry and stateless pointer surface (WP-30).

use std::collections::BTreeMap;
use std::fmt;

use budlum_uel_abi::{
    BudAmount, EeId, EeIdentity, HostApi, HostError, HostRead, Namespace, UniversalCall,
    UniversalResult,
};
use serde::{Deserialize, Serialize};

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::accounts::{derive_asset_id, derive_local_alias};
use crate::execution::coordinator::commitment::NS_UEL_ASSETS;
use crate::execution::coordinator::overlay::resolve_ee_identity;

const SEL_ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SEL_ERC20_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SEL_ERC_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const SEL_ERC20_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const SEL_ERC20_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const SEL_ERC20_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
const SEL_ERC721_SAFE_TRANSFER_FROM: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e];
const SEL_ERC721_OWNER_OF: [u8; 4] = [0x63, 0x52, 0x21, 0x1e];
const SEL_ERC721_TOKEN_URI: [u8; 4] = [0xc8, 0x7b, 0x56, 0xdd];

/// Token standard recorded in `uel/assets` (`Section 8.8` item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStandard {
    /// Fungible token (`ERC-20` on EVM, `CW20` on WASM).
    Fungible,
    /// Non-fungible token (`ERC-721` on EVM, `CW721` on WASM).
    NonFungible,
}

/// Canonical Universal Asset Registry entry persisted under `uel/assets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRecord {
    pub asset_id: [u8; 32],
    pub home_ee: u8,
    pub home_ref: Vec<u8>,
    pub standard: AssetStandard,
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
    /// Map from lowercase environment key (`"evm"`, `"wasm"`) to native pointer address.
    pub pointers: BTreeMap<String, Vec<u8>>,
}

/// Permissionless asset registration request (`Section 8.8` item 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAsset {
    pub home_ee: EeId,
    pub home_ref: Vec<u8>,
    pub standard: AssetStandard,
}

/// Permissionless pointer creation request (`Section 8.8` item 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePointer {
    pub asset_id: [u8; 32],
    pub target_ee: EeId,
}

/// Errors returned by UAR registration and pointer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetRegistryError {
    InvalidHomeReference,
    UnsupportedPhaseOneEnvironment(EeId),
    AssetAlreadyRegistered([u8; 32]),
    AssetNotFound([u8; 32]),
    PointerMatchesHomeEnvironment,
    PointerAlreadyExists,
    MetadataProbeFailed(String),
    Codec(String),
}

impl fmt::Display for AssetRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHomeReference => write!(f, "invalid home asset reference"),
            Self::UnsupportedPhaseOneEnvironment(ee) => {
                write!(f, "environment 0x{:02x} pointers arrive in WP-52", ee.0)
            }
            Self::AssetAlreadyRegistered(_) => write!(f, "asset already registered"),
            Self::AssetNotFound(_) => write!(f, "asset not found in uel/assets"),
            Self::PointerMatchesHomeEnvironment => {
                write!(f, "cannot create pointer in asset home environment")
            }
            Self::PointerAlreadyExists => write!(f, "pointer already exists for target EE"),
            Self::MetadataProbeFailed(m) => write!(f, "home metadata read failed: {m}"),
            Self::Codec(m) => write!(f, "asset codec error: {m}"),
        }
    }
}

impl std::error::Error for AssetRegistryError {}

fn ee_map_key(ee: EeId) -> Option<&'static str> {
    match ee {
        EeId::EVM => Some("evm"),
        EeId::WASM => Some("wasm"),
        _ => None,
    }
}

/// Derive the deterministic pointer contract address in `target_ee` for `asset_id`
/// (`Section 8.8` item 5).
///
/// Convenience: shared by `CreatePointer`, RPC pointer discovery, and tests.
pub fn derive_pointer_address(
    asset_id: &[u8; 32],
    target_ee: EeId,
) -> Result<Vec<u8>, AssetRegistryError> {
    if ee_map_key(target_ee).is_none() {
        return Err(AssetRegistryError::UnsupportedPhaseOneEnvironment(target_ee));
    }
    let seed = hash_fields_bytes(&[
        "BDLM_UEL_POINTER_V1".as_bytes(),
        asset_id.as_slice(),
        &[target_ee.0],
    ]);
    derive_local_alias(&Address(seed), target_ee)
        .map_err(|_| AssetRegistryError::InvalidHomeReference)
}

/// Read an `AssetRecord` from `AccountState::uel_state` (`uel/assets`).
///
/// Convenience: queried by RPC gateways and pointer dispatch.
#[must_use]
pub fn read_asset_record(state: &AccountState, asset_id: &[u8; 32]) -> Option<AssetRecord> {
    let raw = state.uel_state.read(NS_UEL_ASSETS, asset_id)?;
    serde_json::from_slice(raw).ok()
}

/// Metadata returned by a read-only probe against `home_ee` during `RegisterAsset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbedAssetMetadata {
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
}

/// Register a home asset into `uel/assets` after probing metadata via a read-only
/// call to `home_ee` (`Section 8.8` item 4).
///
/// Convenience: coordinator entry point for `RegisterAsset`.
pub fn register_asset<F>(
    state: &mut AccountState,
    req: &RegisterAsset,
    mut probe_home_metadata: F,
) -> Result<AssetRecord, AssetRegistryError>
where
    F: FnMut(EeId, &[u8], AssetStandard) -> Result<ProbedAssetMetadata, String>,
{
    if ee_map_key(req.home_ee).is_none() {
        return Err(AssetRegistryError::UnsupportedPhaseOneEnvironment(req.home_ee));
    }
    if req.home_ee == EeId::EVM && req.home_ref.len() != 20 {
        return Err(AssetRegistryError::InvalidHomeReference);
    }
    let asset_id = derive_asset_id(req.home_ee, &req.home_ref)
        .map_err(|_| AssetRegistryError::InvalidHomeReference)?;
    if state.uel_state.read(NS_UEL_ASSETS, &asset_id).is_some() {
        return Err(AssetRegistryError::AssetAlreadyRegistered(asset_id));
    }
    let meta = probe_home_metadata(req.home_ee, &req.home_ref, req.standard)
        .map_err(AssetRegistryError::MetadataProbeFailed)?;
    let record = AssetRecord {
        asset_id,
        home_ee: req.home_ee.0,
        home_ref: req.home_ref.clone(),
        standard: req.standard,
        decimals: if req.standard == AssetStandard::NonFungible {
            0
        } else {
            meta.decimals
        },
        symbol: meta.symbol,
        name: meta.name,
        pointers: BTreeMap::new(),
    };
    let encoded =
        serde_json::to_vec(&record).map_err(|e| AssetRegistryError::Codec(e.to_string()))?;
    state
        .uel_state
        .write(NS_UEL_ASSETS, asset_id.to_vec(), Some(encoded))
        .map_err(|e| AssetRegistryError::Codec(e.to_string()))?;
    Ok(record)
}

/// Create an immutable pointer in `req.target_ee` for an already-registered `asset_id`
/// (`Section 8.8` items 5-9).
///
/// Convenience: coordinator entry point for `CreatePointer`.
pub fn create_pointer(
    state: &mut AccountState,
    req: &CreatePointer,
) -> Result<(AssetRecord, Vec<u8>), AssetRegistryError> {
    let Some(target_key) = ee_map_key(req.target_ee) else {
        return Err(AssetRegistryError::UnsupportedPhaseOneEnvironment(req.target_ee));
    };
    let mut record = read_asset_record(state, &req.asset_id)
        .ok_or(AssetRegistryError::AssetNotFound(req.asset_id))?;
    if record.home_ee == req.target_ee.0 {
        return Err(AssetRegistryError::PointerMatchesHomeEnvironment);
    }
    if record.pointers.contains_key(target_key) {
        return Err(AssetRegistryError::PointerAlreadyExists);
    }
    let ptr_addr = derive_pointer_address(&req.asset_id, req.target_ee)?;
    record.pointers.insert(target_key.to_string(), ptr_addr.clone());
    let encoded =
        serde_json::to_vec(&record).map_err(|e| AssetRegistryError::Codec(e.to_string()))?;
    state
        .uel_state
        .write(NS_UEL_ASSETS, req.asset_id.to_vec(), Some(encoded))
        .map_err(|e| AssetRegistryError::Codec(e.to_string()))?;
    Ok((record, ptr_addr))
}

/// Locate the `AssetRecord` whose pointer in `ee` equals `native_addr` by scanning
/// `uel/assets` through `HostRead`.
pub fn find_pointer_record_in_state(
    state: &AccountState,
    ee: EeId,
    native_addr: &[u8],
) -> Option<AssetRecord> {
    let target_key = ee_map_key(ee)?;
    for (_, val) in state.uel_state.iter_namespace(NS_UEL_ASSETS) {
        if let Ok(rec) = serde_json::from_slice::<AssetRecord>(val) {
            if rec
                .pointers
                .get(target_key)
                .is_some_and(|p| p.as_slice() == native_addr)
            {
                return Some(rec);
            }
        }
    }
    None
}

fn read_abi_address(args: &[u8], word_idx: usize) -> Option<[u8; 20]> {
    let start = word_idx.checked_mul(32)?;
    let word = args.get(start..start + 32)?;
    if word.get(..12)?.iter().any(|&b| b != 0) {
        return None;
    }
    word.get(12..32)?.try_into().ok()
}

fn read_abi_u128(args: &[u8], word_idx: usize) -> Option<u128> {
    let start = word_idx.checked_mul(32)?;
    let word = args.get(start..start + 32)?;
    if word.get(..16)?.iter().any(|&b| b != 0) {
        return None;
    }
    let tail: [u8; 16] = word.get(16..32)?.try_into().ok()?;
    Some(u128::from_be_bytes(tail))
}

fn encode_abi_u128(v: u128) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if let Some(dst) = out.get_mut(16..32) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn encode_abi_bool(b: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if b {
        if let Some(slot) = out.get_mut(31) {
            *slot = 1;
        }
    }
    out
}

fn encode_abi_address(addr20: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if addr20.len() == 20 {
        if let Some(dst) = out.get_mut(12..32) {
            dst.copy_from_slice(addr20);
        }
    }
    out
}

fn encode_abi_string(s: &str) -> Vec<u8> {
    let raw = s.as_bytes();
    let padded = raw.len().div_ceil(32) * 32;
    let mut out = vec![0u8; 64 + padded];
    if let Some(slot) = out.get_mut(31) {
        *slot = 32;
    }
    let len_be = (raw.len() as u64).to_be_bytes();
    if let Some(dst) = out.get_mut(56..64) {
        dst.copy_from_slice(&len_be);
    }
    if let Some(dst) = out.get_mut(64..64 + raw.len()) {
        dst.copy_from_slice(raw);
    }
    out
}

fn evm_addr_to_wasm_alias(state: &AccountState, addr20: &[u8; 20]) -> Result<String, HostError> {
    let id = EeIdentity {
        ee: EeId::EVM,
        id: addr20.to_vec(),
    };
    let bud = resolve_ee_identity(state, &id)?;
    let wasm_bytes =
        derive_local_alias(&bud, EeId::WASM).map_err(|e| HostError::Invalid(e.to_string()))?;
    String::from_utf8(wasm_bytes).map_err(|e| HostError::Invalid(e.to_string()))
}

fn wasm_addr_to_evm_alias(state: &AccountState, bech32: &str) -> Result<[u8; 20], HostError> {
    let id = EeIdentity {
        ee: EeId::WASM,
        id: bech32.as_bytes().to_vec(),
    };
    let bud = resolve_ee_identity(state, &id)?;
    let evm_bytes =
        derive_local_alias(&bud, EeId::EVM).map_err(|e| HostError::Invalid(e.to_string()))?;
    evm_bytes
        .as_slice()
        .try_into()
        .map_err(|_| HostError::Invalid("EVM alias must be 20 bytes".into()))
}

/// Execute a call targeting a stateless UAR pointer contract by translating the
/// call into a synchronous `UniversalCall` to `(record.home_ee, record.home_ref)`
/// (`Section 8.8` items 6-8).
pub fn execute_pointer_call(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    pointer_ee: EeId,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let _ = Namespace::new(NS_UEL_ASSETS);
    let _ = HostRead::bud_balance(host, caller);
    match (EeId(record.home_ee), pointer_ee, record.standard) {
        (EeId::WASM, EeId::EVM, AssetStandard::Fungible) => {
            exec_evm_erc20_pointer_to_cw20(state, record, caller, input, gas_limit, host)
        }
        (EeId::WASM, EeId::EVM, AssetStandard::NonFungible) => {
            exec_evm_erc721_pointer_to_cw721(state, record, caller, input, gas_limit, host)
        }
        (EeId::EVM, EeId::WASM, AssetStandard::Fungible) => {
            exec_wasm_cw20_pointer_to_erc20(state, record, caller, input, gas_limit, host)
        }
        (EeId::EVM, EeId::WASM, AssetStandard::NonFungible) => {
            exec_wasm_cw721_pointer_to_erc721(state, record, caller, input, gas_limit, host)
        }
        _ => Err(HostError::Denied("unsupported pointer pair".into())),
    }
}

fn exec_evm_erc20_pointer_to_cw20(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let Some((sel_slice, args)) = input.split_at_checked(4) else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };
    let sel: [u8; 4] = sel_slice
        .try_into()
        .map_err(|_| HostError::Invalid("bad selector".into()))?;
    let (cw_json, is_static, mode) = if sel == SEL_ERC20_TRANSFER {
        let Some(to20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad ERC-20 transfer to".into()));
        };
        let Some(amt) = read_abi_u128(args, 1) else {
            return Err(HostError::Invalid("bad ERC-20 transfer amount".into()));
        };
        let rcpt = evm_addr_to_wasm_alias(state, &to20)?;
        (
            serde_json::json!({ "transfer": { "recipient": rcpt, "amount": amt.to_string() } }),
            false,
            0u8,
        )
    } else if sel == SEL_ERC20_TRANSFER_FROM {
        let Some(from20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad transferFrom owner".into()));
        };
        let Some(to20) = read_abi_address(args, 1) else {
            return Err(HostError::Invalid("bad transferFrom recipient".into()));
        };
        let Some(amt) = read_abi_u128(args, 2) else {
            return Err(HostError::Invalid("bad transferFrom amount".into()));
        };
        let owner = evm_addr_to_wasm_alias(state, &from20)?;
        let rcpt = evm_addr_to_wasm_alias(state, &to20)?;
        (
            serde_json::json!({
                "transfer_from": { "owner": owner, "recipient": rcpt, "amount": amt.to_string() }
            }),
            false,
            0u8,
        )
    } else if sel == SEL_ERC_APPROVE {
        let Some(sp20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad approve spender".into()));
        };
        let Some(amt) = read_abi_u128(args, 1) else {
            return Err(HostError::Invalid("bad approve amount".into()));
        };
        let spender = evm_addr_to_wasm_alias(state, &sp20)?;
        (
            serde_json::json!({
                "increase_allowance": { "spender": spender, "amount": amt.to_string() }
            }),
            false,
            0u8,
        )
    } else if sel == SEL_ERC20_BALANCE_OF {
        let Some(own20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad balanceOf owner".into()));
        };
        let owner = evm_addr_to_wasm_alias(state, &own20)?;
        (
            serde_json::json!({ "balance": { "address": owner } }),
            true,
            1u8,
        )
    } else if sel == SEL_ERC20_ALLOWANCE {
        let Some(own20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad allowance owner".into()));
        };
        let Some(sp20) = read_abi_address(args, 1) else {
            return Err(HostError::Invalid("bad allowance spender".into()));
        };
        let owner = evm_addr_to_wasm_alias(state, &own20)?;
        let spender = evm_addr_to_wasm_alias(state, &sp20)?;
        (
            serde_json::json!({ "allowance": { "owner": owner, "spender": spender } }),
            true,
            2u8,
        )
    } else if sel == SEL_ERC20_DECIMALS {
        (serde_json::json!({ "token_info": {} }), true, 3u8)
    } else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };

    let res = host.universal_call(UniversalCall {
        from: caller.clone(),
        to_ee: EeId::WASM,
        target: EeIdentity {
            ee: EeId::WASM,
            id: record.home_ref.clone(),
        },
        value: BudAmount(0),
        input: serde_json::to_vec(&cw_json).unwrap_or_default(),
        gas_limit,
        is_static,
    })?;
    if !res.success {
        return Ok(res);
    }
    let output = match mode {
        0 => encode_abi_bool(true),
        1 => {
            let v: serde_json::Value =
                serde_json::from_slice(&res.output).unwrap_or_else(|_| serde_json::json!({}));
            let b = v
                .get("balance")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            encode_abi_u128(b)
        }
        2 => {
            let v: serde_json::Value =
                serde_json::from_slice(&res.output).unwrap_or_else(|_| serde_json::json!({}));
            let a = v
                .get("allowance")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            encode_abi_u128(a)
        }
        _ => {
            let v: serde_json::Value =
                serde_json::from_slice(&res.output).unwrap_or_else(|_| serde_json::json!({}));
            let dec = v
                .get("decimals")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::from(record.decimals));
            encode_abi_u128(u128::from(dec))
        }
    };
    Ok(UniversalResult {
        success: true,
        output,
        gas_used: res.gas_used,
    })
}

fn exec_evm_erc721_pointer_to_cw721(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let Some((sel_slice, args)) = input.split_at_checked(4) else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };
    let sel: [u8; 4] = sel_slice
        .try_into()
        .map_err(|_| HostError::Invalid("bad selector".into()))?;
    let (cw_json, is_static, mode) = if sel == SEL_ERC721_SAFE_TRANSFER_FROM {
        let Some(to20) = read_abi_address(args, 1) else {
            return Err(HostError::Invalid("bad safeTransferFrom to".into()));
        };
        let Some(tid) = read_abi_u128(args, 2) else {
            return Err(HostError::Invalid("bad tokenId".into()));
        };
        let rcpt = evm_addr_to_wasm_alias(state, &to20)?;
        (
            serde_json::json!({
                "transfer_nft": { "recipient": rcpt, "token_id": tid.to_string() }
            }),
            false,
            0u8,
        )
    } else if sel == SEL_ERC_APPROVE {
        let Some(sp20) = read_abi_address(args, 0) else {
            return Err(HostError::Invalid("bad approve to".into()));
        };
        let Some(tid) = read_abi_u128(args, 1) else {
            return Err(HostError::Invalid("bad tokenId".into()));
        };
        let spender = evm_addr_to_wasm_alias(state, &sp20)?;
        (
            serde_json::json!({
                "approve": { "spender": spender, "token_id": tid.to_string() }
            }),
            false,
            0u8,
        )
    } else if sel == SEL_ERC721_OWNER_OF {
        let Some(tid) = read_abi_u128(args, 0) else {
            return Err(HostError::Invalid("bad ownerOf tokenId".into()));
        };
        (
            serde_json::json!({ "owner_of": { "token_id": tid.to_string() } }),
            true,
            1u8,
        )
    } else if sel == SEL_ERC721_TOKEN_URI {
        let Some(tid) = read_abi_u128(args, 0) else {
            return Err(HostError::Invalid("bad tokenURI tokenId".into()));
        };
        (
            serde_json::json!({ "nft_info": { "token_id": tid.to_string() } }),
            true,
            2u8,
        )
    } else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };

    let res = host.universal_call(UniversalCall {
        from: caller.clone(),
        to_ee: EeId::WASM,
        target: EeIdentity {
            ee: EeId::WASM,
            id: record.home_ref.clone(),
        },
        value: BudAmount(0),
        input: serde_json::to_vec(&cw_json).unwrap_or_default(),
        gas_limit,
        is_static,
    })?;
    if !res.success {
        return Ok(res);
    }
    let output = match mode {
        0 => Vec::new(),
        1 => {
            let v: serde_json::Value =
                serde_json::from_slice(&res.output).unwrap_or_else(|_| serde_json::json!({}));
            let owner_str = v
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let evm20 = wasm_addr_to_evm_alias(state, owner_str).unwrap_or([0u8; 20]);
            encode_abi_address(&evm20)
        }
        _ => {
            let v: serde_json::Value =
                serde_json::from_slice(&res.output).unwrap_or_else(|_| serde_json::json!({}));
            let uri = v
                .get("token_uri")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            encode_abi_string(uri)
        }
    };
    Ok(UniversalResult {
        success: true,
        output,
        gas_used: res.gas_used,
    })
}

fn pack_selector_addr_u128(sel: [u8; 4], addr20: &[u8; 20], amt: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&sel);
    out.extend_from_slice(&encode_abi_address(addr20));
    out.extend_from_slice(&encode_abi_u128(amt));
    out
}

fn pack_selector_two_addrs_u128(sel: [u8; 4], a: &[u8; 20], b: &[u8; 20], amt: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(100);
    out.extend_from_slice(&sel);
    out.extend_from_slice(&encode_abi_address(a));
    out.extend_from_slice(&encode_abi_address(b));
    out.extend_from_slice(&encode_abi_u128(amt));
    out
}

fn exec_wasm_cw20_pointer_to_erc20(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let v: serde_json::Value =
        serde_json::from_slice(input).map_err(|e| HostError::Invalid(e.to_string()))?;
    let (calldata, is_static, mode) = if let Some(obj) = v.get("transfer") {
        let rcpt = obj
            .get("recipient")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing recipient".into()))?;
        let amt: u128 = obj
            .get("amount")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing amount".into()))?;
        let to20 = wasm_addr_to_evm_alias(state, rcpt)?;
        (pack_selector_addr_u128(SEL_ERC20_TRANSFER, &to20, amt), false, 0u8)
    } else if let Some(obj) = v.get("transfer_from") {
        let own = obj
            .get("owner")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing owner".into()))?;
        let rcpt = obj
            .get("recipient")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing recipient".into()))?;
        let amt: u128 = obj
            .get("amount")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing amount".into()))?;
        let own20 = wasm_addr_to_evm_alias(state, own)?;
        let to20 = wasm_addr_to_evm_alias(state, rcpt)?;
        (
            pack_selector_two_addrs_u128(SEL_ERC20_TRANSFER_FROM, &own20, &to20, amt),
            false,
            0u8,
        )
    } else if let Some(obj) = v.get("increase_allowance") {
        let sp = obj
            .get("spender")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing spender".into()))?;
        let amt: u128 = obj
            .get("amount")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing amount".into()))?;
        let sp20 = wasm_addr_to_evm_alias(state, sp)?;
        (pack_selector_addr_u128(SEL_ERC_APPROVE, &sp20, amt), false, 0u8)
    } else if let Some(obj) = v.get("balance") {
        let own = obj
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing address".into()))?;
        let own20 = wasm_addr_to_evm_alias(state, own)?;
        let mut cd = SEL_ERC20_BALANCE_OF.to_vec();
        cd.extend_from_slice(&encode_abi_address(&own20));
        (cd, true, 1u8)
    } else if let Some(obj) = v.get("allowance") {
        let own = obj
            .get("owner")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing owner".into()))?;
        let sp = obj
            .get("spender")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing spender".into()))?;
        let own20 = wasm_addr_to_evm_alias(state, own)?;
        let sp20 = wasm_addr_to_evm_alias(state, sp)?;
        let mut cd = SEL_ERC20_ALLOWANCE.to_vec();
        cd.extend_from_slice(&encode_abi_address(&own20));
        cd.extend_from_slice(&encode_abi_address(&sp20));
        (cd, true, 2u8)
    } else if v.get("token_info").is_some() {
        (SEL_ERC20_DECIMALS.to_vec(), true, 3u8)
    } else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };

    let res = host.universal_call(UniversalCall {
        from: caller.clone(),
        to_ee: EeId::EVM,
        target: EeIdentity {
            ee: EeId::EVM,
            id: record.home_ref.clone(),
        },
        value: BudAmount(0),
        input: calldata,
        gas_limit,
        is_static,
    })?;
    if !res.success {
        return Ok(res);
    }
    let output = match mode {
        0 => br#"{"ok":true}"#.to_vec(),
        1 => {
            let bal = read_abi_u128(&res.output, 0).unwrap_or(0);
            serde_json::to_vec(&serde_json::json!({ "balance": bal.to_string() }))
                .unwrap_or_default()
        }
        2 => {
            let alw = read_abi_u128(&res.output, 0).unwrap_or(0);
            serde_json::to_vec(&serde_json::json!({
                "allowance": alw.to_string(),
                "expires": { "never": {} }
            }))
            .unwrap_or_default()
        }
        _ => {
            let dec = read_abi_u128(&res.output, 0).unwrap_or(u128::from(record.decimals));
            serde_json::to_vec(&serde_json::json!({
                "name": record.name,
                "symbol": record.symbol,
                "decimals": dec as u8,
            }))
            .unwrap_or_default()
        }
    };
    Ok(UniversalResult {
        success: true,
        output,
        gas_used: res.gas_used,
    })
}

fn exec_wasm_cw721_pointer_to_erc721(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let v: serde_json::Value =
        serde_json::from_slice(input).map_err(|e| HostError::Invalid(e.to_string()))?;
    let caller_bud = resolve_ee_identity(state, caller)?;
    let caller_evm: [u8; 20] = derive_local_alias(&caller_bud, EeId::EVM)
        .map_err(|e| HostError::Invalid(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| HostError::Invalid("bad caller EVM alias".into()))?;
    let (calldata, is_static, mode) = if let Some(obj) = v.get("transfer_nft") {
        let rcpt = obj
            .get("recipient")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing recipient".into()))?;
        let tid: u128 = obj
            .get("token_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing token_id".into()))?;
        let to20 = wasm_addr_to_evm_alias(state, rcpt)?;
        (
            pack_selector_two_addrs_u128(SEL_ERC721_SAFE_TRANSFER_FROM, &caller_evm, &to20, tid),
            false,
            0u8,
        )
    } else if let Some(obj) = v.get("approve") {
        let sp = obj
            .get("spender")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| HostError::Invalid("missing spender".into()))?;
        let tid: u128 = obj
            .get("token_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing token_id".into()))?;
        let sp20 = wasm_addr_to_evm_alias(state, sp)?;
        (pack_selector_addr_u128(SEL_ERC_APPROVE, &sp20, tid), false, 0u8)
    } else if let Some(obj) = v.get("owner_of") {
        let tid: u128 = obj
            .get("token_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing token_id".into()))?;
        let mut cd = SEL_ERC721_OWNER_OF.to_vec();
        cd.extend_from_slice(&encode_abi_u128(tid));
        (cd, true, 1u8)
    } else if let Some(obj) = v.get("nft_info") {
        let tid: u128 = obj
            .get("token_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| HostError::Invalid("missing token_id".into()))?;
        let mut cd = SEL_ERC721_TOKEN_URI.to_vec();
        cd.extend_from_slice(&encode_abi_u128(tid));
        (cd, true, 2u8)
    } else {
        return Ok(UniversalResult {
            success: false,
            output: Vec::new(),
            gas_used: 0,
        });
    };

    let res = host.universal_call(UniversalCall {
        from: caller.clone(),
        to_ee: EeId::EVM,
        target: EeIdentity {
            ee: EeId::EVM,
            id: record.home_ref.clone(),
        },
        value: BudAmount(0),
        input: calldata,
        gas_limit,
        is_static,
    })?;
    if !res.success {
        return Ok(res);
    }
    let output = match mode {
        0 => br#"{"ok":true}"#.to_vec(),
        1 => {
            let own20 = read_abi_address(&res.output, 0).unwrap_or([0u8; 20]);
            let own_wasm = evm_addr_to_wasm_alias(state, &own20).unwrap_or_default();
            serde_json::to_vec(&serde_json::json!({ "owner": own_wasm, "approvals": [] }))
                .unwrap_or_default()
        }
        _ => serde_json::to_vec(&serde_json::json!({ "token_uri": "" })).unwrap_or_default(),
    };
    Ok(UniversalResult {
        success: true,
        output,
        gas_used: res.gas_used,
    })
}
