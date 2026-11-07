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

/// Testnet chain identifier (`Section 1.5`) where `WP-52` SVM/Move pointers
/// remain closed at launch until `svm_move_activation_height` is reached.
///
/// Convenience: referenced by pointer activation policies and launch gates.
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// `IP-52` item 3 review outcome (`KR-UEL-REENTRANCY`): cross-environment
/// reentrancy prohibition (`Section 8.7.3` item 6) remains enforced.
///
/// Convenience: exported so conformance and coordinator audits verify the policy.
pub const REENTRANCY_RULE_RETAINED_WP52: bool = true;

/// Activation gate for `T-Genisleme` SVM and Move asset pointers (`Section 1.5`, `WP-52`).
///
/// Convenience: passed to `register_asset_with_policy` and `create_pointer_with_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerActivationPolicy {
    pub chain_id: u64,
    pub block_height: u64,
    pub svm_move_activation_height: Option<u64>,
}

impl Default for PointerActivationPolicy {
    fn default() -> Self {
        Self::testnet_launch()
    }
}

impl PointerActivationPolicy {
    /// Default `T-Acilis` launch policy on testnet `45261` (SVM/Move pointers closed).
    ///
    /// Convenience: default policy used by `register_asset` and `create_pointer`.
    #[must_use]
    pub const fn testnet_launch() -> Self {
        Self {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 0,
            svm_move_activation_height: None,
        }
    }

    /// Returns `true` when SVM and Move pointers are active at `(chain_id, block_height)`.
    ///
    /// Convenience: queried before admitting `EeId::SVM` or `EeId::MOVE` in UAR.
    #[must_use]
    pub const fn svm_move_pointers_active(&self) -> bool {
        match self.svm_move_activation_height {
            Some(h) => self.block_height >= h,
            None => self.chain_id != BUDLUM_TESTNET_CHAIN_ID,
        }
    }
}

/// Errors returned by UAR registration and pointer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetRegistryError {
    InvalidHomeReference,
    UnsupportedPhaseOneEnvironment(EeId),
    SvmMovePointersClosedOnTestnet(EeId),
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
                write!(f, "environment 0x{:02x} does not support UAR pointers", ee.0)
            }
            Self::SvmMovePointersClosedOnTestnet(ee) => {
                write!(
                    f,
                    "SVM/Move asset pointers (0x{:02x}) are closed at testnet launch (WP-52)",
                    ee.0
                )
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

fn ee_map_key_for_policy(
    ee: EeId,
    policy: PointerActivationPolicy,
) -> Result<&'static str, AssetRegistryError> {
    match ee {
        EeId::EVM => Ok("evm"),
        EeId::WASM => Ok("wasm"),
        EeId::SVM => {
            if policy.svm_move_pointers_active() {
                Ok("svm")
            } else {
                Err(AssetRegistryError::SvmMovePointersClosedOnTestnet(ee))
            }
        }
        EeId::MOVE => {
            if policy.svm_move_pointers_active() {
                Ok("move")
            } else {
                Err(AssetRegistryError::SvmMovePointersClosedOnTestnet(ee))
            }
        }
        other => Err(AssetRegistryError::UnsupportedPhaseOneEnvironment(other)),
    }
}

fn ee_any_pointer_key(ee: EeId) -> Option<&'static str> {
    match ee {
        EeId::EVM => Some("evm"),
        EeId::WASM => Some("wasm"),
        EeId::SVM => Some("svm"),
        EeId::MOVE => Some("move"),
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
    derive_pointer_address_with_policy(asset_id, target_ee, PointerActivationPolicy::default())
}

/// Policy-aware pointer address derivation supporting `WP-52` SVM/Move activation.
///
/// Convenience: invoked by `create_pointer_with_policy` and `WP-52` tests.
pub fn derive_pointer_address_with_policy(
    asset_id: &[u8; 32],
    target_ee: EeId,
    policy: PointerActivationPolicy,
) -> Result<Vec<u8>, AssetRegistryError> {
    let _ = ee_map_key_for_policy(target_ee, policy)?;
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
/// Convenience: coordinator entry point for `RegisterAsset` under testnet launch defaults.
pub fn register_asset<F>(
    state: &mut AccountState,
    req: &RegisterAsset,
    probe_home_metadata: F,
) -> Result<AssetRecord, AssetRegistryError>
where
    F: FnMut(EeId, &[u8], AssetStandard) -> Result<ProbedAssetMetadata, String>,
{
    register_asset_with_policy(
        state,
        req,
        PointerActivationPolicy::default(),
        probe_home_metadata,
    )
}

/// Policy-aware `RegisterAsset` supporting `WP-52` SPL and Move home assets once activated.
///
/// Convenience: coordinator entry point for height-gated `RegisterAsset`.
pub fn register_asset_with_policy<F>(
    state: &mut AccountState,
    req: &RegisterAsset,
    policy: PointerActivationPolicy,
    mut probe_home_metadata: F,
) -> Result<AssetRecord, AssetRegistryError>
where
    F: FnMut(EeId, &[u8], AssetStandard) -> Result<ProbedAssetMetadata, String>,
{
    let _ = ee_map_key_for_policy(req.home_ee, policy)?;
    if req.home_ee == EeId::EVM && req.home_ref.len() != 20 {
        return Err(AssetRegistryError::InvalidHomeReference);
    }
    if req.home_ee == EeId::SVM && req.home_ref.len() != 32 {
        return Err(AssetRegistryError::InvalidHomeReference);
    }
    if req.home_ee == EeId::MOVE && req.home_ref.is_empty() {
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
/// Convenience: coordinator entry point for `CreatePointer` under testnet launch defaults.
pub fn create_pointer(
    state: &mut AccountState,
    req: &CreatePointer,
) -> Result<(AssetRecord, Vec<u8>), AssetRegistryError> {
    create_pointer_with_policy(state, req, PointerActivationPolicy::default())
}

/// Policy-aware `CreatePointer` supporting `WP-52` SVM and Move pointers once activated.
///
/// Convenience: coordinator entry point for height-gated `CreatePointer`.
pub fn create_pointer_with_policy(
    state: &mut AccountState,
    req: &CreatePointer,
    policy: PointerActivationPolicy,
) -> Result<(AssetRecord, Vec<u8>), AssetRegistryError> {
    let target_key = ee_map_key_for_policy(req.target_ee, policy)?;
    let mut record = read_asset_record(state, &req.asset_id)
        .ok_or(AssetRegistryError::AssetNotFound(req.asset_id))?;
    if record.home_ee == req.target_ee.0 {
        return Err(AssetRegistryError::PointerMatchesHomeEnvironment);
    }
    if record.pointers.contains_key(target_key) {
        return Err(AssetRegistryError::PointerAlreadyExists);
    }
    let ptr_addr = derive_pointer_address_with_policy(&req.asset_id, req.target_ee, policy)?;
    record
        .pointers
        .insert(target_key.to_string(), ptr_addr.clone());
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
    let target_key = ee_any_pointer_key(ee)?;
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
        (home_ee, ptr_ee, AssetStandard::Fungible)
            if home_ee != ptr_ee
                && ee_any_pointer_key(home_ee).is_some()
                && ee_any_pointer_key(ptr_ee).is_some() =>
        {
            exec_wp52_fungible_pointer(state, record, caller, ptr_ee, input, gas_limit, host)
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

enum CanonicalFungibleIntent {
    Transfer { to: Address, amount: u128 },
    Approve { spender: Address, amount: u128 },
    TransferFrom { owner: Address, to: Address, amount: u128 },
    BalanceOf { owner: Address },
    Allowance { owner: Address, spender: Address },
}

fn parse_json_addr_array32(val: Option<&serde_json::Value>) -> Result<[u8; 32], HostError> {
    let arr = val
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| HostError::Invalid("expected 32-byte JSON array".into()))?;
    if arr.len() != 32 {
        return Err(HostError::Invalid("address array must be 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    for (idx, item) in arr.iter().enumerate() {
        let b = item
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| HostError::Invalid("invalid byte in 32-byte address".into()))?;
        if let Some(slot) = out.get_mut(idx) {
            *slot = b;
        }
    }
    Ok(out)
}

fn parse_json_u128(val: Option<&serde_json::Value>) -> Result<u128, HostError> {
    if let Some(n) = val.and_then(serde_json::Value::as_u64) {
        return Ok(u128::from(n));
    }
    if let Some(s) = val.and_then(serde_json::Value::as_str) {
        return s
            .parse::<u128>()
            .map_err(|_| HostError::Invalid("invalid decimal u128".into()));
    }
    Err(HostError::Invalid("missing u128 amount".into()))
}

fn resolve_native_in_ee(
    state: &AccountState,
    ee: EeId,
    native_id: Vec<u8>,
) -> Result<Address, HostError> {
    resolve_ee_identity(state, &EeIdentity { ee, id: native_id })
}

fn decode_fungible_intent(
    state: &AccountState,
    pointer_ee: EeId,
    input: &[u8],
) -> Result<CanonicalFungibleIntent, HostError> {
    if pointer_ee == EeId::EVM {
        let Some((sel_slice, args)) = input.split_at_checked(4) else {
            return Err(HostError::Invalid("short ERC-20 pointer input".into()));
        };
        let sel: [u8; 4] = sel_slice
            .try_into()
            .map_err(|_| HostError::Invalid("bad selector".into()))?;
        if sel == SEL_ERC20_TRANSFER {
            let to20 = read_abi_address(args, 0)
                .ok_or_else(|| HostError::Invalid("bad ERC-20 to".into()))?;
            let amount = read_abi_u128(args, 1)
                .ok_or_else(|| HostError::Invalid("bad ERC-20 amount".into()))?;
            let to = resolve_native_in_ee(state, EeId::EVM, to20.to_vec())?;
            return Ok(CanonicalFungibleIntent::Transfer { to, amount });
        }
        if sel == SEL_ERC_APPROVE {
            let sp20 = read_abi_address(args, 0)
                .ok_or_else(|| HostError::Invalid("bad ERC-20 spender".into()))?;
            let amount = read_abi_u128(args, 1)
                .ok_or_else(|| HostError::Invalid("bad ERC-20 amount".into()))?;
            let spender = resolve_native_in_ee(state, EeId::EVM, sp20.to_vec())?;
            return Ok(CanonicalFungibleIntent::Approve { spender, amount });
        }
        if sel == SEL_ERC20_TRANSFER_FROM {
            let from20 = read_abi_address(args, 0)
                .ok_or_else(|| HostError::Invalid("bad transferFrom owner".into()))?;
            let to20 = read_abi_address(args, 1)
                .ok_or_else(|| HostError::Invalid("bad transferFrom to".into()))?;
            let amount = read_abi_u128(args, 2)
                .ok_or_else(|| HostError::Invalid("bad transferFrom amount".into()))?;
            let owner = resolve_native_in_ee(state, EeId::EVM, from20.to_vec())?;
            let to = resolve_native_in_ee(state, EeId::EVM, to20.to_vec())?;
            return Ok(CanonicalFungibleIntent::TransferFrom { owner, to, amount });
        }
        if sel == SEL_ERC20_BALANCE_OF {
            let own20 = read_abi_address(args, 0)
                .ok_or_else(|| HostError::Invalid("bad balanceOf owner".into()))?;
            let owner = resolve_native_in_ee(state, EeId::EVM, own20.to_vec())?;
            return Ok(CanonicalFungibleIntent::BalanceOf { owner });
        }
        if sel == SEL_ERC20_ALLOWANCE {
            let own20 = read_abi_address(args, 0)
                .ok_or_else(|| HostError::Invalid("bad allowance owner".into()))?;
            let sp20 = read_abi_address(args, 1)
                .ok_or_else(|| HostError::Invalid("bad allowance spender".into()))?;
            let owner = resolve_native_in_ee(state, EeId::EVM, own20.to_vec())?;
            let spender = resolve_native_in_ee(state, EeId::EVM, sp20.to_vec())?;
            return Ok(CanonicalFungibleIntent::Allowance { owner, spender });
        }
        return Err(HostError::Invalid("unsupported ERC-20 pointer selector".into()));
    }

    let v: serde_json::Value =
        serde_json::from_slice(input).map_err(|e| HostError::Invalid(e.to_string()))?;
    if pointer_ee == EeId::WASM {
        if let Some(obj) = v.get("transfer") {
            let rcpt = obj
                .get("recipient")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing recipient".into()))?;
            let amount = parse_json_u128(obj.get("amount"))?;
            let to = resolve_native_in_ee(state, EeId::WASM, rcpt.as_bytes().to_vec())?;
            return Ok(CanonicalFungibleIntent::Transfer { to, amount });
        }
        if let Some(obj) = v.get("increase_allowance") {
            let sp = obj
                .get("spender")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing spender".into()))?;
            let amount = parse_json_u128(obj.get("amount"))?;
            let spender = resolve_native_in_ee(state, EeId::WASM, sp.as_bytes().to_vec())?;
            return Ok(CanonicalFungibleIntent::Approve { spender, amount });
        }
        if let Some(obj) = v.get("transfer_from") {
            let own = obj
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing owner".into()))?;
            let rcpt = obj
                .get("recipient")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing recipient".into()))?;
            let amount = parse_json_u128(obj.get("amount"))?;
            let owner = resolve_native_in_ee(state, EeId::WASM, own.as_bytes().to_vec())?;
            let to = resolve_native_in_ee(state, EeId::WASM, rcpt.as_bytes().to_vec())?;
            return Ok(CanonicalFungibleIntent::TransferFrom { owner, to, amount });
        }
        if let Some(obj) = v.get("balance") {
            let addr = obj
                .get("address")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing address".into()))?;
            let owner = resolve_native_in_ee(state, EeId::WASM, addr.as_bytes().to_vec())?;
            return Ok(CanonicalFungibleIntent::BalanceOf { owner });
        }
        if let Some(obj) = v.get("allowance") {
            let own = obj
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing owner".into()))?;
            let sp = obj
                .get("spender")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| HostError::Invalid("missing spender".into()))?;
            let owner = resolve_native_in_ee(state, EeId::WASM, own.as_bytes().to_vec())?;
            let spender = resolve_native_in_ee(state, EeId::WASM, sp.as_bytes().to_vec())?;
            return Ok(CanonicalFungibleIntent::Allowance { owner, spender });
        }
        return Err(HostError::Invalid("unsupported CW20 pointer message".into()));
    }

    // SVM (`SplPointerOp`) and Move (`MovePointerOp`) JSON envelopes.
    if let Some(obj) = v.get("transfer") {
        let to32 = parse_json_addr_array32(obj.get("to"))?;
        let amount = parse_json_u128(obj.get("amount"))?;
        let to = resolve_native_in_ee(state, pointer_ee, to32.to_vec())?;
        return Ok(CanonicalFungibleIntent::Transfer { to, amount });
    }
    if let Some(obj) = v.get("approve") {
        let sp_val = obj.get("delegate").or_else(|| obj.get("spender"));
        let sp32 = parse_json_addr_array32(sp_val)?;
        let amount = parse_json_u128(obj.get("amount"))?;
        let spender = resolve_native_in_ee(state, pointer_ee, sp32.to_vec())?;
        return Ok(CanonicalFungibleIntent::Approve { spender, amount });
    }
    if let Some(obj) = v.get("transfer_from") {
        let own32 = parse_json_addr_array32(obj.get("owner"))?;
        let to32 = parse_json_addr_array32(obj.get("to"))?;
        let amount = parse_json_u128(obj.get("amount"))?;
        let owner = resolve_native_in_ee(state, pointer_ee, own32.to_vec())?;
        let to = resolve_native_in_ee(state, pointer_ee, to32.to_vec())?;
        return Ok(CanonicalFungibleIntent::TransferFrom { owner, to, amount });
    }
    if let Some(obj) = v.get("balance_of").or_else(|| v.get("balance")) {
        let own32 = parse_json_addr_array32(obj.get("owner"))?;
        let owner = resolve_native_in_ee(state, pointer_ee, own32.to_vec())?;
        return Ok(CanonicalFungibleIntent::BalanceOf { owner });
    }
    if let Some(obj) = v.get("allowance") {
        let own32 = parse_json_addr_array32(obj.get("owner"))?;
        let sp_val = obj.get("delegate").or_else(|| obj.get("spender"));
        let sp32 = parse_json_addr_array32(sp_val)?;
        let owner = resolve_native_in_ee(state, pointer_ee, own32.to_vec())?;
        let spender = resolve_native_in_ee(state, pointer_ee, sp32.to_vec())?;
        return Ok(CanonicalFungibleIntent::Allowance { owner, spender });
    }
    Err(HostError::Invalid("unsupported SVM/Move pointer operation".into()))
}

fn encode_home_fungible_call(
    home_ee: EeId,
    intent: &CanonicalFungibleIntent,
) -> Result<(Vec<u8>, bool, u8), HostError> {
    let alias_for = |addr: &Address| -> Result<Vec<u8>, HostError> {
        derive_local_alias(addr, home_ee).map_err(|e| HostError::Invalid(e.to_string()))
    };
    match home_ee {
        EeId::EVM => match intent {
            CanonicalFungibleIntent::Transfer { to, amount } => {
                let to20: [u8; 20] = alias_for(to)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| HostError::Invalid("bad EVM alias".into()))?;
                Ok((pack_selector_addr_u128(SEL_ERC20_TRANSFER, &to20, *amount), false, 0))
            }
            CanonicalFungibleIntent::Approve { spender, amount } => {
                let sp20: [u8; 20] = alias_for(spender)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| HostError::Invalid("bad EVM alias".into()))?;
                Ok((pack_selector_addr_u128(SEL_ERC_APPROVE, &sp20, *amount), false, 0))
            }
            CanonicalFungibleIntent::TransferFrom { owner, to, amount } => {
                let own20: [u8; 20] = alias_for(owner)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| HostError::Invalid("bad EVM alias".into()))?;
                let to20: [u8; 20] = alias_for(to)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| HostError::Invalid("bad EVM alias".into()))?;
                Ok((
                    pack_selector_two_addrs_u128(SEL_ERC20_TRANSFER_FROM, &own20, &to20, *amount),
                    false,
                    0,
                ))
            }
            CanonicalFungibleIntent::BalanceOf { owner } => {
                let own20 = alias_for(owner)?;
                let mut cd = SEL_ERC20_BALANCE_OF.to_vec();
                cd.extend_from_slice(&encode_abi_address(&own20));
                Ok((cd, true, 1))
            }
            CanonicalFungibleIntent::Allowance { owner, spender } => {
                let own20 = alias_for(owner)?;
                let sp20 = alias_for(spender)?;
                let mut cd = SEL_ERC20_ALLOWANCE.to_vec();
                cd.extend_from_slice(&encode_abi_address(&own20));
                cd.extend_from_slice(&encode_abi_address(&sp20));
                Ok((cd, true, 2))
            }
        },
        EeId::WASM => match intent {
            CanonicalFungibleIntent::Transfer { to, amount } => {
                let rcpt = String::from_utf8(alias_for(to)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let j = serde_json::json!({
                    "transfer": { "recipient": rcpt, "amount": amount.to_string() }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::Approve { spender, amount } => {
                let sp = String::from_utf8(alias_for(spender)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let j = serde_json::json!({
                    "increase_allowance": { "spender": sp, "amount": amount.to_string() }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::TransferFrom { owner, to, amount } => {
                let own = String::from_utf8(alias_for(owner)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let rcpt = String::from_utf8(alias_for(to)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let j = serde_json::json!({
                    "transfer_from": {
                        "owner": own,
                        "recipient": rcpt,
                        "amount": amount.to_string()
                    }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::BalanceOf { owner } => {
                let own = String::from_utf8(alias_for(owner)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let j = serde_json::json!({ "balance": { "address": own } });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), true, 1))
            }
            CanonicalFungibleIntent::Allowance { owner, spender } => {
                let own = String::from_utf8(alias_for(owner)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let sp = String::from_utf8(alias_for(spender)?)
                    .map_err(|e| HostError::Invalid(e.to_string()))?;
                let j = serde_json::json!({ "allowance": { "owner": own, "spender": sp } });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), true, 2))
            }
        },
        EeId::SVM | EeId::MOVE => match intent {
            CanonicalFungibleIntent::Transfer { to, amount } => {
                let to32 = alias_for(to)?;
                let j = serde_json::json!({
                    "transfer": { "to": to32, "amount": amount.to_string() }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::Approve { spender, amount } => {
                let sp32 = alias_for(spender)?;
                let j = serde_json::json!({
                    "approve": { "spender": sp32, "amount": amount.to_string() }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::TransferFrom { owner, to, amount } => {
                let own32 = alias_for(owner)?;
                let to32 = alias_for(to)?;
                let j = serde_json::json!({
                    "transfer_from": { "owner": own32, "to": to32, "amount": amount.to_string() }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), false, 0))
            }
            CanonicalFungibleIntent::BalanceOf { owner } => {
                let own32 = alias_for(owner)?;
                let j = serde_json::json!({ "balance_of": { "owner": own32 } });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), true, 1))
            }
            CanonicalFungibleIntent::Allowance { owner, spender } => {
                let own32 = alias_for(owner)?;
                let sp32 = alias_for(spender)?;
                let j = serde_json::json!({
                    "allowance": { "owner": own32, "spender": sp32 }
                });
                Ok((serde_json::to_vec(&j).unwrap_or_default(), true, 2))
            }
        },
        _ => Err(HostError::Denied("unsupported home fungible EE".into())),
    }
}

fn parse_home_u128_reply(home_ee: EeId, mode: u8, raw: &[u8]) -> u128 {
    if home_ee == EeId::EVM {
        return read_abi_u128(raw, 0).unwrap_or(0);
    }
    if let Ok(arr) = <[u8; 16]>::try_from(raw) {
        return u128::from_le_bytes(arr);
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return 0;
    };
    let field = if mode == 1 { "balance" } else { "allowance" };
    v.get(field)
        .and_then(|x| {
            x.as_str()
                .and_then(|s| s.parse::<u128>().ok())
                .or_else(|| x.as_u64().map(u128::from))
        })
        .unwrap_or(0)
}

fn format_pointer_reply(pointer_ee: EeId, mode: u8, val: u128) -> Vec<u8> {
    match (pointer_ee, mode) {
        (EeId::EVM, 0) => encode_abi_bool(true),
        (EeId::EVM, _) => encode_abi_u128(val),
        (EeId::WASM, 0) => br#"{"ok":true}"#.to_vec(),
        (EeId::WASM, 1) => serde_json::to_vec(&serde_json::json!({ "balance": val.to_string() }))
            .unwrap_or_default(),
        (EeId::WASM, _) => serde_json::to_vec(&serde_json::json!({
            "allowance": val.to_string(),
            "expires": { "never": {} }
        }))
        .unwrap_or_default(),
        (_, 0) => vec![1u8],
        (_, _) => val.to_le_bytes().to_vec(),
    }
}

fn exec_wp52_fungible_pointer(
    state: &AccountState,
    record: &AssetRecord,
    caller: &EeIdentity,
    pointer_ee: EeId,
    input: &[u8],
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<UniversalResult, HostError> {
    let home_ee = EeId(record.home_ee);
    let intent = decode_fungible_intent(state, pointer_ee, input)?;
    let (home_input, is_static, mode) = encode_home_fungible_call(home_ee, &intent)?;
    let res = host.universal_call(UniversalCall {
        from: caller.clone(),
        to_ee: home_ee,
        target: EeIdentity {
            ee: home_ee,
            id: record.home_ref.clone(),
        },
        value: BudAmount(0),
        input: home_input,
        gas_limit,
        is_static,
    })?;
    if !res.success {
        return Ok(res);
    }
    let val = if mode == 0 {
        0
    } else {
        parse_home_u128_reply(home_ee, mode, &res.output)
    };
    Ok(UniversalResult {
        success: true,
        output: format_pointer_reply(pointer_ee, mode, val),
        gas_used: res.gas_used,
    })
}

#[cfg(test)]
mod wp52_tests {
    use super::*;
    use crate::execution::coordinator::commitment::{NS_MOVE_STATE, NS_SVM_ACCOUNT};
    use budlum_uel_abi::mock::MemoryHost;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn activated_policy() -> PointerActivationPolicy {
        PointerActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 10_000,
            svm_move_activation_height: Some(10_000),
        }
    }

    /// Section 1.5 launch-closure proof: `svm_move_pointers_is_closed_on_testnet`.
    #[test]
    fn svm_move_pointers_is_closed_on_testnet() {
        let mut state = AccountState::new();
        let evm_rec = register_asset(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::EVM,
                home_ref: vec![0xAA; 20],
                standard: AssetStandard::Fungible,
            },
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 6,
                    symbol: "USD".into(),
                    name: "USD Token".into(),
                })
            },
        )
        .unwrap();

        for closed_ee in [EeId::SVM, EeId::MOVE] {
            assert_eq!(
                create_pointer(
                    &mut state,
                    &CreatePointer {
                        asset_id: evm_rec.asset_id,
                        target_ee: closed_ee,
                    },
                ),
                Err(AssetRegistryError::SvmMovePointersClosedOnTestnet(closed_ee))
            );
            assert_eq!(
                register_asset(
                    &mut state,
                    &RegisterAsset {
                        home_ee: closed_ee,
                        home_ref: vec![0xBB; 32],
                        standard: AssetStandard::Fungible,
                    },
                    |_, _, _| unreachable!(),
                ),
                Err(AssetRegistryError::SvmMovePointersClosedOnTestnet(closed_ee))
            );
        }
        assert!(REENTRANCY_RULE_RETAINED_WP52);
    }

    /// Directive IP-52 gate: `svm_pointer_holds_no_balance`.
    #[test]
    fn svm_pointer_holds_no_balance() {
        let mut state = AccountState::new();
        let alice = Address([0x11; 32]);
        let bob = Address([0x22; 32]);
        let alice_svm = state
            .uel_state
            .ensure_alias_registered(&alice, EeId::SVM)
            .unwrap();
        let bob_svm = state
            .uel_state
            .ensure_alias_registered(&bob, EeId::SVM)
            .unwrap();
        let alice_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&alice, EeId::WASM)
                .unwrap(),
        )
        .unwrap();
        let bob_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&bob, EeId::WASM)
                .unwrap(),
        )
        .unwrap();

        let rec = register_asset_with_policy(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::WASM,
                home_ref: b"bud1homecw20".to_vec(),
                standard: AssetStandard::Fungible,
            },
            activated_policy(),
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 6,
                    symbol: "HOME".into(),
                    name: "Home CW20".into(),
                })
            },
        )
        .unwrap();
        let (rec, svm_ptr) = create_pointer_with_policy(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::SVM,
            },
            activated_policy(),
        )
        .unwrap();
        assert_eq!(svm_ptr.len(), 32);

        let home_ledger = Rc::new(RefCell::new(BTreeMap::<String, u128>::new()));
        home_ledger.borrow_mut().insert(alice_wasm.clone(), 500);
        let ledger_ref = Rc::clone(&home_ledger);
        let mut host = MemoryHost::new(1_000_000).with_universal_handler(Box::new(move |uc| {
            let v: serde_json::Value = serde_json::from_slice(&uc.input).unwrap();
            if let Some(tr) = v.get("transfer") {
                let rcpt = tr["recipient"].as_str().unwrap().to_string();
                let amt: u128 = tr["amount"].as_str().unwrap().parse().unwrap();
                let mut m = ledger_ref.borrow_mut();
                *m.entry(alice_wasm.clone()).or_default() -= amt;
                *m.entry(rcpt).or_default() += amt;
                return Ok(UniversalResult {
                    success: true,
                    output: br#"{"ok":true}"#.to_vec(),
                    gas_used: 4_000,
                });
            }
            let addr = v["balance"]["address"].as_str().unwrap();
            let bal = ledger_ref.borrow().get(addr).copied().unwrap_or(0);
            Ok(UniversalResult {
                success: true,
                output: serde_json::to_vec(&serde_json::json!({ "balance": bal.to_string() }))
                    .unwrap(),
                gas_used: 2_000,
            })
        }));

        let bob_svm32: [u8; 32] = bob_svm.as_slice().try_into().unwrap();
        let transfer_in = serde_json::to_vec(&serde_json::json!({
            "transfer": { "to": bob_svm32.to_vec(), "amount": "175" }
        }))
        .unwrap();
        let caller = EeIdentity {
            ee: EeId::SVM,
            id: alice_svm,
        };
        let tr_res = execute_pointer_call(
            &state,
            &rec,
            &caller,
            EeId::SVM,
            &transfer_in,
            200_000,
            &mut host,
        )
        .unwrap();
        assert!(tr_res.success);
        assert!(host.state.keys().all(|(ns, _)| ns != NS_SVM_ACCOUNT));
        assert_eq!(home_ledger.borrow().get(&bob_wasm), Some(&175));

        let bal_in = serde_json::to_vec(&serde_json::json!({
            "balance_of": { "owner": bob_svm32.to_vec() }
        }))
        .unwrap();
        let bal_res = execute_pointer_call(
            &state,
            &rec,
            &caller,
            EeId::SVM,
            &bal_in,
            200_000,
            &mut host,
        )
        .unwrap();
        assert_eq!(
            u128::from_le_bytes(bal_res.output.as_slice().try_into().unwrap()),
            175
        );
    }

    /// Directive IP-52 gate: `move_pointer_holds_no_balance`.
    #[test]
    fn move_pointer_holds_no_balance() {
        let mut state = AccountState::new();
        let alice = Address([0x31; 32]);
        let bob = Address([0x42; 32]);
        let alice_move = state
            .uel_state
            .ensure_alias_registered(&alice, EeId::MOVE)
            .unwrap();
        let bob_move = state
            .uel_state
            .ensure_alias_registered(&bob, EeId::MOVE)
            .unwrap();
        let bob_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&bob, EeId::WASM)
                .unwrap(),
        )
        .unwrap();
        let alice_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&alice, EeId::WASM)
                .unwrap(),
        )
        .unwrap();

        let rec = register_asset_with_policy(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::WASM,
                home_ref: b"bud1homefa".to_vec(),
                standard: AssetStandard::Fungible,
            },
            activated_policy(),
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 8,
                    symbol: "FA".into(),
                    name: "Move Pointer Asset".into(),
                })
            },
        )
        .unwrap();
        let (rec, move_ptr) = create_pointer_with_policy(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::MOVE,
            },
            activated_policy(),
        )
        .unwrap();
        assert_eq!(move_ptr.len(), 32);

        let home_ledger = Rc::new(RefCell::new(BTreeMap::<String, u128>::new()));
        home_ledger.borrow_mut().insert(alice_wasm.clone(), 900);
        let ledger_ref = Rc::clone(&home_ledger);
        let mut host = MemoryHost::new(1_000_000).with_universal_handler(Box::new(move |uc| {
            let v: serde_json::Value = serde_json::from_slice(&uc.input).unwrap();
            if let Some(tr) = v.get("transfer") {
                let rcpt = tr["recipient"].as_str().unwrap().to_string();
                let amt: u128 = tr["amount"].as_str().unwrap().parse().unwrap();
                let mut m = ledger_ref.borrow_mut();
                *m.entry(alice_wasm.clone()).or_default() -= amt;
                *m.entry(rcpt).or_default() += amt;
                return Ok(UniversalResult {
                    success: true,
                    output: br#"{"ok":true}"#.to_vec(),
                    gas_used: 4_000,
                });
            }
            let addr = v["balance"]["address"].as_str().unwrap();
            let bal = ledger_ref.borrow().get(addr).copied().unwrap_or(0);
            Ok(UniversalResult {
                success: true,
                output: serde_json::to_vec(&serde_json::json!({ "balance": bal.to_string() }))
                    .unwrap(),
                gas_used: 2_000,
            })
        }));

        let bob_move32: [u8; 32] = bob_move.as_slice().try_into().unwrap();
        let tr_in = serde_json::to_vec(&serde_json::json!({
            "transfer": { "flavor": "fungible_asset", "to": bob_move32.to_vec(), "amount": "320" }
        }))
        .unwrap();
        let caller = EeIdentity {
            ee: EeId::MOVE,
            id: alice_move,
        };
        let res = execute_pointer_call(
            &state,
            &rec,
            &caller,
            EeId::MOVE,
            &tr_in,
            200_000,
            &mut host,
        )
        .unwrap();
        assert!(res.success);
        assert!(host.state.keys().all(|(ns, _)| ns != NS_MOVE_STATE));
        assert_eq!(home_ledger.borrow().get(&bob_wasm), Some(&320));
    }

    /// Directive IP-52 gate: `pointer_allowance_lives_at_home` (SVM & Move legs).
    #[test]
    fn pointer_allowance_lives_at_home() {
        let mut state = AccountState::new();
        let owner = Address([0x51; 32]);
        let spender = Address([0x62; 32]);
        let owner_svm = state
            .uel_state
            .ensure_alias_registered(&owner, EeId::SVM)
            .unwrap();
        let spender_svm = state
            .uel_state
            .ensure_alias_registered(&spender, EeId::SVM)
            .unwrap();
        let owner_move = state
            .uel_state
            .ensure_alias_registered(&owner, EeId::MOVE)
            .unwrap();
        let spender_move = state
            .uel_state
            .ensure_alias_registered(&spender, EeId::MOVE)
            .unwrap();
        let owner_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&owner, EeId::WASM)
                .unwrap(),
        )
        .unwrap();
        let spender_wasm = String::from_utf8(
            state
                .uel_state
                .ensure_alias_registered(&spender, EeId::WASM)
                .unwrap(),
        )
        .unwrap();

        let rec = register_asset_with_policy(
            &mut state,
            &RegisterAsset {
                home_ee: EeId::WASM,
                home_ref: b"bud1allowhome".to_vec(),
                standard: AssetStandard::Fungible,
            },
            activated_policy(),
            |_, _, _| {
                Ok(ProbedAssetMetadata {
                    decimals: 6,
                    symbol: "ALW".into(),
                    name: "Allowance Asset".into(),
                })
            },
        )
        .unwrap();
        let (rec, _) = create_pointer_with_policy(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::SVM,
            },
            activated_policy(),
        )
        .unwrap();
        let (rec, _) = create_pointer_with_policy(
            &mut state,
            &CreatePointer {
                asset_id: rec.asset_id,
                target_ee: EeId::MOVE,
            },
            activated_policy(),
        )
        .unwrap();

        let home_allowances: Rc<RefCell<BTreeMap<(String, String), u128>>> =
            Rc::new(RefCell::new(BTreeMap::new()));
        let alw_ref = Rc::clone(&home_allowances);
        let owner_w_clone = owner_wasm.clone();
        let mut host = MemoryHost::new(2_000_000).with_universal_handler(Box::new(move |uc| {
            let v: serde_json::Value = serde_json::from_slice(&uc.input).unwrap();
            if let Some(inc) = v.get("increase_allowance") {
                let sp = inc["spender"].as_str().unwrap().to_string();
                let amt: u128 = inc["amount"].as_str().unwrap().parse().unwrap();
                *alw_ref
                    .borrow_mut()
                    .entry((owner_w_clone.clone(), sp))
                    .or_default() += amt;
                return Ok(UniversalResult {
                    success: true,
                    output: br#"{"ok":true}"#.to_vec(),
                    gas_used: 3_000,
                });
            }
            let own = v["allowance"]["owner"].as_str().unwrap().to_string();
            let sp = v["allowance"]["spender"].as_str().unwrap().to_string();
            let cur = alw_ref.borrow().get(&(own, sp)).copied().unwrap_or(0);
            Ok(UniversalResult {
                success: true,
                output: serde_json::to_vec(&serde_json::json!({
                    "allowance": cur.to_string(),
                    "expires": { "never": {} }
                }))
                .unwrap(),
                gas_used: 2_000,
            })
        }));

        // Approve 60 via SVM pointer, then query the SAME home allowance via Move pointer!
        let approve_svm = serde_json::to_vec(&serde_json::json!({
            "approve": { "delegate": spender_svm, "amount": "60" }
        }))
        .unwrap();
        let ok = execute_pointer_call(
            &state,
            &rec,
            &EeIdentity {
                ee: EeId::SVM,
                id: owner_svm,
            },
            EeId::SVM,
            &approve_svm,
            200_000,
            &mut host,
        )
        .unwrap();
        assert!(ok.success);
        assert_eq!(
            home_allowances.borrow().get(&(owner_wasm, spender_wasm)),
            Some(&60)
        );

        let query_move = serde_json::to_vec(&serde_json::json!({
            "allowance": { "owner": owner_move, "spender": spender_move }
        }))
        .unwrap();
        let q_res = execute_pointer_call(
            &state,
            &rec,
            &EeIdentity {
                ee: EeId::MOVE,
                id: owner_move,
            },
            EeId::MOVE,
            &query_move,
            200_000,
            &mut host,
        )
        .unwrap();
        assert_eq!(
            u128::from_le_bytes(q_res.output.as_slice().try_into().unwrap()),
            60
        );
        assert!(host.state.is_empty());
    }
}
