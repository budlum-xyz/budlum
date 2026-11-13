//! Universal Asset Registry (`uel/assets`) and zero-balance cross-EE pointers.
//!
//! Implements section 8.8 and  items 5-6:
//! - Every asset lives exclusively in its home environment (`Y-5`).
//! - `asset_id = SHA3-256("BDLM_UEL_ASSET_V1" || home_ee || len_le64 || home_ref)`.
//! - Permissionless `RegisterAsset` reads metadata from the home EE.
//! - `CreatePointer` deploys an immutable deterministic pointer contract in the
//!   target EE (`EVM <-> WASM` at launch: `CW20 -> ERC20`, `CW721 -> ERC721`,
//!   `ERC20 -> CW20`, `ERC721 -> CW721`).
//! - Pointer contracts hold zero balance storage and zero local allowance ledger:
//!   every balance and approval operation executes at home via `UniversalCall`.
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::alias::{
    bech32_contract_addr, derive_evm_alias, derive_wasm_alias, is_ed25519_on_curve, ALIAS_NAMESPACE,
};
use crate::execution::coordinator::state::{
    derive_uel_asset_id, NS_CAIRO_STATE, NS_EVM_ACCOUNT, NS_EVM_CODE, NS_MOVE_STATE, NS_NEAR_STATE,
    NS_PLUTUS_STATE, NS_POLKAVM_STATE, NS_RV32_STATE, NS_SUI_OBJECT, NS_SVM_ACCOUNT, NS_TVM_STATE,
    NS_UEL_ASSETS, NS_UTXO_STATE, NS_WASM_CODE, NS_WASM_CONTRACT,
};
use budlum_uel_abi::{EeId, HostRead, Namespace};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256, Sha3_256};
use std::collections::BTreeMap;

/// Canonical Budlum testnet chain ID (`45261`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Bytecode magic identifying an immutable UEL pointer contract in EVM, WASM, SVM, or Move.
pub const POINTER_BYTECODE_PREFIX: &[u8] = b"BDLM_UEL_PTR_BYTECODE_V1";

/// Canonical stateless SPL Token pointer operations (`EeId::SVM = 0x03`, section 8.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplPointerOp {
    Transfer {
        to: [u8; 32],
        amount: u128,
    },
    Approve {
        delegate: [u8; 32],
        amount: u128,
    },
    TransferFrom {
        owner: [u8; 32],
        to: [u8; 32],
        amount: u128,
    },
    BalanceOf {
        owner: [u8; 32],
    },
    Allowance {
        owner: [u8; 32],
        delegate: [u8; 32],
    },
}

/// Move pointer flavor (`0x1::fungible_asset` vs `0x1::coin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovePointerFlavor {
    FungibleAsset,
    Coin,
}

/// Canonical stateless Move asset pointer operations (`EeId::MOVE = 0x04`, section 8.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovePointerOp {
    Transfer {
        flavor: MovePointerFlavor,
        to: [u8; 32],
        amount: u128,
    },
    Approve {
        flavor: MovePointerFlavor,
        spender: [u8; 32],
        amount: u128,
    },
    TransferFrom {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
        to: [u8; 32],
        amount: u128,
    },
    Balance {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
    },
    Allowance {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
        spender: [u8; 32],
    },
}

/// Resolves a 32-byte recipient/owner argument inside a cross-EE pointer call
/// to the target `home_ee` identity bytes using `uel/alias` when available.
#[must_use]
pub fn resolve_pointer_party_for_home(
    host: &dyn HostRead,
    raw32: &[u8; 32],
    home_ee: EeId,
) -> Vec<u8> {
    if home_ee == EeId::EVM
        && raw32.get(..12) == Some([0u8; 12].as_slice())
        && raw32.get(12..32) != Some([0u8; 20].as_slice())
    {
        return raw32.get(12..32).unwrap_or(&[]).to_vec();
    }
    if let Ok(ns) = Namespace::new(ALIAS_NAMESPACE) {
        let mut key = [0u8; 33];
        if let Some(prefix) = key.get_mut(..32) {
            prefix.copy_from_slice(raw32);
        }
        if let Some(last) = key.get_mut(32) {
            *last = home_ee.0;
        }
        if let Ok(Some(alias)) = host.read(&ns, &key) {
            return alias;
        }
    }
    match home_ee {
        EeId::EVM => derive_evm_alias(&Address::from(*raw32)).to_vec(),
        EeId::WASM => derive_wasm_alias(&Address::from(*raw32)).into_bytes(),
        _ => raw32.to_vec(),
    }
}

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
///
/// # Errors
///
/// Returns an error if the operation fails.
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
/// - `EeId::EVM`: 20-byte `keccak256("BDLM_UEL_POINTER_V1" || asset_id || 0x01)[12..32]`.
/// - `EeId::WASM`: bech32 `bud1...` over `SHA3-256("BDLM_UEL_POINTER_V1" || asset_id || 0x02)`.
/// - `EeId::SVM`: off-curve PDA `SHA256("BDLM_UEL_POINTER_V1" || asset_id || 0x03 || bump)`.
/// - `EeId::MOVE`: 32-byte address `SHA3-256("BDLM_UEL_POINTER_V1" || asset_id || 0x04)`.
///
/// # Errors
///
/// Returns an error if the operation fails.
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
        EeId::SVM => {
            for step in 0u8..=255u8 {
                let bump = 255u8.wrapping_sub(step);
                let mut h = Sha256::new();
                h.update(b"BDLM_UEL_POINTER_V1");
                h.update(asset_id);
                h.update([EeId::SVM.0, bump]);
                let cand: [u8; 32] = h.finalize().into();
                if !is_ed25519_on_curve(&cand) {
                    return Ok(cand.to_vec());
                }
            }
            Err(String::from("failed to derive off-curve SVM pointer PDA"))
        }
        EeId::MOVE
        | EeId::MOVE_SUI
        | EeId::CAIRO
        | EeId::NEAR_WASM
        | EeId::POLKAVM
        | EeId::TVM
        | EeId::UTXO
        | EeId::PLUTUS
        | EeId::RV32 => {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_UEL_POINTER_V1");
            h.update(asset_id);
            h.update([target_ee.0]);
            let digest: [u8; 32] = h.finalize().into();
            Ok(digest.to_vec())
        }
        other => Err(format!(
            "pointers for EE 0x{:02x} are not yet defined",
            other.0
        )),
    }
}

/// Reads a [`RegisteredAsset`] from `uel/assets` if present.
///
/// # Errors
///
/// Returns an error if the operation fails.
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
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn register_asset_entry(
    state: &mut AccountState,
    home_ee: EeId,
    home_ref: &[u8],
    standard: AssetStandard,
    decimals: u8,
    symbol: String,
    name: String,
) -> Result<RegisteredAsset, String> {
    if !matches!(
        home_ee,
        EeId::EVM
            | EeId::WASM
            | EeId::SVM
            | EeId::MOVE
            | EeId::MOVE_SUI
            | EeId::CAIRO
            | EeId::NEAR_WASM
            | EeId::POLKAVM
            | EeId::TVM
            | EeId::UTXO
            | EeId::PLUTUS
            | EeId::RV32
    ) {
        return Err(format!(
            "asset registration supports catalog execution environments (0x01..0x0C); got 0x{:02x}",
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
///
/// # Errors
///
/// Returns an error if the operation fails.
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
        EeId::SVM => {
            let addr32: [u8; 32] = ptr_addr
                .as_slice()
                .try_into()
                .map_err(|_| String::from("SVM pointer address != 32 bytes"))?;
            let ptr_acc = serde_json::json!({
                "lamports": 1u64,
                "owner": crate::execution::coordinator::svm_ee::SVM_BPF_LOADER_ID,
                "executable": true,
                "rent_epoch": 0u64,
                "data": code,
            });
            let acc_bytes = serde_json::to_vec(&ptr_acc).map_err(|e| e.to_string())?;
            state
                .execution_state
                .write(NS_SVM_ACCOUNT, &addr32, Some(&acc_bytes))?;
        }
        EeId::MOVE => {
            let mut mod_key = Vec::with_capacity(4 + ptr_addr.len() + 8);
            mod_key.extend_from_slice(b"mod:");
            mod_key.extend_from_slice(&ptr_addr);
            mod_key.extend_from_slice(b":pointer");
            state
                .execution_state
                .write(NS_MOVE_STATE, &mod_key, Some(&code))?;
        }
        EeId::MOVE_SUI
        | EeId::CAIRO
        | EeId::NEAR_WASM
        | EeId::POLKAVM
        | EeId::TVM
        | EeId::UTXO
        | EeId::PLUTUS
        | EeId::RV32 => {
            let ns = match target_ee {
                EeId::MOVE_SUI => NS_SUI_OBJECT,
                EeId::CAIRO => NS_CAIRO_STATE,
                EeId::NEAR_WASM => NS_NEAR_STATE,
                EeId::POLKAVM => NS_POLKAVM_STATE,
                EeId::TVM => NS_TVM_STATE,
                EeId::UTXO => NS_UTXO_STATE,
                EeId::PLUTUS => NS_PLUTUS_STATE,
                EeId::RV32 => NS_RV32_STATE,
                other => return Err(format!("unsupported pointer target EE 0x{:02x}", other.0)),
            };
            let mut code_key = Vec::with_capacity(6 + ptr_addr.len());
            code_key.extend_from_slice(b"code:");
            code_key.push(target_ee.0);
            code_key.extend_from_slice(&ptr_addr);
            state.execution_state.write(ns, &code_key, Some(&code))?;
        }
        other => {
            return Err(format!("unsupported pointer target EE 0x{:02x}", other.0));
        }
    }

    asset.pointers.insert(target_ee.0, ptr_addr.clone());
    let updated = serde_json::to_vec(&asset).map_err(|e| e.to_string())?;
    state
        .execution_state
        .write(NS_UEL_ASSETS, asset_id, Some(&updated))?;
    Ok(ptr_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_ees_support_asset_registration_and_pointers() {
        let mut state = AccountState::default();
        let entry = register_asset_entry(
            &mut state,
            EeId::MOVE_SUI,
            b"0x2::sui::SUI",
            AssetStandard::Fungible,
            9,
            "SUI".into(),
            "Sui Native".into(),
        )
        .expect("Sui home asset registers cleanly");
        assert!(derive_pointer_address(&entry.asset_id, EeId::BUDZERO).is_err());

        for target in [
            EeId::CAIRO,
            EeId::NEAR_WASM,
            EeId::POLKAVM,
            EeId::TVM,
            EeId::UTXO,
            EeId::PLUTUS,
            EeId::RV32,
        ] {
            let ptr = deploy_asset_pointer(&mut state, &entry.asset_id, target)
                .expect("expansion EE deploys asset pointer");
            assert_eq!(ptr.len(), 32);
        }
        let reloaded = read_registered_asset(&state, &entry.asset_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.pointers.len(), 7);
    }
}
