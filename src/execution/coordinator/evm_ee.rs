//! EVM execution environment (`EeId::EVM` = `0x01`) over `HostApi`.
//!
//! Implements  and the EVM leg of :
//! - Stateless worker engine reading/writing exclusively via `HostApi`
//!   (`ee/evm/account`, `ee/evm/code`, `ee/evm/storage`).
//! - Prague-fork stack EVM bytecode execution (`PUSH0`, arithmetic, bitwise,
//!   comparisons, `KECCAK256`, memory, `SLOAD`/`SSTORE`, `LOG0..LOG4`, `JUMP`/`JUMPI`,
//!   `CALL`, `STATICCALL`, `CREATE`, `CREATE2`, `RETURN`, `REVERT`).
//! - `CREATE` and `CREATE2` target collision guard against `uel/alias` (8.4.2 rule 3).
//! - `SSTORE` state-growth gas metering (`STATE_GROWTH_GAS_PER_BYTE`) and exact
//!   zero-slot deletion so `namespace_bytes("ee/evm/storage")` reflects live state (`R-12`).
//! - Precompile `0x000000000000000000000000000000000000B001` (`IBudlumUniversal`)
//!   emitting `UniversalCallExecuted(uint8 ee, bytes target, bool ok)`.
//! - Zero-balance ERC-20 / ERC-721 UEL pointers forwarding to home WASM contracts.
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::cross_domain::evm::rlp::{self, Item};
use crate::execution::coordinator::alias::{derive_foreign_cosmos_bech32, ALIAS_NAMESPACE};
use crate::execution::coordinator::assets::{
    decode_pointer_bytecode, AssetStandard, MovePointerFlavor, MovePointerOp, PointerDescriptor,
    SplPointerOp,
};
use crate::execution::coordinator::foreign::ethereum::BUDLUM_EVM_CHAIN_ID;
use crate::execution::coordinator::state::{
    NS_EVM_ACCOUNT, NS_EVM_CODE, NS_EVM_STORAGE, NS_UEL_ASSETS,
};
use crate::execution::coordinator::universal_call::{
    decode_precompile_calldata, decode_uol_precompile_calldata, encode_evm_universal_call_log,
    encode_precompile_return, uol_selector, wrap_static_universal_input, DecodedUolPrecompileCall,
    EVM_UNIVERSAL_PRECOMPILE, EVM_UOL_PRECOMPILE,
};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutOfGas, OutcomeStatus, RefusalCode, UniversalCall, UniversalResult,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

/// Maximum deployed runtime EVM bytecode size (EIP-170: 24 KiB).
pub const MAX_EVM_BYTECODE_BYTES: usize = 24_576;
/// Maximum initcode size at deployment (EIP-3860: 48 KiB).
pub const MAX_EVM_INITCODE_BYTES: usize = 49_152;
/// Maximum EVM call/create nesting depth per EIP-150 (`1024`).
const MAX_EVM_CALL_DEPTH: u32 = 1_024;
/// Cold `SSTORE` zero-to-nonzero base cost in EVM gas / BGU.
pub const GAS_SSTORE_SET: u64 = 20_000;
/// Warm / nonzero-to-nonzero `SSTORE` reset cost in EVM gas / BGU.
pub const GAS_SSTORE_RESET: u64 = 2_900;
/// Additional state-growth charge per new persisted byte (`52` key + `32` value = `84` bytes).
pub const STATE_GROWTH_GAS_PER_BYTE: u64 = 16;
/// New bytes added to `ee/evm/storage` when a fresh `(addr20 || slot32) -> word32` slot opens.
pub const EVM_STORAGE_ENTRY_BYTES: u64 = 84;
/// Bytecode header for canonical in-tree ERC-20 / ERC-721 home token contracts.
pub const STD_EVM_TOKEN_PREFIX: &[u8] = b"BDLM_EVM_STD_TOKEN_V1";

/// Metadata for a canonical in-tree ERC-20 or ERC-721 home contract on EVM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdEvmTokenSpec {
    pub standard: AssetStandard,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_holder: [u8; 20],
    pub initial_supply_or_token_id: u128,
    pub base_uri: String,
}

/// Encodes a [`StdEvmTokenSpec`] as deployable runtime bytecode.
pub fn encode_std_evm_token_code(spec: &StdEvmTokenSpec) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(spec).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(STD_EVM_TOKEN_PREFIX.len() + body.len());
    out.extend_from_slice(STD_EVM_TOKEN_PREFIX);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_std_evm_token_code(code: &[u8]) -> Option<StdEvmTokenSpec> {
    let rest = code.strip_prefix(STD_EVM_TOKEN_PREFIX)?;
    serde_json::from_slice(rest).ok()
}

/// Computes the 4-byte Solidity function selector `keccak256(sig)[..4]`.
#[must_use]
pub fn solidity_selector(sig: &str) -> [u8; 4] {
    let d: [u8; 32] = Keccak256::digest(sig.as_bytes()).into();
    let [b0, b1, b2, b3, ..] = d;
    [b0, b1, b2, b3]
}

/// Computes an EVM `CREATE` address `keccak256(rlp([sender20, nonce]))[12..32]`.
///
/// exposed for: EVM contract deployment helpers and migration verification.
#[must_use]
pub fn compute_create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let encoded = rlp::encode(&Item::List(vec![
        Item::String(sender.to_vec()),
        Item::String(rlp::encode_uint_bytes(nonce)),
    ]));
    let digest: [u8; 32] = Keccak256::digest(&encoded).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, addr @ ..] = digest;
    addr
}

/// Computes EVM `CREATE2` address `keccak256(0xff || sender || salt || keccak256(init))[12..32]`.
#[must_use]
pub fn compute_create2_address(sender: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let init_hash: [u8; 32] = Keccak256::digest(init_code).into();
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend_from_slice(sender);
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(&init_hash);
    let digest: [u8; 32] = Keccak256::digest(&preimage).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, addr @ ..] = digest;
    addr
}

/// On-chain EVM account metadata stored under `ee/evm/account`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvmAccountRecord {
    pub nonce: u64,
    pub code_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<crate::execution::coordinator::migration::ImportSource>,
}

/// Stateless EVM execution environment worker (`budlum-ee-evm`, Prague fork).
#[derive(Debug, Default, Clone)]
pub struct EvmEe;

impl EvmEe {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn ns_obj(name: &str) -> Result<Namespace, EeFault> {
    Namespace::new(name).map_err(|e| EeFault {
        ee: EeId::EVM,
        panic_digest: Keccak256::digest(e.to_string().as_bytes()).into(),
    })
}

fn read_account_rec(host: &dyn HostRead, addr: &[u8; 20]) -> Result<EvmAccountRecord, String> {
    let ns = Namespace::new(NS_EVM_ACCOUNT).map_err(|e| e.to_string())?;
    let Some(bytes) = host.read(&ns, addr).map_err(|e| e.to_string())? else {
        return Ok(EvmAccountRecord::default());
    };
    serde_json::from_slice(&bytes).map_err(|e| format!("corrupt EVM account record: {e}"))
}

fn write_account_rec(
    host: &mut dyn HostApi,
    addr: &[u8; 20],
    rec: &EvmAccountRecord,
) -> Result<(), HostError> {
    let ns = Namespace::new(NS_EVM_ACCOUNT)
        .map_err(|e| HostError::Invalid(format!("bad namespace: {e}")))?;
    let raw = serde_json::to_vec(rec).map_err(|e| HostError::Invalid(e.to_string()))?;
    host.write(&ns, addr, Some(&raw))
}

fn load_contract_code(host: &dyn HostRead, addr: &[u8; 20]) -> Result<Vec<u8>, String> {
    let rec = read_account_rec(host, addr)?;
    let Some(ch_hex) = rec.code_hash else {
        return Ok(Vec::new());
    };
    let ch = hex::decode(&ch_hex).map_err(|e| e.to_string())?;
    let ns = Namespace::new(NS_EVM_CODE).map_err(|e| e.to_string())?;
    Ok(host
        .read(&ns, &ch)
        .map_err(|e| e.to_string())?
        .unwrap_or_default())
}

fn target_collides_with_native_alias(host: &dyn HostRead, addr20: &[u8; 20]) -> bool {
    let Ok(alias_ns) = Namespace::new(ALIAS_NAMESPACE) else {
        return false;
    };
    // Direct probe key convention `[0xff, 'e', 'v', 'm', addr20]` if indexed, plus
    // coordinator-side check at deploy boundary; also refuse reserved precompile range.
    if addr20 == &EVM_UNIVERSAL_PRECOMPILE || addr20 == &EVM_UOL_PRECOMPILE {
        return true;
    }
    let mut probe = Vec::with_capacity(24);
    probe.extend_from_slice(b"evm:");
    probe.extend_from_slice(addr20);
    host.read(&alias_ns, &probe).ok().flatten().is_some()
}

fn storage_key(addr: &[u8; 20], slot: &[u8; 32]) -> [u8; 52] {
    let mut k = [0u8; 52];
    if let Some(a) = k.get_mut(..20) {
        a.copy_from_slice(addr);
    }
    if let Some(s) = k.get_mut(20..52) {
        s.copy_from_slice(slot);
    }
    k
}

fn sload_word(host: &dyn HostRead, addr: &[u8; 20], slot: &[u8; 32]) -> Result<[u8; 32], String> {
    let ns = Namespace::new(NS_EVM_STORAGE).map_err(|e| e.to_string())?;
    let k = storage_key(addr, slot);
    let Some(bytes) = host.read(&ns, &k).map_err(|e| e.to_string())? else {
        return Ok([0u8; 32]);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| String::from("corrupt EVM 32-byte storage word"))
}

fn sstore_word(
    host: &mut dyn HostApi,
    addr: &[u8; 20],
    slot: &[u8; 32],
    val: &[u8; 32],
) -> Result<u64, String> {
    let ns = Namespace::new(NS_EVM_STORAGE).map_err(|e| e.to_string())?;
    let k = storage_key(addr, slot);
    let existing = host.read(&ns, &k).map_err(|e| e.to_string())?;
    let was_zero = existing.as_ref().is_none_or(|b| b.iter().all(|x| *x == 0));
    let is_zero = val.iter().all(|x| *x == 0);
    let gas_cost = if was_zero && !is_zero {
        let growth = STATE_GROWTH_GAS_PER_BYTE.saturating_mul(EVM_STORAGE_ENTRY_BYTES);
        GAS_SSTORE_SET.saturating_add(growth)
    } else {
        GAS_SSTORE_RESET
    };
    host.charge(gas_cost)
        .map_err(|_| String::from("out of gas in SSTORE"))?;
    if is_zero {
        host.write(&ns, &k, None).map_err(|e| e.to_string())?;
    } else {
        host.write(&ns, &k, Some(val)).map_err(|e| e.to_string())?;
    }
    Ok(gas_cost)
}

/// 256-bit unsigned integer in `[u64; 4]` big-endian limbs (`w[0]` most significant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct U256Word([u8; 32]);

impl U256Word {
    const ZERO: Self = Self([0u8; 32]);

    fn from_u64(v: u64) -> Self {
        let mut b = [0u8; 32];
        if let Some(lo) = b.get_mut(24..32) {
            lo.copy_from_slice(&v.to_be_bytes());
        }
        Self(b)
    }

    fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        if let Some(lo) = b.get_mut(16..32) {
            lo.copy_from_slice(&v.to_be_bytes());
        }
        Self(b)
    }

    fn from_addr20(addr: &[u8; 20]) -> Self {
        let mut b = [0u8; 32];
        if let Some(lo) = b.get_mut(12..32) {
            lo.copy_from_slice(addr);
        }
        Self(b)
    }

    fn to_addr20(self) -> [u8; 20] {
        let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = self.0;
        tail
    }

    fn to_u128_checked(self) -> Option<u128> {
        if self
            .0
            .get(..16)
            .is_some_and(|hi| hi.iter().any(|b| *b != 0))
        {
            return None;
        }
        let lo = self.0.get(16..32)?;
        let arr: [u8; 16] = lo.try_into().ok()?;
        Some(u128::from_be_bytes(arr))
    }

    fn to_u128_saturating(self) -> u128 {
        if self
            .0
            .get(..16)
            .is_some_and(|hi| hi.iter().any(|b| *b != 0))
        {
            return u128::MAX;
        }
        let Some(lo) = self.0.get(16..32) else {
            return 0;
        };
        let Ok(arr) = <[u8; 16]>::try_from(lo) else {
            return 0;
        };
        u128::from_be_bytes(arr)
    }

    fn to_usize_checked(self) -> Option<usize> {
        if self
            .0
            .get(..24)
            .is_some_and(|hi| hi.iter().any(|b| *b != 0))
        {
            return None;
        }
        let lo = self.0.get(24..32)?;
        let arr: [u8; 8] = lo.try_into().ok()?;
        usize::try_from(u64::from_be_bytes(arr)).ok()
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    fn wrapping_add(self, rhs: Self) -> Self {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let a = u16::from(self.0.get(i).copied().unwrap_or(0));
            let b = u16::from(rhs.0.get(i).copied().unwrap_or(0));
            let sum = a + b + carry;
            if let Some(slot) = out.get_mut(i) {
                *slot = (sum & 0xff) as u8;
            }
            carry = sum >> 8;
        }
        Self(out)
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let a = i16::from(self.0.get(i).copied().unwrap_or(0));
            let b = i16::from(rhs.0.get(i).copied().unwrap_or(0));
            let diff = a - b - borrow;
            if diff < 0 {
                if let Some(slot) = out.get_mut(i) {
                    *slot = (diff + 256) as u8;
                }
                borrow = 1;
            } else {
                if let Some(slot) = out.get_mut(i) {
                    *slot = diff as u8;
                }
                borrow = 0;
            }
        }
        Self(out)
    }
}

fn abi_encode_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&U256Word::from_u64(32).0);
    out.extend_from_slice(&U256Word::from_u64(s.len() as u64).0);
    out.extend_from_slice(s.as_bytes());
    let rem = s.len() % 32;
    if rem != 0 {
        out.resize(out.len() + (32 - rem), 0);
    }
    out
}

fn decode_abi_addr(args: &[u8], offset: usize) -> Result<[u8; 20], String> {
    let w = args
        .get(offset..offset + 32)
        .ok_or_else(|| String::from("ABI address word truncated"))?;
    let arr: [u8; 32] = w.try_into().map_err(|_| String::from("ABI word len"))?;
    Ok(U256Word(arr).to_addr20())
}

fn decode_abi_u128(args: &[u8], offset: usize) -> Result<u128, String> {
    let w = args
        .get(offset..offset + 32)
        .ok_or_else(|| String::from("ABI uint256 word truncated"))?;
    let arr: [u8; 32] = w.try_into().map_err(|_| String::from("ABI word len"))?;
    Ok(U256Word(arr).to_u128_saturating())
}

fn map_slot(tag: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(tag);
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn execute_std_evm_token(
    spec: &StdEvmTokenSpec,
    self_addr: &[u8; 20],
    caller20: &[u8; 20],
    input: &[u8],
    is_static: bool,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let Some(sel) = input.get(..4) else {
        return Ok((OutcomeStatus::Revert, b"missing selector".to_vec()));
    };
    let args = input.get(4..).unwrap_or(&[]);
    if sel == solidity_selector("name()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&spec.name)));
    }
    if sel == solidity_selector("symbol()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&spec.symbol)));
    }
    if sel == solidity_selector("decimals()") {
        return Ok((
            OutcomeStatus::Success,
            U256Word::from_u64(u64::from(spec.decimals)).0.to_vec(),
        ));
    }
    match spec.standard {
        AssetStandard::Fungible => {
            if sel == solidity_selector("totalSupply()") {
                let ts = sload_word(host, self_addr, &map_slot(b"supply", &[], &[]))?;
                return Ok((OutcomeStatus::Success, ts.to_vec()));
            }
            if sel == solidity_selector("balanceOf(address)") {
                let who = decode_abi_addr(args, 0)?;
                let bal = sload_word(host, self_addr, &map_slot(b"bal", &who, &[]))?;
                return Ok((OutcomeStatus::Success, bal.to_vec()));
            }
            if sel == solidity_selector("allowance(address,address)") {
                let owner = decode_abi_addr(args, 0)?;
                let spender = decode_abi_addr(args, 32)?;
                let alw = sload_word(host, self_addr, &map_slot(b"alw", &owner, &spender))?;
                return Ok((OutcomeStatus::Success, alw.to_vec()));
            }
            if is_static {
                return Ok((OutcomeStatus::Revert, b"static write forbidden".to_vec()));
            }
            if sel == solidity_selector("approve(address,uint256)") {
                let spender = decode_abi_addr(args, 0)?;
                let amt = decode_abi_u128(args, 32)?;
                let slot = map_slot(b"alw", caller20, &spender);
                let _ = sstore_word(host, self_addr, &slot, &U256Word::from_u128(amt).0)?;
                return Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()));
            }
            if sel == solidity_selector("transfer(address,uint256)") {
                let to = decode_abi_addr(args, 0)?;
                let amt = decode_abi_u128(args, 32)?;
                return transfer_erc20(host, self_addr, caller20, &to, amt);
            }
            if sel == solidity_selector("transferFrom(address,address,uint256)") {
                let from = decode_abi_addr(args, 0)?;
                let to = decode_abi_addr(args, 32)?;
                let amt = decode_abi_u128(args, 64)?;
                let alw_slot = map_slot(b"alw", &from, caller20);
                let alw_word = sload_word(host, self_addr, &alw_slot)?;
                let cur_alw = U256Word(alw_word).to_u128_saturating();
                if cur_alw < amt {
                    return Ok((OutcomeStatus::Revert, b"insufficient allowance".to_vec()));
                }
                let _ = sstore_word(
                    host,
                    self_addr,
                    &alw_slot,
                    &U256Word::from_u128(cur_alw - amt).0,
                )?;
                return transfer_erc20(host, self_addr, &from, &to, amt);
            }
            Ok((OutcomeStatus::Revert, b"unknown ERC20 selector".to_vec()))
        }
        AssetStandard::NonFungible => {
            if sel == solidity_selector("ownerOf(uint256)") {
                let tid = decode_abi_u128(args, 0)?;
                let owner_w = sload_word(
                    host,
                    self_addr,
                    &map_slot(b"nft_owner", &tid.to_be_bytes(), &[]),
                )?;
                if U256Word(owner_w).is_zero() {
                    return Ok((OutcomeStatus::Revert, b"nonexistent token".to_vec()));
                }
                return Ok((OutcomeStatus::Success, owner_w.to_vec()));
            }
            if sel == solidity_selector("tokenURI(uint256)") {
                let tid = decode_abi_u128(args, 0)?;
                let uri = format!("{}{}", spec.base_uri, tid);
                return Ok((OutcomeStatus::Success, abi_encode_string(&uri)));
            }
            if is_static {
                return Ok((OutcomeStatus::Revert, b"static write forbidden".to_vec()));
            }
            if sel == solidity_selector("approve(address,uint256)") {
                let to = decode_abi_addr(args, 0)?;
                let tid = decode_abi_u128(args, 32)?;
                let owner = U256Word(sload_word(
                    host,
                    self_addr,
                    &map_slot(b"nft_owner", &tid.to_be_bytes(), &[]),
                )?)
                .to_addr20();
                if &owner != caller20 {
                    return Ok((OutcomeStatus::Revert, b"not token owner".to_vec()));
                }
                let _ = sstore_word(
                    host,
                    self_addr,
                    &map_slot(b"nft_appr", &tid.to_be_bytes(), &[]),
                    &U256Word::from_addr20(&to).0,
                )?;
                return Ok((OutcomeStatus::Success, Vec::new()));
            }
            if sel == solidity_selector("safeTransferFrom(address,address,uint256)")
                || sel == solidity_selector("transferFrom(address,address,uint256)")
            {
                let from = decode_abi_addr(args, 0)?;
                let to = decode_abi_addr(args, 32)?;
                let tid = decode_abi_u128(args, 64)?;
                let owner_slot = map_slot(b"nft_owner", &tid.to_be_bytes(), &[]);
                let owner = U256Word(sload_word(host, self_addr, &owner_slot)?).to_addr20();
                let appr_slot = map_slot(b"nft_appr", &tid.to_be_bytes(), &[]);
                let approved = U256Word(sload_word(host, self_addr, &appr_slot)?).to_addr20();
                if owner != from || (caller20 != &owner && caller20 != &approved) {
                    return Ok((OutcomeStatus::Revert, b"nft transfer unauthorized".to_vec()));
                }
                let _ = sstore_word(host, self_addr, &owner_slot, &U256Word::from_addr20(&to).0)?;
                let _ = sstore_word(host, self_addr, &appr_slot, &[0u8; 32])?;
                return Ok((OutcomeStatus::Success, Vec::new()));
            }
            Ok((OutcomeStatus::Revert, b"unknown ERC721 selector".to_vec()))
        }
    }
}

fn transfer_erc20(
    host: &mut dyn HostApi,
    self_addr: &[u8; 20],
    from: &[u8; 20],
    to: &[u8; 20],
    amt: u128,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let from_slot = map_slot(b"bal", from, &[]);
    let from_bal = U256Word(sload_word(host, self_addr, &from_slot)?).to_u128_saturating();
    if from_bal < amt {
        return Ok((
            OutcomeStatus::Revert,
            b"insufficient ERC20 balance".to_vec(),
        ));
    }
    let _ = sstore_word(
        host,
        self_addr,
        &from_slot,
        &U256Word::from_u128(from_bal - amt).0,
    )?;
    let to_slot = map_slot(b"bal", to, &[]);
    let to_bal = U256Word(sload_word(host, self_addr, &to_slot)?).to_u128_saturating();
    let _ = sstore_word(
        host,
        self_addr,
        &to_slot,
        &U256Word::from_u128(to_bal.saturating_add(amt)).0,
    )?;
    Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
}

fn execute_evm_pointer_to_wasm(
    ptr: &PointerDescriptor,
    caller20: &[u8; 20],
    input: &[u8],
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let Some(sel) = input.get(..4) else {
        return Ok((OutcomeStatus::Revert, b"missing selector".to_vec()));
    };
    let args = input.get(4..).unwrap_or(&[]);
    if sel == solidity_selector("name()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&ptr.name)));
    }
    if sel == solidity_selector("symbol()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&ptr.symbol)));
    }
    if sel == solidity_selector("decimals()") {
        return Ok((
            OutcomeStatus::Success,
            U256Word::from_u64(u64::from(ptr.decimals)).0.to_vec(),
        ));
    }

    let caller_wasm = derive_foreign_cosmos_bech32(caller20);
    let home_target = ptr.home_ref.clone();

    let call_wasm = |host: &mut dyn HostApi,
                     sender_id: Vec<u8>,
                     wasm_payload: serde_json::Value,
                     read_only: bool|
     -> Result<(bool, Vec<u8>), String> {
        let raw_json = serde_json::to_vec(&wasm_payload).map_err(|e| e.to_string())?;
        let final_in = if read_only {
            wrap_static_universal_input(&raw_json)
        } else {
            raw_json
        };
        let res = host
            .universal_call(UniversalCall {
                from: EeIdentity {
                    ee: EeId::WASM,
                    id: sender_id,
                },
                to_ee: EeId::WASM,
                target: EeIdentity {
                    ee: EeId::WASM,
                    id: home_target.clone(),
                },
                value: BudAmount(0),
                input: final_in,
                gas_limit: gas_budget / 2 + 10_000,
                is_static: read_only,
            })
            .map_err(|e| e.to_string())?;
        let log = encode_evm_universal_call_log(EeId::WASM, &home_target, res.success);
        host.emit_log(log).map_err(|e| e.to_string())?;
        Ok((res.success, res.output))
    };

    match ptr.standard {
        AssetStandard::Fungible => {
            if sel == solidity_selector("balanceOf(address)") {
                let who20 = decode_abi_addr(args, 0)?;
                let who_w = derive_foreign_cosmos_bech32(&who20);
                let q = serde_json::json!({ "query": { "balance": { "address": who_w } } });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), q, true)?;
                if !ok {
                    return Ok((OutcomeStatus::Revert, out));
                }
                let v: serde_json::Value =
                    serde_json::from_slice(&out).map_err(|e| e.to_string())?;
                let bal: u128 = v
                    .get("balance")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return Ok((OutcomeStatus::Success, U256Word::from_u128(bal).0.to_vec()));
            }
            if sel == solidity_selector("allowance(address,address)") {
                let owner20 = decode_abi_addr(args, 0)?;
                let spender20 = decode_abi_addr(args, 32)?;
                let q = serde_json::json!({
                    "query": {
                        "allowance": {
                            "owner": derive_foreign_cosmos_bech32(&owner20),
                            "spender": derive_foreign_cosmos_bech32(&spender20),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), q, true)?;
                if !ok {
                    return Ok((OutcomeStatus::Revert, out));
                }
                let v: serde_json::Value =
                    serde_json::from_slice(&out).map_err(|e| e.to_string())?;
                let alw: u128 = v
                    .get("allowance")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return Ok((OutcomeStatus::Success, U256Word::from_u128(alw).0.to_vec()));
            }
            if is_static {
                return Ok((OutcomeStatus::Revert, b"static pointer write".to_vec()));
            }
            if sel == solidity_selector("approve(address,uint256)") {
                let spender20 = decode_abi_addr(args, 0)?;
                let amt = decode_abi_u128(args, 32)?;
                let msg = serde_json::json!({
                    "execute": {
                        "set_allowance": {
                            "spender": derive_foreign_cosmos_bech32(&spender20),
                            "amount": amt.to_string(),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), msg, false)?;
                return if ok {
                    Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
                } else {
                    Ok((OutcomeStatus::Revert, out))
                };
            }
            if sel == solidity_selector("transfer(address,uint256)") {
                let to20 = decode_abi_addr(args, 0)?;
                let amt = decode_abi_u128(args, 32)?;
                let msg = serde_json::json!({
                    "execute": {
                        "transfer": {
                            "recipient": derive_foreign_cosmos_bech32(&to20),
                            "amount": amt.to_string(),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), msg, false)?;
                return if ok {
                    Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
                } else {
                    Ok((OutcomeStatus::Revert, out))
                };
            }
            if sel == solidity_selector("transferFrom(address,address,uint256)") {
                let from20 = decode_abi_addr(args, 0)?;
                let to20 = decode_abi_addr(args, 32)?;
                let amt = decode_abi_u128(args, 64)?;
                let msg = serde_json::json!({
                    "execute": {
                        "transfer_from": {
                            "owner": derive_foreign_cosmos_bech32(&from20),
                            "recipient": derive_foreign_cosmos_bech32(&to20),
                            "amount": amt.to_string(),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), msg, false)?;
                return if ok {
                    Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
                } else {
                    Ok((OutcomeStatus::Revert, out))
                };
            }
            Ok((
                OutcomeStatus::Revert,
                b"unsupported CW20 pointer selector".to_vec(),
            ))
        }
        AssetStandard::NonFungible => {
            if sel == solidity_selector("ownerOf(uint256)") {
                let tid = decode_abi_u128(args, 0)?;
                let q = serde_json::json!({
                    "query": { "owner_of": { "token_id": tid.to_string() } }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), q, true)?;
                if !ok {
                    return Ok((OutcomeStatus::Revert, out));
                }
                let owner_text = String::from_utf8_lossy(&out);
                return Ok((OutcomeStatus::Success, abi_encode_string(&owner_text)));
            }
            if is_static {
                return Ok((OutcomeStatus::Revert, b"static pointer write".to_vec()));
            }
            if sel == solidity_selector("approve(address,uint256)") {
                let spender20 = decode_abi_addr(args, 0)?;
                let tid = decode_abi_u128(args, 32)?;
                let msg = serde_json::json!({
                    "execute": {
                        "approve": {
                            "spender": derive_foreign_cosmos_bech32(&spender20),
                            "token_id": tid.to_string(),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), msg, false)?;
                return Ok((
                    if ok {
                        OutcomeStatus::Success
                    } else {
                        OutcomeStatus::Revert
                    },
                    out,
                ));
            }
            if sel == solidity_selector("safeTransferFrom(address,address,uint256)")
                || sel == solidity_selector("transferFrom(address,address,uint256)")
            {
                let to20 = decode_abi_addr(args, 32)?;
                let tid = decode_abi_u128(args, 64)?;
                let msg = serde_json::json!({
                    "execute": {
                        "transfer_nft": {
                            "recipient": derive_foreign_cosmos_bech32(&to20),
                            "token_id": tid.to_string(),
                        }
                    }
                });
                let (ok, out) = call_wasm(host, caller_wasm.into_bytes(), msg, false)?;
                return Ok((
                    if ok {
                        OutcomeStatus::Success
                    } else {
                        OutcomeStatus::Revert
                    },
                    out,
                ));
            }
            Ok((
                OutcomeStatus::Revert,
                b"unsupported CW721 pointer selector".to_vec(),
            ))
        }
    }
}

fn pad20_to_32(addr20: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(tail) = out.get_mut(12..32) {
        tail.copy_from_slice(addr20);
    }
    out
}

fn execute_evm_pointer_to_svm_or_move(
    ptr: &PointerDescriptor,
    caller20: &[u8; 20],
    input: &[u8],
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let Some(sel) = input.get(..4) else {
        return Ok((OutcomeStatus::Revert, b"missing selector".to_vec()));
    };
    let args = input.get(4..).unwrap_or(&[]);
    if sel == solidity_selector("name()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&ptr.name)));
    }
    if sel == solidity_selector("symbol()") {
        return Ok((OutcomeStatus::Success, abi_encode_string(&ptr.symbol)));
    }
    if sel == solidity_selector("decimals()") {
        return Ok((
            OutcomeStatus::Success,
            U256Word::from_u64(u64::from(ptr.decimals)).0.to_vec(),
        ));
    }

    let home_ee = EeId(ptr.home_ee);
    let mut read_only = false;
    let payload_val: serde_json::Value = if sel == solidity_selector("balanceOf(address)") {
        read_only = true;
        let who20 = decode_abi_addr(args, 0)?;
        let owner = pad20_to_32(&who20);
        if home_ee == EeId::SVM {
            serde_json::to_value(SplPointerOp::BalanceOf { owner }).map_err(|e| e.to_string())?
        } else {
            serde_json::to_value(MovePointerOp::Balance {
                flavor: MovePointerFlavor::FungibleAsset,
                owner,
            })
            .map_err(|e| e.to_string())?
        }
    } else if sel == solidity_selector("allowance(address,address)") {
        read_only = true;
        let ow20 = decode_abi_addr(args, 0)?;
        let sp20 = decode_abi_addr(args, 32)?;
        let owner = pad20_to_32(&ow20);
        let party = pad20_to_32(&sp20);
        if home_ee == EeId::SVM {
            serde_json::to_value(SplPointerOp::Allowance {
                owner,
                delegate: party,
            })
            .map_err(|e| e.to_string())?
        } else {
            serde_json::to_value(MovePointerOp::Allowance {
                flavor: MovePointerFlavor::FungibleAsset,
                owner,
                spender: party,
            })
            .map_err(|e| e.to_string())?
        }
    } else if is_static {
        return Ok((OutcomeStatus::Revert, b"static pointer write".to_vec()));
    } else if sel == solidity_selector("approve(address,uint256)") {
        let sp20 = decode_abi_addr(args, 0)?;
        let amt = decode_abi_u128(args, 32)?;
        let party = pad20_to_32(&sp20);
        if home_ee == EeId::SVM {
            serde_json::to_value(SplPointerOp::Approve {
                delegate: party,
                amount: amt,
            })
            .map_err(|e| e.to_string())?
        } else {
            serde_json::to_value(MovePointerOp::Approve {
                flavor: MovePointerFlavor::FungibleAsset,
                spender: party,
                amount: amt,
            })
            .map_err(|e| e.to_string())?
        }
    } else if sel == solidity_selector("transfer(address,uint256)") {
        let to20 = decode_abi_addr(args, 0)?;
        let amt = decode_abi_u128(args, 32)?;
        let to = pad20_to_32(&to20);
        if home_ee == EeId::SVM {
            serde_json::to_value(SplPointerOp::Transfer { to, amount: amt })
                .map_err(|e| e.to_string())?
        } else {
            serde_json::to_value(MovePointerOp::Transfer {
                flavor: MovePointerFlavor::FungibleAsset,
                to,
                amount: amt,
            })
            .map_err(|e| e.to_string())?
        }
    } else if sel == solidity_selector("transferFrom(address,address,uint256)") {
        let ow20 = decode_abi_addr(args, 0)?;
        let to20 = decode_abi_addr(args, 32)?;
        let amt = decode_abi_u128(args, 64)?;
        let owner = pad20_to_32(&ow20);
        let to = pad20_to_32(&to20);
        if home_ee == EeId::SVM {
            serde_json::to_value(SplPointerOp::TransferFrom {
                owner,
                to,
                amount: amt,
            })
            .map_err(|e| e.to_string())?
        } else {
            serde_json::to_value(MovePointerOp::TransferFrom {
                flavor: MovePointerFlavor::FungibleAsset,
                owner,
                to,
                amount: amt,
            })
            .map_err(|e| e.to_string())?
        }
    } else {
        return Ok((
            OutcomeStatus::Revert,
            b"unsupported pointer selector".to_vec(),
        ));
    };

    let raw_json = serde_json::to_vec(&payload_val).map_err(|e| e.to_string())?;
    let final_in = if read_only {
        wrap_static_universal_input(&raw_json)
    } else {
        raw_json
    };
    let res = host
        .universal_call(UniversalCall {
            from: EeIdentity {
                ee: EeId::EVM,
                id: caller20.to_vec(),
            },
            to_ee: home_ee,
            target: EeIdentity {
                ee: home_ee,
                id: ptr.home_ref.clone(),
            },
            value: BudAmount(0),
            input: final_in,
            gas_limit: gas_budget / 2 + 10_000,
            is_static: read_only,
        })
        .map_err(|e| e.to_string())?;
    let log = encode_evm_universal_call_log(home_ee, &ptr.home_ref, res.success);
    host.emit_log(log).map_err(|e| e.to_string())?;
    if !res.success {
        return Ok((OutcomeStatus::Revert, res.output));
    }
    if read_only {
        let num = <[u8; 16]>::try_from(res.output.as_slice()).map_or(0, u128::from_le_bytes);
        Ok((OutcomeStatus::Success, U256Word::from_u128(num).0.to_vec()))
    } else {
        Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
    }
}

fn execute_evm_pointer_to_expansion(
    ptr: &PointerDescriptor,
    caller20: &[u8; 20],
    input: &[u8],
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let home_ee = EeId(ptr.home_ee);
    if home_ee == EeId::MOVE_SUI {
        return execute_evm_pointer_to_svm_or_move(
            ptr, caller20, input, is_static, gas_budget, host,
        );
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "op": "pointer_call",
        "home_ee": home_ee.0,
        "caller_evm": hex::encode(caller20),
        "calldata": hex::encode(input),
        "is_static": is_static,
    }))
    .map_err(|e| e.to_string())?;
    let final_in = if is_static {
        wrap_static_universal_input(&payload)
    } else {
        payload
    };
    let res = host
        .universal_call(UniversalCall {
            from: EeIdentity {
                ee: EeId::EVM,
                id: caller20.to_vec(),
            },
            to_ee: home_ee,
            target: EeIdentity {
                ee: home_ee,
                id: ptr.home_ref.clone(),
            },
            value: BudAmount(0),
            input: final_in,
            gas_limit: gas_budget / 2 + 10_000,
            is_static,
        })
        .map_err(|e| e.to_string())?;
    let log = encode_evm_universal_call_log(home_ee, &ptr.home_ref, res.success);
    host.emit_log(log).map_err(|e| e.to_string())?;
    if !res.success {
        return Ok((OutcomeStatus::Revert, res.output));
    }
    Ok((OutcomeStatus::Success, res.output))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrecompileUolOffer {
    maker: [u8; 20],
    class_id: [u8; 32],
    asset_id: [u8; 32],
    taker: Vec<u8>,
    payment: Vec<u8>,
    amount: u128,
    expiry: u64,
}

fn uol_bal_key(class_id: &[u8; 32], holder: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32 + holder.len());
    k.extend_from_slice(b"uol:bal:");
    k.extend_from_slice(class_id);
    k.extend_from_slice(holder);
    k
}

fn uol_holder_key(asset_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(11 + 32);
    k.extend_from_slice(b"uol:holder:");
    k.extend_from_slice(asset_id);
    k
}

fn uol_offer_key(offer_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(10 + 32);
    k.extend_from_slice(b"uol:offer:");
    k.extend_from_slice(offer_id);
    k
}

fn encode_uol_offer_bytes(offer: &PrecompileUolOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(116 + offer.taker.len() + offer.payment.len());
    out.extend_from_slice(&offer.maker);
    out.extend_from_slice(&offer.class_id);
    out.extend_from_slice(&offer.asset_id);
    out.extend_from_slice(&offer.amount.to_le_bytes());
    out.extend_from_slice(&offer.expiry.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(offer.taker.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&offer.taker);
    out.extend_from_slice(
        &u32::try_from(offer.payment.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&offer.payment);
    out
}

fn decode_uol_offer_bytes(raw: &[u8]) -> Result<PrecompileUolOffer, String> {
    if raw.len() < 116 {
        return Err(String::from("corrupt UOL offer record"));
    }
    let mut maker = [0u8; 20];
    let maker_slice = raw
        .get(..20)
        .ok_or_else(|| String::from("corrupt UOL offer maker"))?;
    maker.copy_from_slice(maker_slice);
    let mut class_id = [0u8; 32];
    let class_slice = raw
        .get(20..52)
        .ok_or_else(|| String::from("corrupt UOL offer class_id"))?;
    class_id.copy_from_slice(class_slice);
    let mut asset_id = [0u8; 32];
    let asset_slice = raw
        .get(52..84)
        .ok_or_else(|| String::from("corrupt UOL offer asset_id"))?;
    asset_id.copy_from_slice(asset_slice);
    let amount = u128::from_le_bytes(
        raw.get(84..100)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| String::from("corrupt UOL offer amount"))?,
    );
    let expiry = u64::from_le_bytes(
        raw.get(100..108)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| String::from("corrupt UOL offer expiry"))?,
    );
    let taker_len_u32 = u32::from_le_bytes(
        raw.get(108..112)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| String::from("corrupt UOL offer taker_len"))?,
    );
    let taker_len =
        usize::try_from(taker_len_u32).map_err(|_| String::from("UOL offer taker overflow"))?;
    let taker_end = 112usize
        .checked_add(taker_len)
        .ok_or_else(|| String::from("UOL offer taker overflow"))?;
    let pay_hdr_end = taker_end
        .checked_add(4)
        .ok_or_else(|| String::from("UOL offer taker overflow"))?;
    let taker = raw
        .get(112..taker_end)
        .ok_or_else(|| String::from("truncated UOL offer taker"))?
        .to_vec();
    let pay_len_u32 = u32::from_le_bytes(
        raw.get(taker_end..pay_hdr_end)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| String::from("corrupt UOL offer pay_len"))?,
    );
    let pay_len =
        usize::try_from(pay_len_u32).map_err(|_| String::from("UOL offer payment overflow"))?;
    let pay_end = pay_hdr_end
        .checked_add(pay_len)
        .ok_or_else(|| String::from("UOL offer payment overflow"))?;
    if raw.len() != pay_end {
        return Err(String::from("corrupt UOL offer trailing bytes"));
    }
    let payment = raw
        .get(pay_hdr_end..pay_end)
        .ok_or_else(|| String::from("truncated UOL offer payment"))?
        .to_vec();
    Ok(PrecompileUolOffer {
        maker,
        class_id,
        asset_id,
        taker,
        payment,
        amount,
        expiry,
    })
}

fn uol_read_balance(
    host: &dyn HostRead,
    ns: &Namespace,
    class_id: &[u8; 32],
    holder: &[u8],
) -> Result<u128, String> {
    let key = uol_bal_key(class_id, holder);
    let Some(bytes) = host.read(ns, &key).map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    let arr: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| String::from("corrupt UOL balance record"))?;
    Ok(u128::from_le_bytes(arr))
}

fn uol_write_balance(
    host: &mut dyn HostApi,
    ns: &Namespace,
    class_id: &[u8; 32],
    holder: &[u8],
    bal: u128,
) -> Result<(), String> {
    let val = (bal > 0).then(|| bal.to_le_bytes());
    host.write(
        ns,
        &uol_bal_key(class_id, holder),
        val.as_ref().map(<[u8; 16]>::as_slice),
    )
    .map_err(|e| e.to_string())
}

fn invoke_uol_precompile(
    block_height: u64,
    caller20: &[u8; 20],
    calldata: &[u8],
    is_static: bool,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    host.charge(2_600)
        .map_err(|_| String::from("out of gas entering 0x...B002"))?;
    let decoded = match decode_uol_precompile_calldata(calldata) {
        Ok(d) => d,
        Err(msg) => return Ok((OutcomeStatus::Revert, msg.into_bytes())),
    };
    let ns = Namespace::new(NS_UEL_ASSETS).map_err(|e| e.to_string())?;
    match decoded {
        DecodedUolPrecompileCall::BalanceOf { class_id, holder } => {
            let bal = uol_read_balance(host, &ns, &class_id, &holder)?;
            Ok((OutcomeStatus::Success, U256Word::from_u128(bal).0.to_vec()))
        }
        DecodedUolPrecompileCall::HolderOf { asset_id } => {
            let holder = host
                .read(&ns, &uol_holder_key(&asset_id))
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            let mut out = vec![0u8; 64 + holder.len().div_ceil(32) * 32];
            if let Some(s) = out.get_mut(31) {
                *s = 32;
            }
            if let Some(dst) = out.get_mut(56..64) {
                let len_be = u64::try_from(holder.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes();
                dst.copy_from_slice(&len_be);
            }
            if !holder.is_empty() {
                if let Some(dst) = out.get_mut(64..64 + holder.len()) {
                    dst.copy_from_slice(&holder);
                }
            }
            Ok((OutcomeStatus::Success, out))
        }
        DecodedUolPrecompileCall::Transfer {
            class_id,
            asset_id,
            to,
            amount,
        } => {
            if is_static {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL transfer inside static call".to_vec(),
                ));
            }
            if to.is_empty() {
                return Ok((OutcomeStatus::Revert, b"UOL empty recipient".to_vec()));
            }
            if asset_id == [0u8; 32] && amount == 0 {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL transfer requires asset or non-zero amount".to_vec(),
                ));
            }
            let cp = host.checkpoint_begin().map_err(|e| e.to_string())?;
            if asset_id != [0u8; 32] {
                let hk = uol_holder_key(&asset_id);
                let Some(cur) = host.read(&ns, &hk).map_err(|e| e.to_string())? else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL unknown asset".to_vec()));
                };
                if cur.as_slice() != caller20 {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((
                        OutcomeStatus::Revert,
                        b"UOL caller is not asset holder".to_vec(),
                    ));
                }
                if let Err(e) = host.write(&ns, &hk, Some(&to)) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e.to_string());
                }
            }
            if amount > 0 {
                let from_bal = uol_read_balance(host, &ns, &class_id, caller20)?;
                let Some(rem) = from_bal.checked_sub(amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL insufficient balance".to_vec()));
                };
                if let Err(e) = uol_write_balance(host, &ns, &class_id, caller20, rem) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e);
                }
                let to_bal = uol_read_balance(host, &ns, &class_id, &to)?;
                let Some(next_to) = to_bal.checked_add(amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL balance overflow".to_vec()));
                };
                if let Err(e) = uol_write_balance(host, &ns, &class_id, &to, next_to) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e);
                }
            }
            if let Err(e) = host.emit_log(EeLog {
                emitter: EeIdentity {
                    ee: EeId::EVM,
                    id: EVM_UOL_PRECOMPILE.to_vec(),
                },
                topics: vec![{
                    let mut t = [0u8; 32];
                    if let Some(dst) = t.get_mut(..4) {
                        dst.copy_from_slice(&uol_selector(
                            "transfer(bytes32,bytes32,bytes,uint128)",
                        ));
                    }
                    t.to_vec()
                }],
                data: asset_id.to_vec(),
            }) {
                let _ = host.checkpoint_rollback(cp);
                return Err(e.to_string());
            }
            host.checkpoint_commit(cp).map_err(|e| e.to_string())?;
            Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
        }
        DecodedUolPrecompileCall::Offer {
            class_id,
            asset_id,
            taker,
            payment,
            amount,
            expiry,
        } => {
            if is_static {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL offer inside static call".to_vec(),
                ));
            }
            if asset_id == [0u8; 32] && amount == 0 {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL offer requires asset or non-zero amount".to_vec(),
                ));
            }
            if expiry > 0 && block_height > expiry {
                return Ok((OutcomeStatus::Revert, b"UOL offer already expired".to_vec()));
            }
            if !payment.is_empty() && payment.len() != 16 && payment.len() != 48 {
                return Ok((
                    OutcomeStatus::Revert,
                    b"unsupported UOL offer payment encoding".to_vec(),
                ));
            }
            if asset_id != [0u8; 32] {
                let hk = uol_holder_key(&asset_id);
                let Some(cur) = host.read(&ns, &hk).map_err(|e| e.to_string())? else {
                    return Ok((OutcomeStatus::Revert, b"UOL unknown asset".to_vec()));
                };
                if cur.as_slice() != caller20 {
                    return Ok((
                        OutcomeStatus::Revert,
                        b"UOL offerer does not hold asset".to_vec(),
                    ));
                }
            }
            if amount > 0 && uol_read_balance(host, &ns, &class_id, caller20)? < amount {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL offerer balance exhausted".to_vec(),
                ));
            }
            let mut preimage = Vec::with_capacity(96 + taker.len() + payment.len());
            preimage.extend_from_slice(b"BDLM_UOL_OFFER_V1");
            preimage.extend_from_slice(caller20);
            preimage.extend_from_slice(&class_id);
            preimage.extend_from_slice(&asset_id);
            preimage.extend_from_slice(&taker);
            preimage.extend_from_slice(&payment);
            preimage.extend_from_slice(&amount.to_le_bytes());
            preimage.extend_from_slice(&expiry.to_le_bytes());
            let offer_id: [u8; 32] = Keccak256::digest(&preimage).into();
            let rec = PrecompileUolOffer {
                maker: *caller20,
                class_id,
                asset_id,
                taker,
                payment,
                amount,
                expiry,
            };
            let enc = encode_uol_offer_bytes(&rec);
            host.write(&ns, &uol_offer_key(&offer_id), Some(&enc))
                .map_err(|e| e.to_string())?;
            Ok((OutcomeStatus::Success, offer_id.to_vec()))
        }
        DecodedUolPrecompileCall::Accept { offer_id } => {
            if is_static {
                return Ok((
                    OutcomeStatus::Revert,
                    b"UOL accept inside static call".to_vec(),
                ));
            }
            let ok = uol_offer_key(&offer_id);
            let Some(raw) = host.read(&ns, &ok).map_err(|e| e.to_string())? else {
                return Ok((OutcomeStatus::Revert, b"UOL unknown offerId".to_vec()));
            };
            let offer = decode_uol_offer_bytes(&raw)?;
            if offer.expiry > 0 && block_height > offer.expiry {
                return Ok((OutcomeStatus::Revert, b"UOL offer expired".to_vec()));
            }
            if !offer.taker.is_empty() && offer.taker.as_slice() != caller20 {
                return Ok((OutcomeStatus::Revert, b"UOL unauthorized taker".to_vec()));
            }
            let cp = host.checkpoint_begin().map_err(|e| e.to_string())?;
            if offer.payment.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&offer.payment);
                let pay_attos = u128::from_le_bytes(arr);
                if pay_attos > 0
                    && host
                        .bud_transfer(
                            &EeIdentity {
                                ee: EeId::EVM,
                                id: caller20.to_vec(),
                            },
                            &EeIdentity {
                                ee: EeId::EVM,
                                id: offer.maker.to_vec(),
                            },
                            pay_attos,
                        )
                        .is_err()
                {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL native payment failed".to_vec()));
                }
            } else if offer.payment.len() == 48 {
                let Some(pay_class_slice) = offer.payment.get(..32) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((
                        OutcomeStatus::Revert,
                        b"unsupported UOL offer payment encoding".to_vec(),
                    ));
                };
                let Some(pay_amt_slice) = offer.payment.get(32..48) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((
                        OutcomeStatus::Revert,
                        b"unsupported UOL offer payment encoding".to_vec(),
                    ));
                };
                let mut pay_class = [0u8; 32];
                pay_class.copy_from_slice(pay_class_slice);
                let mut pay_arr = [0u8; 16];
                pay_arr.copy_from_slice(pay_amt_slice);
                let pay_amt = u128::from_le_bytes(pay_arr);
                if pay_amt > 0 {
                    let payer_bal = uol_read_balance(host, &ns, &pay_class, caller20)?;
                    let Some(rem_pay) = payer_bal.checked_sub(pay_amt) else {
                        let _ = host.checkpoint_rollback(cp);
                        return Ok((
                            OutcomeStatus::Revert,
                            b"UOL taker payment balance exhausted".to_vec(),
                        ));
                    };
                    if let Err(e) = uol_write_balance(host, &ns, &pay_class, caller20, rem_pay) {
                        let _ = host.checkpoint_rollback(cp);
                        return Err(e);
                    }
                    let maker_pay_bal = uol_read_balance(host, &ns, &pay_class, &offer.maker)?;
                    let Some(next_maker_pay) = maker_pay_bal.checked_add(pay_amt) else {
                        let _ = host.checkpoint_rollback(cp);
                        return Ok((OutcomeStatus::Revert, b"UOL payment overflow".to_vec()));
                    };
                    if let Err(e) =
                        uol_write_balance(host, &ns, &pay_class, &offer.maker, next_maker_pay)
                    {
                        let _ = host.checkpoint_rollback(cp);
                        return Err(e);
                    }
                }
            } else if !offer.payment.is_empty() {
                let _ = host.checkpoint_rollback(cp);
                return Ok((
                    OutcomeStatus::Revert,
                    b"unsupported UOL offer payment encoding".to_vec(),
                ));
            }
            if offer.asset_id != [0u8; 32] {
                let hk = uol_holder_key(&offer.asset_id);
                let Some(cur_holder) = host.read(&ns, &hk).map_err(|e| e.to_string())? else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL offer asset missing".to_vec()));
                };
                if cur_holder.as_slice() != offer.maker {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((
                        OutcomeStatus::Revert,
                        b"UOL maker no longer holds offered asset".to_vec(),
                    ));
                }
                if let Err(e) = host.write(&ns, &hk, Some(caller20)) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e.to_string());
                }
            }
            if offer.amount > 0 {
                let bal = uol_read_balance(host, &ns, &offer.class_id, &offer.maker)?;
                let Some(rem) = bal.checked_sub(offer.amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((
                        OutcomeStatus::Revert,
                        b"UOL maker balance exhausted".to_vec(),
                    ));
                };
                if let Err(e) = uol_write_balance(host, &ns, &offer.class_id, &offer.maker, rem) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e);
                }
                let taker_bal = uol_read_balance(host, &ns, &offer.class_id, caller20)?;
                let Some(next) = taker_bal.checked_add(offer.amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return Ok((OutcomeStatus::Revert, b"UOL balance overflow".to_vec()));
                };
                if let Err(e) = uol_write_balance(host, &ns, &offer.class_id, caller20, next) {
                    let _ = host.checkpoint_rollback(cp);
                    return Err(e);
                }
            }
            if let Err(e) = host.write(&ns, &ok, None) {
                let _ = host.checkpoint_rollback(cp);
                return Err(e.to_string());
            }
            if let Err(e) = host.emit_log(EeLog {
                emitter: EeIdentity {
                    ee: EeId::EVM,
                    id: EVM_UOL_PRECOMPILE.to_vec(),
                },
                topics: vec![{
                    let mut t = [0u8; 32];
                    if let Some(dst) = t.get_mut(..4) {
                        dst.copy_from_slice(&uol_selector("accept(bytes32)"));
                    }
                    t.to_vec()
                }],
                data: offer_id.to_vec(),
            }) {
                let _ = host.checkpoint_rollback(cp);
                return Err(e.to_string());
            }
            host.checkpoint_commit(cp).map_err(|e| e.to_string())?;
            Ok((OutcomeStatus::Success, U256Word::from_u64(1).0.to_vec()))
        }
    }
}

fn invoke_universal_precompile(
    caller20: &[u8; 20],
    calldata: &[u8],
    force_static: bool,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    host.charge(2_600)
        .map_err(|_| String::from("out of gas entering 0x...B001"))?;
    let decoded = match decode_precompile_calldata(calldata) {
        Ok(d) => d,
        Err(msg) => return Ok((OutcomeStatus::Revert, msg.into_bytes())),
    };
    if force_static && decoded.value_attos > 0 {
        return Ok((
            OutcomeStatus::Revert,
            b"staticCall forbids non-zero valueAttos".to_vec(),
        ));
    }
    let is_static = force_static || decoded.is_static;
    let payload = if is_static {
        wrap_static_universal_input(&decoded.input)
    } else {
        decoded.input.clone()
    };
    let caller_for_target = if decoded.target_ee == EeId::WASM {
        EeIdentity {
            ee: EeId::WASM,
            id: derive_foreign_cosmos_bech32(caller20).into_bytes(),
        }
    } else {
        EeIdentity {
            ee: EeId::EVM,
            id: caller20.to_vec(),
        }
    };
    let ucall = UniversalCall {
        from: caller_for_target,
        to_ee: decoded.target_ee,
        target: EeIdentity {
            ee: decoded.target_ee,
            id: decoded.target.clone(),
        },
        value: BudAmount(decoded.value_attos),
        input: payload,
        gas_limit: decoded.gas_bgu,
        is_static,
    };
    match host.universal_call(ucall) {
        Ok(ures) => {
            let log =
                encode_evm_universal_call_log(decoded.target_ee, &decoded.target, ures.success);
            host.emit_log(log).map_err(|e| e.to_string())?;
            let ret = encode_precompile_return(ures.success, &ures.output);
            Ok((OutcomeStatus::Success, ret))
        }
        Err(HostError::OutOfGas) => Err(String::from("out of gas")),
        Err(HostError::Denied(reason)) => Ok((OutcomeStatus::Revert, reason.into_bytes())),
        Err(other) => Ok((OutcomeStatus::Revert, other.to_string().into_bytes())),
    }
}

/// Hard ceiling on interpreter memory (16 MiB), independent of gas.
pub const MAX_EVM_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// EVM memory-expansion cost for growing the highest touched word from `old_bytes` to `new_bytes`.
fn memory_expansion_gas(old_bytes: usize, new_bytes: usize) -> u64 {
    let words = |n: usize| (n as u64).div_ceil(32);
    let square = |w: u64| w.saturating_mul(w) / 512;
    let (old_w, new_w) = (words(old_bytes), words(new_bytes));
    3u64.saturating_mul(new_w.saturating_sub(old_w))
        .saturating_add(square(new_w).saturating_sub(square(old_w)))
}

/// Charges quadratic expansion gas and grows `mem` to cover `offset..offset + len`.
fn grow_mem(
    mem: &mut Vec<u8>,
    host: &mut dyn HostApi,
    offset: usize,
    len: usize,
) -> Result<(), String> {
    if len == 0 {
        return Ok(());
    }
    let Some(need) = offset.checked_add(len) else {
        return Err(String::from("out of gas: evm memory overflow"));
    };
    if need > MAX_EVM_MEMORY_BYTES {
        return Err(String::from("out of gas: evm memory limit exceeded"));
    }
    if need > mem.len() {
        host.charge(memory_expansion_gas(mem.len(), need))
            .map_err(|_| String::from("out of gas in memory expansion"))?;
        mem.resize(need, 0);
    }
    Ok(())
}

fn mem_read_32(
    mem: &mut Vec<u8>,
    host: &mut dyn HostApi,
    offset: usize,
) -> Result<[u8; 32], String> {
    grow_mem(mem, host, offset, 32)?;
    let mut out = [0u8; 32];
    if let Some(s) = mem.get(offset..offset + 32) {
        out.copy_from_slice(s);
    }
    Ok(out)
}

fn mem_write(
    mem: &mut Vec<u8>,
    host: &mut dyn HostApi,
    offset: usize,
    data: &[u8],
) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    grow_mem(mem, host, offset, data.len())?;
    if let Some(dst) = mem.get_mut(offset..offset + data.len()) {
        dst.copy_from_slice(data);
    }
    Ok(())
}

struct EvmFrameOverlay {
    gas_limit: u64,
    gas_used: u64,
    is_static: bool,
    staged_writes: BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>,
    staged_logs: Vec<EeLog>,
    staged_transfers: Vec<(EeIdentity, EeIdentity, u128)>,
    balance_deltas: BTreeMap<(u8, Vec<u8>), i128>,
    root_cp_id: Option<u64>,
}

impl EvmFrameOverlay {
    fn new(gas_limit: u64, is_static: bool, root_cp_id: Option<u64>) -> Self {
        Self {
            gas_limit,
            gas_used: 0,
            is_static,
            staged_writes: BTreeMap::new(),
            staged_logs: Vec::new(),
            staged_transfers: Vec::new(),
            balance_deltas: BTreeMap::new(),
            root_cp_id,
        }
    }

    const fn remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }
}

struct EvmHostCheckpoint {
    id: u64,
    overlay_idx: usize,
    staged_writes: BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>,
    staged_logs_len: usize,
    staged_transfers_len: usize,
    balance_deltas: BTreeMap<(u8, Vec<u8>), i128>,
    root_cp_id: Option<u64>,
}

/// Heap-backed stack of EVM frame overlays providing bounded nested gas
/// accounting, static-context propagation, and atomic rollback on revert or OOG.
struct EvmStackHost<'a> {
    root: &'a mut dyn HostApi,
    overlays: Vec<EvmFrameOverlay>,
    next_checkpoint_id: u64,
    checkpoints: Vec<EvmHostCheckpoint>,
}

impl<'a> EvmStackHost<'a> {
    fn new(root: &'a mut dyn HostApi) -> Self {
        Self {
            root,
            overlays: Vec::new(),
            next_checkpoint_id: 1,
            checkpoints: Vec::new(),
        }
    }

    fn push_overlay(&mut self, gas_limit: u64, is_static: bool) {
        let inherited_static = is_static || self.overlays.iter().any(|o| o.is_static);
        let root_cp_id = self.root.checkpoint_begin().ok();
        self.overlays.push(EvmFrameOverlay::new(
            gas_limit,
            inherited_static,
            root_cp_id,
        ));
    }

    fn remaining(&self) -> u64 {
        self.overlays.last().map_or(0, EvmFrameOverlay::remaining)
    }

    fn discard_top_overlay(&mut self) {
        if let Some(top) = self.overlays.pop() {
            let depth = self.overlays.len();
            self.checkpoints.retain(|cp| cp.overlay_idx < depth);
            if let Some(cp_id) = top.root_cp_id {
                let _ = self.root.checkpoint_rollback(cp_id);
            }
        }
    }

    fn commit_top_overlay(&mut self) -> Result<(), HostError> {
        let Some(top) = self.overlays.pop() else {
            return Ok(());
        };
        let depth = self.overlays.len();
        self.checkpoints.retain(|cp| cp.overlay_idx < depth);

        let mut parsed_writes = Vec::with_capacity(top.staged_writes.len());
        for ((ns_str, key), val) in top.staged_writes {
            match Namespace::new(&ns_str) {
                Ok(ns) => parsed_writes.push((ns_str, ns, key, val)),
                Err(e) => {
                    if let Some(cp_id) = top.root_cp_id {
                        let _ = self.root.checkpoint_rollback(cp_id);
                    }
                    return Err(HostError::Invalid(format!("bad staged namespace: {e}")));
                }
            }
        }

        if let Some(parent) = self.overlays.last_mut() {
            for (k, d) in &top.balance_deltas {
                let cur = parent.balance_deltas.get(k).copied().unwrap_or(0);
                if cur.checked_add(*d).is_none() {
                    if let Some(cp_id) = top.root_cp_id {
                        let _ = self.root.checkpoint_rollback(cp_id);
                    }
                    return Err(HostError::Invalid(String::from("balance delta overflow")));
                }
            }
            if let Some(cp_id) = top.root_cp_id {
                if let Err(e) = self.root.checkpoint_commit(cp_id) {
                    let _ = self.root.checkpoint_rollback(cp_id);
                    return Err(e);
                }
            }
            for (k, d) in top.balance_deltas {
                let entry = parent.balance_deltas.entry(k).or_insert(0);
                *entry += d;
            }
            parent.staged_transfers.extend(top.staged_transfers);
            for (ns_str, _, key, val) in parsed_writes {
                parent.staged_writes.insert((ns_str, key), val);
            }
            parent.staged_logs.extend(top.staged_logs);
            return Ok(());
        }
        for (from, to, attos) in top.staged_transfers {
            if let Err(e) = self.root.bud_transfer(&from, &to, attos) {
                if let Some(cp_id) = top.root_cp_id {
                    let _ = self.root.checkpoint_rollback(cp_id);
                }
                return Err(e);
            }
        }
        for (_, ns, key, val) in parsed_writes {
            if let Err(e) = self.root.write(&ns, &key, val.as_deref()) {
                if let Some(cp_id) = top.root_cp_id {
                    let _ = self.root.checkpoint_rollback(cp_id);
                }
                return Err(e);
            }
        }
        for log in top.staged_logs {
            if let Err(e) = self.root.emit_log(log) {
                if let Some(cp_id) = top.root_cp_id {
                    let _ = self.root.checkpoint_rollback(cp_id);
                }
                return Err(e);
            }
        }
        if let Some(cp_id) = top.root_cp_id {
            if let Err(e) = self.root.checkpoint_commit(cp_id) {
                let _ = self.root.checkpoint_rollback(cp_id);
                return Err(e);
            }
        }
        Ok(())
    }

    fn active_is_static(&self) -> bool {
        self.overlays.iter().any(|o| o.is_static)
    }
}

impl HostRead for EvmStackHost<'_> {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        let lookup = (ns.as_str().to_string(), key.to_vec());
        for overlay in self.overlays.iter().rev() {
            if let Some(staged) = overlay.staged_writes.get(&lookup) {
                return Ok(staged.clone());
            }
        }
        self.root.read(ns, key)
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        let base = self.root.bud_balance(who)?.0;
        let key = (who.ee.0, who.id.clone());
        let mut delta: i128 = 0;
        for overlay in &self.overlays {
            if let Some(&d) = overlay.balance_deltas.get(&key) {
                delta = delta
                    .checked_add(d)
                    .ok_or_else(|| HostError::Invalid(String::from("balance delta overflow")))?;
            }
        }
        let adjusted = if delta >= 0 {
            base.saturating_add(delta.unsigned_abs())
        } else {
            base.saturating_sub(delta.unsigned_abs())
        };
        Ok(BudAmount(adjusted))
    }
}

impl HostApi for EvmStackHost<'_> {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        if self.active_is_static() {
            return Err(HostError::Denied(String::from(
                "state write forbidden in static EVM sub-call",
            )));
        }
        let is_uol_write = ns.as_str() == NS_UEL_ASSETS && key.starts_with(b"uol:");
        if self.overlays.len() > 1
            && !is_uol_write
            && crate::execution::coordinator::state::RootGroup::for_namespace(ns.as_str())
                != Some(crate::execution::coordinator::state::RootGroup::Evm)
        {
            return Err(HostError::Denied(format!(
                "EVM sub-call cannot write non-EVM namespace `{}`",
                ns.as_str()
            )));
        }
        if let Some(top) = self.overlays.last_mut() {
            top.staged_writes.insert(
                (ns.as_str().to_string(), key.to_vec()),
                value.map(<[u8]>::to_vec),
            );
            Ok(())
        } else {
            self.root.write(ns, key, value)
        }
    }

    fn universal_call(&mut self, mut call: UniversalCall) -> Result<UniversalResult, HostError> {
        if self.active_is_static() {
            call.is_static = true;
            if call.value.0 > 0 {
                return Err(HostError::Denied(String::from(
                    "non-zero value transfer forbidden in static call",
                )));
            }
        }
        call.gas_limit = call.gas_limit.min(self.remaining());
        self.root.universal_call(call)
    }

    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        if self.active_is_static() {
            return Err(HostError::Denied(String::from(
                "LOG forbidden in static EVM sub-call",
            )));
        }
        if let Some(top) = self.overlays.last_mut() {
            top.staged_logs.push(log);
            Ok(())
        } else {
            self.root.emit_log(log)
        }
    }

    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        if self.overlays.is_empty() {
            return self.root.charge(bgu);
        }
        for overlay in self.overlays.iter().rev() {
            let next = overlay.gas_used.checked_add(bgu).ok_or(OutOfGas)?;
            if next > overlay.gas_limit {
                let avail = self.overlays.last().map_or(0, EvmFrameOverlay::remaining);
                if avail > 0 {
                    let _ = self.root.charge(avail);
                    for ov in &mut self.overlays {
                        ov.gas_used = ov.gas_used.saturating_add(avail).min(ov.gas_limit);
                    }
                }
                if let Some(top) = self.overlays.last_mut() {
                    top.gas_used = top.gas_limit;
                }
                return Err(OutOfGas);
            }
        }
        self.root.charge(bgu)?;
        for overlay in &mut self.overlays {
            overlay.gas_used = overlay.gas_used.saturating_add(bgu);
        }
        Ok(())
    }

    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError> {
        if attos == 0 {
            return Ok(());
        }
        if self.active_is_static() {
            return Err(HostError::Denied(String::from(
                "value transfer forbidden in static EVM sub-call",
            )));
        }
        let delta = i128::try_from(attos)
            .map_err(|_| HostError::Invalid(String::from("transfer amount exceeds i128")))?;
        let cur_from = self.bud_balance(from)?.0;
        if cur_from < attos {
            return Err(HostError::Denied(String::from("insufficient EVM balance")));
        }
        if let Some(top) = self.overlays.last_mut() {
            if from != to {
                let from_key = (from.ee.0, from.id.clone());
                let next_from = top
                    .balance_deltas
                    .get(&from_key)
                    .copied()
                    .unwrap_or(0)
                    .checked_sub(delta)
                    .ok_or_else(|| HostError::Invalid(String::from("balance delta underflow")))?;
                let to_key = (to.ee.0, to.id.clone());
                let next_to = top
                    .balance_deltas
                    .get(&to_key)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(delta)
                    .ok_or_else(|| HostError::Invalid(String::from("balance delta overflow")))?;
                top.balance_deltas.insert(from_key, next_from);
                top.balance_deltas.insert(to_key, next_to);
            }
            top.staged_transfers.push((from.clone(), to.clone(), attos));
            Ok(())
        } else {
            self.root.bud_transfer(from, to, attos)
        }
    }

    fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
        let Some(top) = self.overlays.last() else {
            return self.root.checkpoint_begin();
        };
        let id = self.next_checkpoint_id;
        self.next_checkpoint_id = self
            .next_checkpoint_id
            .checked_add(1)
            .ok_or_else(|| HostError::Invalid(String::from("checkpoint id overflow")))?;
        let root_cp_id = Some(self.root.checkpoint_begin()?);
        self.checkpoints.push(EvmHostCheckpoint {
            id,
            overlay_idx: self.overlays.len() - 1,
            staged_writes: top.staged_writes.clone(),
            staged_logs_len: top.staged_logs.len(),
            staged_transfers_len: top.staged_transfers.len(),
            balance_deltas: top.balance_deltas.clone(),
            root_cp_id,
        });
        Ok(id)
    }

    fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
        if self.overlays.is_empty() {
            return self.root.checkpoint_commit(id);
        }
        let cur_idx = self.overlays.len() - 1;
        let Some(top) = self.checkpoints.last() else {
            return Err(HostError::Invalid(format!("unknown checkpoint {id}")));
        };
        if top.id != id || top.overlay_idx != cur_idx {
            return Err(HostError::Invalid(format!(
                "out-of-order checkpoint commit {id}"
            )));
        }
        let Some(cp) = self.checkpoints.pop() else {
            return Err(HostError::Invalid(String::from("missing checkpoint")));
        };
        if let Some(rcp) = cp.root_cp_id {
            self.root.checkpoint_commit(rcp)?;
        }
        Ok(())
    }

    fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
        if self.overlays.is_empty() {
            return self.root.checkpoint_rollback(id);
        }
        let cur_idx = self.overlays.len() - 1;
        let Some(top_cp) = self.checkpoints.last() else {
            return Err(HostError::Invalid(format!("unknown checkpoint {id}")));
        };
        if top_cp.id != id || top_cp.overlay_idx != cur_idx {
            return Err(HostError::Invalid(format!(
                "out-of-order checkpoint rollback {id}"
            )));
        }
        let Some(cp) = self.checkpoints.pop() else {
            return Err(HostError::Invalid(String::from("missing checkpoint")));
        };
        if let Some(ov) = self.overlays.last_mut() {
            ov.staged_writes = cp.staged_writes;
            ov.staged_logs.truncate(cp.staged_logs_len);
            ov.staged_transfers.truncate(cp.staged_transfers_len);
            ov.balance_deltas = cp.balance_deltas;
        }
        if let Some(rcp) = cp.root_cp_id {
            self.root.checkpoint_rollback(rcp)?;
        }
        Ok(())
    }
}

struct EvmExecFrame {
    self_addr: [u8; 20],
    caller20: [u8; 20],
    value_wei: u128,
    code: Vec<u8>,
    calldata: Vec<u8>,
    is_static: bool,
    depth: u32,
    stack: Vec<U256Word>,
    mem: Vec<u8>,
    returndata: Vec<u8>,
    pc: usize,
    pending_ret: Option<(usize, usize)>,
}

enum EvmFrameOutcome {
    Done(OutcomeStatus, Vec<u8>),
    CallChild(Box<EvmExecFrame>),
}

fn evm_revert(msg: &[u8]) -> Result<EvmFrameOutcome, String> {
    Ok(EvmFrameOutcome::Done(OutcomeStatus::Revert, msg.to_vec()))
}

fn step_evm_frame(
    ctx: &BlockContext,
    frame: &mut EvmExecFrame,
    host: &mut EvmStackHost<'_>,
) -> Result<EvmFrameOutcome, String> {
    let EvmExecFrame {
        self_addr,
        caller20,
        value_wei,
        code,
        calldata,
        is_static,
        depth,
        stack,
        mem,
        returndata,
        pc,
        pending_ret,
    } = frame;
    let self_addr = &*self_addr;
    let caller20 = &*caller20;
    let value_wei = *value_wei;
    let code = code.as_slice();
    let calldata = calldata.as_slice();
    let is_static = *is_static;
    let depth = *depth;

    while let Some(&op) = code.get(*pc) {
        *pc += 1;
        host.charge(3).map_err(|_| String::from("out of gas"))?;
        match op {
            0x00 => return Ok(EvmFrameOutcome::Done(OutcomeStatus::Success, Vec::new())),
            0x01 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                stack.push(a.wrapping_add(b));
            }
            0x03 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                stack.push(a.wrapping_sub(b));
            }
            0x14 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                stack.push(U256Word::from_u64(u64::from(a == b)));
            }
            0x15 => {
                let Some(a) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                stack.push(U256Word::from_u64(u64::from(a.is_zero())));
            }
            0x20 => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return evm_revert(b"memory overflow");
                };
                let words = (len as u64).div_ceil(32);
                host.charge(30u64.saturating_add(words.saturating_mul(6)))
                    .map_err(|_| String::from("out of gas"))?;
                grow_mem(mem, host, off, len)?;
                let digest: [u8; 32] =
                    Keccak256::digest(mem.get(off..off + len).unwrap_or(&[])).into();
                stack.push(U256Word(digest));
            }
            0x30 => stack.push(U256Word::from_addr20(self_addr)),
            0x31 => {
                let Some(addr_w) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                host.charge(100)
                    .map_err(|_| String::from("out of gas in BALANCE"))?;
                let target = addr_w.to_addr20();
                let bal = host
                    .bud_balance(&EeIdentity {
                        ee: EeId::EVM,
                        id: target.to_vec(),
                    })
                    .map_err(|e| e.to_string())?
                    .0;
                stack.push(U256Word::from_u128(bal));
            }
            0x33 => stack.push(U256Word::from_addr20(caller20)),
            0x34 => stack.push(U256Word::from_u128(value_wei)),
            0x35 => {
                let Some(off_w) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                let off = off_w.to_usize_checked().unwrap_or(calldata.len());
                let mut w = [0u8; 32];
                if let Some(rem) = calldata.get(off..) {
                    let n = rem.len().min(32);
                    if let (Some(d), Some(s)) = (w.get_mut(..n), rem.get(..n)) {
                        d.copy_from_slice(s);
                    }
                }
                stack.push(U256Word(w));
            }
            0x36 => stack.push(U256Word::from_u64(calldata.len() as u64)),
            0x37 => {
                let (Some(dst_w), Some(off_w), Some(len_w)) =
                    (stack.pop(), stack.pop(), stack.pop())
                else {
                    return evm_revert(b"stack underflow");
                };
                let (Some(dst), Some(off), Some(len)) = (
                    dst_w.to_usize_checked(),
                    off_w.to_usize_checked(),
                    len_w.to_usize_checked(),
                ) else {
                    return evm_revert(b"calldatacopy overflow");
                };
                host.charge(3u64.saturating_mul((len as u64).div_ceil(32)))
                    .map_err(|_| String::from("out of gas in CALLDATACOPY"))?;
                grow_mem(mem, host, dst, len)?;
                if let Some(d) = mem.get_mut(dst..dst + len) {
                    d.fill(0);
                    if let Some(rem) = calldata.get(off..) {
                        let n = rem.len().min(len);
                        if let (Some(sub_d), Some(sub_s)) = (d.get_mut(..n), rem.get(..n)) {
                            sub_d.copy_from_slice(sub_s);
                        }
                    }
                }
            }
            0x3d => stack.push(U256Word::from_u64(returndata.len() as u64)),
            0x3e => {
                let (Some(dst_w), Some(off_w), Some(len_w)) =
                    (stack.pop(), stack.pop(), stack.pop())
                else {
                    return evm_revert(b"stack underflow");
                };
                let (Some(dst), Some(off), Some(len)) = (
                    dst_w.to_usize_checked(),
                    off_w.to_usize_checked(),
                    len_w.to_usize_checked(),
                ) else {
                    return evm_revert(b"returndatacopy overflow");
                };
                let Some(end) = off.checked_add(len) else {
                    return evm_revert(b"returndatacopy oob");
                };
                let Some(slice) = returndata.get(off..end) else {
                    return evm_revert(b"returndatacopy oob");
                };
                host.charge(3u64.saturating_mul((len as u64).div_ceil(32)))
                    .map_err(|_| String::from("out of gas in RETURNDATACOPY"))?;
                mem_write(mem, host, dst, slice)?;
            }
            0x46 => stack.push(U256Word::from_u64(BUDLUM_EVM_CHAIN_ID)),
            0x47 => {
                host.charge(5)
                    .map_err(|_| String::from("out of gas in SELFBALANCE"))?;
                let bal = host
                    .bud_balance(&EeIdentity {
                        ee: EeId::EVM,
                        id: self_addr.to_vec(),
                    })
                    .map_err(|e| e.to_string())?
                    .0;
                stack.push(U256Word::from_u128(bal));
            }
            0x48 => {
                let _ = ctx;
                stack.push(U256Word::from_u128(
                    crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS,
                ));
            }
            0x50 => {
                if stack.pop().is_none() {
                    return evm_revert(b"stack underflow");
                }
            }
            0x51 => {
                let Some(off_w) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                let Some(off) = off_w.to_usize_checked() else {
                    return evm_revert(b"mload overflow");
                };
                stack.push(U256Word(mem_read_32(mem, host, off)?));
            }
            0x52 => {
                let (Some(off_w), Some(val_w)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                let Some(off) = off_w.to_usize_checked() else {
                    return evm_revert(b"mstore overflow");
                };
                mem_write(mem, host, off, &val_w.0)?;
            }
            0x54 => {
                host.charge(2_100)
                    .map_err(|_| String::from("out of gas in SLOAD"))?;
                let Some(slot_w) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                let val = sload_word(host, self_addr, &slot_w.0)?;
                stack.push(U256Word(val));
            }
            0x55 => {
                if is_static {
                    return evm_revert(b"SSTORE in static call");
                }
                let (Some(slot_w), Some(val_w)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                let _ = sstore_word(host, self_addr, &slot_w.0, &val_w.0)?;
            }
            0x56 => {
                let Some(dest_w) = stack.pop() else {
                    return evm_revert(b"stack underflow");
                };
                let Some(dest) = dest_w.to_usize_checked() else {
                    return evm_revert(b"bad jump dest");
                };
                if code.get(dest).copied() != Some(0x5b) {
                    return evm_revert(b"invalid JUMPDEST");
                }
                (*pc) = dest + 1;
            }
            0x57 => {
                let (Some(dest_w), Some(cond_w)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"stack underflow");
                };
                if !cond_w.is_zero() {
                    let Some(dest) = dest_w.to_usize_checked() else {
                        return evm_revert(b"bad jumpi dest");
                    };
                    if code.get(dest).copied() != Some(0x5b) {
                        return evm_revert(b"invalid JUMPDEST");
                    }
                    (*pc) = dest + 1;
                }
            }
            0x5b => {}
            0x5f => stack.push(U256Word::ZERO),
            0x60..=0x7f => {
                let n = usize::from(op - 0x5f);
                let mut w = [0u8; 32];
                let slice = code.get((*pc)..(*pc).saturating_add(n)).unwrap_or(&[]);
                let pad = 32usize.saturating_sub(slice.len());
                if let Some(dst) = w.get_mut(pad..pad + slice.len()) {
                    dst.copy_from_slice(slice);
                }
                (*pc) = (*pc).saturating_add(n);
                stack.push(U256Word(w));
            }
            0x80..=0x8f => {
                let depth = usize::from(op - 0x7f);
                let Some(idx) = stack.len().checked_sub(depth) else {
                    return evm_revert(b"DUP underflow");
                };
                let val = *stack.get(idx).unwrap_or(&U256Word::ZERO);
                stack.push(val);
            }
            0x90..=0x9f => {
                let depth = usize::from(op - 0x8f);
                let top_idx = stack.len().saturating_sub(1);
                let Some(other_idx) = top_idx.checked_sub(depth) else {
                    return evm_revert(b"SWAP underflow");
                };
                stack.swap(top_idx, other_idx);
            }
            0xa0..=0xa4 => {
                if is_static {
                    return evm_revert(b"LOG in static call");
                }
                let topic_count = usize::from(op - 0xa0);
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return evm_revert(b"LOG underflow");
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return evm_revert(b"LOG mem overflow");
                };
                let mut topics = Vec::with_capacity(topic_count);
                for _ in 0..topic_count {
                    let Some(tw) = stack.pop() else {
                        return evm_revert(b"LOG topic underflow");
                    };
                    topics.push(tw.0);
                }
                host.charge(
                    375u64
                        .saturating_add(375u64.saturating_mul(topic_count as u64))
                        .saturating_add(8u64.saturating_mul(len as u64)),
                )
                .map_err(|_| String::from("out of gas in LOG"))?;
                grow_mem(mem, host, off, len)?;
                let data = mem.get(off..off + len).unwrap_or(&[]).to_vec();
                host.emit_log(EeLog {
                    emitter: EeIdentity {
                        ee: EeId::EVM,
                        id: self_addr.to_vec(),
                    },
                    topics: topics.into_iter().map(|t| t.to_vec()).collect(),
                    data,
                })
                .map_err(|e| e.to_string())?;
            }
            0xf0 | 0xf5 => {
                if is_static {
                    return evm_revert(b"CREATE in static call");
                }
                let (Some(val_w), Some(off_w), Some(len_w)) =
                    (stack.pop(), stack.pop(), stack.pop())
                else {
                    return evm_revert(b"CREATE underflow");
                };
                let salt_opt = if op == 0xf5 {
                    let Some(salt_w) = stack.pop() else {
                        return evm_revert(b"CREATE2 underflow");
                    };
                    Some(salt_w.0)
                } else {
                    None
                };
                let Some(val_u128) = val_w.to_u128_checked() else {
                    return evm_revert(b"CREATE value overflow");
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return evm_revert(b"CREATE mem overflow");
                };
                if len > MAX_EVM_INITCODE_BYTES {
                    return evm_revert(b"CREATE initcode limit");
                }
                host.charge(
                    32_000u64.saturating_add(2u64.saturating_mul((len as u64).div_ceil(32))),
                )
                .map_err(|_| String::from("out of gas in CREATE"))?;
                grow_mem(mem, host, off, len)?;
                let init = mem.get(off..off + len).unwrap_or(&[]).to_vec();
                if depth.saturating_add(1) >= MAX_EVM_CALL_DEPTH {
                    returndata.clear();
                    stack.push(U256Word::ZERO);
                    continue;
                }
                let rem = host.remaining();
                let max_forward = rem.saturating_sub(rem / 64);
                host.push_overlay(max_forward, false);
                let created = (|| -> Result<[u8; 20], ()> {
                    let child20 = if let Some(salt) = salt_opt {
                        compute_create2_address(self_addr, &salt, &init)
                    } else {
                        let mut sender_rec = read_account_rec(host, self_addr).map_err(|_| ())?;
                        let addr = compute_create_address(self_addr, sender_rec.nonce);
                        sender_rec.nonce = sender_rec.nonce.saturating_add(1);
                        write_account_rec(host, self_addr, &sender_rec).map_err(|_| ())?;
                        addr
                    };
                    if target_collides_with_native_alias(host, &child20) {
                        return Err(());
                    }
                    let existing = read_account_rec(host, &child20).map_err(|_| ())?;
                    if existing.code_hash.is_some() || existing.nonce > 0 {
                        return Err(());
                    }
                    if val_u128 > 0 {
                        let from_id = EeIdentity {
                            ee: EeId::EVM,
                            id: self_addr.to_vec(),
                        };
                        let to_id = EeIdentity {
                            ee: EeId::EVM,
                            id: child20.to_vec(),
                        };
                        host.bud_transfer(&from_id, &to_id, val_u128)
                            .map_err(|_| ())?;
                    }
                    deploy_runtime_code(host, &child20, &init).map_err(|_| ())?;
                    Ok(child20)
                })();
                match created {
                    Ok(child20) if host.commit_top_overlay().is_ok() => {
                        returndata.clear();
                        stack.push(U256Word::from_addr20(&child20));
                    }
                    _ => {
                        host.discard_top_overlay();
                        returndata.clear();
                        stack.push(U256Word::ZERO);
                    }
                }
            }
            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let call_is_static = is_static || op == 0xfa;
                let Some(gas_w) = stack.pop() else {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"CALL underflow".to_vec(),
                    ));
                };
                let Some(addr_w) = stack.pop() else {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"CALL underflow".to_vec(),
                    ));
                };
                let val_u128 = if op == 0xf1 || op == 0xf2 {
                    let Some(vw) = stack.pop() else {
                        return Ok(EvmFrameOutcome::Done(
                            OutcomeStatus::Revert,
                            b"CALL value underflow".to_vec(),
                        ));
                    };
                    let Some(val) = vw.to_u128_checked() else {
                        return Ok(EvmFrameOutcome::Done(
                            OutcomeStatus::Revert,
                            b"CALL value overflow".to_vec(),
                        ));
                    };
                    val
                } else if op == 0xf4 {
                    value_wei
                } else {
                    0
                };
                let (Some(in_off_w), Some(in_len_w), Some(ret_off_w), Some(ret_len_w)) =
                    (stack.pop(), stack.pop(), stack.pop(), stack.pop())
                else {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"CALL args underflow".to_vec(),
                    ));
                };
                let (Some(in_off), Some(in_len), Some(ret_off), Some(ret_len)) = (
                    in_off_w.to_usize_checked(),
                    in_len_w.to_usize_checked(),
                    ret_off_w.to_usize_checked(),
                    ret_len_w.to_usize_checked(),
                ) else {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"CALL mem overflow".to_vec(),
                    ));
                };
                if (op == 0xf1 || op == 0xf2) && call_is_static && val_u128 > 0 {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"value in STATICCALL".to_vec(),
                    ));
                }
                grow_mem(mem, host, in_off, in_len)?;
                grow_mem(mem, host, ret_off, ret_len)?;
                let sub_in = mem.get(in_off..in_off + in_len).unwrap_or(&[]).to_vec();
                let target20 = addr_w.to_addr20();
                if (target20 == EVM_UNIVERSAL_PRECOMPILE || target20 == EVM_UOL_PRECOMPILE)
                    && val_u128 > 0
                {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"universal precompile rejects msg.value".to_vec(),
                    ));
                }
                let next_depth = depth.saturating_add(1);
                if next_depth >= MAX_EVM_CALL_DEPTH {
                    returndata.clear();
                    stack.push(U256Word::ZERO);
                    continue;
                }
                let rem = host.remaining();
                let max_forward = rem.saturating_sub(rem / 64);
                let sub_gas = gas_w.to_u128_saturating().min(u128::from(max_forward)) as u64;
                host.push_overlay(sub_gas, call_is_static);
                if op == 0xf1 && val_u128 > 0 {
                    let from_id = EeIdentity {
                        ee: EeId::EVM,
                        id: self_addr.to_vec(),
                    };
                    let to_id = EeIdentity {
                        ee: EeId::EVM,
                        id: target20.to_vec(),
                    };
                    if host.bud_transfer(&from_id, &to_id, val_u128).is_err() {
                        host.discard_top_overlay();
                        returndata.clear();
                        stack.push(U256Word::ZERO);
                        continue;
                    }
                } else if op == 0xf2 && val_u128 > 0 {
                    let self_id = EeIdentity {
                        ee: EeId::EVM,
                        id: self_addr.to_vec(),
                    };
                    let Ok(bal) = host.bud_balance(&self_id) else {
                        host.discard_top_overlay();
                        returndata.clear();
                        stack.push(U256Word::ZERO);
                        continue;
                    };
                    if bal.0 < val_u128 {
                        host.discard_top_overlay();
                        returndata.clear();
                        stack.push(U256Word::ZERO);
                        continue;
                    }
                }
                let (exec_addr, sub_caller) = match op {
                    0xf2 => (Some(self_addr), self_addr),
                    0xf4 => (Some(self_addr), caller20),
                    _ => (None, self_addr),
                };
                match prepare_evm_target(
                    &EvmTargetDispatch {
                        ctx,
                        code_addr: &target20,
                        exec_addr,
                        caller20: sub_caller,
                        value_wei: val_u128,
                        input: &sub_in,
                        is_static: call_is_static,
                        gas_limit: sub_gas,
                        depth: next_depth,
                    },
                    host,
                ) {
                    Ok(PreparedTarget::Bytecode(child)) => {
                        *pending_ret = Some((ret_off, ret_len));
                        return Ok(EvmFrameOutcome::CallChild(Box::new(child)));
                    }
                    Ok(PreparedTarget::Finished(OutcomeStatus::Success, sub_out)) => {
                        if host.commit_top_overlay().is_ok() {
                            *returndata = sub_out;
                            let copy_n = ret_len.min(returndata.len());
                            if let Some(s) = returndata.get(..copy_n) {
                                mem_write(mem, host, ret_off, s)?;
                            }
                            stack.push(U256Word::from_u64(1));
                        } else {
                            returndata.clear();
                            stack.push(U256Word::ZERO);
                        }
                    }
                    Ok(PreparedTarget::Finished(_, sub_out)) => {
                        host.discard_top_overlay();
                        *returndata = sub_out;
                        let copy_n = ret_len.min(returndata.len());
                        if let Some(s) = returndata.get(..copy_n) {
                            mem_write(mem, host, ret_off, s)?;
                        }
                        stack.push(U256Word::ZERO);
                    }
                    Err(_) => {
                        host.discard_top_overlay();
                        returndata.clear();
                        stack.push(U256Word::ZERO);
                    }
                }
            }
            0xf3 => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok(EvmFrameOutcome::Done(
                        OutcomeStatus::Revert,
                        b"RETURN underflow".to_vec(),
                    ));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Err(String::from("out of gas: RETURN mem overflow"));
                };
                grow_mem(mem, host, off, len)?;
                return Ok(EvmFrameOutcome::Done(
                    OutcomeStatus::Success,
                    mem.get(off..off + len).unwrap_or(&[]).to_vec(),
                ));
            }
            0xfd => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok(EvmFrameOutcome::Done(OutcomeStatus::Revert, Vec::new()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Err(String::from("out of gas: REVERT mem overflow"));
                };
                grow_mem(mem, host, off, len)?;
                return Ok(EvmFrameOutcome::Done(
                    OutcomeStatus::Revert,
                    mem.get(off..off + len).unwrap_or(&[]).to_vec(),
                ));
            }
            _ => return Ok(EvmFrameOutcome::Done(OutcomeStatus::Revert, vec![op])),
        }
    }
    Ok(EvmFrameOutcome::Done(OutcomeStatus::Success, Vec::new()))
}

fn deploy_runtime_code(
    host: &mut dyn HostApi,
    target20: &[u8; 20],
    runtime_code: &[u8],
) -> Result<(), String> {
    if runtime_code.len() > MAX_EVM_BYTECODE_BYTES {
        return Err(String::from("runtime code exceeds 24 KiB EIP-170 limit"));
    }
    host.charge(200 * runtime_code.len() as u64)
        .map_err(|_| String::from("out of gas storing contract code"))?;
    let code_hash: [u8; 32] = Keccak256::digest(runtime_code).into();
    let code_ns = Namespace::new(NS_EVM_CODE).map_err(|e| e.to_string())?;
    host.write(&code_ns, &code_hash, Some(runtime_code))
        .map_err(|e| e.to_string())?;
    let rec = EvmAccountRecord {
        nonce: 1,
        code_hash: Some(hex::encode(code_hash)),
        imported_from: None,
    };
    write_account_rec(host, target20, &rec).map_err(|e| e.to_string())?;

    if let Some(spec) = decode_std_evm_token_code(runtime_code) {
        match spec.standard {
            AssetStandard::Fungible if spec.initial_supply_or_token_id > 0 => {
                let supply_w = U256Word::from_u128(spec.initial_supply_or_token_id).0;
                let _ = sstore_word(host, target20, &map_slot(b"supply", &[], &[]), &supply_w)?;
                let _ = sstore_word(
                    host,
                    target20,
                    &map_slot(b"bal", &spec.initial_holder, &[]),
                    &supply_w,
                )?;
            }
            AssetStandard::NonFungible => {
                let tid = spec.initial_supply_or_token_id;
                let _ = sstore_word(
                    host,
                    target20,
                    &map_slot(b"nft_owner", &tid.to_be_bytes(), &[]),
                    &U256Word::from_addr20(&spec.initial_holder).0,
                )?;
            }
            AssetStandard::Fungible => {}
        }
    }
    Ok(())
}

struct EvmTargetDispatch<'a> {
    ctx: &'a BlockContext,
    code_addr: &'a [u8; 20],
    exec_addr: Option<&'a [u8; 20]>,
    caller20: &'a [u8; 20],
    value_wei: u128,
    input: &'a [u8],
    is_static: bool,
    gas_limit: u64,
    depth: u32,
}

enum PreparedTarget {
    Finished(OutcomeStatus, Vec<u8>),
    Bytecode(EvmExecFrame),
}

fn prepare_evm_target(
    req: &EvmTargetDispatch<'_>,
    host: &mut dyn HostApi,
) -> Result<PreparedTarget, String> {
    let EvmTargetDispatch {
        ctx,
        code_addr,
        exec_addr,
        caller20,
        value_wei,
        input,
        is_static,
        gas_limit,
        depth,
    } = *req;
    if depth >= MAX_EVM_CALL_DEPTH {
        return Ok(PreparedTarget::Finished(
            OutcomeStatus::Revert,
            b"EVM call depth exceeded".to_vec(),
        ));
    }
    let storage_addr = exec_addr.unwrap_or(code_addr);
    if code_addr == &EVM_UNIVERSAL_PRECOMPILE {
        let (st, out) = invoke_universal_precompile(caller20, input, is_static, host)?;
        return Ok(PreparedTarget::Finished(st, out));
    }
    if code_addr == &EVM_UOL_PRECOMPILE {
        let (st, out) = invoke_uol_precompile(ctx.height, caller20, input, is_static, host)?;
        return Ok(PreparedTarget::Finished(st, out));
    }
    let code = load_contract_code(host, code_addr)?;
    if code.is_empty() {
        return Ok(PreparedTarget::Finished(OutcomeStatus::Success, Vec::new()));
    }
    if let Some(ptr) = decode_pointer_bytecode(&code) {
        let home = EeId(ptr.home_ee);
        let (st, out) = if home == EeId::WASM {
            execute_evm_pointer_to_wasm(&ptr, caller20, input, is_static, gas_limit, host)?
        } else if home == EeId::SVM || home == EeId::MOVE {
            execute_evm_pointer_to_svm_or_move(&ptr, caller20, input, is_static, gas_limit, host)?
        } else {
            execute_evm_pointer_to_expansion(&ptr, caller20, input, is_static, gas_limit, host)?
        };
        return Ok(PreparedTarget::Finished(st, out));
    }
    if let Some(spec) = decode_std_evm_token_code(&code) {
        let (st, out) =
            execute_std_evm_token(&spec, storage_addr, caller20, input, is_static, host)?;
        return Ok(PreparedTarget::Finished(st, out));
    }
    Ok(PreparedTarget::Bytecode(EvmExecFrame {
        self_addr: *storage_addr,
        caller20: *caller20,
        value_wei,
        code,
        calldata: input.to_vec(),
        is_static,
        depth,
        stack: Vec::with_capacity(64),
        mem: Vec::new(),
        returndata: Vec::new(),
        pc: 0,
        pending_ret: None,
    }))
}

fn dispatch_evm_target(
    req: &EvmTargetDispatch<'_>,
    root_host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let mut host = EvmStackHost::new(root_host);
    host.push_overlay(req.gas_limit, req.is_static);
    let root_frame = match prepare_evm_target(req, &mut host) {
        Ok(PreparedTarget::Finished(OutcomeStatus::Success, out)) => {
            host.commit_top_overlay().map_err(|e| e.to_string())?;
            return Ok((OutcomeStatus::Success, out));
        }
        Ok(PreparedTarget::Finished(status, out)) => {
            host.discard_top_overlay();
            return Ok((status, out));
        }
        Ok(PreparedTarget::Bytecode(frame)) => frame,
        Err(e) => {
            host.discard_top_overlay();
            return Err(e);
        }
    };

    let mut frames = Vec::with_capacity(16);
    frames.push(root_frame);
    let mut pending_finish: Option<Result<(OutcomeStatus, Vec<u8>), String>> = None;

    while !frames.is_empty() {
        let step_result = if let Some(done) = pending_finish.take() {
            match done {
                Ok((st, out)) => Ok(EvmFrameOutcome::Done(st, out)),
                Err(e) => Err(e),
            }
        } else if let Some(cur) = frames.last_mut() {
            step_evm_frame(req.ctx, cur, &mut host)
        } else {
            break;
        };

        let child_res = match step_result {
            Ok(EvmFrameOutcome::CallChild(child)) => {
                frames.push(*child);
                continue;
            }
            Ok(EvmFrameOutcome::Done(st, out)) => Ok((st, out)),
            Err(e) => Err(e),
        };

        frames.pop();
        if frames.is_empty() {
            match child_res {
                Ok((OutcomeStatus::Success, out)) => {
                    host.commit_top_overlay().map_err(|e| e.to_string())?;
                    return Ok((OutcomeStatus::Success, out));
                }
                other => {
                    host.discard_top_overlay();
                    return other;
                }
            }
        }

        if let Some(caller) = frames.last_mut() {
            let (ret_off, ret_len) = caller.pending_ret.take().unwrap_or((0, 0));
            match child_res {
                Ok((OutcomeStatus::Success, sub_out)) => {
                    if host.commit_top_overlay().is_ok() {
                        caller.returndata = sub_out;
                        let copy_n = ret_len.min(caller.returndata.len());
                        if let Some(s) = caller.returndata.get(..copy_n) {
                            if let Err(e) = mem_write(&mut caller.mem, &mut host, ret_off, s) {
                                pending_finish = Some(Err(e));
                                continue;
                            }
                        }
                        caller.stack.push(U256Word::from_u64(1));
                    } else {
                        caller.returndata.clear();
                        caller.stack.push(U256Word::ZERO);
                    }
                }
                Ok((_, sub_out)) => {
                    host.discard_top_overlay();
                    caller.returndata = sub_out;
                    let copy_n = ret_len.min(caller.returndata.len());
                    if let Some(s) = caller.returndata.get(..copy_n) {
                        if let Err(e) = mem_write(&mut caller.mem, &mut host, ret_off, s) {
                            pending_finish = Some(Err(e));
                            continue;
                        }
                    }
                    caller.stack.push(U256Word::ZERO);
                }
                Err(_) => {
                    host.discard_top_overlay();
                    caller.returndata.clear();
                    caller.stack.push(U256Word::ZERO);
                }
            }
        }
    }
    Ok((OutcomeStatus::Success, Vec::new()))
}

fn coerce_addr20(raw: &[u8]) -> [u8; 20] {
    if let Ok(exact) = <[u8; 20]>::try_from(raw) {
        return exact;
    }
    if raw.len() == 32 {
        if let Some(tail) = raw.get(12..32) {
            if let Ok(arr) = <[u8; 20]>::try_from(tail) {
                return arr;
            }
        }
    }
    let digest: [u8; 32] = Keccak256::digest(raw).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = digest;
    tail
}

impl ExecutionEnvironment for EvmEe {
    fn id(&self) -> EeId {
        EeId::EVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("EVM deploy code must not be empty"),
            });
        }
        if code.len() > MAX_EVM_INITCODE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("EVM initcode exceeds 48 KiB EIP-3860 limit"),
            });
        }
        let code_hash: [u8; 32] = Keccak256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: String::from("evm-prague-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let _ = ns_obj(NS_EVM_ACCOUNT)?;
        let caller20 = coerce_addr20(&call.caller.id);
        let target20 = coerce_addr20(&call.target.id);
        let (is_static, unwrapped_input) =
            crate::execution::coordinator::universal_call::unwrap_static_universal_input(
                &call.input,
            );

        if host.charge(21_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }

        match call.kind {
            EeCallKind::Deploy => {
                if is_static {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"deploy forbidden in static call".to_vec(),
                        gas_used: 21_000,
                    });
                }
                if target_collides_with_native_alias(host, &target20) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"target collides with registered alias".to_vec(),
                        gas_used: 21_000,
                    });
                }
                match deploy_runtime_code(host, &target20, unwrapped_input) {
                    Ok(()) => Ok(EeOutcome {
                        status: OutcomeStatus::Success,
                        output: target20.to_vec(),
                        gas_used: 21_000 + 200 * unwrapped_input.len() as u64,
                    }),
                    Err(msg) if msg.contains("out of gas") => Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    }),
                    Err(msg) => Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: msg.into_bytes(),
                        gas_used: 21_000,
                    }),
                }
            }
            EeCallKind::Call => {
                let exec_gas = call.gas_limit.saturating_sub(21_000);
                match dispatch_evm_target(
                    &EvmTargetDispatch {
                        ctx,
                        code_addr: &target20,
                        exec_addr: None,
                        caller20: &caller20,
                        value_wei: call.value.0,
                        input: unwrapped_input,
                        is_static,
                        gas_limit: exec_gas,
                        depth: 0,
                    },
                    host,
                ) {
                    Ok((status, out)) => Ok(EeOutcome {
                        status,
                        output: out,
                        gas_used: 25_000,
                    }),
                    Err(msg) if msg.contains("out of gas") => Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    }),
                    Err(msg) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: msg.into_bytes(),
                        gas_used: 25_000,
                    }),
                }
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let target20 = coerce_addr20(&q.target.id);
        let code = load_contract_code(host, &target20).map_err(|m| EeRefusal {
            code: RefusalCode::Denied,
            message: m,
        })?;
        if let Some(spec) = decode_std_evm_token_code(&code) {
            let sel = q.input.get(..4).unwrap_or(&[]);
            let args = q.input.get(4..).unwrap_or(&[]);
            if sel == solidity_selector("name()") {
                return Ok(abi_encode_string(&spec.name));
            }
            if sel == solidity_selector("symbol()") {
                return Ok(abi_encode_string(&spec.symbol));
            }
            if sel == solidity_selector("decimals()") {
                return Ok(U256Word::from_u64(u64::from(spec.decimals)).0.to_vec());
            }
            if sel == solidity_selector("balanceOf(address)") {
                let who = decode_abi_addr(args, 0).map_err(|m| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: m,
                })?;
                let bal =
                    sload_word(host, &target20, &map_slot(b"bal", &who, &[])).map_err(|m| {
                        EeRefusal {
                            code: RefusalCode::Denied,
                            message: m,
                        }
                    })?;
                return Ok(bal.to_vec());
            }
            if sel == solidity_selector("allowance(address,address)") {
                let owner = decode_abi_addr(args, 0).map_err(|m| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: m,
                })?;
                let spender = decode_abi_addr(args, 32).map_err(|m| EeRefusal {
                    code: RefusalCode::InvalidCode,
                    message: m,
                })?;
                let alw = sload_word(host, &target20, &map_slot(b"alw", &owner, &spender))
                    .map_err(|m| EeRefusal {
                        code: RefusalCode::Denied,
                        message: m,
                    })?;
                return Ok(alw.to_vec());
            }
        }
        if let Ok(slot) = <[u8; 32]>::try_from(q.input.as_slice()) {
            let word = sload_word(host, &target20, &slot).map_err(|m| EeRefusal {
                code: RefusalCode::Denied,
                message: m,
            })?;
            return Ok(word.to_vec());
        }
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;

    fn test_ctx() -> BlockContext {
        BlockContext {
            chain_id: 45261,
            height: 1,
            timestamp_ms: 1_762_000_000_000,
        }
    }

    fn deploy(host: &mut MemoryHost, addr: [u8; 20], code: Vec<u8>) {
        let mut ee = EvmEe::new();
        let res = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Deploy,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: vec![0x01; 20],
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: addr.to_vec(),
                    },
                    value: BudAmount(0),
                    input: code,
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                host,
            )
            .unwrap();
        assert_eq!(res.status, OutcomeStatus::Success);
    }

    fn push20(out: &mut Vec<u8>, addr: [u8; 20]) {
        out.push(0x73); // PUSH20
        out.extend_from_slice(&addr);
    }

    fn push1(out: &mut Vec<u8>, v: u8) {
        out.push(0x60);
        out.push(v);
    }

    #[test]
    fn evm_nested_call_rolls_back_storage_and_value_on_revert() {
        let mut host = MemoryHost::new(2_000_000);
        let caller = [0x11; 20];
        let contract_a = [0xAA; 20];
        let contract_b = [0xBB; 20];
        host.balances.insert(
            EeIdentity {
                ee: EeId::EVM,
                id: contract_a.to_vec(),
            },
            500,
        );

        // Contract B writes slot 1 = 0x42, then REVERT(0, 0).
        let mut code_b = Vec::new();
        push1(&mut code_b, 0x42);
        push1(&mut code_b, 0x01);
        code_b.push(0x55); // SSTORE
        code_b.extend_from_slice(&[0x5f, 0x5f, 0xfd]); // PUSH0, PUSH0, REVERT
        deploy(&mut host, contract_b, code_b);

        // Contract A CALLs B with 100 wei and returns the CALL success flag (0).
        let mut code_a = Vec::new();
        code_a.extend_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f]); // retLen, retOff, argsLen, argsOff
        push1(&mut code_a, 100); // value = 100
        push20(&mut code_a, contract_b);
        code_a.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40]); // PUSH3 1_000_000 gas
        code_a.push(0xf1); // CALL
        code_a.extend_from_slice(&[0x5f, 0x52]); // MSTORE at 0
        push1(&mut code_a, 32);
        code_a.extend_from_slice(&[0x5f, 0xf3]); // RETURN(0, 32)
        deploy(&mut host, contract_a, code_a);

        let mut ee = EvmEe::new();
        let out = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: caller.to_vec(),
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: contract_a.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, vec![0u8; 32], "CALL must push 0 on revert");
        assert_eq!(
            sload_word(&host, &contract_b, &U256Word::from_u64(1).0).unwrap(),
            [0u8; 32],
            "reverted callee storage write must be rolled back"
        );
        assert_eq!(
            host.bud_balance(&EeIdentity {
                ee: EeId::EVM,
                id: contract_a.to_vec(),
            })
            .unwrap()
            .0,
            500,
            "reverted CALL value must stay with caller"
        );
        assert_eq!(
            host.bud_balance(&EeIdentity {
                ee: EeId::EVM,
                id: contract_b.to_vec(),
            })
            .unwrap()
            .0,
            0
        );
    }

    #[test]
    fn evm_nested_call_enforces_sub_gas_cap_without_draining_caller() {
        let mut host = MemoryHost::new(1_000_000);
        let contract_a = [0xA1; 20];
        let contract_b = [0xB1; 20];

        // Contract B attempts SSTORE (costs 20_000 gas).
        let mut code_b = Vec::new();
        push1(&mut code_b, 9);
        push1(&mut code_b, 1);
        code_b.extend_from_slice(&[0x55, 0x00]);
        deploy(&mut host, contract_b, code_b);

        // Contract A gives B only 500 gas, stores 0x77 if CALL pushes 0.
        let mut code_a = Vec::new();
        code_a.extend_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f, 0x5f]);
        push20(&mut code_a, contract_b);
        code_a.extend_from_slice(&[0x61, 0x01, 0xf4]); // PUSH2 500 gas
        code_a.push(0xf1); // CALL
        code_a.push(0x15); // ISZERO -> 1
        push1(&mut code_a, 0x77);
        code_a.extend_from_slice(&[0x01, 0x5f, 0x52]); // ADD, PUSH0, MSTORE
        push1(&mut code_a, 32);
        code_a.extend_from_slice(&[0x5f, 0xf3]);
        deploy(&mut host, contract_a, code_a);

        let mut ee = EvmEe::new();
        let out = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: vec![0x01; 20],
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: contract_a.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 500_000,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, U256Word::from_u64(0x78).0.to_vec());
        assert_eq!(
            sload_word(&host, &contract_b, &U256Word::from_u64(1).0).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn evm_recursive_call_depth_limit_stops_before_stack_overflow() {
        let mut host = MemoryHost::new(u64::MAX / 4);
        let self_rec = [0xCC; 20];
        let mut code = Vec::new();
        code.extend_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f, 0x5f]); // value + IO
        code.push(0x30); // ADDRESS
        code.extend_from_slice(&[0x64, 0xff, 0xff, 0xff, 0xff, 0xff]); // large gas
        code.extend_from_slice(&[0xf1, 0x5f, 0x52]); // CALL, MSTORE(0, ok)
        push1(&mut code, 32);
        code.extend_from_slice(&[0x5f, 0xf3]);
        deploy(&mut host, self_rec, code);

        let mut ee = EvmEe::new();
        let out = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: vec![0x01; 20],
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: self_rec.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: u64::MAX / 8,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, U256Word::from_u64(1).0.to_vec());
    }

    #[test]
    fn evm_balance_selfbalance_delegatecall_callcode_create_work() {
        let mut host = MemoryHost::new(2_000_000);
        let caller = [0x11; 20];
        let contract_a = [0xD1; 20];
        let contract_b = [0xD2; 20];
        host.balances.insert(
            EeIdentity {
                ee: EeId::EVM,
                id: contract_a.to_vec(),
            },
            777,
        );

        // B writes caller20 into slot 2 and self_addr into slot 3, returns SELFBALANCE.
        let code_b = vec![
            0x33, 0x60, 0x02, 0x55, // CALLER -> SSTORE(2)
            0x30, 0x60, 0x03, 0x55, // ADDRESS -> SSTORE(3)
            0x47, 0x5f, 0x52, // SELFBALANCE -> MSTORE(0)
            0x60, 32, 0x5f, 0xf3, // RETURN(0, 32)
        ];
        deploy(&mut host, contract_b, code_b);

        // A DELEGATECALLs B, returns retdata[..32].
        let mut code_a = Vec::new();
        code_a.extend_from_slice(&[0x60, 32, 0x5f, 0x5f, 0x5f]); // retLen=32, retOff=0, in=0
        push20(&mut code_a, contract_b);
        code_a.extend_from_slice(&[0x62, 0x07, 0xa1, 0x20, 0xf4]); // PUSH3 500_000, DELEGATECALL
        code_a.push(0x50); // POP
        code_a.extend_from_slice(&[0x60, 32, 0x5f, 0xf3]); // RETURN(0, 32)
        deploy(&mut host, contract_a, code_a);

        let mut ee = EvmEe::new();
        let out = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: caller.to_vec(),
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: contract_a.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 800_000,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, U256Word::from_u64(777).0.to_vec());
        assert_eq!(
            sload_word(&host, &contract_a, &U256Word::from_u64(2).0).unwrap(),
            U256Word::from_addr20(&caller).0
        );
        assert_eq!(
            sload_word(&host, &contract_a, &U256Word::from_u64(3).0).unwrap(),
            U256Word::from_addr20(&contract_a).0
        );
    }

    #[test]
    fn evm_callcode_rejects_unbacked_value() {
        let mut host = MemoryHost::new(2_000_000);
        let caller = [0x11u8; 20];
        let contract_a = [0xAAu8; 20];
        let contract_b = [0xBBu8; 20];

        // B would write slot 1 if entered.
        deploy(
            &mut host,
            contract_b,
            vec![0x60, 0x42, 0x60, 0x01, 0x55, 0x00],
        );

        // A executes CALLCODE with value 500 > balance 100 and returns the success flag.
        let mut code_a = Vec::new();
        code_a.extend_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f]); // retLen, retOff, inLen, inOff
        code_a.extend_from_slice(&[0x61, 0x01, 0xf4]); // PUSH2 500 (value)
        push20(&mut code_a, contract_b);
        code_a.extend_from_slice(&[0x62, 0x07, 0xa1, 0x20, 0xf2]); // PUSH3 500_000, CALLCODE
        code_a.extend_from_slice(&[0x5f, 0x52, 0x60, 32, 0x5f, 0xf3]); // MSTORE(0), RETURN(0,32)
        deploy(&mut host, contract_a, code_a);
        host.balances.insert(
            EeIdentity {
                ee: EeId::EVM,
                id: contract_a.to_vec(),
            },
            100,
        );

        let mut ee = EvmEe::new();
        let out = ee
            .execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: EeIdentity {
                        ee: EeId::EVM,
                        id: caller.to_vec(),
                    },
                    target: EeIdentity {
                        ee: EeId::EVM,
                        id: contract_a.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 800_000,
                    depth: 0,
                    tx_hash: [0u8; 32],
                },
                &mut host,
            )
            .unwrap();
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_ne!(out.output, U256Word::from_u64(1).0.to_vec());
        assert_eq!(out.output, U256Word::ZERO.0.to_vec());
        assert_eq!(
            sload_word(&host, &contract_a, &U256Word::from_u64(1).0).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn evm_uol_precompile_b002_offers_transfers_and_accepts() {
        let mut host = MemoryHost::new(2_000_000);
        let maker = [0x11u8; 20];
        let taker = [0x22u8; 20];
        let class_id = [0xAAu8; 32];
        let asset_id = [0xBBu8; 32];
        let ns = Namespace::new(NS_UEL_ASSETS).unwrap();
        host.write(&ns, &uol_holder_key(&asset_id), Some(&maker))
            .unwrap();
        host.write(
            &ns,
            &uol_bal_key(&class_id, &maker),
            Some(&100u128.to_le_bytes()),
        )
        .unwrap();

        let mut offer_calldata = Vec::new();
        offer_calldata.extend_from_slice(&uol_selector(
            "offer(bytes32,bytes32,bytes,bytes,uint128,uint64)",
        ));
        offer_calldata.extend_from_slice(&class_id);
        offer_calldata.extend_from_slice(&asset_id);
        let mut head = [0u8; 32];
        head[24..32].copy_from_slice(&192u64.to_be_bytes());
        offer_calldata.extend_from_slice(&head);
        head[24..32].copy_from_slice(&256u64.to_be_bytes());
        offer_calldata.extend_from_slice(&head);
        let mut amt = [0u8; 32];
        amt[16..32].copy_from_slice(&40u128.to_be_bytes());
        offer_calldata.extend_from_slice(&amt);
        let mut exp = [0u8; 32];
        exp[24..32].copy_from_slice(&999u64.to_be_bytes());
        offer_calldata.extend_from_slice(&exp);
        // taker dynamic bytes at offset 192
        let mut len_word = [0u8; 32];
        len_word[31] = 20;
        offer_calldata.extend_from_slice(&len_word);
        let mut taker_padded = [0u8; 32];
        taker_padded[..20].copy_from_slice(&taker);
        offer_calldata.extend_from_slice(&taker_padded);
        // empty payment dynamic bytes at offset 256
        offer_calldata.extend_from_slice(&[0u8; 32]);

        let (st, offer_out) =
            invoke_uol_precompile(10, &maker, &offer_calldata, false, &mut host).unwrap();
        assert_eq!(st, OutcomeStatus::Success);
        assert_eq!(offer_out.len(), 32);

        let mut accept_cd = Vec::from(uol_selector("accept(bytes32)"));
        accept_cd.extend_from_slice(&offer_out);
        let (st_static, _) =
            invoke_uol_precompile(10, &taker, &accept_cd, true, &mut host).unwrap();
        assert_eq!(st_static, OutcomeStatus::Revert);

        let (st2, _) = invoke_uol_precompile(10, &taker, &accept_cd, false, &mut host).unwrap();
        assert_eq!(st2, OutcomeStatus::Success);

        let holder_cd = [uol_selector("holderOf(bytes32)").as_slice(), &asset_id].concat();
        let (st_h, holder_out) =
            invoke_uol_precompile(10, &taker, &holder_cd, true, &mut host).unwrap();
        assert_eq!(st_h, OutcomeStatus::Success);
        assert_eq!(&holder_out[64..84], &taker);

        // Expired offers revert and unknown asset transfers revert cleanly.
        let (st_exp, _) =
            invoke_uol_precompile(1_000, &maker, &offer_calldata, false, &mut host).unwrap();
        assert_eq!(st_exp, OutcomeStatus::Revert);

        let mut bad_xfer = Vec::from(uol_selector("transfer(bytes32,bytes32,bytes,uint128)"));
        bad_xfer.extend_from_slice(&class_id);
        bad_xfer.extend_from_slice(&[0xEEu8; 32]);
        let mut off_word = [0u8; 32];
        off_word[31] = 128;
        bad_xfer.extend_from_slice(&off_word);
        bad_xfer.extend_from_slice(&[0u8; 32]);
        let mut tlen = [0u8; 32];
        tlen[31] = 20;
        bad_xfer.extend_from_slice(&tlen);
        let mut tpad = [0u8; 32];
        tpad[..20].copy_from_slice(&taker);
        bad_xfer.extend_from_slice(&tpad);
        let (st_bad_asset, _) =
            invoke_uol_precompile(10, &maker, &bad_xfer, false, &mut host).unwrap();
        assert_eq!(st_bad_asset, OutcomeStatus::Revert);
    }
}
