//! EVM execution environment (`EeId::EVM` = `0x01`) over `HostApi`.
//!
//! Implements WP-27 and the EVM leg of WP-30:
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

use crate::cross_domain::evm::rlp::{self, Item};
use crate::execution::coordinator::alias::{derive_foreign_cosmos_bech32, ALIAS_NAMESPACE};
use crate::execution::coordinator::assets::{
    decode_pointer_bytecode, AssetStandard, PointerDescriptor,
};
use crate::execution::coordinator::foreign::ethereum::BUDLUM_EVM_CHAIN_ID;
use crate::execution::coordinator::state::{NS_EVM_ACCOUNT, NS_EVM_CODE, NS_EVM_STORAGE};
use crate::execution::coordinator::universal_call::{
    decode_precompile_calldata, encode_evm_universal_call_log, encode_precompile_return,
    wrap_static_universal_input, EVM_UNIVERSAL_PRECOMPILE,
};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Maximum deployed runtime EVM bytecode size (EIP-170: 24 KiB).
pub const MAX_EVM_BYTECODE_BYTES: usize = 24_576;
/// Maximum initcode size at deployment (EIP-3860: 48 KiB).
pub const MAX_EVM_INITCODE_BYTES: usize = 49_152;
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
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
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
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
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
        Item::String(rlp::encode_uint(nonce)),
    ]));
    let digest: [u8; 32] = Keccak256::digest(&encoded).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, addr @ ..] = digest;
    addr
}

/// Computes EVM `CREATE2` address `keccak256(0xff || sender || salt || keccak256(init))[12..32]`.
#[must_use]
pub fn compute_create2_address(
    sender: &[u8; 20],
    salt: &[u8; 32],
    init_code: &[u8],
) -> [u8; 20] {
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
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
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
    if addr20 == &EVM_UNIVERSAL_PRECOMPILE {
        return true;
    }
    let mut probe = Vec::with_capacity(24);
    probe.extend_from_slice(b"evm:");
    probe.extend_from_slice(addr20);
    host.read(&alias_ns, &probe)
        .ok()
        .flatten()
        .is_some()
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

    fn to_u128_saturating(self) -> u128 {
        if self.0.get(..16).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
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
        if self.0.get(..24).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
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
        return Ok((OutcomeStatus::Revert, b"insufficient ERC20 balance".to_vec()));
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
            Ok((OutcomeStatus::Revert, b"unsupported CW20 pointer selector".to_vec()))
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
                    if ok { OutcomeStatus::Success } else { OutcomeStatus::Revert },
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
                    if ok { OutcomeStatus::Success } else { OutcomeStatus::Revert },
                    out,
                ));
            }
            Ok((OutcomeStatus::Revert, b"unsupported CW721 pointer selector".to_vec()))
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
    };
    match host.universal_call(ucall) {
        Ok(ures) => {
            let log = encode_evm_universal_call_log(
                decoded.target_ee,
                &decoded.target,
                ures.success,
            );
            host.emit_log(log).map_err(|e| e.to_string())?;
            let ret = encode_precompile_return(ures.success, &ures.output);
            Ok((OutcomeStatus::Success, ret))
        }
        Err(HostError::OutOfGas) => Err(String::from("out of gas")),
        Err(HostError::Denied(reason)) => Ok((OutcomeStatus::Revert, reason.into_bytes())),
        Err(other) => Ok((OutcomeStatus::Revert, other.to_string().into_bytes())),
    }
}

fn mem_read_32(mem: &mut Vec<u8>, offset: usize) -> [u8; 32] {
    let need = offset.saturating_add(32);
    if mem.len() < need {
        mem.resize(need, 0);
    }
    let mut out = [0u8; 32];
    if let Some(s) = mem.get(offset..offset + 32) {
        out.copy_from_slice(s);
    }
    out
}

fn mem_write(mem: &mut Vec<u8>, offset: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let need = offset.saturating_add(data.len());
    if mem.len() < need {
        mem.resize(need, 0);
    }
    if let Some(dst) = mem.get_mut(offset..offset + data.len()) {
        dst.copy_from_slice(data);
    }
}

fn run_evm_bytecode(
    ctx: &BlockContext,
    self_addr: &[u8; 20],
    caller20: &[u8; 20],
    value_wei: u128,
    code: &[u8],
    calldata: &[u8],
    is_static: bool,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let mut stack: Vec<U256Word> = Vec::with_capacity(64);
    let mut mem: Vec<u8> = Vec::new();
    let mut returndata: Vec<u8> = Vec::new();
    let mut pc = 0usize;

    while let Some(&op) = code.get(pc) {
        pc += 1;
        host.charge(3).map_err(|_| String::from("out of gas"))?;
        match op {
            0x00 => return Ok((OutcomeStatus::Success, Vec::new())),
            0x01 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                stack.push(a.wrapping_add(b));
            }
            0x03 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                stack.push(a.wrapping_sub(b));
            }
            0x14 => {
                let (Some(a), Some(b)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                stack.push(U256Word::from_u64(u64::from(a == b)));
            }
            0x15 => {
                let Some(a) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                stack.push(U256Word::from_u64(u64::from(a.is_zero())));
            }
            0x20 => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Ok((OutcomeStatus::Revert, b"memory overflow".to_vec()));
                };
                host.charge(30 + (len as u64 / 32) * 6)
                    .map_err(|_| String::from("out of gas"))?;
                if mem.len() < off.saturating_add(len) {
                    mem.resize(off.saturating_add(len), 0);
                }
                let digest: [u8; 32] =
                    Keccak256::digest(mem.get(off..off + len).unwrap_or(&[])).into();
                stack.push(U256Word(digest));
            }
            0x30 => stack.push(U256Word::from_addr20(self_addr)),
            0x33 => stack.push(U256Word::from_addr20(caller20)),
            0x34 => stack.push(U256Word::from_u128(value_wei)),
            0x35 => {
                let Some(off_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
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
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let (Some(dst), Some(off), Some(len)) = (
                    dst_w.to_usize_checked(),
                    off_w.to_usize_checked(),
                    len_w.to_usize_checked(),
                ) else {
                    return Ok((OutcomeStatus::Revert, b"calldatacopy overflow".to_vec()));
                };
                let mut tmp = vec![0u8; len];
                if let Some(rem) = calldata.get(off..) {
                    let n = rem.len().min(len);
                    if let (Some(d), Some(s)) = (tmp.get_mut(..n), rem.get(..n)) {
                        d.copy_from_slice(s);
                    }
                }
                mem_write(&mut mem, dst, &tmp);
            }
            0x3d => stack.push(U256Word::from_u64(returndata.len() as u64)),
            0x3e => {
                let (Some(dst_w), Some(off_w), Some(len_w)) =
                    (stack.pop(), stack.pop(), stack.pop())
                else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let (Some(dst), Some(off), Some(len)) = (
                    dst_w.to_usize_checked(),
                    off_w.to_usize_checked(),
                    len_w.to_usize_checked(),
                ) else {
                    return Ok((OutcomeStatus::Revert, b"returndatacopy overflow".to_vec()));
                };
                let Some(slice) = returndata.get(off..off.saturating_add(len)) else {
                    return Ok((OutcomeStatus::Revert, b"returndatacopy oob".to_vec()));
                };
                mem_write(&mut mem, dst, slice);
            }
            0x46 => stack.push(U256Word::from_u64(BUDLUM_EVM_CHAIN_ID)),
            0x48 => stack.push(U256Word::from_u128(ctx.base_fee.0)),
            0x50 => {
                if stack.pop().is_none() {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                }
            }
            0x51 => {
                let Some(off_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let Some(off) = off_w.to_usize_checked() else {
                    return Ok((OutcomeStatus::Revert, b"mload overflow".to_vec()));
                };
                stack.push(U256Word(mem_read_32(&mut mem, off)));
            }
            0x52 => {
                let (Some(off_w), Some(val_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let Some(off) = off_w.to_usize_checked() else {
                    return Ok((OutcomeStatus::Revert, b"mstore overflow".to_vec()));
                };
                mem_write(&mut mem, off, &val_w.0);
            }
            0x54 => {
                host.charge(2_100)
                    .map_err(|_| String::from("out of gas in SLOAD"))?;
                let Some(slot_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let val = sload_word(host, self_addr, &slot_w.0)?;
                stack.push(U256Word(val));
            }
            0x55 => {
                if is_static {
                    return Ok((OutcomeStatus::Revert, b"SSTORE in static call".to_vec()));
                }
                let (Some(slot_w), Some(val_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let _ = sstore_word(host, self_addr, &slot_w.0, &val_w.0)?;
            }
            0x56 => {
                let Some(dest_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                let Some(dest) = dest_w.to_usize_checked() else {
                    return Ok((OutcomeStatus::Revert, b"bad jump dest".to_vec()));
                };
                if code.get(dest).copied() != Some(0x5b) {
                    return Ok((OutcomeStatus::Revert, b"invalid JUMPDEST".to_vec()));
                }
                pc = dest + 1;
            }
            0x57 => {
                let (Some(dest_w), Some(cond_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"stack underflow".to_vec()));
                };
                if !cond_w.is_zero() {
                    let Some(dest) = dest_w.to_usize_checked() else {
                        return Ok((OutcomeStatus::Revert, b"bad jumpi dest".to_vec()));
                    };
                    if code.get(dest).copied() != Some(0x5b) {
                        return Ok((OutcomeStatus::Revert, b"invalid JUMPDEST".to_vec()));
                    }
                    pc = dest + 1;
                }
            }
            0x5b => {}
            0x5f => stack.push(U256Word::ZERO),
            0x60..=0x7f => {
                let n = usize::from(op - 0x5f);
                let mut w = [0u8; 32];
                let slice = code.get(pc..pc.saturating_add(n)).unwrap_or(&[]);
                let pad = 32usize.saturating_sub(slice.len());
                if let Some(dst) = w.get_mut(pad..pad + slice.len()) {
                    dst.copy_from_slice(slice);
                }
                pc = pc.saturating_add(n);
                stack.push(U256Word(w));
            }
            0x80..=0x8f => {
                let depth = usize::from(op - 0x7f);
                let Some(idx) = stack.len().checked_sub(depth) else {
                    return Ok((OutcomeStatus::Revert, b"DUP underflow".to_vec()));
                };
                let val = *stack.get(idx).unwrap_or(&U256Word::ZERO);
                stack.push(val);
            }
            0x90..=0x9f => {
                let depth = usize::from(op - 0x8f);
                let top_idx = stack.len().saturating_sub(1);
                let Some(other_idx) = top_idx.checked_sub(depth) else {
                    return Ok((OutcomeStatus::Revert, b"SWAP underflow".to_vec()));
                };
                stack.swap(top_idx, other_idx);
            }
            0xa0..=0xa4 => {
                if is_static {
                    return Ok((OutcomeStatus::Revert, b"LOG in static call".to_vec()));
                }
                let topic_count = usize::from(op - 0xa0);
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"LOG underflow".to_vec()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Ok((OutcomeStatus::Revert, b"LOG mem overflow".to_vec()));
                };
                let mut topics = Vec::with_capacity(topic_count);
                for _ in 0..topic_count {
                    let Some(tw) = stack.pop() else {
                        return Ok((OutcomeStatus::Revert, b"LOG topic underflow".to_vec()));
                    };
                    topics.push(tw.0);
                }
                if mem.len() < off.saturating_add(len) {
                    mem.resize(off.saturating_add(len), 0);
                }
                let data = mem.get(off..off + len).unwrap_or(&[]).to_vec();
                host.charge(375 + 375 * topic_count as u64 + 8 * len as u64)
                    .map_err(|_| String::from("out of gas in LOG"))?;
                host.emit_log(EeLog {
                    address: self_addr.to_vec(),
                    topics,
                    data,
                })
                .map_err(|e| e.to_string())?;
            }
            0xf1 | 0xfa => {
                let call_is_static = is_static || op == 0xfa;
                let Some(gas_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"CALL underflow".to_vec()));
                };
                let Some(addr_w) = stack.pop() else {
                    return Ok((OutcomeStatus::Revert, b"CALL underflow".to_vec()));
                };
                let val_u128 = if op == 0xf1 {
                    let Some(vw) = stack.pop() else {
                        return Ok((OutcomeStatus::Revert, b"CALL value underflow".to_vec()));
                    };
                    vw.to_u128_saturating()
                } else {
                    0
                };
                let (Some(in_off_w), Some(in_len_w), Some(ret_off_w), Some(ret_len_w)) =
                    (stack.pop(), stack.pop(), stack.pop(), stack.pop())
                else {
                    return Ok((OutcomeStatus::Revert, b"CALL args underflow".to_vec()));
                };
                let (Some(in_off), Some(in_len), Some(ret_off), Some(ret_len)) = (
                    in_off_w.to_usize_checked(),
                    in_len_w.to_usize_checked(),
                    ret_off_w.to_usize_checked(),
                    ret_len_w.to_usize_checked(),
                ) else {
                    return Ok((OutcomeStatus::Revert, b"CALL mem overflow".to_vec()));
                };
                if call_is_static && val_u128 > 0 {
                    return Ok((OutcomeStatus::Revert, b"value in STATICCALL".to_vec()));
                }
                if mem.len() < in_off.saturating_add(in_len) {
                    mem.resize(in_off.saturating_add(in_len), 0);
                }
                let sub_in = mem.get(in_off..in_off + in_len).unwrap_or(&[]).to_vec();
                let target20 = addr_w.to_addr20();
                let sub_gas = gas_w.to_u128_saturating().min(u128::from(gas_limit)) as u64;
                let (sub_status, sub_out) = dispatch_evm_target(
                    ctx,
                    &target20,
                    self_addr,
                    val_u128,
                    &sub_in,
                    call_is_static,
                    sub_gas,
                    host,
                )?;
                returndata = sub_out;
                let copy_n = ret_len.min(returndata.len());
                if let Some(s) = returndata.get(..copy_n) {
                    mem_write(&mut mem, ret_off, s);
                }
                stack.push(U256Word::from_u64(u64::from(
                    sub_status == OutcomeStatus::Success,
                )));
            }
            0xf5 => {
                if is_static {
                    return Ok((OutcomeStatus::Revert, b"CREATE2 in static call".to_vec()));
                }
                let (Some(_val_w), Some(off_w), Some(len_w), Some(salt_w)) =
                    (stack.pop(), stack.pop(), stack.pop(), stack.pop())
                else {
                    return Ok((OutcomeStatus::Revert, b"CREATE2 underflow".to_vec()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Ok((OutcomeStatus::Revert, b"CREATE2 mem overflow".to_vec()));
                };
                if mem.len() < off.saturating_add(len) {
                    mem.resize(off.saturating_add(len), 0);
                }
                let init = mem.get(off..off + len).unwrap_or(&[]).to_vec();
                let child20 = compute_create2_address(self_addr, &salt_w.0, &init);
                if target_collides_with_native_alias(host, &child20) {
                    stack.push(U256Word::ZERO);
                    continue;
                }
                let existing = read_account_rec(host, &child20)?;
                if existing.code_hash.is_some() || existing.nonce > 0 {
                    stack.push(U256Word::ZERO);
                    continue;
                }
                deploy_runtime_code(host, &child20, &init)?;
                stack.push(U256Word::from_addr20(&child20));
            }
            0xf3 => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, b"RETURN underflow".to_vec()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Ok((OutcomeStatus::Revert, b"RETURN mem overflow".to_vec()));
                };
                if mem.len() < off.saturating_add(len) {
                    mem.resize(off.saturating_add(len), 0);
                }
                return Ok((
                    OutcomeStatus::Success,
                    mem.get(off..off + len).unwrap_or(&[]).to_vec(),
                ));
            }
            0xfd => {
                let (Some(off_w), Some(len_w)) = (stack.pop(), stack.pop()) else {
                    return Ok((OutcomeStatus::Revert, Vec::new()));
                };
                let (Some(off), Some(len)) = (off_w.to_usize_checked(), len_w.to_usize_checked())
                else {
                    return Ok((OutcomeStatus::Revert, Vec::new()));
                };
                if mem.len() < off.saturating_add(len) {
                    mem.resize(off.saturating_add(len), 0);
                }
                return Ok((
                    OutcomeStatus::Revert,
                    mem.get(off..off + len).unwrap_or(&[]).to_vec(),
                ));
            }
            _ => return Ok((OutcomeStatus::Revert, vec![op])),
        }
    }
    Ok((OutcomeStatus::Success, Vec::new()))
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

#[allow(clippy::too_many_arguments)]
fn dispatch_evm_target(
    ctx: &BlockContext,
    target20: &[u8; 20],
    caller20: &[u8; 20],
    value_wei: u128,
    input: &[u8],
    is_static: bool,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    if target20 == &EVM_UNIVERSAL_PRECOMPILE {
        return invoke_universal_precompile(caller20, input, is_static, host);
    }
    let code = load_contract_code(host, target20)?;
    if code.is_empty() {
        return Ok((OutcomeStatus::Success, Vec::new()));
    }
    if let Some(ptr) = decode_pointer_bytecode(&code) {
        return execute_evm_pointer_to_wasm(&ptr, caller20, input, is_static, gas_limit, host);
    }
    if let Some(spec) = decode_std_evm_token_code(&code) {
        return execute_std_evm_token(&spec, target20, caller20, input, is_static, host);
    }
    run_evm_bytecode(
        ctx, target20, caller20, value_wei, &code, input, is_static, gas_limit, host,
    )
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
                match dispatch_evm_target(
                    ctx,
                    &target20,
                    &caller20,
                    call.value.0,
                    unwrapped_input,
                    is_static,
                    call.gas_limit,
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
                let bal = sload_word(host, &target20, &map_slot(b"bal", &who, &[])).map_err(
                    |m| EeRefusal {
                        code: RefusalCode::Denied,
                        message: m,
                    },
                )?;
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
