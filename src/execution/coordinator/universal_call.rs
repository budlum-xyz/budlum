//! Cross-environment Universal Call encoding, ABI precompile codec, and log events.
//!
//! Implements section 8.7 and  items 1-4:
//! - EVM `0x000000000000000000000000000000000000B001` Solidity ABI `call(...)` and
//!   `staticCall(...)` plus `UniversalCallExecuted(uint8 ee, bytes target, bool ok)` log.
//! - WASM `BudlumMsg::UniversalCall` and `BudlumQuery::UniversalView`.
//! - BudZero syscall `UNIVERSAL_CALL` (`0x40`).
//! - Static-call envelope tagging enforced as read-only by `TxOverlay`.

use budlum_uel_abi::{EeId, EeLog};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Canonical 20-byte EVM Universal Call precompile address (`0x...B001`).
pub const EVM_UNIVERSAL_PRECOMPILE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB0, 0x01,
];

/// BudZero `UNIVERSAL_CALL` syscall code (section 8.7.2).
pub const BUDZERO_SYSCALL_UNIVERSAL_CALL: u8 = 0x40;

/// Envelope prefix marking a read-only (`static = true`) Universal Call over `HostApi`.
const STATIC_PREFIX: &[u8] = b"BDLM_UCALL_STATIC_V1";

/// Wraps `input` with the read-only (`static = true`) Universal Call marker.
#[must_use]
pub fn wrap_static_universal_input(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATIC_PREFIX.len() + input.len());
    out.extend_from_slice(STATIC_PREFIX);
    out.extend_from_slice(input);
    out
}

/// Returns `true` if `input` begins with the reserved coordinator static-call prefix.
#[must_use]
pub fn has_reserved_static_prefix(input: &[u8]) -> bool {
    input.starts_with(STATIC_PREFIX)
}

/// Unwraps `(is_static, payload)` from a `UniversalCall.input` buffer.
#[must_use]
pub fn unwrap_static_universal_input(input: &[u8]) -> (bool, &[u8]) {
    if let Some(rest) = input.strip_prefix(STATIC_PREFIX) {
        (true, rest)
    } else {
        (false, input)
    }
}

/// 4-byte Solidity selector for `call(uint8,bytes,bytes,uint256,uint64)`.
#[must_use]
pub fn evm_universal_call_selector() -> [u8; 4] {
    let digest: [u8; 32] = Keccak256::digest(b"call(uint8,bytes,bytes,uint256,uint64)").into();
    let [b0, b1, b2, b3, ..] = digest;
    [b0, b1, b2, b3]
}

/// 4-byte Solidity selector for `staticCall(uint8,bytes,bytes,uint64)`.
#[must_use]
pub fn evm_universal_static_call_selector() -> [u8; 4] {
    let digest: [u8; 32] = Keccak256::digest(b"staticCall(uint8,bytes,bytes,uint64)").into();
    let [b0, b1, b2, b3, ..] = digest;
    [b0, b1, b2, b3]
}

/// `topic0 = keccak256("UniversalCallExecuted(uint8,bytes,bool)")` (section 8.7.3 item 8).
#[must_use]
pub fn universal_call_executed_topic0() -> [u8; 32] {
    Keccak256::digest(b"UniversalCallExecuted(uint8,bytes,bool)").into()
}

/// Decoded request passed to `0x...B001`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPrecompileCall {
    pub target_ee: EeId,
    pub target: Vec<u8>,
    pub input: Vec<u8>,
    pub value_attos: u128,
    pub gas_bgu: u64,
    pub is_static: bool,
}

fn pad_to_32(len: usize) -> usize {
    let rem = len % 32;
    if rem == 0 {
        len
    } else {
        len + (32 - rem)
    }
}

fn write_u64_word(val: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&val.to_be_bytes());
}

fn write_u128_word(val: u128, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&val.to_be_bytes());
}

fn write_dyn_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_u64_word(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
    let pad = pad_to_32(bytes.len()).saturating_sub(bytes.len());
    if pad > 0 {
        out.resize(out.len() + pad, 0);
    }
}

fn read_word(buf: &[u8], offset: usize) -> Result<&[u8], String> {
    buf.get(offset..offset + 32)
        .ok_or_else(|| String::from("ABI calldata truncated reading 32-byte word"))
}

fn read_u64_word(buf: &[u8], offset: usize) -> Result<u64, String> {
    let w = read_word(buf, offset)?;
    if w.get(..24).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
        return Err(String::from("ABI uint64 overflows 64 bits"));
    }
    let lo = w
        .get(24..32)
        .ok_or_else(|| String::from("ABI uint64 word slice error"))?;
    let arr: [u8; 8] = lo
        .try_into()
        .map_err(|_| String::from("ABI uint64 conversion error"))?;
    Ok(u64::from_be_bytes(arr))
}

fn read_u128_word(buf: &[u8], offset: usize) -> Result<u128, String> {
    let w = read_word(buf, offset)?;
    if w.get(..16).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
        return Err(String::from("ABI valueAttos overflows u128"));
    }
    let lo = w
        .get(16..32)
        .ok_or_else(|| String::from("ABI u128 word slice error"))?;
    let arr: [u8; 16] = lo
        .try_into()
        .map_err(|_| String::from("ABI u128 conversion error"))?;
    Ok(u128::from_be_bytes(arr))
}

fn read_dyn_bytes(args: &[u8], head_offset: usize) -> Result<Vec<u8>, String> {
    let rel = usize::try_from(read_u64_word(args, head_offset)?)
        .map_err(|_| String::from("ABI dynamic offset overflow"))?;
    let len = usize::try_from(read_u64_word(args, rel)?)
        .map_err(|_| String::from("ABI dynamic length overflow"))?;
    let start = rel
        .checked_add(32)
        .ok_or_else(|| String::from("ABI dynamic start overflow"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| String::from("ABI dynamic end overflow"))?;
    let slice = args
        .get(start..end)
        .ok_or_else(|| String::from("ABI dynamic payload truncated"))?;
    Ok(slice.to_vec())
}

/// ABI-encodes `IBudlumUniversal.call(ee, target, input, valueAttos, gasBgu)`.
#[must_use]
pub fn encode_precompile_call(
    target_ee: EeId,
    target: &[u8],
    input: &[u8],
    value_attos: u128,
    gas_bgu: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&evm_universal_call_selector());
    let target_off = 5u64 * 32;
    let input_off = target_off + 32 + pad_to_32(target.len()) as u64;
    write_u64_word(u64::from(target_ee.0), &mut out);
    write_u64_word(target_off, &mut out);
    write_u64_word(input_off, &mut out);
    write_u128_word(value_attos, &mut out);
    write_u64_word(gas_bgu, &mut out);
    write_dyn_bytes(target, &mut out);
    write_dyn_bytes(input, &mut out);
    out
}

/// ABI-encodes `IBudlumUniversal.staticCall(ee, target, input, gasBgu)`.
///
/// exposed for: Solidity `BudlumUniversal.staticCall` SDK callers.
#[must_use]
pub fn encode_precompile_static_call(
    target_ee: EeId,
    target: &[u8],
    input: &[u8],
    gas_bgu: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&evm_universal_static_call_selector());
    let target_off = 4u64 * 32;
    let input_off = target_off + 32 + pad_to_32(target.len()) as u64;
    write_u64_word(u64::from(target_ee.0), &mut out);
    write_u64_word(target_off, &mut out);
    write_u64_word(input_off, &mut out);
    write_u64_word(gas_bgu, &mut out);
    write_dyn_bytes(target, &mut out);
    write_dyn_bytes(input, &mut out);
    out
}

/// Decodes calldata sent to `0x...B001`.
pub fn decode_precompile_calldata(calldata: &[u8]) -> Result<DecodedPrecompileCall, String> {
    let sel = calldata
        .get(..4)
        .ok_or_else(|| String::from("0x...B001 calldata shorter than 4-byte selector"))?;
    let args = calldata.get(4..).unwrap_or(&[]);
    if sel == evm_universal_call_selector() {
        let ee_u64 = read_u64_word(args, 0)?;
        let ee_u8 =
            u8::try_from(ee_u64).map_err(|_| String::from("target_ee exceeds uint8"))?;
        let target = read_dyn_bytes(args, 32)?;
        let input = read_dyn_bytes(args, 64)?;
        if has_reserved_static_prefix(&input) {
            return Err(String::from(
                "call input cannot carry reserved static-call envelope prefix ()",
            ));
        }
        let value_attos = read_u128_word(args, 96)?;
        let gas_bgu = read_u64_word(args, 128)?;
        Ok(DecodedPrecompileCall {
            target_ee: EeId(ee_u8),
            target,
            input,
            value_attos,
            gas_bgu,
            is_static: false,
        })
    } else if sel == evm_universal_static_call_selector() {
        let ee_u64 = read_u64_word(args, 0)?;
        let ee_u8 =
            u8::try_from(ee_u64).map_err(|_| String::from("target_ee exceeds uint8"))?;
        let target = read_dyn_bytes(args, 32)?;
        let input = read_dyn_bytes(args, 64)?;
        let gas_bgu = read_u64_word(args, 96)?;
        Ok(DecodedPrecompileCall {
            target_ee: EeId(ee_u8),
            target,
            input,
            value_attos: 0,
            gas_bgu,
            is_static: true,
        })
    } else {
        Err(String::from("unknown selector on 0x...B001 precompile"))
    }
}

/// ABI-encodes `(bool ok, bytes ret)` returned by `0x...B001`.
#[must_use]
pub fn encode_precompile_return(ok: bool, ret: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_u64_word(u64::from(ok), &mut out);
    write_u64_word(64, &mut out);
    write_dyn_bytes(ret, &mut out);
    out
}

/// Decodes `(bool ok, bytes ret)` returned by `0x...B001`.
///
/// exposed for: Solidity `BudlumUniversal` return-data SDK callers.
pub fn decode_precompile_return(raw: &[u8]) -> Result<(bool, Vec<u8>), String> {
    let ok_u64 = read_u64_word(raw, 0)?;
    let ret = read_dyn_bytes(raw, 32)?;
    Ok((ok_u64 != 0, ret))
}

/// Builds the canonical `UniversalCallExecuted(uint8 ee, bytes target, bool ok)` EVM log
/// emitted from `0x000000000000000000000000000000000000B001` (section 8.7.3 item 8).
#[must_use]
pub fn encode_evm_universal_call_log(target_ee: EeId, target: &[u8], ok: bool) -> EeLog {
    let mut data = Vec::new();
    write_u64_word(u64::from(target_ee.0), &mut data);
    write_u64_word(96, &mut data);
    write_u64_word(u64::from(ok), &mut data);
    write_dyn_bytes(target, &mut data);
    EeLog {
        address: EVM_UNIVERSAL_PRECOMPILE.to_vec(),
        topics: vec![universal_call_executed_topic0()],
        data,
    }
}

/// Custom CosmWasm `CosmosMsg::Custom(BudlumMsg)` message (section 8.7.2 WASM row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumMsg {
    UniversalCall {
        target_ee: u8,
        target_hex: String,
        input_hex: String,
        value_attos: u128,
        gas_limit_bgu: u64,
    },
}

/// Custom CosmWasm `QueryRequest::Custom(BudlumQuery)` read-only request (section 8.7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumQuery {
    UniversalView {
        target_ee: u8,
        target_hex: String,
        input_hex: String,
        gas_limit_bgu: u64,
    },
}
