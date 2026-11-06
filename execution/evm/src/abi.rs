//! Solidity ABI codec for the UEL Universal Call precompile at
//! `0x000000000000000000000000000000000000B001` (`Section 8.7.2`, `WP-27`).

use revm::primitives::{address, Address};

/// Canonical EVM precompile address for cross-EE Universal Calls (`0x...B001`).
pub const UNIVERSAL_CALL_PRECOMPILE: Address =
    address!("0x000000000000000000000000000000000000b001");

/// `keccak256("call(uint8,bytes,bytes,uint256,uint64)")[..4]`.
pub const SEL_UNIVERSAL_CALL: [u8; 4] = [0x25, 0xd4, 0xd8, 0x1b];

/// `keccak256("staticCall(uint8,bytes,bytes,uint64)")[..4]`.
pub const SEL_UNIVERSAL_STATIC_CALL: [u8; 4] = [0xf9, 0xe4, 0x11, 0xde];

/// Base BGU cost charged for invoking the `0x...B001` precompile skeleton.
pub const PRECOMPILE_BASE_GAS: u64 = 500;

/// Parsed invocation of `IBudlumUniversalPrecompile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPrecompileCall {
    pub is_static_selector: bool,
    pub target_ee: u8,
    pub target: Vec<u8>,
    pub input: Vec<u8>,
    pub value_attos: u128,
    pub gas_bgu: u64,
}

fn read_word(buf: &[u8], offset: usize) -> Option<&[u8]> {
    let end = offset.checked_add(32)?;
    buf.get(offset..end)
}

fn read_usize_word(buf: &[u8], offset: usize) -> Option<usize> {
    let word = read_word(buf, offset)?;
    if word.get(..24)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(word.get(24..32)?);
    usize::try_from(u64::from_be_bytes(tail)).ok()
}

fn read_u64_word(buf: &[u8], offset: usize) -> Option<u64> {
    let word = read_word(buf, offset)?;
    if word.get(..24)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(word.get(24..32)?);
    Some(u64::from_be_bytes(tail))
}

fn read_u128_word(buf: &[u8], offset: usize) -> Option<u128> {
    let word = read_word(buf, offset)?;
    if word.get(..16)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 16];
    tail.copy_from_slice(word.get(16..32)?);
    Some(u128::from_be_bytes(tail))
}

fn read_u8_word(buf: &[u8], offset: usize) -> Option<u8> {
    let word = read_word(buf, offset)?;
    if word.get(..31)?.iter().any(|&b| b != 0) {
        return None;
    }
    word.get(31).copied()
}

fn read_dyn_bytes(args: &[u8], head_offset: usize) -> Option<Vec<u8>> {
    let rel = read_usize_word(args, head_offset)?;
    let len = read_usize_word(args, rel)?;
    let data_start = rel.checked_add(32)?;
    let data_end = data_start.checked_add(len)?;
    Some(args.get(data_start..data_end)?.to_vec())
}

/// Decode Solidity calldata targeting `0x000000000000000000000000000000000000B001`.
#[must_use]
pub fn decode_precompile_call(calldata: &[u8]) -> Option<ParsedPrecompileCall> {
    let sel = calldata.get(..4)?;
    let args = calldata.get(4..)?;
    if sel == SEL_UNIVERSAL_CALL {
        if args.len() < 32 * 5 {
            return None;
        }
        let target_ee = read_u8_word(args, 0)?;
        let target = read_dyn_bytes(args, 32)?;
        let input = read_dyn_bytes(args, 64)?;
        let value_attos = read_u128_word(args, 96)?;
        let gas_bgu = read_u64_word(args, 128)?;
        Some(ParsedPrecompileCall {
            is_static_selector: false,
            target_ee,
            target,
            input,
            value_attos,
            gas_bgu,
        })
    } else if sel == SEL_UNIVERSAL_STATIC_CALL {
        if args.len() < 32 * 4 {
            return None;
        }
        let target_ee = read_u8_word(args, 0)?;
        let target = read_dyn_bytes(args, 32)?;
        let input = read_dyn_bytes(args, 64)?;
        let gas_bgu = read_u64_word(args, 96)?;
        Some(ParsedPrecompileCall {
            is_static_selector: true,
            target_ee,
            target,
            input,
            value_attos: 0,
            gas_bgu,
        })
    } else {
        None
    }
}

/// ABI-encode `(bool ok, bytes ret)` as returned by `IBudlumUniversalPrecompile`.
#[must_use]
pub fn encode_precompile_return(ok: bool, ret: &[u8]) -> Vec<u8> {
    let padded_len = ret.len().div_ceil(32) * 32;
    let mut out = vec![0u8; 96 + padded_len];
    if ok {
        if let Some(slot) = out.get_mut(31) {
            *slot = 1;
        }
    }
    // Offset to `bytes ret` tuple tail is 64 (0x40).
    if let Some(slot) = out.get_mut(63) {
        *slot = 64;
    }
    let len_be = (ret.len() as u64).to_be_bytes();
    if let Some(dst) = out.get_mut(88..96) {
        dst.copy_from_slice(&len_be);
    }
    if let Some(dst) = out.get_mut(96..96 + ret.len()) {
        dst.copy_from_slice(ret);
    }
    out
}

/// ABI-encode a `call(uint8,bytes,bytes,uint256,uint64)` payload (used by tests and callers).
#[must_use]
pub fn encode_universal_call_input(
    ee: u8,
    target: &[u8],
    input: &[u8],
    value_attos: u128,
    gas_bgu: u64,
) -> Vec<u8> {
    let target_padded = target.len().div_ceil(32) * 32;
    let input_padded = input.len().div_ceil(32) * 32;
    let head_bytes = 32 * 5;
    let target_offset = head_bytes;
    let input_offset = target_offset + 32 + target_padded;
    let total = 4 + input_offset + 32 + input_padded;
    let mut out = vec![0u8; total];

    if let Some(dst) = out.get_mut(..4) {
        dst.copy_from_slice(&SEL_UNIVERSAL_CALL);
    }
    let body = &mut out[4..];
    body[31] = ee;
    body[56..64].copy_from_slice(&(target_offset as u64).to_be_bytes());
    body[88..96].copy_from_slice(&(input_offset as u64).to_be_bytes());
    body[112..128].copy_from_slice(&value_attos.to_be_bytes());
    body[152..160].copy_from_slice(&gas_bgu.to_be_bytes());

    body[target_offset + 24..target_offset + 32]
        .copy_from_slice(&(target.len() as u64).to_be_bytes());
    body[target_offset + 32..target_offset + 32 + target.len()].copy_from_slice(target);

    body[input_offset + 24..input_offset + 32]
        .copy_from_slice(&(input.len() as u64).to_be_bytes());
    body[input_offset + 32..input_offset + 32 + input.len()].copy_from_slice(input);
    out
}
