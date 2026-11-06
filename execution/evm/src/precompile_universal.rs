//! EVM `0x000000000000000000000000000000000000B001` Universal Call precompile codec
//! shared with the standalone `budlum-ee-evm` worker binary (WP-27, WP-30).

use budlum_uel_abi::{BudAmount, EeId, EeIdentity, EeLog, HostApi, HostError, UniversalCall};
use sha3::{Digest, Keccak256};

/// Canonical 20-byte EVM Universal Call precompile address (`0x...B001`).
pub const EVM_UNIVERSAL_PRECOMPILE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB0, 0x01,
];

/// `topic0 = keccak256("UniversalCallExecuted(uint8,bytes,bool)")`.
#[must_use]
pub fn universal_call_executed_topic0() -> [u8; 32] {
    Keccak256::digest(b"UniversalCallExecuted(uint8,bytes,bool)").into()
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

fn write_dyn_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_u64_word(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
    let pad = pad_to_32(bytes.len()).saturating_sub(bytes.len());
    if pad > 0 {
        out.resize(out.len() + pad, 0);
    }
}

fn read_u64_word(buf: &[u8], offset: usize) -> Result<u64, String> {
    let w = buf
        .get(offset..offset + 32)
        .ok_or_else(|| String::from("ABI word truncated"))?;
    if w.get(..24).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
        return Err(String::from("ABI uint64 overflow"));
    }
    let lo = w.get(24..32).ok_or_else(|| String::from("ABI slice"))?;
    let arr: [u8; 8] = lo.try_into().map_err(|_| String::from("ABI u64"))?;
    Ok(u64::from_be_bytes(arr))
}

fn read_u128_word(buf: &[u8], offset: usize) -> Result<u128, String> {
    let w = buf
        .get(offset..offset + 32)
        .ok_or_else(|| String::from("ABI word truncated"))?;
    if w.get(..16).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
        return Err(String::from("ABI uint128 overflow"));
    }
    let lo = w.get(16..32).ok_or_else(|| String::from("ABI slice"))?;
    let arr: [u8; 16] = lo.try_into().map_err(|_| String::from("ABI u128"))?;
    Ok(u128::from_be_bytes(arr))
}

fn read_dyn_bytes(args: &[u8], head_offset: usize) -> Result<Vec<u8>, String> {
    let rel = usize::try_from(read_u64_word(args, head_offset)?)
        .map_err(|_| String::from("ABI offset overflow"))?;
    let len = usize::try_from(read_u64_word(args, rel)?)
        .map_err(|_| String::from("ABI length overflow"))?;
    let start = rel
        .checked_add(32)
        .ok_or_else(|| String::from("ABI start overflow"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| String::from("ABI end overflow"))?;
    Ok(args
        .get(start..end)
        .ok_or_else(|| String::from("ABI payload truncated"))?
        .to_vec())
}

/// Executes `0x...B001` precompile calldata over `host` and emits `UniversalCallExecuted`.
pub fn run_precompile_call(
    caller20: &[u8; 20],
    calldata: &[u8],
    host: &mut dyn HostApi,
) -> Result<Vec<u8>, String> {
    let call_sel: [u8; 4] = {
        let [b0, b1, b2, b3, ..]: [u8; 32] =
            Keccak256::digest(b"call(uint8,bytes,bytes,uint256,uint64)").into();
        [b0, b1, b2, b3]
    };
    let static_sel: [u8; 4] = {
        let [b0, b1, b2, b3, ..]: [u8; 32] =
            Keccak256::digest(b"staticCall(uint8,bytes,bytes,uint64)").into();
        [b0, b1, b2, b3]
    };
    let sel = calldata
        .get(..4)
        .ok_or_else(|| String::from("short selector"))?;
    let args = calldata.get(4..).unwrap_or(&[]);
    let (to_ee, target, mut input, value_attos, gas_bgu, is_static) = if sel == call_sel {
        let ee = u8::try_from(read_u64_word(args, 0)?).map_err(|_| String::from("ee u8"))?;
        (
            EeId(ee),
            read_dyn_bytes(args, 32)?,
            read_dyn_bytes(args, 64)?,
            read_u128_word(args, 96)?,
            read_u64_word(args, 128)?,
            false,
        )
    } else if sel == static_sel {
        let ee = u8::try_from(read_u64_word(args, 0)?).map_err(|_| String::from("ee u8"))?;
        (
            EeId(ee),
            read_dyn_bytes(args, 32)?,
            read_dyn_bytes(args, 64)?,
            0,
            read_u64_word(args, 96)?,
            true,
        )
    } else {
        return Err(String::from("unknown 0x...B001 selector"));
    };

    if is_static {
        let mut prefixed = b"BDLM_UCALL_STATIC_V1".to_vec();
        prefixed.append(&mut input);
        input = prefixed;
    }

    let ures = host
        .universal_call(UniversalCall {
            from: EeIdentity {
                ee: EeId::EVM,
                id: caller20.to_vec(),
            },
            to_ee,
            target: EeIdentity {
                ee: to_ee,
                id: target.clone(),
            },
            value: BudAmount(value_attos),
            input,
            gas_limit: gas_bgu,
        })
        .map_err(|e: HostError| e.to_string())?;

    let mut log_data = Vec::new();
    write_u64_word(u64::from(to_ee.0), &mut log_data);
    write_u64_word(96, &mut log_data);
    write_u64_word(u64::from(ures.success), &mut log_data);
    write_dyn_bytes(&target, &mut log_data);
    host.emit_log(EeLog {
        address: EVM_UNIVERSAL_PRECOMPILE.to_vec(),
        topics: vec![universal_call_executed_topic0()],
        data: log_data,
    })
    .map_err(|e| e.to_string())?;

    let mut ret = Vec::new();
    write_u64_word(u64::from(ures.success), &mut ret);
    write_u64_word(64, &mut ret);
    write_dyn_bytes(&ures.output, &mut ret);
    Ok(ret)
}
