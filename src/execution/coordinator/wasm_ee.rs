//! WASM (CosmWasm ABI) execution environment (`EeId::WASM` = `0x02`) over `HostApi`.
//!
//! Implements  items 1-3 and the WASM leg of :
//! - Deterministic WebAssembly module validation: refuses IEEE-754 floating-point
//!   types (`f32`/`f64`) and opcodes, enforces the 64 MiB (1024-page) memory ceiling,
//!   and refuses IBC entry-point exports (`ibc_channel_*`, `ibc_packet_*`).
//! - CosmWasm storage/contract namespaces (`ee/wasm/code`, `ee/wasm/contract`,
//!   `ee/wasm/store`) backed strictly by `HostApi`.
//! - Refuses `StakingMsg`, `DistributionMsg`, `GovMsg`, and `IbcMsg` messages.
//! - Supports `BudlumMsg::UniversalCall` (`SubMsg` reply model), `BudlumQuery::UniversalView`,
//!   CW20 (`cw20-base`), CW721 (`cw721-base`), and zero-balance UEL pointers to EVM.
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::execution::coordinator::assets::{
    decode_pointer_bytecode, resolve_pointer_party_for_home, AssetStandard, MovePointerFlavor,
    MovePointerOp, PointerDescriptor, SplPointerOp,
};
use crate::execution::coordinator::evm_ee::solidity_selector;
use crate::execution::coordinator::state::{NS_WASM_CODE, NS_WASM_CONTRACT, NS_WASM_STORE};
use crate::execution::coordinator::universal_call::{
    has_reserved_static_prefix, unwrap_static_universal_input, wrap_static_universal_input,
    BudlumMsg,
};
use crate::object_layer::family::encoding::bech32_decode;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// Maximum WASM linear memory in 64 KiB pages (`1024 * 64 KiB = 64 MiB`, 8.3.5 item 1).
pub const MAX_WASM_MEMORY_PAGES: u32 = 1_024;
/// Maximum CosmWasm module bytecode size (2 MiB).
pub const MAX_WASM_CODE_BYTES: usize = 2 * 1024 * 1024;

/// Forbidden CosmWasm IBC export symbols (section 8.15 WASM row).
pub const FORBIDDEN_IBC_EXPORTS: &[&str] = &[
    "ibc_channel_open",
    "ibc_channel_connect",
    "ibc_channel_close",
    "ibc_packet_receive",
    "ibc_packet_ack",
    "ibc_packet_timeout",
];

/// Forbidden Cosmos / CosmWasm message families refused at runtime (section 8.15).
pub const FORBIDDEN_COSMOS_SUBMSG_KEYS: &[&str] = &["staking", "distribution", "gov", "ibc"];

fn read_leb_u32(buf: &[u8], cur: &mut usize) -> Result<u32, String> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let byte = *buf
            .get(*cur)
            .ok_or_else(|| String::from("truncated WASM LEB128 u32"))?;
        *cur += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(String::from("WASM LEB128 u32 overflow"))
}

fn skip_leb_s64(buf: &[u8], cur: &mut usize) -> Result<(), String> {
    for _ in 0..10 {
        let byte = *buf
            .get(*cur)
            .ok_or_else(|| String::from("truncated WASM signed LEB128"))?;
        *cur += 1;
        if byte & 0x80 == 0 {
            return Ok(());
        }
    }
    Err(String::from("WASM signed LEB128 overflow"))
}

fn check_valtype_no_float(vt: u8) -> Result<(), String> {
    if vt == 0x7d || vt == 0x7c {
        return Err(String::from(
            "floating-point WASM value types (f32/f64) are forbidden",
        ));
    }
    Ok(())
}

fn is_float_opcode(op: u8) -> bool {
    matches!(
        op,
        0x2a | 0x2b
            | 0x38
            | 0x39
            | 0x43
            | 0x44
            | 0x5b..=0x66
            | 0x8b..=0xa6
            | 0xa8..=0xab
            | 0xae..=0xbf
    )
}

fn scan_code_body_no_floats(body: &[u8]) -> Result<(), String> {
    let mut cur = 0usize;
    let local_decl_count = read_leb_u32(body, &mut cur)?;
    for _ in 0..local_decl_count {
        let _cnt = read_leb_u32(body, &mut cur)?;
        let vt = *body
            .get(cur)
            .ok_or_else(|| String::from("truncated WASM local decl"))?;
        cur += 1;
        check_valtype_no_float(vt)?;
    }

    while let Some(&op) = body.get(cur) {
        cur += 1;
        if is_float_opcode(op) {
            return Err(format!(
                "floating-point WASM opcode 0x{op:02x} is forbidden"
            ));
        }
        match op {
            0x02..=0x04 => {
                let bt = *body
                    .get(cur)
                    .ok_or_else(|| String::from("truncated blocktype"))?;
                cur += 1;
                check_valtype_no_float(bt)?;
            }
            0x0c | 0x0d | 0x10 | 0x20..=0x24 => {
                let _ = read_leb_u32(body, &mut cur)?;
            }
            0x0e => {
                let n = read_leb_u32(body, &mut cur)?;
                for _ in 0..=n {
                    let _ = read_leb_u32(body, &mut cur)?;
                }
            }
            0x11 => {
                let _ = read_leb_u32(body, &mut cur)?;
                let _ = read_leb_u32(body, &mut cur)?;
            }
            0x28 | 0x29 | 0x2c..=0x37 | 0x3a..=0x3e => {
                let _align = read_leb_u32(body, &mut cur)?;
                let _offset = read_leb_u32(body, &mut cur)?;
            }
            0x3f | 0x40 => {
                cur = cur.saturating_add(1);
            }
            0x41 | 0x42 => {
                skip_leb_s64(body, &mut cur)?;
            }
            0xfc => {
                let sub_op = read_leb_u32(body, &mut cur)?;
                if sub_op <= 7 {
                    return Err(format!(
                        "saturating float-to-int opcode 0xfc:{sub_op} is forbidden"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validates a WebAssembly binary for UEL determinism, page limits, and CosmWasm rules.
pub fn validate_cosmwasm_bytecode(code: &[u8]) -> Result<(), String> {
    if decode_pointer_bytecode(code).is_some() {
        return Ok(());
    }
    if code.len() > MAX_WASM_CODE_BYTES {
        return Err(String::from("WASM module exceeds 2 MiB size ceiling"));
    }
    let Some(header) = code.get(..8) else {
        return Err(String::from("WASM module shorter than 8-byte header"));
    };
    if header != [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] {
        return Err(String::from("invalid WASM magic or version"));
    }

    let mut cur = 8usize;
    while cur < code.len() {
        let sec_id = *code
            .get(cur)
            .ok_or_else(|| String::from("truncated WASM section id"))?;
        cur += 1;
        let sec_len = read_leb_u32(code, &mut cur)? as usize;
        let sec = code
            .get(cur..cur.saturating_add(sec_len))
            .ok_or_else(|| String::from("truncated WASM section payload"))?;
        cur += sec_len;

        match sec_id {
            1 => {
                let mut sc = 0usize;
                let count = read_leb_u32(sec, &mut sc)?;
                for _ in 0..count {
                    let form = *sec
                        .get(sc)
                        .ok_or_else(|| String::from("truncated functype"))?;
                    sc += 1;
                    if form != 0x60 {
                        return Err(String::from("invalid WASM functype tag"));
                    }
                    let plen = read_leb_u32(sec, &mut sc)? as usize;
                    for &vt in sec
                        .get(sc..sc + plen)
                        .ok_or_else(|| String::from("truncated params"))?
                    {
                        check_valtype_no_float(vt)?;
                    }
                    sc += plen;
                    let rlen = read_leb_u32(sec, &mut sc)? as usize;
                    for &vt in sec
                        .get(sc..sc + rlen)
                        .ok_or_else(|| String::from("truncated results"))?
                    {
                        check_valtype_no_float(vt)?;
                    }
                    sc += rlen;
                }
            }
            5 => {
                let mut sc = 0usize;
                let count = read_leb_u32(sec, &mut sc)?;
                for _ in 0..count {
                    let flags = *sec
                        .get(sc)
                        .ok_or_else(|| String::from("truncated memory limits"))?;
                    sc += 1;
                    let initial = read_leb_u32(sec, &mut sc)?;
                    if initial > MAX_WASM_MEMORY_PAGES {
                        return Err(String::from("WASM initial memory exceeds 64 MiB"));
                    }
                    if flags & 0x01 != 0 {
                        let max_p = read_leb_u32(sec, &mut sc)?;
                        if max_p > MAX_WASM_MEMORY_PAGES {
                            return Err(String::from("WASM max memory exceeds 64 MiB"));
                        }
                    }
                }
            }
            7 => {
                let mut sc = 0usize;
                let count = read_leb_u32(sec, &mut sc)?;
                for _ in 0..count {
                    let name_len = read_leb_u32(sec, &mut sc)? as usize;
                    let name_b = sec
                        .get(sc..sc + name_len)
                        .ok_or_else(|| String::from("truncated export name"))?;
                    sc += name_len;
                    let name = std::str::from_utf8(name_b)
                        .map_err(|_| String::from("non-UTF8 WASM export"))?;
                    if FORBIDDEN_IBC_EXPORTS.contains(&name) || name.starts_with("ibc_") {
                        return Err(format!("IBC entry point `{name}` is refused on Budlum UEL"));
                    }
                    sc += 1;
                    let _idx = read_leb_u32(sec, &mut sc)?;
                }
            }
            10 => {
                let mut sc = 0usize;
                let count = read_leb_u32(sec, &mut sc)?;
                for _ in 0..count {
                    let body_len = read_leb_u32(sec, &mut sc)? as usize;
                    let body = sec
                        .get(sc..sc + body_len)
                        .ok_or_else(|| String::from("truncated code body"))?;
                    sc += body_len;
                    scan_code_body_no_floats(body)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Builds a minimal valid WebAssembly binary carrying CosmWasm exports
/// (`instantiate`, `execute`, `query`) so tests and CW20/CW721 templates pass
/// real binary validation.
#[must_use]
pub fn build_valid_cosmwasm_module(export_names: &[&str], body_ops: &[u8]) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Section 1: Type `[ -> ]`
    wasm.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // Section 3: Function (1 func of type 0)
    wasm.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Section 5: Memory (min 1 page, max 256 pages <= 1024)
    wasm.extend_from_slice(&[0x05, 0x05, 0x01, 0x01, 0x01, 0x80, 0x02]);
    // Section 7: Exports
    let mut exp_sec = vec![export_names.len() as u8];
    for name in export_names {
        exp_sec.push(name.len() as u8);
        exp_sec.extend_from_slice(name.as_bytes());
        exp_sec.push(0x00);
        exp_sec.push(0x00);
    }
    wasm.push(0x07);
    wasm.push(exp_sec.len() as u8);
    wasm.extend_from_slice(&exp_sec);
    // Section 10: Code
    let mut func_body = vec![0x00]; // 0 local decls
    func_body.extend_from_slice(body_ops);
    func_body.push(0x0b); // end
    let mut code_sec = vec![0x01, func_body.len() as u8];
    code_sec.extend_from_slice(&func_body);
    wasm.push(0x0a);
    wasm.push(code_sec.len() as u8);
    wasm.extend_from_slice(&code_sec);
    wasm
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WasmContractMeta {
    pub(crate) code_hash: String,
    pub(crate) creator: String,
    pub(crate) label: String,
}

/// Stateless WASM (CosmWasm ABI) execution environment worker (`budlum-ee-wasm`).
#[derive(Debug, Default, Clone)]
pub struct WasmEe;

impl WasmEe {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

pub(crate) fn wasm_store_key(contract: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contract.len() + 1 + key.len());
    out.extend_from_slice(contract);
    out.push(b':');
    out.extend_from_slice(key);
    out
}

fn read_store(host: &dyn HostRead, contract: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let ns = Namespace::new(NS_WASM_STORE).map_err(|e| e.to_string())?;
    host.read(&ns, &wasm_store_key(contract, key))
        .map_err(|e| e.to_string())
}

fn write_store(
    host: &mut dyn HostApi,
    contract: &[u8],
    key: &[u8],
    val: Option<&[u8]>,
) -> Result<(), String> {
    let ns = Namespace::new(NS_WASM_STORE).map_err(|e| e.to_string())?;
    host.write(&ns, &wasm_store_key(contract, key), val)
        .map_err(|e| e.to_string())
}

fn load_contract_meta(
    host: &dyn HostRead,
    contract: &[u8],
) -> Result<Option<WasmContractMeta>, String> {
    let c_ns = Namespace::new(NS_WASM_CONTRACT).map_err(|e| e.to_string())?;
    let Some(meta_b) = host.read(&c_ns, contract).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let meta: WasmContractMeta = serde_json::from_slice(&meta_b).map_err(|e| e.to_string())?;
    Ok(Some(meta))
}

fn require_creator_or_self(
    host: &dyn HostRead,
    contract: &[u8],
    sender_str: &str,
) -> Result<(), String> {
    let contract_str = String::from_utf8_lossy(contract);
    if sender_str == contract_str.as_ref() {
        return Ok(());
    }
    let Some(meta) = load_contract_meta(host, contract)? else {
        return Err(String::from("unknown CosmWasm contract metadata"));
    };
    if meta.creator == sender_str {
        Ok(())
    } else {
        Err(String::from("unauthorized CosmWasm creator action"))
    }
}

fn require_authorized_writer(
    host: &dyn HostRead,
    contract: &[u8],
    sender_str: &str,
) -> Result<(), String> {
    if require_creator_or_self(host, contract, sender_str).is_ok() {
        return Ok(());
    }
    let allow_k = format!("sys:allowed_writer:{sender_str}");
    if read_store(host, contract, allow_k.as_bytes())?.is_some_and(|v| v == b"1") {
        Ok(())
    } else {
        Err(String::from("unauthorized CosmWasm storage write"))
    }
}

fn load_wasm_code(host: &dyn HostRead, contract: &[u8]) -> Result<Vec<u8>, String> {
    let c_ns = Namespace::new(NS_WASM_CONTRACT).map_err(|e| e.to_string())?;
    let Some(meta_b) = host.read(&c_ns, contract).map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    let meta: serde_json::Value = serde_json::from_slice(&meta_b).map_err(|e| e.to_string())?;
    let Some(ch_hex) = meta.get("code_hash").and_then(|v| v.as_str()) else {
        return Ok(Vec::new());
    };
    let ch = hex::decode(ch_hex).map_err(|e| e.to_string())?;
    let code_ns = Namespace::new(NS_WASM_CODE).map_err(|e| e.to_string())?;
    Ok(host
        .read(&code_ns, &ch)
        .map_err(|e| e.to_string())?
        .unwrap_or_default())
}

fn wasm_principal_to_evm20(principal: &str) -> [u8; 20] {
    let mut h = Keccak256::new();
    h.update(b"BDLM_EVM_ALIAS_V1");
    h.update(principal.as_bytes());
    let d: [u8; 32] = h.finalize().into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = d;
    tail
}

fn abi_word_addr(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(lo) = w.get_mut(12..32) {
        lo.copy_from_slice(addr);
    }
    w
}

fn abi_word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(lo) = w.get_mut(16..32) {
        lo.copy_from_slice(&v.to_be_bytes());
    }
    w
}

fn decode_word_u128(raw: &[u8]) -> u128 {
    let Some(lo) = raw.get(16..32) else {
        return 0;
    };
    let Ok(arr) = <[u8; 16]>::try_from(lo) else {
        return 0;
    };
    u128::from_be_bytes(arr)
}

fn execute_wasm_pointer_to_evm(
    ptr: &PointerDescriptor,
    sender_str: &str,
    msg_json: &serde_json::Value,
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let caller20 = wasm_principal_to_evm20(sender_str);
    let home_evm = ptr.home_ref.clone();

    let call_evm = |host: &mut dyn HostApi, calldata: Vec<u8>, read_only: bool| {
        let wrapped = if read_only {
            wrap_static_universal_input(&calldata)
        } else {
            calldata
        };
        host.universal_call(UniversalCall {
            from: EeIdentity {
                ee: EeId::EVM,
                id: caller20.to_vec(),
            },
            to_ee: EeId::EVM,
            target: EeIdentity {
                ee: EeId::EVM,
                id: home_evm.clone(),
            },
            value: BudAmount(0),
            input: wrapped,
            gas_limit: gas_budget / 2 + 10_000,
            is_static: read_only,
        })
        .map_err(|e| e.to_string())
    };

    if let Some(q_obj) = msg_json.get("query") {
        if let Some(bal_q) = q_obj.get("balance") {
            let addr_s = bal_q
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let mut cd = solidity_selector("balanceOf(address)").to_vec();
            cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(addr_s)));
            let ures = call_evm(host, cd, true)?;
            if !ures.success {
                return Ok((OutcomeStatus::Revert, ures.output));
            }
            let bal = decode_word_u128(&ures.output);
            let out = serde_json::to_vec(&serde_json::json!({ "balance": bal.to_string() }))
                .map_err(|e| e.to_string())?;
            return Ok((OutcomeStatus::Success, out));
        }
        if let Some(alw_q) = q_obj.get("allowance") {
            let owner_s = alw_q
                .get("owner")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let spender_s = alw_q
                .get("spender")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let mut cd = solidity_selector("allowance(address,address)").to_vec();
            cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(owner_s)));
            cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(spender_s)));
            let ures = call_evm(host, cd, true)?;
            if !ures.success {
                return Ok((OutcomeStatus::Revert, ures.output));
            }
            let alw = decode_word_u128(&ures.output);
            let out = serde_json::to_vec(&serde_json::json!({ "allowance": alw.to_string() }))
                .map_err(|e| e.to_string())?;
            return Ok((OutcomeStatus::Success, out));
        }
        if q_obj.get("token_info").is_some() {
            let out = serde_json::to_vec(&serde_json::json!({
                "name": ptr.name,
                "symbol": ptr.symbol,
                "decimals": ptr.decimals,
            }))
            .map_err(|e| e.to_string())?;
            return Ok((OutcomeStatus::Success, out));
        }
        if let Some(owner_q) = q_obj.get("owner_of") {
            let tid: u128 = owner_q
                .get("token_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut cd = solidity_selector("ownerOf(uint256)").to_vec();
            cd.extend_from_slice(&abi_word_u128(tid));
            let ures = call_evm(host, cd, true)?;
            return Ok((
                if ures.success {
                    OutcomeStatus::Success
                } else {
                    OutcomeStatus::Revert
                },
                ures.output,
            ));
        }
    }

    if is_static {
        return Ok((OutcomeStatus::Revert, b"static CW pointer write".to_vec()));
    }
    let exec_obj = msg_json.get("execute").unwrap_or(msg_json);
    if let Some(tr) = exec_obj.get("transfer") {
        let rcpt = tr
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = tr
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut cd = solidity_selector("transfer(address,uint256)").to_vec();
        cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(rcpt)));
        cd.extend_from_slice(&abi_word_u128(amt));
        let ures = call_evm(host, cd, false)?;
        return Ok((
            if ures.success {
                OutcomeStatus::Success
            } else {
                OutcomeStatus::Revert
            },
            ures.output,
        ));
    }
    if let Some(inc) = exec_obj
        .get("increase_allowance")
        .or_else(|| exec_obj.get("approve"))
    {
        if ptr.standard == AssetStandard::Fungible {
            let spender = inc
                .get("spender")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let amt: u128 = inc
                .get("amount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut cd = solidity_selector("approve(address,uint256)").to_vec();
            cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(spender)));
            cd.extend_from_slice(&abi_word_u128(amt));
            let ures = call_evm(host, cd, false)?;
            return Ok((
                if ures.success {
                    OutcomeStatus::Success
                } else {
                    OutcomeStatus::Revert
                },
                ures.output,
            ));
        }
        let spender = inc
            .get("spender")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let tid: u128 = inc
            .get("token_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut cd = solidity_selector("approve(address,uint256)").to_vec();
        cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(spender)));
        cd.extend_from_slice(&abi_word_u128(tid));
        let ures = call_evm(host, cd, false)?;
        return Ok((
            if ures.success {
                OutcomeStatus::Success
            } else {
                OutcomeStatus::Revert
            },
            ures.output,
        ));
    }
    if let Some(tf) = exec_obj.get("transfer_from") {
        let owner = tf.get("owner").and_then(|v| v.as_str()).unwrap_or_default();
        let rcpt = tf
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = tf
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut cd = solidity_selector("transferFrom(address,address,uint256)").to_vec();
        cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(owner)));
        cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(rcpt)));
        cd.extend_from_slice(&abi_word_u128(amt));
        let ures = call_evm(host, cd, false)?;
        return Ok((
            if ures.success {
                OutcomeStatus::Success
            } else {
                OutcomeStatus::Revert
            },
            ures.output,
        ));
    }
    if let Some(tn) = exec_obj.get("transfer_nft") {
        let rcpt = tn
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let tid: u128 = tn
            .get("token_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut cd = solidity_selector("safeTransferFrom(address,address,uint256)").to_vec();
        cd.extend_from_slice(&abi_word_addr(&caller20));
        cd.extend_from_slice(&abi_word_addr(&wasm_principal_to_evm20(rcpt)));
        cd.extend_from_slice(&abi_word_u128(tid));
        let ures = call_evm(host, cd, false)?;
        return Ok((
            if ures.success {
                OutcomeStatus::Success
            } else {
                OutcomeStatus::Revert
            },
            ures.output,
        ));
    }
    Ok((
        OutcomeStatus::Revert,
        b"unsupported CW pointer action".to_vec(),
    ))
}

fn parse_wasm_party32(host: &dyn HostRead, home_ee: EeId, raw: &str) -> [u8; 32] {
    let trimmed_raw = raw.trim();
    if let Ok((hrp, bytes)) = bech32_decode(trimmed_raw) {
        if hrp == "bud" {
            if let Ok(arr32) = <[u8; 32]>::try_from(bytes.as_slice()) {
                let resolved = resolve_pointer_party_for_home(host, &arr32, home_ee);
                if let Ok(mapped) = <[u8; 32]>::try_from(resolved.as_slice()) {
                    return mapped;
                }
                return arr32;
            }
        }
    }
    let trimmed = trimmed_raw.trim_start_matches("0x");
    if let Ok(bytes) = hex::decode(trimmed) {
        if let Ok(arr32) = <[u8; 32]>::try_from(bytes.as_slice()) {
            let resolved = resolve_pointer_party_for_home(host, &arr32, home_ee);
            if let Ok(mapped) = <[u8; 32]>::try_from(resolved.as_slice()) {
                return mapped;
            }
            return arr32;
        }
    }
    Sha256::digest(trimmed_raw.as_bytes()).into()
}

fn execute_wasm_pointer_to_svm_or_move(
    ptr: &PointerDescriptor,
    sender_str: &str,
    msg_json: &serde_json::Value,
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    let home_ee = EeId(ptr.home_ee);
    if let Some(q_obj) = msg_json.get("query") {
        if q_obj.get("token_info").is_some() {
            let out = serde_json::to_vec(&serde_json::json!({
                "name": ptr.name,
                "symbol": ptr.symbol,
                "decimals": ptr.decimals,
            }))
            .map_err(|e| e.to_string())?;
            return Ok((OutcomeStatus::Success, out));
        }
        let (key_name, raw_payload) = if let Some(bal_q) = q_obj.get("balance") {
            let owner = parse_wasm_party32(
                host,
                home_ee,
                bal_q
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            );
            let bytes = if home_ee == EeId::SVM {
                serde_json::to_vec(&SplPointerOp::BalanceOf { owner }).map_err(|e| e.to_string())?
            } else {
                serde_json::to_vec(&MovePointerOp::Balance {
                    flavor: MovePointerFlavor::FungibleAsset,
                    owner,
                })
                .map_err(|e| e.to_string())?
            };
            ("balance", bytes)
        } else if let Some(alw_q) = q_obj.get("allowance") {
            let owner = parse_wasm_party32(
                host,
                home_ee,
                alw_q
                    .get("owner")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            );
            let party = parse_wasm_party32(
                host,
                home_ee,
                alw_q
                    .get("spender")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            );
            let bytes = if home_ee == EeId::SVM {
                serde_json::to_vec(&SplPointerOp::Allowance {
                    owner,
                    delegate: party,
                })
                .map_err(|e| e.to_string())?
            } else {
                serde_json::to_vec(&MovePointerOp::Allowance {
                    flavor: MovePointerFlavor::FungibleAsset,
                    owner,
                    spender: party,
                })
                .map_err(|e| e.to_string())?
            };
            ("allowance", bytes)
        } else {
            return Ok((
                OutcomeStatus::Revert,
                b"unsupported CW pointer query".to_vec(),
            ));
        };
        let ures = host
            .universal_call(UniversalCall {
                from: EeIdentity {
                    ee: EeId::WASM,
                    id: sender_str.as_bytes().to_vec(),
                },
                to_ee: home_ee,
                target: EeIdentity {
                    ee: home_ee,
                    id: ptr.home_ref.clone(),
                },
                value: BudAmount(0),
                input: wrap_static_universal_input(&raw_payload),
                gas_limit: gas_budget / 2 + 10_000,
                is_static: true,
            })
            .map_err(|e| e.to_string())?;
        if !ures.success {
            return Ok((OutcomeStatus::Revert, ures.output));
        }
        let num = <[u8; 16]>::try_from(ures.output.as_slice()).map_or(0, u128::from_le_bytes);
        let out = serde_json::to_vec(&serde_json::json!({ key_name: num.to_string() }))
            .map_err(|e| e.to_string())?;
        return Ok((OutcomeStatus::Success, out));
    }

    if is_static {
        return Ok((OutcomeStatus::Revert, b"static CW pointer write".to_vec()));
    }
    let exec_obj = msg_json.get("execute").unwrap_or(msg_json);
    let raw_payload = if let Some(tr) = exec_obj.get("transfer") {
        let to = parse_wasm_party32(
            host,
            home_ee,
            tr.get("recipient")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        let amount: u128 = tr
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if home_ee == EeId::SVM {
            serde_json::to_vec(&SplPointerOp::Transfer { to, amount }).map_err(|e| e.to_string())?
        } else {
            serde_json::to_vec(&MovePointerOp::Transfer {
                flavor: MovePointerFlavor::FungibleAsset,
                to,
                amount,
            })
            .map_err(|e| e.to_string())?
        }
    } else if let Some(inc) = exec_obj
        .get("increase_allowance")
        .or_else(|| exec_obj.get("approve"))
    {
        let party = parse_wasm_party32(
            host,
            home_ee,
            inc.get("spender")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        let amount: u128 = inc
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if home_ee == EeId::SVM {
            serde_json::to_vec(&SplPointerOp::Approve {
                delegate: party,
                amount,
            })
            .map_err(|e| e.to_string())?
        } else {
            serde_json::to_vec(&MovePointerOp::Approve {
                flavor: MovePointerFlavor::FungibleAsset,
                spender: party,
                amount,
            })
            .map_err(|e| e.to_string())?
        }
    } else if let Some(tf) = exec_obj.get("transfer_from") {
        let owner = parse_wasm_party32(
            host,
            home_ee,
            tf.get("owner").and_then(|v| v.as_str()).unwrap_or_default(),
        );
        let to = parse_wasm_party32(
            host,
            home_ee,
            tf.get("recipient")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        let amount: u128 = tf
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if home_ee == EeId::SVM {
            serde_json::to_vec(&SplPointerOp::TransferFrom { owner, to, amount })
                .map_err(|e| e.to_string())?
        } else {
            serde_json::to_vec(&MovePointerOp::TransferFrom {
                flavor: MovePointerFlavor::FungibleAsset,
                owner,
                to,
                amount,
            })
            .map_err(|e| e.to_string())?
        }
    } else {
        return Ok((
            OutcomeStatus::Revert,
            b"unsupported CW pointer action".to_vec(),
        ));
    };

    let ures = host
        .universal_call(UniversalCall {
            from: EeIdentity {
                ee: EeId::WASM,
                id: sender_str.as_bytes().to_vec(),
            },
            to_ee: home_ee,
            target: EeIdentity {
                ee: home_ee,
                id: ptr.home_ref.clone(),
            },
            value: BudAmount(0),
            input: raw_payload,
            gas_limit: gas_budget / 2 + 10_000,
            is_static: false,
        })
        .map_err(|e| e.to_string())?;
    Ok((
        if ures.success {
            OutcomeStatus::Success
        } else {
            OutcomeStatus::Revert
        },
        ures.output,
    ))
}

fn handle_cw_query(
    host: &dyn HostRead,
    contract: &[u8],
    q_obj: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    if let Some(bal_q) = q_obj.get("balance") {
        let addr = bal_q
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let k = format!("cw20:bal:{addr}");
        let cur = read_store(host, contract, k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| String::from("0"));
        return serde_json::to_vec(&serde_json::json!({ "balance": cur }))
            .map_err(|e| e.to_string());
    }
    if let Some(alw_q) = q_obj.get("allowance") {
        let owner = alw_q
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let spender = alw_q
            .get("spender")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let k = format!("cw20:alw:{owner}:{spender}");
        let cur = read_store(host, contract, k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| String::from("0"));
        return serde_json::to_vec(&serde_json::json!({ "allowance": cur }))
            .map_err(|e| e.to_string());
    }
    if q_obj.get("token_info").is_some() {
        return Ok(read_store(host, contract, b"cw20:info")?.unwrap_or_else(|| b"{}".to_vec()));
    }
    if let Some(ow_q) = q_obj.get("owner_of") {
        let tid = ow_q
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let k = format!("cw721:owner:{tid}");
        let owner = read_store(host, contract, k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| String::from("cw721 token not found"))?;
        return Ok(owner.into_bytes());
    }
    if let Some(ni_q) = q_obj.get("nft_info") {
        let tid = ni_q
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let k = format!("cw721:uri:{tid}");
        let uri = read_store(host, contract, k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        return serde_json::to_vec(&serde_json::json!({ "token_uri": uri }))
            .map_err(|e| e.to_string());
    }
    if let Some(raw_q) = q_obj.get("raw") {
        let key_s = raw_q.as_str().unwrap_or_default();
        let kv_key = format!("kv:{key_s}");
        if let Some(val) = read_store(host, contract, kv_key.as_bytes())? {
            return Ok(val);
        }
        return Ok(read_store(host, contract, key_s.as_bytes())?.unwrap_or_default());
    }
    Err(String::from("unknown CosmWasm query"))
}

fn execute_cosmwasm_json(
    contract: &[u8],
    sender_str: &str,
    msg_json: &serde_json::Value,
    is_static: bool,
    gas_budget: u64,
    host: &mut dyn HostApi,
) -> Result<(OutcomeStatus, Vec<u8>), String> {
    for forbidden in FORBIDDEN_COSMOS_SUBMSG_KEYS {
        if msg_json.get(*forbidden).is_some()
            || msg_json
                .get("execute")
                .and_then(|e| e.get(*forbidden))
                .is_some()
        {
            return Ok((
                OutcomeStatus::Revert,
                format!("CosmWasm `{forbidden}` messages are refused on Budlum UEL").into_bytes(),
            ));
        }
    }

    if let Some(q_obj) = msg_json.get("query") {
        return match handle_cw_query(host, contract, q_obj) {
            Ok(bytes) => Ok((OutcomeStatus::Success, bytes)),
            Err(e) => Ok((OutcomeStatus::Revert, e.into_bytes())),
        };
    }

    if is_static {
        return Ok((
            OutcomeStatus::Revert,
            b"state mutation forbidden in static WASM call".to_vec(),
        ));
    }

    let exec_obj = msg_json.get("execute").unwrap_or(msg_json);

    if let Some(auth) = exec_obj.get("authorize_caller") {
        if let Err(reason) = require_creator_or_self(host, contract, sender_str) {
            return Ok((OutcomeStatus::Revert, reason.into_bytes()));
        }
        let caller_str = auth
            .get("caller")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if caller_str.is_empty() {
            return Ok((OutcomeStatus::Revert, b"empty authorized caller".to_vec()));
        }
        let allow_k = format!("sys:allowed_writer:{caller_str}");
        write_store(host, contract, allow_k.as_bytes(), Some(b"1"))?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(init_cw20) = exec_obj.get("instantiate_cw20") {
        if let Err(reason) = require_creator_or_self(host, contract, sender_str) {
            return Ok((OutcomeStatus::Revert, reason.into_bytes()));
        }
        if read_store(host, contract, b"cw20:info")?.is_some() {
            return Ok((OutcomeStatus::Revert, b"cw20 already instantiated".to_vec()));
        }
        let name = init_cw20
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("CW20");
        let symbol = init_cw20
            .get("symbol")
            .and_then(|v| v.as_str())
            .unwrap_or("CW");
        let decimals = init_cw20
            .get("decimals")
            .and_then(|v| v.as_u64())
            .unwrap_or(6);
        let mut total = 0u128;
        if let Some(arr) = init_cw20.get("initial_balances").and_then(|v| v.as_array()) {
            for item in arr {
                let addr = item
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if addr.is_empty() {
                    return Ok((
                        OutcomeStatus::Revert,
                        b"empty cw20 initial balance address".to_vec(),
                    ));
                }
                let Some(amt_str) = item.get("amount").and_then(|v| v.as_str()) else {
                    return Ok((
                        OutcomeStatus::Revert,
                        b"missing cw20 initial balance amount".to_vec(),
                    ));
                };
                let Ok(amt) = amt_str.parse::<u128>() else {
                    return Ok((
                        OutcomeStatus::Revert,
                        b"invalid cw20 initial balance amount".to_vec(),
                    ));
                };
                let Some(next_total) = total.checked_add(amt) else {
                    return Ok((OutcomeStatus::Revert, b"cw20 supply overflow".to_vec()));
                };
                total = next_total;
                write_store(
                    host,
                    contract,
                    format!("cw20:bal:{addr}").as_bytes(),
                    Some(amt.to_string().as_bytes()),
                )?;
            }
        }
        let info = serde_json::json!({
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "total_supply": total.to_string(),
        });
        let info_b = serde_json::to_vec(&info).map_err(|e| e.to_string())?;
        write_store(host, contract, b"cw20:info", Some(&info_b))?;
        return Ok((OutcomeStatus::Success, info_b));
    }

    if let Some(tr) = exec_obj.get("transfer") {
        let rcpt = tr
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = tr
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let fk = format!("cw20:bal:{sender_str}");
        let cur_from: u128 = read_store(host, contract, fk.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if cur_from < amt {
            return Ok((OutcomeStatus::Revert, b"insufficient CW20 balance".to_vec()));
        }
        write_store(
            host,
            contract,
            fk.as_bytes(),
            Some((cur_from - amt).to_string().as_bytes()),
        )?;
        let tk = format!("cw20:bal:{rcpt}");
        let cur_to: u128 = read_store(host, contract, tk.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        write_store(
            host,
            contract,
            tk.as_bytes(),
            Some(cur_to.saturating_add(amt).to_string().as_bytes()),
        )?;
        let topic_arr: [u8; 32] = Sha256::digest(b"wasm:transfer").into();
        host.emit_log(EeLog {
            emitter: EeIdentity {
                ee: EeId::WASM,
                id: contract.to_vec(),
            },
            topics: vec![topic_arr.to_vec()],
            data: format!("{sender_str}->{rcpt}:{amt}").into_bytes(),
        })
        .map_err(|e| e.to_string())?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(sa) = exec_obj.get("set_allowance") {
        let spender = sa
            .get("spender")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = sa
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let ak = format!("cw20:alw:{sender_str}:{spender}");
        write_store(
            host,
            contract,
            ak.as_bytes(),
            Some(amt.to_string().as_bytes()),
        )?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(inc) = exec_obj.get("increase_allowance") {
        let spender = inc
            .get("spender")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = inc
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let ak = format!("cw20:alw:{sender_str}:{spender}");
        let cur: u128 = read_store(host, contract, ak.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        write_store(
            host,
            contract,
            ak.as_bytes(),
            Some(cur.saturating_add(amt).to_string().as_bytes()),
        )?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(tf) = exec_obj.get("transfer_from") {
        let owner = tf.get("owner").and_then(|v| v.as_str()).unwrap_or_default();
        let rcpt = tf
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let amt: u128 = tf
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let ak = format!("cw20:alw:{owner}:{sender_str}");
        let alw: u128 = read_store(host, contract, ak.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if alw < amt {
            return Ok((
                OutcomeStatus::Revert,
                b"insufficient CW20 allowance".to_vec(),
            ));
        }
        let fk = format!("cw20:bal:{owner}");
        let bal: u128 = read_store(host, contract, fk.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if bal < amt {
            return Ok((OutcomeStatus::Revert, b"insufficient CW20 balance".to_vec()));
        }
        write_store(
            host,
            contract,
            ak.as_bytes(),
            Some((alw - amt).to_string().as_bytes()),
        )?;
        write_store(
            host,
            contract,
            fk.as_bytes(),
            Some((bal - amt).to_string().as_bytes()),
        )?;
        let tk = format!("cw20:bal:{rcpt}");
        let cur_to: u128 = read_store(host, contract, tk.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        write_store(
            host,
            contract,
            tk.as_bytes(),
            Some(cur_to.saturating_add(amt).to_string().as_bytes()),
        )?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(mint_nft) = exec_obj.get("mint_nft") {
        if let Err(reason) = require_creator_or_self(host, contract, sender_str) {
            return Ok((OutcomeStatus::Revert, reason.into_bytes()));
        }
        let tid = mint_nft
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or("1");
        if read_store(host, contract, format!("cw721:owner:{tid}").as_bytes())?.is_some() {
            return Ok((OutcomeStatus::Revert, b"cw721 already minted".to_vec()));
        }
        let owner = mint_nft
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or(sender_str);
        let uri = mint_nft
            .get("token_uri")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        write_store(
            host,
            contract,
            format!("cw721:owner:{tid}").as_bytes(),
            Some(owner.as_bytes()),
        )?;
        write_store(
            host,
            contract,
            format!("cw721:uri:{tid}").as_bytes(),
            Some(uri.as_bytes()),
        )?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(appr_nft) = exec_obj.get("approve") {
        let spender = appr_nft
            .get("spender")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let tid = appr_nft
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let owner_k = format!("cw721:owner:{tid}");
        let owner = read_store(host, contract, owner_k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        if owner != sender_str {
            return Ok((OutcomeStatus::Revert, b"not cw721 owner".to_vec()));
        }
        write_store(
            host,
            contract,
            format!("cw721:appr:{tid}").as_bytes(),
            Some(spender.as_bytes()),
        )?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(tn) = exec_obj.get("transfer_nft") {
        let rcpt = tn
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let tid = tn
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let owner_k = format!("cw721:owner:{tid}");
        let appr_k = format!("cw721:appr:{tid}");
        let owner = read_store(host, contract, owner_k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let appr = read_store(host, contract, appr_k.as_bytes())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        if sender_str != owner && sender_str != appr {
            return Ok((OutcomeStatus::Revert, b"cw721 unauthorized".to_vec()));
        }
        write_store(host, contract, owner_k.as_bytes(), Some(rcpt.as_bytes()))?;
        write_store(host, contract, appr_k.as_bytes(), None)?;
        return Ok((OutcomeStatus::Success, b"{\"ok\":true}".to_vec()));
    }

    if let Some(custom_val) = exec_obj.get("budlum_msg") {
        if let Err(reason) = require_creator_or_self(host, contract, sender_str) {
            return Ok((OutcomeStatus::Revert, reason.into_bytes()));
        }
        let bmsg: BudlumMsg = serde_json::from_value(custom_val.clone())
            .map_err(|e| format!("invalid BudlumMsg: {e}"))?;
        match bmsg {
            BudlumMsg::UniversalCall {
                target_ee,
                target_hex,
                input_hex,
                value_attos,
                gas_limit_bgu,
            } => {
                let target_b = hex::decode(target_hex).map_err(|e| e.to_string())?;
                let input_b = hex::decode(input_hex).map_err(|e| e.to_string())?;
                if has_reserved_static_prefix(&input_b) {
                    return Err(String::from(
                        "BudlumMsg::UniversalCall input cannot carry reserved static prefix",
                    ));
                }
                let res = host
                    .universal_call(UniversalCall {
                        from: EeIdentity {
                            ee: EeId::WASM,
                            id: contract.to_vec(),
                        },
                        to_ee: EeId(target_ee),
                        target: EeIdentity {
                            ee: EeId(target_ee),
                            id: target_b,
                        },
                        value: BudAmount(value_attos),
                        input: input_b,
                        gas_limit: gas_limit_bgu.min(gas_budget),
                        is_static: false,
                    })
                    .map_err(|e| e.to_string())?;
                return Ok((
                    if res.success {
                        OutcomeStatus::Success
                    } else {
                        OutcomeStatus::Revert
                    },
                    res.output,
                ));
            }
        }
    }

    if let Some(kv) = exec_obj.get("put") {
        // A raw store write is restricted to the contract creator, self, or an
        // explicitly authorized universal caller, and reserved state prefixes
        // (`cw20:`, `cw721:`, `sys:`) may never be overwritten via `put`.
        if let Err(reason) = require_authorized_writer(host, contract, sender_str) {
            return Ok((OutcomeStatus::Revert, reason.into_bytes()));
        }
        let k = kv.get("key").and_then(|v| v.as_str()).unwrap_or_default();
        if k.is_empty()
            || k.starts_with("cw20:")
            || k.starts_with("cw721:")
            || k.starts_with("sys:")
        {
            return Ok((
                OutcomeStatus::Revert,
                b"reserved CosmWasm storage key prefix".to_vec(),
            ));
        }
        let v = kv.get("value").and_then(|v| v.as_str()).unwrap_or_default();
        let namespaced = format!("kv:{k}");
        write_store(host, contract, namespaced.as_bytes(), Some(v.as_bytes()))?;
        return Ok((OutcomeStatus::Success, v.as_bytes().to_vec()));
    }

    Ok((
        OutcomeStatus::Revert,
        b"unknown CosmWasm execute message".to_vec(),
    ))
}

impl ExecutionEnvironment for WasmEe {
    fn id(&self) -> EeId {
        EeId::WASM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        validate_cosmwasm_bytecode(code).map_err(|message| EeRefusal {
            code: RefusalCode::InvalidCode,
            message,
        })?;
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: String::from("cosmwasm-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let (is_static, raw_in) = unwrap_static_universal_input(&call.input);
        if host.charge(15_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }
        let sender_str = String::from_utf8_lossy(&call.caller.id).into_owned();

        match call.kind {
            EeCallKind::Deploy => {
                if is_static {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"static deploy refused".to_vec(),
                        gas_used: 15_000,
                    });
                }
                if let Err(reason) = validate_cosmwasm_bytecode(raw_in) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: reason.into_bytes(),
                        gas_used: 15_000,
                    });
                }
                let code_hash: [u8; 32] = Sha256::digest(raw_in).into();
                let Ok(code_ns) = Namespace::new(NS_WASM_CODE) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: 15_000,
                    });
                };
                let Ok(contract_ns) = Namespace::new(NS_WASM_CONTRACT) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: 15_000,
                    });
                };
                if host.write(&code_ns, &code_hash, Some(raw_in)).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed writing wasm code".to_vec(),
                        gas_used: 15_000,
                    });
                }
                let meta = WasmContractMeta {
                    code_hash: hex::encode(code_hash),
                    creator: sender_str,
                    label: String::from("cosmwasm"),
                };
                let meta_b = serde_json::to_vec(&meta).unwrap_or_default();
                if host
                    .write(&contract_ns, &call.target.id, Some(&meta_b))
                    .is_err()
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"failed writing wasm contract meta".to_vec(),
                        gas_used: 15_000,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: 25_000,
                })
            }
            EeCallKind::Call => {
                let code = match load_wasm_code(host, &call.target.id) {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: e.into_bytes(),
                            gas_used: 15_000,
                        });
                    }
                };
                if code.is_empty() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"unknown CosmWasm contract".to_vec(),
                        gas_used: 15_000,
                    });
                }
                let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(raw_in) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"CosmWasm message must be valid JSON".to_vec(),
                        gas_used: 15_000,
                    });
                };
                let res = if let Some(ptr) = decode_pointer_bytecode(&code) {
                    if EeId(ptr.home_ee) == EeId::EVM {
                        execute_wasm_pointer_to_evm(
                            &ptr,
                            &sender_str,
                            &msg_json,
                            is_static,
                            call.gas_limit,
                            host,
                        )
                    } else {
                        execute_wasm_pointer_to_svm_or_move(
                            &ptr,
                            &sender_str,
                            &msg_json,
                            is_static,
                            call.gas_limit,
                            host,
                        )
                    }
                } else {
                    execute_cosmwasm_json(
                        &call.target.id,
                        &sender_str,
                        &msg_json,
                        is_static,
                        call.gas_limit,
                        host,
                    )
                };
                match res {
                    Ok((status, output)) => Ok(EeOutcome {
                        status,
                        output,
                        gas_used: 20_000,
                    }),
                    Err(msg) if msg.contains("out of gas") => Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    }),
                    Err(msg) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: msg.into_bytes(),
                        gas_used: 20_000,
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
        let msg_json: serde_json::Value =
            serde_json::from_slice(&q.input).map_err(|e| EeRefusal {
                code: RefusalCode::InvalidCode,
                message: format!("invalid CosmWasm query JSON: {e}"),
            })?;
        let inner = msg_json.get("query").unwrap_or(&msg_json);
        handle_cw_query(host, &q.target.id, inner).map_err(|message| EeRefusal {
            code: RefusalCode::Denied,
            message,
        })
    }
}

#[cfg(test)]
mod creator_gate_tests {
    use super::*;
    use budlum_uel_abi::{HostError, OutOfGas, UniversalResult};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockHost {
        store: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    }

    impl MockHost {
        fn with_creator(contract: &[u8], creator: &str) -> Self {
            let mut host = Self::default();
            let meta = serde_json::json!({
                "code_hash": "00",
                "creator": creator,
                "label": "cosmwasm",
            });
            host.store.insert(
                (NS_WASM_CONTRACT.to_owned(), contract.to_vec()),
                serde_json::to_vec(&meta).unwrap(),
            );
            host
        }
    }

    impl HostRead for MockHost {
        fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
            Ok(self
                .store
                .get(&(ns.as_str().to_owned(), key.to_vec()))
                .cloned())
        }

        fn bud_balance(&self, _who: &EeIdentity) -> Result<BudAmount, HostError> {
            Ok(BudAmount(0))
        }
    }

    impl HostApi for MockHost {
        fn write(
            &mut self,
            ns: &Namespace,
            key: &[u8],
            value: Option<&[u8]>,
        ) -> Result<(), HostError> {
            match value {
                Some(v) => {
                    self.store
                        .insert((ns.as_str().to_owned(), key.to_vec()), v.to_vec());
                }
                None => {
                    self.store.remove(&(ns.as_str().to_owned(), key.to_vec()));
                }
            }
            Ok(())
        }

        fn universal_call(&mut self, _call: UniversalCall) -> Result<UniversalResult, HostError> {
            Err(HostError::Denied(String::from("no universal call in test")))
        }

        fn emit_log(&mut self, _log: EeLog) -> Result<(), HostError> {
            Ok(())
        }

        fn charge(&mut self, _bgu: u64) -> Result<(), OutOfGas> {
            Ok(())
        }

        fn bud_transfer(
            &mut self,
            _from: &EeIdentity,
            _to: &EeIdentity,
            _attos: u128,
        ) -> Result<(), HostError> {
            Ok(())
        }
    }

    #[test]
    fn non_creator_cannot_instantiate_mint_or_put() {
        let contract = b"contract-1";
        let mut host = MockHost::with_creator(contract, "creator");
        for msg in [
            serde_json::json!({
                "execute": {
                    "instantiate_cw20": {
                        "name": "T",
                        "initial_balances": [{"address": "attacker", "amount": "100"}]
                    }
                }
            }),
            serde_json::json!({"execute": {"mint_nft": {"token_id": "1", "owner": "attacker"}}}),
            serde_json::json!({"execute": {"put": {"key": "cw20:bal:attacker", "value": "100"}}}),
        ] {
            let (status, _) =
                execute_cosmwasm_json(contract, "attacker", &msg, false, 100_000, &mut host)
                    .unwrap();
            assert_eq!(status, OutcomeStatus::Revert, "msg: {msg}");
        }
        assert!(read_store(&host, contract, b"cw20:info").unwrap().is_none());
        assert!(read_store(&host, contract, b"cw721:owner:1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn creator_instantiates_once_and_mints_once() {
        let contract = b"contract-1";
        let mut host = MockHost::with_creator(contract, "creator");
        let init = serde_json::json!({
            "execute": {
                "instantiate_cw20": {
                    "name": "T",
                    "initial_balances": [{"address": "creator", "amount": "100"}]
                }
            }
        });
        let (status, _) =
            execute_cosmwasm_json(contract, "creator", &init, false, 100_000, &mut host).unwrap();
        assert_eq!(status, OutcomeStatus::Success);
        let (status, _) =
            execute_cosmwasm_json(contract, "creator", &init, false, 100_000, &mut host).unwrap();
        assert_eq!(status, OutcomeStatus::Revert);

        let mint =
            serde_json::json!({"execute": {"mint_nft": {"token_id": "1", "owner": "alice"}}});
        let (status, _) =
            execute_cosmwasm_json(contract, "creator", &mint, false, 100_000, &mut host).unwrap();
        assert_eq!(status, OutcomeStatus::Success);
        let steal =
            serde_json::json!({"execute": {"mint_nft": {"token_id": "1", "owner": "attacker"}}});
        let (status, _) =
            execute_cosmwasm_json(contract, "creator", &steal, false, 100_000, &mut host).unwrap();
        assert_eq!(status, OutcomeStatus::Revert);
        assert_eq!(
            read_store(&host, contract, b"cw721:owner:1").unwrap(),
            Some(b"alice".to_vec())
        );
    }

    #[test]
    fn authorize_caller_put_prefix_guard_and_integer_extend_opcodes() {
        // 0xac (i64.extend_i32_s) and 0xad (i64.extend_i32_u) are integer ops, not floats.
        let int_wasm =
            build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0xac, 0xad]);
        assert!(validate_cosmwasm_bytecode(&int_wasm).is_ok());

        let contract = b"contract-1";
        let mut host = MockHost::with_creator(contract, "creator");
        let auth_by_attacker =
            serde_json::json!({"execute": {"authorize_caller": {"caller": "bridge"}}});
        let (st, _) = execute_cosmwasm_json(
            contract,
            "attacker",
            &auth_by_attacker,
            false,
            100_000,
            &mut host,
        )
        .unwrap();
        assert_eq!(st, OutcomeStatus::Revert);

        let auth_by_creator =
            serde_json::json!({"execute": {"authorize_caller": {"caller": "bridge"}}});
        let (st, _) = execute_cosmwasm_json(
            contract,
            "creator",
            &auth_by_creator,
            false,
            100_000,
            &mut host,
        )
        .unwrap();
        assert_eq!(st, OutcomeStatus::Success);

        let put_ok = serde_json::json!({"execute": {"put": {"key": "hello", "value": "world"}}});
        let (st, _) =
            execute_cosmwasm_json(contract, "bridge", &put_ok, false, 100_000, &mut host).unwrap();
        assert_eq!(st, OutcomeStatus::Success);

        for reserved in [
            "cw20:bal:attacker",
            "cw721:owner:1",
            "sys:allowed_writer:x",
            "",
        ] {
            let put_bad = serde_json::json!({"execute": {"put": {"key": reserved, "value": "x"}}});
            let (st, _) =
                execute_cosmwasm_json(contract, "creator", &put_bad, false, 100_000, &mut host)
                    .unwrap();
            assert_eq!(st, OutcomeStatus::Revert);
        }
    }
}
