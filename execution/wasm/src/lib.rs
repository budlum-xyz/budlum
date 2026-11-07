//! Out-of-process CosmWasm Execution Environment (`EeId::WASM = 0x02`,  &).
//!
//! Runs `wasmi = "=2.0.0"` in pure-interpreter mode with:
//! - floating-point instructions forbidden (`Config::floats(false)`);
//! - 64 MiB linear-memory ceiling (`1024` Wasm 64-KiB pages);
//! - `1 wasmi fuel = 1 BGU` (`Section 8.9`);
//! - CosmWasm `interface_version_8` `Region` ABI (`allocate`, `deallocate`,
//!   `instantiate`, `execute`, `migrate`, `reply`, `query`);
//! - IBC entry-point exports (`ibc_*`) and `StakingMsg` / `DistributionMsg` /
//!   `GovMsg` / `IbcMsg` submessages deterministically refused (`Section 8.15`);
//! - `BudlumMsg::UniversalCall` and `BudlumQuery::UniversalView` routed over
//!   `HostApi::universal_call` (`Section 8.7.2`,).

#![forbid(unsafe_code)]

pub mod abi;
pub mod budlum_msg;

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

use budlum_uel_abi::transport::panic_digest;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use sha2::{Digest as _, Sha256};
use wasmi::errors::HostError as WasmiHostError;
use wasmi::{
    Caller, Config, Engine, Error as WasmiError, Extern, ExternType, Instance, Linker, Memory,
    Module, Store, StoreLimits, StoreLimitsBuilder, TypedResumableCall, Val,
};

use crate::abi::{StoredCodeMeta, StoredContractInfo, WasmTxAction, WasmViewAction};
use crate::budlum_msg::{
    b64_decode, b64_encode, bud_addr_canonicalize, bud_addr_humanize, BudlumMsg, BudlumQuery,
    CwBankMsg, CwBankQuery, CwBlockInfo, CwCoin, CwContractResult, CwCosmosMsg, CwEnv,
    CwEnvContract, CwMessageInfo, CwQueryRequest, CwReply, CwReplyOn, CwResponse,
    CwSubMsgResponse, CwSubMsgResult, CwSystemError, CwSystemResult, CwTxInfo, CwWasmMsg,
    CwWasmQuery,
};

/// Namespace holding uploaded `.wasm` bytecode and code-id counter (`Section 8.10`).
pub const NS_WASM_CODE: &str = "ee/wasm/code";
/// Namespace holding instantiated contract metadata and instantiate counter.
pub const NS_WASM_CONTRACT: &str = "ee/wasm/contract";
/// Namespace holding per-contract key-value storage (`ee/wasm/store`).
pub const NS_WASM_STORE: &str = "ee/wasm/store";

/// Maximum accepted `.wasm` upload size (`3 MiB`).
pub const MAX_WASM_CODE_BYTES: usize = 3 * 1024 * 1024;
/// Maximum linear memory size per CosmWasm instance (`64 MiB` = `1024` Wasm pages).
pub const MAX_WASM_MEMORY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum single `Region` read/write size across guest boundary (`2 MiB`).
pub const MAX_REGION_BYTES: usize = 2 * 1024 * 1024;
/// Read-only `query` fuel ceiling (`24_000_000` BGU, `Section 8.9`).
pub const QUERY_FUEL_LIMIT: u64 = 24_000_000;
/// `1 ubud` = `10^12` attoBUD (`Section 8.5`).
pub const ATTOS_PER_UBUD: u128 = 1_000_000_000_000;
/// Maximum nested submessage depth within WASM (`8`).
pub const MAX_SUBMSG_DEPTH: u32 = 8;

/// IBC entry points forbidden on Budlum T-Launch (`Section 8.15`,  item 2).
pub const FORBIDDEN_IBC_EXPORTS: &[&str] = &[
    "ibc_channel_open",
    "ibc_channel_connect",
    "ibc_channel_close",
    "ibc_packet_receive",
    "ibc_packet_ack",
    "ibc_packet_timeout",
];

const KEY_NEXT_CODE_ID: &[u8] = b"__meta/next_code_id";
const KEY_NEXT_INSTANCE_ID: &[u8] = b"__meta/next_instance_id";

/// Stateless worker handle implementing [`ExecutionEnvironment`] for `EeId::WASM`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WasmWorker;

#[derive(Debug, Clone)]
enum PendingHostOp {
    ChainQuery { request_bytes: Vec<u8> },
}

#[derive(Debug, Clone)]
struct SuspendForHostQuery;

impl fmt::Display for SuspendForHostQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("suspend_for_host_query")
    }
}

impl WasmiHostError for SuspendForHostQuery {}

#[derive(Debug, Clone)]
struct GuestAbort(String);

impl fmt::Display for GuestAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest abort: {}", self.0)
    }
}

impl WasmiHostError for GuestAbort {}

#[derive(Debug, Clone)]
struct KvIterator {
    items: Vec<(Vec<u8>, Vec<u8>)>,
    cursor: usize,
}

struct GuestStoreState {
    limits: StoreLimits,
    read_only: bool,
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    dirty_keys: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    iterators: BTreeMap<i32, KvIterator>,
    next_iter_id: i32,
    pending_op: Option<PendingHostOp>,
}

impl GuestStoreState {
    fn new(initial_kv: BTreeMap<Vec<u8>, Vec<u8>>, read_only: bool) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_WASM_MEMORY_BYTES)
            .memories(1)
            .instances(1)
            .tables(4)
            .table_elements(16_384)
            .build();
        Self {
            limits,
            read_only,
            kv: initial_kv,
            dirty_keys: BTreeMap::new(),
            iterators: BTreeMap::new(),
            next_iter_id: 1,
            pending_op: None,
        }
    }
}

/// Construct a deterministic `wasmi::Engine` with `floats(false)` and fuel metering.
#[must_use]
pub fn build_wasm_engine() -> Engine {
    let mut cfg = Config::default();
    cfg.floats(false);
    cfg.consume_fuel(true);
    cfg.wasm_simd(false);
    cfg.wasm_relaxed_simd(false);
    cfg.wasm_memory64(false);
    cfg.wasm_multi_memory(false);
    Engine::new(&cfg)
}

/// Compile and validate `.wasm` bytecode against Budlum's CosmWasm rules ().
pub fn compile_and_validate_module(engine: &Engine, code: &[u8]) -> Result<Module, EeRefusal> {
    if code.is_empty() {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("WASM bytecode cannot be empty"),
        });
    }
    if code.len() > MAX_WASM_CODE_BYTES {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: format!(
                "WASM bytecode size {} exceeds limit {MAX_WASM_CODE_BYTES}",
                code.len()
            ),
        });
    }
    if !code.starts_with(b"\0asm") {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("WASM payload must start with binary magic \\0asm"),
        });
    }
    let module = Module::new(engine, code).map_err(|err| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: format!("WASM validation failed (floats/SIMD forbidden): {err}"),
    })?;

    for forbidden in FORBIDDEN_IBC_EXPORTS {
        if module.get_export(forbidden).is_some() {
            return Err(EeRefusal {
                code: RefusalCode::Unsupported,
                message: format!("IBC entry point '{forbidden}' is refused on Budlum"),
            });
        }
    }

    let Some(ExternType::Memory(mem_ty)) = module.get_export("memory") else {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("CosmWasm module must export linear 'memory'"),
        });
    };
    let min_bytes = mem_ty.minimum().saturating_mul(65_536);
    if min_bytes > MAX_WASM_MEMORY_BYTES as u64 {
        return Err(EeRefusal {
            code: RefusalCode::TooLarge,
            message: format!("WASM initial memory {min_bytes} exceeds 64 MiB ceiling"),
        });
    }
    for req_fn in ["allocate", "deallocate"] {
        if !matches!(module.get_export(req_fn), Some(ExternType::Func(_))) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: format!("CosmWasm module missing required export '{req_fn}'"),
            });
        }
    }
    Ok(module)
}

fn ns(name: &str) -> Result<Namespace, String> {
    Namespace::new(name).map_err(|e| e.to_string())
}

fn code_blob_key(code_id: u64) -> Vec<u8> {
    let mut k = b"blob/".to_vec();
    k.extend_from_slice(&code_id.to_be_bytes());
    k
}

fn code_meta_key(code_id: u64) -> Vec<u8> {
    let mut k = b"meta/".to_vec();
    k.extend_from_slice(&code_id.to_be_bytes());
    k
}

fn contract_info_key(contract: &str) -> Vec<u8> {
    let mut k = b"info/".to_vec();
    k.extend_from_slice(contract.as_bytes());
    k
}

fn contract_keys_index_key(contract: &str) -> Vec<u8> {
    let mut k = b"keys/".to_vec();
    k.extend_from_slice(contract.as_bytes());
    k
}

fn contract_store_key(contract: &str, user_key: &[u8]) -> Vec<u8> {
    let addr_bytes = contract.as_bytes();
    let mut out = Vec::with_capacity(4 + addr_bytes.len() + user_key.len());
    out.extend_from_slice(&(addr_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(addr_bytes);
    out.extend_from_slice(user_key);
    out
}

fn load_contract_kv(
    host: &dyn HostRead,
    contract: &str,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, String> {
    let ns_contract = ns(NS_WASM_CONTRACT)?;
    let ns_store = ns(NS_WASM_STORE)?;
    let idx_raw = host
        .read(&ns_contract, &contract_keys_index_key(contract))
        .map_err(|e| e.to_string())?;
    let Some(idx_bytes) = idx_raw else {
        return Ok(BTreeMap::new());
    };
    let key_hexes: Vec<String> =
        serde_json::from_slice(&idx_bytes).map_err(|e| format!("corrupt key index: {e}"))?;
    let mut map = BTreeMap::new();
    for kh in key_hexes {
        let user_key = hex::decode(&kh).map_err(|e| format!("corrupt key hex: {e}"))?;
        let full_key = contract_store_key(contract, &user_key);
        if let Some(val) = host.read(&ns_store, &full_key).map_err(|e| e.to_string())? {
            map.insert(user_key, val);
        }
    }
    Ok(map)
}

fn flush_contract_kv(
    host: &mut dyn HostApi,
    contract: &str,
    final_kv: &BTreeMap<Vec<u8>, Vec<u8>>,
    dirty: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
) -> Result<(), String> {
    if dirty.is_empty() {
        return Ok(());
    }
    let ns_contract = ns(NS_WASM_CONTRACT)?;
    let ns_store = ns(NS_WASM_STORE)?;
    for (user_key, maybe_val) in dirty {
        let full_key = contract_store_key(contract, user_key);
        host.write(&ns_store, &full_key, maybe_val.as_deref())
            .map_err(|e| e.to_string())?;
    }
    let key_hexes: Vec<String> = final_kv.keys().map(hex::encode).collect();
    let idx_bytes = serde_json::to_vec(&key_hexes).map_err(|e| e.to_string())?;
    host.write(
        &ns_contract,
        &contract_keys_index_key(contract),
        Some(&idx_bytes),
    )
    .map_err(|e| e.to_string())
}

fn caller_memory<T>(caller: &Caller<'_, T>) -> Result<Memory, WasmiError> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(WasmiError::new("missing exported linear memory")),
    }
}

fn read_region_from_caller(
    caller: &Caller<'_, GuestStoreState>,
    region_ptr: i32,
) -> Result<Vec<u8>, WasmiError> {
    if region_ptr <= 0 {
        return Err(WasmiError::new("null or negative Region pointer"));
    }
    let mem = caller_memory(caller)?;
    let mut hdr = [0u8; 12];
    mem.read(caller, region_ptr as usize, &mut hdr)
        .map_err(|_| WasmiError::new("Region header out of bounds"))?;
    let offset = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let capacity = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    let length = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    if length > capacity || length > MAX_REGION_BYTES {
        return Err(WasmiError::new("Region length exceeds capacity or ceiling"));
    }
    let mut out = vec![0u8; length];
    if length > 0 {
        mem.read(caller, offset, &mut out)
            .map_err(|_| WasmiError::new("Region payload out of bounds"))?;
    }
    Ok(out)
}

fn write_into_existing_region_caller(
    caller: &mut Caller<'_, GuestStoreState>,
    region_ptr: i32,
    bytes: &[u8],
) -> Result<(), WasmiError> {
    if region_ptr <= 0 || bytes.len() > MAX_REGION_BYTES {
        return Err(WasmiError::new("invalid destination Region"));
    }
    let mem = caller_memory(caller)?;
    let mut hdr = [0u8; 12];
    mem.read(&*caller, region_ptr as usize, &mut hdr)
        .map_err(|_| WasmiError::new("Region header out of bounds"))?;
    let offset = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let capacity = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if bytes.len() > capacity {
        return Err(WasmiError::new("destination Region capacity too small"));
    }
    if !bytes.is_empty() {
        mem.write(&mut *caller, offset, bytes)
            .map_err(|_| WasmiError::new("Region payload write out of bounds"))?;
    }
    let len_le = (bytes.len() as u32).to_le_bytes();
    mem.write(&mut *caller, (region_ptr as usize).saturating_add(8), &len_le)
        .map_err(|_| WasmiError::new("Region length write out of bounds"))
}

fn alloc_and_write_caller(
    caller: &mut Caller<'_, GuestStoreState>,
    bytes: &[u8],
) -> Result<i32, WasmiError> {
    if bytes.len() > MAX_REGION_BYTES {
        return Err(WasmiError::new("allocation exceeds MAX_REGION_BYTES"));
    }
    let alloc_fn = match caller.get_export("allocate") {
        Some(Extern::Func(f)) => f,
        _ => return Err(WasmiError::new("missing exported allocate function")),
    };
    let typed = alloc_fn.typed::<i32, i32>(&*caller)?;
    let region_ptr = typed.call(&mut *caller, bytes.len() as i32)?;
    write_into_existing_region_caller(caller, region_ptr, bytes)?;
    Ok(region_ptr)
}

fn alloc_and_write_store(
    instance: &Instance,
    store: &mut Store<GuestStoreState>,
    bytes: &[u8],
) -> Result<i32, WasmiError> {
    if bytes.len() > MAX_REGION_BYTES {
        return Err(WasmiError::new("allocation exceeds MAX_REGION_BYTES"));
    }
    let alloc = instance.get_typed_func::<i32, i32>(&*store, "allocate")?;
    let region_ptr = alloc.call(&mut *store, bytes.len() as i32)?;
    if region_ptr <= 0 {
        return Err(WasmiError::new("guest allocate returned null Region"));
    }
    let Some(mem) = instance.get_memory(&*store, "memory") else {
        return Err(WasmiError::new("missing linear memory"));
    };
    let mut hdr = [0u8; 12];
    mem.read(&*store, region_ptr as usize, &mut hdr)
        .map_err(|_| WasmiError::new("Region header out of bounds"))?;
    let offset = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let capacity = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if bytes.len() > capacity {
        return Err(WasmiError::new("allocated Region smaller than requested"));
    }
    if !bytes.is_empty() {
        mem.write(&mut *store, offset, bytes)
            .map_err(|_| WasmiError::new("Region write out of bounds"))?;
    }
    let len_le = (bytes.len() as u32).to_le_bytes();
    mem.write(&mut *store, (region_ptr as usize).saturating_add(8), &len_le)
        .map_err(|_| WasmiError::new("Region length write out of bounds"))?;
    Ok(region_ptr)
}

fn read_region_store(
    instance: &Instance,
    store: &Store<GuestStoreState>,
    region_ptr: i32,
) -> Result<Vec<u8>, WasmiError> {
    if region_ptr <= 0 {
        return Err(WasmiError::new("null or negative Region pointer"));
    }
    let Some(mem) = instance.get_memory(store, "memory") else {
        return Err(WasmiError::new("missing linear memory"));
    };
    let mut hdr = [0u8; 12];
    mem.read(store, region_ptr as usize, &mut hdr)
        .map_err(|_| WasmiError::new("Region header out of bounds"))?;
    let offset = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let capacity = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    let length = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    if length > capacity || length > MAX_REGION_BYTES {
        return Err(WasmiError::new("Region length out of bounds"));
    }
    let mut out = vec![0u8; length];
    if length > 0 {
        mem.read(store, offset, &mut out)
            .map_err(|_| WasmiError::new("Region payload out of bounds"))?;
    }
    Ok(out)
}

fn encode_cw_sections(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
    }
    out
}

fn host_db_read(mut caller: Caller<'_, GuestStoreState>, key_ptr: i32) -> Result<i32, WasmiError> {
    let key = read_region_from_caller(&caller, key_ptr)?;
    let maybe_val = caller.data().kv.get(&key).cloned();
    match maybe_val {
        Some(val) => alloc_and_write_caller(&mut caller, &val),
        None => Ok(0),
    }
}

fn host_db_write(
    mut caller: Caller<'_, GuestStoreState>,
    key_ptr: i32,
    val_ptr: i32,
) -> Result<(), WasmiError> {
    if caller.data().read_only {
        let msg = String::from("db_write forbidden in read-only query context");
        return Err(WasmiError::host(GuestAbort(msg)));
    }
    let key = read_region_from_caller(&caller, key_ptr)?;
    let val = read_region_from_caller(&caller, val_ptr)?;
    let st = caller.data_mut();
    st.kv.insert(key.clone(), val.clone());
    st.dirty_keys.insert(key, Some(val));
    Ok(())
}

fn host_db_remove(mut caller: Caller<'_, GuestStoreState>, key_ptr: i32) -> Result<(), WasmiError> {
    if caller.data().read_only {
        let msg = String::from("db_remove forbidden in read-only query context");
        return Err(WasmiError::host(GuestAbort(msg)));
    }
    let key = read_region_from_caller(&caller, key_ptr)?;
    let st = caller.data_mut();
    st.kv.remove(&key);
    st.dirty_keys.insert(key, None);
    Ok(())
}

fn host_db_scan(
    mut caller: Caller<'_, GuestStoreState>,
    start_ptr: i32,
    end_ptr: i32,
    order: i32,
) -> Result<i32, WasmiError> {
    let start = if start_ptr == 0 {
        None
    } else {
        Some(read_region_from_caller(&caller, start_ptr)?)
    };
    let end = if end_ptr == 0 {
        None
    } else {
        Some(read_region_from_caller(&caller, end_ptr)?)
    };
    if order != 1 && order != 2 {
        return Err(WasmiError::new("invalid CosmWasm Order (expected 1 or 2)"));
    }
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = caller
        .data()
        .kv
        .iter()
        .filter(|(k, _)| {
            let after = start.as_ref().is_none_or(|s| k.as_slice() >= s.as_slice());
            let before = end.as_ref().is_none_or(|e| k.as_slice() < e.as_slice());
            after && before
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if order == 2 {
        items.reverse();
    }
    let st = caller.data_mut();
    let id = st.next_iter_id;
    st.next_iter_id = st.next_iter_id.saturating_add(1);
    st.iterators.insert(id, KvIterator { items, cursor: 0 });
    Ok(id)
}

fn host_db_next(mut caller: Caller<'_, GuestStoreState>, iter_id: i32) -> Result<i32, WasmiError> {
    let next_pair = {
        let st = caller.data_mut();
        let Some(it) = st.iterators.get_mut(&iter_id) else {
            return Err(WasmiError::new("unknown db_scan iterator"));
        };
        let pair = it.items.get(it.cursor).cloned();
        if pair.is_some() {
            it.cursor = it.cursor.saturating_add(1);
        }
        pair
    };
    let encoded = match next_pair {
        Some((k, v)) => encode_cw_sections(&[&k, &v]),
        None => encode_cw_sections(&[&[], &[]]),
    };
    alloc_and_write_caller(&mut caller, &encoded)
}

fn host_db_next_key(
    mut caller: Caller<'_, GuestStoreState>,
    iter_id: i32,
) -> Result<i32, WasmiError> {
    let next_k = {
        let st = caller.data_mut();
        let Some(it) = st.iterators.get_mut(&iter_id) else {
            return Err(WasmiError::new("unknown db_scan iterator"));
        };
        let key = it.items.get(it.cursor).map(|(k, _)| k.clone());
        if key.is_some() {
            it.cursor = it.cursor.saturating_add(1);
        }
        key
    };
    match next_k {
        Some(k) => alloc_and_write_caller(&mut caller, &k),
        None => Ok(0),
    }
}

fn host_db_next_value(
    mut caller: Caller<'_, GuestStoreState>,
    iter_id: i32,
) -> Result<i32, WasmiError> {
    let next_v = {
        let st = caller.data_mut();
        let Some(it) = st.iterators.get_mut(&iter_id) else {
            return Err(WasmiError::new("unknown db_scan iterator"));
        };
        let val = it.items.get(it.cursor).map(|(_, v)| v.clone());
        if val.is_some() {
            it.cursor = it.cursor.saturating_add(1);
        }
        val
    };
    match next_v {
        Some(v) => alloc_and_write_caller(&mut caller, &v),
        None => Ok(0),
    }
}

fn host_addr_validate(
    mut caller: Caller<'_, GuestStoreState>,
    src_ptr: i32,
) -> Result<i32, WasmiError> {
    let raw = read_region_from_caller(&caller, src_ptr)?;
    let Ok(s) = std::str::from_utf8(&raw) else {
        return alloc_and_write_caller(&mut caller, b"address is not valid UTF-8");
    };
    match bud_addr_canonicalize(s) {
        Ok(_) => Ok(0),
        Err(msg) => alloc_and_write_caller(&mut caller, msg.as_bytes()),
    }
}

fn host_addr_canonicalize(
    mut caller: Caller<'_, GuestStoreState>,
    src_ptr: i32,
    dst_ptr: i32,
) -> Result<i32, WasmiError> {
    let raw = read_region_from_caller(&caller, src_ptr)?;
    let Ok(s) = std::str::from_utf8(&raw) else {
        return alloc_and_write_caller(&mut caller, b"address is not valid UTF-8");
    };
    match bud_addr_canonicalize(s) {
        Ok(canon) => {
            write_into_existing_region_caller(&mut caller, dst_ptr, &canon)?;
            Ok(0)
        }
        Err(msg) => alloc_and_write_caller(&mut caller, msg.as_bytes()),
    }
}

fn host_addr_humanize(
    mut caller: Caller<'_, GuestStoreState>,
    src_ptr: i32,
    dst_ptr: i32,
) -> Result<i32, WasmiError> {
    let raw = read_region_from_caller(&caller, src_ptr)?;
    match bud_addr_humanize(&raw) {
        Ok(human) => {
            write_into_existing_region_caller(&mut caller, dst_ptr, human.as_bytes())?;
            Ok(0)
        }
        Err(msg) => alloc_and_write_caller(&mut caller, msg.as_bytes()),
    }
}

fn host_debug(caller: Caller<'_, GuestStoreState>, msg_ptr: i32) -> Result<(), WasmiError> {
    let _ = read_region_from_caller(&caller, msg_ptr)?;
    Ok(())
}

fn host_abort(caller: Caller<'_, GuestStoreState>, msg_ptr: i32) -> Result<(), WasmiError> {
    let raw = read_region_from_caller(&caller, msg_ptr).unwrap_or_default();
    let text = String::from_utf8_lossy(&raw).into_owned();
    Err(WasmiError::host(GuestAbort(text)))
}

fn host_chain_query(
    mut caller: Caller<'_, GuestStoreState>,
    req_ptr: i32,
) -> Result<i32, WasmiError> {
    let request_bytes = read_region_from_caller(&caller, req_ptr)?;
    caller.data_mut().pending_op = Some(PendingHostOp::ChainQuery { request_bytes });
    Err(WasmiError::host(SuspendForHostQuery))
}

fn build_linker(engine: &Engine) -> Result<Linker<GuestStoreState>, String> {
    let mut linker = <Linker<GuestStoreState>>::new(engine);
    linker
        .func_wrap("env", "db_read", host_db_read)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_write", host_db_write)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_remove", host_db_remove)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_scan", host_db_scan)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_next", host_db_next)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_next_key", host_db_next_key)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "db_next_value", host_db_next_value)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "addr_validate", host_addr_validate)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "addr_canonicalize", host_addr_canonicalize)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "addr_humanize", host_addr_humanize)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "debug", host_debug)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "abort", host_abort)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "chain_query", host_chain_query)
        .map_err(|e| e.to_string())?;
    Ok(linker)
}

enum QuerierAccess<'a> {
    ReadWrite(&'a mut dyn HostApi, EeIdentity),
    ReadOnly(&'a dyn HostRead),
}

impl QuerierAccess<'_> {
    fn as_read(&self) -> &dyn HostRead {
        match self {
            Self::ReadWrite(h, _) => *h,
            Self::ReadOnly(h) => *h,
        }
    }
}

fn service_chain_query(
    ctx: &BlockContext,
    access: &mut QuerierAccess<'_>,
    request_bytes: &[u8],
) -> Vec<u8> {
    let sys_res: CwSystemResult<CwContractResult<String>> = match serde_json::from_slice::<
        CwQueryRequest,
    >(request_bytes)
    {
        Err(err) => CwSystemResult::Error(CwSystemError::InvalidRequest {
            error: err.to_string(),
            request: b64_encode(request_bytes),
        }),
        Ok(
            CwQueryRequest::Staking(_)
            | CwQueryRequest::Distribution(_)
            | CwQueryRequest::Ibc(_),
        ) => CwSystemResult::Error(CwSystemError::UnsupportedRequest {
            kind: String::from("staking/distribution/ibc queries are closed on Budlum"),
        }),
        Ok(CwQueryRequest::Stargate { path, .. }) => {
            CwSystemResult::Error(CwSystemError::UnsupportedRequest { kind: path })
        }
        Ok(CwQueryRequest::Bank(CwBankQuery::Balance { address, denom })) => {
            if denom != "ubud" {
                let coin = serde_json::json!({ "amount": { "denom": denom, "amount": "0" } });
                CwSystemResult::Ok(CwContractResult::Ok(b64_encode(
                    coin.to_string().as_bytes(),
                )))
            } else {
                let id = EeIdentity {
                    ee: EeId::WASM,
                    id: address.into_bytes(),
                };
                let ubud = access
                    .as_read()
                    .bud_balance(&id)
                    .map_or(0u128, |b| b.0 / ATTOS_PER_UBUD);
                let coin = serde_json::json!({
                    "amount": { "denom": "ubud", "amount": ubud.to_string() }
                });
                CwSystemResult::Ok(CwContractResult::Ok(b64_encode(
                    coin.to_string().as_bytes(),
                )))
            }
        }
        Ok(CwQueryRequest::Bank(CwBankQuery::AllBalances { address })) => {
            let id = EeIdentity {
                ee: EeId::WASM,
                id: address.into_bytes(),
            };
            let ubud = access
                .as_read()
                .bud_balance(&id)
                .map_or(0u128, |b| b.0 / ATTOS_PER_UBUD);
            let list = if ubud == 0 {
                serde_json::json!({ "amount": [] })
            } else {
                serde_json::json!({
                    "amount": [{ "denom": "ubud", "amount": ubud.to_string() }]
                })
            };
            CwSystemResult::Ok(CwContractResult::Ok(b64_encode(
                list.to_string().as_bytes(),
            )))
        }
        Ok(CwQueryRequest::Wasm(CwWasmQuery::Raw { contract_addr, key })) => match b64_decode(&key)
        {
            Err(e) => CwSystemResult::Error(CwSystemError::InvalidRequest {
                error: e,
                request: key,
            }),
            Ok(raw_key) => {
                let Ok(ns_store) = ns(NS_WASM_STORE) else {
                    return b"{}".to_vec();
                };
                let val = access
                    .as_read()
                    .read(&ns_store, &contract_store_key(&contract_addr, &raw_key))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                CwSystemResult::Ok(CwContractResult::Ok(b64_encode(&val)))
            }
        },
        Ok(CwQueryRequest::Wasm(CwWasmQuery::ContractInfo { contract_addr })) => {
            let Ok(ns_contract) = ns(NS_WASM_CONTRACT) else {
                return b"{}".to_vec();
            };
            match access
                .as_read()
                .read(&ns_contract, &contract_info_key(&contract_addr))
            {
                Ok(Some(info_bytes)) => {
                    CwSystemResult::Ok(CwContractResult::Ok(b64_encode(&info_bytes)))
                }
                _ => CwSystemResult::Error(CwSystemError::NoSuchContract {
                    addr: contract_addr,
                }),
            }
        }
        Ok(CwQueryRequest::Wasm(CwWasmQuery::Smart { contract_addr, msg })) => {
            match b64_decode(&msg) {
                Err(e) => CwSystemResult::Error(CwSystemError::InvalidRequest {
                    error: e,
                    request: msg,
                }),
                Ok(query_json) => {
                    match run_smart_query_on_read(
                        ctx,
                        access.as_read(),
                        &contract_addr,
                        &query_json,
                        QUERY_FUEL_LIMIT / 2,
                    ) {
                        Ok(out_bytes) => {
                            CwSystemResult::Ok(CwContractResult::Ok(b64_encode(&out_bytes)))
                        }
                        Err(e) => CwSystemResult::Ok(CwContractResult::Error(e.message)),
                    }
                }
            }
        }
        Ok(CwQueryRequest::Custom(BudlumQuery::UniversalView {
            target_ee,
            target,
            input,
            gas_limit_bgu,
        })) => {
            let Ok(target_bytes) = b64_decode(&target) else {
                let fallback = CwSystemResult::<CwContractResult<String>>::Error(
                    CwSystemError::InvalidRequest {
                        error: String::from("bad base64 target"),
                        request: target,
                    },
                );
                return serde_json::to_vec(&fallback).unwrap_or_default();
            };
            let Ok(input_bytes) = b64_decode(&input) else {
                let fallback = CwSystemResult::<CwContractResult<String>>::Error(
                    CwSystemError::InvalidRequest {
                        error: String::from("bad base64 input"),
                        request: input,
                    },
                );
                return serde_json::to_vec(&fallback).unwrap_or_default();
            };
            match access {
                QuerierAccess::ReadWrite(host, from_id) => {
                    let ucall = UniversalCall {
                        from: from_id.clone(),
                        to_ee: EeId(target_ee),
                        target: EeIdentity {
                            ee: EeId(target_ee),
                            id: target_bytes,
                        },
                        value: BudAmount(0),
                        input: input_bytes,
                        gas_limit: gas_limit_bgu,
                        is_static: true,
                    };
                    match host.universal_call(ucall) {
                        Ok(res) if res.success => {
                            CwSystemResult::Ok(CwContractResult::Ok(b64_encode(&res.output)))
                        }
                        Ok(res) => CwSystemResult::Ok(CwContractResult::Error(format!(
                            "UniversalView reverted ({} bytes)",
                            res.output.len()
                        ))),
                        Err(err) => CwSystemResult::Error(CwSystemError::InvalidRequest {
                            error: err.to_string(),
                            request: String::new(),
                        }),
                    }
                }
                QuerierAccess::ReadOnly(_) => {
                    CwSystemResult::Error(CwSystemError::UnsupportedRequest {
                        kind: String::from(
                            "UniversalView requires coordinator UniversalCall context",
                        ),
                    })
                }
            }
        }
    };
    serde_json::to_vec(&sys_res).unwrap_or_default()
}

enum WasmInvokeOutcome {
    Ok { bytes: Vec<u8>, fuel_used: u64 },
    OutOfFuel { fuel_used: u64 },
    Trap { reason: String, fuel_used: u64 },
}

fn drive_resumable(
    ctx: &BlockContext,
    instance: &Instance,
    store: &mut Store<GuestStoreState>,
    access: &mut QuerierAccess<'_>,
    initial: TypedResumableCall<i32>,
    initial_fuel: u64,
) -> WasmInvokeOutcome {
    let mut cur = initial;
    loop {
        let rem = store.get_fuel().unwrap_or(0);
        let used_so_far = initial_fuel.saturating_sub(rem);
        match cur {
            TypedResumableCall::Finished(region_ptr) => {
                return match read_region_store(instance, store, region_ptr) {
                    Ok(bytes) => WasmInvokeOutcome::Ok {
                        bytes,
                        fuel_used: used_so_far,
                    },
                    Err(e) => WasmInvokeOutcome::Trap {
                        reason: e.to_string(),
                        fuel_used: used_so_far,
                    },
                };
            }
            TypedResumableCall::OutOfFuel(_) => {
                return WasmInvokeOutcome::OutOfFuel {
                    fuel_used: initial_fuel,
                };
            }
            TypedResumableCall::HostTrap(trap) => {
                let pending = store.data_mut().pending_op.take();
                let Some(PendingHostOp::ChainQuery { request_bytes }) = pending else {
                    return WasmInvokeOutcome::Trap {
                        reason: trap.host_error().to_string(),
                        fuel_used: used_so_far,
                    };
                };
                let response_json = service_chain_query(ctx, access, &request_bytes);
                let Ok(resp_ptr) = alloc_and_write_store(instance, store, &response_json) else {
                    return WasmInvokeOutcome::Trap {
                        reason: String::from("failed to allocate chain_query response Region"),
                        fuel_used: used_so_far,
                    };
                };
                match trap.resume(&mut *store, &[Val::I32(resp_ptr)]) {
                    Ok(next) => cur = next,
                    Err(e) => {
                        let rem2 = store.get_fuel().unwrap_or(0);
                        return WasmInvokeOutcome::Trap {
                            reason: e.to_string(),
                            fuel_used: initial_fuel.saturating_sub(rem2),
                        };
                    }
                }
            }
        }
    }
}

fn make_cw_env(ctx: &BlockContext, contract_addr: &str) -> CwEnv {
    let chain_id = if ctx.chain_id == 0 {
        String::from("budlum-testnet-1")
    } else {
        format!("budlum-{}", ctx.chain_id)
    };
    let nanos = u128::from(ctx.timestamp_ms).saturating_mul(1_000_000);
    CwEnv {
        block: CwBlockInfo {
            height: ctx.height,
            time: nanos.to_string(),
            chain_id,
        },
        transaction: Some(CwTxInfo { index: 0 }),
        contract: CwEnvContract {
            address: contract_addr.to_string(),
        },
    }
}

fn load_contract_module(
    engine: &Engine,
    host: &dyn HostRead,
    contract_addr: &str,
) -> Result<(StoredContractInfo, Module), EeRefusal> {
    let ns_contract = Namespace::new(NS_WASM_CONTRACT).map_err(|e| EeRefusal {
        code: RefusalCode::Denied,
        message: e.to_string(),
    })?;
    let ns_code = Namespace::new(NS_WASM_CODE).map_err(|e| EeRefusal {
        code: RefusalCode::Denied,
        message: e.to_string(),
    })?;
    let Some(info_bytes) = host
        .read(&ns_contract, &contract_info_key(contract_addr))
        .map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?
    else {
        return Err(EeRefusal {
            code: RefusalCode::Unsupported,
            message: format!("unknown CosmWasm contract '{contract_addr}'"),
        });
    };
    let info: StoredContractInfo =
        serde_json::from_slice(&info_bytes).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("corrupt StoredContractInfo: {e}"),
        })?;
    let Some(wasm_bytes) = host
        .read(&ns_code, &code_blob_key(info.code_id))
        .map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?
    else {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("missing code blob for code_id {}", info.code_id),
        });
    };
    let module = compile_and_validate_module(engine, &wasm_bytes)?;
    Ok((info, module))
}

fn run_smart_query_on_read(
    ctx: &BlockContext,
    host: &dyn HostRead,
    contract_addr: &str,
    query_json: &[u8],
    fuel_budget: u64,
) -> Result<Vec<u8>, EeRefusal> {
    let engine = build_wasm_engine();
    let (_, module) = load_contract_module(&engine, host, contract_addr)?;
    let linker = build_linker(&engine).map_err(|m| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: m,
    })?;
    let kv = load_contract_kv(host, contract_addr).map_err(|m| EeRefusal {
        code: RefusalCode::Denied,
        message: m,
    })?;
    let mut store = Store::new(&engine, GuestStoreState::new(kv, true));
    store.limiter(|s| &mut s.limits);
    store.set_fuel(fuel_budget).map_err(|e| EeRefusal {
        code: RefusalCode::Denied,
        message: e.to_string(),
    })?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("WASM instantiate failed: {e}"),
        })?;
    let env_bytes = serde_json::to_vec(&make_cw_env(ctx, contract_addr)).map_err(|e| EeRefusal {
        code: RefusalCode::Denied,
        message: e.to_string(),
    })?;
    let env_ptr = alloc_and_write_store(&instance, &mut store, &env_bytes).map_err(|e| {
        EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        }
    })?;
    let msg_ptr = alloc_and_write_store(&instance, &mut store, query_json).map_err(|e| {
        EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        }
    })?;
    let query_fn = instance
        .get_typed_func::<(i32, i32), i32>(&store, "query")
        .map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("missing 'query' export: {e}"),
        })?;
    let resumable = query_fn
        .call_resumable(&mut store, (env_ptr, msg_ptr))
        .map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: format!("WASM query trap: {e}"),
        })?;
    let mut access = QuerierAccess::ReadOnly(host);
    match drive_resumable(ctx, &instance, &mut store, &mut access, resumable, fuel_budget) {
        WasmInvokeOutcome::Ok { bytes, .. } => {
            let parsed: CwContractResult<String> =
                serde_json::from_slice(&bytes).map_err(|e| EeRefusal {
                    code: RefusalCode::Denied,
                    message: format!("bad ContractResult<Binary> JSON: {e}"),
                })?;
            match parsed {
                CwContractResult::Ok(b64_bin) => b64_decode(&b64_bin).map_err(|e| EeRefusal {
                    code: RefusalCode::Denied,
                    message: e,
                }),
                CwContractResult::Error(err_msg) => Err(EeRefusal {
                    code: RefusalCode::Denied,
                    message: err_msg,
                }),
            }
        }
        WasmInvokeOutcome::OutOfFuel { .. } => Err(EeRefusal {
            code: RefusalCode::Denied,
            message: String::from("WASM query exhausted fuel"),
        }),
        WasmInvokeOutcome::Trap { reason, .. } => Err(EeRefusal {
            code: RefusalCode::Denied,
            message: reason,
        }),
    }
}

fn next_u64_counter(host: &mut dyn HostApi, ns_obj: &Namespace, key: &[u8]) -> Result<u64, String> {
    let cur = match host.read(ns_obj, key).map_err(|e| e.to_string())? {
        Some(b) if b.len() == 8 => {
            let Ok(arr) = <[u8; 8]>::try_from(b.as_slice()) else {
                return Err(String::from("corrupt counter"));
            };
            u64::from_be_bytes(arr)
        }
        _ => 1,
    };
    let next = cur.saturating_add(1);
    host.write(ns_obj, key, Some(&next.to_be_bytes()))
        .map_err(|e| e.to_string())?;
    Ok(cur)
}

fn derive_instantiate_address(code_id: u64, instance_id: u64) -> Result<String, String> {
    let mut h = Sha256::new();
    h.update(b"BDLM_CW_INSTANTIATE_V1");
    h.update(code_id.to_be_bytes());
    h.update(instance_id.to_be_bytes());
    let digest: [u8; 32] = h.finalize().into();
    bud_addr_humanize(&digest)
}

fn derive_instantiate2_address(
    creator: &str,
    checksum_hex: &str,
    salt: &[u8],
) -> Result<String, String> {
    let mut h = Sha256::new();
    h.update(b"BDLM_CW_INSTANTIATE2_V1");
    h.update((creator.len() as u64).to_le_bytes());
    h.update(creator.as_bytes());
    h.update(checksum_hex.as_bytes());
    h.update((salt.len() as u64).to_le_bytes());
    h.update(salt);
    let digest: [u8; 32] = h.finalize().into();
    bud_addr_humanize(&digest)
}

#[allow(clippy::too_many_arguments)]
fn invoke_contract_entry(
    ctx: &BlockContext,
    host: &mut dyn HostApi,
    contract_addr: &str,
    entry: &str,
    info_opt: Option<&CwMessageInfo>,
    msg_bytes: &[u8],
    fuel_budget: u64,
    submsg_depth: u32,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String, u64)> {
    if submsg_depth > MAX_SUBMSG_DEPTH {
        return Err((
            OutcomeStatus::Revert,
            String::from("CosmWasm submessage depth limit exceeded"),
            0,
        ));
    }
    let engine = build_wasm_engine();
    let (_, module) = load_contract_module(&engine, host, contract_addr)
        .map_err(|e| (OutcomeStatus::InvalidCode, e.message, 0))?;
    let linker = build_linker(&engine).map_err(|m| (OutcomeStatus::InvalidCode, m, 0))?;
    let initial_kv =
        load_contract_kv(host, contract_addr).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let mut store = Store::new(&engine, GuestStoreState::new(initial_kv, false));
    store.limiter(|s| &mut s.limits);
    store
        .set_fuel(fuel_budget)
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| (OutcomeStatus::InvalidCode, e.to_string(), 0))?;

    let env_json = serde_json::to_vec(&make_cw_env(ctx, contract_addr))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    let env_ptr = alloc_and_write_store(&instance, &mut store, &env_json)
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    let msg_ptr = alloc_and_write_store(&instance, &mut store, msg_bytes)
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;

    let resumable = if let Some(info) = info_opt {
        let info_json =
            serde_json::to_vec(info).map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
        let info_ptr = alloc_and_write_store(&instance, &mut store, &info_json)
            .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
        let func = instance
            .get_typed_func::<(i32, i32, i32), i32>(&store, entry)
            .map_err(|e| (OutcomeStatus::InvalidCode, e.to_string(), 0))?;
        func.call_resumable(&mut store, (env_ptr, info_ptr, msg_ptr))
            .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
    } else {
        let func = instance
            .get_typed_func::<(i32, i32), i32>(&store, entry)
            .map_err(|e| (OutcomeStatus::InvalidCode, e.to_string(), 0))?;
        func.call_resumable(&mut store, (env_ptr, msg_ptr))
            .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
    };

    let contract_id = EeIdentity {
        ee: EeId::WASM,
        id: contract_addr.as_bytes().to_vec(),
    };
    let invoke_res = {
        let mut access = QuerierAccess::ReadWrite(host, contract_id.clone());
        drive_resumable(ctx, &instance, &mut store, &mut access, resumable, fuel_budget)
    };
    let (resp_bytes, mut total_fuel) = match invoke_res {
        WasmInvokeOutcome::Ok { bytes, fuel_used } => (bytes, fuel_used),
        WasmInvokeOutcome::OutOfFuel { fuel_used } => {
            return Err((
                OutcomeStatus::OutOfGas,
                String::from("WASM out of fuel"),
                fuel_used,
            ));
        }
        WasmInvokeOutcome::Trap { reason, fuel_used } => {
            return Err((OutcomeStatus::Revert, reason, fuel_used));
        }
    };

    let cw_res: CwContractResult<CwResponse> = serde_json::from_slice(&resp_bytes)
        .map_err(|e| (OutcomeStatus::Revert, format!("bad Response JSON: {e}"), total_fuel))?;
    let resp = match cw_res {
        CwContractResult::Ok(r) => r,
        CwContractResult::Error(err_msg) => {
            return Err((OutcomeStatus::Revert, err_msg, total_fuel));
        }
    };

    // Validate none of the submessages use forbidden Staking/Distribution/Gov/IBC before flushing.
    for sub in &resp.messages {
        if matches!(
            sub.msg,
            CwCosmosMsg::Staking(_)
                | CwCosmosMsg::Distribution(_)
                | CwCosmosMsg::Gov(_)
                | CwCosmosMsg::Ibc(_)
                | CwCosmosMsg::Stargate { .. }
        ) {
            return Err((
                OutcomeStatus::Revert,
                String::from("StakingMsg/DistributionMsg/GovMsg/IbcMsg refused on Budlum"),
                total_fuel,
            ));
        }
    }

    let guest_state = store.into_data();
    flush_contract_kv(host, contract_addr, &guest_state.kv, &guest_state.dirty_keys)
        .map_err(|m| (OutcomeStatus::Revert, m, total_fuel))?;

    if !resp.attributes.is_empty() || !resp.events.is_empty() {
        let log_json = serde_json::json!({
            "contract": contract_addr,
            "entry": entry,
            "attributes": resp.attributes,
            "events": resp.events,
        });
        let _ = host.emit_log(EeLog {
            emitter: contract_id.clone(),
            topics: vec![b"wasm".to_vec()],
            data: serde_json::to_vec(&log_json).unwrap_or_default(),
        });
    }

    let mut final_data = match &resp.data {
        Some(d_b64) => b64_decode(d_b64)
            .map_err(|m| (OutcomeStatus::Revert, m, total_fuel))?,
        None => Vec::new(),
    };

    for sub in &resp.messages {
        let rem_fuel = fuel_budget.saturating_sub(total_fuel);
        let sub_limit = sub.gas_limit.map_or(rem_fuel, |g| g.min(rem_fuel));
        let sub_exec = dispatch_submsg(
            ctx,
            host,
            contract_addr,
            &sub.msg,
            sub_limit,
            submsg_depth.saturating_add(1),
        );
        let (sub_result, sub_used) = match sub_exec {
            Ok((sub_data, used)) => (
                CwSubMsgResult::Ok(CwSubMsgResponse {
                    events: Vec::new(),
                    data: if sub_data.is_empty() {
                        None
                    } else {
                        Some(b64_encode(&sub_data))
                    },
                }),
                used,
            ),
            Err((OutcomeStatus::OutOfGas, msg, used)) => {
                return Err((OutcomeStatus::OutOfGas, msg, total_fuel.saturating_add(used)));
            }
            Err((_, err_msg, used)) => (CwSubMsgResult::Error(err_msg), used),
        };
        total_fuel = total_fuel.saturating_add(sub_used);

        let is_ok = matches!(sub_result, CwSubMsgResult::Ok(_));
        let should_reply = match sub.reply_on {
            CwReplyOn::Always => true,
            CwReplyOn::Success => is_ok,
            CwReplyOn::Error => !is_ok,
            CwReplyOn::Never => false,
        };
        if !is_ok && matches!(sub.reply_on, CwReplyOn::Never | CwReplyOn::Success) {
            let CwSubMsgResult::Error(e) = sub_result else {
                return Err((OutcomeStatus::Revert, String::from("submsg failed"), total_fuel));
            };
            return Err((OutcomeStatus::Revert, e, total_fuel));
        }
        if should_reply {
            let reply_payload = CwReply {
                id: sub.id,
                result: sub_result,
            };
            let reply_json = serde_json::to_vec(&reply_payload)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string(), total_fuel))?;
            let (reply_data, reply_used) = invoke_contract_entry(
                ctx,
                host,
                contract_addr,
                "reply",
                None,
                &reply_json,
                fuel_budget.saturating_sub(total_fuel),
                submsg_depth.saturating_add(1),
            )?;
            total_fuel = total_fuel.saturating_add(reply_used);
            if !reply_data.is_empty() {
                final_data = reply_data;
            }
        }
    }

    Ok((final_data, total_fuel))
}

fn parse_ubud_coins(coins: &[CwCoin]) -> Result<u64, String> {
    let mut total: u64 = 0;
    for c in coins {
        if c.denom != "ubud" {
            return Err(format!("unsupported WASM coin denom '{}'", c.denom));
        }
        let amt = c
            .amount
            .parse::<u64>()
            .map_err(|_| format!("invalid ubud amount '{}'", c.amount))?;
        total = total
            .checked_add(amt)
            .ok_or_else(|| String::from("ubud amount overflow"))?;
    }
    Ok(total)
}

fn dispatch_submsg(
    ctx: &BlockContext,
    host: &mut dyn HostApi,
    sender_contract: &str,
    msg: &CwCosmosMsg,
    fuel_budget: u64,
    depth: u32,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String, u64)> {
    let from_id = EeIdentity {
        ee: EeId::WASM,
        id: sender_contract.as_bytes().to_vec(),
    };
    match msg {
        CwCosmosMsg::Bank(CwBankMsg::Send { to_address, amount }) => {
            let ubud = parse_ubud_coins(amount).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let attos = u128::from(ubud).saturating_mul(ATTOS_PER_UBUD);
            let to_id = EeIdentity {
                ee: EeId::WASM,
                id: to_address.as_bytes().to_vec(),
            };
            host.bud_transfer(&from_id, &to_id, attos)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
            Ok((Vec::new(), 1_000))
        }
        CwCosmosMsg::Bank(CwBankMsg::Burn { .. }) => Err((
            OutcomeStatus::Revert,
            String::from("BankMsg::Burn is not enabled on Budlum"),
            0,
        )),
        CwCosmosMsg::Custom(BudlumMsg::UniversalCall {
            target_ee,
            target,
            input,
            value_attos,
            gas_limit_bgu,
            is_static,
        }) => {
            let target_bytes = b64_decode(target).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let input_bytes = b64_decode(input).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let val_u128 = value_attos
                .parse::<u128>()
                .map_err(|_| (OutcomeStatus::Revert, String::from("bad value_attos"), 0))?;
            if *is_static && val_u128 != 0 {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("static UniversalCall cannot carry value"),
                    0,
                ));
            }
            let ucall = UniversalCall {
                from: from_id,
                to_ee: EeId(*target_ee),
                target: EeIdentity {
                    ee: EeId(*target_ee),
                    id: target_bytes,
                },
                value: BudAmount(val_u128),
                input: input_bytes,
                gas_limit: (*gas_limit_bgu).min(fuel_budget),
                is_static: *is_static,
            };
            match host.universal_call(ucall) {
                Ok(res) if res.success => Ok((res.output, res.gas_used)),
                Ok(res) => Err((
                    OutcomeStatus::Revert,
                    String::from("UniversalCall reverted"),
                    res.gas_used,
                )),
                Err(e) => Err((OutcomeStatus::Revert, e.to_string(), 0)),
            }
        }
        CwCosmosMsg::Wasm(CwWasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) => {
            let ubud = parse_ubud_coins(funds).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            if ubud > 0 {
                let to_id = EeIdentity {
                    ee: EeId::WASM,
                    id: contract_addr.as_bytes().to_vec(),
                };
                host.bud_transfer(
                    &from_id,
                    &to_id,
                    u128::from(ubud).saturating_mul(ATTOS_PER_UBUD),
                )
                .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
            }
            let decoded_msg = b64_decode(msg).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let info = CwMessageInfo {
                sender: sender_contract.to_string(),
                funds: funds.clone(),
            };
            invoke_contract_entry(
                ctx,
                host,
                contract_addr,
                "execute",
                Some(&info),
                &decoded_msg,
                fuel_budget,
                depth,
            )
        }
        CwCosmosMsg::Wasm(CwWasmMsg::Instantiate {
            admin,
            code_id,
            msg,
            funds,
            label,
        }) => {
            let ubud = parse_ubud_coins(funds).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let decoded_msg = b64_decode(msg).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            execute_instantiate(
                ctx,
                host,
                sender_contract,
                *code_id,
                admin.clone(),
                label.clone(),
                &decoded_msg,
                ubud,
                None,
                fuel_budget,
                depth,
            )
        }
        CwCosmosMsg::Wasm(CwWasmMsg::Instantiate2 {
            admin,
            code_id,
            label,
            msg,
            funds,
            salt,
        }) => {
            let ubud = parse_ubud_coins(funds).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let decoded_msg = b64_decode(msg).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            let salt_bytes = b64_decode(salt).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            execute_instantiate(
                ctx,
                host,
                sender_contract,
                *code_id,
                admin.clone(),
                label.clone(),
                &decoded_msg,
                ubud,
                Some(&salt_bytes),
                fuel_budget,
                depth,
            )
        }
        CwCosmosMsg::Wasm(CwWasmMsg::Migrate {
            contract_addr,
            new_code_id,
            msg,
        }) => {
            let decoded_msg = b64_decode(msg).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            execute_migrate(
                ctx,
                host,
                sender_contract,
                contract_addr,
                *new_code_id,
                &decoded_msg,
                fuel_budget,
                depth,
            )
        }
        CwCosmosMsg::Staking(_)
        | CwCosmosMsg::Distribution(_)
        | CwCosmosMsg::Gov(_)
        | CwCosmosMsg::Ibc(_)
        | CwCosmosMsg::Stargate { .. } => Err((
            OutcomeStatus::Revert,
            String::from("forbidden CosmosMsg variant"),
            0,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_instantiate(
    ctx: &BlockContext,
    host: &mut dyn HostApi,
    sender_str: &str,
    code_id: u64,
    admin: Option<String>,
    label: String,
    init_msg: &[u8],
    funds_ubud: u64,
    salt_opt: Option<&[u8]>,
    fuel_budget: u64,
    depth: u32,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String, u64)> {
    let ns_code = ns(NS_WASM_CODE).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let ns_contract = ns(NS_WASM_CONTRACT).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let Some(meta_bytes) = host
        .read(&ns_code, &code_meta_key(code_id))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
    else {
        return Err((
            OutcomeStatus::InvalidCode,
            format!("unknown code_id {code_id}"),
            0,
        ));
    };
    let meta: StoredCodeMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;

    let contract_addr = match salt_opt {
        Some(salt) => derive_instantiate2_address(sender_str, &meta.checksum_hex, salt)
            .map_err(|m| (OutcomeStatus::Revert, m, 0))?,
        None => {
            let inst_id = next_u64_counter(host, &ns_contract, KEY_NEXT_INSTANCE_ID)
                .map_err(|m| (OutcomeStatus::Revert, m, 0))?;
            derive_instantiate_address(code_id, inst_id)
                .map_err(|m| (OutcomeStatus::Revert, m, 0))?
        }
    };
    if host
        .read(&ns_contract, &contract_info_key(&contract_addr))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
        .is_some()
    {
        return Err((
            OutcomeStatus::Revert,
            format!("contract '{contract_addr}' already exists"),
            0,
        ));
    }

    let info_rec = StoredContractInfo {
        code_id,
        creator: sender_str.to_string(),
        admin,
        label,
        created_height: ctx.height,
    };
    let info_bytes =
        serde_json::to_vec(&info_rec).map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    host.write(&ns_contract, &contract_info_key(&contract_addr), Some(&info_bytes))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;

    let mut funds = Vec::new();
    if funds_ubud > 0 {
        let from_id = EeIdentity {
            ee: EeId::WASM,
            id: sender_str.as_bytes().to_vec(),
        };
        let to_id = EeIdentity {
            ee: EeId::WASM,
            id: contract_addr.as_bytes().to_vec(),
        };
        host.bud_transfer(
            &from_id,
            &to_id,
            u128::from(funds_ubud).saturating_mul(ATTOS_PER_UBUD),
        )
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
        funds.push(CwCoin {
            denom: String::from("ubud"),
            amount: funds_ubud.to_string(),
        });
    }
    let msg_info = CwMessageInfo {
        sender: sender_str.to_string(),
        funds,
    };
    let (_, used) = invoke_contract_entry(
        ctx,
        host,
        &contract_addr,
        "instantiate",
        Some(&msg_info),
        init_msg,
        fuel_budget,
        depth,
    )?;
    Ok((contract_addr.into_bytes(), used))
}

#[allow(clippy::too_many_arguments)]
fn execute_migrate(
    ctx: &BlockContext,
    host: &mut dyn HostApi,
    sender_str: &str,
    contract_addr: &str,
    new_code_id: u64,
    migrate_msg: &[u8],
    fuel_budget: u64,
    depth: u32,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String, u64)> {
    let ns_code = ns(NS_WASM_CODE).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let ns_contract = ns(NS_WASM_CONTRACT).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    if host
        .read(&ns_code, &code_meta_key(new_code_id))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
        .is_none()
    {
        return Err((
            OutcomeStatus::InvalidCode,
            format!("unknown new_code_id {new_code_id}"),
            0,
        ));
    }
    let Some(info_bytes) = host
        .read(&ns_contract, &contract_info_key(contract_addr))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?
    else {
        return Err((
            OutcomeStatus::Revert,
            format!("unknown contract '{contract_addr}'"),
            0,
        ));
    };
    let mut info: StoredContractInfo = serde_json::from_slice(&info_bytes)
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    if info.admin.as_deref() != Some(sender_str) {
        return Err((
            OutcomeStatus::Revert,
            String::from("caller is not contract admin"),
            0,
        ));
    }
    info.code_id = new_code_id;
    let updated = serde_json::to_vec(&info).map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    host.write(&ns_contract, &contract_info_key(contract_addr), Some(&updated))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    invoke_contract_entry(
        ctx,
        host,
        contract_addr,
        "migrate",
        None,
        migrate_msg,
        fuel_budget,
        depth,
    )
}

fn sender_string(id: &EeIdentity) -> Result<String, String> {
    if let Ok(s) = std::str::from_utf8(&id.id) {
        if s.starts_with("bud1") {
            return Ok(s.to_string());
        }
    }
    if id.id.len() == 20 || id.id.len() == 32 {
        return bud_addr_humanize(&id.id);
    }
    let digest: [u8; 32] = Sha256::digest(&id.id).into();
    bud_addr_humanize(&digest)
}

fn store_wasm_code(
    host: &mut dyn HostApi,
    sender_str: &str,
    wasm_bytes: &[u8],
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String, u64)> {
    let engine = build_wasm_engine();
    if let Err(refusal) = compile_and_validate_module(&engine, wasm_bytes) {
        return Err((OutcomeStatus::InvalidCode, refusal.message, 0));
    }
    let ns_code = ns(NS_WASM_CODE).map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let code_id = next_u64_counter(host, &ns_code, KEY_NEXT_CODE_ID)
        .map_err(|m| (OutcomeStatus::Revert, m, 0))?;
    let checksum: [u8; 32] = Sha256::digest(wasm_bytes).into();
    let meta = StoredCodeMeta {
        code_id,
        creator: sender_str.to_string(),
        checksum_hex: hex::encode(checksum),
    };
    let meta_bytes =
        serde_json::to_vec(&meta).map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    host.write(&ns_code, &code_blob_key(code_id), Some(wasm_bytes))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    host.write(&ns_code, &code_meta_key(code_id), Some(&meta_bytes))
        .map_err(|e| (OutcomeStatus::Revert, e.to_string(), 0))?;
    let store_gas = (wasm_bytes.len() as u64).saturating_mul(10).max(5_000);
    Ok((code_id.to_be_bytes().to_vec(), store_gas))
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("unknown wasm engine panic")
    }
}

impl WasmWorker {
    fn execute_inner(ctx: &BlockContext, call: &EeCall, host: &mut dyn HostApi) -> EeOutcome {
        let Ok(sender) = sender_string(&call.caller) else {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"invalid caller identity".to_vec(),
                gas_used: 0,
            };
        };

        // `EeCallKind::Deploy` uploads raw `.wasm` bytecode and returns the 8-byte BE `code_id`.
        if call.kind == EeCallKind::Deploy {
            return match store_wasm_code(host, &sender, &call.input) {
                Ok((out, gas)) => {
                    let g = gas.min(call.gas_limit);
                    if host.charge(g).is_err() {
                        return EeOutcome {
                            status: OutcomeStatus::OutOfGas,
                            output: Vec::new(),
                            gas_used: call.gas_limit,
                        };
                    }
                    EeOutcome {
                        status: OutcomeStatus::Success,
                        output: out,
                        gas_used: g,
                    }
                }
                Err((status, msg, gas)) => {
                    let g = gas.min(call.gas_limit);
                    let _ = host.charge(g);
                    EeOutcome {
                        status,
                        output: msg.into_bytes(),
                        gas_used: g,
                    }
                }
            };
        }

        // Parse either `WasmTxAction` JSON envelope or direct `UniversalCall` contract JSON.
        let res = if let Ok(action) = serde_json::from_slice::<WasmTxAction>(&call.input) {
            match action {
                WasmTxAction::StoreCode { wasm_b64 } => match b64_decode(&wasm_b64) {
                    Ok(wasm_bytes) => store_wasm_code(host, &sender, &wasm_bytes),
                    Err(m) => Err((OutcomeStatus::InvalidCode, m, 0)),
                },
                WasmTxAction::Instantiate {
                    code_id,
                    admin,
                    label,
                    msg_b64,
                    funds_ubud,
                } => match b64_decode(&msg_b64) {
                    Ok(init_msg) => execute_instantiate(
                        ctx,
                        host,
                        &sender,
                        code_id,
                        admin,
                        label,
                        &init_msg,
                        funds_ubud,
                        None,
                        call.gas_limit,
                        0,
                    ),
                    Err(m) => Err((OutcomeStatus::Revert, m, 0)),
                },
                WasmTxAction::Instantiate2 {
                    code_id,
                    admin,
                    label,
                    msg_b64,
                    funds_ubud,
                    salt_b64,
                } => match (b64_decode(&msg_b64), b64_decode(&salt_b64)) {
                    (Ok(init_msg), Ok(salt)) => execute_instantiate(
                        ctx,
                        host,
                        &sender,
                        code_id,
                        admin,
                        label,
                        &init_msg,
                        funds_ubud,
                        Some(&salt),
                        call.gas_limit,
                        0,
                    ),
                    (Err(m), _) | (_, Err(m)) => Err((OutcomeStatus::Revert, m, 0)),
                },
                WasmTxAction::Execute {
                    contract,
                    msg_b64,
                    funds_ubud,
                } => match b64_decode(&msg_b64) {
                    Ok(exec_msg) => {
                        let mut funds = Vec::new();
                        if funds_ubud > 0 {
                            let from_id = EeIdentity {
                                ee: EeId::WASM,
                                id: sender.as_bytes().to_vec(),
                            };
                            let to_id = EeIdentity {
                                ee: EeId::WASM,
                                id: contract.as_bytes().to_vec(),
                            };
                            if let Err(e) = host.bud_transfer(
                                &from_id,
                                &to_id,
                                u128::from(funds_ubud).saturating_mul(ATTOS_PER_UBUD),
                            ) {
                                return EeOutcome {
                                    status: OutcomeStatus::Revert,
                                    output: e.to_string().into_bytes(),
                                    gas_used: 0,
                                };
                            }
                            funds.push(CwCoin {
                                denom: String::from("ubud"),
                                amount: funds_ubud.to_string(),
                            });
                        }
                        let info = CwMessageInfo { sender, funds };
                        invoke_contract_entry(
                            ctx,
                            host,
                            &contract,
                            "execute",
                            Some(&info),
                            &exec_msg,
                            call.gas_limit,
                            0,
                        )
                    }
                    Err(m) => Err((OutcomeStatus::Revert, m, 0)),
                },
                WasmTxAction::Migrate {
                    contract,
                    new_code_id,
                    msg_b64,
                } => match b64_decode(&msg_b64) {
                    Ok(mig_msg) => execute_migrate(
                        ctx,
                        host,
                        &sender,
                        &contract,
                        new_code_id,
                        &mig_msg,
                        call.gas_limit,
                        0,
                    ),
                    Err(m) => Err((OutcomeStatus::Revert, m, 0)),
                },
                WasmTxAction::BankSend {
                    to_address,
                    amount_ubud,
                } => {
                    let from_id = EeIdentity {
                        ee: EeId::WASM,
                        id: sender.into_bytes(),
                    };
                    let to_id = EeIdentity {
                        ee: EeId::WASM,
                        id: to_address.into_bytes(),
                    };
                    match host.bud_transfer(
                        &from_id,
                        &to_id,
                        u128::from(amount_ubud).saturating_mul(ATTOS_PER_UBUD),
                    ) {
                        Ok(()) => Ok((Vec::new(), 1_000)),
                        Err(e) => Err((OutcomeStatus::Revert, e.to_string(), 1_000)),
                    }
                }
            }
        } else {
            // Direct `UniversalCall` path (`Section 8.7.1`): `call.target` is `bud1...` contract
            // address and `call.input` is the raw JSON execute message.
            let Ok(contract) = std::str::from_utf8(&call.target.id) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"WASM target must be UTF-8 bud1 contract address".to_vec(),
                    gas_used: 0,
                };
            };
            let ubud_val = (call.value.0 / ATTOS_PER_UBUD) as u64;
            let mut funds = Vec::new();
            if ubud_val > 0 {
                funds.push(CwCoin {
                    denom: String::from("ubud"),
                    amount: ubud_val.to_string(),
                });
            }
            let info = CwMessageInfo { sender, funds };
            invoke_contract_entry(
                ctx,
                host,
                contract,
                "execute",
                Some(&info),
                &call.input,
                call.gas_limit,
                0,
            )
        };

        match res {
            Ok((out, used)) => {
                let g = used.min(call.gas_limit);
                if host.charge(g).is_err() {
                    return EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    };
                }
                EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: g,
                }
            }
            Err((OutcomeStatus::OutOfGas, _, _)) => {
                let _ = host.charge(call.gas_limit);
                EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                }
            }
            Err((status, msg, used)) => {
                let g = used.min(call.gas_limit);
                let _ = host.charge(g);
                EeOutcome {
                    status,
                    output: msg.into_bytes(),
                    gas_used: g,
                }
            }
        }
    }
}

impl ExecutionEnvironment for WasmWorker {
    fn id(&self) -> EeId {
        EeId::WASM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let engine = build_wasm_engine();
        let _ = compile_and_validate_module(&engine, code)?;
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: String::from("cosmwasm-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        catch_unwind(AssertUnwindSafe(|| Self::execute_inner(ctx, call, host))).map_err(
            |payload| {
                let msg = panic_payload_message(&*payload);
                EeFault {
                    ee: EeId::WASM,
                    panic_digest: panic_digest(EeId::WASM, &msg),
                }
            },
        )
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if let Ok(action) = serde_json::from_slice::<WasmViewAction>(&q.input) {
            return match action {
                WasmViewAction::SmartQuery {
                    contract,
                    query_b64,
                } => {
                    let query_json = b64_decode(&query_b64).map_err(|m| EeRefusal {
                        code: RefusalCode::InvalidCode,
                        message: m,
                    })?;
                    run_smart_query_on_read(ctx, host, &contract, &query_json, QUERY_FUEL_LIMIT)
                }
                WasmViewAction::RawQuery { contract, key_b64 } => {
                    let raw_key = b64_decode(&key_b64).map_err(|m| EeRefusal {
                        code: RefusalCode::InvalidCode,
                        message: m,
                    })?;
                    let ns_store = Namespace::new(NS_WASM_STORE).map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?;
                    Ok(host
                        .read(&ns_store, &contract_store_key(&contract, &raw_key))
                        .map_err(|e| EeRefusal {
                            code: RefusalCode::Denied,
                            message: e.to_string(),
                        })?
                        .unwrap_or_default())
                }
                WasmViewAction::ContractInfo { contract } => {
                    let ns_contract = Namespace::new(NS_WASM_CONTRACT).map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?;
                    host.read(&ns_contract, &contract_info_key(&contract))
                        .map_err(|e| EeRefusal {
                            code: RefusalCode::Denied,
                            message: e.to_string(),
                        })?
                        .ok_or_else(|| EeRefusal {
                            code: RefusalCode::Unsupported,
                            message: format!("contract '{contract}' not found"),
                        })
                }
                WasmViewAction::CodeInfo { code_id } => {
                    let ns_code = Namespace::new(NS_WASM_CODE).map_err(|e| EeRefusal {
                        code: RefusalCode::Denied,
                        message: e.to_string(),
                    })?;
                    host.read(&ns_code, &code_meta_key(code_id))
                        .map_err(|e| EeRefusal {
                            code: RefusalCode::Denied,
                            message: e.to_string(),
                        })?
                        .ok_or_else(|| EeRefusal {
                            code: RefusalCode::Unsupported,
                            message: format!("code_id {code_id} not found"),
                        })
                }
            };
        }

        let Ok(contract) = std::str::from_utf8(&q.target.id) else {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("WASM query target must be UTF-8 bud1 contract address"),
            });
        };
        run_smart_query_on_read(ctx, host, contract, &q.input, QUERY_FUEL_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::transport::{serve_connection, EeClient};
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeQuery,
        ExecutionEnvironment, OutcomeStatus, RefusalCode, UniversalResult,
    };

    use crate::abi::WasmTxAction;
    use crate::budlum_msg::{b64_encode, bud_addr_canonicalize, bud_addr_humanize};
    use crate::WasmWorker;

    fn sample_ctx() -> BlockContext {
        BlockContext {
            chain_id: 45_261,
            height: 42,
            timestamp_ms: 1_762_000_000_000,
        }
    }

    /// Minimal genuine CosmWasm `interface_version_8` contract compiled from WAT to
    /// binary WebAssembly (`\0asm`), storing `"state"` in `ee/wasm/store` via `db_write`
    /// and returning it on `query` via `db_read`.
    fn counter_cw_wasm() -> Result<Vec<u8>, String> {
        let wat_src = r#"
        (module
            (import "env" "db_read" (func $db_read (param i32) (result i32)))
            (import "env" "db_write" (func $db_write (param i32 i32)))
            (memory (export "memory") 2)
            (global $bump (mut i32) (i32.const 4096))

            ;; Static key Region at 128 -> key bytes "count" at 160 (len 5)
            ;; Static ok Response JSON `{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}` at 256 (len 62)
            (data (i32.const 128) "\a0\00\00\00\05\00\00\00\05\00\00\00")
            (data (i32.const 160) "count")
            (data (i32.const 224) "\00\01\00\00\3e\00\00\00\3e\00\00\00")
            (data (i32.const 256) "{\"ok\":{\"messages\":[],\"attributes\":[],\"events\":[],\"data\":null}}")
            ;; Query result `{"ok":"NDI="}` (Base64("42") = "NDI=") at 512 (len 13), Region at 480
            (data (i32.const 480) "\00\02\00\00\0d\00\00\00\0d\00\00\00")
            (data (i32.const 512) "{\"ok\":\"NDI=\"}")
            ;; Value Region at 600 -> "42" at 620 (len 2)
            (data (i32.const 600) "\6c\02\00\00\02\00\00\00\02\00\00\00")
            (data (i32.const 620) "42")

            (func (export "allocate") (param $size i32) (result i32)
                (local $hdr i32)
                (local $buf i32)
                (local.set $hdr (global.get $bump))
                (local.set $buf (i32.add (local.get $hdr) (i32.const 16)))
                (global.set $bump (i32.add (local.get $buf) (local.get $size)))
                (i32.store (local.get $hdr) (local.get $buf))
                (i32.store (i32.add (local.get $hdr) (i32.const 4)) (local.get $size))
                (i32.store (i32.add (local.get $hdr) (i32.const 8)) (i32.const 0))
                (local.get $hdr)
            )

            (func (export "deallocate") (param $ptr i32))

            (func (export "instantiate") (param $env i32) (param $info i32) (param $msg i32) (result i32)
                (call $db_write (i32.const 128) (i32.const 600))
                (i32.const 224)
            )

            (func (export "execute") (param $env i32) (param $info i32) (param $msg i32) (result i32)
                ;; Echo whatever msg Region was passed into key "count"
                (call $db_write (i32.const 128) (local.get $msg))
                (i32.const 224)
            )

            (func (export "query") (param $env i32) (param $msg i32) (result i32)
                (drop (call $db_read (i32.const 128)))
                (i32.const 480)
            )
        )
        "#;
        wat::parse_str(wat_src).map_err(|e| e.to_string())
    }

    #[test]
    fn wasm_float_code_refused() {
        let float_wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "allocate") (param i32) (result i32) (i32.const 16))
            (func (export "deallocate") (param i32))
            (func (export "execute") (param i32 i32 i32) (result i32)
                (drop (f64.add (f64.const 1.5) (f64.const 2.5)))
                (i32.const 16)
            )
        )
        "#;
        let Ok(wasm_bytes) = wat::parse_str(float_wat) else {
            panic!("wat::parse_str failed");
        };
        let worker = WasmWorker;
        let Err(refusal) = worker.validate_deploy(&wasm_bytes) else {
            panic!("float-using WASM module must be refused");
        };
        assert_eq!(refusal.code, RefusalCode::InvalidCode);
    }

    #[test]
    fn wasm_ibc_entry_points_refused() {
        let ibc_wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "allocate") (param i32) (result i32) (i32.const 16))
            (func (export "deallocate") (param i32))
            (func (export "ibc_packet_receive") (param i32 i32) (result i32) (i32.const 0))
        )
        "#;
        let Ok(wasm_bytes) = wat::parse_str(ibc_wat) else {
            panic!("wat::parse_str failed");
        };
        let worker = WasmWorker;
        let Err(refusal) = worker.validate_deploy(&wasm_bytes) else {
            panic!("IBC entry-point WASM module must be refused");
        };
        assert_eq!(refusal.code, RefusalCode::Unsupported);
        assert!(refusal.message.contains("ibc_packet_receive"));
    }

    #[test]
    fn wasm_64_mib_ceiling_and_bech32_roundtrip() {
        let raw = [0x42u8; 32];
        let Ok(human) = bud_addr_humanize(&raw) else {
            panic!("humanize failed");
        };
        assert!(human.starts_with("bud1"));
        let Ok(back) = bud_addr_canonicalize(&human) else {
            panic!("canonicalize failed");
        };
        assert_eq!(back, raw);

        // Module requesting 1025 pages (> 64 MiB = 1024 pages) must be refused.
        let huge_mem_wat = r#"
        (module
            (memory (export "memory") 1025)
            (func (export "allocate") (param i32) (result i32) (i32.const 16))
            (func (export "deallocate") (param i32))
        )
        "#;
        let Ok(wasm_bytes) = wat::parse_str(huge_mem_wat) else {
            panic!("wat::parse_str failed");
        };
        let worker = WasmWorker;
        let Err(refusal) = worker.validate_deploy(&wasm_bytes) else {
            panic!("64 MiB memory ceiling must refuse 1025-page module");
        };
        assert_eq!(refusal.code, RefusalCode::TooLarge);
    }

    #[test]
    fn wasm_store_instantiate_execute_query_and_forbidden_staking_submsg() {
        let Ok(code_bytes) = counter_cw_wasm() else {
            panic!("counter_cw_wasm failed");
        };
        let mut worker = WasmWorker;
        let mut host = MemoryHost::new(50_000_000);
        let ctx = sample_ctx();
        let Ok(sender_bech32) = bud_addr_humanize(&[0x11u8; 32]) else {
            panic!("sender humanize failed");
        };
        let caller = EeIdentity {
            ee: EeId::WASM,
            id: sender_bech32.into_bytes(),
        };

        // 1. Deploy (`StoreCode`)
        let deploy_call = EeCall {
            kind: EeCallKind::Deploy,
            caller: caller.clone(),
            target: EeIdentity {
                ee: EeId::WASM,
                id: Vec::new(),
            },
            value: BudAmount(0),
            input: code_bytes,
            gas_limit: 5_000_000,
            depth: 0,
            tx_hash: [1u8; 32],
        };
        let Ok(deploy_out) = worker.execute(&ctx, &deploy_call, &mut host) else {
            panic!("deploy faulted");
        };
        assert_eq!(deploy_out.status, OutcomeStatus::Success);
        let Ok(cid_arr) = <[u8; 8]>::try_from(deploy_out.output.as_slice()) else {
            panic!("expected 8-byte code_id");
        };
        assert_eq!(u64::from_be_bytes(cid_arr), 1);

        // 2. Instantiate
        let inst_action = WasmTxAction::Instantiate {
            code_id: 1,
            admin: None,
            label: String::from("counter"),
            msg_b64: b64_encode(b"{}"),
            funds_ubud: 0,
        };
        let Ok(inst_bytes) = serde_json::to_vec(&inst_action) else {
            panic!("serialize inst");
        };
        let inst_call = EeCall {
            kind: EeCallKind::Call,
            caller: caller.clone(),
            target: EeIdentity {
                ee: EeId::WASM,
                id: Vec::new(),
            },
            value: BudAmount(0),
            input: inst_bytes,
            gas_limit: 5_000_000,
            depth: 0,
            tx_hash: [2u8; 32],
        };
        let Ok(inst_out) = worker.execute(&ctx, &inst_call, &mut host) else {
            panic!("instantiate faulted");
        };
        assert_eq!(inst_out.status, OutcomeStatus::Success);
        let Ok(contract_addr) = String::from_utf8(inst_out.output) else {
            panic!("bad contract utf8");
        };
        assert!(contract_addr.starts_with("bud1"));

        // 3. Direct execute + smart query
        let exec_call = EeCall {
            kind: EeCallKind::Call,
            caller,
            target: EeIdentity {
                ee: EeId::WASM,
                id: contract_addr.as_bytes().to_vec(),
            },
            value: BudAmount(0),
            input: b"{\"inc\":1}".to_vec(),
            gas_limit: 5_000_000,
            depth: 0,
            tx_hash: [3u8; 32],
        };
        let Ok(exec_out) = worker.execute(&ctx, &exec_call, &mut host) else {
            panic!("execute faulted");
        };
        assert_eq!(exec_out.status, OutcomeStatus::Success);

        let q = EeQuery {
            target: EeIdentity {
                ee: EeId::WASM,
                id: contract_addr.into_bytes(),
            },
            input: b"{\"get\":{}}".to_vec(),
        };
        let Ok(q_out) = worker.query(&ctx, &q, &host) else {
            panic!("query refused");
        };
        assert_eq!(q_out, b"42");
    }

    #[test]
    fn wasm_universal_call_submsg_and_ipc_roundtrip() {
        // Contract emits a BudlumMsg::UniversalCall to EVM (target_ee = 1) on execute.
        let ucall_json = concat!(
            r#"{"ok":{"messages":[{"id":7,"msg":{"custom":{"universal_call":"#,
            r#"{"target_ee":1,"target":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","input":"AQID","#,
            r#""value_attos":"0","gas_limit_bgu":100000,"is_static":false}}},"#,
            r#""reply_on":"never"}],"attributes":[],"events":[],"data":null}}"#,
        );
        let wat_src = format!(
            r#"
            (module
                (memory (export "memory") 2)
                (global $bump (mut i32) (i32.const 4096))
                (data (i32.const 256) "{escaped}")
                (data (i32.const 224) "\00\01\00\00{len_lo}{len_hi}\00\00{len_lo}{len_hi}\00\00")
                (data (i32.const 800) "{empty_ok}")
                (data (i32.const 768) "\20\03\00\00\3e\00\00\00\3e\00\00\00")
                (func (export "allocate") (param $size i32) (result i32)
                    (local $hdr i32) (local $buf i32)
                    (local.set $hdr (global.get $bump))
                    (local.set $buf (i32.add (local.get $hdr) (i32.const 16)))
                    (global.set $bump (i32.add (local.get $buf) (local.get $size)))
                    (i32.store (local.get $hdr) (local.get $buf))
                    (i32.store (i32.add (local.get $hdr) (i32.const 4)) (local.get $size))
                    (i32.store (i32.add (local.get $hdr) (i32.const 8)) (i32.const 0))
                    (local.get $hdr)
                )
                (func (export "deallocate") (param i32))
                (func (export "instantiate") (param i32 i32 i32) (result i32) (i32.const 768))
                (func (export "execute") (param i32 i32 i32) (result i32) (i32.const 224))
            )
            "#,
            escaped = ucall_json.replace('"', "\\\""),
            len_lo = format!("\\{:02x}", ucall_json.len() & 0xff),
            len_hi = format!("\\{:02x}", (ucall_json.len() >> 8) & 0xff),
            empty_ok = r#"{\"ok\":{\"messages\":[],\"attributes\":[],\"events\":[],\"data\":null}}"#,
        );
        let Ok(code_bytes) = wat::parse_str(&wat_src) else {
            panic!("wat compile failed");
        };

        let sock_path = std::env::temp_dir().join(format!(
            "budlum-ee-wasm-{}-{:?}.sock",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_file(&sock_path);
        let Ok(listener) = UnixListener::bind(&sock_path) else {
            panic!("bind failed");
        };
        let handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut w = WasmWorker;
                let _ = serve_connection(stream, &mut w);
            }
        });

        let mut client = EeClient::new(&sock_path, EeId::WASM);
        let mut host = MemoryHost::new(50_000_000).with_universal_handler(Box::new(|ucall| {
            assert_eq!(ucall.to_ee, EeId::EVM);
            Ok(UniversalResult {
                success: true,
                output: vec![0x99],
                gas_used: 5_000,
            })
        }));
        let ctx = sample_ctx();
        let Ok(sender_str) = bud_addr_humanize(&[0x22u8; 32]) else {
            panic!("humanize");
        };
        let caller = EeIdentity {
            ee: EeId::WASM,
            id: sender_str.into_bytes(),
        };

        let Ok(Ok(dep)) = client.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: EeIdentity {
                    ee: EeId::WASM,
                    id: Vec::new(),
                },
                value: BudAmount(0),
                input: code_bytes,
                gas_limit: 5_000_000,
                depth: 0,
                tx_hash: [4u8; 32],
            },
            &mut host,
        ) else {
            panic!("ipc deploy failed");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);

        let Ok(inst_payload) = serde_json::to_vec(&WasmTxAction::Instantiate {
            code_id: 1,
            admin: None,
            label: String::from("uc"),
            msg_b64: b64_encode(b"{}"),
            funds_ubud: 0,
        }) else {
            panic!("inst serialize");
        };
        let Ok(Ok(inst)) = client.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: EeIdentity {
                    ee: EeId::WASM,
                    id: Vec::new(),
                },
                value: BudAmount(0),
                input: inst_payload,
                gas_limit: 5_000_000,
                depth: 0,
                tx_hash: [5u8; 32],
            },
            &mut host,
        ) else {
            panic!("ipc inst failed");
        };
        assert_eq!(inst.status, OutcomeStatus::Success);

        let Ok(Ok(exec)) = client.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: EeIdentity {
                    ee: EeId::WASM,
                    id: inst.output,
                },
                value: BudAmount(0),
                input: b"{}".to_vec(),
                gas_limit: 5_000_000,
                depth: 0,
                tx_hash: [6u8; 32],
            },
            &mut host,
        ) else {
            panic!("ipc exec failed");
        };
        assert_eq!(exec.status, OutcomeStatus::Success);
        drop(client);
        let _ = handle.join();
        let _ = std::fs::remove_file(&sock_path);
    }
}
