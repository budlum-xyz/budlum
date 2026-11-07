//! CometBFT JSON-RPC (`127.0.0.1:18550`) and Cosmos LCD REST (`127.0.0.1:18551`)
//! compatibility gateways (`Section 8.11.5`, `WP-29`, closing `BLG-249` Cosmos leg).
//!
//! Enables unmodified CosmJS `SigningCosmWasmClient` workflows (`status`,
//! `abci_query` across `auth`/`bank`/`wasm`/`tx.Simulate`, and `broadcast_tx_*`
//! admitting `Foreign::Cosmos` `SIGN_MODE_DIRECT` `TxRaw` transactions).
//! Convenience: public CometBFT JSON-RPC and Cosmos LCD compatibility gateway surface (WP-29).

pub mod method_class;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder, ServerConfig, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use prost::Message;
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::cli::commands::CompatGatewayListenerSection;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::accounts::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::bud_unit::ATTOS_PER_ATOM;
use crate::execution::coordinator::foreign::cosmos::{
    CosmosCoinProto, DecodedCosmosTx, ProtoAny, Secp256k1PubKeyProto, BUDLUM_COSMOS_CHAIN_ID,
    SECP256K1_PUBKEY_TYPE_URL,
};
use crate::execution::coordinator::foreign::ForeignCoordinatorBook;
use crate::rpc::compat::cosmos::method_class::{
    check_served_cosmos_methods, is_supported_abci_query_path, COSMOS_RPC_METHODS,
};

/// Default CometBFT JSON-RPC listener (`Section 8.11.1`).
pub const DEFAULT_COSMOS_RPC_LISTENER: &str = "127.0.0.1:18550";
/// Default Cosmos LCD REST listener (`Section 8.11.1`).
pub const DEFAULT_COSMOS_REST_LISTENER: &str = "127.0.0.1:18551";
/// Maximum `tx_search` page size (`Section 8.11.5` item 1).
pub const MAX_TX_SEARCH_PER_PAGE: usize = 100;
/// Maximum `blockchain` header range per call.
pub const MAX_BLOCKCHAIN_RANGE: u64 = 20;
/// Maximum LCD HTTP body size (`2 MiB`).
const MAX_LCD_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum concurrent LCD HTTP connections.
const MAX_LCD_CONNECTIONS: usize = 256;

const JSONRPC_INVALID_PARAMS: i32 = -32602;

/// Listener configuration for `[compat.cosmos]`.
///
/// Convenience: built from `CompatGatewayListenerSection` and passed to `CosmosCompatServer`.
#[derive(Debug, Clone)]
pub struct CosmosRpcConfig {
    pub enabled: bool,
    pub rpc_listener: String,
    pub rest_listener: String,
}

impl Default for CosmosRpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rpc_listener: DEFAULT_COSMOS_RPC_LISTENER.to_string(),
            rest_listener: DEFAULT_COSMOS_REST_LISTENER.to_string(),
        }
    }
}

impl CosmosRpcConfig {
    /// Construct from `[compat.cosmos]` TOML config section.
    ///
    /// Convenience: wires `FileConfig` into `CosmosCompatServer`.
    #[must_use]
    pub fn from_section(sec: Option<&CompatGatewayListenerSection>) -> Self {
        let mut cfg = Self::default();
        if let Some(s) = sec {
            if let Some(en) = s.enabled {
                cfg.enabled = en;
            }
            if let Some(l) = &s.listener {
                cfg.rpc_listener.clone_from(l);
            }
            if let Some(r) = &s.rest_listener {
                cfg.rest_listener.clone_from(r);
            }
        }
        cfg
    }
}

// --- Protobuf request/response messages for `abci_query` (CosmJS v0.32+) ---

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryAccountRequestProto {
    #[prost(string, tag = "1")]
    address: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct BaseAccountProto {
    #[prost(string, tag = "1")]
    address: String,
    #[prost(message, optional, tag = "2")]
    pub_key: Option<ProtoAny>,
    #[prost(uint64, tag = "3")]
    account_number: u64,
    #[prost(uint64, tag = "4")]
    sequence: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryAccountResponseProto {
    #[prost(message, optional, tag = "1")]
    account: Option<ProtoAny>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryBalanceRequestProto {
    #[prost(string, tag = "1")]
    address: String,
    #[prost(string, tag = "2")]
    denom: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryBalanceResponseProto {
    #[prost(message, optional, tag = "1")]
    balance: Option<CosmosCoinProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryAllBalancesRequestProto {
    #[prost(string, tag = "1")]
    address: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryAllBalancesResponseProto {
    #[prost(message, repeated, tag = "1")]
    balances: Vec<CosmosCoinProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QuerySmartContractStateRequestProto {
    #[prost(string, tag = "1")]
    address: String,
    #[prost(bytes = "vec", tag = "2")]
    query_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryRawContractStateRequestProto {
    #[prost(string, tag = "1")]
    address: String,
    #[prost(bytes = "vec", tag = "2")]
    query_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryContractStateResponseProto {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryContractInfoRequestProto {
    #[prost(string, tag = "1")]
    address: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct ContractInfoProto {
    #[prost(uint64, tag = "1")]
    code_id: u64,
    #[prost(string, tag = "2")]
    creator: String,
    #[prost(string, tag = "3")]
    admin: String,
    #[prost(string, tag = "4")]
    label: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryContractInfoResponseProto {
    #[prost(string, tag = "1")]
    address: String,
    #[prost(message, optional, tag = "2")]
    contract_info: Option<ContractInfoProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryContractsByCodeRequestProto {
    #[prost(uint64, tag = "1")]
    code_id: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryContractsByCodeResponseProto {
    #[prost(string, repeated, tag = "1")]
    contracts: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryCodeRequestProto {
    #[prost(uint64, tag = "1")]
    code_id: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct CodeInfoResponseProto {
    #[prost(uint64, tag = "1")]
    code_id: u64,
    #[prost(string, tag = "2")]
    creator: String,
    #[prost(bytes = "vec", tag = "3")]
    data_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryCodeResponseProto {
    #[prost(message, optional, tag = "1")]
    code_info: Option<CodeInfoResponseProto>,
    #[prost(bytes = "vec", tag = "2")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct QueryCodesResponseProto {
    #[prost(message, repeated, tag = "1")]
    code_infos: Vec<CodeInfoResponseProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct SimulateRequestProto {
    #[prost(bytes = "vec", tag = "2")]
    tx_bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct GasInfoProto {
    #[prost(uint64, tag = "1")]
    gas_wanted: u64,
    #[prost(uint64, tag = "2")]
    gas_used: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct SimulateResponseProto {
    #[prost(message, optional, tag = "1")]
    gas_info: Option<GasInfoProto>,
}

/// Summary of a finalized block visible through CometBFT `block`/`blockchain`.
///
/// Convenience: populated by block commit notifications into `CosmosCompatInner`.
#[derive(Debug, Clone)]
pub struct CosmosBlockRecord {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub app_hash: [u8; 32],
    pub timestamp_rfc3339: String,
    pub tx_hashes: Vec<[u8; 32]>,
}

/// Stored CosmWasm contract record mirrored for RPC queries.
#[derive(Debug, Clone)]
pub struct CosmosContractView {
    pub code_id: u64,
    pub creator: String,
    pub admin: String,
    pub label: String,
    pub raw_store: BTreeMap<Vec<u8>, Vec<u8>>,
    pub smart_responses: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Stored CosmWasm code record mirrored for RPC queries.
#[derive(Debug, Clone)]
pub struct CosmosCodeView {
    pub code_id: u64,
    pub creator: String,
    pub checksum: [u8; 32],
    pub wasm_bytes: Vec<u8>,
}

/// Active Budlum validator entry exposed on CometBFT `validators`.
#[derive(Debug, Clone)]
pub struct CosmosValidatorView {
    pub address_hex: String,
    pub pubkey_b64: String,
    pub voting_power: u64,
}

/// Mutable state backing the CometBFT RPC and Cosmos LCD REST gateways.
pub struct CosmosCompatInner {
    pub chain_id: String,
    pub latest_height: u64,
    pub blocks: BTreeMap<u64, CosmosBlockRecord>,
    pub txs_by_hash: BTreeMap<[u8; 32], (u64, Vec<u8>, DecodedCosmosTx)>,
    pub bech32_to_bud: BTreeMap<String, Address>,
    pub pubkeys_by_bech32: BTreeMap<String, [u8; 33]>,
    pub codes: BTreeMap<u64, CosmosCodeView>,
    pub contracts: BTreeMap<String, CosmosContractView>,
    pub validators: Vec<CosmosValidatorView>,
    pub account_state: AccountState,
    pub foreign_book: ForeignCoordinatorBook,
}

impl Default for CosmosCompatInner {
    fn default() -> Self {
        let genesis = CosmosBlockRecord {
            height: 0,
            block_hash: [0u8; 32],
            app_hash: [0u8; 32],
            timestamp_rfc3339: String::from("2026-01-01T00:00:00Z"),
            tx_hashes: Vec::new(),
        };
        let mut blocks = BTreeMap::new();
        blocks.insert(0, genesis);
        Self {
            chain_id: BUDLUM_COSMOS_CHAIN_ID.to_string(),
            latest_height: 0,
            blocks,
            txs_by_hash: BTreeMap::new(),
            bech32_to_bud: BTreeMap::new(),
            pubkeys_by_bech32: BTreeMap::new(),
            codes: BTreeMap::new(),
            contracts: BTreeMap::new(),
            validators: Vec::new(),
            account_state: AccountState::new(),
            foreign_book: ForeignCoordinatorBook::new(),
        }
    }
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_enc(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let b0 = c.first().copied().unwrap_or(0);
        let b1 = c.get(1).copied().unwrap_or(0);
        let b2 = c.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for s in [18u32, 12, 6, 0] {
            out.push(B64_TABLE.get(((n >> s) & 63) as usize).copied().unwrap_or(b'A') as char);
        }
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let n = u32::from(rem.first().copied().unwrap_or(0)) << 16;
        out.push(B64_TABLE.get(((n >> 18) & 63) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_TABLE.get(((n >> 12) & 63) as usize).copied().unwrap_or(b'A') as char);
        out.push_str("==");
    } else if rem.len() == 2 {
        let b0 = rem.first().copied().unwrap_or(0);
        let b1 = rem.get(1).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8);
        out.push(B64_TABLE.get(((n >> 18) & 63) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_TABLE.get(((n >> 12) & 63) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_TABLE.get(((n >> 6) & 63) as usize).copied().unwrap_or(b'A') as char);
        out.push('=');
    }
    out
}

fn b64_dec(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(String::from("invalid base64 length"));
    }
    let val_of = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for (idx, ch) in bytes.chunks_exact(4).enumerate() {
        let last = (idx + 1) * 4 == bytes.len();
        let c0 = ch.first().copied().unwrap_or(0);
        let c1 = ch.get(1).copied().unwrap_or(0);
        let c2 = ch.get(2).copied().unwrap_or(0);
        let c3 = ch.get(3).copied().unwrap_or(0);
        let v0 = val_of(c0).ok_or_else(|| String::from("bad base64"))?;
        let v1 = val_of(c1).ok_or_else(|| String::from("bad base64"))?;
        if c2 == b'=' {
            if !last || c3 != b'=' || (v1 & 0x0f) != 0 {
                return Err(String::from("bad base64 pad"));
            }
            out.push((v0 << 2) | (v1 >> 4));
        } else if c3 == b'=' {
            let v2 = val_of(c2).ok_or_else(|| String::from("bad base64"))?;
            if !last || (v2 & 0x03) != 0 {
                return Err(String::from("bad base64 pad"));
            }
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
        } else {
            let v2 = val_of(c2).ok_or_else(|| String::from("bad base64"))?;
            let v3 = val_of(c3).ok_or_else(|| String::from("bad base64"))?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}

fn decode_tx_arg(s: &str) -> Result<Vec<u8>, String> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return hex::decode(hex_str).map_err(|e| format!("bad hex tx: {e}"));
    }
    b64_dec(s).or_else(|_| hex::decode(s).map_err(|e| format!("bad base64/hex tx: {e}")))
}

fn err_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_INVALID_PARAMS, msg.into(), None::<()>)
}

fn ubud_of_bech32(inner: &CosmosCompatInner, bech32: &str) -> u64 {
    let Some(bud_addr) = inner.bech32_to_bud.get(bech32) else {
        return 0;
    };
    inner
        .account_state
        .accounts
        .get(bud_addr)
        .map_or(0, |a| a.balance)
}

fn eval_abci_query(inner: &CosmosCompatInner, path: &str, data: &[u8]) -> (u32, String, Vec<u8>) {
    if !is_supported_abci_query_path(path) {
        return (
            6,
            format!("unsupported abci_query path '{path}'"),
            Vec::new(),
        );
    }
    match path {
        "/cosmos.auth.v1beta1.Query/Account" => {
            let Ok(req) = QueryAccountRequestProto::decode(data) else {
                return (2, String::from("malformed QueryAccountRequest"), Vec::new());
            };
            let (acct_num, seq) = match inner.bech32_to_bud.get(&req.address) {
                Some(bud_addr) => inner.foreign_book.cosmos_account_meta(bud_addr),
                None => (0, 0),
            };
            let pub_any = inner.pubkeys_by_bech32.get(&req.address).map(|pk33| ProtoAny {
                type_url: SECP256K1_PUBKEY_TYPE_URL.to_string(),
                value: Secp256k1PubKeyProto { key: pk33.to_vec() }.encode_to_vec(),
            });
            let base = BaseAccountProto {
                address: req.address,
                pub_key: pub_any,
                account_number: acct_num,
                sequence: seq,
            };
            let resp = QueryAccountResponseProto {
                account: Some(ProtoAny {
                    type_url: String::from("/cosmos.auth.v1beta1.BaseAccount"),
                    value: base.encode_to_vec(),
                }),
            };
            (0, String::new(), resp.encode_to_vec())
        }
        "/cosmos.bank.v1beta1.Query/Balance" => {
            let Ok(req) = QueryBalanceRequestProto::decode(data) else {
                return (2, String::from("malformed QueryBalanceRequest"), Vec::new());
            };
            let amt = if req.denom == "ubud" {
                ubud_of_bech32(inner, &req.address)
            } else {
                0
            };
            let resp = QueryBalanceResponseProto {
                balance: Some(CosmosCoinProto {
                    denom: req.denom,
                    amount: amt.to_string(),
                }),
            };
            (0, String::new(), resp.encode_to_vec())
        }
        "/cosmos.bank.v1beta1.Query/AllBalances" => {
            let Ok(req) = QueryAllBalancesRequestProto::decode(data) else {
                return (
                    2,
                    String::from("malformed QueryAllBalancesRequest"),
                    Vec::new(),
                );
            };
            let amt = ubud_of_bech32(inner, &req.address);
            let balances = if amt == 0 {
                Vec::new()
            } else {
                vec![CosmosCoinProto {
                    denom: String::from("ubud"),
                    amount: amt.to_string(),
                }]
            };
            let resp = QueryAllBalancesResponseProto { balances };
            (0, String::new(), resp.encode_to_vec())
        }
        "/cosmwasm.wasm.v1.Query/SmartContractState" => {
            let Ok(req) = QuerySmartContractStateRequestProto::decode(data) else {
                return (2, String::from("malformed SmartContractState"), Vec::new());
            };
            let Some(c) = inner.contracts.get(&req.address) else {
                return (22, format!("no such contract '{}'", req.address), Vec::new());
            };
            let out = c
                .smart_responses
                .get(&req.query_data)
                .cloned()
                .unwrap_or_else(|| b"{}".to_vec());
            (
                0,
                String::new(),
                QueryContractStateResponseProto { data: out }.encode_to_vec(),
            )
        }
        "/cosmwasm.wasm.v1.Query/RawContractState" => {
            let Ok(req) = QueryRawContractStateRequestProto::decode(data) else {
                return (2, String::from("malformed RawContractState"), Vec::new());
            };
            let Some(c) = inner.contracts.get(&req.address) else {
                return (22, format!("no such contract '{}'", req.address), Vec::new());
            };
            let out = c
                .raw_store
                .get(&req.query_data)
                .cloned()
                .unwrap_or_default();
            (
                0,
                String::new(),
                QueryContractStateResponseProto { data: out }.encode_to_vec(),
            )
        }
        "/cosmwasm.wasm.v1.Query/ContractInfo" => {
            let Ok(req) = QueryContractInfoRequestProto::decode(data) else {
                return (2, String::from("malformed ContractInfoRequest"), Vec::new());
            };
            let Some(c) = inner.contracts.get(&req.address) else {
                return (22, format!("no such contract '{}'", req.address), Vec::new());
            };
            let resp = QueryContractInfoResponseProto {
                address: req.address,
                contract_info: Some(ContractInfoProto {
                    code_id: c.code_id,
                    creator: c.creator.clone(),
                    admin: c.admin.clone(),
                    label: c.label.clone(),
                }),
            };
            (0, String::new(), resp.encode_to_vec())
        }
        "/cosmwasm.wasm.v1.Query/ContractsByCode" => {
            let Ok(req) = QueryContractsByCodeRequestProto::decode(data) else {
                return (2, String::from("malformed ContractsByCode"), Vec::new());
            };
            let contracts: Vec<String> = inner
                .contracts
                .iter()
                .filter(|(_, v)| v.code_id == req.code_id)
                .map(|(addr, _)| addr.clone())
                .collect();
            (
                0,
                String::new(),
                QueryContractsByCodeResponseProto { contracts }.encode_to_vec(),
            )
        }
        "/cosmwasm.wasm.v1.Query/Code" => {
            let Ok(req) = QueryCodeRequestProto::decode(data) else {
                return (2, String::from("malformed QueryCodeRequest"), Vec::new());
            };
            let Some(code) = inner.codes.get(&req.code_id) else {
                return (22, format!("no such code_id {}", req.code_id), Vec::new());
            };
            let resp = QueryCodeResponseProto {
                code_info: Some(CodeInfoResponseProto {
                    code_id: code.code_id,
                    creator: code.creator.clone(),
                    data_hash: code.checksum.to_vec(),
                }),
                data: code.wasm_bytes.clone(),
            };
            (0, String::new(), resp.encode_to_vec())
        }
        "/cosmwasm.wasm.v1.Query/Codes" => {
            let infos: Vec<CodeInfoResponseProto> = inner
                .codes
                .values()
                .map(|c| CodeInfoResponseProto {
                    code_id: c.code_id,
                    creator: c.creator.clone(),
                    data_hash: c.checksum.to_vec(),
                })
                .collect();
            (
                0,
                String::new(),
                QueryCodesResponseProto { code_infos: infos }.encode_to_vec(),
            )
        }
        "/cosmos.tx.v1beta1.Service/Simulate" => {
            let Ok(req) = SimulateRequestProto::decode(data) else {
                return (2, String::from("malformed SimulateRequest"), Vec::new());
            };
            let est_gas = (req.tx_bytes.len() as u64)
                .saturating_mul(250)
                .saturating_add(120_000);
            let resp = SimulateResponseProto {
                gas_info: Some(GasInfoProto {
                    gas_wanted: est_gas,
                    gas_used: est_gas,
                }),
            };
            (0, String::new(), resp.encode_to_vec())
        }
        _ => (6, String::from("unsupported path"), Vec::new()),
    }
}

fn admit_cosmos_tx_bytes(
    inner: &mut CosmosCompatInner,
    raw_bytes: &[u8],
) -> Result<(u32, String, [u8; 32], u64), String> {
    let tx_hash: [u8; 32] = Sha256::digest(raw_bytes).into();
    if inner.txs_by_hash.contains_key(&tx_hash) {
        return Ok((19, String::from("tx already in cache"), tx_hash, 0));
    }
    // Probe known account_number via existing pubkey/address map, defaulting to 0.
    let mut matched = None;
    let mut candidate_acct_nums = vec![0u64];
    for bud_addr in inner.bech32_to_bud.values() {
        let (acct_num, _) = inner.foreign_book.cosmos_account_meta(bud_addr);
        if !candidate_acct_nums.contains(&acct_num) {
            candidate_acct_nums.push(acct_num);
        }
    }
    let mut last_err = String::from("signature/envelope verification failed");
    for acct_num in candidate_acct_nums {
        match inner.foreign_book.apply_cosmos_envelope(
            raw_bytes,
            acct_num,
            &mut inner.account_state,
        ) {
            Ok(decoded) => {
                matched = Some(decoded);
                break;
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }
    let Some(decoded) = matched else {
        return Ok((4, last_err, tx_hash, 0));
    };
    if let Ok(foreign_bud) =
        derive_foreign_account(ForeignScheme::CosmosSecp256k1, &decoded.sender_raw)
    {
        inner
            .bech32_to_bud
            .insert(decoded.sender_bech32.clone(), foreign_bud);
    }
    inner
        .pubkeys_by_bech32
        .insert(decoded.sender_bech32.clone(), decoded.pubkey_compressed);
    let height = inner.latest_height;
    let gas_used = decoded.gas_limit.min(150_000);
    inner
        .txs_by_hash
        .insert(tx_hash, (height, raw_bytes.to_vec(), decoded));
    if let Some(blk) = inner.blocks.get_mut(&height) {
        blk.tx_hashes.push(tx_hash);
    }
    Ok((0, String::new(), tx_hash, gas_used))
}

#[rpc(server)]
pub trait CometBftCompatApi {
    #[method(name = "status")]
    async fn status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "abci_info")]
    async fn abci_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "abci_query")]
    async fn abci_query(
        &self,
        path: String,
        data: Option<String>,
        height: Option<String>,
        prove: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "broadcast_tx_sync")]
    async fn broadcast_tx_sync(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "broadcast_tx_async")]
    async fn broadcast_tx_async(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "broadcast_tx_commit")]
    async fn broadcast_tx_commit(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "tx")]
    async fn tx(
        &self,
        hash: String,
        prove: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "tx_search")]
    async fn tx_search(
        &self,
        query: String,
        prove: Option<bool>,
        page: Option<String>,
        per_page: Option<String>,
        order_by: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "block")]
    async fn block(&self, height: Option<String>) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "block_results")]
    async fn block_results(
        &self,
        height: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "blockchain")]
    async fn blockchain(
        &self,
        min_height: Option<String>,
        max_height: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "validators")]
    async fn validators(
        &self,
        height: Option<String>,
        page: Option<String>,
        per_page: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
}

/// Shared CometBFT + LCD REST compatibility backend.
#[derive(Clone)]
pub struct CosmosCompatBackend {
    inner: Arc<RwLock<CosmosCompatInner>>,
}

impl CosmosCompatBackend {
    /// Construct a new backend with `CosmosCompatInner::default()`.
    ///
    /// Convenience: instantiated by `CosmosCompatServer` and tests.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CosmosCompatInner::default())),
        }
    }

    /// Seed a foreign Cosmos `bud1...` account balance in `ubud` for devnet/tests.
    ///
    /// Convenience: populates unified ledger balance and Bech32 lookup map.
    pub fn seed_foreign_ubud(&self, raw20: &[u8; 20], bech32: &str, ubud: u64) {
        if let Ok(bud_addr) = derive_foreign_account(ForeignScheme::CosmosSecp256k1, raw20) {
            if let Ok(mut g) = self.inner.write() {
                let acc = g.account_state.get_or_create(&bud_addr);
                acc.balance = acc.balance.saturating_add(ubud);
                let _ = ATTOS_PER_ATOM;
                g.bech32_to_bud.insert(bech32.to_string(), bud_addr);
            }
        }
    }

    /// Access inner state handle.
    #[must_use]
    pub fn state(&self) -> &Arc<RwLock<CosmosCompatInner>> {
        &self.inner
    }
}

impl Default for CosmosCompatBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CometBftCompatApiServer for CosmosCompatBackend {
    async fn status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let latest = g.blocks.get(&g.latest_height);
        let bh = latest.map_or_else(|| "00".repeat(32), |b| hex::encode_upper(b.block_hash));
        let ah = latest.map_or_else(|| "00".repeat(32), |b| hex::encode_upper(b.app_hash));
        let ts = latest.map_or("2026-01-01T00:00:00Z", |b| b.timestamp_rfc3339.as_str());
        Ok(serde_json::json!({
            "node_info": {
                "protocol_version": { "p2p": "8", "block": "11", "app": "0" },
                "id": "0000000000000000000000000000000000000001",
                "network": g.chain_id,
                "version": "0.38.12",
                "moniker": "budlum-uel-cosmos",
            },
            "sync_info": {
                "latest_block_hash": bh,
                "latest_app_hash": ah,
                "latest_block_height": g.latest_height.to_string(),
                "latest_block_time": ts,
                "catching_up": false,
            },
            "validator_info": {
                "address": "0000000000000000000000000000000000000001",
                "voting_power": "1",
            }
        }))
    }

    async fn abci_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let ah = g
            .blocks
            .get(&g.latest_height)
            .map_or_else(String::new, |b| b64_enc(&b.app_hash));
        Ok(serde_json::json!({
            "response": {
                "data": "budlum-uel",
                "version": env!("CARGO_PKG_VERSION"),
                "last_block_height": g.latest_height.to_string(),
                "last_block_app_hash": ah,
            }
        }))
    }

    async fn abci_query(
        &self,
        path: String,
        data: Option<String>,
        _height: Option<String>,
        _prove: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let raw_data = match data.as_deref() {
            None | Some("") => Vec::new(),
            Some(hex_str) => {
                let clean = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(hex_str);
                hex::decode(clean).map_err(|e| err_params(format!("bad abci_query data: {e}")))?
            }
        };
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let (code, log, val_bytes) = eval_abci_query(&g, &path, &raw_data);
        Ok(serde_json::json!({
            "response": {
                "code": code,
                "log": log,
                "key": b64_enc(&raw_data),
                "value": b64_enc(&val_bytes),
                "height": g.latest_height.to_string(),
            }
        }))
    }

    async fn broadcast_tx_sync(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let raw = decode_tx_arg(&tx).map_err(err_params)?;
        let mut g = self
            .inner
            .write()
            .map_err(|_| err_params("state lock poisoned"))?;
        let (code, log, hash, _) = admit_cosmos_tx_bytes(&mut g, &raw).map_err(err_params)?;
        Ok(serde_json::json!({
            "code": code,
            "data": "",
            "log": log,
            "codespace": if code == 0 { "" } else { "sdk" },
            "hash": hex::encode_upper(hash),
        }))
    }

    async fn broadcast_tx_async(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.broadcast_tx_sync(tx).await
    }

    async fn broadcast_tx_commit(&self, tx: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let raw = decode_tx_arg(&tx).map_err(err_params)?;
        let mut g = self
            .inner
            .write()
            .map_err(|_| err_params("state lock poisoned"))?;
        let (code, log, hash, gas_used) = admit_cosmos_tx_bytes(&mut g, &raw).map_err(err_params)?;
        let height = g.latest_height;
        Ok(serde_json::json!({
            "check_tx": { "code": code, "log": log, "gas_wanted": gas_used.to_string() },
            "tx_result": { "code": code, "log": log, "gas_used": gas_used.to_string() },
            "hash": hex::encode_upper(hash),
            "height": height.to_string(),
        }))
    }

    async fn tx(
        &self,
        hash: String,
        _prove: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean = hash
            .strip_prefix("0x")
            .or_else(|| hash.strip_prefix("0X"))
            .unwrap_or(&hash);
        let decoded = hex::decode(clean).map_err(|e| err_params(format!("bad tx hash: {e}")))?;
        let arr: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| err_params("tx hash must be 32 bytes"))?;
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let Some((height, raw_bytes, parsed)) = g.txs_by_hash.get(&arr) else {
            return Err(err_params("tx not found"));
        };
        Ok(serde_json::json!({
            "hash": hex::encode_upper(arr),
            "height": height.to_string(),
            "index": 0,
            "tx_result": {
                "code": 0,
                "data": "",
                "log": "",
                "gas_wanted": parsed.gas_limit.to_string(),
                "gas_used": parsed.gas_limit.min(150_000).to_string(),
                "events": [],
            },
            "tx": b64_enc(raw_bytes),
        }))
    }

    async fn tx_search(
        &self,
        _query: String,
        _prove: Option<bool>,
        page: Option<String>,
        per_page: Option<String>,
        _order_by: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let p: usize = page
            .as_deref()
            .unwrap_or("1")
            .parse()
            .map_err(|_| err_params("invalid page"))?;
        let pp: usize = per_page
            .as_deref()
            .unwrap_or("30")
            .parse()
            .map_err(|_| err_params("invalid per_page"))?;
        if p == 0 || pp == 0 || pp > MAX_TX_SEARCH_PER_PAGE {
            return Err(err_params(format!(
                "per_page must be in 1..={MAX_TX_SEARCH_PER_PAGE}"
            )));
        }
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let total = g.txs_by_hash.len();
        let skip = (p - 1).saturating_mul(pp);
        let txs: Vec<serde_json::Value> = g
            .txs_by_hash
            .iter()
            .skip(skip)
            .take(pp)
            .map(|(h, (height, raw, parsed))| {
                serde_json::json!({
                    "hash": hex::encode_upper(h),
                    "height": height.to_string(),
                    "index": 0,
                    "tx_result": { "code": 0, "gas_wanted": parsed.gas_limit.to_string() },
                    "tx": b64_enc(raw),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "txs": txs,
            "total_count": total.to_string(),
        }))
    }

    async fn block(&self, height: Option<String>) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let h = match height.as_deref() {
            None | Some("") => g.latest_height,
            Some(s) => s.parse::<u64>().map_err(|_| err_params("bad height"))?,
        };
        let Some(blk) = g.blocks.get(&h) else {
            return Err(err_params(format!("block {h} not found")));
        };
        Ok(serde_json::json!({
            "block_id": { "hash": hex::encode_upper(blk.block_hash) },
            "block": {
                "header": {
                    "chain_id": g.chain_id,
                    "height": blk.height.to_string(),
                    "time": blk.timestamp_rfc3339,
                    "app_hash": hex::encode_upper(blk.app_hash),
                },
                "data": { "txs": [] },
            }
        }))
    }

    async fn block_results(
        &self,
        height: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let h = match height.as_deref() {
            None | Some("") => g.latest_height,
            Some(s) => s.parse::<u64>().map_err(|_| err_params("bad height"))?,
        };
        let Some(blk) = g.blocks.get(&h) else {
            return Err(err_params(format!("block {h} not found")));
        };
        let results: Vec<serde_json::Value> = blk
            .tx_hashes
            .iter()
            .map(|_| serde_json::json!({ "code": 0, "log": "", "events": [] }))
            .collect();
        Ok(serde_json::json!({
            "height": h.to_string(),
            "txs_results": results,
            "finalize_block_events": [],
            "validator_updates": [],
            "app_hash": hex::encode_upper(blk.app_hash),
        }))
    }

    async fn blockchain(
        &self,
        min_height: Option<String>,
        max_height: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let max_h = match max_height.as_deref() {
            None | Some("") => g.latest_height,
            Some(s) => s
                .parse::<u64>()
                .map_err(|_| err_params("bad maxHeight"))?
                .min(g.latest_height),
        };
        let min_h = match min_height.as_deref() {
            None | Some("") => max_h.saturating_sub(MAX_BLOCKCHAIN_RANGE - 1),
            Some(s) => s.parse::<u64>().map_err(|_| err_params("bad minHeight"))?,
        };
        let bounded_min = min_h.max(max_h.saturating_sub(MAX_BLOCKCHAIN_RANGE - 1));
        let mut metas = Vec::new();
        for h in (bounded_min..=max_h).rev() {
            if let Some(blk) = g.blocks.get(&h) {
                metas.push(serde_json::json!({
                    "block_id": { "hash": hex::encode_upper(blk.block_hash) },
                    "header": {
                        "chain_id": g.chain_id,
                        "height": blk.height.to_string(),
                        "time": blk.timestamp_rfc3339,
                        "app_hash": hex::encode_upper(blk.app_hash),
                    },
                    "num_txs": blk.tx_hashes.len().to_string(),
                }));
            }
        }
        Ok(serde_json::json!({
            "last_height": g.latest_height.to_string(),
            "block_metas": metas,
        }))
    }

    async fn validators(
        &self,
        height: Option<String>,
        _page: Option<String>,
        _per_page: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let g = self
            .inner
            .read()
            .map_err(|_| err_params("state lock poisoned"))?;
        let h = match height.as_deref() {
            None | Some("") => g.latest_height,
            Some(s) => s.parse::<u64>().map_err(|_| err_params("bad height"))?,
        };
        let vals: Vec<serde_json::Value> = g
            .validators
            .iter()
            .map(|v| {
                serde_json::json!({
                    "address": v.address_hex,
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": v.pubkey_b64,
                    },
                    "voting_power": v.voting_power.to_string(),
                    "proposer_priority": "0",
                })
            })
            .collect();
        Ok(serde_json::json!({
            "block_height": h.to_string(),
            "validators": vals,
            "count": vals.len().to_string(),
            "total": vals.len().to_string(),
        }))
    }
}

fn json_http_response(status: StatusCode, val: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

async fn handle_lcd_request(
    backend: CosmosCompatBackend,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if method == Method::GET && path == "/cosmos/base/tendermint/v1beta1/node_info" {
        let chain_id = backend
            .inner
            .read()
            .map_or_else(|_| BUDLUM_COSMOS_CHAIN_ID.to_string(), |g| g.chain_id.clone());
        return Ok(json_http_response(
            StatusCode::OK,
            &serde_json::json!({
                "default_node_info": {
                    "network": chain_id,
                    "version": "0.38.12",
                    "moniker": "budlum-uel-cosmos",
                }
            }),
        ));
    }

    if method == Method::GET && path == "/cosmos/base/tendermint/v1beta1/blocks/latest" {
        let Ok(g) = backend.inner.read() else {
            return Ok(json_http_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({ "message": "lock poisoned" }),
            ));
        };
        return Ok(json_http_response(
            StatusCode::OK,
            &serde_json::json!({
                "block": {
                    "header": {
                        "chain_id": g.chain_id,
                        "height": g.latest_height.to_string(),
                    }
                }
            }),
        ));
    }

    if method == Method::GET {
        if let Some(addr) = path.strip_prefix("/cosmos/auth/v1beta1/accounts/") {
            let Ok(g) = backend.inner.read() else {
                return Ok(json_http_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({ "message": "lock poisoned" }),
                ));
            };
            let (acct_num, seq) = match g.bech32_to_bud.get(addr) {
                Some(b) => g.foreign_book.cosmos_account_meta(b),
                None => (0, 0),
            };
            return Ok(json_http_response(
                StatusCode::OK,
                &serde_json::json!({
                    "account": {
                        "@type": "/cosmos.auth.v1beta1.BaseAccount",
                        "address": addr,
                        "account_number": acct_num.to_string(),
                        "sequence": seq.to_string(),
                    }
                }),
            ));
        }

        if let Some(addr) = path.strip_prefix("/cosmos/bank/v1beta1/balances/") {
            if !addr.contains('/') {
                let Ok(g) = backend.inner.read() else {
                    return Ok(json_http_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({ "message": "lock poisoned" }),
                    ));
                };
                let amt = ubud_of_bech32(&g, addr);
                let balances = if amt == 0 {
                    serde_json::json!([])
                } else {
                    serde_json::json!([{ "denom": "ubud", "amount": amt.to_string() }])
                };
                return Ok(json_http_response(
                    StatusCode::OK,
                    &serde_json::json!({ "balances": balances }),
                ));
            }
        }

        if let Some(rest) = path.strip_prefix("/cosmwasm/wasm/v1/contract/") {
            let parts: Vec<&str> = rest.split('/').collect();
            let Ok(g) = backend.inner.read() else {
                return Ok(json_http_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({ "message": "lock poisoned" }),
                ));
            };
            if let [addr] = parts.as_slice() {
                let Some(c) = g.contracts.get(*addr) else {
                    return Ok(json_http_response(
                        StatusCode::NOT_FOUND,
                        &serde_json::json!({ "message": "not found" }),
                    ));
                };
                return Ok(json_http_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "address": addr,
                        "contract_info": {
                            "code_id": c.code_id.to_string(),
                            "creator": c.creator,
                            "admin": c.admin,
                            "label": c.label,
                        }
                    }),
                ));
            }
            if let [addr, "smart", q_b64] = parts.as_slice() {
                let Ok(q_bytes) = b64_dec(q_b64) else {
                    return Ok(json_http_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "message": "bad base64 query" }),
                    ));
                };
                let Some(c) = g.contracts.get(*addr) else {
                    return Ok(json_http_response(
                        StatusCode::NOT_FOUND,
                        &serde_json::json!({ "message": "not found" }),
                    ));
                };
                let out = c
                    .smart_responses
                    .get(&q_bytes)
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                return Ok(json_http_response(
                    StatusCode::OK,
                    &serde_json::json!({ "data": out }),
                ));
            }
        }
    }

    if method == Method::POST && path == "/cosmos/tx/v1beta1/txs" {
        let Ok(collected) = Limited::new(req.into_body(), MAX_LCD_BODY_BYTES)
            .collect()
            .await
        else {
            return Ok(json_http_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "message": "body too large" }),
            ));
        };
        let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(&collected.to_bytes())
        else {
            return Ok(json_http_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "message": "invalid JSON" }),
            ));
        };
        let Some(tx_b64) = body_json.get("tx_bytes").and_then(serde_json::Value::as_str) else {
            return Ok(json_http_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "message": "missing tx_bytes" }),
            ));
        };
        let Ok(raw) = b64_dec(tx_b64) else {
            return Ok(json_http_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "message": "bad tx_bytes base64" }),
            ));
        };
        let Ok(mut g) = backend.inner.write() else {
            return Ok(json_http_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({ "message": "lock poisoned" }),
            ));
        };
        let Ok((code, log, hash, _)) = admit_cosmos_tx_bytes(&mut g, &raw) else {
            return Ok(json_http_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "message": "admit error" }),
            ));
        };
        return Ok(json_http_response(
            StatusCode::OK,
            &serde_json::json!({
                "tx_response": {
                    "txhash": hex::encode_upper(hash),
                    "code": code,
                    "raw_log": log,
                }
            }),
        ));
    }

    Ok(json_http_response(
        StatusCode::NOT_FOUND,
        &serde_json::json!({ "message": "unsupported LCD route" }),
    ))
}

/// Running CometBFT JSON-RPC (`127.0.0.1:18550`) + Cosmos LCD REST (`127.0.0.1:18551`) server.
pub struct CosmosCompatServer {
    pub rpc_addr: SocketAddr,
    pub rest_addr: SocketAddr,
    rpc_handle: ServerHandle,
    rest_task: JoinHandle<()>,
}

impl CosmosCompatServer {
    /// Start both the CometBFT JSON-RPC listener and the Cosmos LCD REST listener.
    ///
    /// Convenience: launched when `[compat.cosmos]` is enabled (`Section 8.11.1`).
    pub async fn start(
        cfg: &CosmosRpcConfig,
        backend: CosmosCompatBackend,
    ) -> Result<Self, String> {
        let module = backend.clone().into_rpc();
        check_served_cosmos_methods(module.method_names())
            .map_err(|m| format!("unclassified CometBFT RPC methods: {m:?}"))?;

        let server_cfg = ServerConfig::builder()
            .max_connections(256)
            .max_request_body_size(2 * 1024 * 1024)
            .max_response_body_size(8 * 1024 * 1024)
            .set_batch_request_config(BatchRequestConfig::Limit(50))
            .build();
        let server = ServerBuilder::with_config(server_cfg)
            .build(&cfg.rpc_listener)
            .await
            .map_err(|e| format!("bind CometBFT RPC {}: {e}", cfg.rpc_listener))?;
        let rpc_addr = server
            .local_addr()
            .map_err(|e| format!("CometBFT local_addr: {e}"))?;
        let rpc_handle = server.start(module);

        let lcd_listener = TcpListener::bind(&cfg.rest_listener)
            .await
            .map_err(|e| format!("bind Cosmos LCD {}: {e}", cfg.rest_listener))?;
        let rest_addr = lcd_listener
            .local_addr()
            .map_err(|e| format!("LCD local_addr: {e}"))?;
        let sem = Arc::new(Semaphore::new(MAX_LCD_CONNECTIONS));
        let rest_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = lcd_listener.accept().await else {
                    break;
                };
                let Ok(permit) = sem.clone().try_acquire_owned() else {
                    continue;
                };
                let b = backend.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let svc = hyper::service::service_fn(move |req| {
                        handle_lcd_request(b.clone(), req)
                    });
                    let mut http = hyper::server::conn::http1::Builder::new();
                    http.timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .max_buf_size(16 * 1024)
                        .keep_alive(false);
                    let conn = http.serve_connection(hyper_util::rt::TokioIo::new(stream), svc);
                    let _ = tokio::time::timeout(Duration::from_secs(15), conn).await;
                });
            }
        });

        let _ = COSMOS_RPC_METHODS.len();
        Ok(Self {
            rpc_addr,
            rest_addr,
            rpc_handle,
            rest_task,
        })
    }

    /// Gracefully stop both listeners.
    pub async fn stop(self) {
        let _ = self.rpc_handle.stop();
        self.rpc_handle.stopped().await;
        self.rest_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::coordinator::foreign::cosmos::{
        cosmos_address_from_compressed_pubkey, cosmos_bech32_address, AuthInfoProto,
        CosmosFeeProto, ModeInfoProto, ModeInfoSingleProto, MsgSendProto, SignDocProto,
        SignerInfoProto, TxBodyProto, TxRawProto, SIGN_MODE_DIRECT,
    };
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::ToSec1Point;
    use k256::elliptic_curve::PrimeField;
    use k256::{FieldBytes, ProjectivePoint, Scalar};

    #[test]
    fn cosmos_method_table_and_abci_paths_are_complete() {
        let backend = CosmosCompatBackend::new();
        let rpc_mod = backend.into_rpc();
        assert_eq!(check_served_cosmos_methods(rpc_mod.method_names()), Ok(()));
        assert_eq!(COSMOS_RPC_METHODS.len(), 12);
        assert!(is_supported_abci_query_path("/cosmwasm.wasm.v1.Query/SmartContractState"));
        assert!(!is_supported_abci_query_path("/cosmos.staking.v1beta1.Query/Validators"));
    }

    #[tokio::test]
    async fn cosmjs_abci_queries_and_broadcast_tx_sync_roundtrip() {
        let backend = CosmosCompatBackend::new();
        let sk = [0x44u8; 32];
        let d = Scalar::from_repr(sk.into()).unwrap();
        let pub33: [u8; 33] = (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let raw20 = cosmos_address_from_compressed_pubkey(&pub33).unwrap();
        let sender = cosmos_bech32_address(&raw20);
        backend.seed_foreign_ubud(&raw20, &sender, 50_000);

        // 1. Query balance via protobuf `abci_query` (exact CosmJS query path)
        let bal_req = QueryBalanceRequestProto {
            address: sender.clone(),
            denom: String::from("ubud"),
        }
        .encode_to_vec();
        let q_out = backend
            .abci_query(
                String::from("/cosmos.bank.v1beta1.Query/Balance"),
                Some(hex::encode(&bal_req)),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(q_out["response"]["code"], 0);
        let val_b64 = q_out["response"]["value"].as_str().unwrap();
        let bal_resp = QueryBalanceResponseProto::decode(b64_dec(val_b64).unwrap().as_slice())
            .unwrap();
        assert_eq!(bal_resp.balance.unwrap().amount, "50000");

        // 2. Broadcast signed TxRaw via `broadcast_tx_sync`
        let body_bytes = TxBodyProto {
            messages: vec![ProtoAny {
                type_url: String::from("/cosmos.bank.v1beta1.MsgSend"),
                value: MsgSendProto {
                    from_address: sender,
                    to_address: cosmos_bech32_address(&[0x99; 20]),
                    amount: vec![CosmosCoinProto {
                        denom: String::from("ubud"),
                        amount: String::from("100"),
                    }],
                }
                .encode_to_vec(),
            }],
            memo: String::new(),
            timeout_height: 0,
        }
        .encode_to_vec();
        let auth_bytes = AuthInfoProto {
            signer_infos: vec![SignerInfoProto {
                public_key: Some(ProtoAny {
                    type_url: SECP256K1_PUBKEY_TYPE_URL.to_string(),
                    value: Secp256k1PubKeyProto {
                        key: pub33.to_vec(),
                    }
                    .encode_to_vec(),
                }),
                mode_info: Some(ModeInfoProto {
                    single: Some(ModeInfoSingleProto {
                        mode: SIGN_MODE_DIRECT,
                    }),
                }),
                sequence: 0,
            }],
            fee: Some(CosmosFeeProto {
                amount: vec![CosmosCoinProto {
                    denom: String::from("ubud"),
                    amount: String::from("10"),
                }],
                gas_limit: 150_000,
                payer: String::new(),
                granter: String::new(),
            }),
        }
        .encode_to_vec();
        let sdoc = SignDocProto {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_bytes.clone(),
            chain_id: BUDLUM_COSMOS_CHAIN_ID.to_string(),
            account_number: 0,
        }
        .encode_to_vec();
        let digest: [u8; 32] = Sha256::digest(&sdoc).into();
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(digest));
        let k = Scalar::from_repr([0x21u8; 32].into()).unwrap();
        let big_r = (ProjectivePoint::GENERATOR * k).to_affine().to_sec1_point(true);
        let rx = FieldBytes::try_from(&big_r.as_bytes()[1..33]).unwrap();
        let r = <Scalar as Reduce<FieldBytes>>::reduce(&rx);
        let mut s = k.invert().unwrap() * (e + r * d);
        let half: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa0,
        ];
        let sb: [u8; 32] = s.to_bytes().into();
        if sb > half {
            s = -s;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r.to_bytes().as_slice());
        sig[32..].copy_from_slice(s.to_bytes().as_slice());
        let tx_raw = TxRawProto {
            body_bytes,
            auth_info_bytes: auth_bytes,
            signatures: vec![sig.to_vec()],
        }
        .encode_to_vec();

        let bcast = backend.broadcast_tx_sync(b64_enc(&tx_raw)).await.unwrap();
        assert_eq!(bcast["code"], 0);
        let tx_hash_hex = bcast["hash"].as_str().unwrap().to_string();
        let tx_lookup = backend.tx(tx_hash_hex, None).await.unwrap();
        assert_eq!(tx_lookup["tx_result"]["code"], 0);
    }
}
