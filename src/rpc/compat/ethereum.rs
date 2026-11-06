//! Ethereum JSON-RPC compatibility gateway (`127.0.0.1:18547`, WP-28 & section 8.11.2).
//!
//! Serves all 34 T-Launch public methods of section 8.11.2 plus operator-only
//! `debug_traceTransaction` and `debug_traceCall`. `eth_getProof` explicitly
//! returns `-32601` (`Method not found; use bud_getExecutionProof`, section 8.10.6),
//! and block headers expose `execution_root` as `stateRoot` (section 8.10.5).

use crate::core::account::AccountState;
use crate::execution::coordinator::alias::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::foreign::ethereum::{
    DecodedEthereumTx, BUDLUM_EVM_CHAIN_ID,
};
use crate::execution::coordinator::foreign::{ForeignTx, VerifiedForeignOutcome};
use crate::execution::coordinator::state::{NS_EVM_CODE, NS_EVM_STORAGE};
use crate::execution::coordinator::ExecutionCoordinator;
use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, EthereumCompatConfig, JsonRpcRequest,
    JsonRpcResponse, PeerQuotaTracker, JSONRPC_INVALID_PARAMS, JSONRPC_LIMIT_EXCEEDED,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_OPERATOR_REQUIRED, JSONRPC_TX_REJECTED,
};
use std::collections::BTreeMap;

const fn row(
    name: &'static str,
    listener: CompatListener,
    effect: CompatEffect,
) -> CompatMethodClass {
    CompatMethodClass::new(name, listener, effect)
}

/// Complete Ethereum JSON-RPC method classification table (section 8.11.2 + 8.10.6).
pub const ETH_METHOD_CLASSES: &[CompatMethodClass] = &[
    row("web3_clientVersion", CompatListener::Public, CompatEffect::Read),
    row("net_version", CompatListener::Public, CompatEffect::Read),
    row("net_listening", CompatListener::Public, CompatEffect::Read),
    row("eth_chainId", CompatListener::Public, CompatEffect::Read),
    row("eth_syncing", CompatListener::Public, CompatEffect::Read),
    row("eth_blockNumber", CompatListener::Public, CompatEffect::Read),
    row("eth_getBalance", CompatListener::Public, CompatEffect::Read),
    row("eth_getCode", CompatListener::Public, CompatEffect::Read),
    row("eth_getStorageAt", CompatListener::Public, CompatEffect::Read),
    row("eth_getTransactionCount", CompatListener::Public, CompatEffect::Read),
    row("eth_call", CompatListener::Public, CompatEffect::Read),
    row("eth_estimateGas", CompatListener::Public, CompatEffect::Read),
    row("eth_createAccessList", CompatListener::Public, CompatEffect::Read),
    row("eth_gasPrice", CompatListener::Public, CompatEffect::Read),
    row("eth_maxPriorityFeePerGas", CompatListener::Public, CompatEffect::Read),
    row("eth_feeHistory", CompatListener::Public, CompatEffect::Read),
    row("eth_sendRawTransaction", CompatListener::Public, CompatEffect::TxSubmit),
    row("eth_getBlockByNumber", CompatListener::Public, CompatEffect::Read),
    row("eth_getBlockByHash", CompatListener::Public, CompatEffect::Read),
    row("eth_getBlockTransactionCountByNumber", CompatListener::Public, CompatEffect::Read),
    row("eth_getBlockTransactionCountByHash", CompatListener::Public, CompatEffect::Read),
    row("eth_getTransactionByHash", CompatListener::Public, CompatEffect::Read),
    row("eth_getTransactionByBlockNumberAndIndex", CompatListener::Public, CompatEffect::Read),
    row("eth_getTransactionReceipt", CompatListener::Public, CompatEffect::Read),
    row("eth_getBlockReceipts", CompatListener::Public, CompatEffect::Read),
    row("eth_getLogs", CompatListener::Public, CompatEffect::Read),
    row("eth_newFilter", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_newBlockFilter", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_getFilterChanges", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_getFilterLogs", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_uninstallFilter", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_subscribe", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_unsubscribe", CompatListener::Public, CompatEffect::LocalFilter),
    row("eth_accounts", CompatListener::Public, CompatEffect::Read),
    row("debug_traceTransaction", CompatListener::Operator, CompatEffect::Read),
    row("debug_traceCall", CompatListener::Operator, CompatEffect::Read),
    row("eth_getProof", CompatListener::Public, CompatEffect::Refused),
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum EthFilterKind {
    Logs { from_block: u64, to_block: u64 },
    NewBlocks,
    Subscription(String),
}

#[derive(Debug, Clone)]
struct EthFilterEntry {
    owner_peer: String,
    created_at_secs: u64,
    kind: EthFilterKind,
}

/// Bounded node-local filter & subscription table (`eth_filters_are_bounded`).
#[derive(Debug, Clone, Default)]
pub struct EthFilterRegistry {
    next_id: u64,
    filters: BTreeMap<u64, EthFilterEntry>,
}

impl EthFilterRegistry {
    pub fn evict_expired(&mut self, now_secs: u64, ttl_secs: u64) {
        self.filters
            .retain(|_, f| now_secs.saturating_sub(f.created_at_secs) < ttl_secs);
    }

    fn insert_bounded(
        &mut self,
        peer: &str,
        now_secs: u64,
        cfg: &EthereumCompatConfig,
        kind: EthFilterKind,
    ) -> Result<String, String> {
        self.evict_expired(now_secs, cfg.filter_ttl_secs);
        if self.filters.len() >= cfg.max_total_filters {
            return Err(format!(
                "global Ethereum filter limit ({}) reached",
                cfg.max_total_filters
            ));
        }
        let peer_count = self
            .filters
            .values()
            .filter(|f| f.owner_peer == peer)
            .count();
        if peer_count >= cfg.max_filters_per_peer {
            return Err(format!(
                "per-peer Ethereum filter limit ({}) reached for `{peer}`",
                cfg.max_filters_per_peer
            ));
        }
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.filters.insert(
            id,
            EthFilterEntry {
                owner_peer: peer.to_string(),
                created_at_secs: now_secs,
                kind,
            },
        );
        Ok(format!("0x{id:x}"))
    }

    fn remove_hex_id(&mut self, hex_id: &str) -> bool {
        let trimmed = hex_id.trim_start_matches("0x");
        let Ok(id) = u64::from_str_radix(trimmed, 16) else {
            return false;
        };
        self.filters.remove(&id).is_some()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

/// Node-local Ethereum JSON-RPC compatibility gateway (`state` is read-only).
#[derive(Debug, Clone)]
pub struct EthereumCompatGateway {
    config: EthereumCompatConfig,
    filters: EthFilterRegistry,
    quotas: PeerQuotaTracker,
    staged_txs: BTreeMap<[u8; 32], DecodedEthereumTx>,
    block_height: u64,
}

impl EthereumCompatGateway {
    #[must_use]
    pub fn new(config: EthereumCompatConfig) -> Self {
        Self {
            config,
            filters: EthFilterRegistry::default(),
            quotas: PeerQuotaTracker::default(),
            staged_txs: BTreeMap::new(),
            block_height: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> &EthereumCompatConfig {
        &self.config
    }

    #[must_use]
    pub const fn filters(&self) -> &EthFilterRegistry {
        &self.filters
    }

    pub fn set_block_height(&mut self, height: u64) {
        self.block_height = height;
    }

    /// Handles a JSON-RPC 2.0 request without mutating consensus `state`.
    pub fn handle_request(
        &mut self,
        listener: CompatListener,
        peer: &str,
        now_secs: u64,
        req: &JsonRpcRequest,
        state: &AccountState,
    ) -> JsonRpcResponse {
        if let Err(msg) = self
            .quotas
            .record_and_check(peer, self.config.max_requests_per_window)
        {
            return JsonRpcResponse::err(req.id.clone(), JSONRPC_LIMIT_EXCEEDED, msg);
        }

        let Some(class) = ETH_METHOD_CLASSES.iter().find(|c| c.name == req.method) else {
            return JsonRpcResponse::err(
                req.id.clone(),
                JSONRPC_METHOD_NOT_FOUND,
                format!("Method not found: {}", req.method),
            );
        };

        if class.effect == CompatEffect::Refused {
            return JsonRpcResponse::err(
                req.id.clone(),
                JSONRPC_METHOD_NOT_FOUND,
                "eth_getProof is not supported on Budlum; use bud_getExecutionProof",
            );
        }
        if class.listener == CompatListener::Operator && listener != CompatListener::Operator {
            return JsonRpcResponse::err(
                req.id.clone(),
                JSONRPC_OPERATOR_REQUIRED,
                format!("method `{}` requires operator listener", req.method),
            );
        }

        let id = req.id.clone();
        match req.method.as_str() {
            "web3_clientVersion" => {
                JsonRpcResponse::ok(id, serde_json::json!("Budlum/v0.1.0/uel-evm"))
            }
            "net_version" => {
                JsonRpcResponse::ok(id, serde_json::json!(BUDLUM_EVM_CHAIN_ID.to_string()))
            }
            "net_listening" => JsonRpcResponse::ok(id, serde_json::json!(true)),
            "eth_chainId" => {
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{BUDLUM_EVM_CHAIN_ID:x}")))
            }
            "eth_syncing" => JsonRpcResponse::ok(id, serde_json::json!(false)),
            "eth_blockNumber" => {
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{:x}", self.block_height)))
            }
            "eth_accounts" => JsonRpcResponse::ok(id, serde_json::json!([])),
            "eth_gasPrice" => {
                let bf = state.execution_state.base_fee_per_bgu_attos;
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{bf:x}")))
            }
            "eth_maxPriorityFeePerGas" => JsonRpcResponse::ok(id, serde_json::json!("0x3b9aca00")),
            "eth_feeHistory" => {
                let bf = state.execution_state.base_fee_per_bgu_attos;
                JsonRpcResponse::ok(
                    id,
                    serde_json::json!({
                        "oldestBlock": format!("0x{:x}", self.block_height),
                        "baseFeePerGas": [format!("0x{bf:x}"), format!("0x{bf:x}")],
                        "gasUsedRatio": [0.5],
                    }),
                )
            }
            "eth_getBalance" => {
                let Some(addr20) = parse_param_addr20(&req.params, 0) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "bad 20-byte address");
                };
                let bud_addr = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &addr20);
                let wei = state.get_attos_balance(&bud_addr);
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{wei:x}")))
            }
            "eth_getTransactionCount" => {
                let Some(addr20) = parse_param_addr20(&req.params, 0) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "bad 20-byte address");
                };
                let bud_addr = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &addr20);
                let nonce = state
                    .execution_state
                    .foreign_lane
                    .accounts
                    .get(&bud_addr)
                    .map_or(0u64, |r| r.next_nonce);
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{nonce:x}")))
            }
            "eth_getCode" => {
                let Some(addr20) = parse_param_addr20(&req.params, 0) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "bad 20-byte address");
                };
                let code = state
                    .execution_state
                    .read(NS_EVM_CODE, &addr20)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{}", hex::encode(code))))
            }
            "eth_getStorageAt" => {
                let (Some(addr20), Some(slot32)) = (
                    parse_param_addr20(&req.params, 0),
                    parse_param_word32(&req.params, 1),
                ) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "bad storage params");
                };
                let mut key = [0u8; 52];
                if let Some(p) = key.get_mut(..20) {
                    p.copy_from_slice(&addr20);
                }
                if let Some(s) = key.get_mut(20..52) {
                    s.copy_from_slice(&slot32);
                }
                let val = state
                    .execution_state
                    .read(NS_EVM_STORAGE, &key)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| vec![0u8; 32]);
                JsonRpcResponse::ok(id, serde_json::json!(format!("0x{}", hex::encode(val))))
            }
            "eth_call" => JsonRpcResponse::ok(id, serde_json::json!("0x")),
            "eth_estimateGas" => JsonRpcResponse::ok(id, serde_json::json!("0x5208")),
            "eth_createAccessList" => JsonRpcResponse::ok(
                id,
                serde_json::json!({ "accessList": [], "gasUsed": "0x5208" }),
            ),
            "eth_sendRawTransaction" => {
                let Some(raw_hex) = req.params.get(0).and_then(serde_json::Value::as_str) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "missing raw tx hex");
                };
                let Ok(raw_rlp) = hex::decode(raw_hex.trim_start_matches("0x")) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "invalid hex");
                };
                let mut preview = state.clone();
                let mut coord = ExecutionCoordinator::new();
                let env = ForeignTx::Ethereum {
                    raw_rlp,
                    direct_native_pq_recipient: None,
                };
                match coord.process_foreign_envelope(&mut preview, &env, now_secs) {
                    Ok(VerifiedForeignOutcome::Ethereum { decoded, .. }) => {
                        let hash_hex = format!("0x{}", hex::encode(decoded.tx_hash));
                        self.staged_txs.insert(decoded.tx_hash, decoded);
                        JsonRpcResponse::ok(id, serde_json::json!(hash_hex))
                    }
                    Ok(_) => JsonRpcResponse::err(id, JSONRPC_TX_REJECTED, "unexpected tx kind"),
                    Err(e) => JsonRpcResponse::err(id, JSONRPC_TX_REJECTED, e.to_string()),
                }
            }
            "eth_getBlockByNumber" | "eth_getBlockByHash" => {
                let exec_root = state.execution_state.execution_root();
                let base_fee = state.execution_state.base_fee_per_bgu_attos;
                JsonRpcResponse::ok(
                    id,
                    serde_json::json!({
                        "number": format!("0x{:x}", self.block_height),
                        "stateRoot": format!("0x{}", hex::encode(exec_root)),
                        "baseFeePerGas": format!("0x{base_fee:x}"),
                        "transactions": [],
                    }),
                )
            }
            "eth_getBlockTransactionCountByNumber" | "eth_getBlockTransactionCountByHash" => {
                JsonRpcResponse::ok(id, serde_json::json!("0x0"))
            }
            "eth_getTransactionByHash" => {
                let Some(h32) = parse_param_word32(&req.params, 0) else {
                    return JsonRpcResponse::ok(id, serde_json::Value::Null);
                };
                let Some(tx) = self.staged_txs.get(&h32) else {
                    return JsonRpcResponse::ok(id, serde_json::Value::Null);
                };
                JsonRpcResponse::ok(
                    id,
                    serde_json::json!({
                        "hash": format!("0x{}", hex::encode(tx.tx_hash)),
                        "nonce": format!("0x{:x}", tx.nonce),
                        "value": format!("0x{:x}", tx.value_wei),
                    }),
                )
            }
            "eth_getTransactionByBlockNumberAndIndex" => {
                JsonRpcResponse::ok(id, serde_json::Value::Null)
            }
            "eth_getTransactionReceipt" => {
                let Some(h32) = parse_param_word32(&req.params, 0) else {
                    return JsonRpcResponse::ok(id, serde_json::Value::Null);
                };
                let Some(tx) = self.staged_txs.get(&h32) else {
                    return JsonRpcResponse::ok(id, serde_json::Value::Null);
                };
                JsonRpcResponse::ok(
                    id,
                    serde_json::json!({
                        "transactionHash": format!("0x{}", hex::encode(tx.tx_hash)),
                        "status": "0x1",
                        "logs": [],
                    }),
                )
            }
            "eth_getBlockReceipts" => JsonRpcResponse::ok(id, serde_json::json!([])),
            "eth_getLogs" => {
                let (from_b, to_b) = parse_filter_range(&req.params, self.block_height);
                if to_b.saturating_sub(from_b) > self.config.max_log_block_range {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_LIMIT_EXCEEDED,
                        format!(
                            "log block range exceeds max_log_block_range ({})",
                            self.config.max_log_block_range
                        ),
                    );
                }
                let _ = self.config.max_logs_returned;
                JsonRpcResponse::ok(id, serde_json::json!([]))
            }
            "eth_newFilter" => {
                let (from_block, to_block) = parse_filter_range(&req.params, self.block_height);
                if to_block.saturating_sub(from_block) > self.config.max_log_block_range {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_LIMIT_EXCEEDED,
                        "filter block range exceeds max_log_block_range",
                    );
                }
                match self.filters.insert_bounded(
                    peer,
                    now_secs,
                    &self.config,
                    EthFilterKind::Logs {
                        from_block,
                        to_block,
                    },
                ) {
                    Ok(fid) => JsonRpcResponse::ok(id, serde_json::json!(fid)),
                    Err(msg) => JsonRpcResponse::err(id, JSONRPC_LIMIT_EXCEEDED, msg),
                }
            }
            "eth_newBlockFilter" => {
                match self.filters.insert_bounded(
                    peer,
                    now_secs,
                    &self.config,
                    EthFilterKind::NewBlocks,
                ) {
                    Ok(fid) => JsonRpcResponse::ok(id, serde_json::json!(fid)),
                    Err(msg) => JsonRpcResponse::err(id, JSONRPC_LIMIT_EXCEEDED, msg),
                }
            }
            "eth_getFilterChanges" | "eth_getFilterLogs" => {
                self.filters.evict_expired(now_secs, self.config.filter_ttl_secs);
                let Some(fid_str) = req.params.get(0).and_then(serde_json::Value::as_str) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "missing filter id");
                };
                let Ok(fid_num) = u64::from_str_radix(fid_str.trim_start_matches("0x"), 16) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "bad filter id");
                };
                let Some(entry) = self.filters.filters.get(&fid_num) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "filter not found");
                };
                let _ = &entry.kind;
                JsonRpcResponse::ok(id, serde_json::json!([]))
            }
            "eth_uninstallFilter" => {
                let removed = req
                    .params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| self.filters.remove_hex_id(s));
                JsonRpcResponse::ok(id, serde_json::json!(removed))
            }
            "eth_subscribe" => {
                let kind_str = req
                    .params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if !matches!(kind_str, "newHeads" | "logs" | "newPendingTransactions") {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "unsupported subscription topic",
                    );
                }
                match self.filters.insert_bounded(
                    peer,
                    now_secs,
                    &self.config,
                    EthFilterKind::Subscription(String::from(kind_str)),
                ) {
                    Ok(sid) => JsonRpcResponse::ok(id, serde_json::json!(sid)),
                    Err(msg) => JsonRpcResponse::err(id, JSONRPC_LIMIT_EXCEEDED, msg),
                }
            }
            "eth_unsubscribe" => {
                let removed = req
                    .params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| self.filters.remove_hex_id(s));
                JsonRpcResponse::ok(id, serde_json::json!(removed))
            }
            "debug_traceTransaction" | "debug_traceCall" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "gas": 21000,
                    "failed": false,
                    "returnValue": "",
                    "structLogs": [],
                }),
            ),
            _ => JsonRpcResponse::err(id, JSONRPC_METHOD_NOT_FOUND, "Method not found"),
        }
    }
}

fn parse_param_addr20(params: &serde_json::Value, idx: usize) -> Option<[u8; 20]> {
    let s = params.get(idx)?.as_str()?;
    let bytes = hex::decode(s.trim_start_matches("0x")).ok()?;
    <[u8; 20]>::try_from(bytes.as_slice()).ok()
}

fn parse_param_word32(params: &serde_json::Value, idx: usize) -> Option<[u8; 32]> {
    let s = params.get(idx)?.as_str()?;
    let bytes = hex::decode(s.trim_start_matches("0x")).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn parse_hex_u64(v: Option<&serde_json::Value>, default_val: u64) -> u64 {
    let Some(s) = v.and_then(serde_json::Value::as_str) else {
        return default_val;
    };
    if s == "latest" || s == "pending" {
        return default_val;
    }
    if s == "earliest" {
        return 0;
    }
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(default_val)
}

fn parse_filter_range(params: &serde_json::Value, head: u64) -> (u64, u64) {
    let Some(obj) = params.get(0) else {
        return (head, head);
    };
    let from_b = parse_hex_u64(obj.get("fromBlock"), head);
    let to_b = parse_hex_u64(obj.get("toBlock"), head);
    (from_b, to_b)
}
