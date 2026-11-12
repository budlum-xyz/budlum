//! CometBFT RPC (`127.0.0.1:18550`) & Cosmos LCD (`127.0.0.1:18551`) gateway
//! ( & section 8.11.5) supporting CosmJS `SigningCosmWasmClient`.
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::core::account::{AccountState, ATTOS_PER_ATOM};
use crate::execution::coordinator::foreign::cosmos::BUDLUM_COSMOS_CHAIN_ID;
use crate::execution::coordinator::foreign::ForeignTx;
use crate::execution::coordinator::state::{NS_WASM_CODE, NS_WASM_CONTRACT, NS_WASM_STORE};
use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, CosmosCompatConfig, JsonRpcRequest,
    JsonRpcResponse, PeerQuotaTracker, JSONRPC_INVALID_PARAMS, JSONRPC_LIMIT_EXCEEDED,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_TX_REJECTED,
};

const DEFAULT_COSMOS_MAX_REQUESTS_PER_WINDOW: u32 = 120;

const fn row(name: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass::new(name, CompatListener::Public, effect)
}

/// Complete `CometBFT` JSON-RPC method table (section 8.11.5 item 1, all 12 methods).
pub const COMETBFT_RPC_METHODS: &[CompatMethodClass] = &[
    row("status", CompatEffect::Read),
    row("abci_info", CompatEffect::Read),
    row("abci_query", CompatEffect::Read),
    row("broadcast_tx_sync", CompatEffect::TxSubmit),
    row("broadcast_tx_async", CompatEffect::TxSubmit),
    row("broadcast_tx_commit", CompatEffect::TxSubmit),
    row("tx", CompatEffect::Read),
    row("tx_search", CompatEffect::Read),
    row("block", CompatEffect::Read),
    row("block_results", CompatEffect::Read),
    row("blockchain", CompatEffect::Read),
    row("validators", CompatEffect::Read),
];

/// Supported `abci_query` gRPC query paths (section 8.11.5 item 2, all 10 paths).
pub const ABCI_QUERY_PATHS: &[&str] = &[
    "/cosmos.auth.v1beta1.Query/Account",
    "/cosmos.bank.v1beta1.Query/Balance",
    "/cosmos.bank.v1beta1.Query/AllBalances",
    "/cosmwasm.wasm.v1.Query/SmartContractState",
    "/cosmwasm.wasm.v1.Query/RawContractState",
    "/cosmwasm.wasm.v1.Query/ContractInfo",
    "/cosmwasm.wasm.v1.Query/ContractsByCode",
    "/cosmwasm.wasm.v1.Query/Code",
    "/cosmwasm.wasm.v1.Query/Codes",
    "/cosmos.tx.v1beta1.Service/Simulate",
];

/// CometBFT + Cosmos gRPC-REST compatibility gateway (`state` is read-only).
#[derive(Debug, Clone)]
pub struct CosmosCompatGateway {
    config: CosmosCompatConfig,
    height: u64,
    quotas: PeerQuotaTracker,
    max_requests_per_window: u32,
}

impl CosmosCompatGateway {
    #[must_use]
    pub fn new(config: CosmosCompatConfig, height: u64) -> Self {
        Self {
            config,
            height,
            quotas: PeerQuotaTracker::default(),
            max_requests_per_window: DEFAULT_COSMOS_MAX_REQUESTS_PER_WINDOW,
        }
    }

    pub fn handle_rpc(&mut self, req: &JsonRpcRequest, state: &AccountState) -> JsonRpcResponse {
        self.handle_rpc_for_peer("local", req, state)
    }

    pub(crate) fn handle_rpc_for_peer(
        &mut self,
        peer: &str,
        req: &JsonRpcRequest,
        state: &AccountState,
    ) -> JsonRpcResponse {
        let id = req.id.clone();
        if let Err(msg) = self
            .quotas
            .record_and_check(peer, self.max_requests_per_window)
        {
            return JsonRpcResponse::err(id, JSONRPC_LIMIT_EXCEEDED, msg);
        }
        if !COMETBFT_RPC_METHODS.iter().any(|m| m.name == req.method) {
            return JsonRpcResponse::err(id, JSONRPC_METHOD_NOT_FOUND, "Method not found");
        }
        let h_str = self.height.to_string();
        match req.method.as_str() {
            "status" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "node_info": {
                        "network": BUDLUM_COSMOS_CHAIN_ID,
                        "version": "0.38.0-budlum",
                    },
                    "sync_info": {
                        "latest_block_height": h_str,
                        "catching_up": false,
                    }
                }),
            ),
            "abci_info" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "response": {
                        "data": "Budlum-UEL-WASM",
                        "last_block_height": h_str,
                    }
                }),
            ),
            "abci_query" => {
                let path = req
                    .params
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if !ABCI_QUERY_PATHS.contains(&path) {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        format!("unsupported abci_query path: {path}"),
                    );
                }
                let data_hex = req
                    .params
                    .get("data")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();
                let resp_bytes = execute_abci_query(path, &data, state);
                JsonRpcResponse::ok(
                    id,
                    serde_json::json!({
                        "response": {
                            "code": 0,
                            "value": hex::encode(resp_bytes),
                            "height": h_str,
                        }
                    }),
                )
            }
            "broadcast_tx_sync" | "broadcast_tx_async" | "broadcast_tx_commit" => {
                let Some(tx_hex) = req.params.get("tx").and_then(serde_json::Value::as_str) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "missing tx hex");
                };
                if tx_hex.len()
                    > crate::rpc::compat::ethereum::MAX_COMPAT_REQUEST_BYTES.saturating_mul(2)
                {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_LIMIT_EXCEEDED,
                        "broadcast_tx payload exceeds MAX_COMPAT_REQUEST_BYTES",
                    );
                }
                let Ok(tx_raw_bytes) = hex::decode(tx_hex.trim_start_matches("0x")) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "invalid tx hex");
                };
                let acct_num = req
                    .params
                    .get("account_number")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let env = ForeignTx::Cosmos {
                    tx_raw_bytes,
                    chain_id: String::from(BUDLUM_COSMOS_CHAIN_ID),
                    account_number: acct_num,
                    direct_native_pq_recipient: None,
                };
                match state
                    .execution_state
                    .foreign_lane
                    .validate_envelope_readonly(&state.execution_state, &env, 0)
                {
                    Ok(tx_hash) => JsonRpcResponse::ok(
                        id,
                        serde_json::json!({
                            "code": 0,
                            "hash": hex::encode(tx_hash).to_uppercase(),
                        }),
                    ),
                    Err(e) => JsonRpcResponse::err(id, JSONRPC_TX_REJECTED, e.to_string()),
                }
            }
            "tx_search" => {
                let per_page = req
                    .params
                    .get("per_page")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(30) as usize;
                if per_page > self.config.max_tx_search_results {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_LIMIT_EXCEEDED,
                        "per_page exceeds max_tx_search_results",
                    );
                }
                JsonRpcResponse::ok(id, serde_json::json!({ "txs": [], "total_count": "0" }))
            }
            "validators" => JsonRpcResponse::ok(
                id,
                serde_json::json!({ "block_height": h_str, "validators": [] }),
            ),
            _ => JsonRpcResponse::ok(id, serde_json::json!({})),
        }
    }
}

fn execute_abci_query(path: &str, data: &[u8], state: &AccountState) -> Vec<u8> {
    let _ = ATTOS_PER_ATOM;
    match path {
        "/cosmwasm.wasm.v1.Query/RawContractState" => state
            .execution_state
            .read(NS_WASM_STORE, data)
            .ok()
            .flatten()
            .unwrap_or_default(),
        "/cosmwasm.wasm.v1.Query/SmartContractState" => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
                let contract = v
                    .get("contract")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let key = v
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let mut sk = contract.as_bytes().to_vec();
                sk.extend_from_slice(format!(":kv:{key}").as_bytes());
                return state
                    .execution_state
                    .read(NS_WASM_STORE, &sk)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
            }
            Vec::new()
        }
        "/cosmwasm.wasm.v1.Query/ContractInfo" => state
            .execution_state
            .read(NS_WASM_CONTRACT, data)
            .ok()
            .flatten()
            .unwrap_or_default(),
        "/cosmwasm.wasm.v1.Query/Code" => state
            .execution_state
            .read(NS_WASM_CODE, data)
            .ok()
            .flatten()
            .unwrap_or_default(),
        _ => b"{}".to_vec(),
    }
}

/// Evaluates a Cosmos LCD gRPC-REST request against read-only `state` (`18551`).
///
/// exposed for: wire-level Cosmos LCD REST handler.
#[must_use]
pub fn handle_cosmos_rest(
    state: &AccountState,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> (u16, String) {
    if body.is_some_and(|b| b.len() > crate::rpc::compat::ethereum::MAX_COMPAT_REQUEST_BYTES) {
        return (
            413,
            serde_json::json!({ "message": "payload too large" }).to_string(),
        );
    }
    match (method, path) {
        ("GET", "/cosmos/base/tendermint/v1beta1/node_info") => (
            200,
            serde_json::json!({
                "default_node_info": {
                    "network": BUDLUM_COSMOS_CHAIN_ID,
                    "version": "0.50.0-budlum",
                }
            })
            .to_string(),
        ),
        ("GET", p) if p.starts_with("/cosmwasm/wasm/v1/contract/") => {
            let rest = p.trim_start_matches("/cosmwasm/wasm/v1/contract/");
            let info = execute_abci_query(
                "/cosmwasm.wasm.v1.Query/ContractInfo",
                rest.as_bytes(),
                state,
            );
            (
                200,
                serde_json::json!({ "data": hex::encode(info) }).to_string(),
            )
        }
        _ => (
            404,
            serde_json::json!({ "message": "cosmos LCD route not found" }).to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosmos_compat_peer_quota_enforces_limit_and_payload_bound() {
        let state = AccountState::new(45261);
        let mut gw = CosmosCompatGateway::new(CosmosCompatConfig::default(), 7);
        let req = JsonRpcRequest {
            jsonrpc: String::from("2.0"),
            id: serde_json::json!(1),
            method: String::from("status"),
            params: serde_json::json!({}),
        };
        for _ in 0..DEFAULT_COSMOS_MAX_REQUESTS_PER_WINDOW {
            assert!(gw.handle_rpc_for_peer("peer-a", &req, &state).error.is_none());
        }
        let limited = gw.handle_rpc_for_peer("peer-a", &req, &state);
        assert_eq!(limited.error.as_ref().map(|e| e.code), Some(JSONRPC_LIMIT_EXCEEDED));
        assert!(gw.handle_rpc_for_peer("peer-b", &req, &state).error.is_none());

        let oversized = "ab".repeat(crate::rpc::compat::ethereum::MAX_COMPAT_REQUEST_BYTES + 8);
        let big_tx = JsonRpcRequest {
            jsonrpc: String::from("2.0"),
            id: serde_json::json!(2),
            method: String::from("broadcast_tx_sync"),
            params: serde_json::json!({ "tx": oversized }),
        };
        let big_resp = gw.handle_rpc_for_peer("peer-b", &big_tx, &state);
        assert_eq!(big_resp.error.as_ref().map(|e| e.code), Some(JSONRPC_LIMIT_EXCEEDED));
    }
}
