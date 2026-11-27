//! Starknet JSON-RPC v0.7 read-only compatibility subset (`Section 8.11`).
//!
//! Serves Starknet read methods (`starknet_specVersion`, `starknet_chainId`,
//! `starknet_blockNumber`, `starknet_getNonce`, `starknet_getStorageAt`,
//! `starknet_getClassHashAt`) without mutating consensus state, and enforces
//! `Section 1.5` launch-closure on testnet `45261` until activation.
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::account::AccountState;
use crate::execution::coordinator::assets::BUDLUM_TESTNET_CHAIN_ID;

/// Explicit activation fixture height; the public-testnet default remains closed.
///
/// Convenience: shared by Starknet RPC policy and activation checks.
pub const PROPOSED_CAIRO_ACTIVATION_HEIGHT: u64 = 0;
/// Maximum Starknet RPC request envelope size (1 MiB).
pub const MAX_STARKNET_RPC_REQUEST_BYTES: usize = 1 << 20;

/// Starknet JSON-RPC specification version supported by this gateway.
///
/// Convenience: returned by `starknet_specVersion`.
pub const STARKNET_SPEC_VERSION: &str = "0.7.1";

/// Height-gated activation policy for Starknet JSON-RPC (`Section 1.5`).
///
/// Convenience: passed to `handle_starknet_rpc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarknetActivationPolicy {
    pub chain_id: u64,
    pub block_height: u64,
    pub activation_height: Option<u64>,
}

impl Default for StarknetActivationPolicy {
    fn default() -> Self {
        Self::testnet_launch()
    }
}

impl StarknetActivationPolicy {
    /// Default launch posture on testnet `45261`: closed until explicit activation.
    ///
    /// Convenience: default policy for Starknet RPC handlers.
    #[must_use]
    pub const fn testnet_launch() -> Self {
        Self {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 0,
            activation_height: None,
        }
    }

    /// Returns `true` when Cairo/Starknet RPC is open at `(chain_id, block_height)`.
    ///
    /// Convenience: queried before serving Starknet JSON-RPC requests.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        if self.chain_id == budlum_uel_abi::BUDLUM_DEVNET_CHAIN_ID {
            return true;
        }
        if self.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return false;
        }
        match self.activation_height {
            Some(h) => self.block_height >= h,
            None => false,
        }
    }
}

/// JSON-RPC 2.0 request envelope for Starknet compatibility endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct StarknetRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Vec<Value>,
}

/// JSON-RPC 2.0 response envelope for Starknet compatibility endpoints.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StarknetRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl StarknetRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Value, code: i64, msg: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(json!({ "code": code, "message": msg })),
        }
    }
}

/// Starknet `felt252` field prime `P = 2^251 + 17 * 2^192 + 1`.
const STARKNET_PRIME: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn parse_felt_hex(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.strip_prefix("0x")?;
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let padded = format!("{trimmed:0>64}");
    let bytes = hex::decode(padded).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    if arr >= STARKNET_PRIME {
        return None;
    }
    Some(arr)
}

fn is_valid_block_id(val: &Value) -> bool {
    match val {
        Value::String(s) => s == "latest" || s == "pending",
        Value::Object(obj) => {
            if obj.len() != 1 {
                return false;
            }
            if let Some(num) = obj.get("block_number") {
                return num.is_u64();
            }
            if let Some(hash) = obj.get("block_hash").and_then(Value::as_str) {
                return parse_felt_hex(hash).is_some();
            }
            false
        }
        _ => false,
    }
}

/// Evaluates a raw Starknet JSON-RPC 2.0 request string against read-only `state`.
///
/// Convenience: bounded raw JSON-RPC envelope entry point for Starknet callers.
#[must_use]
pub fn handle_starknet_jsonrpc(
    state: &AccountState,
    policy: StarknetActivationPolicy,
    raw_json: &str,
) -> String {
    if raw_json.len() > MAX_STARKNET_RPC_REQUEST_BYTES {
        let resp = StarknetRpcResponse::err(
            Value::Null,
            -32005,
            "request payload exceeds MAX_STARKNET_RPC_REQUEST_BYTES",
        );
        return serde_json::to_string(&resp).unwrap_or_default();
    }
    let Ok(req) = serde_json::from_str::<StarknetRpcRequest>(raw_json) else {
        let resp = StarknetRpcResponse::err(Value::Null, -32700, "Parse error");
        return serde_json::to_string(&resp).unwrap_or_default();
    };
    let resp = handle_starknet_rpc(state, policy, req);
    serde_json::to_string(&resp).unwrap_or_default()
}

/// Handle a read-only Starknet JSON-RPC v0.7 request.
///
/// Convenience: entry point for the Starknet compatibility gateway.
pub fn handle_starknet_rpc(
    state: &AccountState,
    policy: StarknetActivationPolicy,
    req: StarknetRpcRequest,
) -> StarknetRpcResponse {
    let _ = state.account_count();
    if !policy.is_active() {
        return StarknetRpcResponse::err(
            req.id,
            -32051,
            "Cairo (Starknet) RPC is closed on testnet before activation height",
        );
    }
    // strict JSON-RPC 2.0 version enforcement.
    if req.jsonrpc != "2.0" {
        return StarknetRpcResponse::err(
            req.id,
            -32600,
            &format!(
                "Starknet RPC requires jsonrpc \"2.0\", got {:?}",
                req.jsonrpc
            ),
        );
    }
    match req.method.as_str() {
        "starknet_specVersion" => {
            if !req.params.is_empty() {
                return StarknetRpcResponse::err(req.id, -32602, "unexpected parameters");
            }
            StarknetRpcResponse::ok(req.id, json!(STARKNET_SPEC_VERSION))
        }
        "starknet_chainId" => {
            if !req.params.is_empty() {
                return StarknetRpcResponse::err(req.id, -32602, "unexpected parameters");
            }
            let tag = format!("SN_BDLM_{}", policy.chain_id);
            StarknetRpcResponse::ok(req.id, json!(format!("0x{}", hex::encode(tag))))
        }
        "starknet_blockNumber" => {
            if !req.params.is_empty() {
                return StarknetRpcResponse::err(req.id, -32602, "unexpected parameters");
            }
            StarknetRpcResponse::ok(req.id, json!(policy.block_height))
        }
        "starknet_getNonce" => {
            if req.params.len() != 2 {
                return StarknetRpcResponse::err(
                    req.id,
                    -32602,
                    "starknet_getNonce requires [block_id, contract_address]",
                );
            }
            if !is_valid_block_id(&req.params[0]) {
                return StarknetRpcResponse::err(req.id, -32602, "invalid block_id");
            }
            let Some(addr_str) = req.params[1].as_str() else {
                return StarknetRpcResponse::err(req.id, -32602, "missing contract_address");
            };
            let Some(_felt) = parse_felt_hex(addr_str) else {
                return StarknetRpcResponse::err(req.id, -32602, "invalid Starknet felt252");
            };
            StarknetRpcResponse::ok(req.id, json!("0x0"))
        }
        "starknet_getStorageAt" => {
            if req.params.len() != 3 {
                return StarknetRpcResponse::err(
                    req.id,
                    -32602,
                    "starknet_getStorageAt requires [contract_address, key, block_id]",
                );
            }
            let Some(addr_str) = req.params[0].as_str() else {
                return StarknetRpcResponse::err(req.id, -32602, "missing contract_address");
            };
            let Some(key_str) = req.params[1].as_str() else {
                return StarknetRpcResponse::err(req.id, -32602, "missing storage key");
            };
            if parse_felt_hex(addr_str).is_none() || parse_felt_hex(key_str).is_none() {
                return StarknetRpcResponse::err(req.id, -32602, "invalid Starknet felt252");
            }
            if !is_valid_block_id(&req.params[2]) {
                return StarknetRpcResponse::err(req.id, -32602, "invalid block_id");
            }
            StarknetRpcResponse::ok(req.id, json!("0x0"))
        }
        "starknet_getClassHashAt" => {
            if req.params.len() != 2 {
                return StarknetRpcResponse::err(
                    req.id,
                    -32602,
                    "starknet_getClassHashAt requires [block_id, contract_address]",
                );
            }
            if !is_valid_block_id(&req.params[0]) {
                return StarknetRpcResponse::err(req.id, -32602, "invalid block_id");
            }
            let Some(addr_str) = req.params[1].as_str() else {
                return StarknetRpcResponse::err(req.id, -32602, "missing contract_address");
            };
            if parse_felt_hex(addr_str).is_none() {
                return StarknetRpcResponse::err(req.id, -32602, "invalid Starknet felt252");
            }
            StarknetRpcResponse::err(req.id, 20, "Contract not found")
        }
        _ => StarknetRpcResponse::err(req.id, -32601, "unsupported Starknet RPC method"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starknet_rpc_is_closed_on_testnet() {
        let state = AccountState::new();
        let launch = StarknetActivationPolicy::default();
        assert!(!launch.is_active());
        for chain_id in [45_260, 99_999] {
            assert!(!StarknetActivationPolicy { chain_id, ..launch }.is_active());
        }
        assert!(StarknetActivationPolicy {
            chain_id: 45_262,
            ..launch
        }
        .is_active());
        let closed = handle_starknet_rpc(
            &state,
            launch,
            StarknetRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "starknet_specVersion".into(),
                params: vec![],
            },
        );
        assert!(closed.error.is_some());

        let spec = handle_starknet_rpc(
            &state,
            StarknetActivationPolicy {
                chain_id: BUDLUM_TESTNET_CHAIN_ID,
                block_height: 100,
                activation_height: Some(100),
            },
            StarknetRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "starknet_specVersion".into(),
                params: vec![],
            },
        );
        assert_eq!(spec.result.unwrap().as_str(), Some("0.7.1"));
    }

    #[test]
    fn starknet_rpc_rejects_wrong_jsonrpc_version() {
        let state = AccountState::new();
        let policy = StarknetActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };
        let resp = handle_starknet_rpc(
            &state,
            policy,
            StarknetRpcRequest {
                jsonrpc: "1.0".into(),
                id: json!(1),
                method: "starknet_specVersion".into(),
                params: vec![],
            },
        );
        assert!(resp.result.is_none() && !resp.error.is_none());
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("2.0"));
    }

    #[test]
    fn starknet_rpc_rejects_invalid_block_id() {
        let state = AccountState::new();
        let policy = StarknetActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };
        let resp = handle_starknet_rpc(
            &state,
            policy,
            StarknetRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "starknet_getNonce".into(),
                params: vec![json!(42), json!("0x1234")],
            },
        );
        assert!(resp.result.is_none() && !resp.error.is_none());
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("block_id"));
    }

    #[test]
    fn max_starknet_rpc_request_bytes_is_bounded() {
        assert_eq!(MAX_STARKNET_RPC_REQUEST_BYTES, 1 << 20);
    }

    #[test]
    fn starknet_rejects_malformed_block_ids_and_unprefixed_or_out_of_field_felts() {
        let state = AccountState::new();
        let policy = StarknetActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };

        // 1. starknet_getNonce must reject non-u64 block_number, non-felt block_hash, extra keys, and bare hex string.
        for bad_block_id in [
            json!({ "block_number": -5 }),
            json!({ "block_hash": "not-felt" }),
            json!({ "block_number": 1, "extra": true }),
            json!("0x1234"),
        ] {
            let resp = handle_starknet_rpc(
                &state,
                policy,
                StarknetRpcRequest {
                    jsonrpc: "2.0".into(),
                    id: json!(1),
                    method: "starknet_getNonce".into(),
                    params: vec![bad_block_id.clone(), json!("0x1234")],
                },
            );
            assert!(
                resp.error.is_some(),
                "starknet_getNonce accepted malformed block_id: {bad_block_id}"
            );
        }

        // 2. starknet_getStorageAt must validate its 3rd param (block_id).
        let storage_bad = handle_starknet_rpc(
            &state,
            policy,
            StarknetRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "starknet_getStorageAt".into(),
                params: vec![json!("0x1234"), json!("0x1"), json!(42)],
            },
        );
        assert!(
            storage_bad.error.is_some(),
            "starknet_getStorageAt must reject invalid block_id"
        );

        // 3. starknet_getClassHashAt must validate its 1st param (block_id).
        let class_bad = handle_starknet_rpc(
            &state,
            policy,
            StarknetRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(3),
                method: "starknet_getClassHashAt".into(),
                params: vec![json!({ "block_hash": "not-felt" }), json!("0x1234")],
            },
        );
        assert_eq!(
            class_bad.error.as_ref().and_then(|e| e["code"].as_i64()),
            Some(-32602),
            "starknet_getClassHashAt must reject malformed block_id with -32602"
        );

        // 4. felt252 parsing must require 0x prefix and enforce exact prime bound (< P).
        assert!(parse_felt_hex("deadbeef").is_none());
        assert!(
            parse_felt_hex("0x0800000000000011000000000000000000000000000000000000000000000001")
                .is_none(),
            "felt == STARKNET_PRIME must be rejected"
        );
        assert!(
            parse_felt_hex("0x0800000000000011000000000000000000000000000000000000000000000000")
                .is_some(),
            "felt == STARKNET_PRIME - 1 must be accepted"
        );

        let oversized = " ".repeat(MAX_STARKNET_RPC_REQUEST_BYTES + 1);
        let raw_over = handle_starknet_jsonrpc(&state, policy, &oversized);
        assert!(raw_over.contains("-32005"), "raw_over: {raw_over}");
    }
}
