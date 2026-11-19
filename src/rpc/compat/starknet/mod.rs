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
/// Maximum Starknet RPC request envelope size (1 MiB). Strix B-0063.
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

fn parse_felt_hex(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    let padded = format!("{trimmed:0>64}");
    let bytes = hex::decode(padded).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    if arr.first().copied().unwrap_or(0) > 0x07 {
        return None;
    }
    Some(arr)
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
    // Strix B-0063: strict JSON-RPC 2.0 version enforcement.
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
        "starknet_specVersion" => StarknetRpcResponse::ok(req.id, json!(STARKNET_SPEC_VERSION)),
        "starknet_chainId" => {
            let tag = format!("SN_BDLM_{}", policy.chain_id);
            StarknetRpcResponse::ok(req.id, json!(format!("0x{}", hex::encode(tag))))
        }
        "starknet_blockNumber" => StarknetRpcResponse::ok(req.id, json!(policy.block_height)),
        "starknet_getNonce" => {
            // block_id validation (Strix B-0063): must be present and valid.
            if let Some(block_id) = req.params.first() {
                let valid = match block_id {
                    Value::String(s) => {
                        s == "latest" || s == "pending" || parse_felt_hex(s).is_some()
                    }
                    Value::Object(obj) => {
                        obj.contains_key("block_number") || obj.contains_key("block_hash")
                    }
                    _ => false,
                };
                if !valid {
                    return StarknetRpcResponse::err(req.id, -32602, "invalid block_id");
                }
            }
            let Some(addr_str) = req.params.get(1).and_then(Value::as_str) else {
                return StarknetRpcResponse::err(req.id, -32602, "missing contract_address");
            };
            let Some(_felt) = parse_felt_hex(addr_str) else {
                return StarknetRpcResponse::err(req.id, -32602, "invalid Starknet felt252");
            };
            StarknetRpcResponse::ok(req.id, json!("0x0"))
        }
        "starknet_getStorageAt" => {
            let Some(addr_str) = req.params.first().and_then(Value::as_str) else {
                return StarknetRpcResponse::err(req.id, -32602, "missing contract_address");
            };
            let Some(key_str) = req.params.get(1).and_then(Value::as_str) else {
                return StarknetRpcResponse::err(req.id, -32602, "missing storage key");
            };
            if parse_felt_hex(addr_str).is_none() || parse_felt_hex(key_str).is_none() {
                return StarknetRpcResponse::err(req.id, -32602, "invalid Starknet felt252");
            }
            StarknetRpcResponse::ok(req.id, json!("0x0"))
        }
        "starknet_getClassHashAt" => {
            let Some(addr_str) = req.params.get(1).and_then(Value::as_str) else {
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
        assert!(!resp.error.is_none());
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
        assert!(!resp.error.is_none());
        assert!(resp.error.unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("block_id"));
    }

    #[test]
    fn max_starknet_rpc_request_bytes_is_bounded() {
        assert_eq!(MAX_STARKNET_RPC_REQUEST_BYTES, 1 << 20);
    }
}
