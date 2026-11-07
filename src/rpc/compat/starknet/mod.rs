//! Starknet JSON-RPC read-subset gateway (`127.0.0.1:18553`, `WP-51`).
//!
//! WIRING: unwired - staged for post-launch T-Expansion Cairo/Starknet activation (WP-51).

use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, JsonRpcRequest, JsonRpcResponse,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_TX_REJECTED,
};

/// Method classification table for the Starknet JSON-RPC read gateway.
pub const STARKNET_COMPAT_METHODS: &[CompatMethodClass] = &[
    CompatMethodClass::new("starknet_chainId", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new("starknet_blockNumber", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new("starknet_getStorageAt", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new("starknet_getClassHashAt", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new(
        "starknet_addInvokeTransaction",
        CompatListener::Public,
        CompatEffect::Refused,
    ),
];

/// Handles a read-only Starknet JSON-RPC request against finalized execution state.
///
/// WIRING: exposed for post-launch T-Expansion activation.
#[must_use]
pub fn handle_starknet_rpc(req: &JsonRpcRequest, finalized_height: u64) -> JsonRpcResponse {
    match req.method.as_str() {
        "starknet_chainId" => {
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!("0x42444c4d5f534e"))
        }
        "starknet_blockNumber" => {
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!(finalized_height))
        }
        "starknet_getStorageAt" | "starknet_getClassHashAt" => {
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!("0x0"))
        }
        "starknet_addInvokeTransaction" => JsonRpcResponse::err(
            req.id.clone(),
            JSONRPC_TX_REJECTED,
            "Cairo execution environment is height-gated closed on public testnet",
        ),
        _ => JsonRpcResponse::err(
            req.id.clone(),
            JSONRPC_METHOD_NOT_FOUND,
            "unsupported Starknet JSON-RPC method",
        ),
    }
}
