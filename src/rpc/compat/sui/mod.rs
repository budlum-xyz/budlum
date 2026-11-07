//! Sui JSON-RPC read-subset gateway (`127.0.0.1:18552`, `WP-50`).
//!
//! WIRING: unwired - staged for post-launch T-Expansion Sui compatibility activation (WP-50).

use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, JsonRpcRequest, JsonRpcResponse,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_TX_REJECTED,
};

/// Method classification table for the Sui JSON-RPC read gateway.
pub const SUI_COMPAT_METHODS: &[CompatMethodClass] = &[
    CompatMethodClass::new("sui_getChainIdentifier", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new(
        "sui_getLatestCheckpointSequenceNumber",
        CompatListener::Public,
        CompatEffect::Read,
    ),
    CompatMethodClass::new("sui_getObject", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new("suix_getBalance", CompatListener::Public, CompatEffect::Read),
    CompatMethodClass::new(
        "sui_executeTransactionBlock",
        CompatListener::Public,
        CompatEffect::Refused,
    ),
];

/// Handles a read-only Sui JSON-RPC request against finalized execution state.
///
/// WIRING: exposed for post-launch T-Expansion activation.
#[must_use]
pub fn handle_sui_rpc(req: &JsonRpcRequest, finalized_height: u64) -> JsonRpcResponse {
    match req.method.as_str() {
        "sui_getChainIdentifier" => {
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!("budlum-sui-45261"))
        }
        "sui_getLatestCheckpointSequenceNumber" => {
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!(finalized_height.to_string()))
        }
        "sui_getObject" => JsonRpcResponse::ok(
            req.id.clone(),
            serde_json::json!({"data": null, "error": {"code": "notExists"}}),
        ),
        "suix_getBalance" => JsonRpcResponse::ok(
            req.id.clone(),
            serde_json::json!({"coinType": "0x2::sui::SUI", "totalBalance": "0"}),
        ),
        "sui_executeTransactionBlock" => JsonRpcResponse::err(
            req.id.clone(),
            JSONRPC_TX_REJECTED,
            "Move Sui execution environment is height-gated closed on public testnet",
        ),
        _ => JsonRpcResponse::err(
            req.id.clone(),
            JSONRPC_METHOD_NOT_FOUND,
            "unsupported Sui JSON-RPC method",
        ),
    }
}
