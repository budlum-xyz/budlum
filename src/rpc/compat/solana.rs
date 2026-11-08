//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`,  & section 8.11.3).

use crate::core::account::AccountState;
use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, JsonRpcRequest, JsonRpcResponse,
    SolanaCompatConfig, JSONRPC_METHOD_NOT_FOUND, JSONRPC_TX_REJECTED,
};

const SOLANA_UNAVAILABLE: i32 = -32004;

const fn row(name: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass::new(name, CompatListener::Public, effect)
}

/// Complete Solana JSON-RPC method table (section 8.11.3: 25 HTTP + 5 WebSocket).
pub const SOLANA_METHOD_CLASSES: &[CompatMethodClass] = &[
    row("getHealth", CompatEffect::Read),
    row("getVersion", CompatEffect::Read),
    row("getGenesisHash", CompatEffect::Refused),
    row("getSlot", CompatEffect::Read),
    row("getBlockHeight", CompatEffect::Read),
    row("getEpochInfo", CompatEffect::Refused),
    row("getLatestBlockhash", CompatEffect::Refused),
    row("isBlockhashValid", CompatEffect::Refused),
    row("getBalance", CompatEffect::Refused),
    row("getAccountInfo", CompatEffect::Refused),
    row("getMultipleAccounts", CompatEffect::Refused),
    row("getProgramAccounts", CompatEffect::Refused),
    row("getTokenAccountsByOwner", CompatEffect::Refused),
    row("getTokenAccountBalance", CompatEffect::Refused),
    row("getTokenSupply", CompatEffect::Refused),
    row("getMinimumBalanceForRentExemption", CompatEffect::Refused),
    row("getFeeForMessage", CompatEffect::Refused),
    row("getRecentPrioritizationFees", CompatEffect::Refused),
    row("sendTransaction", CompatEffect::Refused),
    row("simulateTransaction", CompatEffect::Refused),
    row("getSignatureStatuses", CompatEffect::Refused),
    row("getSignaturesForAddress", CompatEffect::Refused),
    row("getTransaction", CompatEffect::Refused),
    row("getBlock", CompatEffect::Refused),
    row("requestAirdrop", CompatEffect::Refused),
    row("accountSubscribe", CompatEffect::Refused),
    row("signatureSubscribe", CompatEffect::Refused),
    row("slotSubscribe", CompatEffect::Refused),
    row("logsSubscribe", CompatEffect::Refused),
    row("programSubscribe", CompatEffect::Refused),
    row("accountUnsubscribe", CompatEffect::Refused),
    row("signatureUnsubscribe", CompatEffect::Refused),
    row("slotUnsubscribe", CompatEffect::Refused),
    row("logsUnsubscribe", CompatEffect::Refused),
    row("programUnsubscribe", CompatEffect::Refused),
];

/// Solana JSON-RPC gateway adapter (`state` is read-only).
#[derive(Debug, Clone)]
pub struct SolanaCompatGateway {
    config: SolanaCompatConfig,
    slot: u64,
}

impl SolanaCompatGateway {
    #[must_use]
    pub fn new(config: SolanaCompatConfig, slot: u64, _latest_blockhash: [u8; 32]) -> Self {
        Self { config, slot }
    }

    pub fn handle_request(
        &mut self,
        req: &JsonRpcRequest,
        _state: &AccountState,
    ) -> JsonRpcResponse {
        let id = req.id.clone();
        if !SOLANA_METHOD_CLASSES.iter().any(|m| m.name == req.method) {
            return JsonRpcResponse::err(id, JSONRPC_METHOD_NOT_FOUND, "Method not found");
        }
        match req.method.as_str() {
            "getHealth" => JsonRpcResponse::ok(id, serde_json::json!("ok")),
            "getVersion" => {
                JsonRpcResponse::ok(id, serde_json::json!({ "solana-core": "2.0.0-budlum" }))
            }
            "getSlot" | "getBlockHeight" => JsonRpcResponse::ok(id, serde_json::json!(self.slot)),
            "requestAirdrop" => {
                if !self.config.testnet_faucet_enabled {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_TX_REJECTED,
                        "requestAirdrop is disabled outside testnet faucet mode",
                    );
                }
                JsonRpcResponse::err(
                    id,
                    JSONRPC_TX_REJECTED,
                    "requestAirdrop is not wired to the faucet; no grant was queued",
                )
            }
            method => JsonRpcResponse::err(
                id,
                SOLANA_UNAVAILABLE,
                format!(
                    "{method}: no production Solana implementation; no data was invented and no request was submitted"
                ),
            ),
        }
    }
}

/// Evaluates a raw Solana JSON-RPC 2.0 request string against read-only `state` (`18548`).
///
/// exposed for: wire-level Solana JSON-RPC handler.
#[must_use]
pub fn handle_solana_jsonrpc(state: &AccountState, raw_json: &str) -> String {
    if raw_json.len() > crate::rpc::compat::ethereum::MAX_COMPAT_REQUEST_BYTES {
        let resp = JsonRpcResponse::err(
            serde_json::Value::Null,
            crate::rpc::compat::JSONRPC_LIMIT_EXCEEDED,
            "request payload exceeds MAX_COMPAT_REQUEST_BYTES",
        );
        return serde_json::to_string(&resp).unwrap_or_default();
    }
    let Ok(req) = serde_json::from_str::<JsonRpcRequest>(raw_json) else {
        let resp = JsonRpcResponse::err(serde_json::Value::Null, -32700, "Parse error");
        return serde_json::to_string(&resp).unwrap_or_default();
    };
    let mut gw = SolanaCompatGateway::new(SolanaCompatConfig::default(), 0, [0u8; 32]);
    let resp = gw.handle_request(&req, state);
    serde_json::to_string(&resp).unwrap_or_default()
}
