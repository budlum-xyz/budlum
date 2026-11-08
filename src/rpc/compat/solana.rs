//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`,  & section 8.11.3).

use crate::core::account::AccountState;
use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, JsonRpcRequest, JsonRpcResponse,
    SolanaCompatConfig, JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND, JSONRPC_TX_REJECTED,
};

pub mod subscriptions;
#[cfg(test)]
mod tests;

pub const SOLANA_UNAVAILABLE: i32 = -32004;

/// Native read or submission door named by a Solana refusal.
#[must_use]
pub fn native_door(method: &str) -> Option<&'static str> {
    Some(match method {
        "getGenesisHash" | "getLatestBlockhash" | "isBlockhashValid" | "getBlock" => "bud_getBlockByNumber",
        "getEpochInfo" | "getTokenSupply" | "getMinimumBalanceForRentExemption" => "bud_getStatus",
        "getBalance" | "getTokenAccountBalance" => "bud_getBalance",
        "getAccountInfo" | "getMultipleAccounts" | "getProgramAccounts"
        | "getTokenAccountsByOwner" | "accountSubscribe" | "programSubscribe" => "bud_getAccountProof",
        "getFeeForMessage" | "getRecentPrioritizationFees" => "bud_gasPrice",
        "sendTransaction" | "requestAirdrop" => "bud_sendRawTransaction",
        "simulateTransaction" => "bud_txPrecheck",
        "getSignatureStatuses" | "signatureSubscribe" | "logsSubscribe" => "bud_getTransactionReceipt",
        "getSignaturesForAddress" | "getTransaction" => "bud_getTransactionByHash",
        _ => return None,
    })
}

#[must_use]
pub fn owns_method(name: &str) -> bool {
    SOLANA_METHOD_CLASSES.iter().any(|row| row.name == name) || name.starts_with("solana_")
}

#[must_use]
pub fn is_unsubscribe(name: &str) -> bool {
    matches!(
        name,
        "accountUnsubscribe"
            | "signatureUnsubscribe"
            | "slotUnsubscribe"
            | "logsUnsubscribe"
            | "programUnsubscribe"
    )
}

/// Copy only Solana callbacks onto the dedicated compatibility listener.
pub fn dedicated_methods(
    all: &jsonrpsee::core::server::Methods,
) -> Result<jsonrpsee::core::server::Methods, String> {
    let mut out = jsonrpsee::core::server::Methods::new();
    for name in all.method_names() {
        if !owns_method(name) {
            continue;
        }
        let callback = all
            .method(name)
            .ok_or_else(|| format!("Solana method {name} disappeared while filtering"))?
            .clone();
        out.verify_and_insert(name, callback)
            .map_err(|error| format!("register dedicated Solana method {name}: {error}"))?;
    }
    check_served(out.method_names())?;
    Ok(out)
}

/// Reject a Solana-prefixed method that has no classification row.
pub fn check_served<'a>(registered: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let problems: Vec<String> = registered
        .into_iter()
        .filter(|name| owns_method(name))
        .filter(|name| !SOLANA_METHOD_CLASSES.iter().any(|row| row.name == *name))
        .map(|name| format!("{name} has no Solana gateway row"))
        .collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[must_use]
pub fn ee_unavailable(
    method: &str,
    door: &'static str,
) -> jsonrpsee::types::error::ErrorObjectOwned {
    jsonrpsee::types::error::ErrorObjectOwned::owned(
        SOLANA_UNAVAILABLE,
        format!("{method}: production Solana state mapping is unavailable; use {door}"),
        Some(serde_json::json!({ "door": door })),
    )
}

#[must_use]
pub fn not_exposed(
    method: &str,
    door: &'static str,
) -> jsonrpsee::types::error::ErrorObjectOwned {
    jsonrpsee::types::error::ErrorObjectOwned::owned(
        SOLANA_UNAVAILABLE,
        format!("{method}: this chain fact is not exposed in Solana form; use {door}"),
        Some(serde_json::json!({ "door": door })),
    )
}

#[must_use]
pub fn faucet_unavailable(
    method: &str,
) -> jsonrpsee::types::error::ErrorObjectOwned {
    jsonrpsee::types::error::ErrorObjectOwned::owned(
        SOLANA_UNAVAILABLE,
        format!("{method}: no grant was queued; use the testnet faucet"),
        Some(serde_json::json!({ "door": "bud_sendRawTransaction" })),
    )
}

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
    row("accountUnsubscribe", CompatEffect::Read),
    row("signatureSubscribe", CompatEffect::Refused),
    row("signatureUnsubscribe", CompatEffect::Read),
    row("slotSubscribe", CompatEffect::Read),
    row("slotUnsubscribe", CompatEffect::Read),
    row("logsSubscribe", CompatEffect::Refused),
    row("logsUnsubscribe", CompatEffect::Read),
    row("programSubscribe", CompatEffect::Refused),
    row("programUnsubscribe", CompatEffect::Read),
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
            "getVersion" => JsonRpcResponse::ok(id, serde_json::json!({ "solana-core": format!("budlum-core/{}", env!("CARGO_PKG_VERSION")) })),
            "getSlot" | "getBlockHeight" => {
                let no_config = req.params.is_null()
                    || req.params.as_array().is_some_and(|params| {
                        params.is_empty()
                            || (params.len() == 1
                                && params[0].as_object().is_some_and(serde_json::Map::is_empty))
                    });
                if !no_config {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "the standalone adapter cannot honor a slot commitment config");
                }
                JsonRpcResponse::ok(id, serde_json::json!(self.slot))
            }
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
                    "{method}: no production Solana implementation; no data was invented and no request was submitted; use {}",
                    native_door(method).unwrap_or("bud_getStatus")
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
