//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`,  & section 8.11.3).

use crate::core::account::AccountState;
use crate::execution::coordinator::alias::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::foreign::solana::{
    decode_solana_base58, decode_solana_base64, decode_solana_tx, encode_solana_base58,
};
use crate::execution::coordinator::foreign::{ForeignTx, VerifiedForeignOutcome};
use crate::execution::coordinator::state::NS_SVM_ACCOUNT;
use crate::execution::coordinator::svm_ee::ATTOS_PER_LAMPORT;
use crate::execution::coordinator::ExecutionCoordinator;
use crate::rpc::compat::{
    CompatEffect, CompatListener, CompatMethodClass, JsonRpcRequest, JsonRpcResponse,
    SolanaCompatConfig, JSONRPC_INVALID_PARAMS, JSONRPC_LIMIT_EXCEEDED, JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_TX_REJECTED,
};

const fn row(name: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass::new(name, CompatListener::Public, effect)
}

/// Complete Solana JSON-RPC method table (section 8.11.3: 25 HTTP + 5 WebSocket).
pub const SOLANA_METHOD_CLASSES: &[CompatMethodClass] = &[
    row("getHealth", CompatEffect::Read),
    row("getVersion", CompatEffect::Read),
    row("getGenesisHash", CompatEffect::Read),
    row("getSlot", CompatEffect::Read),
    row("getBlockHeight", CompatEffect::Read),
    row("getEpochInfo", CompatEffect::Read),
    row("getLatestBlockhash", CompatEffect::Read),
    row("isBlockhashValid", CompatEffect::Read),
    row("getBalance", CompatEffect::Read),
    row("getAccountInfo", CompatEffect::Read),
    row("getMultipleAccounts", CompatEffect::Read),
    row("getProgramAccounts", CompatEffect::Read),
    row("getTokenAccountsByOwner", CompatEffect::Read),
    row("getTokenAccountBalance", CompatEffect::Read),
    row("getTokenSupply", CompatEffect::Read),
    row("getMinimumBalanceForRentExemption", CompatEffect::Read),
    row("getFeeForMessage", CompatEffect::Read),
    row("getRecentPrioritizationFees", CompatEffect::Read),
    row("sendTransaction", CompatEffect::TxSubmit),
    row("simulateTransaction", CompatEffect::Read),
    row("getSignatureStatuses", CompatEffect::Read),
    row("getSignaturesForAddress", CompatEffect::Read),
    row("getTransaction", CompatEffect::Read),
    row("getBlock", CompatEffect::Read),
    row("requestAirdrop", CompatEffect::TxSubmit),
    row("accountSubscribe", CompatEffect::LocalFilter),
    row("signatureSubscribe", CompatEffect::LocalFilter),
    row("slotSubscribe", CompatEffect::LocalFilter),
    row("logsSubscribe", CompatEffect::LocalFilter),
    row("programSubscribe", CompatEffect::LocalFilter),
    row("accountUnsubscribe", CompatEffect::LocalFilter),
    row("signatureUnsubscribe", CompatEffect::LocalFilter),
    row("slotUnsubscribe", CompatEffect::LocalFilter),
    row("logsUnsubscribe", CompatEffect::LocalFilter),
    row("programUnsubscribe", CompatEffect::LocalFilter),
];

/// Solana JSON-RPC gateway adapter (`state` is read-only).
#[derive(Debug, Clone)]
pub struct SolanaCompatGateway {
    config: SolanaCompatConfig,
    slot: u64,
    latest_blockhash: [u8; 32],
}

impl SolanaCompatGateway {
    #[must_use]
    pub fn new(config: SolanaCompatConfig, slot: u64, latest_blockhash: [u8; 32]) -> Self {
        Self {
            config,
            slot,
            latest_blockhash,
        }
    }

    pub fn handle_request(
        &mut self,
        req: &JsonRpcRequest,
        state: &AccountState,
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
            "getGenesisHash" => {
                JsonRpcResponse::ok(id, serde_json::json!(encode_solana_base58(&[0xBDu8; 32])))
            }
            "getSlot" | "getBlockHeight" => JsonRpcResponse::ok(id, serde_json::json!(self.slot)),
            "getEpochInfo" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "epoch": 0,
                    "absoluteSlot": self.slot,
                    "slotIndex": self.slot,
                }),
            ),
            "getLatestBlockhash" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "value": {
                        "blockhash": encode_solana_base58(&self.latest_blockhash),
                        "lastValidBlockHeight": self.slot + 150,
                    }
                }),
            ),
            "isBlockhashValid" => {
                let valid = parse_pubkey(&req.params, 0)
                    .is_some_and(|blockhash| blockhash == self.latest_blockhash);
                JsonRpcResponse::ok(id, serde_json::json!({ "value": valid }))
            }
            "getBalance" => {
                let Some(pk32) = parse_pubkey(&req.params, 0) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "invalid Solana pubkey");
                };
                let bud_addr = derive_foreign_account(ForeignScheme::SolanaEd25519, &pk32);
                let lamports = state.get_attos_balance(&bud_addr) / ATTOS_PER_LAMPORT;
                JsonRpcResponse::ok(id, serde_json::json!({ "value": lamports }))
            }
            "getAccountInfo" => {
                let Some(pk32) = parse_pubkey(&req.params, 0) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "invalid Solana pubkey");
                };
                let data = state
                    .execution_state
                    .read(NS_SVM_ACCOUNT, &pk32)
                    .ok()
                    .flatten();
                JsonRpcResponse::ok(id, serde_json::json!({ "value": data.map(hex::encode) }))
            }
            "getProgramAccounts" => {
                let req_limit = req
                    .params
                    .get(1)
                    .and_then(|o| o.get("limit"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize;
                if req_limit > self.config.max_program_accounts {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_LIMIT_EXCEEDED,
                        "exceeds max_program_accounts",
                    );
                }
                JsonRpcResponse::ok(id, serde_json::json!([]))
            }
            "sendTransaction" => {
                let Some(encoded) = req.params.get(0).and_then(serde_json::Value::as_str) else {
                    return JsonRpcResponse::err(id, JSONRPC_INVALID_PARAMS, "missing transaction");
                };
                let Some(raw_wire) = parse_transaction_bytes(encoded) else {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "transaction is neither canonical base64 nor legacy hex",
                    );
                };
                let mut preview = state.clone();
                if !preview
                    .execution_state
                    .foreign_lane
                    .recent_blockhashes
                    .contains(&self.latest_blockhash)
                {
                    preview
                        .execution_state
                        .foreign_lane
                        .recent_blockhashes
                        .push_back(self.latest_blockhash);
                }
                let mut coord = ExecutionCoordinator::new();
                let env = ForeignTx::Solana {
                    raw_wire,
                    direct_native_pq_recipient: None,
                };
                match coord.process_foreign_envelope(&mut preview, &env, 0) {
                    Ok(VerifiedForeignOutcome::Solana { decoded, .. }) => {
                        JsonRpcResponse::ok(
                            id,
                            serde_json::json!(encode_solana_base58(&decoded.fee_payer_signature)),
                        )
                    }
                    Ok(_) => JsonRpcResponse::err(id, JSONRPC_TX_REJECTED, "unexpected tx kind"),
                    Err(e) => JsonRpcResponse::err(id, JSONRPC_TX_REJECTED, e.to_string()),
                }
            }
            "requestAirdrop" => {
                if !self.config.testnet_faucet_enabled {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_TX_REJECTED,
                        "requestAirdrop is disabled outside testnet faucet mode",
                    );
                }
                JsonRpcResponse::ok(id, serde_json::json!("airdrop_queued"))
            }
            _ => JsonRpcResponse::ok(id, serde_json::json!({})),
        }
    }
}

fn parse_pubkey(params: &serde_json::Value, idx: usize) -> Option<[u8; 32]> {
    let text = params.get(idx)?.as_str()?;
    if let Ok(key) = decode_solana_base58::<32>(text) {
        if encode_solana_base58(&key) == text {
            return Some(key);
        }
    }
    let bytes = hex::decode(text.trim_start_matches("0x")).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn parse_transaction_bytes(text: &str) -> Option<Vec<u8>> {
    if let Some(explicit_hex) = text.strip_prefix("0x") {
        return hex::decode(explicit_hex).ok();
    }

    let base64 = decode_solana_base64(text).ok();
    let looks_like_legacy_hex = !text.is_empty()
        && text.len() % 2 == 0
        && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    if looks_like_legacy_hex {
        if let Some(wire) = base64.as_ref().filter(|wire| decode_solana_tx(wire).is_ok()) {
            return Some(wire.clone());
        }
        return hex::decode(text).ok();
    }
    base64
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
