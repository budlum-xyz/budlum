//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`,  & section 8.11.3).
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

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
        "getGenesisHash" | "getLatestBlockhash" | "isBlockhashValid" | "getBlock" => {
            "bud_getBlockByNumber"
        }
        "getEpochInfo" | "getTokenSupply" | "getMinimumBalanceForRentExemption" => "bud_getStatus",
        "getBalance" | "getTokenAccountBalance" => "bud_getBalance",
        "getAccountInfo"
        | "getMultipleAccounts"
        | "getProgramAccounts"
        | "getTokenAccountsByOwner"
        | "accountSubscribe"
        | "programSubscribe" => "bud_getAccountProof",
        "getFeeForMessage" | "getRecentPrioritizationFees" => "bud_gasPrice",
        "sendTransaction" | "requestAirdrop" => "bud_sendRawTransaction",
        "simulateTransaction" => "bud_txPrecheck",
        "getSignatureStatuses" | "signatureSubscribe" | "logsSubscribe" => {
            "bud_getTransactionReceipt"
        }
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
pub fn not_exposed(method: &str, door: &'static str) -> jsonrpsee::types::error::ErrorObjectOwned {
    jsonrpsee::types::error::ErrorObjectOwned::owned(
        SOLANA_UNAVAILABLE,
        format!("{method}: this chain fact is not exposed in Solana form; use {door}"),
        Some(serde_json::json!({ "door": door })),
    )
}

#[must_use]
pub fn faucet_unavailable(method: &str) -> jsonrpsee::types::error::ErrorObjectOwned {
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
    latest_blockhash: [u8; 32],
    lane_pool: crate::mempool::lanes::MultiLaneMempool,
}

fn decode_variable_base58(text: &str, max_bytes: usize) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if text.is_empty() {
        return Err("empty base58 transaction");
    }
    if text.len() > max_bytes.saturating_mul(2).saturating_add(2) {
        return Err("base58 transaction exceeds packet-size encoding bound");
    }
    let input = text.as_bytes();
    let zeros = input.iter().take_while(|byte| **byte == b'1').count();
    if zeros > max_bytes {
        return Err("base58 transaction exceeds maximum byte length");
    }
    let mut digits = Vec::<u8>::new();
    for &byte in input.get(zeros..).unwrap_or(&[]) {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("character outside the Solana base58 alphabet")? as u32;
        let mut carry = digit;
        for value in &mut digits {
            carry += u32::from(*value) * 58;
            *value = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry != 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
        if zeros.saturating_add(digits.len()) > max_bytes {
            return Err("base58 transaction exceeds maximum byte length");
        }
    }
    let mut out = Vec::with_capacity(zeros.saturating_add(digits.len()));
    out.resize(zeros, 0u8);
    out.extend(digits.iter().rev().copied());
    Ok(out)
}

impl SolanaCompatGateway {
    #[must_use]
    pub fn new(config: SolanaCompatConfig, slot: u64, latest_blockhash: [u8; 32]) -> Self {
        let mut lane_pool = crate::mempool::lanes::MultiLaneMempool::new(1024, 4 * 1024 * 1024);
        if latest_blockhash != [0u8; 32] {
            lane_pool.push_recent_blockhash(latest_blockhash);
        }
        Self {
            config,
            slot,
            latest_blockhash,
            lane_pool,
        }
    }

    pub fn handle_request(
        &mut self,
        req: &JsonRpcRequest,
        _state: &AccountState,
    ) -> JsonRpcResponse {
        let id = req.id.clone();
        if req.jsonrpc != "2.0" {
            return JsonRpcResponse::err(
                id,
                -32600,
                format!("Solana RPC requires jsonrpc \"2.0\", got {:?}", req.jsonrpc),
            );
        }
        if !SOLANA_METHOD_CLASSES.iter().any(|m| m.name == req.method) {
            return JsonRpcResponse::err(id, JSONRPC_METHOD_NOT_FOUND, "Method not found");
        }
        match req.method.as_str() {
            "getHealth" => JsonRpcResponse::ok(id, serde_json::json!("ok")),
            "getVersion" => JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "solana-core": format!("budlum-core/{}", env!("CARGO_PKG_VERSION"))
                }),
            ),
            "getSlot" | "getBlockHeight" => {
                let no_config = req.params.is_null()
                    || req.params.as_array().is_some_and(|params| {
                        params.is_empty()
                            || (params.len() == 1
                                && params[0].as_object().is_some_and(serde_json::Map::is_empty))
                    });
                if !no_config {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "the standalone adapter cannot honor a slot commitment config",
                    );
                }
                JsonRpcResponse::ok(id, serde_json::json!(self.slot))
            }
            "sendTransaction" => {
                if !self.config.enabled {
                    let door = native_door("sendTransaction").unwrap_or("bud_sendRawTransaction");
                    return JsonRpcResponse::err(
                        id,
                        SOLANA_UNAVAILABLE,
                        format!(
                            "sendTransaction: no production Solana implementation; \
                             no data was invented and no request was submitted; use {door}"
                        ),
                    );
                }
                let Some(params) = req.params.as_array() else {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "sendTransaction params must be an array",
                    );
                };
                if params.is_empty() || params.len() > 2 {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "sendTransaction expects 1 or 2 parameters",
                    );
                }
                let Some(raw_str) = params.first().and_then(serde_json::Value::as_str) else {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "sendTransaction requires a base58 or base64 wire transaction string",
                    );
                };
                let use_base64 = match params.get(1) {
                    None | Some(serde_json::Value::Null) => false,
                    Some(serde_json::Value::Object(cfg)) => match cfg.get("encoding") {
                        None | Some(serde_json::Value::Null) => false,
                        Some(serde_json::Value::String(enc)) if enc == "base58" => false,
                        Some(serde_json::Value::String(enc)) if enc == "base64" => true,
                        Some(_) => {
                            return JsonRpcResponse::err(
                                id,
                                JSONRPC_INVALID_PARAMS,
                                "sendTransaction encoding must be \"base58\" or \"base64\"",
                            );
                        }
                    },
                    Some(_) => {
                        return JsonRpcResponse::err(
                            id,
                            JSONRPC_INVALID_PARAMS,
                            "sendTransaction config parameter must be an object",
                        );
                    }
                };
                let wire_res = if use_base64 {
                    crate::execution::coordinator::foreign::solana::decode_solana_base64(raw_str)
                } else {
                    decode_variable_base58(
                        raw_str,
                        crate::execution::coordinator::foreign::solana::MAX_SOLANA_TRANSACTION_BYTES,
                    )
                };
                let Ok(wire) = wire_res else {
                    return JsonRpcResponse::err(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "invalid Solana wire encoding",
                    );
                };
                let _window = self.lane_pool.solana_blockhash_window();
                let _bh = self.latest_blockhash;
                match self
                    .lane_pool
                    .admit_foreign_solana(&wire, 200_000, 1_000, 100, self.slot)
                {
                    Ok(decoded) => {
                        let sig =
                            crate::execution::coordinator::foreign::solana::encode_solana_base58(
                                &decoded.fee_payer_signature,
                            );
                        if crate::execution::coordinator::foreign::solana::decode_solana_base58::<64>(
                            &sig,
                        )
                        .is_err()
                        {
                            return JsonRpcResponse::err(
                                id,
                                JSONRPC_TX_REJECTED,
                                "Solana signature encoding self-check failed",
                            );
                        }
                        JsonRpcResponse::ok(id, serde_json::json!(sig))
                    }
                    Err(err) => JsonRpcResponse::err(
                        id,
                        JSONRPC_TX_REJECTED,
                        format!("Solana lane admission refused: {err:?}"),
                    ),
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
                JsonRpcResponse::err(
                    id,
                    JSONRPC_TX_REJECTED,
                    "requestAirdrop is not wired to the faucet; no grant was queued",
                )
            }
            method => {
                let door = native_door(method).unwrap_or("bud_getStatus");
                JsonRpcResponse::err(
                    id,
                    SOLANA_UNAVAILABLE,
                    format!(
                        "{method}: no production Solana implementation; \
                         no data was invented and no request was submitted; use {door}"
                    ),
                )
            }
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

#[cfg(test)]
mod security_tests {
    use super::*;

    fn signed_solana_tx_bytes(blockhash: [u8; 32]) -> Vec<u8> {
        let ix = crate::execution::coordinator::foreign::solana::SolanaCompiledInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: vec![1, 2, 3, 4],
        };
        crate::execution::coordinator::foreign::solana::sign_solana_tx(
            &[0x42; 32],
            false,
            blockhash,
            &[[0x11; 32]],
            &[ix],
        )
    }

    #[test]
    fn send_transaction_rejects_unknown_encoding_instead_of_base58_fallback() {
        let state = AccountState::new();
        let mut gw = SolanaCompatGateway::new(
            SolanaCompatConfig {
                enabled: true,
                ..SolanaCompatConfig::default()
            },
            10,
            [0xAA; 32],
        );
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: "sendTransaction".to_string(),
            params: serde_json::json!(["1111", { "encoding": "base64+zstd" }]),
        };
        let resp = gw.handle_request(&req, &state);
        assert!(resp.result.is_none() && !resp.error.is_none());
        let err = resp.error.expect("unsupported encoding must fail");
        assert_eq!(err.code, JSONRPC_INVALID_PARAMS);
        assert!(
            err.message.contains("encoding"),
            "expected encoding error, got: {}",
            err.message
        );
    }

    #[test]
    fn send_transaction_accepts_variable_length_base58_wire_tx() {
        let state = AccountState::new();
        let bh = [0xAA; 32];
        let mut gw = SolanaCompatGateway::new(
            SolanaCompatConfig {
                enabled: true,
                ..SolanaCompatConfig::default()
            },
            10,
            bh,
        );
        let wire = signed_solana_tx_bytes(bh);
        assert_ne!(
            wire.len(),
            164,
            "wire length must test variable-length base58"
        );
        let b58 = crate::execution::coordinator::foreign::solana::encode_solana_base58(&wire);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(2),
            method: "sendTransaction".to_string(),
            params: serde_json::json!([b58]),
        };
        let resp = gw.handle_request(&req, &state);
        assert!(
            resp.error.is_none() && resp.result.is_some(),
            "variable-length base58 Solana tx ({} bytes) must succeed, got {:?}",
            wire.len(),
            resp.error
        );
    }

    #[test]
    fn solana_gateway_rejects_non_2_0_jsonrpc_version() {
        let state = AccountState::new();
        let mut gw = SolanaCompatGateway::new(SolanaCompatConfig::default(), 10, [0xAA; 32]);
        let req = JsonRpcRequest {
            jsonrpc: "1.0".to_string(),
            id: serde_json::json!(3),
            method: "getHealth".to_string(),
            params: serde_json::json!([]),
        };
        let resp = gw.handle_request(&req, &state);
        assert!(resp.result.is_none() && !resp.error.is_none());
        let err = resp.error.expect("jsonrpc 1.0 must be rejected");
        assert_eq!(err.code, -32600);

        let raw_resp = handle_solana_jsonrpc(
            &state,
            r#"{"jsonrpc":"1.0","id":4,"method":"getHealth","params":[]}"#,
        );
        assert!(raw_resp.contains("-32600"), "raw_resp: {raw_resp}");
    }
}
