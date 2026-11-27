//! Sui JSON-RPC compatibility read & height-gated submission subset (
//! `Section 8.11`).
//!
//! Serves read-only Sui JSON-RPC methods (`sui_getChainIdentifier`,
//! `sui_getLatestCheckpointSequenceNumber`, `sui_getObject`, `suix_getBalance`,
//! `suix_getAllBalances`) against `AccountState` without mutating consensus state,
//! and enforces `Section 1.5` launch-closure on `45261` until activation.
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::account::AccountState;
use crate::execution::coordinator::alias::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::foreign::sui::{decode_and_recover_sui_tx, SuiActivationPolicy};

/// `1 MIST = 10^9 attoBUD`.
const ATTO_PER_MIST: u128 = 1_000_000_000;
/// Maximum Sui RPC request envelope size (1 MiB).
pub const MAX_SUI_RPC_REQUEST_BYTES: usize = 1 << 20;

/// Canonical Sui coin type string representing native BUD on Sui RPC.
///
/// Convenience: returned by `suix_getBalance` and `suix_getAllBalances`.
pub const SUI_BUD_COIN_TYPE: &str = "0x2::bud::BUD";

/// JSON-RPC 2.0 request envelope for Sui compatibility endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct SuiRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Vec<Value>,
}

/// JSON-RPC 2.0 response envelope for Sui compatibility endpoints.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SuiRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl SuiRpcResponse {
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

fn parse_sui_hex32(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.strip_prefix("0x")?;
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(trimmed).ok()?;
    bytes.as_slice().try_into().ok()
}

fn mist_balance_of(state: &AccountState, sui_addr: &[u8; 32]) -> u64 {
    let _ = EeId::MOVE_SUI;
    let addr = derive_foreign_account(ForeignScheme::SuiEd25519, sui_addr);
    let Some(acct) = state.accounts.get(&addr) else {
        return 0;
    };
    let attos = acct.checked_total_attos().unwrap_or(u128::MAX);
    u64::try_from(attos / ATTO_PER_MIST).unwrap_or(u64::MAX)
}

/// Evaluates a raw Sui JSON-RPC 2.0 request string against read-only `state`.
///
/// Convenience: bounded raw JSON-RPC envelope entry point for Sui callers.
#[must_use]
pub fn handle_sui_jsonrpc(
    state: &AccountState,
    policy: SuiActivationPolicy,
    raw_json: &str,
) -> String {
    if raw_json.len() > MAX_SUI_RPC_REQUEST_BYTES {
        let resp = SuiRpcResponse::err(
            Value::Null,
            -32005,
            "request payload exceeds MAX_SUI_RPC_REQUEST_BYTES",
        );
        return serde_json::to_string(&resp).unwrap_or_default();
    }
    let Ok(req) = serde_json::from_str::<SuiRpcRequest>(raw_json) else {
        let resp = SuiRpcResponse::err(Value::Null, -32700, "Parse error");
        return serde_json::to_string(&resp).unwrap_or_default();
    };
    let resp = handle_sui_rpc(state, policy, req);
    serde_json::to_string(&resp).unwrap_or_default()
}

/// Handle a read-only or height-gated Sui JSON-RPC 2.0 request.
///
/// Convenience: entry point for the Sui compatibility gateway.
pub fn handle_sui_rpc(
    state: &AccountState,
    policy: SuiActivationPolicy,
    req: SuiRpcRequest,
) -> SuiRpcResponse {
    if !policy.is_active() {
        return SuiRpcResponse::err(
            req.id,
            -32050,
            "Move (Sui) RPC is closed on testnet before activation height",
        );
    }
    // strict JSON-RPC 2.0 version enforcement.
    if req.jsonrpc != "2.0" {
        return SuiRpcResponse::err(
            req.id,
            -32600,
            &format!("Sui RPC requires jsonrpc \"2.0\", got {:?}", req.jsonrpc),
        );
    }
    match req.method.as_str() {
        "sui_getChainIdentifier" => {
            if !req.params.is_empty() {
                return SuiRpcResponse::err(req.id, -32602, "unexpected parameters");
            }
            SuiRpcResponse::ok(req.id, json!(format!("{:08x}", policy.chain_id)))
        }
        "sui_getLatestCheckpointSequenceNumber" => {
            if !req.params.is_empty() {
                return SuiRpcResponse::err(req.id, -32602, "unexpected parameters");
            }
            SuiRpcResponse::ok(req.id, json!(policy.block_height.to_string()))
        }
        "suix_getBalance" => {
            if req.params.is_empty() || req.params.len() > 2 {
                return SuiRpcResponse::err(
                    req.id,
                    -32602,
                    "suix_getBalance requires [owner, coinType?]",
                );
            }
            let Some(addr_str) = req.params[0].as_str() else {
                return SuiRpcResponse::err(req.id, -32602, "missing Sui address");
            };
            let Some(addr32) = parse_sui_hex32(addr_str) else {
                return SuiRpcResponse::err(req.id, -32602, "invalid 32-byte Sui hex address");
            };
            let coin_type = match req.params.get(1) {
                None | Some(Value::Null) => SUI_BUD_COIN_TYPE,
                Some(Value::String(ct)) if !ct.is_empty() => ct.as_str(),
                Some(_) => return SuiRpcResponse::err(req.id, -32602, "invalid coinType"),
            };
            if coin_type != SUI_BUD_COIN_TYPE {
                return SuiRpcResponse::ok(
                    req.id,
                    json!({
                        "coinType": coin_type,
                        "coinObjectCount": 0,
                        "totalBalance": "0",
                        "lockedBalance": {}
                    }),
                );
            }
            let mist = mist_balance_of(state, &addr32);
            SuiRpcResponse::ok(
                req.id,
                json!({
                    "coinType": SUI_BUD_COIN_TYPE,
                    "coinObjectCount": usize::from(mist > 0),
                    "totalBalance": mist.to_string(),
                    "lockedBalance": {}
                }),
            )
        }
        "suix_getAllBalances" => {
            if req.params.len() != 1 {
                return SuiRpcResponse::err(req.id, -32602, "suix_getAllBalances requires [owner]");
            }
            let Some(addr_str) = req.params[0].as_str() else {
                return SuiRpcResponse::err(req.id, -32602, "missing Sui address");
            };
            let Some(addr32) = parse_sui_hex32(addr_str) else {
                return SuiRpcResponse::err(req.id, -32602, "invalid 32-byte Sui hex address");
            };
            let mist = mist_balance_of(state, &addr32);
            SuiRpcResponse::ok(
                req.id,
                json!([{
                    "coinType": SUI_BUD_COIN_TYPE,
                    "coinObjectCount": usize::from(mist > 0),
                    "totalBalance": mist.to_string(),
                    "lockedBalance": {}
                }]),
            )
        }
        "sui_getObject" => {
            if req.params.len() != 1 {
                return SuiRpcResponse::err(req.id, -32602, "sui_getObject requires [object_id]");
            }
            let Some(id_str) = req.params[0].as_str() else {
                return SuiRpcResponse::err(req.id, -32602, "missing object_id");
            };
            let Some(_oid) = parse_sui_hex32(id_str) else {
                return SuiRpcResponse::err(req.id, -32602, "invalid 32-byte object_id");
            };
            SuiRpcResponse::ok(
                req.id,
                json!({
                    "data": null,
                    "error": { "code": "notExists", "object_id": id_str }
                }),
            )
        }
        "sui_executeTransactionBlock" => {
            if req.params.len() != 1 {
                return SuiRpcResponse::err(
                    req.id,
                    -32602,
                    "sui_executeTransactionBlock requires [hex_envelope]",
                );
            }
            let Some(hex_env) = req.params[0].as_str() else {
                return SuiRpcResponse::err(req.id, -32602, "missing hex envelope");
            };
            let trimmed_hex = hex_env.strip_prefix("0x").unwrap_or(hex_env);
            if trimmed_hex.len()
                > crate::execution::coordinator::foreign::sui::MAX_SUI_ENVELOPE_BYTES * 2
            {
                return SuiRpcResponse::err(req.id, -32602, "Sui envelope exceeds 256 KiB limit");
            }
            let Ok(raw) = hex::decode(trimmed_hex) else {
                return SuiRpcResponse::err(req.id, -32602, "invalid hex envelope");
            };
            match decode_and_recover_sui_tx(&raw, policy) {
                Ok(dec) => SuiRpcResponse::ok(
                    req.id,
                    json!({ "digest": format!("0x{}", hex::encode(dec.tx_digest)) }),
                ),
                Err(e) => SuiRpcResponse::err(req.id, -32002, &e.to_string()),
            }
        }
        _ => SuiRpcResponse::err(req.id, -32601, "unsupported Sui RPC method"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::coordinator::assets::BUDLUM_TESTNET_CHAIN_ID;

    #[test]
    fn sui_rpc_is_closed_on_testnet() {
        let mut state = AccountState::new();
        let closed = handle_sui_rpc(
            &state,
            SuiActivationPolicy::default(),
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "sui_getChainIdentifier".into(),
                params: vec![],
            },
        );
        assert!(closed.error.is_some());

        let sui_addr = [0x55u8; 32];
        let bud_addr = derive_foreign_account(ForeignScheme::SuiEd25519, &sui_addr);
        state.add_balance(&bud_addr, 7); // 7 atoms = 7_000 MIST (1 atom = 10^12 attos = 10^3 MIST)

        let bal = handle_sui_rpc(
            &state,
            SuiActivationPolicy {
                chain_id: BUDLUM_TESTNET_CHAIN_ID,
                block_height: 100,
                activation_height: Some(100),
            },
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "suix_getBalance".into(),
                params: vec![json!(format!("0x{}", hex::encode(sui_addr)))],
            },
        );
        assert_eq!(bal.result.unwrap()["totalBalance"].as_str(), Some("7000"));
    }

    #[test]
    fn sui_rpc_rejects_wrong_jsonrpc_version() {
        let state = AccountState::new();
        let policy = SuiActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };
        let resp = handle_sui_rpc(
            &state,
            policy,
            SuiRpcRequest {
                jsonrpc: "1.0".into(),
                id: json!(1),
                method: "sui_getChainIdentifier".into(),
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
    fn sui_rpc_rejects_missing_jsonrpc_version() {
        let state = AccountState::new();
        let policy = SuiActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };
        let resp = handle_sui_rpc(
            &state,
            policy,
            SuiRpcRequest {
                jsonrpc: "".into(),
                id: json!(1),
                method: "sui_getChainIdentifier".into(),
                params: vec![],
            },
        );
        assert!(resp.result.is_none() && !resp.error.is_none());
        assert!(resp.error.is_some());
    }

    #[test]
    fn max_sui_rpc_request_bytes_is_bounded() {
        assert_eq!(MAX_SUI_RPC_REQUEST_BYTES, 1 << 20);
    }

    #[test]
    fn suix_get_balance_respects_coin_type_filter_and_requires_0x_addresses() {
        let mut state = AccountState::new();
        let sui_addr = [0x55u8; 32];
        let bud_addr = derive_foreign_account(ForeignScheme::SuiEd25519, &sui_addr);
        state.add_balance(&bud_addr, 7);
        let policy = SuiActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 100,
            activation_height: Some(100),
        };

        // Querying a foreign coinType must NOT return native BUD balance.
        let other_coin = handle_sui_rpc(
            &state,
            policy,
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "suix_getBalance".into(),
                params: vec![
                    json!(format!("0x{}", hex::encode(sui_addr))),
                    json!("0xdead::usdc::USDC"),
                ],
            },
        );
        let res = other_coin.result.expect("zero coin balance response");
        assert_eq!(res["coinType"].as_str(), Some("0xdead::usdc::USDC"));
        assert_eq!(res["totalBalance"].as_str(), Some("0"));
        assert_eq!(res["coinObjectCount"].as_u64(), Some(0));

        // Unprefixed address must be rejected.
        let no_prefix = handle_sui_rpc(
            &state,
            policy,
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "suix_getBalance".into(),
                params: vec![json!(hex::encode(sui_addr))],
            },
        );
        assert!(no_prefix.error.is_some());

        // Oversized hex envelope must be rejected before hex::decode.
        let huge_hex = format!(
            "0x{}",
            "aa".repeat(crate::execution::coordinator::foreign::sui::MAX_SUI_ENVELOPE_BYTES + 1)
        );
        let over_env = handle_sui_rpc(
            &state,
            policy,
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(3),
                method: "sui_executeTransactionBlock".into(),
                params: vec![json!(huge_hex)],
            },
        );
        assert_eq!(
            over_env.error.as_ref().and_then(|e| e["code"].as_i64()),
            Some(-32602)
        );

        // handle_sui_jsonrpc enforces MAX_SUI_RPC_REQUEST_BYTES.
        let oversized = " ".repeat(MAX_SUI_RPC_REQUEST_BYTES + 1);
        let raw_over = handle_sui_jsonrpc(&state, policy, &oversized);
        assert!(raw_over.contains("-32005"), "raw_over: {raw_over}");
    }
}
