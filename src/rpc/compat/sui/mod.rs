//! Sui JSON-RPC compatibility read & height-gated submission subset (`WP-50`,
//! `Section 8.11`).
//!
//! Serves read-only Sui JSON-RPC methods (`sui_getChainIdentifier`,
//! `sui_getLatestCheckpointSequenceNumber`, `sui_getObject`, `suix_getBalance`,
//! `suix_getAllBalances`) against `AccountState` without mutating consensus state,
//! and enforces `Section 1.5` launch-closure on `45261` until activation.

use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::account::AccountState;
use crate::execution::coordinator::accounts::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::bud_unit::account_total_attos;
use crate::execution::coordinator::foreign::sui::{
    decode_and_recover_sui_tx, SuiActivationPolicy, PROPOSED_SUI_ACTIVATION_HEIGHT,
};
use crate::execution::coordinator::universal_call::resolve_ee_identity;

/// `1 MIST = 10^9 attoBUD`.
const ATTO_PER_MIST: u128 = 1_000_000_000;

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
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(trimmed).ok()?;
    bytes.as_slice().try_into().ok()
}

fn mist_balance_of(state: &AccountState, sui_addr: &[u8; 32]) -> u64 {
    let id = budlum_uel_abi::EeIdentity {
        ee: EeId::MOVE_SUI,
        id: sui_addr.to_vec(),
    };
    let bud_addr = resolve_ee_identity(state, &id)
        .ok()
        .or_else(|| derive_foreign_account(ForeignScheme::SuiEd25519, sui_addr).ok());
    let Some(addr) = bud_addr else {
        return 0;
    };
    let Some(acct) = state.get_account(&addr) else {
        return 0;
    };
    let attos = account_total_attos(acct.balance, acct.frac_attos).unwrap_or(0);
    u64::try_from(attos / ATTO_PER_MIST).unwrap_or(u64::MAX)
}

/// Handle a read-only or height-gated Sui JSON-RPC 2.0 request (`WP-50`).
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
    match req.method.as_str() {
        "sui_getChainIdentifier" => {
            SuiRpcResponse::ok(req.id, json!(format!("{:08x}", policy.chain_id)))
        }
        "sui_getLatestCheckpointSequenceNumber" => {
            SuiRpcResponse::ok(req.id, json!(policy.block_height.to_string()))
        }
        "suix_getBalance" => {
            let Some(addr_str) = req.params.first().and_then(Value::as_str) else {
                return SuiRpcResponse::err(req.id, -32602, "missing Sui address");
            };
            let Some(addr32) = parse_sui_hex32(addr_str) else {
                return SuiRpcResponse::err(req.id, -32602, "invalid 32-byte Sui hex address");
            };
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
            let Some(addr_str) = req.params.first().and_then(Value::as_str) else {
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
            let Some(id_str) = req.params.first().and_then(Value::as_str) else {
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
            let Some(hex_env) = req.params.first().and_then(Value::as_str) else {
                return SuiRpcResponse::err(req.id, -32602, "missing hex envelope");
            };
            let Ok(raw) = hex::decode(hex_env.strip_prefix("0x").unwrap_or(hex_env)) else {
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
    fn sui_rpc_is_closed_on_testnet_before_activation_and_reads_mist_once_active() {
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
        let bud_addr = derive_foreign_account(ForeignScheme::SuiEd25519, &sui_addr).unwrap();
        state.add_balance(&bud_addr, 7); // 7 atoms = 7_000 MIST (1 atom = 10^12 attos = 10^3 MIST)

        let active = SuiActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: PROPOSED_SUI_ACTIVATION_HEIGHT,
            activation_height: Some(PROPOSED_SUI_ACTIVATION_HEIGHT),
        };
        let bal = handle_sui_rpc(
            &state,
            active,
            SuiRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "suix_getBalance".into(),
                params: vec![json!(format!("0x{}", hex::encode(sui_addr)))],
            },
        );
        assert_eq!(bal.result.unwrap()["totalBalance"].as_str(), Some("7000"));
    }
}
