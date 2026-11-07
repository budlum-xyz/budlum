//! Aptos `/v1` REST compatibility gateway (`127.0.0.1:18549`, `Section 8.11.4`, `WP-32`).
//! Convenience: public Aptos REST compatibility gateway surface (WP-32).

pub mod method_class;

use crate::core::account::AccountState;
use crate::execution::coordinator::commitment::NS_MOVE_STATE;
use crate::execution::coordinator::foreign::aptos::{
    decode_and_verify_aptos_tx, BUDLUM_APTOS_CHAIN_ID,
};

/// Default loopback listener for the Aptos `/v1` REST compatibility gateway.
pub const DEFAULT_APTOS_REST_LISTENER: &str = "127.0.0.1:18549";

/// Read-only Aptos `/v1` REST gateway + BCS foreign-envelope validator (`BLG-249`).
#[derive(Debug, Clone)]
pub struct AptosCompatGateway {
    pub listener: String,
    pub now_secs: u64,
}

impl AptosCompatGateway {
    #[must_use]
    pub fn new(now_secs: u64) -> Self {
        let _ = method_class::check_served_aptos_routes(
            method_class::APTOS_REST_ROUTES.iter().map(|r| r.name),
        );
        Self {
            listener: String::from(DEFAULT_APTOS_REST_LISTENER),
            now_secs,
        }
    }

    /// Dispatch one Aptos `/v1` REST call without mutating committed `state`.
    /// Convenience: handle a parsed Aptos `/v1` REST request.
    pub fn handle_rest(
        &self,
        state: &AccountState,
        route_pattern: &str,
        param: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<(u16, serde_json::Value), (u16, String)> {
        let Some(_cls) = method_class::lookup_aptos_route(route_pattern) else {
            return Err((404, format!("unsupported Aptos route `{route_pattern}`")));
        };
        match route_pattern {
            "GET /v1" => Ok((
                200,
                serde_json::json!({
                    "chain_id": BUDLUM_APTOS_CHAIN_ID,
                    "epoch": "1",
                    "ledger_version": state.current_block_height.to_string(),
                    "block_height": state.current_block_height.to_string(),
                }),
            )),
            "GET /v1/-/healthy" => Ok((200, serde_json::json!({ "message": "aptos-node:ok" }))),
            "GET /v1/estimate_gas_price" => Ok((
                200,
                serde_json::json!({
                    "deprioritized_gas_estimate": 100,
                    "gas_estimate": 100,
                    "prioritized_gas_estimate": 150,
                }),
            )),
            "GET /v1/accounts/{addr}" => {
                let addr_hex = param.unwrap_or("0x0");
                let raw = hex::decode(addr_hex.strip_prefix("0x").unwrap_or(addr_hex))
                    .map_err(|e| (400, format!("invalid Move address hex: {e}")))?;
                let present = state.uel_state.read(NS_MOVE_STATE, &raw).is_some();
                Ok((
                    200,
                    serde_json::json!({
                        "sequence_number": "0",
                        "authentication_key": format!("0x{}", hex::encode(&raw)),
                        "present": present,
                    }),
                ))
            }
            "POST /v1/transactions" | "POST /v1/transactions/simulate" => {
                let raw_bcs = body.ok_or_else(|| (400, String::from("missing BCS body")))?;
                let decoded = decode_and_verify_aptos_tx(
                    raw_bcs,
                    BUDLUM_APTOS_CHAIN_ID,
                    self.now_secs,
                )
                .map_err(|e| (400, e.to_string()))?;
                Ok((
                    if route_pattern == "POST /v1/transactions" { 202 } else { 200 },
                    serde_json::json!({
                        "hash": format!("0x{}", hex::encode(decoded.tx_hash)),
                        "sender": format!("0x{}", hex::encode(decoded.sender)),
                        "sequence_number": decoded.sequence_number.to_string(),
                    }),
                ))
            }
            _ => Ok((200, serde_json::json!([]))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aptos_rest_route_table_is_complete_and_healthy() {
        let routes: Vec<&str> = method_class::APTOS_REST_ROUTES.iter().map(|r| r.name).collect();
        assert_eq!(routes.len(), 18);
        method_class::check_served_aptos_routes(routes).expect("18 unique Aptos REST routes");

        let state = AccountState::new();
        let gw = AptosCompatGateway::new(1_762_000_000);
        let (code, ledger) = gw.handle_rest(&state, "GET /v1", None, None).expect("ledger info");
        assert_eq!(code, 200);
        assert_eq!(ledger["chain_id"].as_u64(), Some(u64::from(BUDLUM_APTOS_CHAIN_ID)));
    }
}
