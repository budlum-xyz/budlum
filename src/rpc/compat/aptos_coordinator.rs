//! Aptos REST compatibility gateway (`127.0.0.1:18549`, WP-32 & section 8.11.4).

use crate::core::account::AccountState;
use crate::execution::coordinator::alias::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::foreign::aptos::BUDLUM_APTOS_CHAIN_ID;
use crate::execution::coordinator::foreign::{ForeignTx, VerifiedForeignOutcome};
use crate::execution::coordinator::move_ee::ATTOS_PER_OCTA;
use crate::execution::coordinator::ExecutionCoordinator;
use crate::rpc::compat::{AptosCompatConfig, CompatEffect, CompatListener, CompatMethodClass};
use serde::{Deserialize, Serialize};

const fn route(pattern: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass::new(pattern, CompatListener::Public, effect)
}

/// Complete Aptos `/v1` REST route table (section 8.11.4, all 18 routes).
pub const APTOS_REST_ROUTES: &[CompatMethodClass] = &[
    route("GET /v1", CompatEffect::Read),
    route("GET /v1/-/healthy", CompatEffect::Read),
    route("GET /v1/accounts/{addr}", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/resources", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/resource/{type}", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/modules", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/module/{name}", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/transactions", CompatEffect::Read),
    route("POST /v1/transactions", CompatEffect::TxSubmit),
    route("POST /v1/transactions/simulate", CompatEffect::Read),
    route("GET /v1/transactions/by_hash/{h}", CompatEffect::Read),
    route("GET /v1/transactions/wait_by_hash/{h}", CompatEffect::Read),
    route("GET /v1/transactions/by_version/{v}", CompatEffect::Read),
    route("POST /v1/view", CompatEffect::Read),
    route("GET /v1/estimate_gas_price", CompatEffect::Read),
    route("GET /v1/blocks/by_height/{h}", CompatEffect::Read),
    route("POST /v1/tables/{handle}/item", CompatEffect::Read),
    route("GET /v1/accounts/{addr}/events/{creation_number}", CompatEffect::Read),
];

/// Minimal HTTP response model for Aptos `/v1` REST handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AptosRestResponse {
    pub status: u16,
    pub body: serde_json::Value,
}

/// Aptos `/v1` REST compatibility gateway (`state` is read-only).
#[derive(Debug, Clone)]
pub struct AptosCompatGateway {
    config: AptosCompatConfig,
    block_height: u64,
    now_secs: u64,
}

impl AptosCompatGateway {
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn new(config: AptosCompatConfig, block_height: u64, now_secs: u64) -> Self {
        Self {
            config,
            block_height,
            now_secs,
        }
    }

    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn handle_rest(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        state: &AccountState,
    ) -> AptosRestResponse {
        let _ = &self.config;
        match (method, path) {
            ("GET", "/v1") => AptosRestResponse {
                status: 200,
                body: serde_json::json!({
                    "chain_id": BUDLUM_APTOS_CHAIN_ID,
                    "epoch": "1",
                    "ledger_version": self.block_height.to_string(),
                    "block_height": self.block_height.to_string(),
                    "ledger_timestamp": (self.now_secs * 1_000_000).to_string(),
                    "node_role": "full_node",
                }),
            },
            ("GET", "/v1/-/healthy") => AptosRestResponse {
                status: 200,
                body: serde_json::json!({ "message": "aptos-node:ok" }),
            },
            ("GET", "/v1/estimate_gas_price") => AptosRestResponse {
                status: 200,
                body: serde_json::json!({ "gas_estimate": 100 }),
            },
            ("POST", "/v1/transactions") => {
                let Some(raw) = body else {
                    return AptosRestResponse {
                        status: 400,
                        body: serde_json::json!({ "message": "missing BCS transaction body" }),
                    };
                };
                let mut preview = state.clone();
                let mut coord = ExecutionCoordinator::new();
                let env = ForeignTx::Aptos {
                    raw_bcs: raw.to_vec(),
                    direct_native_pq_recipient: None,
                };
                match coord.process_foreign_envelope(&mut preview, &env, self.now_secs) {
                    Ok(VerifiedForeignOutcome::Aptos { decoded, .. }) => {
                        let tx_hex = format!("0x{}", hex::encode(decoded.tx_hash));
                        AptosRestResponse {
                            status: 202,
                            body: serde_json::json!({ "hash": tx_hex }),
                        }
                    }
                    Ok(_) => AptosRestResponse {
                        status: 400,
                        body: serde_json::json!({ "message": "unexpected Aptos envelope" }),
                    },
                    Err(e) => AptosRestResponse {
                        status: 400,
                        body: serde_json::json!({ "message": e.to_string() }),
                    },
                }
            }
            ("POST", "/v1/transactions/simulate" | "/v1/view") => AptosRestResponse {
                status: 200,
                body: serde_json::json!([]),
            },
            ("GET", p) if p.starts_with("/v1/accounts/") => {
                let rest = p.trim_start_matches("/v1/accounts/");
                let addr_seg = rest.split('/').next().unwrap_or("");
                let Ok(bytes) = hex::decode(addr_seg.trim_start_matches("0x")) else {
                    return AptosRestResponse {
                        status: 400,
                        body: serde_json::json!({ "message": "bad account hex" }),
                    };
                };
                let Ok(auth32) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    return AptosRestResponse {
                        status: 400,
                        body: serde_json::json!({ "message": "expected 32-byte auth key" }),
                    };
                };
                let bud_addr = derive_foreign_account(ForeignScheme::Aptos, &auth32);
                let seq = state
                    .execution_state
                    .foreign_lane
                    .accounts
                    .get(&bud_addr)
                    .map_or(0u64, |r| r.next_nonce);
                let octas = state.get_attos_balance(&bud_addr) / ATTOS_PER_OCTA;
                if rest.ends_with("/resources") {
                    return AptosRestResponse {
                        status: 200,
                        body: serde_json::json!([{
                            "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                            "data": { "coin": { "value": octas.to_string() } }
                        }]),
                    };
                }
                AptosRestResponse {
                    status: 200,
                    body: serde_json::json!({
                        "sequence_number": seq.to_string(),
                        "authentication_key": format!("0x{}", hex::encode(auth32)),
                    }),
                }
            }
            _ => AptosRestResponse {
                status: 404,
                body: serde_json::json!({ "message": "route not found" }),
            },
        }
    }
}

/// Evaluates an Aptos REST v1 HTTP request against read-only `state` (`18549`).
///
/// exposed for: wire-level Aptos REST handler (`WP-28`, `WP-48`).
#[must_use]
pub fn handle_aptos_rest(
    state: &AccountState,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> (u16, String) {
    if body.is_some_and(|b| b.len() > crate::rpc::compat::ethereum::MAX_COMPAT_REQUEST_BYTES) {
        return (
            413,
            serde_json::json!({ "message": "payload too large" }).to_string(),
        );
    }
    let mut gw = AptosCompatGateway::new(AptosCompatConfig::default(), 0, 0);
    let resp = gw.handle_rest(method, path, body, state);
    (resp.status, resp.body.to_string())
}
