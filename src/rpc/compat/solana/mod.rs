//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`, `Section 8.11.3`, `WP-31`).
//! Convenience: public Solana JSON-RPC compatibility gateway surface (WP-31).

pub mod method_class;

use crate::core::account::{AccountState, ATTO_PER_ATOM};
use crate::execution::coordinator::accounts::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::bud_unit::ATTO_PER_LAMPORT;
use crate::execution::coordinator::commitment::NS_SVM_ACCOUNT;
use crate::execution::coordinator::foreign::solana::{decode_solana_tx, SolanaReplayWindow};

/// Default loopback listener for the Solana JSON-RPC compatibility gateway.
pub const DEFAULT_SOLANA_RPC_LISTENER: &str = "127.0.0.1:18548";

/// Read-only Solana JSON-RPC gateway + mempool foreign-envelope validator (`BLG-249`).
#[derive(Debug, Clone)]
pub struct SolanaCompatGateway {
    pub listener: String,
    pub genesis_hash_hex: String,
    pub latest_blockhash: [u8; 32],
    pub replay_window: SolanaReplayWindow,
}

impl SolanaCompatGateway {
    #[must_use]
    pub fn new(genesis_hash_hex: String, latest_blockhash: [u8; 32]) -> Self {
        let _ = method_class::check_served_solana_methods(
            method_class::SOLANA_METHOD_CLASSES.iter().map(|m| m.name),
        );
        let mut replay_window = SolanaReplayWindow::new();
        replay_window.push_blockhash(latest_blockhash);
        Self {
            listener: String::from(DEFAULT_SOLANA_RPC_LISTENER),
            genesis_hash_hex,
            latest_blockhash,
            replay_window,
        }
    }

    /// Convenience: dispatch one Solana JSON-RPC request without mutating committed `state`.
    pub fn handle_jsonrpc(
        &mut self,
        state: &AccountState,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, (i64, String)> {
        let Some(_cls) = method_class::lookup_solana_method(method) else {
            return Err((-32601, format!("unsupported Solana RPC method `{method}`")));
        };
        match method {
            "getHealth" => Ok(serde_json::json!("ok")),
            "getVersion" => Ok(serde_json::json!({ "solana-core": "2.1.0-budlum", "feature-set": 1 })),
            "getGenesisHash" => Ok(serde_json::json!(self.genesis_hash_hex)),
            "getSlot" | "getBlockHeight" => Ok(serde_json::json!(state.current_block_height)),
            "getLatestBlockhash" => Ok(serde_json::json!({
                "context": { "slot": state.current_block_height },
                "value": {
                    "blockhash": hex::encode(self.latest_blockhash),
                    "lastValidBlockHeight": state.current_block_height.saturating_add(150),
                }
            })),
            "getBalance" => {
                let pk_hex = params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| (-32602, String::from("missing pubkey hex parameter")))?;
                let raw = hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))
                    .map_err(|e| (-32602, format!("invalid pubkey hex: {e}")))?;
                let pk32: [u8; 32] = raw
                    .try_into()
                    .map_err(|_| (-32602, String::from("Solana pubkey must be 32 bytes")))?;
                let addr = derive_foreign_account(ForeignScheme::SolanaEd25519, &pk32)
                    .map_err(|e| (-32602, e.to_string()))?;
                let attos = state.accounts.get(&addr).map_or(0u128, |a| {
                    u128::from(a.balance)
                        .saturating_mul(u128::from(ATTO_PER_ATOM))
                        .saturating_add(u128::from(a.frac_attos))
                });
                let lamports = u64::try_from(attos / ATTO_PER_LAMPORT).unwrap_or(u64::MAX);
                Ok(serde_json::json!({
                    "context": { "slot": state.current_block_height },
                    "value": lamports,
                }))
            }
            "getAccountInfo" => {
                let pk_hex = params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| (-32602, String::from("missing account key hex")))?;
                let raw = hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))
                    .map_err(|e| (-32602, format!("invalid account hex: {e}")))?;
                let data_hex = state
                    .uel_state
                    .read(NS_SVM_ACCOUNT, &raw)
                    .map(hex::encode);
                Ok(serde_json::json!({
                    "context": { "slot": state.current_block_height },
                    "value": data_hex.map(|d| serde_json::json!({ "data": [d, "hex"] })),
                }))
            }
            "sendTransaction" => {
                let wire_hex = params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| (-32602, String::from("missing wire transaction hex")))?;
                let wire = hex::decode(wire_hex.strip_prefix("0x").unwrap_or(wire_hex))
                    .map_err(|e| (-32602, format!("invalid transaction hex: {e}")))?;
                let decoded = self
                    .replay_window
                    .verify_and_admit(&wire)
                    .map_err(|e| (-32002, e.to_string()))?;
                Ok(serde_json::json!(hex::encode(decoded.fee_payer_signature)))
            }
            "simulateTransaction" => {
                let wire_hex = params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| (-32602, String::from("missing wire transaction hex")))?;
                let wire = hex::decode(wire_hex.strip_prefix("0x").unwrap_or(wire_hex))
                    .map_err(|e| (-32602, format!("invalid transaction hex: {e}")))?;
                let decoded = decode_solana_tx(&wire).map_err(|e| (-32002, e.to_string()))?;
                Ok(serde_json::json!({
                    "context": { "slot": state.current_block_height },
                    "value": { "err": serde_json::Value::Null, "logs": [], "unitsConsumed": decoded.instructions.len() * 1000 }
                }))
            }
            _ => Ok(serde_json::json!({ "context": { "slot": state.current_block_height }, "value": serde_json::Value::Null })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::coordinator::foreign::solana::{sign_solana_tx, SolanaCompiledInstruction};

    #[test]
    fn solana_rpc_table_complete_and_send_transaction_never_writes_state() {
        let names: Vec<&str> = method_class::SOLANA_METHOD_CLASSES.iter().map(|m| m.name).collect();
        assert_eq!(names.len(), 30);
        method_class::check_served_solana_methods(names).expect("30 unique Solana RPC methods");

        let state = AccountState::new();
        let root_before = state.calculate_state_root();
        let bh = [0x55u8; 32];
        let mut gw = SolanaCompatGateway::new(String::from("budlum-devnet"), bh);
        let wire = sign_solana_tx(
            &[0x22u8; 32],
            false,
            bh,
            &[],
            &[SolanaCompiledInstruction {
                program_id_index: 0,
                accounts: vec![0],
                data: vec![9],
            }],
        );
        let sig = gw
            .handle_jsonrpc(&state, "sendTransaction", &serde_json::json!([hex::encode(&wire)]))
            .expect("admitted");
        assert!(sig.as_str().is_some_and(|s| s.len() == 128));
        assert_eq!(state.calculate_state_root(), root_before);
    }
}
