//! Custom CosmWasm messages (`BudlumMsg::UniversalCall`) and queries
//! (`BudlumQuery::UniversalView`) exposed inside `budlum-ee-wasm` (WP-29, WP-30).

use serde::{Deserialize, Serialize};

/// Custom `CosmosMsg::Custom(BudlumMsg)` message dispatched to the UEL Coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumMsg {
    UniversalCall {
        target_ee: u8,
        target_hex: String,
        input_hex: String,
        value_attos: u128,
        gas_limit_bgu: u64,
    },
}

/// Custom `QueryRequest::Custom(BudlumQuery)` read-only view dispatched to the Coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumQuery {
    UniversalView {
        target_ee: u8,
        target_hex: String,
        input_hex: String,
        gas_limit_bgu: u64,
    },
}
