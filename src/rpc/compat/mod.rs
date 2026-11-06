//! Compatibility Lane RPC and REST gateways (section 8.11):
//! - Ethereum JSON-RPC (`127.0.0.1:18547`, `WP-28`)
//! - Solana JSON-RPC (`127.0.0.1:18548`, `WP-31`)
//! - Aptos REST (`127.0.0.1:18549`, `WP-32`)
//! - CometBFT RPC & Cosmos LCD (`127.0.0.1:18550` / `127.0.0.1:18551`, `WP-29`)
//!
//! Every gateway follows the `method_class.rs` discipline: each method's listener
//! and effect are declared in a single table, and no method mutates consensus
//! state outside block execution.

pub mod aptos;
pub mod cosmos;
pub mod ethereum;
pub mod solana;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON-RPC 2.0 standard error code: Method not found.
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0 standard error code: Invalid params.
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC error code: Operator listener required.
pub const JSONRPC_OPERATOR_REQUIRED: i32 = -32001;
/// JSON-RPC error code: Resource / filter / rate quota exceeded (EIP-1474 `-32005`).
pub const JSONRPC_LIMIT_EXCEEDED: i32 = -32005;
/// JSON-RPC error code: Transaction rejected at mempool admission (`-32003`).
pub const JSONRPC_TX_REJECTED: i32 = -32003;

/// Which listener may serve a Compatibility Lane RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatListener {
    Public,
    Operator,
}

/// Effect of a Compatibility Lane RPC method (never out-of-block consensus mutation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatEffect {
    Read,
    TxSubmit,
    LocalFilter,
    Refused,
}

/// Single row in a Compatibility Lane method classification table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatMethodClass {
    pub name: &'static str,
    pub listener: CompatListener,
    pub effect: CompatEffect,
}

impl CompatMethodClass {
    #[must_use]
    pub const fn new(
        name: &'static str,
        listener: CompatListener,
        effect: CompatEffect,
    ) -> Self {
        Self {
            name,
            listener,
            effect,
        }
    }
}

/// Configuration for `[compat.ethereum]` (`127.0.0.1:18547`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumCompatConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub max_filters_per_peer: usize,
    pub max_total_filters: usize,
    pub filter_ttl_secs: u64,
    pub max_log_block_range: u64,
    pub max_logs_returned: usize,
    pub max_requests_per_window: u32,
}

impl Default for EthereumCompatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: String::from("127.0.0.1:18547"),
            max_filters_per_peer: 16,
            max_total_filters: 256,
            filter_ttl_secs: 300,
            max_log_block_range: 2_000,
            max_logs_returned: 10_000,
            max_requests_per_window: 120,
        }
    }
}

/// Configuration for `[compat.solana]` (`127.0.0.1:18548`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaCompatConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub max_program_accounts: usize,
    pub testnet_faucet_enabled: bool,
}

impl Default for SolanaCompatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: String::from("127.0.0.1:18548"),
            max_program_accounts: 500,
            testnet_faucet_enabled: false,
        }
    }
}

/// Configuration for `[compat.aptos]` (`127.0.0.1:18549`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AptosCompatConfig {
    pub enabled: bool,
    pub listen_addr: String,
}

impl Default for AptosCompatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: String::from("127.0.0.1:18549"),
        }
    }
}

/// Configuration for `[compat.cosmos]` (`127.0.0.1:18550` and `127.0.0.1:18551`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosmosCompatConfig {
    pub enabled: bool,
    pub cometbft_listen_addr: String,
    pub lcd_listen_addr: String,
    pub max_tx_search_results: usize,
}

impl Default for CosmosCompatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cometbft_listen_addr: String::from("127.0.0.1:18550"),
            lcd_listen_addr: String::from("127.0.0.1:18551"),
            max_tx_search_results: 100,
        }
    }
}

/// Top-level `[compat]` node configuration section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatRpcConfig {
    pub ethereum: EthereumCompatConfig,
    pub solana: SolanaCompatConfig,
    pub aptos: AptosCompatConfig,
    pub cosmos: CosmosCompatConfig,
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    #[must_use]
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: String::from("2.0"),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn err(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: String::from("2.0"),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Simple per-peer sliding-window request quota tracker.
#[derive(Debug, Clone, Default)]
pub struct PeerQuotaTracker {
    counts: BTreeMap<String, u32>,
}

impl PeerQuotaTracker {
    pub fn record_and_check(&mut self, peer: &str, max_per_window: u32) -> Result<(), String> {
        let entry = self.counts.entry(peer.to_string()).or_insert(0);
        if *entry >= max_per_window {
            return Err(format!("peer `{peer}` exceeded RPC window quota ({max_per_window})"));
        }
        *entry = entry.saturating_add(1);
        Ok(())
    }

    pub fn reset_window(&mut self) {
        self.counts.clear();
    }
}

#[cfg(test)]
mod compat_tests;
