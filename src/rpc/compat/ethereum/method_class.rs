//! Method classification table for the Ethereum JSON-RPC gateway (`Section 8.11.2`, `WP-28`).
//!
//! Follows the exact `src/rpc/method_class.rs` discipline: every method served on
//! `127.0.0.1:18547` (public HTTP + WebSocket) or the operator trace listener is
//! listed here once with its listener and state effect. Startup refuses to bind if
//! the registered `RpcModule` methods diverge from [`ETH_METHOD_CLASSES`].

use std::collections::BTreeSet;

use CompatEffect::{LocalAdmin, Read, Refused, TxSubmit};
use CompatListener::{Operator, Public};

/// Which listener is permitted to serve a compatibility RPC method.
///
/// Convenience: inspected by gateway startup verification and operator policy tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatListener {
    /// Served on both the public listener (`127.0.0.1:18547`) and the operator listener.
    Public,
    /// Served exclusively on the operator listener (`debug_trace*`).
    Operator,
}

/// State effect of a compatibility RPC method.
///
/// Convenience: inspected by gateway startup verification and audit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatEffect {
    /// Pure read or deterministic simulation over committed/pending state.
    Read,
    /// Validates and hands a signed `Foreign::Ethereum` RLP envelope to the mempool.
    TxSubmit,
    /// Node-local bounded filter or WebSocket subscription lifecycle.
    LocalAdmin,
    /// Deterministic refusal (`eth_getProof` returns `-32601` at T-Genesis).
    Refused,
}

/// One row of [`ETH_METHOD_CLASSES`].
///
/// Convenience: inspected by `eth_rpc_method_table_is_complete` and startup checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatMethodClass {
    /// Canonical JSON-RPC method name.
    pub name: &'static str,
    /// Required listener tier.
    pub listener: CompatListener,
    /// Allowed state effect.
    pub effect: CompatEffect,
}

const fn row(
    name: &'static str,
    listener: CompatListener,
    effect: CompatEffect,
) -> CompatMethodClass {
    CompatMethodClass {
        name,
        listener,
        effect,
    }
}

/// Complete T-Genesis Ethereum JSON-RPC surface (`Section 8.10.6` + `Section 8.11.2`).
///
/// Convenience: verified against `EthCompatApi` at server startup and in unit tests.
pub const ETH_METHOD_CLASSES: &[CompatMethodClass] = &[
    row("web3_clientVersion", Public, Read),
    row("net_version", Public, Read),
    row("net_listening", Public, Read),
    row("eth_chainId", Public, Read),
    row("eth_syncing", Public, Read),
    row("eth_blockNumber", Public, Read),
    row("eth_getBalance", Public, Read),
    row("eth_getCode", Public, Read),
    row("eth_getStorageAt", Public, Read),
    row("eth_getTransactionCount", Public, Read),
    row("eth_call", Public, Read),
    row("eth_estimateGas", Public, Read),
    row("eth_createAccessList", Public, Read),
    row("eth_gasPrice", Public, Read),
    row("eth_maxPriorityFeePerGas", Public, Read),
    row("eth_feeHistory", Public, Read),
    row("eth_sendRawTransaction", Public, TxSubmit),
    row("eth_getBlockByNumber", Public, Read),
    row("eth_getBlockByHash", Public, Read),
    row("eth_getBlockTransactionCountByNumber", Public, Read),
    row("eth_getBlockTransactionCountByHash", Public, Read),
    row("eth_getTransactionByHash", Public, Read),
    row("eth_getTransactionByBlockNumberAndIndex", Public, Read),
    row("eth_getTransactionReceipt", Public, Read),
    row("eth_getBlockReceipts", Public, Read),
    row("eth_getLogs", Public, Read),
    row("eth_newFilter", Public, LocalAdmin),
    row("eth_newBlockFilter", Public, LocalAdmin),
    row("eth_getFilterChanges", Public, LocalAdmin),
    row("eth_getFilterLogs", Public, LocalAdmin),
    row("eth_uninstallFilter", Public, LocalAdmin),
    row("eth_subscribe", Public, LocalAdmin),
    row("eth_unsubscribe", Public, LocalAdmin),
    row("eth_accounts", Public, Read),
    // Section 8.10 item 6: stateRoot is BDLM_UEL_ROOT_V1 sparse-Merkle execution_root,
    // not a Patricia MPT root; eth_getProof deterministically returns -32601.
    row("eth_getProof", Public, Refused),
    // Section 8.11.2: debug tracing is restricted to the operator listener.
    row("debug_traceTransaction", Operator, Read),
    row("debug_traceCall", Operator, Read),
];

/// Look up the classification row for `method`.
///
/// Convenience: used by gateway middleware and tests.
#[must_use]
pub fn lookup_eth_method(method: &str) -> Option<CompatMethodClass> {
    ETH_METHOD_CLASSES.iter().copied().find(|m| m.name == method)
}

/// Verify that the methods registered on a `jsonrpsee` server match
/// [`ETH_METHOD_CLASSES`] 1-to-1 with no unclassified or missing methods.
///
/// Convenience: called at `EthCompatServer::start` before binding the socket.
pub fn check_served_eth_methods<'a>(
    served: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut table_names = BTreeSet::new();
    for entry in ETH_METHOD_CLASSES {
        if !table_names.insert(entry.name) {
            return Err(format!("duplicate method in ETH_METHOD_CLASSES: {}", entry.name));
        }
    }

    let served_set: BTreeSet<&str> = served.into_iter().collect();
    for name in &served_set {
        if !table_names.contains(name) {
            return Err(format!("unclassified Ethereum RPC method served: {name}"));
        }
    }
    for expected in &table_names {
        if !served_set.contains(expected) {
            return Err(format!(
                "classified Ethereum RPC method missing from server: {expected}"
            ));
        }
    }
    Ok(())
}
