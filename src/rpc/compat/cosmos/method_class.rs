//! Listener and side-effect classification table for the CometBFT JSON-RPC and
//! Cosmos LCD REST compatibility gateways (`Section 8.11.5`, `WP-29`, `BLG-249`).
//! Convenience: public CometBFT and Cosmos LCD method classification table (WP-29).

use crate::rpc::compat::ethereum::method_class::{CompatEffect, CompatListener};

/// Single row in the Cosmos compatibility method classification table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosmosMethodClass {
    pub method: &'static str,
    pub listener: CompatListener,
    pub effect: CompatEffect,
}

/// Complete `Section 8.11.5` CometBFT JSON-RPC method table (`12` methods).
pub const COSMOS_RPC_METHODS: &[CosmosMethodClass] = &[
    CosmosMethodClass {
        method: "status",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "abci_info",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "abci_query",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "broadcast_tx_sync",
        listener: CompatListener::Public,
        effect: CompatEffect::TxSubmit,
    },
    CosmosMethodClass {
        method: "broadcast_tx_async",
        listener: CompatListener::Public,
        effect: CompatEffect::TxSubmit,
    },
    CosmosMethodClass {
        method: "broadcast_tx_commit",
        listener: CompatListener::Public,
        effect: CompatEffect::TxSubmit,
    },
    CosmosMethodClass {
        method: "tx",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "tx_search",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "block",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "block_results",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "blockchain",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
    CosmosMethodClass {
        method: "validators",
        listener: CompatListener::Public,
        effect: CompatEffect::Read,
    },
];

/// Supported `abci_query` gRPC paths (`Section 8.11.5` item 2).
pub const COSMOS_ABCI_QUERY_PATHS: &[&str] = &[
    "/cosmos.auth.v1beta1.Query/Account",
    "/cosmos.bank.v1beta1.Query/Balance",
    "/cosmos.bank.v1beta1.Query/AllBalances",
    "/cosmwasm.wasm.v1.Query/SmartContractState",
    "/cosmwasm.wasm.v1.Query/RawContractState",
    "/cosmwasm.wasm.v1.Query/ContractInfo",
    "/cosmwasm.wasm.v1.Query/ContractsByCode",
    "/cosmwasm.wasm.v1.Query/Code",
    "/cosmwasm.wasm.v1.Query/Codes",
    "/cosmos.tx.v1beta1.Service/Simulate",
];

/// Look up a CometBFT JSON-RPC method in [`COSMOS_RPC_METHODS`].
#[must_use]
pub fn lookup_cosmos_method(method: &str) -> Option<&'static CosmosMethodClass> {
    COSMOS_RPC_METHODS.iter().find(|row| row.method == method)
}

/// Return `true` if `path` is an allowed `abci_query` gRPC path.
#[must_use]
pub fn is_supported_abci_query_path(path: &str) -> bool {
    COSMOS_ABCI_QUERY_PATHS.contains(&path)
}

/// Verify that every registered `jsonrpsee` CometBFT method appears in
/// [`COSMOS_RPC_METHODS`].
pub fn check_served_cosmos_methods<'a>(
    served: impl IntoIterator<Item = &'a str>,
) -> Result<(), Vec<String>> {
    let mut missing = Vec::new();
    for m in served {
        if lookup_cosmos_method(m).is_none() {
            missing.push(m.to_string());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}
