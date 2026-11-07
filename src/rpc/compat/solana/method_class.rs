//! Method classification table for the Solana JSON-RPC gateway (`127.0.0.1:18548`, `Section 8.11.3`, `WP-31`).
//! Convenience: public Solana JSON-RPC method classification surface (WP-31).

use std::collections::BTreeSet;

use crate::rpc::compat::ethereum::method_class::{CompatEffect, CompatListener, CompatMethodClass};

const fn row(name: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass {
        name,
        listener: CompatListener::Public,
        effect,
    }
}

/// Complete Solana JSON-RPC method table (`Section 8.11.3`: 25 HTTP + 5 WebSocket).
pub const SOLANA_METHOD_CLASSES: &[CompatMethodClass] = &[
    row("getHealth", CompatEffect::Read),
    row("getVersion", CompatEffect::Read),
    row("getGenesisHash", CompatEffect::Read),
    row("getSlot", CompatEffect::Read),
    row("getBlockHeight", CompatEffect::Read),
    row("getEpochInfo", CompatEffect::Read),
    row("getLatestBlockhash", CompatEffect::Read),
    row("isBlockhashValid", CompatEffect::Read),
    row("getBalance", CompatEffect::Read),
    row("getAccountInfo", CompatEffect::Read),
    row("getMultipleAccounts", CompatEffect::Read),
    row("getProgramAccounts", CompatEffect::Read),
    row("getTokenAccountsByOwner", CompatEffect::Read),
    row("getTokenAccountBalance", CompatEffect::Read),
    row("getTokenSupply", CompatEffect::Read),
    row("getMinimumBalanceForRentExemption", CompatEffect::Read),
    row("getFeeForMessage", CompatEffect::Read),
    row("getRecentPrioritizationFees", CompatEffect::Read),
    row("sendTransaction", CompatEffect::TxSubmit),
    row("simulateTransaction", CompatEffect::Read),
    row("getSignatureStatuses", CompatEffect::Read),
    row("getSignaturesForAddress", CompatEffect::Read),
    row("getTransaction", CompatEffect::Read),
    row("getBlock", CompatEffect::Read),
    row("requestAirdrop", CompatEffect::TxSubmit),
    row("accountSubscribe", CompatEffect::LocalAdmin),
    row("signatureSubscribe", CompatEffect::LocalAdmin),
    row("slotSubscribe", CompatEffect::LocalAdmin),
    row("logsSubscribe", CompatEffect::LocalAdmin),
    row("programSubscribe", CompatEffect::LocalAdmin),
];

/// Look up the classification row for a Solana JSON-RPC method.
#[must_use]
pub fn lookup_solana_method(method: &str) -> Option<CompatMethodClass> {
    SOLANA_METHOD_CLASSES.iter().copied().find(|m| m.name == method)
}

/// Verify that served Solana methods match [`SOLANA_METHOD_CLASSES`] 1-to-1.
/// Convenience: guard invoked on Solana gateway initialization.
pub fn check_served_solana_methods<'a>(
    served: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut table = BTreeSet::new();
    for entry in SOLANA_METHOD_CLASSES {
        if !table.insert(entry.name) {
            return Err(format!("duplicate Solana method: {}", entry.name));
        }
    }
    let served_set: BTreeSet<&str> = served.into_iter().collect();
    for name in &served_set {
        if !table.contains(name) {
            return Err(format!("unclassified Solana method served: {name}"));
        }
    }
    for expected in &table {
        if !served_set.contains(expected) {
            return Err(format!("classified Solana method missing: {expected}"));
        }
    }
    Ok(())
}
