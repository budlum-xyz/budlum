//! Route classification table for the Aptos `/v1` REST gateway (`127.0.0.1:18549`, `Section 8.11.4`, `WP-32`).
//! Convenience: public Aptos REST route classification surface (WP-32).

use std::collections::BTreeSet;

use crate::rpc::compat::ethereum::method_class::{CompatEffect, CompatListener, CompatMethodClass};

const fn route(name: &'static str, effect: CompatEffect) -> CompatMethodClass {
    CompatMethodClass {
        name,
        listener: CompatListener::Public,
        effect,
    }
}

/// Complete Aptos `/v1` REST route table (`Section 8.11.4`: all 18 routes).
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

/// Look up an Aptos REST route pattern.
#[must_use]
pub fn lookup_aptos_route(pattern: &str) -> Option<CompatMethodClass> {
    APTOS_REST_ROUTES.iter().copied().find(|r| r.name == pattern)
}

/// Verify that served Aptos `/v1` routes match [`APTOS_REST_ROUTES`] 1-to-1.
/// Convenience: guard invoked on Aptos gateway initialization.
pub fn check_served_aptos_routes<'a>(
    served: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut table = BTreeSet::new();
    for entry in APTOS_REST_ROUTES {
        if !table.insert(entry.name) {
            return Err(format!("duplicate Aptos route: {}", entry.name));
        }
    }
    let served_set: BTreeSet<&str> = served.into_iter().collect();
    for name in &served_set {
        if !table.contains(name) {
            return Err(format!("unclassified Aptos route served: {name}"));
        }
    }
    for expected in &table {
        if !served_set.contains(expected) {
            return Err(format!("classified Aptos route missing: {expected}"));
        }
    }
    Ok(())
}
