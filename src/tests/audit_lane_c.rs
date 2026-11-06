//! Live-verification regression locks for the lane C findings of the unified
//! findings ledger (directive section 14). Each lock names the finding it
//! keeps closed and cites the evidence it relies on.
//!
//! No lane C record is Kapalı in this snapshot. Every Açık and Doğrulandı
//! row is recorded in `docs/audit/live/lane-c.md`; their repro tests are
//! owed on the `audit/repro-c` branch (directive sections 14.1 and 15.8, S-3).
//! The engine catalog for this lane is in `docs/audit/live/engine-inventory.md`.
//!
//! This module carries only permanent locks for facts that must hold
//! regardless of which package flips the findings.

fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// BLG-256 (permanent foot): the canonical amount type at the execution
/// interface is attoBUD in a `u128`. EVM 1e-18 and SVM 1e-9 fractions are
/// handled by the EE gas-accounting advice of WP-26 (İP-26), not by adding a
/// second unit here; the canonical ledger unit stays attoBUD (directive 8.3.5,
/// 11.1). If this struct moves to another module or another width, the
/// change is an interface change and must be called out in the PR.
#[test]
fn blg_256_bud_amount_is_attobud_u128() {
    let types = include_str!("../../crates/uel-abi/src/types.rs");
    assert!(
        types.contains("pub struct BudAmount(pub u128);"),
        "BudAmount must stay the attoBUD u128 newtype at the execution interface"
    );
}

/// BLG-249 (permanent foot, until İP-28/29/31/32 land): the RPC surface has
/// exactly one namespace. This lock is expected to fail when the first compat
/// gateway lands; that failure is the reminder to extend it, not to revert.
#[test]
fn blg_249_no_compat_rpc_namespace_yet() {
    let method_class = production_part(include_str!("../rpc/method_class.rs"));
    // The bud_ namespace is the only method family in the tree today.
    assert!(
        method_class.contains("bud_"),
        "the bud_ namespace must be present in the method table"
    );
    assert!(
        !method_class.contains("eth_call"),
        "no Ethereum-compatible methods until the compat gateways land (İP-28)"
    );
}
