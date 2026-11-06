//! Method classification table for the Solana JSON-RPC gateway (directive
//! 8.11.3, `WP-31`).
//!
//! The same discipline as `src/rpc/method_class.rs` and the Ethereum table: every
//! method served on `127.0.0.1:18548` (public HTTP and WebSocket) or the operator
//! listener is listed here once, with its listener and its state effect. Startup
//! refuses to bind if the registered module's methods and [`SOL_METHOD_CLASSES`]
//! diverge in either direction, so a method cannot be served before it is
//! classified and a row cannot survive a method that was removed.
//!
//! The effects are the compatibility gateways' only acceptable ones (directive
//! 8.11.1): a read, a signed transaction handed to the mempool, or node-local
//! work no other node has to agree on. A Solana method that would change
//! consensus state outside block execution has no row, and therefore cannot be
//! classified at all.
//!
//! Two rows need a note:
//!
//! * `requestAirdrop` is `TxSubmit` and not a grant. Directive 8.11.3 sends it to
//!   the faucet, and the faucet (WP-41) hands out testnet BUD behind proof of
//!   work; the gateway only forwards the request, so the node that serves it
//!   holds no balance of its own. On mainnet the faucet is closed, which the
//!   faucet's own feature flag decides, not this table.
//! * `getProgramAccounts` is `Read` but bounded: directive 8.11.3 says
//!   "filtered, limited", so the filter and the result cap are part of the
//!   method's contract and an unbounded scan is a refusal, not a slow read.

use std::collections::BTreeSet;

use CompatEffect::{LocalAdmin, Read, TxSubmit};
use CompatListener::Public;

use crate::rpc::compat::ethereum::method_class::{CompatEffect, CompatListener, CompatMethodClass};

/// One row of [`SOL_METHOD_CLASSES`] is the shared compatibility row, so the two
/// gateways cannot drift into two different notions of a listener or an effect.
pub type SolMethodClass = CompatMethodClass;

const fn row(name: &'static str, listener: CompatListener, effect: CompatEffect) -> SolMethodClass {
    CompatMethodClass {
        name,
        listener,
        effect,
    }
}

/// The complete T-Launch Solana JSON-RPC surface (directive 8.11.3), in the
/// order the directive lists it.
///
/// Convenience: verified against the registered module at gateway startup and in
/// unit tests.
pub const SOL_METHOD_CLASSES: &[SolMethodClass] = &[
    // Health and identity.
    row("getHealth", Public, Read),
    row("getVersion", Public, Read),
    row("getGenesisHash", Public, Read),
    row("getSlot", Public, Read),
    row("getBlockHeight", Public, Read),
    row("getEpochInfo", Public, Read),
    row("getLatestBlockhash", Public, Read),
    row("isBlockhashValid", Public, Read),
    // Accounts and balances.
    row("getBalance", Public, Read),
    row("getAccountInfo", Public, Read),
    row("getMultipleAccounts", Public, Read),
    // Bound by the filter and the result cap; see the module note.
    row("getProgramAccounts", Public, Read),
    row("getTokenAccountsByOwner", Public, Read),
    row("getTokenAccountBalance", Public, Read),
    row("getTokenSupply", Public, Read),
    row("getMinimumBalanceForRentExemption", Public, Read),
    // Fees.
    row("getFeeForMessage", Public, Read),
    row("getRecentPrioritizationFees", Public, Read),
    // Submission and simulation.
    row("sendTransaction", Public, TxSubmit),
    row("simulateTransaction", Public, Read),
    // History.
    row("getSignatureStatuses", Public, Read),
    row("getSignaturesForAddress", Public, Read),
    row("getTransaction", Public, Read),
    row("getBlock", Public, Read),
    // The faucet door; the faucet holds the balance, not this node.
    row("requestAirdrop", Public, TxSubmit),
    // WebSocket subscriptions: node-local session state, no shared state.
    row("accountSubscribe", Public, LocalAdmin),
    row("signatureSubscribe", Public, LocalAdmin),
    row("slotSubscribe", Public, LocalAdmin),
    row("logsSubscribe", Public, LocalAdmin),
    row("programSubscribe", Public, LocalAdmin),
    // The unsubscribe pair every subscription needs. The directive's list names
    // the subscriptions and stops; a subscription with no way to end it is a leak
    // that no peer has to agree on, which is exactly the `LocalAdmin` effect.
    row("accountUnsubscribe", Public, LocalAdmin),
    row("signatureUnsubscribe", Public, LocalAdmin),
    row("slotUnsubscribe", Public, LocalAdmin),
    row("logsUnsubscribe", Public, LocalAdmin),
    row("programUnsubscribe", Public, LocalAdmin),
];

/// Look up the classification row for `method`.
///
/// Convenience: used by gateway middleware and tests.
#[must_use]
pub fn lookup_sol_method(method: &str) -> Option<SolMethodClass> {
    SOL_METHOD_CLASSES.iter().copied().find(|m| m.name == method)
}

/// Verify that the methods registered on a server match [`SOL_METHOD_CLASSES`]
/// one to one, with no unclassified method and no row without a method.
///
/// Convenience: called by the gateway before it binds the socket.
///
/// # Errors
///
/// A message naming the duplicate row, the served but unclassified method, or the
/// classified method that is not served.
pub fn check_served_sol_methods<'a>(
    served: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut table_names = BTreeSet::new();
    for entry in SOL_METHOD_CLASSES {
        if !table_names.insert(entry.name) {
            return Err(format!("duplicate method in SOL_METHOD_CLASSES: {}", entry.name));
        }
    }

    let served_set: BTreeSet<&str> = served.into_iter().collect();
    for name in &served_set {
        if !table_names.contains(name) {
            return Err(format!("unclassified Solana RPC method served: {name}"));
        }
    }
    for expected in &table_names {
        if !served_set.contains(expected) {
            return Err(format!(
                "classified Solana RPC method missing from server: {expected}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_covers_the_directive_list_exactly() {
        // Directive 8.11.3, transcribed independently of the table, so the two
        // have to agree: this is the list a reviewer can check against the
        // directive without reading Rust.
        const DIRECTIVE: &[&str] = &[
            "getHealth",
            "getVersion",
            "getGenesisHash",
            "getSlot",
            "getBlockHeight",
            "getEpochInfo",
            "getLatestBlockhash",
            "isBlockhashValid",
            "getBalance",
            "getAccountInfo",
            "getMultipleAccounts",
            "getProgramAccounts",
            "getTokenAccountsByOwner",
            "getTokenAccountBalance",
            "getTokenSupply",
            "getMinimumBalanceForRentExemption",
            "getFeeForMessage",
            "getRecentPrioritizationFees",
            "sendTransaction",
            "simulateTransaction",
            "getSignatureStatuses",
            "getSignaturesForAddress",
            "getTransaction",
            "getBlock",
            "requestAirdrop",
            "accountSubscribe",
            "signatureSubscribe",
            "slotSubscribe",
            "logsSubscribe",
            "programSubscribe",
        ];
        let table: BTreeSet<&str> = SOL_METHOD_CLASSES.iter().map(|m| m.name).collect();
        for name in DIRECTIVE {
            assert!(
                table.contains(name),
                "directive 8.11.3 names {name} and the table does not"
            );
        }
        // Everything else in the table is the unsubscribe pair of a listed
        // subscription.
        let unsubscribes: Vec<&str> = table
            .iter()
            .copied()
            .filter(|n| n.ends_with("Unsubscribe"))
            .collect();
        assert_eq!(unsubscribes.len(), 5, "one unsubscribe per subscription");
        for name in &unsubscribes {
            let base = name.trim_end_matches("Unsubscribe");
            assert!(
                DIRECTIVE.iter().any(|d| d.starts_with(base) && d.ends_with("Subscribe")),
                "{name} has no matching subscription in the directive"
            );
        }
        assert_eq!(table.len(), DIRECTIVE.len() + unsubscribes.len());
    }

    #[test]
    fn every_row_is_distinct_and_the_order_is_the_directive_order() {
        let names: Vec<&str> = SOL_METHOD_CLASSES.iter().map(|m| m.name).collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "a method appears twice");
        // The reads the directive lists first stay first.
        assert_eq!(names[0], "getHealth");
        assert_eq!(names[1], "getVersion");
    }

    #[test]
    fn send_transaction_is_the_only_submission_beside_the_faucet_door() {
        let submitting: BTreeSet<&str> = SOL_METHOD_CLASSES
            .iter()
            .filter(|m| m.effect == TxSubmit)
            .map(|m| m.name)
            .collect();
        assert_eq!(
            submitting,
            BTreeSet::from(["sendTransaction", "requestAirdrop"]),
            "a Solana method that submits must be one of these two doors"
        );
    }

    #[test]
    fn the_subscriptions_are_node_local_and_never_reads() {
        for class in SOL_METHOD_CLASSES {
            if class.name.ends_with("Subscribe") || class.name.ends_with("Unsubscribe") {
                assert_eq!(
                    class.effect,
                    LocalAdmin,
                    "{} changes only this node's session table",
                    class.name
                );
            }
        }
    }

    #[test]
    fn the_startup_check_refuses_a_gap_in_either_direction() {
        let all: Vec<&str> = SOL_METHOD_CLASSES.iter().map(|m| m.name).collect();
        assert!(check_served_sol_methods(all.iter().copied()).is_ok());

        let mut extra = all.clone();
        extra.push("getRecentBlockhash");
        let err = check_served_sol_methods(extra).unwrap_err();
        assert!(
            err.contains("unclassified Solana RPC method served: getRecentBlockhash"),
            "{err}"
        );

        let missing = &all[1..];
        let err = check_served_sol_methods(missing.iter().copied()).unwrap_err();
        assert!(err.contains(&format!("missing from server: {}", all[0])), "{err}");
    }

    #[test]
    fn lookup_finds_a_row_and_refuses_an_unknown_name() {
        let class = lookup_sol_method("sendTransaction").expect("a listed method");
        assert_eq!(class.effect, TxSubmit);
        assert_eq!(class.listener, Public);
        assert!(lookup_sol_method("solana_getEverything").is_none());
    }
}
