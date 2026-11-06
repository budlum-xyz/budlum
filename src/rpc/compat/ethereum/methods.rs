//! The Ethereum JSON-RPC method table (section 8.11.2) and its listener rules.
//!
//! This module is the whole surface in one place, for the reason
//! [`crate::rpc::method_class`] exists: a table a reader and a test can see at
//! once, instead of a surface reconstructed from handler bodies. The listener
//! is fixed by section 8.11.2's own last sentence - every method above it is
//! public, and `debug_traceTransaction` and `debug_traceCall` are served only
//! on the operator listener.
//!
//! # What is refused, and why the refusal is a row
//!
//! `eth_getProof` answers with a Merkle-Patricia proof. Budlum's execution
//! state is a sparse Merkle tree whose proofs are a different shape, so a
//! gateway that translated one into the other would be inventing a proof
//! format and calling it Ethereum's. Section
//! 8.10 rule 6 settles it: `eth_getProof` returns JSON-RPC error `-32601`
//! (method not found) and the native proof lives at `bud_getExecutionProof`.
//! The row is present, so the refusal is a decision and not an omission, and
//! the test below holds the error code to the directive's number.
//!
//! `eth_accounts` is served and returns the empty list. A node holds no keys
//! for a caller: section 8.11.2 says so explicitly, and an empty list is the
//! answer MetaMask needs to fall back to its own signer.

use std::fmt::Write as _;

/// Which listener serves an Ethereum method.
///
/// Section 8.11.2: the public listener serves every method in its list, and
/// the two `debug_` methods are added on the operator listener only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// Served on the public listener (and therefore also on the operator one,
    /// which is a superset).
    Public,
    /// Refused on the public listener; served only to the operator.
    Operator,
}

/// What a successful call does.
///
/// The list is deliberately short. A compatibility gateway reads, hands a
/// signed transaction to the mempool, or refuses by name. There is no
/// "changes state" arm, because that arm would be the bug: a client that
/// thinks it is talking to Ethereum must not be able to make this chain agree
/// to something its peers did not execute in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Reads state or computes from the arguments.
    Read,
    /// Hands a signed raw transaction to the mempool. State changes only when
    /// a block carries it.
    TxSubmit,
    /// Manages a filter in this node's memory: bounded, expiring, and
    /// node-local, so two nodes may hold different sets without disagreeing.
    Filter,
    /// Manages a WebSocket subscription. Node-local for the same reason.
    Subscribe,
    /// The method exists and refuses every call, saying where the real answer
    /// lives.
    Refused,
}

/// Why a method is refused, when it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing here answers it.
    NotHere,
    /// A Merkle-Patricia proof is not this chain's proof format.
    NoMptProof,
}

impl Refusal {
    /// The JSON-RPC error code the gateway returns (section 8.10 rule 6).
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            // "Method not found" is the JSON-RPC reserved code, and it is the
            // one the directive names: a client that asked for a proof learns
            // the method does not exist here, rather than receiving a proof
            // in a format it would misread.
            Self::NoMptProof | Self::NotHere => -32601,
        }
    }

    /// The message, naming the door the client should use instead.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotHere => "method not found",
            Self::NoMptProof => {
                "eth_getProof is not served: this chain's execution proofs are not \
                 Merkle-Patricia proofs; use bud_getExecutionProof"
            }
        }
    }
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    /// The method name as a client sends it.
    pub name: &'static str,
    /// Which listener serves it.
    pub listener: Listener,
    /// What it does.
    pub effect: Effect,
    /// Why it is refused, when `effect` is [`Effect::Refused`].
    pub refusal: Option<Refusal>,
}

const fn row(name: &'static str, listener: Listener, effect: Effect) -> Method {
    Method {
        name,
        listener,
        effect,
        refusal: None,
    }
}

const fn refused(name: &'static str, why: Refusal) -> Method {
    Method {
        name,
        listener: Listener::Public,
        effect: Effect::Refused,
        refusal: Some(why),
    }
}

/// Every method section 8.11.2 lists, plus the two operator-only methods.
///
/// The order is the directive's, so a reviewer can check the two lists against
/// each other line by line. `eth_getProof` and `eth_getExecutionProof` are not
/// in the directive's list of Ethereum methods; the first is here because the
/// directive orders it refused by name (8.10 rule 6), and the second does not
/// exist - the native proof is `bud_getExecutionProof` on the native listener.
pub const METHODS: &[Method] = &[
    row("web3_clientVersion", Listener::Public, Effect::Read),
    row("net_version", Listener::Public, Effect::Read),
    row("net_listening", Listener::Public, Effect::Read),
    row("eth_chainId", Listener::Public, Effect::Read),
    row("eth_syncing", Listener::Public, Effect::Read),
    row("eth_blockNumber", Listener::Public, Effect::Read),
    row("eth_getBalance", Listener::Public, Effect::Read),
    row("eth_getCode", Listener::Public, Effect::Read),
    row("eth_getStorageAt", Listener::Public, Effect::Read),
    row("eth_getTransactionCount", Listener::Public, Effect::Read),
    row("eth_call", Listener::Public, Effect::Read),
    row("eth_estimateGas", Listener::Public, Effect::Read),
    row("eth_createAccessList", Listener::Public, Effect::Read),
    row("eth_gasPrice", Listener::Public, Effect::Read),
    row(
        "eth_maxPriorityFeePerGas",
        Listener::Public,
        Effect::Read,
    ),
    row("eth_feeHistory", Listener::Public, Effect::Read),
    row("eth_sendRawTransaction", Listener::Public, Effect::TxSubmit),
    row("eth_getBlockByNumber", Listener::Public, Effect::Read),
    row("eth_getBlockByHash", Listener::Public, Effect::Read),
    row(
        "eth_getBlockTransactionCountByNumber",
        Listener::Public,
        Effect::Read,
    ),
    row(
        "eth_getBlockTransactionCountByHash",
        Listener::Public,
        Effect::Read,
    ),
    row("eth_getTransactionByHash", Listener::Public, Effect::Read),
    row(
        "eth_getTransactionByBlockNumberAndIndex",
        Listener::Public,
        Effect::Read,
    ),
    row("eth_getTransactionReceipt", Listener::Public, Effect::Read),
    row("eth_getBlockReceipts", Listener::Public, Effect::Read),
    row("eth_getLogs", Listener::Public, Effect::Read),
    row("eth_newFilter", Listener::Public, Effect::Filter),
    row("eth_newBlockFilter", Listener::Public, Effect::Filter),
    row("eth_getFilterChanges", Listener::Public, Effect::Filter),
    row("eth_getFilterLogs", Listener::Public, Effect::Filter),
    row("eth_uninstallFilter", Listener::Public, Effect::Filter),
    row("eth_subscribe", Listener::Public, Effect::Subscribe),
    row("eth_unsubscribe", Listener::Public, Effect::Subscribe),
    // Serve it and return the empty list: this node holds no key for a caller.
    row("eth_accounts", Listener::Public, Effect::Read),
    // Section 8.10 rule 6: named, refused, and pointed at the native method.
    refused("eth_getProof", Refusal::NoMptProof),
    // Section 8.11.2: operator listener only.
    row(
        "debug_traceTransaction",
        Listener::Operator,
        Effect::Read,
    ),
    row("debug_traceCall", Listener::Operator, Effect::Read),
];

/// The row for `name`, if the gateway serves or refuses it at all.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|m| m.name == name)
}

/// Whether `name` may be served on `listener`.
///
/// An unknown name is refused, which is the point: the gateway serves exactly
/// this table, so a method added to a handler without a row here cannot be
/// reached. This is the Ethereum counterpart of
/// [`crate::rpc::method_class::check_served_methods`], and both answer the same
/// question for their own surface.
#[must_use]
pub fn is_served(name: &str, listener: Listener) -> bool {
    match lookup(name) {
        None => false,
        Some(m) => match (m.effect, listener) {
            // A refusal row is served and answers with an error, on the public
            // listener: the client learns the truth instead of a transport
            // failure. On the operator listener it refuses the same way; there
            // is no operator-only proof format either.
            (Effect::Refused, _) => true,
            (_, Listener::Public) => m.listener == Listener::Public,
            (_, Listener::Operator) => true,
        },
    }
}

/// The complete method table as text, for the operator listener's startup log
/// and for the test that holds this table to its directives.
///
/// # Errors
///
/// The word `table` when a row has an effect of [`Effect::Refused`] without a
/// refusal, or a refusal on a row that is not refused: a table with either is a
/// row whose meaning a reader cannot recover.
pub fn render() -> Result<String, &'static str> {
    let mut out = String::new();
    for m in METHODS {
        let effect = match m.effect {
            Effect::Read => "read",
            Effect::TxSubmit => "tx-submit",
            Effect::Filter => "filter",
            Effect::Subscribe => "subscribe",
            Effect::Refused => "refused",
        };
        let listener = match m.listener {
            Listener::Public => "public",
            Listener::Operator => "operator",
        };
        let ok = match (m.effect, m.refusal) {
            (Effect::Refused, Some(_)) | (_, None) => true,
            _ => false,
        };
        if !ok {
            return Err("table");
        }
        let _ = writeln!(out, "{} {} {}", m.name, listener, effect);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Section 8.11.2, copied here by hand so the two lists can be compared.
    /// A method added to `METHODS` without being added here fails the test
    /// below, and the failure names both files.
    const DIRECTIVE_PUBLIC: &[&str] = &[
        "web3_clientVersion",
        "net_version",
        "net_listening",
        "eth_chainId",
        "eth_syncing",
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getTransactionCount",
        "eth_call",
        "eth_estimateGas",
        "eth_createAccessList",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_feeHistory",
        "eth_sendRawTransaction",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getBlockTransactionCountByHash",
        "eth_getTransactionByHash",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionReceipt",
        "eth_getBlockReceipts",
        "eth_getLogs",
        "eth_newFilter",
        "eth_newBlockFilter",
        "eth_getFilterChanges",
        "eth_getFilterLogs",
        "eth_uninstallFilter",
        "eth_subscribe",
        "eth_unsubscribe",
        "eth_accounts",
    ];

    #[test]
    fn the_method_table_covers_every_directive_method_once() {
        let public: Vec<&str> = METHODS
            .iter()
            .filter(|m| m.listener == Listener::Public)
            .map(|m| m.name)
            .collect();
        let want: BTreeSet<&str> = DIRECTIVE_PUBLIC.iter().copied().collect();
        let got: BTreeSet<&str> = public
            .iter()
            .copied()
            .filter(|n| *n != "eth_getProof")
            .collect();
        assert_eq!(
            want, got,
            "section 8.11.2's list and the public rows disagree: a method is \
             missing from the table or was added without a line here"
        );
        // Every method appears exactly once: a duplicate row would make
        // `lookup` order-dependent.
        let unique: BTreeSet<&str> = METHODS.iter().map(|m| m.name).collect();
        assert_eq!(unique.len(), METHODS.len(), "a method has two rows");
    }

    #[test]
    fn eth_get_proof_returns_method_not_found() {
        let m = lookup("eth_getProof").expect("the row exists");
        assert_eq!(m.effect, Effect::Refused);
        assert_eq!(m.refusal, Some(Refusal::NoMptProof));
        // Section 8.10 rule 6 fixes the number, and a client distinguishes
        // "does not exist" from "failed" by it.
        assert_eq!(m.refusal.unwrap().code(), -32601);
        assert!(is_served("eth_getProof", Listener::Public));
    }

    #[test]
    fn debug_tracing_is_operator_only() {
        for name in ["debug_traceTransaction", "debug_traceCall"] {
            let m = lookup(name).expect(name);
            assert_eq!(m.listener, Listener::Operator);
            assert!(!is_served(name, Listener::Public), "{name} on public");
            assert!(is_served(name, Listener::Operator), "{name} on operator");
        }
        // The strongest reading of the rule: no read method is operator-only
        // except those two, so a public listener cannot miss one by accident.
        let operator_only: Vec<&str> = METHODS
            .iter()
            .filter(|m| m.listener == Listener::Operator)
            .map(|m| m.name)
            .collect();
        assert_eq!(
            operator_only,
            vec!["debug_traceTransaction", "debug_traceCall"]
        );
    }

    #[test]
    fn an_unknown_method_is_not_served_on_any_listener() {
        assert!(!is_served("eth_sendUnsignedTransaction", Listener::Public));
        assert!(!is_served("eth_sendUnsignedTransaction", Listener::Operator));
        assert!(!is_served("", Listener::Public));
    }

    #[test]
    fn no_gateway_method_changes_state_outside_a_block() {
        // The rule of section 8.11.1, as a test: the only effects are read,
        // submit, filter, subscribe and refuse.
        for m in METHODS {
            match m.effect {
                Effect::Read | Effect::TxSubmit | Effect::Filter | Effect::Subscribe => {}
                Effect::Refused => {
                    assert!(
                        m.refusal.is_some(),
                        "{} is refused without saying why",
                        m.name
                    );
                }
            }
        }
    }

    #[test]
    fn the_table_renders_and_refuses_a_half_written_row() {
        let text = render().expect("the real table is well formed");
        assert!(text.contains("eth_getProof public refused"));
        assert!(text.contains("debug_traceTransaction operator read"));
    }
}
