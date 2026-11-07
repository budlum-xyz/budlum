//! The Solana JSON-RPC compatibility gateway (WP-31, Section 8.11.3).
//!
//! # What this gateway is
//!
//! A Solana tool (web3.js, Anchor, the Solana CLI) speaks one vocabulary.
//! This gateway answers that vocabulary from Budlum state. It is not a
//! Solana node and it holds no state of its own: every answer is a read of
//! the same chain `bud_*` serves.
//!
//! # What is served today
//!
//! Delivery 1/N of WP-31 serves the methods whose answer is a node or chain
//! fact that does not require an SVM account model:
//!
//! * `getHealth`, `getVersion`, `getSlot`, `getBlockHeight`.
//!
//! Every method that needs the SVM account model, a token program, a
//! message fee or a transaction answers `-32004` and names the Budlum door
//! for the same fact. The reason is not caution, it is the dependency order
//! of Section 15.7: WP-31 depends on WP-26, and this node does not run the
//! SVM execution environment yet. An answer invented from the Budlum account
//! ledger would report a balance for an address whose SVM account does not
//! exist, and a wallet sizing a transfer from it would send a transaction
//! the chain refuses. A refusal that names the door is true; a plausible
//! number is not.
//!
//! # What waits for the SVM worker
//!
//! The SVM account model, token programs, transaction execution and their
//! four state-dependent subscriptions. `slotSubscribe` is served from the
//! Budlum chain; the other four subscriptions refuse by name before a
//! subscription id or feed task is created.
//!
//! # The three tables agree
//!
//! A method is served only when three places say the same thing:
//! [`METHODS`] here (listener and answer), the declaration in
//! `src/rpc/api.rs` (the wire name the client sends), and the row in
//! `src/rpc/method_class.rs` (listener and effect, checked at every server
//! start). The tests in [`tests`] compare all three, so a method cannot be
//! half-added.
//!
//! exposed for: Solana JSON-RPC and WebSocket compatibility router (`WP-28`, `WP-51`).

use jsonrpsee::types::error::ErrorObjectOwned;

#[cfg(test)]
mod tests;
pub mod subscriptions;

/// The code for a method this node cannot answer, with the door named in
/// the message and in the error data.
///
/// `-32004` is the server-defined range, the same code `require_operator`
/// uses for the operator listener. The two are told apart by the message and
/// by the `door` field, never by the code alone.
const EE_UNAVAILABLE: i32 = -32004;

/// What a method answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Read from chain state. No execution environment is involved, so the
    /// answer is the same on every node at the same block.
    ChainRead,
    /// `-32004`, naming the Budlum door that replaces the method.
    EeUnavailable {
        /// The `bud_*` method that answers the same question on Budlum.
        door: &'static str,
    },
    /// A chain-backed WebSocket feed. Its unsubscribe door is node-local.
    Subscription,
    /// The matching unsubscribe door of a subscription.
    Unsubscribe,
    /// Not served yet. A client gets `-32601` from the dispatcher.
    Pending {
        /// The work package and delivery that serves it.
        package: &'static str,
    },
}

/// One row of the gateway table.
///
/// The listener column is not here: `src/rpc/method_class.rs` holds it, and
/// the tests hold the two tables to the same answer. One copy of a fact does
/// not drift from itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MethodRow {
    /// The wire name, exactly as a client sends it.
    name: &'static str,
    /// What a successful call does.
    answer: Answer,
}

/// The Solana subset of Section 8.11.3, in the order that section lists
/// it, then the five WebSocket subscriptions of the same section.
const METHODS: &[MethodRow] = &[
    MethodRow {
        name: "getHealth",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "getVersion",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "getGenesisHash",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "getSlot",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "getBlockHeight",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "getEpochInfo",
        answer: Answer::EeUnavailable {
            door: "bud_getStatus",
        },
    },
    MethodRow {
        name: "getLatestBlockhash",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "isBlockhashValid",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "getBalance",
        answer: Answer::EeUnavailable {
            door: "bud_getBalance",
        },
    },
    MethodRow {
        name: "getAccountInfo",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "getMultipleAccounts",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "getProgramAccounts",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "getTokenAccountsByOwner",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "getTokenAccountBalance",
        answer: Answer::EeUnavailable {
            door: "bud_getBalance",
        },
    },
    MethodRow {
        name: "getTokenSupply",
        answer: Answer::EeUnavailable {
            door: "bud_getStatus",
        },
    },
    MethodRow {
        name: "getMinimumBalanceForRentExemption",
        answer: Answer::EeUnavailable {
            door: "bud_getStatus",
        },
    },
    MethodRow {
        name: "getFeeForMessage",
        answer: Answer::EeUnavailable {
            door: "bud_gasPrice",
        },
    },
    MethodRow {
        name: "getRecentPrioritizationFees",
        answer: Answer::EeUnavailable {
            door: "bud_gasPrice",
        },
    },
    MethodRow {
        name: "sendTransaction",
        answer: Answer::EeUnavailable {
            door: "bud_sendRawTransaction",
        },
    },
    MethodRow {
        name: "simulateTransaction",
        answer: Answer::EeUnavailable {
            door: "bud_txPrecheck",
        },
    },
    MethodRow {
        name: "getSignatureStatuses",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionReceipt",
        },
    },
    MethodRow {
        name: "getSignaturesForAddress",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionByHash",
        },
    },
    MethodRow {
        name: "getTransaction",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionByHash",
        },
    },
    MethodRow {
        name: "getBlock",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "requestAirdrop",
        answer: Answer::EeUnavailable {
            door: "bud_sendRawTransaction",
        },
    },
    MethodRow { name: "accountSubscribe", answer: Answer::EeUnavailable { door: "bud_getAccountProof" } },
    MethodRow { name: "accountUnsubscribe", answer: Answer::Unsubscribe },
    MethodRow { name: "signatureSubscribe", answer: Answer::EeUnavailable { door: "bud_getTransactionReceipt" } },
    MethodRow { name: "signatureUnsubscribe", answer: Answer::Unsubscribe },
    MethodRow { name: "slotSubscribe", answer: Answer::Subscription },
    MethodRow { name: "slotUnsubscribe", answer: Answer::Unsubscribe },
    MethodRow { name: "logsSubscribe", answer: Answer::EeUnavailable { door: "bud_getTransactionReceipt" } },
    MethodRow { name: "logsUnsubscribe", answer: Answer::Unsubscribe },
    MethodRow { name: "programSubscribe", answer: Answer::EeUnavailable { door: "bud_getAccountProof" } },
    MethodRow { name: "programUnsubscribe", answer: Answer::Unsubscribe },
];

/// The row for a wire name, or `None` when the gateway does not list it.
fn row(name: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|row| row.name == name)
}

/// The namespaces this gateway owns. A method in one of them is answered by
/// [`METHODS`] or it is not answered at all.
///
/// The Solana wire names are bare (`getBalance`, not `solana_getBalance`),
/// so the exact table is the namespace. The `solana_` prefix is reserved for
/// a future name that is not in the table yet: it is treated as in the
/// namespace so the startup check refuses it rather than letting it through
/// unclassified.
pub fn owns_method(name: &str) -> bool {
    namespace_of(name)
}

/// The method set for the dedicated Solana listener: exactly the served rows
/// of this gateway, copied from the already-registered production callbacks.
pub fn dedicated_methods(
    all: &jsonrpsee::core::server::Methods,
) -> Result<jsonrpsee::core::server::Methods, String> {
    let mut out = jsonrpsee::core::server::Methods::new();
    for name in all.method_names() {
        if !owns_method(name) {
            continue;
        }
        let callback = all
            .method(name)
            .ok_or_else(|| format!("Solana method {name} disappeared while filtering"))?
            .clone();
        out.verify_and_insert(name, callback)
            .map_err(|e| format!("register dedicated Solana method {name}: {e}"))?;
    }
    check_served(out.method_names())?;
    Ok(out)
}

/// Whether this name is one of the five generated unsubscribe doors.
/// exposed for: Solana WebSocket unsubscribe method dispatch (`WP-51`).
#[must_use]
pub fn is_unsubscribe(name: &str) -> bool {
    row(name).is_some_and(|entry| entry.answer == Answer::Unsubscribe)
}

fn namespace_of(name: &str) -> bool {
    METHODS.iter().any(|row| row.name == name) || name.starts_with("solana_")
}

/// Check the Solana names a listener serves against this gateway's table.
///
/// `src/rpc/method_class.rs` calls this at every server start, next to the
/// Budlum class check, so a foreign method cannot be served before the
/// gateway says what it answers and cannot be served while its row still
/// says [`Answer::Pending`].
///
/// # Errors
///
/// Names every foreign method with no row, and every served method whose row
/// is pending.
pub fn check_served<'a>(registered: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let mut problems = Vec::new();
    for name in registered {
        if !namespace_of(name) {
            continue;
        }
        match row(name) {
            None => problems.push(format!("{name} has no Solana gateway row")),
            Some(entry) => {
                if let Answer::Pending { package } = entry.answer {
                    problems.push(format!("{name} is served, its row waits for {package}"));
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// The `-32004` refusal: the method needs an execution environment this node
/// does not run, and the Budlum door for the same fact is `door`.
///
/// The message is one line so a client's log shows the door next to the
/// method. The long version is in `docs/SOLANA_RPC.md`.
pub fn ee_unavailable(method: &str, door: &'static str) -> ErrorObjectOwned {
    let message = format!("{method}: no SVM execution environment (WP-31); use {door}");
    ErrorObjectOwned::owned(
        EE_UNAVAILABLE,
        message,
        Some(serde_json::json!({ "door": door, "package": "WP-31" })),
    )
}

/// The `-32004` refusal for a chain fact this node does not expose in the
/// Solana shape yet. The door is a Budlum read that carries the same fact or
/// the closest fact; the message does not blame the SVM for a chain gap.
pub fn not_exposed(method: &str, door: &'static str) -> ErrorObjectOwned {
    let message = format!("{method}: not exposed on this node yet; use {door}");
    ErrorObjectOwned::owned(
        EE_UNAVAILABLE,
        message,
        Some(serde_json::json!({ "door": door, "package": "WP-31" })),
    )
}

/// The `-32004` refusal for `requestAirdrop`: the faucet is a separate
/// service (WP-41), not an SVM program, and this node does not mint.
pub fn faucet_unavailable(method: &str) -> ErrorObjectOwned {
    let message = format!("{method}: testnet only; use the Budlum faucet (WP-41)");
    ErrorObjectOwned::owned(
        EE_UNAVAILABLE,
        message,
        Some(serde_json::json!({ "door": "bud_sendRawTransaction", "package": "WP-41" })),
    )
}
