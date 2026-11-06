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
//! # What waits for 2/N
//!
//! The dedicated listener (`127.0.0.1:18548`, HTTP and WebSocket), the five
//! subscription methods (`accountSubscribe`, `signatureSubscribe`,
//! `slotSubscribe`, `logsSubscribe`, `programSubscribe`), the bounded
//! account subscription pool and the SVM worker. The subscriptions are in
//! the table and marked [`Answer::Pending`], so a client that asks for them
//! gets `-32601` from the dispatcher instead of a subscription table that
//! nothing bounds.
//!
//! # The three tables agree
//!
//! A method is served only when three places say the same thing:
//! [`METHODS`] here (listener and answer), the declaration in
//! `src/rpc/api.rs` (the wire name the client sends), and the row in
//! `src/rpc/method_class.rs` (listener and effect, checked at every server
//! start). The tests in [`tests`] compare all three, so a method cannot be
//! half-added.

use jsonrpsee::types::error::ErrorObjectOwned;

#[cfg(test)]
mod tests;

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
    MethodRow {
        name: "accountSubscribe",
        answer: Answer::Pending {
            package: "WP-31, 2/N",
        },
    },
    MethodRow {
        name: "signatureSubscribe",
        answer: Answer::Pending {
            package: "WP-31, 2/N",
        },
    },
    MethodRow {
        name: "slotSubscribe",
        answer: Answer::Pending {
            package: "WP-31, 2/N",
        },
    },
    MethodRow {
        name: "logsSubscribe",
        answer: Answer::Pending {
            package: "WP-31, 2/N",
        },
    },
    MethodRow {
        name: "programSubscribe",
        answer: Answer::Pending {
            package: "WP-31, 2/N",
        },
    },
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
