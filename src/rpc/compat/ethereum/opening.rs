//! The Ethereum JSON-RPC compatibility gateway (WP-28, Section 8.11).
//!
//! # What this gateway is
//!
//! An Ethereum tool (Foundry, Hardhat, viem, ethers, MetaMask) speaks one
//! vocabulary. This gateway answers that vocabulary from Budlum state. It is
//! not an Ethereum node and it holds no state of its own: every answer is a
//! read of the same chain `bud_*` serves.
//!
//! # What is served today
//!
//! Delivery 1/2 of WP-28 serves the methods whose answer is a chain-level
//! fact on every node:
//!
//! * `web3_clientVersion`, `net_version`, `net_listening`,
//! * `eth_chainId`, `eth_syncing`, `eth_blockNumber`, `eth_accounts`,
//! * `eth_gasPrice`, `eth_maxPriorityFeePerGas`.
//!
//! Every method that needs the EVM state answers `-32004` and names the
//! Budlum door for the same fact. The reason is not caution, it is the
//! dependency order of Section 15.7: WP-28 depends on WP-27, and this opening
//! RPC surface does not expose a validated end-to-end EVM execution
//! environment. An answer invented from
//! the Budlum account ledger would report a balance for an address whose EVM
//! account does not exist, and a wallet sizing a transfer from it would send
//! a transaction the chain refuses. A refusal that names the door is true; a
//! plausible number is not.
//!
//! `eth_getProof` is not a refusal and not a wait: Section 8.10.6 makes it
//! `-32601` for good at the opening layer, because the Budlum state root is not an
//! MPT root and an MPT proof over it would be a false proof. The Budlum
//! native proof is `bud_getAccountProof`.
//!
//! # What delivery 2/N adds
//!
//! [`filters`] is the bounded, expiring, per-peer filter table the card asks
//! for. The five filter methods now admit filters through it. A read of a
//! filter still answers `-32004`: log data needs the EVM execution environment
//! of WP-27, and an empty change list would be a false answer.
//!
//! # What still waits
//!
//! The dedicated listeners (`127.0.0.1:18547`, HTTP and WebSocket), the
//! subscription pool, the block and receipt shapes with `stateRoot` set to
//! `execution_root`, and the nightly tool tests. `eth_subscribe` and
//! `eth_unsubscribe` stay in the table marked [`Answer::Pending`], so a client
//! that asks for them gets `-32601` from the dispatcher. Those rows name their
//! owner package in the error, not a delivery number that has already landed.
//!
//! # The three tables agree
//!
//! A method is served only when three places say the same thing:
//! [`METHODS`] here (listener and answer), the declaration in
//! `src/rpc/api.rs` (the wire name the client sends), and the row in
//! `src/rpc/method_class.rs` (listener and effect, checked at every server
//! start). The unit tests compare all three, so a method cannot be
//! half-added.

use jsonrpsee::types::error::ErrorObjectOwned;

pub use super::filters;
#[cfg(test)]
mod tests;

/// The code for a method this node cannot answer, with the door named in the
/// message and in the error data.
///
/// `-32004` is the server-defined range, the same code `require_operator`
/// uses for the operator listener. The two are told apart by the message and
/// by the `door` field, never by the code alone.
const EE_UNAVAILABLE: i32 = -32004;

/// The JSON-RPC code for a method a gateway deliberately does not serve.
const METHOD_NOT_FOUND: i32 = -32601;

/// What a method answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Read from chain state. No execution environment is involved, so the
    /// answer is the same on every node at the same block.
    ChainRead,
    /// `-32601` on purpose (Section 8.10.6: `eth_getProof`).
    MethodNotFound,
    /// `-32004`, naming the Budlum door that replaces the method.
    EeUnavailable {
        /// The `bud_*` method that answers the same question on Budlum.
        door: &'static str,
    },
    /// Creation or removal of one record in the bounded filter table. These
    /// successful calls perform node-local administration, so their class is
    /// `LocalAdmin`.
    BoundedFilter,
    /// Validation of a bounded filter followed by the honest WP-27 refusal.
    /// No successful log response exists yet, so these rows stay `Refused`
    /// instead of implying that a success behavior can be covered.
    BoundedFilterRead,
    /// Not served yet. A client gets `-32601` from the dispatcher.
    Pending {
        /// The work left before this row can be served.
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

/// The Ethereum subset of Section 8.11.2, in the order that section lists
/// it, then `eth_getProof` (Section 8.10.6) and the two operator methods.
const METHODS: &[MethodRow] = &[
    MethodRow {
        name: "web3_clientVersion",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "net_version",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "net_listening",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_chainId",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_syncing",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_blockNumber",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_getBalance",
        answer: Answer::EeUnavailable {
            door: "bud_getBalance",
        },
    },
    MethodRow {
        name: "eth_getCode",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "eth_getStorageAt",
        answer: Answer::EeUnavailable {
            door: "bud_getAccountProof",
        },
    },
    MethodRow {
        name: "eth_getTransactionCount",
        answer: Answer::EeUnavailable {
            door: "bud_getNonce",
        },
    },
    MethodRow {
        name: "eth_call",
        answer: Answer::EeUnavailable {
            door: "bud_txPrecheck",
        },
    },
    MethodRow {
        name: "eth_estimateGas",
        answer: Answer::EeUnavailable {
            door: "bud_estimateGas",
        },
    },
    MethodRow {
        name: "eth_createAccessList",
        answer: Answer::EeUnavailable {
            door: "bud_txPrecheck",
        },
    },
    MethodRow {
        name: "eth_gasPrice",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_maxPriorityFeePerGas",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "eth_feeHistory",
        answer: Answer::EeUnavailable {
            door: "bud_gasPrice",
        },
    },
    MethodRow {
        name: "eth_sendRawTransaction",
        answer: Answer::EeUnavailable {
            door: "bud_sendRawTransaction",
        },
    },
    MethodRow {
        name: "eth_getBlockByNumber",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "eth_getBlockByHash",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByHash",
        },
    },
    MethodRow {
        name: "eth_getBlockTransactionCountByNumber",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "eth_getBlockTransactionCountByHash",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByHash",
        },
    },
    MethodRow {
        name: "eth_getTransactionByHash",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionByHash",
        },
    },
    MethodRow {
        name: "eth_getTransactionByBlockNumberAndIndex",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "eth_getTransactionReceipt",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionReceipt",
        },
    },
    MethodRow {
        name: "eth_getBlockReceipts",
        answer: Answer::EeUnavailable {
            door: "bud_getBlockByNumber",
        },
    },
    MethodRow {
        name: "eth_getLogs",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionReceipt",
        },
    },
    MethodRow {
        name: "eth_newFilter",
        answer: Answer::BoundedFilter,
    },
    MethodRow {
        name: "eth_newBlockFilter",
        answer: Answer::BoundedFilter,
    },
    MethodRow {
        name: "eth_getFilterChanges",
        answer: Answer::BoundedFilterRead,
    },
    MethodRow {
        name: "eth_getFilterLogs",
        answer: Answer::BoundedFilterRead,
    },
    MethodRow {
        name: "eth_uninstallFilter",
        answer: Answer::BoundedFilter,
    },
    MethodRow {
        name: "eth_subscribe",
        answer: Answer::Pending {
            package: "WP-28 subscription listener and WP-27 log data",
        },
    },
    MethodRow {
        name: "eth_unsubscribe",
        answer: Answer::Pending {
            package: "WP-28 subscription listener and WP-27 log data",
        },
    },
    MethodRow {
        name: "eth_accounts",
        answer: Answer::ChainRead,
    },
    MethodRow {
        name: "debug_traceTransaction",
        answer: Answer::EeUnavailable {
            door: "bud_getTransactionReceipt",
        },
    },
    MethodRow {
        name: "debug_traceCall",
        answer: Answer::EeUnavailable {
            door: "bud_txPrecheck",
        },
    },
    MethodRow {
        name: "eth_getProof",
        answer: Answer::MethodNotFound,
    },
];

/// The row for a wire name, or `None` when the gateway does not list it.
fn row(name: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|row| row.name == name)
}

/// The namespaces this gateway owns. A method in one of them is answered by
/// [`METHODS`] or it is not answered at all.
fn namespace_of(name: &str) -> bool {
    name.starts_with("eth_")
        || name.starts_with("net_")
        || name.starts_with("web3_")
        || name.starts_with("debug_")
}

/// Check the Ethereum names a listener serves against this gateway's table.
///
/// `src/rpc/method_class.rs` calls this at every server start, next to the
/// Budlum class check, so a foreign method cannot be served before the
/// gateway says what it answers and cannot be served while its row still says
/// [`Answer::Pending`].
///
/// # Errors
///
/// Names every foreign method with no row, and every served method whose row
/// is pending.
pub(crate) fn check_served<'a>(registered: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let mut problems = Vec::new();
    for name in registered {
        if !namespace_of(name) {
            continue;
        }
        match row(name) {
            None => problems.push(format!("{name} has no Ethereum gateway row")),
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

/// The `-32004` refusal: the method needs an execution environment unavailable
/// on this RPC surface, and the Budlum door for the same fact is `door`.
///
/// The message is one line so a client's log shows the door next to the
/// method. The long version is in `docs/RPC_COMPAT.md`.
pub(crate) fn ee_unavailable(method: &str, door: &'static str) -> ErrorObjectOwned {
    let message = format!(
        "{method}: EVM execution environment is not available on this RPC surface (WP-27); use {door}"
    );
    ErrorObjectOwned::owned(
        EE_UNAVAILABLE,
        message,
        Some(serde_json::json!({ "door": door, "package": "WP-27" })),
    )
}

/// Turn a bounded-filter failure into a JSON-RPC error.
///
/// The reason is machine-readable, so a wallet can tell a quota refusal from
/// a missing execution environment. The door is present only for the reason
/// that has a Budlum answer, and `WP-27` names the package that will remove
/// the refusal.
pub(crate) fn filter_error(method: &str, error: filters::FilterError) -> ErrorObjectOwned {
    let mut data = serde_json::json!({ "reason": error.reason() });
    if let Some(door) = error.door() {
        data["door"] = serde_json::Value::String(door.to_string());
        data["package"] = serde_json::Value::String("WP-27".to_string());
    }
    ErrorObjectOwned::owned(
        error.code(),
        format!("{method}: {}", error.message()),
        Some(data),
    )
}

/// The `-32601` answer Section 8.10.6 requires for `eth_getProof`: the Budlum
/// state root is not an MPT root, so an MPT proof over it would prove nothing.
pub(crate) fn proof_is_not_an_mpt_proof() -> ErrorObjectOwned {
    let message = "eth_getProof: not an MPT proof (Section 8.10.6); use bud_getAccountProof";
    ErrorObjectOwned::owned(
        METHOD_NOT_FOUND,
        message,
        Some(serde_json::json!({ "door": "bud_getAccountProof" })),
    )
}
