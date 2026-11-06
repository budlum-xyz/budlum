//! The Ethereum gateway's surface, held to section 8.11.2.
//!
//! These are the tests the directive names for WP-28's table and bounds, plus
//! the one negative test the refusal row exists for. They live here rather than
//! beside the module because the question they ask is about the *published*
//! surface: a method a client may call, an error code a client reads, and a
//! bound a stranger cannot cross. The module's own tests hold the internals;
//! these hold the contract.

use crate::rpc::compat::ethereum::config::{
    Config, ConfigError, DEFAULT_LISTEN, DEFAULT_PORT, FOREIGN_ETHEREUM_CHAIN_ID,
};
use crate::rpc::compat::ethereum::limits::{
    FilterBudget, FilterRefused, InstalledFilter, MAX_FILTERS_PER_PEER, MAX_FILTERS_TOTAL,
    MAX_FILTER_TTL_BLOCKS,
};
use crate::rpc::compat::ethereum::methods::{self, Effect, Listener};

/// Section 8.11.2's list, in its own order, so a reader can compare the two
/// side by side. `eth_getProof` is added because section 8.10 rule 6 orders it
/// refused by name, and the two `debug_` methods because section 8.11.2's last
/// sentence puts them on the operator listener.
const DIRECTIVE: &[(&str, Listener)] = &[
    ("web3_clientVersion", Listener::Public),
    ("net_version", Listener::Public),
    ("net_listening", Listener::Public),
    ("eth_chainId", Listener::Public),
    ("eth_syncing", Listener::Public),
    ("eth_blockNumber", Listener::Public),
    ("eth_getBalance", Listener::Public),
    ("eth_getCode", Listener::Public),
    ("eth_getStorageAt", Listener::Public),
    ("eth_getTransactionCount", Listener::Public),
    ("eth_call", Listener::Public),
    ("eth_estimateGas", Listener::Public),
    ("eth_createAccessList", Listener::Public),
    ("eth_gasPrice", Listener::Public),
    ("eth_maxPriorityFeePerGas", Listener::Public),
    ("eth_feeHistory", Listener::Public),
    ("eth_sendRawTransaction", Listener::Public),
    ("eth_getBlockByNumber", Listener::Public),
    ("eth_getBlockByHash", Listener::Public),
    ("eth_getBlockTransactionCountByNumber", Listener::Public),
    ("eth_getBlockTransactionCountByHash", Listener::Public),
    ("eth_getTransactionByHash", Listener::Public),
    ("eth_getTransactionByBlockNumberAndIndex", Listener::Public),
    ("eth_getTransactionReceipt", Listener::Public),
    ("eth_getBlockReceipts", Listener::Public),
    ("eth_getLogs", Listener::Public),
    ("eth_newFilter", Listener::Public),
    ("eth_newBlockFilter", Listener::Public),
    ("eth_getFilterChanges", Listener::Public),
    ("eth_getFilterLogs", Listener::Public),
    ("eth_uninstallFilter", Listener::Public),
    ("eth_subscribe", Listener::Public),
    ("eth_unsubscribe", Listener::Public),
    ("eth_accounts", Listener::Public),
    ("eth_getProof", Listener::Public),
    ("debug_traceTransaction", Listener::Operator),
    ("debug_traceCall", Listener::Operator),
];

/// `eth_rpc_method_table_is_complete`: every method the directive lists is in
/// the table, on the listener the directive names, and the table holds nothing
/// else.
#[test]
fn eth_rpc_method_table_is_complete() {
    for (name, listener) in DIRECTIVE {
        let row = methods::lookup(name)
            .unwrap_or_else(|| panic!("section 8.11.2 lists {name}; the table does not"));
        assert_eq!(row.listener, *listener, "{name} is on the wrong listener");
    }
    for row in methods::METHODS {
        assert!(
            DIRECTIVE.iter().any(|(n, _)| *n == row.name),
            "{} is served but section 8.11.2 does not list it; either the \
             directive changed or a method was added without a line there",
            row.name
        );
    }
}

/// `eth_get_proof_returns_method_not_found`: the refusal is a decision, and the
/// code is the directive's, not a transport failure a client would retry.
#[test]
fn eth_get_proof_returns_method_not_found() {
    let row = methods::lookup("eth_getProof").expect("the refusal row exists");
    assert_eq!(row.effect, Effect::Refused);
    let refusal = row.refusal.expect("a refused row says why");
    assert_eq!(
        refusal.code(),
        -32601,
        "section 8.10 rule 6 fixes the code at -32601"
    );
    assert!(
        refusal.message().contains("bud_getExecutionProof"),
        "the refusal names the door that does answer: {}",
        refusal.message()
    );
    // Served, not absent: the client reaches the answer and reads the reason.
    assert!(methods::is_served("eth_getProof", Listener::Public));
}

/// `eth_filters_are_bounded`: a stranger holds a bounded number of filters, a
/// filter he stops polling expires by chain height, and the sweep reclaims it.
#[test]
fn eth_filters_are_bounded() {
    let mut budget = FilterBudget::new();
    for id in 0..u64::try_from(MAX_FILTERS_PER_PEER).unwrap() {
        budget.install(id, "203.0.113.7", 0).expect("within the cap");
    }
    let refused = budget
        .install(500, "203.0.113.7", 0)
        .expect_err("the cap holds");
    assert_eq!(refused, FilterRefused::PerPeer);
    assert_eq!(refused.code(), -32005);

    // The ttl is a chain height, so the same sequence of heights gives the same
    // answer on every node, whatever the wall clock did between the calls.
    let mut quiet = FilterBudget::new();
    quiet.install(1, "peer", 1000).expect("install");
    assert!(quiet.poll(1, 1000 + MAX_FILTER_TTL_BLOCKS).is_some());
    assert!(quiet.poll(1, 1000 + 2 * MAX_FILTER_TTL_BLOCKS + 1).is_none());
    assert!(quiet.is_empty(), "an expired filter is reclaimed");
}

/// No method a compatibility gateway serves changes consensus state. This is
/// section 8.11.1's rule and the reason [`Effect`] has no arm for it.
#[test]
fn no_gateway_method_writes_consensus_state() {
    for row in methods::METHODS {
        match row.effect {
            Effect::Read | Effect::TxSubmit | Effect::Filter | Effect::Subscribe => {}
            Effect::Refused => assert!(row.refusal.is_some(), "{}", row.name),
        }
    }
}

/// The node-wide bound is real and it is not the same number as the per-peer
/// one: a peer can fill its own share and the node still has room, and the
/// total is what stops the sum.
#[test]
fn the_node_filter_budget_is_larger_than_one_peer_share() {
    assert!(
        MAX_FILTERS_TOTAL > MAX_FILTERS_PER_PEER,
        "a total at or below the per-peer cap would make the per-peer cap dead"
    );
    // The half-written row the table refuses: an expiry that reads as a
    // description of the filter rather than of its age.
    let fresh = InstalledFilter {
        installed_at: 10,
        polled_at: 10,
    };
    assert!(!fresh.is_expired(10));
    assert!(fresh.is_expired(10 + MAX_FILTER_TTL_BLOCKS + 1));
}

/// `eth_gateway_binds_loopback_only`: section 8.11.1's port table, enforced
/// rather than documented. A public bind is refused by name, and the foreign
/// chain id is a separate constant from this chain's answer so that neither can
/// be changed by editing the other.
#[test]
fn eth_gateway_binds_loopback_only() {
    let default = Config::default();
    assert_eq!(default.listen, DEFAULT_LISTEN);
    assert_eq!(default.port(), Ok(DEFAULT_PORT));
    assert_eq!(default.validate(), Ok(()));

    assert_eq!(
        Config::new("0.0.0.0:18547").validate(),
        Err(ConfigError::NotLoopback)
    );
    assert_eq!(
        Config::new("127.0.0.1:18545").validate(),
        Err(ConfigError::PortCollision),
        "the native listener's port is not a gateway's"
    );
    // The foreign envelope's identity is not this chain's id.
    assert_eq!(FOREIGN_ETHEREUM_CHAIN_ID, 45261);
}
