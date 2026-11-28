//! The Solana compatibility door, answered and refused on the real wire.
//!
//! The RPC coverage debt register records 42 rows of this surface as coverage gaps
//! (`.github/rpc-test-coverage-baseline.txt`). Every row is closed here:
//!
//! * the four read rows answer a chain fact through the real handler,
//! * the 21 refused rows answer `-32004` and name the native door,
//! * `getSlot`/`getBlockHeight`/`slotSubscribe` refuse a commitment config they
//!   cannot honor,
//! * the four SVM subscription rows are refused by name through the dedicated
//!   listener's own method table (`solana::dedicated_methods`), which is the
//!   exact `Methods` set that listener serves,
//! * the generated unsubscribe doors answer `result: false` for an unknown id.
//!
//! The wire calls go through `Methods::raw_json_request`, so the assertion is
//! made on the JSON-RPC response the listener really puts on the socket, not on
//! a re-implementation of it.

use crate::chain::blockchain::Blockchain;
use crate::chain::chain_actor::ChainActor;
use crate::consensus::pow::PoWEngine;
use crate::network::node::Node;
use crate::rpc::api::BudlumApiServer;
use crate::rpc::compat::solana;
use crate::rpc::server::RpcServer;
use jsonrpsee::core::server::Methods;
use jsonrpsee::types::error::ErrorObjectOwned;
use std::sync::Arc;

async fn server() -> RpcServer {
    let consensus = Arc::new(PoWEngine::new(0));
    let blockchain = Blockchain::new(consensus, None, 45262, None);
    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(async move {
        chain_actor.run().await;
    });
    let node = Node::new(chain.clone()).expect("node");
    RpcServer::new(chain, node.get_client())
}

/// The dedicated Solana listener's method table, built the way `RpcServer::run`
/// builds it before handing it to the listener.
async fn solana_methods() -> Methods {
    let all: Methods = server().await.into_rpc().into();
    solana::dedicated_methods(&all).expect("the Solana listener's method set")
}

/// The whole server's method table, for the native subscription doors.
async fn native_methods() -> Methods {
    server().await.into_rpc().into()
}

/// One JSON-RPC 2.0 call body.
fn body(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#)
}

/// The error object of a refused wire call. The caller reads `.code()` on the
/// same statement that names the method, which is what the coverage ratchet in
/// `src/rpc/method_class.rs` looks for.
async fn wire_refusal(module: &Methods, method: &str, params: &str) -> ErrorObjectOwned {
    let (response, _stream) = module
        .raw_json_request(&body(method, params), 8192)
        .await
        .expect("the wire call is answered");
    let answer: serde_json::Value =
        serde_json::from_str(response.get()).expect("the answer is a JSON-RPC response");
    serde_json::from_value::<ErrorObjectOwned>(answer["error"].clone())
        .expect("a refusal is a JSON-RPC error object")
}

/// The four read rows answer a fact this node really has.
#[tokio::test]
async fn solana_read_rows_answer_a_real_chain_fact() {
    let server = server().await;
    assert_eq!(
        server.solana_get_health().await.expect("getHealth answers"),
        "ok"
    );
    assert!(server
        .solana_get_version()
        .await
        .expect("getVersion answers")["solana-core"]
        .is_string());
    assert_eq!(
        server.solana_get_slot(None).await.expect("getSlot answers"),
        0
    );
    assert_eq!(
        server
            .solana_get_block_height(None)
            .await
            .expect("getBlockHeight answers"),
        0
    );
}

/// Every refused row answers `-32004` and names the native door for the fact.
#[tokio::test]
async fn solana_refused_rows_answer_minus_32004_and_name_the_native_door() {
    let server = server().await;
    let refused: [(&str, ErrorObjectOwned); 21] = [
        (
            "getGenesisHash",
            server.solana_get_genesis_hash().await.unwrap_err(),
        ),
        (
            "getEpochInfo",
            server.solana_get_epoch_info(None).await.unwrap_err(),
        ),
        (
            "getLatestBlockhash",
            server.solana_get_latest_blockhash(None).await.unwrap_err(),
        ),
        (
            "isBlockhashValid",
            server
                .solana_is_blockhash_valid(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getBalance",
            server
                .solana_get_balance(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getAccountInfo",
            server
                .solana_get_account_info(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getMultipleAccounts",
            server
                .solana_get_multiple_accounts(vec![String::from("x")], None)
                .await
                .unwrap_err(),
        ),
        (
            "getProgramAccounts",
            server
                .solana_get_program_accounts(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getTokenAccountsByOwner",
            server
                .solana_get_token_accounts_by_owner(String::from("x"), serde_json::json!({}), None)
                .await
                .unwrap_err(),
        ),
        (
            "getTokenAccountBalance",
            server
                .solana_get_token_account_balance(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getTokenSupply",
            server
                .solana_get_token_supply(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getMinimumBalanceForRentExemption",
            server
                .solana_get_minimum_balance_for_rent_exemption(0, None)
                .await
                .unwrap_err(),
        ),
        (
            "getFeeForMessage",
            server
                .solana_get_fee_for_message(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getRecentPrioritizationFees",
            server
                .solana_get_recent_prioritization_fees(None)
                .await
                .unwrap_err(),
        ),
        (
            "sendTransaction",
            server
                .solana_send_transaction(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "simulateTransaction",
            server
                .solana_simulate_transaction(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getSignatureStatuses",
            server
                .solana_get_signature_statuses(vec![String::from("x")], None)
                .await
                .unwrap_err(),
        ),
        (
            "getSignaturesForAddress",
            server
                .solana_get_signatures_for_address(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getTransaction",
            server
                .solana_get_transaction(String::from("x"), None)
                .await
                .unwrap_err(),
        ),
        (
            "getBlock",
            server.solana_get_block(0, None).await.unwrap_err(),
        ),
        (
            "requestAirdrop",
            server
                .solana_request_airdrop(String::from("x"), 0, None)
                .await
                .unwrap_err(),
        ),
    ];
    for (name, error) in &refused {
        assert_eq!(error.code(), solana::SOLANA_UNAVAILABLE, "{name}");
        let door = solana::native_door(name).unwrap_or("bud_getStatus");
        // `requestAirdrop` carries its door in `data`, not in the message.
        let in_data = error.data().is_some_and(|data| data.get().contains(door));
        assert!(
            error.message().contains(door) || in_data,
            "{name} must name {door}, said {} / {in_data}",
            error.message()
        );
    }
}

/// A commitment this gateway cannot honor is a refusal, not a silent default.
#[tokio::test]
async fn solana_slot_rows_refuse_a_commitment_they_cannot_honor() {
    let module = solana_methods().await;
    let bogus = r#"[{"commitment":"bogus"}]"#;
    let slot_err = wire_refusal(&module, "getSlot", bogus).await;
    assert_eq!(slot_err.code(), crate::rpc::compat::JSONRPC_INVALID_PARAMS);
    assert!(!slot_err.message().is_empty());
    let slot = wire_refusal(&module, "getSlot", bogus).await.code();
    assert_eq!(slot, crate::rpc::compat::JSONRPC_INVALID_PARAMS);
    let height = wire_refusal(&module, "getBlockHeight", bogus).await.code();
    assert_eq!(height, crate::rpc::compat::JSONRPC_INVALID_PARAMS);
    let feed = wire_refusal(&module, "slotSubscribe", bogus).await.code();
    assert_eq!(feed, crate::rpc::compat::JSONRPC_INVALID_PARAMS);
}

/// The SVM-dependent feeds are refused by name before any feed slot is taken.
#[tokio::test]
async fn solana_svm_subscriptions_are_refused_by_name() {
    let module = solana_methods().await;
    let account_err = wire_refusal(&module, "accountSubscribe", r#"["x"]"#).await;
    assert_eq!(account_err.code(), solana::SOLANA_UNAVAILABLE);
    assert!(!account_err.message().is_empty());
    let account = wire_refusal(&module, "accountSubscribe", r#"["x"]"#)
        .await
        .code();
    assert_eq!(account, solana::SOLANA_UNAVAILABLE);
    let signature = wire_refusal(&module, "signatureSubscribe", r#"["x"]"#)
        .await
        .code();
    assert_eq!(signature, solana::SOLANA_UNAVAILABLE);
    let logs = wire_refusal(&module, "logsSubscribe", r#"[{}]"#)
        .await
        .code();
    assert_eq!(logs, solana::SOLANA_UNAVAILABLE);
    let program = wire_refusal(&module, "programSubscribe", r#"["x"]"#)
        .await
        .code();
    assert_eq!(program, solana::SOLANA_UNAVAILABLE);
}

/// The one chain-backed feed is accepted, and its unsubscribe door answers a
/// boolean for an unknown id.
#[tokio::test]
async fn solana_slot_feed_is_accepted_and_unsubscribe_answers_false() {
    let module = solana_methods().await;
    let (accepted, _stream) = module
        .raw_json_request(&body("slotSubscribe", "[{}]"), 8192)
        .await
        .expect("slotSubscribe is accepted");
    let accepted: serde_json::Value =
        serde_json::from_str(accepted.get()).expect("the accept answer is JSON");
    assert!(
        accepted["result"].is_number(),
        "an accepted feed answers its subscription id: {accepted}"
    );
    let (off, _stream) = module
        .raw_json_request(&body("slotUnsubscribe", "[7]"), 8192)
        .await
        .expect("slotUnsubscribe answers");
    let off: serde_json::Value =
        serde_json::from_str(off.get()).expect("the unsubscribe answer is JSON");
    assert_eq!(off["result"], serde_json::json!(false));
}

/// The four remaining generated unsubscribe doors answer `false`, never an
/// error. This is the evidence for the `wants_refusal` exemption in
/// `src/rpc/method_class.rs`: jsonrpsee's unsubscribe callback always answers
/// `result: true/false`.
#[tokio::test]
async fn solana_unsubscribe_doors_answer_a_boolean_and_never_an_error() {
    let module = solana_methods().await;
    for name in [
        "accountUnsubscribe",
        "signatureUnsubscribe",
        "logsUnsubscribe",
        "programUnsubscribe",
    ] {
        let (answer, _stream) = module
            .raw_json_request(&body(name, "[7]"), 8192)
            .await
            .expect("the unsubscribe door answers");
        let answer: serde_json::Value =
            serde_json::from_str(answer.get()).expect("the answer is JSON");
        assert!(
            answer["error"].is_null(),
            "{name} is total: it answers a boolean, not a JSON-RPC error"
        );
        assert_eq!(answer["result"], serde_json::json!(false));
    }
}

/// The native subscription doors: a real feed kind is accepted, an unknown one
/// is refused, and the generated unsubscribe door answers a boolean.
#[tokio::test]
async fn native_subscription_doors_are_accepted_refused_and_unsubscribed() {
    let module = native_methods().await;
    let (heads, _stream) = module
        .raw_json_request(&body("bud_subscribe", r#"["newHeads"]"#), 8192)
        .await
        .expect("bud_subscribe accepts newHeads");
    let heads: serde_json::Value =
        serde_json::from_str(heads.get()).expect("the accept answer is JSON");
    assert!(
        heads["result"].is_number(),
        "an accepted feed answers its subscription id: {heads}"
    );
    let bogus_err = wire_refusal(&module, "bud_subscribe", r#"["bogus"]"#).await;
    assert!(!bogus_err.message().is_empty());
    let bogus = wire_refusal(&module, "bud_subscribe", r#"["bogus"]"#)
        .await
        .code();
    assert_eq!(bogus, crate::rpc::compat::JSONRPC_INVALID_PARAMS);
    let (off, _stream) = module
        .raw_json_request(&body("bud_unsubscribe", "[7]"), 8192)
        .await
        .expect("bud_unsubscribe answers");
    let off: serde_json::Value =
        serde_json::from_str(off.get()).expect("the unsubscribe answer is JSON");
    assert_eq!(off["result"], serde_json::json!(false));
}
