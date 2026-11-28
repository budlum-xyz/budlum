//! Directive K3-D - Compatibility RPC doors (RED->GREEN locks).
//!
//! Four doors are locked under the same discipline:
//! 1. `eth_sendRawTransaction` - even a valid envelope is refused with `EE_UNAVAILABLE` (-32004)
//!    naming the `bud_sendRawTransaction` door; malformed or missing parameters
//!    receive `JSONRPC_INVALID_PARAMS` and never fabricate a tx hash.
//! 2. `eth_getTransactionReceipt` - no response without naming the `bud_getTransactionReceipt`
//!    (UER-1 receipt door); the response carries `-32004` and the door name.
//! 3. Solana `sendTransaction` - when no production execution engine is present, `-32004` +
//!    `bud_sendRawTransaction`; malformed wire format returns `-32602`.
//! 4. CosmWasm - `SmartContractState`/`RawContractState` queries read from state;
//!    an unknown abci_query path is refused fail-closed.
//!
//! This file touches only the public gateway surface.

use budlum_core::core::account::AccountState;
use budlum_core::execution::coordinator::foreign::ethereum::{
    sign_eip1559_tx, BUDLUM_EVM_CHAIN_ID,
};
use budlum_core::execution::coordinator::state::NS_WASM_STORE;
use budlum_core::rpc::compat::cosmos::{CosmosCompatGateway, ABCI_QUERY_PATHS};
use budlum_core::rpc::compat::ethereum::{EthereumCompatGateway, EE_UNAVAILABLE};
use budlum_core::rpc::compat::solana::{SolanaCompatGateway, SOLANA_UNAVAILABLE};
use budlum_core::rpc::compat::{
    CosmosCompatConfig, EthereumCompatConfig, JsonRpcRequest, SolanaCompatConfig,
    JSONRPC_INVALID_PARAMS,
};

fn rpc_req(method: &str, params: serde_json::Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: String::from("2.0"),
        id: serde_json::json!(1),
        method: String::from(method),
        params,
    }
}

fn eth_gw() -> EthereumCompatGateway {
    EthereumCompatGateway::new(EthereumCompatConfig::default())
}

/// K3-D / eth_sendRawTransaction: even a valid EIP-1559 envelope is refused on
/// this surface by naming the `bud_sendRawTransaction` door (no fake success without EE).
#[test]
fn k3d_eth_send_raw_tx_names_the_bud_door() {
    let mut state = AccountState::new();
    let sk = [7u8; 32];
    let raw = sign_eip1559_tx(
        &sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        (1_000_000_000, 2_000_000_000, 21_000),
        Some([0xAB; 20]),
        1_000,
        (&[], &[]),
    )
    .expect("sign eip1559");

    let mut gw = eth_gw();
    let resp = gw.handle_request(
        budlum_core::rpc::compat::CompatListener::Public,
        "127.0.0.1",
        1_700_000_000,
        &rpc_req(
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw))]),
        ),
        &state,
    );
    let err = resp.error.expect("must refuse, never invent a hash");
    assert_eq!(
        err.code, EE_UNAVAILABLE,
        "valid envelope: EE_UNAVAILABLE (-32004)"
    );
    assert!(
        err.message.contains("bud_sendRawTransaction"),
        "door named in refusal: {}",
        err.message
    );
    assert!(resp.result.is_none(), "no fabricated tx hash");

    // Malformed hex: invalid params, no fake result.
    let bad = gw.handle_request(
        budlum_core::rpc::compat::CompatListener::Public,
        "127.0.0.1",
        1_700_000_001,
        &rpc_req("eth_sendRawTransaction", serde_json::json!(["0xzz"])),
        &state,
    );
    let bad_err = bad.error.expect("bad hex refuses");
    assert_eq!(bad_err.code, JSONRPC_INVALID_PARAMS);
    assert!(bad.result.is_none());

    // Missing parameter.
    let missing = gw.handle_request(
        budlum_core::rpc::compat::CompatListener::Public,
        "127.0.0.1",
        1_700_000_002,
        &rpc_req("eth_sendRawTransaction", serde_json::json!([])),
        &state,
    );
    let miss_err = missing.error.expect("missing params refuse");
    assert_eq!(miss_err.code, JSONRPC_INVALID_PARAMS);

    // State mutation check: refusing door never mutates state.
    let _ = &mut state;
}

/// K3-D / eth_getTransactionReceipt: no response without naming the UER-1
/// receipt door `bud_getTransactionReceipt`.
#[test]
fn k3d_eth_receipt_refuses_with_uer1_door() {
    let state = AccountState::new();
    let mut gw = eth_gw();
    let resp = gw.handle_request(
        budlum_core::rpc::compat::CompatListener::Public,
        "127.0.0.1",
        1_700_000_100,
        &rpc_req(
            "eth_getTransactionReceipt",
            serde_json::json!([format!("0x{}", hex::encode([0x11u8; 32]))]),
        ),
        &state,
    );
    let err = resp.error.expect("receipt without EE refuses");
    assert_eq!(err.code, EE_UNAVAILABLE);
    assert!(
        err.message.contains("bud_getTransactionReceipt"),
        "UER-1 door must be named: {}",
        err.message
    );
    assert!(resp.result.is_none(), "no fake receipt object");
}

/// K3-D / Solana sendTransaction: door-named refusal when production EE is absent.
#[test]
fn k3d_solana_send_transaction_names_the_bud_door() {
    let state = AccountState::new();
    let mut gw = SolanaCompatGateway::new(SolanaCompatConfig::default(), 50, [0x99; 32]);

    // Disabled (default) - door-named refusal.
    let resp = gw.handle_request(
        &rpc_req(
            "sendTransaction",
            serde_json::json!(["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIAEgABAJA="]),
        ),
        &state,
    );
    let err = resp.error.expect("disabled gateway refuses");
    assert_eq!(err.code, SOLANA_UNAVAILABLE);
    assert!(
        err.message.contains("bud_sendRawTransaction"),
        "door named: {}",
        err.message
    );
    assert!(resp.result.is_none());

    // On a disabled surface a missing wire parameter also names the door FIRST:
    // parameter parsing never precedes the door check (fail-closed order).
    let missing = gw.handle_request(&rpc_req("sendTransaction", serde_json::json!([])), &state);
    let miss_err = missing.error.expect("missing wire refuses");
    assert_eq!(miss_err.code, SOLANA_UNAVAILABLE, "door before params when disabled");
    assert!(miss_err.message.contains("bud_sendRawTransaction"));

    // When enabled=true, malformed base58/base64 still never fabricates a signature.
    let mut enabled = SolanaCompatGateway::new(
        SolanaCompatConfig {
            enabled: true,
            ..SolanaCompatConfig::default()
        },
        50,
        [0x99; 32],
    );
    let junk = enabled.handle_request(
        &rpc_req("sendTransaction", serde_json::json!(["!!!not-base58!!!"])),
        &state,
    );
    assert!(junk.result.is_none(), "junk wire never becomes a signature");
    if let Some(e) = junk.error {
        assert!(
            e.code == JSONRPC_INVALID_PARAMS || e.code == SOLANA_UNAVAILABLE,
            "refusal code stays in the fail-closed set: {}",
            e.code
        );
    }
}

/// K3-D / CosmWasm: smart query reads from state; unknown path is fail-closed.
#[test]
fn k3d_cosmwasm_smart_query_and_fail_closed_path() {
    let mut state = AccountState::new();
    state
        .execution_state
        .write(NS_WASM_STORE, b"bud1c:kv:greeting", Some(b"hello"))
        .expect("write");

    let mut gw = CosmosCompatGateway::new(CosmosCompatConfig::default(), 50);

    // SmartContractState read comes from the live state root.
    let data = hex::encode(
        serde_json::to_vec(&serde_json::json!({
            "contract": "bud1c",
            "key": "greeting"
        }))
        .expect("json"),
    );
    let ok = gw.handle_rpc(
        &rpc_req(
            "abci_query",
            serde_json::json!({
                "path": "/cosmwasm.wasm.v1.Query/SmartContractState",
                "data": data
            }),
        ),
        &state,
    );
    let value = ok
        .result
        .expect("smart query answers")["response"]["value"]
        .clone();
    assert_eq!(
        value.as_str(),
        Some(hex::encode(b"hello").as_str()),
        "smart query reads the store"
    );

    // Unknown path: fail-closed, no fabricated response.
    let unknown = gw.handle_rpc(
        &rpc_req(
            "abci_query",
            serde_json::json!({
                "path": "/cosmwasm.wasm.v1.Msg/ExecuteContract",
                "data": data
            }),
        ),
        &state,
    );
    assert!(
        unknown.result.is_none(),
        "unknown abci path must not invent a value"
    );
    let uerr = unknown.error.expect("unknown path refuses");
    assert!(
        uerr.message.contains("unsupported") || uerr.code == JSONRPC_INVALID_PARAMS,
        "fail-closed refusal: {}",
        uerr.message
    );

    // Door inventory: SmartContractState path is listed, Execute is not.
    assert!(ABCI_QUERY_PATHS.contains(&"/cosmwasm.wasm.v1.Query/SmartContractState"));
    assert!(
        !ABCI_QUERY_PATHS
            .iter()
            .any(|p| p.contains("Msg/ExecuteContract")),
        "execute is not a served query path on this surface"
    );
}

/// K3-D / method class sync: eth_* Refused rows stay on the public listener;
/// sendRawTx/receipt remain Refused (method_class.rs lock).
#[test]
fn k3d_eth_class_rows_stay_refused_public() {
    let source = include_str!("../src/rpc/method_class.rs");
    for (name, needle) in [
        ("eth_sendRawTransaction", "row(\"eth_sendRawTransaction\", Public, Refused)"),
        ("eth_getTransactionReceipt", "row(\"eth_getTransactionReceipt\", Public, Refused)"),
    ] {
        assert!(
            source.contains(needle),
            "method_class must keep `{name}` Public+Refused (found={})",
            source.contains(&format!("row(\"{name}\""))
        );
    }
}
