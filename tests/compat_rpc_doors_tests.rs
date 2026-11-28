//! CEO Direktif K3-D — Uyumluluk RPC kapıları (RED->GREEN kilitleri).
//!
//! Dört kapı aynı disiplinde kilitlenir:
//! 1. `eth_sendRawTransaction` — geçerli zarf bile `EE_UNAVAILABLE` (-32004) ile
//!    `bud_sendRawTransaction` kapısını adlandırır; bozar/eksik parametre
//!    `JSONRPC_INVALID_PARAMS` alır, asla sahte tx-hash dönmez.
//! 2. `eth_getTransactionReceipt` — `bud_getTransactionReceipt` (UER-1 makbuz
//!    kapısı) adlandırılmadan yanıt yoktur; yanıt `-32004` ve kapı adını taşır.
//! 3. Solana `sendTransaction` — üretim uygulaması yokken `-32004` +
//!    `bud_sendRawTransaction`; tel formatı bozuksa `-32602`.
//! 4. CosmWasm — `SmartContractState`/`RawContractState` sorguları durumdan
//!    okur; bilinmeyen abci_query yolu fail-closed reddedilir.
//!
//! Bu dosya kilitli satırlara dokunmaz; yalnız public gateway yüzeyini sınar.

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

/// K3-D / eth_sendRawTransaction: geçerli EIP-1559 zarfı bile bu yüzeyde
/// `bud_sendRawTransaction` kapısını adlandırarak reddedilir (EE yoksa sahte
/// başarı yok).
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

    // Bozuk hex: invalid params, yine kapı sahtesi yok.
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

    // Eksik parametre.
    let missing = gw.handle_request(
        budlum_core::rpc::compat::CompatListener::Public,
        "127.0.0.1",
        1_700_000_002,
        &rpc_req("eth_sendRawTransaction", serde_json::json!([])),
        &state,
    );
    let miss_err = missing.error.expect("missing params refuse");
    assert_eq!(miss_err.code, JSONRPC_INVALID_PARAMS);

    // state mutasyon kontrolü: reddeden kapı durumu değiştirmez.
    let _ = &mut state;
}

/// K3-D / eth_getTransactionReceipt: UER-1 makbuz kapısı `bud_getTransactionReceipt`
/// adlandırılmadan yanıt yok.
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

/// K3-D / Solana sendTransaction: üretim yokken kapı adlandırılmış reddi.
#[test]
fn k3d_solana_send_transaction_names_the_bud_door() {
    let state = AccountState::new();
    let mut gw = SolanaCompatGateway::new(SolanaCompatConfig::default(), 50, [0x99; 32]);

    // Devre dışı (varsayılan) — kapı adlandırılmış ret.
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

    // Devre dışı yüzeyde eksik tel parametresi de ÖNCE kapı adlandırır:
    // parametre ayrıştırımı kapıdan önce uydurma cevap üretmez (fail-closed sıra).
    let missing = gw.handle_request(&rpc_req("sendTransaction", serde_json::json!([])), &state);
    let miss_err = missing.error.expect("missing wire refuses");
    assert_eq!(miss_err.code, SOLANA_UNAVAILABLE, "door before params when disabled");
    assert!(miss_err.message.contains("bud_sendRawTransaction"));

    // enable=true iken bozuk base58/base64 yine uydurma imza üretmez.
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

/// K3-D / CosmWasm: smart query durumdan okur; bilinmeyen yol fail-closed.
#[test]
fn k3d_cosmwasm_smart_query_and_fail_closed_path() {
    let mut state = AccountState::new();
    state
        .execution_state
        .write(NS_WASM_STORE, b"bud1c:kv:greeting", Some(b"merhaba"))
        .expect("write");

    let mut gw = CosmosCompatGateway::new(CosmosCompatConfig::default(), 50);

    // SmartContractState okuması gerçek durum kökünden gelir.
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
        Some(hex::encode(b"merhaba").as_str()),
        "smart query reads the store"
    );

    // Bilinmeyen path: fail-closed, uydurma cevap yok.
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

    // Kapı envanteri: SmartContractState yolu listede, Execute listede değil.
    assert!(ABCI_QUERY_PATHS.contains(&"/cosmwasm.wasm.v1.Query/SmartContractState"));
    assert!(
        !ABCI_QUERY_PATHS
            .iter()
            .any(|p| p.contains("Msg/ExecuteContract")),
        "execute is not a served query path on this surface"
    );
}

/// K3-D / method class senkronu: eth_* Refused satırları public listener'da
/// kalır; sendRawTx/receipt Refused etkisindedir (method_class.rs kilidi).
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
