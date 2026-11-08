use crate::core::account::AccountState;
use crate::execution::coordinator::alias::{derive_foreign_account, ForeignScheme};
use crate::execution::coordinator::foreign::ethereum::{
    evm_address_from_secret_key, sign_eip1559_tx, BUDLUM_EVM_CHAIN_ID,
};
use crate::execution::coordinator::state::NS_WASM_STORE;
use crate::rpc::compat::aptos::{AptosCompatGateway, APTOS_REST_ROUTES};
use crate::rpc::compat::cosmos::{ABCI_QUERY_PATHS, COMETBFT_RPC_METHODS, CosmosCompatGateway};
use crate::rpc::compat::ethereum::{EthereumCompatGateway, ETH_METHOD_CLASSES};
use crate::rpc::compat::solana::{SolanaCompatGateway, SOLANA_METHOD_CLASSES};
use crate::rpc::compat::{
    AptosCompatConfig, CompatListener, CosmosCompatConfig, EthereumCompatConfig, JsonRpcRequest,
    SolanaCompatConfig, JSONRPC_LIMIT_EXCEEDED, JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_OPERATOR_REQUIRED,
};

fn rpc_req(method: &str, params: serde_json::Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: String::from("2.0"),
        id: serde_json::json!(1),
        method: String::from(method),
        params,
    }
}

#[test]
fn eth_rpc_method_table_is_complete() {
    let required_public = [
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
    for name in required_public {
        let entry = ETH_METHOD_CLASSES
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("missing public Ethereum RPC method `{name}`"));
        assert_eq!(entry.listener, CompatListener::Public);
    }

    for op_name in ["debug_traceTransaction", "debug_traceCall"] {
        let entry = ETH_METHOD_CLASSES
            .iter()
            .find(|m| m.name == op_name)
            .expect("operator method present");
        assert_eq!(entry.listener, CompatListener::Operator);
    }

    // Verify default listener port (`127.0.0.1:18547`) and stateRoot = execution_root.
    let cfg = EthereumCompatConfig::default();
    assert_eq!(cfg.listen_addr, "127.0.0.1:18547");
    let mut gw = EthereumCompatGateway::new(cfg);
    let state = AccountState::new();
    let expected_root = format!(
        "0x{}",
        hex::encode(state.execution_state.execution_root())
    );
    let blk = gw.handle_request(
        CompatListener::Public,
        "127.0.0.1",
        100,
        &rpc_req("eth_getBlockByNumber", serde_json::json!(["latest", false])),
        &state,
    );
    assert_eq!(
        blk.result.expect("block")["stateRoot"].as_str(),
        Some(expected_root.as_str())
    );

    // Operator methods must be refused on the Public listener.
    let denied = gw.handle_request(
        CompatListener::Public,
        "127.0.0.1",
        100,
        &rpc_req("debug_traceTransaction", serde_json::json!(["0x00"])),
        &state,
    );
    assert_eq!(denied.error.expect("err").code, JSONRPC_OPERATOR_REQUIRED);
}

#[test]
fn eth_get_proof_returns_method_not_found() {
    let mut gw = EthereumCompatGateway::new(EthereumCompatConfig::default());
    let state = AccountState::new();
    let resp = gw.handle_request(
        CompatListener::Public,
        "127.0.0.1",
        100,
        &rpc_req(
            "eth_getProof",
            serde_json::json!(["0x0000000000000000000000000000000000000001", [], "latest"]),
        ),
        &state,
    );
    let err = resp.error.expect("eth_getProof must return JSON-RPC error");
    assert_eq!(err.code, JSONRPC_METHOD_NOT_FOUND);
    assert!(err.message.contains("bud_getExecutionProof"));
}

#[test]
fn eth_filters_are_bounded() {
    let cfg = EthereumCompatConfig {
        max_filters_per_peer: 2,
        max_total_filters: 3,
        filter_ttl_secs: 60,
        max_log_block_range: 100,
        ..EthereumCompatConfig::default()
    };
    let mut gw = EthereumCompatGateway::new(cfg);
    let state = AccountState::new();

    // Peer A installs 2 filters -> succeeds; 3rd from Peer A hits per-peer bound!
    for _ in 0..2 {
        let r = gw.handle_request(
            CompatListener::Public,
            "peer-a",
            1_000,
            &rpc_req("eth_newBlockFilter", serde_json::json!([])),
            &state,
        );
        assert!(r.result.is_some());
    }
    let r_over_peer = gw.handle_request(
        CompatListener::Public,
        "peer-a",
        1_000,
        &rpc_req("eth_newBlockFilter", serde_json::json!([])),
        &state,
    );
    assert_eq!(
        r_over_peer.error.expect("peer cap").code,
        JSONRPC_LIMIT_EXCEEDED
    );

    // Peer B installs 1 filter -> hits global total cap (3) on its 2nd filter!
    let r_b1 = gw.handle_request(
        CompatListener::Public,
        "peer-b",
        1_000,
        &rpc_req("eth_newBlockFilter", serde_json::json!([])),
        &state,
    );
    assert!(r_b1.result.is_some());
    let r_b2 = gw.handle_request(
        CompatListener::Public,
        "peer-b",
        1_000,
        &rpc_req("eth_newBlockFilter", serde_json::json!([])),
        &state,
    );
    assert_eq!(
        r_b2.error.expect("global cap").code,
        JSONRPC_LIMIT_EXCEEDED
    );

    // Advance clock past TTL (`1_000 + 61`): expired filters are evicted automatically!
    let r_after_ttl = gw.handle_request(
        CompatListener::Public,
        "peer-a",
        1_061,
        &rpc_req("eth_newBlockFilter", serde_json::json!([])),
        &state,
    );
    assert!(r_after_ttl.result.is_some());
    assert_eq!(gw.filters().len(), 1);
}

#[test]
fn eth_send_raw_transaction_and_other_compat_gateways_work() {
    let sk = [0x33u8; 32];
    let addr20 = evm_address_from_secret_key(&sk).expect("evm addr");
    let mut state = AccountState::new();
    let sender_bud = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &addr20);
    state.credit_account(&sender_bud, 5_000);

    let raw = sign_eip1559_tx(
        &sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000_000_000,
        2_000_000_000,
        21_000,
        Some([0xAB; 20]),
        1_000,
        &[],
        &[],
    )
    .expect("sign eip1559");

    let mut eth_gw = EthereumCompatGateway::new(EthereumCompatConfig::default());
    let send_resp = eth_gw.handle_request(
        CompatListener::Public,
        "127.0.0.1",
        200,
        &rpc_req(
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw))]),
        ),
        &state,
    );
    let tx_hash_hex = send_resp
        .result
        .expect("eth_sendRawTransaction ok")
        .as_str()
        .expect("str")
        .to_string();
    assert!(tx_hash_hex.starts_with("0x"));

    // Solana, Aptos, and Cosmos route tables are complete and responsive.
    assert_eq!(SOLANA_METHOD_CLASSES.len(), 35);
    assert_eq!(APTOS_REST_ROUTES.len(), 18);
    assert_eq!(COMETBFT_RPC_METHODS.len(), 12);
    assert_eq!(ABCI_QUERY_PATHS.len(), 10);

    let mut sol_gw = SolanaCompatGateway::new(SolanaCompatConfig::default(), 50, [0x99; 32]);
    let health_req = rpc_req("getHealth", serde_json::json!([]));
    let sol_health = sol_gw.handle_request(&health_req, &state);
    assert_eq!(sol_health.result, Some(serde_json::json!("ok")));

    let mut faucet_gw = SolanaCompatGateway::new(
        SolanaCompatConfig {
            testnet_faucet_enabled: true,
            ..SolanaCompatConfig::default()
        },
        50,
        [0x99; 32],
    );
    let airdrop = faucet_gw.handle_request(
        &rpc_req("requestAirdrop", serde_json::json!([hex::encode([7u8; 32]), 1])),
        &state,
    );
    assert!(airdrop.result.is_none());
    assert!(airdrop
        .error
        .expect("unwired airdrop must fail")
        .message
        .contains("no grant was queued"));

    let mut apt_gw = AptosCompatGateway::new(AptosCompatConfig::default(), 50, 1_700_000_000);
    let apt_info = apt_gw.handle_rest("GET", "/v1", None, &state);
    assert_eq!(apt_info.status, 200);
    assert_eq!(apt_info.body["chain_id"], serde_json::json!(205));

    state
        .execution_state
        .write(NS_WASM_STORE, b"bud1contract:kv:greeting", Some(b"merhaba"))
        .expect("w");
    let mut cos_gw = CosmosCompatGateway::new(CosmosCompatConfig::default(), 50);
    let q_data = hex::encode(
        serde_json::to_vec(&serde_json::json!({
            "contract": "bud1contract",
            "key": "greeting"
        }))
        .expect("json"),
    );
    let abci = cos_gw.handle_rpc(
        &rpc_req(
            "abci_query",
            serde_json::json!({
                "path": "/cosmwasm.wasm.v1.Query/SmartContractState",
                "data": q_data
            }),
        ),
        &state,
    );
    assert_eq!(
        abci.result.expect("abci")["response"]["value"].as_str(),
        Some(hex::encode(b"merhaba").as_str())
    );
}

#[test]
fn eth_filters_are_peer_isolated_and_bud_execution_proof_verifies() {
    let mut gw = EthereumCompatGateway::new(EthereumCompatConfig::default());
    let mut state = AccountState::new();
    state
        .execution_state
        .write(NS_WASM_STORE, b"k1", Some(b"v1"))
        .expect("write");

    // Peer A creates filter 0x1; Peer B cannot poll or uninstall Peer A's filter (#76).
    let created = gw.handle_request(
        CompatListener::Public,
        "10.0.0.1",
        100,
        &rpc_req("eth_newBlockFilter", serde_json::json!([])),
        &state,
    );
    let fid = created.result.expect("filter id").as_str().expect("str").to_string();

    let poll_other_peer = gw.handle_request(
        CompatListener::Public,
        "10.0.0.2",
        101,
        &rpc_req("eth_getFilterChanges", serde_json::json!([fid])),
        &state,
    );
    assert!(poll_other_peer.error.is_some());

    let uninst_other = gw.handle_request(
        CompatListener::Public,
        "10.0.0.2",
        102,
        &rpc_req("eth_uninstallFilter", serde_json::json!([fid])),
        &state,
    );
    assert_eq!(uninst_other.result, Some(serde_json::json!(false)));

    let poll_owner = gw.handle_request(
        CompatListener::Public,
        "10.0.0.1",
        103,
        &rpc_req("eth_getFilterChanges", serde_json::json!([fid])),
        &state,
    );
    assert!(poll_owner.error.is_none());

    // `bud_getExecutionProof` returns a verifiable `UelExecutionProof` anchored at
    // `execution_root`.
    let proof_resp = gw.handle_request(
        CompatListener::Public,
        "10.0.0.1",
        104,
        &rpc_req(
            "bud_getExecutionProof",
            serde_json::json!([NS_WASM_STORE, format!("0x{}", hex::encode(b"k1"))]),
        ),
        &state,
    );
    let res = proof_resp.result.expect("proof result");
    let proof: crate::execution::coordinator::state::UelExecutionProof =
        serde_json::from_value(res["proof"].clone()).expect("decode proof");
    assert!(crate::execution::coordinator::state::uel_proof_matches_root(
        &proof,
        &state.execution_state.execution_root(),
    ));
}


#[test]
fn solana_unimplemented_methods_never_return_invented_success() {
    let state = AccountState::default();
    let mut gateway = SolanaCompatGateway::new(SolanaCompatConfig::default(), 50, [0x99; 32]);
    for method in [
        "getGenesisHash",
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
        "accountSubscribe",
        "signatureSubscribe",
        "slotSubscribe",
        "logsSubscribe",
        "programSubscribe",
        "accountUnsubscribe",
        "signatureUnsubscribe",
        "slotUnsubscribe",
        "logsUnsubscribe",
        "programUnsubscribe",
    ] {
        let response = gateway.handle_request(&rpc_req(method, serde_json::json!([])), &state);
        assert!(response.result.is_none(), "{method} returned an invented result");
        let error = response.error.expect("unimplemented method must fail");
        assert_eq!(error.code, -32004, "{method}");
        assert!(error.message.contains(method), "{method}: {}", error.message);
    }

    for method in ["getHealth", "getVersion", "getSlot", "getBlockHeight"] {
        let response = gateway.handle_request(&rpc_req(method, serde_json::json!([])), &state);
        assert!(response.error.is_none(), "{method} must remain served");
        assert!(response.result.is_some(), "{method} lost its chain answer");
    }
}
