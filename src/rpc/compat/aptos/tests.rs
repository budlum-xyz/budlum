//! Route-table and response-shape tests for the Aptos REST gateway.

use super::{
    check_routes, classify, healthy_response, move_unavailable, node_info_response, owns_path,
    validate_listener, Answer, Effect, Listener, RouteMatch, Verb, ENDPOINTS,
};
use crate::core::block::Block;
use hyper::{Method, StatusCode};

const DIRECTIVE_ROUTES: &[(Verb, &str)] = &[
    (Verb::Get, "/v1"),
    (Verb::Get, "/v1/-/healthy"),
    (Verb::Get, "/v1/accounts/{addr}"),
    (Verb::Get, "/v1/accounts/{addr}/resources"),
    (Verb::Get, "/v1/accounts/{addr}/resource/{type}"),
    (Verb::Get, "/v1/accounts/{addr}/modules"),
    (Verb::Get, "/v1/accounts/{addr}/module/{name}"),
    (Verb::Get, "/v1/accounts/{addr}/transactions"),
    (Verb::Post, "/v1/transactions"),
    (Verb::Post, "/v1/transactions/simulate"),
    (Verb::Get, "/v1/transactions/by_hash/{h}"),
    (Verb::Get, "/v1/transactions/wait_by_hash/{h}"),
    (Verb::Get, "/v1/transactions/by_version/{v}"),
    (Verb::Post, "/v1/view"),
    (Verb::Get, "/v1/estimate_gas_price"),
    (Verb::Get, "/v1/blocks/by_height/{h}"),
    (Verb::Post, "/v1/tables/{handle}/item"),
    (
        Verb::Get,
        "/v1/accounts/{addr}/events/{creation_number}",
    ),
];

fn method(verb: Verb) -> Method {
    match verb {
        Verb::Get => Method::GET,
        Verb::Post => Method::POST,
    }
}

fn example_path(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "0x01"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn aptos_rest_route_table_is_complete_and_ordered() {
    let actual: Vec<(Verb, &str)> = ENDPOINTS
        .iter()
        .map(|endpoint| (endpoint.verb, endpoint.pattern))
        .collect();
    assert_eq!(actual, DIRECTIVE_ROUTES);
    assert_eq!(ENDPOINTS.len(), 18);
    check_routes().expect("the production route table is valid");
}

#[test]
fn aptos_every_route_is_public_and_has_one_effect() {
    for endpoint in ENDPOINTS {
        assert_eq!(endpoint.listener, Listener::Public);
        match endpoint.answer {
            Answer::ChainRead => assert_eq!(endpoint.effect, Effect::Read),
            Answer::MoveUnavailable { .. } => assert!(matches!(
                endpoint.effect,
                Effect::Refused | Effect::TxSubmit
            )),
        }
    }
}

#[test]
fn aptos_dynamic_routes_match_exactly_one_path_shape() {
    let cases = [
        ("/v1/accounts/0x01", "/v1/accounts/{addr}"),
        (
            "/v1/accounts/0x01/resource/0x1::coin::CoinStore",
            "/v1/accounts/{addr}/resource/{type}",
        ),
        (
            "/v1/accounts/0x01/events/7",
            "/v1/accounts/{addr}/events/{creation_number}",
        ),
        (
            "/v1/transactions/by_version/42",
            "/v1/transactions/by_version/{v}",
        ),
    ];
    for (path, pattern) in cases {
        let RouteMatch::Found(index) = classify(&Method::GET, path) else {
            panic!("{path} did not match {pattern}");
        };
        assert_eq!(ENDPOINTS[index].pattern, pattern);
    }

    assert_eq!(
        classify(&Method::GET, "/v1/accounts/0x01/resources/extra"),
        RouteMatch::NotFound
    );
    assert_eq!(
        classify(&Method::GET, "/v1/accounts//resources"),
        RouteMatch::NotFound
    );
}

#[test]
fn aptos_wrong_methods_and_unknown_routes_are_explicit() {
    assert_eq!(
        classify(&Method::POST, "/v1/-/healthy"),
        RouteMatch::MethodNotAllowed
    );
    assert_eq!(
        classify(&Method::GET, "/v1/transactions"),
        RouteMatch::MethodNotAllowed
    );
    assert_eq!(
        classify(&Method::GET, "/v1/not-a-route"),
        RouteMatch::NotFound
    );
    assert!(owns_path("/v1"));
    assert!(owns_path("/v1/not-a-route"));
    assert!(!owns_path("/v10"));
    assert!(!owns_path("/"));
}

#[test]
fn aptos_every_table_route_reaches_the_production_classifier() {
    for (index, endpoint) in ENDPOINTS.iter().enumerate() {
        let path = example_path(endpoint.pattern);
        assert_eq!(
            classify(&method(endpoint.verb), &path),
            RouteMatch::Found(index),
            "{} {} is not routed",
            endpoint.verb.as_str(),
            endpoint.pattern
        );
    }
}

#[test]
fn aptos_move_refusals_name_an_existing_budlum_door() {
    let api = include_str!("../../api.rs");
    let mut refusals = 0usize;
    for endpoint in ENDPOINTS {
        let Answer::MoveUnavailable { door } = endpoint.answer else {
            continue;
        };
        refusals += 1;
        let declaration = format!("#[method(name = \"{door}\")]");
        assert!(
            api.contains(&declaration),
            "{} names {door}, which src/rpc/api.rs does not declare",
            endpoint.pattern
        );
        let error = move_unavailable(endpoint, door);
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.message.contains(door));
        let body = error.body();
        assert_eq!(body["door"], door);
        assert_eq!(body["package"], "WP-32");
        assert_eq!(
            body["error_code"],
            "move_execution_environment_unavailable"
        );
    }
    assert_eq!(refusals, 16, "only the two health routes are served");
}

#[test]
fn aptos_post_transactions_is_a_future_tx_door_not_a_current_write() {
    let endpoint = ENDPOINTS
        .iter()
        .find(|endpoint| endpoint.pattern == "/v1/transactions")
        .expect("the transaction route exists");
    assert_eq!(endpoint.effect, Effect::TxSubmit);
    assert_eq!(
        endpoint.answer,
        Answer::MoveUnavailable {
            door: "bud_sendRawTransaction"
        }
    );
}

#[test]
fn aptos_node_info_binds_aptos_id_to_the_real_head() {
    let mut head = Block::new(41, "00".repeat(32), vec![]);
    head.epoch = 7;
    head.timestamp = 1_762_400_000_123;
    let info = node_info_response(head, true).expect("node information is available");
    assert_eq!(info["chain_id"], 205);
    assert_eq!(info["epoch"], "7");
    assert_eq!(info["ledger_version"], "41");
    assert_eq!(info["block_height"], "41");
    assert_eq!(info["oldest_ledger_version"], "0");
    assert_eq!(info["ledger_timestamp"], "1762400000123000");
    assert_eq!(info["node_role"], "full_node");
}

#[test]
fn aptos_node_info_refuses_an_unknown_oldest_version() {
    let head = Block::new(41, "00".repeat(32), vec![]);
    let error = node_info_response(head, false)
        .expect_err("a pruned node must not claim that version zero is available");
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.door, Some("bud_getStatus"));
    assert!(error.message.contains("oldest ledger version"));
}

#[test]
fn aptos_node_info_refuses_timestamp_overflow() {
    let mut head = Block::new(1, "00".repeat(32), vec![]);
    head.timestamp = u128::MAX;
    let error = node_info_response(head, true)
        .expect_err("milliseconds must not wrap into false Aptos microseconds");
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.message.contains("timestamp"));
}

#[test]
fn aptos_health_reports_ready_and_syncing_without_json_wrappers() {
    assert_eq!(healthy_response(false).status(), StatusCode::OK);
    assert_eq!(
        healthy_response(true).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn aptos_dedicated_listener_is_loopback_only() {
    assert_eq!(
        validate_listener("127.0.0.1:18549").expect("IPv4 loopback is valid"),
        "127.0.0.1:18549".parse().expect("the expected socket is valid")
    );
    assert!(validate_listener("[::1]:18549").is_ok());
    for invalid in ["0.0.0.0:18549", "192.0.2.1:18549", "localhost:18549", "bad"] {
        assert!(
            validate_listener(invalid).is_err(),
            "{invalid} must not open the dedicated public service"
        );
    }
}
