//! Aptos REST compatibility gateway (WP-32, delivery 1/N).
//!
//! The table in this module is the REST counterpart of `method_class.rs`:
//! every route has one public listener and one effect. The production HTTP
//! service in `rpc::server` calls [`AptosGateway::handle`] for every `/v1`
//! request, so this is a served surface rather than a route inventory.
//!
//! Delivery 1/N serves the two node-health routes. Routes that need the Move
//! account model, Move resources, BCS transactions, events, or table state
//! answer HTTP 503 and name the native Budlum door. They do not invent an
//! Aptos-shaped answer from a different ledger. The dedicated
//! `127.0.0.1:18549` listener and the Move worker belong to the next delivery.

use crate::chain::chain_actor::ChainHandle;
use crate::core::block::Block;
use crate::network::node::NodeClient;
use hyper::{Method, StatusCode};
use jsonrpsee::server::{HttpBody, HttpResponse};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

/// The Aptos chain id assigned to Budlum's Aptos foreign envelope.
const APTOS_CHAIN_ID: u8 = 205;

/// HTTP verbs in the directive's Aptos REST subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verb {
    Get,
    Post,
}

impl Verb {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }

    fn matches(self, method: &Method) -> bool {
        match self {
            Self::Get => method == Method::GET,
            Self::Post => method == Method::POST,
        }
    }
}

/// The listener named by the compatibility method table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listener {
    Public,
}

/// What a successful route does, or what a named refusal would do once its
/// execution environment exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Read,
    TxSubmit,
    Refused,
}

/// The answer this delivery can give without a Move execution environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    ChainRead,
    MoveUnavailable { door: &'static str },
}

/// One route, its listener, its effect, and its current answer.
#[derive(Debug, Clone, Copy)]
struct Endpoint {
    verb: Verb,
    pattern: &'static str,
    listener: Listener,
    effect: Effect,
    answer: Answer,
}

const fn read(verb: Verb, pattern: &'static str) -> Endpoint {
    Endpoint {
        verb,
        pattern,
        listener: Listener::Public,
        effect: Effect::Read,
        answer: Answer::ChainRead,
    }
}

const fn refused(
    verb: Verb,
    pattern: &'static str,
    effect: Effect,
    door: &'static str,
) -> Endpoint {
    Endpoint {
        verb,
        pattern,
        listener: Listener::Public,
        effect,
        answer: Answer::MoveUnavailable { door },
    }
}

/// Section 8.11.4, verbatim and in its order.
const ENDPOINTS: &[Endpoint] = &[
    read(Verb::Get, "/v1"),
    read(Verb::Get, "/v1/-/healthy"),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/resources",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/resource/{type}",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/modules",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/module/{name}",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/transactions",
        Effect::Refused,
        "bud_getTransactionByHash",
    ),
    refused(
        Verb::Post,
        "/v1/transactions",
        Effect::TxSubmit,
        "bud_sendRawTransaction",
    ),
    refused(
        Verb::Post,
        "/v1/transactions/simulate",
        Effect::Refused,
        "bud_txPrecheck",
    ),
    refused(
        Verb::Get,
        "/v1/transactions/by_hash/{h}",
        Effect::Refused,
        "bud_getTransactionByHash",
    ),
    refused(
        Verb::Get,
        "/v1/transactions/wait_by_hash/{h}",
        Effect::Refused,
        "bud_getTransactionReceipt",
    ),
    refused(
        Verb::Get,
        "/v1/transactions/by_version/{v}",
        Effect::Refused,
        "bud_getTransactionByHash",
    ),
    refused(
        Verb::Post,
        "/v1/view",
        Effect::Refused,
        "bud_txPrecheck",
    ),
    refused(
        Verb::Get,
        "/v1/estimate_gas_price",
        Effect::Refused,
        "bud_gasPrice",
    ),
    refused(
        Verb::Get,
        "/v1/blocks/by_height/{h}",
        Effect::Refused,
        "bud_getBlockByNumber",
    ),
    refused(
        Verb::Post,
        "/v1/tables/{handle}/item",
        Effect::Refused,
        "bud_getAccountProof",
    ),
    refused(
        Verb::Get,
        "/v1/accounts/{addr}/events/{creation_number}",
        Effect::Refused,
        "bud_getTransactionReceipt",
    ),
];

/// Whether the HTTP request belongs to this gateway, including an unknown
/// path that must receive this gateway's 404 rather than a JSON-RPC error.
pub fn owns_path(path: &str) -> bool {
    path == "/v1" || path.starts_with("/v1/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMatch {
    Found(usize),
    MethodNotAllowed,
    NotFound,
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|segment| !segment.is_empty())
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern = segments(pattern);
    let mut path = segments(path);
    loop {
        match (pattern.next(), path.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual)) => {
                let placeholder = expected.starts_with('{') && expected.ends_with('}');
                if (!placeholder && expected != actual) || (placeholder && actual.is_empty()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn classify(method: &Method, path: &str) -> RouteMatch {
    let mut path_found = false;
    for (index, endpoint) in ENDPOINTS.iter().enumerate() {
        if path_matches(endpoint.pattern, path) {
            path_found = true;
            if endpoint.verb.matches(method) {
                return RouteMatch::Found(index);
            }
        }
    }
    if path_found {
        RouteMatch::MethodNotAllowed
    } else {
        RouteMatch::NotFound
    }
}

/// Check the production route table at listener startup.
///
/// # Errors
///
/// Names a duplicate route, a non-public route, or a listener/effect mismatch.
pub fn check_routes() -> Result<(), String> {
    let mut routes = BTreeSet::new();
    let mut problems = Vec::new();
    for endpoint in ENDPOINTS {
        if !routes.insert((endpoint.verb, endpoint.pattern)) {
            problems.push(format!(
                "{} {} has a duplicate route row",
                endpoint.verb.as_str(),
                endpoint.pattern
            ));
        }
        if endpoint.listener != Listener::Public {
            problems.push(format!("{} is not public", endpoint.pattern));
        }
        let consistent = matches!(
            (endpoint.effect, endpoint.answer),
            (Effect::Read, Answer::ChainRead)
                | (Effect::Refused, Answer::MoveUnavailable { .. })
                | (Effect::TxSubmit, Answer::MoveUnavailable { .. })
        );
        if !consistent {
            problems.push(format!(
                "{} has inconsistent effect and answer rows",
                endpoint.pattern
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[derive(Debug)]
struct RestError {
    status: StatusCode,
    error_code: &'static str,
    message: String,
    door: Option<&'static str>,
}

impl RestError {
    fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "message": self.message,
            "error_code": self.error_code,
            "vm_error_code": null,
            "door": self.door,
            "package": "WP-32",
        })
    }
}

fn move_unavailable(endpoint: &Endpoint, door: &'static str) -> RestError {
    RestError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_code: "move_execution_environment_unavailable",
        message: format!(
            "{} {} needs the Move execution environment (WP-32); use {door}",
            endpoint.verb.as_str(),
            endpoint.pattern
        ),
        door: Some(door),
    }
}

fn chain_unavailable(detail: &str) -> RestError {
    RestError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_code: "chain_read_unavailable",
        message: format!("Aptos node information is unavailable: {detail}; use bud_getStatus"),
        door: Some("bud_getStatus"),
    }
}

fn response(status: StatusCode, content_type: &'static str, body: String) -> HttpResponse {
    HttpResponse::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(HttpBody::from(body.clone()))
        .unwrap_or_else(|_| HttpResponse::new(HttpBody::from(body)))
}

fn json_response(status: StatusCode, body: serde_json::Value) -> HttpResponse {
    response(
        status,
        "application/json",
        serde_json::to_string(&body).unwrap_or_else(|_| {
            "{\"message\":\"JSON serialization failed\",\"error_code\":\"internal_error\"}"
                .to_string()
        }),
    )
}

fn error_response(error: RestError) -> HttpResponse {
    json_response(error.status, error.body())
}

fn healthy_response(syncing: bool) -> HttpResponse {
    if syncing {
        response(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            "aptos-node:syncing".to_string(),
        )
    } else {
        response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            "aptos-node:ok".to_string(),
        )
    }
}

/// The Aptos node-information view of one Budlum head block.
///
/// Aptos ledger versions and Budlum block heights are different consensus
/// concepts. Until the Move worker has a versioned ledger, this delivery uses
/// the head height only as the compatibility progress counter. Every route
/// that would interpret that counter as a Move transaction version refuses.
fn node_info_response(head: Block, has_genesis: bool) -> Result<serde_json::Value, RestError> {
    if !has_genesis {
        return Err(chain_unavailable(
            "the oldest ledger version cannot be established on this pruned node",
        ));
    }
    let ledger_timestamp = head
        .timestamp
        .checked_mul(1_000)
        .ok_or_else(|| chain_unavailable("the head timestamp does not fit Aptos microseconds"))?;
    Ok(serde_json::json!({
        "chain_id": APTOS_CHAIN_ID,
        "epoch": head.epoch.to_string(),
        "ledger_version": head.index.to_string(),
        "oldest_ledger_version": "0",
        "ledger_timestamp": ledger_timestamp.to_string(),
        "node_role": "full_node",
        "oldest_block_height": "0",
        "block_height": head.index.to_string(),
        "git_hash": option_env!("BUDLUM_GIT_HASH").unwrap_or("unknown"),
    }))
}

/// The chain-backed Aptos REST handler wired into the node HTTP service.
#[derive(Clone)]
pub struct AptosGateway {
    chain: ChainHandle,
    node: NodeClient,
}

impl AptosGateway {
    pub fn new(chain: ChainHandle, node: NodeClient) -> Self {
        Self { chain, node }
    }

    async fn node_info(&self) -> Result<serde_json::Value, RestError> {
        let height = self.chain.get_height().await;
        let head = self
            .chain
            .get_block(height)
            .await
            .ok_or_else(|| chain_unavailable("the head block is not available"))?;
        let has_genesis = self.chain.get_block(0).await.is_some();
        node_info_response(head, has_genesis)
    }

    /// Answer one classified REST request. POST bodies are not read while the
    /// Move worker is absent: a named refusal must not become a body parser or
    /// an allocation door.
    pub async fn handle(&self, method: &Method, path: &str) -> HttpResponse {
        match classify(method, path) {
            RouteMatch::NotFound => error_response(RestError {
                status: StatusCode::NOT_FOUND,
                error_code: "not_found",
                message: format!("No Aptos REST route matches {path}"),
                door: None,
            }),
            RouteMatch::MethodNotAllowed => error_response(RestError {
                status: StatusCode::METHOD_NOT_ALLOWED,
                error_code: "method_not_allowed",
                message: format!("{method} is not allowed for {path}"),
                door: None,
            }),
            RouteMatch::Found(index) => {
                let endpoint = &ENDPOINTS[index];
                match endpoint.answer {
                    Answer::ChainRead if endpoint.pattern == "/v1/-/healthy" => {
                        healthy_response(self.node.is_syncing())
                    }
                    Answer::ChainRead if endpoint.pattern == "/v1" => match self.node_info().await {
                        Ok(info) => json_response(StatusCode::OK, info),
                        Err(error) => error_response(error),
                    },
                    Answer::MoveUnavailable { door } => {
                        error_response(move_unavailable(endpoint, door))
                    }
                    Answer::ChainRead => error_response(chain_unavailable(
                        "a chain-read route has no production handler",
                    )),
                }
            }
        }
    }
}
