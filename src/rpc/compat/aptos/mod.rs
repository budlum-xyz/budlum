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
//! Aptos-shaped answer from a different ledger. Delivery 2/N opens the
//! dedicated loopback listener. Delivery 3/N can explicitly forward the
//! complete route table to an operator-selected full node; without that
//! option the local named refusals remain unchanged. The Move worker belongs
//! to a later delivery.

use crate::chain::chain_actor::ChainHandle;
use crate::core::block::Block;
use crate::network::node::NodeClient;
use http_body_util::BodyExt;
use hyper::header::{HeaderName, ACCEPT, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Method, StatusCode};
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};
use std::collections::BTreeSet;
use std::time::Duration;

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

/// Validate the dedicated Aptos bind address before any listener starts.
/// The public endpoint is exposed by the reverse proxy, never by binding this
/// unauthenticated REST service to a non-loopback interface.
pub fn validate_listener(addr: &str) -> Result<std::net::SocketAddr, String> {
    let socket = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|error| format!("Aptos REST listener must be an IP:port socket: {error}"))?;
    if !socket.ip().is_loopback() {
        return Err(format!(
            "Aptos REST listener must bind a loopback IP, not {socket}"
        ));
    }
    Ok(socket)
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

fn proxy_error(status: StatusCode, code: &'static str, message: &str) -> HttpResponse {
    error_response(RestError {
        status,
        error_code: code,
        message: message.to_string(),
        door: None,
    })
}

/// An explicitly configured Aptos full node. Remote upstreams require HTTPS;
/// plain HTTP is limited to a numeric loopback peer for tests and local
/// deployments. Redirects stay disabled so an upstream cannot change origin.
#[derive(Clone)]
pub struct AptosUpstream {
    base: reqwest::Url,
    client: reqwest::Client,
}

impl AptosUpstream {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut base = reqwest::Url::parse(value)
            .map_err(|error| format!("Aptos upstream URL is invalid: {error}"))?;
        if base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err("Aptos upstream URL needs a host and no credentials, query, or fragment"
                .to_string());
        }
        if base.path().trim_end_matches('/') != "/v1" {
            return Err("Aptos upstream URL must end in /v1".to_string());
        }
        let loopback = base
            .host_str()
            .and_then(|host| {
                let host = host
                    .strip_prefix('[')
                    .and_then(|host| host.strip_suffix(']'))
                    .unwrap_or(host);
                host.parse::<std::net::IpAddr>().ok()
            })
            .is_some_and(|host| host.is_loopback());
        if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
            return Err(
                "Aptos upstream must use HTTPS, or HTTP only with a numeric loopback host"
                    .to_string(),
            );
        }
        base.set_path("/v1");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("Aptos upstream HTTP client: {error}"))?;
        Ok(Self { base, client })
    }

    fn url_for(&self, uri: &hyper::Uri) -> Result<reqwest::Url, HttpResponse> {
        let suffix = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/v1");
        reqwest::Url::parse(&format!("{}{suffix}", self.base.as_str())).map_err(|_| {
            proxy_error(
                StatusCode::BAD_REQUEST,
                "invalid_aptos_path",
                "The Aptos request path is not a valid upstream URL",
            )
        })
    }

    async fn forward<B>(&self, req: HttpRequest<B>, body_limit: usize) -> HttpResponse
    where
        B: hyper::body::Body<Data = hyper::body::Bytes> + Send + Unpin + 'static,
        B::Error: Send + 'static,
    {
        let (parts, mut incoming) = req.into_parts();
        let url = match self.url_for(&parts.uri) {
            Ok(url) => url,
            Err(response) => return response,
        };
        if parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > body_limit as u64)
        {
            return proxy_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "aptos_request_too_large",
                "The Aptos request body exceeds the listener limit",
            );
        }
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => {
                    return proxy_error(
                        StatusCode::BAD_REQUEST,
                        "aptos_request_body_error",
                        "The Aptos request body could not be read",
                    )
                }
            };
            if let Some(chunk) = frame.data_ref() {
                if body.len().saturating_add(chunk.len()) > body_limit {
                    return proxy_error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "aptos_request_too_large",
                        "The Aptos request body exceeds the listener limit",
                    );
                }
                body.extend_from_slice(chunk);
            }
        }

        let mut outgoing = self.client.request(parts.method, url);
        for name in [ACCEPT, CONTENT_TYPE] {
            if let Some(value) = parts.headers.get(name.clone()) {
                outgoing = outgoing.header(name, value.clone());
            }
        }
        let mut upstream = match outgoing.body(body).send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!("Aptos upstream request failed: {error}");
                return proxy_error(
                    StatusCode::BAD_GATEWAY,
                    "aptos_upstream_unavailable",
                    "The configured Aptos full node is unavailable",
                );
            }
        };
        if upstream
            .content_length()
            .is_some_and(|length| length > body_limit as u64)
        {
            return proxy_error(
                StatusCode::BAD_GATEWAY,
                "aptos_upstream_response_too_large",
                "The Aptos full node response exceeds the listener limit",
            );
        }
        let status = upstream.status();
        let headers = upstream.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = match upstream.chunk().await {
            Ok(chunk) => chunk,
            Err(error) => {
                tracing::warn!("Aptos upstream response failed: {error}");
                return proxy_error(
                    StatusCode::BAD_GATEWAY,
                    "aptos_upstream_response_error",
                    "The Aptos full node response could not be read",
                );
            }
        } {
            if body.len().saturating_add(chunk.len()) > body_limit {
                return proxy_error(
                    StatusCode::BAD_GATEWAY,
                    "aptos_upstream_response_too_large",
                    "The Aptos full node response exceeds the listener limit",
                );
            }
            body.extend_from_slice(&chunk);
        }

        let mut builder = HttpResponse::builder().status(status);
        for (name, value) in &headers {
            if forward_response_header(name) {
                builder = builder.header(name.clone(), value.clone());
            }
        }
        builder
            .body(HttpBody::from(hyper::body::Bytes::from(body)))
            .unwrap_or_else(|_| {
                proxy_error(
                    StatusCode::BAD_GATEWAY,
                    "aptos_upstream_response_error",
                    "The Aptos full node returned invalid response headers",
                )
            })
    }
}

fn forward_response_header(name: &HeaderName) -> bool {
    let blocked = [
        CONNECTION,
        CONTENT_LENGTH,
        hyper::header::TRANSFER_ENCODING,
        hyper::header::UPGRADE,
        hyper::header::SET_COOKIE,
        hyper::header::LOCATION,
    ];
    !blocked.iter().any(|candidate| name == candidate)
        && !name.as_str().starts_with("access-control-")
        && !matches!(
            name.as_str(),
            "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailer"
        )
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
    upstream: Option<AptosUpstream>,
}

impl AptosGateway {
    pub fn new(chain: ChainHandle, node: NodeClient) -> Self {
        Self {
            chain,
            node,
            upstream: None,
        }
    }

    pub fn with_upstream(mut self, upstream: AptosUpstream) -> Self {
        self.upstream = Some(upstream);
        self
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

    /// Forward only known table routes when an upstream is configured. Bad
    /// methods and unknown paths are answered locally and never read a body.
    pub async fn handle_request<B>(&self, req: HttpRequest<B>, body_limit: usize) -> HttpResponse
    where
        B: hyper::body::Body<Data = hyper::body::Bytes> + Send + Unpin + 'static,
        B::Error: Send + 'static,
    {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        match (&self.upstream, classify(&method, &path)) {
            (Some(upstream), RouteMatch::Found(_)) => upstream.forward(req, body_limit).await,
            _ => self.handle(&method, &path).await,
        }
    }

    /// Answer one classified REST request locally. POST bodies are not read
    /// while the Move worker is absent: a named refusal must not become a body
    /// parser or an allocation door.
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
