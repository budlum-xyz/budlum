//! `budlum-indexer`: the read-only explorer API.
//!
//! The indexer follows a node's finalized chain through the node's public
//! JSON-RPC, stores every finalized block and its transactions in a local
//! `sled` database, and serves them as read-only JSON over HTTP. It indexes
//! only finalized blocks, so nothing it has served is ever taken back by a
//! reorg, and it writes nothing to the chain.
//!
//! What the index holds (history the node does not keep in a queryable
//! form): blocks by height and hash, transactions by hash, every address's
//! transactions, and each block producer's record (blocks produced, first and
//! last height). Current-state reads (domains, global headers, BNS names,
//! B.U.D. manifests) are answered from the node, so they are never stale
//! copies. The contract is `docs/explorer-api.openapi.yaml`.
//!
//! # Usage
//!
//! ```text
//! budlum-indexer --rpc-url http://127.0.0.1:18545 \
//!     --db ./data/testnet/indexer --listen 127.0.0.1:18700
//! curl http://127.0.0.1:18700/v1/status
//! ```

use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// Blocks fetched per follow step.
const BLOCKS_PER_STEP: u64 = 100;
/// How often the follower asks for the finalized height.
const FOLLOW_INTERVAL: Duration = Duration::from_secs(2);
/// The largest page a list endpoint returns.
const MAX_PAGE: usize = 100;

#[derive(Parser, Debug)]
#[command(
    name = "budlum-indexer",
    about = "Read-only explorer API over a node's finalized chain"
)]
struct Cli {
    /// The node's public JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:18545")]
    rpc_url: String,
    /// The index database directory.
    #[arg(long, default_value = "./data/indexer")]
    db: String,
    /// The HTTP listener of the API.
    #[arg(long, default_value = "127.0.0.1:18700")]
    listen: String,
}

struct Node {
    url: String,
    http: reqwest::Client,
}

impl Node {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let value: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{method}: node unreachable: {e}"))?
            .json()
            .await
            .map_err(|e| format!("{method}: answer is not JSON: {e}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("{method}: {error}"));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: answer has no result"))
    }
}

/// A hex id without a `0x` prefix, lower case.
fn normalize(id: &str) -> String {
    id.strip_prefix("0x").unwrap_or(id).to_ascii_lowercase()
}

/// A `0x` quantity or a decimal number.
fn quantity(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    let text = value.as_str()?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The index: four trees in one sled database.
struct Index {
    db: sled::Db,
    /// height (8 bytes, big endian) -> block JSON
    blocks: sled::Tree,
    /// block hash -> height
    block_hashes: sled::Tree,
    /// transaction hash -> `{"blockNumber", "index", "transaction"}`
    txs: sled::Tree,
    /// address ‖ height ‖ index (big endian) -> transaction hash
    address_txs: sled::Tree,
    /// producer -> `{"blocks", "first", "last"}`
    producers: sled::Tree,
}

const NEXT_HEIGHT: &[u8] = b"next_height";

impl Index {
    fn open(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
        let tree = |name: &str| db.open_tree(name).map_err(|e| format!("tree {name}: {e}"));
        Ok(Self {
            blocks: tree("blocks")?,
            block_hashes: tree("block_hashes")?,
            txs: tree("txs")?,
            address_txs: tree("address_txs")?,
            producers: tree("producers")?,
            db,
        })
    }

    fn next_height(&self) -> u64 {
        self.db
            .get(NEXT_HEIGHT)
            .ok()
            .flatten()
            .and_then(|v| <[u8; 8]>::try_from(v.as_ref()).ok())
            .map_or(0, u64::from_be_bytes)
    }

    /// Store one finalized block and everything derived from it, then move
    /// the cursor past it.
    fn add_block(&self, height: u64, block: &serde_json::Value) -> Result<(), String> {
        let store = |e: sled::Error| format!("index write: {e}");
        let key = height.to_be_bytes();
        if let Some(hash) = block.get("hash").and_then(|h| h.as_str()) {
            self.block_hashes
                .insert(normalize(hash).as_bytes(), &key)
                .map_err(store)?;
        }
        let empty = Vec::new();
        let txs = block
            .get("transactions")
            .and_then(|t| t.as_array())
            .unwrap_or(&empty);
        for (index, tx) in txs.iter().enumerate() {
            let Some(hash) = tx.get("hash").and_then(|h| h.as_str()).map(normalize) else {
                continue;
            };
            let record = serde_json::json!({
                "blockNumber": height,
                "index": index,
                "transaction": tx,
            });
            self.txs
                .insert(hash.as_bytes(), record.to_string().as_bytes())
                .map_err(store)?;
            let position = u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes();
            for side in ["from", "to"] {
                if let Some(address) = tx.get(side).and_then(|a| a.as_str()).map(normalize) {
                    let mut k = address.into_bytes();
                    k.extend_from_slice(&key);
                    k.extend_from_slice(&position);
                    self.address_txs.insert(k, hash.as_bytes()).map_err(store)?;
                }
            }
        }
        if let Some(producer) = block
            .get("producer")
            .and_then(|p| p.as_str())
            .map(normalize)
        {
            let previous: serde_json::Value = self
                .producers
                .get(producer.as_bytes())
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_slice(&v).ok())
                .unwrap_or_else(|| serde_json::json!({"blocks": 0, "first": height}));
            let blocks = previous.get("blocks").and_then(|b| b.as_u64()).unwrap_or(0);
            let first = previous
                .get("first")
                .and_then(|f| f.as_u64())
                .unwrap_or(height);
            let record = serde_json::json!({
                "blocks": blocks.saturating_add(1),
                "first": first,
                "last": height,
            });
            self.producers
                .insert(producer.as_bytes(), record.to_string().as_bytes())
                .map_err(store)?;
        }
        self.blocks
            .insert(key, block.to_string().as_bytes())
            .map_err(store)?;
        self.db
            .insert(NEXT_HEIGHT, &height.saturating_add(1).to_be_bytes())
            .map_err(store)?;
        self.db.flush().map_err(store)?;
        Ok(())
    }

    fn block(&self, height: u64) -> Option<serde_json::Value> {
        let raw = self.blocks.get(height.to_be_bytes()).ok()??;
        serde_json::from_slice(&raw).ok()
    }

    fn block_by_hash(&self, hash: &str) -> Option<serde_json::Value> {
        let raw = self.block_hashes.get(normalize(hash).as_bytes()).ok()??;
        let height = u64::from_be_bytes(<[u8; 8]>::try_from(raw.as_ref()).ok()?);
        self.block(height)
    }

    fn latest_blocks(&self, limit: usize) -> Vec<serde_json::Value> {
        self.blocks
            .iter()
            .rev()
            .take(limit)
            .filter_map(|entry| entry.ok())
            .filter_map(|(_, raw)| serde_json::from_slice(&raw).ok())
            .collect()
    }

    fn tx(&self, hash: &str) -> Option<serde_json::Value> {
        let raw = self.txs.get(normalize(hash).as_bytes()).ok()??;
        serde_json::from_slice(&raw).ok()
    }

    /// An address's transactions, newest first, below `before` when given.
    fn address_history(
        &self,
        address: &str,
        before: Option<u64>,
        limit: usize,
    ) -> Vec<serde_json::Value> {
        let prefix = normalize(address).into_bytes();
        let mut upper = prefix.clone();
        upper.extend_from_slice(&before.unwrap_or(u64::MAX).to_be_bytes());
        self.address_txs
            .range(prefix.clone()..upper)
            .rev()
            .take(limit)
            .filter_map(|entry| entry.ok())
            .filter_map(|(_, hash)| std::str::from_utf8(&hash).ok().and_then(|h| self.tx(h)))
            .collect()
    }

    fn producers(&self) -> Vec<serde_json::Value> {
        self.producers
            .iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|(address, raw)| {
                let mut record: serde_json::Value = serde_json::from_slice(&raw).ok()?;
                record["address"] =
                    serde_json::Value::String(format!("0x{}", String::from_utf8_lossy(&address)));
                Some(record)
            })
            .collect()
    }
}

/// Fetch every finalized block the index does not hold yet, in height order.
async fn follow_step(node: &Node, index: &Index) -> Result<u64, String> {
    let status = node.call("bud_getStatus", serde_json::json!([])).await?;
    let finalized = status
        .get("finalizedHeight")
        .and_then(quantity)
        .ok_or("bud_getStatus has no finalizedHeight")?;
    let mut next = index.next_height();
    let last = finalized.min(next.saturating_add(BLOCKS_PER_STEP - 1));
    while next <= last {
        let block = node
            .call("bud_getBlockByNumber", serde_json::json!([next]))
            .await?;
        if block.is_null() {
            return Err(format!("the node has no block {next}"));
        }
        index.add_block(next, &block)?;
        next = next.saturating_add(1);
    }
    Ok(finalized)
}

async fn follow(node: Arc<Node>, index: Arc<Index>) {
    loop {
        if let Err(e) = follow_step(&node, &index).await {
            eprintln!("budlum-indexer: follow: {e}");
        }
        tokio::time::sleep(FOLLOW_INTERVAL).await;
    }
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in [
        (hyper::header::CONTENT_TYPE, "application/json"),
        // A public read-only API: any origin may read it.
        (hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
    ] {
        if let Ok(value) = hyper::header::HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    }
    response
}

fn found(value: Option<serde_json::Value>) -> Response<Full<Bytes>> {
    value.map_or_else(
        || {
            json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({"error": "not found"}),
            )
        },
        |v| json_response(StatusCode::OK, &v),
    )
}

/// One query parameter of `query`.
fn param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

fn limit(query: &str) -> usize {
    param(query, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(20, |n| n.clamp(1, MAX_PAGE))
}

/// Answer a current-state read from the node.
async fn from_node(node: &Node, method: &str, params: serde_json::Value) -> Response<Full<Bytes>> {
    match node.call(method, params).await {
        Ok(serde_json::Value::Null) => found(None),
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(e) => json_response(StatusCode::BAD_GATEWAY, &serde_json::json!({"error": e})),
    }
}

async fn route(node: &Node, index: &Index, path: &str, query: &str) -> Response<Full<Bytes>> {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["health"] => json_response(StatusCode::OK, &serde_json::json!({"ok": true})),
        ["v1", "status"] => {
            let node_status = node.call("bud_getStatus", serde_json::json!([])).await.ok();
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "indexedHeight": index.next_height().checked_sub(1),
                    "node": node_status,
                }),
            )
        }
        ["v1", "blocks"] => json_response(
            StatusCode::OK,
            &serde_json::Value::Array(index.latest_blocks(limit(query))),
        ),
        ["v1", "blocks", "hash", hash] => found(index.block_by_hash(hash)),
        ["v1", "blocks", height] => found(height.parse().ok().and_then(|h| index.block(h))),
        ["v1", "txs", hash] => found(index.tx(hash)),
        ["v1", "addresses", address, "txs"] => {
            let before = param(query, "before").and_then(|b| b.parse().ok());
            json_response(
                StatusCode::OK,
                &serde_json::Value::Array(index.address_history(address, before, limit(query))),
            )
        }
        ["v1", "producers"] => {
            json_response(StatusCode::OK, &serde_json::Value::Array(index.producers()))
        }
        ["v1", "domains"] => {
            from_node(node, "bud_getConsensusDomains", serde_json::json!([])).await
        }
        ["v1", "domains", id] => match id.parse::<u32>() {
            Ok(id) => from_node(node, "bud_getDomainInfo", serde_json::json!([id])).await,
            Err(_) => found(None),
        },
        ["v1", "external-domains"] => {
            from_node(node, "bud_getExternalDomains", serde_json::json!([])).await
        }
        ["v1", "global-headers", height] => match height.parse::<u64>() {
            Ok(h) => from_node(node, "bud_getGlobalHeader", serde_json::json!([h])).await,
            Err(_) => found(None),
        },
        ["v1", "bns", name] => {
            from_node(node, "bud_bnsResolveFull", serde_json::json!([name])).await
        }
        ["v1", "manifests", id] => {
            from_node(node, "bud_storageGetManifest", serde_json::json!([id])).await
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "unknown path; see docs/explorer-api.openapi.yaml"}),
        ),
    }
}

async fn handle(
    node: Arc<Node>,
    index: Arc<Index>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if request.method() != Method::GET {
        return Ok(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({"error": "the explorer API is read-only (GET)"}),
        ));
    }
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    Ok(route(&node, &index, &path, &query).await)
}

async fn serve(cli: Cli) -> Result<(), String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let node = Arc::new(Node {
        url: cli.rpc_url,
        http,
    });
    let index = Arc::new(Index::open(&cli.db)?);
    tokio::spawn(follow(node.clone(), index.clone()));
    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", cli.listen))?;
    eprintln!(
        "budlum-indexer: index at height {}, listening on {}",
        index.next_height(),
        cli.listen
    );
    loop {
        let (stream, peer): (_, SocketAddr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("budlum-indexer: accept failed: {e}");
                continue;
            }
        };
        let (node, index) = (node.clone(), index.clone());
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request| {
                handle(node.clone(), index.clone(), request)
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                eprintln!("budlum-indexer: connection from {peer} ended: {e}");
            }
        });
    }
}

fn main() -> ExitCode {
    budlum_core::crypto::tls::install_default_provider();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("budlum-indexer: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("budlum-indexer: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(height: u64, producer: &str, txs: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "number": format!("0x{height:x}"),
            "hash": format!("0x{:064x}", height + 1),
            "producer": producer,
            "transactions": txs,
        })
    }

    #[test]
    fn a_block_is_indexed_by_height_hash_transaction_address_and_producer() {
        let dir = tempfile::tempdir().expect("temp dir");
        let index = Index::open(dir.path().to_str().expect("utf-8")).expect("opens");
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        let tx = serde_json::json!({"hash": "0xT1", "from": alice, "to": bob});
        index
            .add_block(0, &block(0, "p1", serde_json::json!([])))
            .expect("indexes");
        index
            .add_block(1, &block(1, "p1", serde_json::json!([tx])))
            .expect("indexes");
        assert_eq!(index.next_height(), 2);
        assert!(index.block(1).is_some());
        assert!(index.block_by_hash(&format!("{:064x}", 2)).is_some());
        assert_eq!(index.tx("0xt1").expect("indexed")["blockNumber"], 1);
        assert_eq!(
            index.address_history(&format!("0x{bob}"), None, 10).len(),
            1
        );
        assert_eq!(index.address_history(&alice, Some(1), 10).len(), 0);
        let producers = index.producers();
        assert_eq!(producers.len(), 1);
        assert_eq!(producers[0]["blocks"], 2);
        assert_eq!(index.latest_blocks(1)[0]["number"], "0x1");
    }

    #[test]
    fn quantities_and_pages_are_read_defensively() {
        assert_eq!(quantity(&serde_json::json!("0x10")), Some(16));
        assert_eq!(quantity(&serde_json::json!(7)), Some(7));
        assert_eq!(quantity(&serde_json::json!("x")), None);
        assert_eq!(limit("limit=5000"), MAX_PAGE);
        assert_eq!(limit(""), 20);
        assert_eq!(param("a=1&before=9", "before"), Some("9"));
    }
}
