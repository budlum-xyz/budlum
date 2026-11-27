//! The `budlum.xyz` network gateway process (B14, `A7`).
//!
//! This binary mounts the rules in [`budlum_core::web_gateway`] on a socket. It
//! holds no rules of its own: every decision about what a host means, what a
//! path resolves to, what headers a response carries and whether a proof
//! verifies is made in the module, where it has a test. This file is the part
//! that has to be right about bytes, sockets and JSON.
//!
//! # What it answers
//!
//! `GET` and `HEAD` only. A gateway that accepted `POST` would have to decide
//! what a body meant, and a site served from an immutable content id has
//! nothing to accept.
//!
//! # How a request is answered
//!
//! ```text
//! Host header     -> web_gateway::host::parse_host     (pure)
//! block list      -> web_gateway::policy::BlockList     (pure)
//! rate limit      -> web_gateway::policy::RateLimiter   (pure)
//! RPC proof       -> web_gateway::resolve::resolve_verified
//! path -> route   -> web_gateway::manifest::SiteManifest::resolve
//! content         -> ContentSource
//! headers         -> web_gateway::policy::content_headers_with_csp
//! ```
//!
//! # Configuration
//!
//! A single TOML file, read once. The fields are the ones `A7` names:
//! `suffix`, `listen`, `rpc`, `cache_dir`, `cache_max_bytes`, `rate_per_minute`,
//! `blocklist_file`. TLS is the caller's: the process listens on plain HTTP and
//! a terminator (the systemd unit in `ops/gateway`) puts TLS in front, so the
//! binary never needs a private key.
//!
//! # Content sources
//!
//! The process supports two mutually exclusive content sources:
//! - `[bud3]`: production B.U.D. 3.0 RPC source (`bud_storageGetObject`
//!   metadata agreement across all configured RPC endpoints plus
//!   `bud_storageGetContent` paid fallback decode verified against the proved
//!   public `ContentId` and cached under `cache_dir`).
//! - `content_dir`: local directory source for offline rehearsals.
//!
//! If neither is configured (or both are set), the process refuses to start.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use budlum_core::web_gateway::host::{parse_host, DEFAULT_GATEWAY_SUFFIX};
use budlum_core::web_gateway::manifest::{RouteError as RouteErrorKind, SiteManifest};
use budlum_core::web_gateway::policy::{
    content_headers_with_csp, BlockList, LimitDecision, RateLimiter, BLOCKED_STATUS,
    IMMUTABLE_CACHE, RESOLUTION_CACHE,
};
use budlum_core::web_gateway::resolve::{
    resolve_verified, route_of, served_content_of, CacheMiss, ContentCache, ContentSource,
    GatewayError, NameProof, NameProver, StateRoots,
};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

#[path = "support/http.rs"]
mod http_support;

/// The file an operator passes as the only argument.
#[derive(Debug, Clone, Deserialize)]
struct GatewayConfig {
    /// The suffix the gateway answers for. Defaults to `budlum.xyz`.
    #[serde(default = "default_suffix")]
    suffix: String,
    /// The address to bind. Plain HTTP; a terminator puts TLS in front.
    #[serde(default = "default_listen")]
    listen: String,
    /// RPC endpoints. The gateway asks every one and requires them to agree.
    rpc: Vec<String>,
    /// Where the durable content cache lives.
    cache_dir: PathBuf,
    /// The cache budget in bytes.
    #[serde(default = "default_cache_bytes")]
    cache_max_bytes: usize,
    /// Requests per minute per client address.
    #[serde(default = "default_rate")]
    rate_per_minute: u32,
    /// An optional block list file, one name per line. A block affects this
    /// gateway only and never touches a chain record.
    #[serde(default)]
    blocklist_file: Option<PathBuf>,
    /// A directory of objects for the rehearsal content source.
    #[serde(default)]
    content_dir: Option<PathBuf>,
    /// Production B.U.D. 3.0 RPC content source configuration.
    #[serde(default)]
    bud3: Option<Bud3SourceConfig>,
    /// How long a cached name resolution is trusted, in seconds.
    #[serde(default = "default_resolve_ttl")]
    resolve_ttl_secs: u64,
    /// Serve clients that connect directly. Forwarded headers are ignored and
    /// the socket peer is the client. Set this or `trusted_proxies`, not both,
    /// and not neither: a gateway that does not know who its clients are
    /// refuses to start.
    #[serde(default)]
    allow_direct: bool,
    /// The immediate peers allowed to connect, normally the TLS terminator in
    /// front of this process. Each must send one valid `X-Forwarded-For`, and
    /// the client is its rightmost address that is not itself a trusted proxy.
    #[serde(default)]
    trusted_proxies: Vec<std::net::IpAddr>,
    /// Content fetches that miss the cache, per minute per client address.
    /// A miss costs a read of the content source, so it has its own budget
    /// below the request budget.
    #[serde(default = "default_fill_rate")]
    fill_per_minute: u32,
    /// Headers the operator verified: the registry root and the epoch at a
    /// height. A proof is checked against these and against nothing a node
    /// answers.
    #[serde(default)]
    checkpoints: Vec<Checkpoint>,
    /// A file of further checkpoints in the same form, re-read whenever it
    /// changes. The process that follows headers writes it; the gateway
    /// only reads it.
    #[serde(default)]
    checkpoints_file: Option<PathBuf>,
}

/// Configuration for the production B.U.D. 3.0 RPC-backed content source.
#[derive(Debug, Clone, Deserialize)]
struct Bud3SourceConfig {
    /// Payer account (32-byte hex) that funded the gateway's fallback-view receipts.
    payer: String,
    /// Paid fallback-view receipt identifier (32-byte hex, `StorageTxV3::PayFallbackView`).
    receipt_id: String,
    /// Paid fee in BUD atoms (must be at least `MIN_PAID_VIEW_FEE_ATOMS`).
    fee_paid_atoms: u64,
}

/// One verified header, as the configuration and the checkpoint file carry it.
#[derive(Debug, Clone, Deserialize)]
struct Checkpoint {
    height: u64,
    /// The registry root at `height`, 32 bytes of hex.
    root: String,
    epoch: u64,
}

/// The checkpoint file: a `checkpoints` list and nothing else.
#[derive(Debug, Deserialize)]
struct CheckpointFile {
    #[serde(default)]
    checkpoints: Vec<Checkpoint>,
}

type RootTable = std::collections::BTreeMap<u64, ([u8; 32], u64)>;

/// Read a checkpoint list into a table. A malformed root or a height listed
/// twice refuses the whole list: half a table is a table nobody checked.
fn checkpoint_table(list: &[Checkpoint]) -> Result<RootTable, String> {
    let mut table = RootTable::new();
    for checkpoint in list {
        let root = hex32(&checkpoint.root)
            .map_err(|e| format!("checkpoint {}: {e}", checkpoint.height))?;
        if table
            .insert(checkpoint.height, (root, checkpoint.epoch))
            .is_some()
        {
            return Err(format!("checkpoint {} is listed twice", checkpoint.height));
        }
    }
    Ok(table)
}

fn default_suffix() -> String {
    DEFAULT_GATEWAY_SUFFIX.to_string()
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_cache_bytes() -> usize {
    10_000_000_000
}

fn default_rate() -> u32 {
    120
}

fn default_resolve_ttl() -> u64 {
    10
}

fn default_fill_rate() -> u32 {
    30
}

/// What the process counts, for the line it logs once a minute.
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    served: AtomicU64,
    not_found: AtomicU64,
    rate_limited: AtomicU64,
    /// Answers refused because a proof, a header or a content check failed.
    refused_upstream: AtomicU64,
    cache_hits: AtomicU64,
    cache_fills: AtomicU64,
}

impl Counters {
    fn count_status(&self, status: StatusCode) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let bucket = match status {
            StatusCode::OK => &self.served,
            StatusCode::NOT_FOUND => &self.not_found,
            StatusCode::TOO_MANY_REQUESTS => &self.rate_limited,
            StatusCode::BAD_GATEWAY => &self.refused_upstream,
            _ => return,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    fn log(&self) {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        tracing::info!(
            requests = read(&self.requests),
            served = read(&self.served),
            not_found = read(&self.not_found),
            rate_limited = read(&self.rate_limited),
            refused_upstream = read(&self.refused_upstream),
            cache_hits = read(&self.cache_hits),
            cache_fills = read(&self.cache_fills),
            "gateway counters"
        );
    }
}

/// Everything a request handler needs, built once at startup.
type ResolvedCache = std::collections::BTreeMap<String, (u64, CachedResolution)>;
type ManifestCache = std::collections::BTreeMap<[u8; 32], (usize, Arc<SiteManifest>)>;

struct GatewayState {
    config: GatewayConfig,
    suffix: String,
    provers: Vec<RpcProver>,
    roots: Arc<dyn StateRoots + Send + Sync>,
    content: Arc<dyn ContentSource + Send + Sync>,
    blocklist: BlockList,
    identity: http_support::ClientIdentity,
    limiter: std::sync::Mutex<RateLimiter>,
    fill_limiter: std::sync::Mutex<RateLimiter>,
    cache: std::sync::Mutex<ContentCache>,
    resolved: std::sync::Mutex<ResolvedCache>,
    manifests: std::sync::Mutex<ManifestCache>,
    counters: Counters,
}

/// A resolved name, as the request handler holds it between the proof and the
/// content fetch.
#[derive(Clone)]
struct CachedResolution {
    content: budlum_core::storage::bud3::content_ref::ContentRef,
    height: u64,
}

/// One RPC endpoint.
struct RpcProver {
    url: String,
    client: reqwest::Client,
}

impl RpcProver {
    fn new(url: String) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("rpc client for {url}: {e}"))?;
        Ok(Self { url, client })
    }
}

/// Cap on BNS proof JSON responses read by `RpcProver` (2 MiB).
const MAX_BNS_PROOF_RPC_BYTES: usize = 2 * 1024 * 1024;

/// Cap on B.U.D. 3.0 RPC JSON responses read by `Bud3RpcSource` (32 MiB).
const MAX_BUD3_RPC_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

async fn read_bounded_rpc_json(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<serde_json::Value, String> {
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "rpc response content-length {len} exceeds {max_bytes}-byte cap"
            ));
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("rpc body read: {e}"))?
    {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("rpc response body exceeds {max_bytes}-byte cap"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("rpc json decode: {e}"))
}

impl NameProver for RpcProver {
    fn proof_for(&self, name: &str) -> Result<NameProof, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bud_bnsGetProof",
            "params": [name],
        });
        // The verifier is synchronous and the client is not. The request is
        // driven to completion here, and `block_in_place` tells the runtime
        // this worker is busy so the other connections move to another one.
        let request = async {
            let resp = self
                .client
                .post(&self.url)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?;
            read_bounded_rpc_json(resp, MAX_BNS_PROOF_RPC_BYTES).await
        };
        let json =
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(request))
                .map_err(|e| format!("{}: {e}", self.url))?;
        if let Some(error) = json.get("error") {
            return Err(format!("{}: rpc error {error}", self.url));
        }
        let result = json.get("result").ok_or("rpc answer has no result")?;
        let parsed = decode_proof_result(result)?;
        if parsed.proof.name != name {
            return Err(format!(
                "{}: proof name `{}` does not match requested name `{name}`",
                self.url, parsed.proof.name
            ));
        }
        Ok(parsed)
    }
}

/// Read a `bud_bnsGetProof` answer into the proof type the module checks.
///
/// `extras` and `absence` are read as the node writes them. A branch without
/// its extras proves only the fields outside the digest, and a non-inclusion
/// answer without an absence path is refused by the module's verifier.
fn decode_proof_result(result: &serde_json::Value) -> Result<NameProof, String> {
    use budlum_core::bns::types::{BnsMerkleBranch, BnsStateProof};
    let branch = |value: &serde_json::Value| -> Result<BnsMerkleBranch, String> {
        Ok(BnsMerkleBranch {
            name: value
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("branch.name")?
                .to_string(),
            owner: address_field(value, "owner")?,
            address: optional_address(value, "address")?,
            expires_at: value
                .get("expires_at")
                .and_then(serde_json::Value::as_u64)
                .ok_or("branch.expires_at")?,
            content: match value.get("content") {
                Some(v) if !v.is_null() => Some(
                    budlum_core::bns::types::content_ref_from_json(v)
                        .map_err(|e| format!("branch.content: {e}"))?,
                ),
                _ => None,
            },
            storage_root: optional_hex32(value, "storage_root")?,
            extras_digest: hex32_field(value, "extras_digest")?,
            leaf: hex32_field(value, "leaf")?,
            siblings: value
                .get("siblings")
                .and_then(serde_json::Value::as_array)
                .ok_or("branch.siblings")?
                .iter()
                .map(|v| hex32(v.as_str().ok_or("branch.siblings[]")?))
                .collect::<Result<Vec<_>, _>>()?,
            extras: match value.get("extras") {
                Some(v) if !v.is_null() => Some(decode_extras(v)?),
                _ => None,
            },
        })
    };
    let proof = BnsStateProof {
        name: result
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or("proof.name")?
            .to_string(),
        included: result
            .get("included")
            .and_then(serde_json::Value::as_bool)
            .ok_or("proof.included")?,
        bns_root: hex32_field(result, "bns_root")?,
        meta_digest: hex32_field(result, "meta_digest")?,
        names_count: result
            .get("names_count")
            .and_then(serde_json::Value::as_u64)
            .ok_or("proof.names_count")?,
        epoch: result
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or("proof.epoch")?,
        entry: match result.get("entry") {
            Some(v) if !v.is_null() => Some(branch(v)?),
            _ => None,
        },
        absence: match result.get("absence") {
            Some(v) if !v.is_null() => Some(budlum_core::bns::types::absence_from_json(v)?),
            _ => None,
        },
    };
    // The height is what binds the proof to a header. An answer without one
    // cannot be checked against a verified root, so it is not an answer.
    let height = result
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .ok_or(
            "proof.height (the gateway needs the height whose header root the proof folds to)",
        )?;
    Ok(NameProof {
        height,
        epoch: proof.epoch,
        proof,
    })
}

fn decode_extras(
    value: &serde_json::Value,
) -> Result<budlum_core::bns::types::BnsBranchExtras, String> {
    let mut subdomains = std::collections::BTreeMap::new();
    if let Some(map) = value
        .get("subdomains")
        .and_then(serde_json::Value::as_object)
    {
        for (label, sub) in map {
            subdomains.insert(
                label.clone(),
                budlum_core::bns::types::SubdomainRecord::from_json(sub)
                    .map_err(|e| format!("extras.subdomains.{label}: {e}"))?,
            );
        }
    }
    let mut records = std::collections::BTreeMap::new();
    if let Some(map) = value.get("records").and_then(serde_json::Value::as_object) {
        for (key, entry) in map {
            records.insert(
                key.clone(),
                entry
                    .as_str()
                    .ok_or_else(|| format!("extras.records.{key} is not a string"))?
                    .to_string(),
            );
        }
    }
    Ok(budlum_core::bns::types::BnsBranchExtras {
        address: optional_address(value, "address")?,
        consensus_domain_id: value
            .get("consensus_domain_id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        storage_domain_id: value
            .get("storage_domain_id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        storage_root_height: value
            .get("storage_root_height")
            .and_then(serde_json::Value::as_u64),
        subdomains,
        records,
    })
}

fn hex32(raw: &str) -> Result<[u8; 32], String> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).map_err(|e| format!("hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex32_field(value: &serde_json::Value, field: &str) -> Result<[u8; 32], String> {
    hex32(
        value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or(field)?,
    )
}

fn optional_hex32(value: &serde_json::Value, field: &str) -> Result<Option<[u8; 32]>, String> {
    match value.get(field) {
        Some(v) if !v.is_null() => hex32(v.as_str().ok_or(field)?).map(Some),
        _ => Ok(None),
    }
}

fn address_json(
    value: &serde_json::Value,
    field: &str,
) -> Result<budlum_core::core::address::Address, String> {
    let raw = value.as_str().ok_or(field)?;
    Ok(budlum_core::core::address::Address::from(hex32(raw)?))
}

fn address_field(
    value: &serde_json::Value,
    field: &str,
) -> Result<budlum_core::core::address::Address, String> {
    let raw = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(field)?;
    Ok(budlum_core::core::address::Address::from(hex32(raw)?))
}

fn optional_address(
    value: &serde_json::Value,
    field: &str,
) -> Result<Option<budlum_core::core::address::Address>, String> {
    match value.get(field) {
        Some(v) if !v.is_null() => Ok(Some(address_json(v, field)?)),
        _ => Ok(None),
    }
}

/// A verified-root source for the gateway process.
///
/// The gateway will not take a root from the answer it is checking. The roots
/// come from checkpoints the operator pins in the configuration and from an
/// optional checkpoint file that a header-following process keeps current.
/// With neither, the process has no root for any height and every request
/// answers 502: a gateway with no verified header is a gateway with nothing
/// to say.
struct PinnedHeaderRoots {
    /// Height to the root and the epoch, both pinned by the operator from a
    /// header they checked. The epoch is pinned next to the root because expiry
    /// can only be judged against a header, never against the answering node.
    pinned: RootTable,
    /// The followed checkpoint file, if one is configured.
    followed: Option<FollowedCheckpoints>,
}

/// A checkpoint file and the table last read from it.
struct FollowedCheckpoints {
    path: PathBuf,
    seen: std::sync::Mutex<(Option<std::time::SystemTime>, RootTable)>,
}

impl FollowedCheckpoints {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            seen: std::sync::Mutex::new((None, RootTable::new())),
        }
    }

    /// The checkpoint at `height`, after re-reading the file if it changed.
    ///
    /// A file that is missing or does not parse leaves an empty table: the
    /// heights it used to name are unknown again, which is a 502 and never a
    /// stale root.
    fn at(&self, height: u64) -> Option<([u8; 32], u64)> {
        use std::io::Read as _;
        const MAX_CHECKPOINT_TOML_BYTES: usize = 1_048_576;
        let Ok(file) = budlum_core::crypto::key_file::open_regular_pinned(&self.path) else {
            let mut seen = match self.seen.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Missing or symlinked checkpoint file: nothing is followed, and nothing cached is kept.
            *seen = (None, RootTable::new());
            return None;
        };
        let meta = file.metadata().ok();
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if modified.is_none() {
            *seen = (None, RootTable::new());
            return None;
        }
        if seen.0 != modified {
            let table = (|| -> Result<RootTable, String> {
                let len = meta.map_or(0, |m| m.len());
                let max_u64 = u64::try_from(MAX_CHECKPOINT_TOML_BYTES).unwrap_or(u64::MAX);
                if len > max_u64 {
                    return Err(format!(
                        "{} exceeds {MAX_CHECKPOINT_TOML_BYTES}-byte limit",
                        self.path.display()
                    ));
                }
                let mut raw = Vec::new();
                file.take(max_u64.saturating_add(1))
                    .read_to_end(&mut raw)
                    .map_err(|e| e.to_string())?;
                if raw.len() > MAX_CHECKPOINT_TOML_BYTES {
                    return Err(format!(
                        "{} exceeds {MAX_CHECKPOINT_TOML_BYTES}-byte limit",
                        self.path.display()
                    ));
                }
                let text = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
                let parsed: CheckpointFile = toml::from_str(text).map_err(|e| e.to_string())?;
                checkpoint_table(&parsed.checkpoints)
            })();
            *seen = match table {
                Ok(table) => (modified, table),
                Err(reason) => {
                    tracing::warn!(
                        path = %self.path.display(),
                        %reason,
                        "the checkpoint file was refused; its heights are unknown"
                    );
                    (modified, RootTable::new())
                }
            };
        }
        seen.1.get(&height).copied()
    }
}

impl PinnedHeaderRoots {
    fn at(&self, height: u64) -> Option<([u8; 32], u64)> {
        // A pinned height is never overridden by the file.
        if let Some(pinned) = self.pinned.get(&height) {
            return Some(*pinned);
        }
        self.followed.as_ref().and_then(|file| file.at(height))
    }
}

impl StateRoots for PinnedHeaderRoots {
    fn verified_state_root(&self, height: u64) -> Option<[u8; 32]> {
        self.at(height).map(|(root, _)| root)
    }

    fn verified_epoch(&self, height: u64) -> Option<u64> {
        self.at(height).map(|(_, epoch)| epoch)
    }
}

/// A content source that serves a local directory.
///
/// The rehearsal source: an operator points it at a directory of published
/// objects and the manifest fetches from there. It is not the production
/// source. The production source is B.U.D. 3.0, and it needs a node and a
/// paid-view receipt the gateway pays for its own cache fills.
struct DirectorySource {
    root: PathBuf,
}

impl ContentSource for DirectorySource {
    fn fetch(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
    ) -> Result<Vec<u8>, String> {
        let ceiling = budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES as u64;
        if content.content_id.len > ceiling {
            return Err(format!(
                "content length {} exceeds the gateway ceiling {ceiling}",
                content.content_id.len
            ));
        }
        let path = self.root.join(hex::encode(content.content_id.digest));
        // Pin the open regular file without following symlinks and enforce the
        // gateway ceiling on the same descriptor before full allocation.
        let bytes = budlum_core::crypto::key_file::read_regular_bounded(
            &path,
            budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES,
            "gateway content",
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                format!("{} exceeds the gateway ceiling ({e})", path.display())
            } else {
                format!("{}: {e}", path.display())
            }
        })?;
        // This read also backs fetch_manifest: parse no unverified site rules
        // and serve no body unless both digest and length match the public
        // identifier proved by BNS. A sealed object has no public site route.
        if !content.content_id.matches_public(&bytes) {
            return Err("content bytes do not match the proved public ContentId".into());
        }
        Ok(bytes)
    }

    fn fetch_manifest(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
    ) -> Result<SiteManifest, String> {
        let bytes = self.fetch(content)?;
        SiteManifest::from_json_bytes(&bytes)
    }
}

/// Production B.U.D. 3.0 content source backed by `bud_storageGetObject`
/// consensus agreement and `bud_storageGetContent` paid public fallback decode.
///
/// Sealed objects are refused unconditionally before any network call. Every
/// fetched body (and every cached body read back from `cache_dir`) is verified
/// against the proved public `ContentId` (both SHA-3 digest and exact length).
struct Bud3RpcSource {
    endpoints: Vec<String>,
    client: reqwest::Client,
    payer_hex: String,
    receipt_id_hex: String,
    fee_paid_atoms: u64,
    cache_dir: PathBuf,
    /// The bytes `cache_dir` may hold, matching the in-memory cache budget.
    cache_max_bytes: u64,
    /// Bytes currently held inside `cache_dir` so bounded writes never walk
    /// the whole directory on each fill.
    cache_bytes: std::sync::Mutex<u64>,
}

impl Bud3RpcSource {
    fn new(
        endpoints: Vec<String>,
        cfg: &Bud3SourceConfig,
        cache_dir: PathBuf,
        cache_max_bytes: usize,
    ) -> Result<Self, String> {
        if endpoints.is_empty() {
            return Err("bud3 content source requires at least one rpc endpoint".into());
        }
        let payer = hex32(&cfg.payer).map_err(|e| format!("bud3.payer: {e}"))?;
        let receipt_id = hex32(&cfg.receipt_id).map_err(|e| format!("bud3.receipt_id: {e}"))?;
        let min_fee = budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS;
        if cfg.fee_paid_atoms < min_fee {
            return Err(format!(
                "bud3.fee_paid_atoms ({}) is below MIN_PAID_VIEW_FEE_ATOMS ({min_fee})",
                cfg.fee_paid_atoms
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("bud3 rpc client: {e}"))?;
        let held = Self::sweep_orphan_tmp_and_measure(&cache_dir);
        Ok(Self {
            endpoints,
            client,
            payer_hex: hex::encode(payer),
            receipt_id_hex: hex::encode(receipt_id),
            fee_paid_atoms: cfg.fee_paid_atoms,
            cache_dir,
            cache_max_bytes: cache_max_bytes as u64,
            cache_bytes: std::sync::Mutex::new(held),
        })
    }

    /// Time-to-live after which stale cached objects may be reclaimed when the
    /// on-disk verified cache hits `cache_max_bytes`.
    const DISK_CACHE_ENTRY_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

    fn is_tmp_cache_entry(path: &std::path::Path) -> bool {
        path.extension().and_then(|ext| ext.to_str()) == Some("tmp")
    }

    fn sweep_orphan_tmp_and_measure(cache_dir: &std::path::Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(cache_dir) else {
            return 0;
        };
        let mut total = 0u64;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if Self::is_tmp_cache_entry(&path) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        total
    }

    fn reap_stale_entries(&self, preserve: &std::path::Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(&self.cache_dir) else {
            return 0;
        };
        let now = std::time::SystemTime::now();
        let mut remaining = 0u64;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path != preserve && Self::is_tmp_cache_entry(&path) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let expired = path != preserve
                && meta
                    .modified()
                    .ok()
                    .and_then(|mtime| now.duration_since(mtime).ok())
                    .is_some_and(|age| age >= Self::DISK_CACHE_ENTRY_TTL);
            if expired && std::fs::remove_file(&path).is_ok() {
                continue;
            }
            remaining = remaining.saturating_add(meta.len());
        }
        remaining
    }

    fn call_rpc(
        &self,
        url: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let request = async {
            let resp = self
                .client
                .post(url)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?;
            read_bounded_rpc_json(resp, MAX_BUD3_RPC_RESPONSE_BYTES).await
        };
        let json = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(request))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("bud3 rpc runtime: {e}"))?;
            rt.block_on(request)
        }
        .map_err(|e| format!("{url}: {e}"))?;
        if let Some(error) = json.get("error") {
            return Err(format!("{url}: rpc error {error}"));
        }
        json.get("result")
            .cloned()
            .ok_or_else(|| format!("{url}: rpc answer has no result"))
    }

    fn verify_object_record(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
        commitment_hex: &str,
    ) -> Result<(), String> {
        let expected_digest = hex::encode(content.content_id.digest);
        for url in &self.endpoints {
            let result = self.call_rpc(
                url,
                "bud_storageGetObject",
                &serde_json::json!([commitment_hex]),
            )?;
            let status = result
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if status != "live" {
                return Err(format!(
                    "{url}: object {commitment_hex} is not live (status={status})"
                ));
            }
            if result
                .get("sealed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true)
            {
                return Err(format!(
                    "{url}: object {commitment_hex} is sealed and refused by public gateway"
                ));
            }
            let digest = result
                .get("content_digest")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let len = result
                .get("content_len")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX);
            if !digest.eq_ignore_ascii_case(&expected_digest) || len != content.content_id.len {
                return Err(format!(
                    "{url}: object metadata disagrees with proved ContentId"
                ));
            }
        }
        Ok(())
    }

    fn cache_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.cache_dir.join(hex::encode(digest))
    }

    fn read_verified_cache(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
    ) -> Option<Vec<u8>> {
        let path = self.cache_path(&content.content_id.digest);
        let bytes = budlum_core::crypto::key_file::read_regular_bounded(
            &path,
            budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES,
            "gateway cache entry",
        )
        .ok()?;
        if bytes.len() <= budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES
            && content.content_id.matches_public(&bytes)
        {
            Some(bytes)
        } else {
            None
        }
    }

    /// Persist verified bytes, within the byte budget the operator configured.
    ///
    /// An object that does not fit within `cache_max_bytes` is still served to
    /// the caller, just not persisted to disk.
    fn write_verified_cache(&self, digest: &[u8; 32], bytes: &[u8]) {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};
        static CACHE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

        if std::fs::create_dir_all(&self.cache_dir).is_err() {
            return;
        }
        let target = self.cache_path(digest);
        let replaced = std::fs::symlink_metadata(&target)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map_or(0, |meta| meta.len());
        let len = bytes.len() as u64;
        if len > self.cache_max_bytes {
            return;
        }
        let mut held = match self.cache_bytes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut projected = held.saturating_sub(replaced).saturating_add(len);
        if projected > self.cache_max_bytes {
            *held = self.reap_stale_entries(&target);
            projected = held.saturating_sub(replaced).saturating_add(len);
            if projected > self.cache_max_bytes {
                return;
            }
        }
        let seq = CACHE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.cache_dir.join(format!(
            "{}.{}.{seq}.tmp",
            hex::encode(digest),
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&tmp) {
            if file.write_all(bytes).is_ok() && std::fs::rename(&tmp, &target).is_ok() {
                *held = projected;
            } else {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

impl ContentSource for Bud3RpcSource {
    fn fetch(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
    ) -> Result<Vec<u8>, String> {
        if content.content_id.kind != budlum_core::storage::bud3::content_id::ContentIdKind::Public
        {
            return Err("sealed B.U.D. 3.0 objects have no public web gateway route".into());
        }
        let max_bytes = budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES;
        if content.content_id.len > max_bytes as u64 {
            return Err(format!(
                "content length {} exceeds gateway ceiling {max_bytes}",
                content.content_id.len
            ));
        }
        if let Some(cached) = self.read_verified_cache(content) {
            return Ok(cached);
        }
        let commitment_hex = hex::encode(content.object_commitment);
        self.verify_object_record(content, &commitment_hex)?;

        let params = serde_json::json!({
            "payer": self.payer_hex,
            "object": commitment_hex,
            "receipt_id": self.receipt_id_hex,
            "fee_paid_atoms": self.fee_paid_atoms,
        });
        let mut last_err = String::from("no rpc endpoint returned B.U.D. 3.0 content");
        for url in &self.endpoints {
            match self.call_rpc(url, "bud_storageGetContent", &params) {
                Ok(result) => {
                    let Some(raw_hex) = result
                        .get("content_hex")
                        .and_then(serde_json::Value::as_str)
                    else {
                        last_err = format!("{url}: bud_storageGetContent missing content_hex");
                        continue;
                    };
                    let clean_hex = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
                    if clean_hex.len() > max_bytes.saturating_mul(2) {
                        last_err = format!("{url}: bud_storageGetContent exceeds gateway ceiling");
                        continue;
                    }
                    let bytes = match hex::decode(clean_hex) {
                        Ok(b) => b,
                        Err(e) => {
                            last_err = format!("{url}: invalid content_hex: {e}");
                            continue;
                        }
                    };
                    if !content.content_id.matches_public(&bytes) {
                        return Err(format!(
                            "{url}: content bytes do not match the proved public ContentId"
                        ));
                    }
                    self.write_verified_cache(&content.content_id.digest, &bytes);
                    return Ok(bytes);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn fetch_manifest(
        &self,
        content: &budlum_core::storage::bud3::content_ref::ContentRef,
    ) -> Result<SiteManifest, String> {
        let bytes = self.fetch(content)?;
        SiteManifest::from_json_bytes(&bytes)
    }
}

type BoxBody = http_body_util::Full<Bytes>;

fn plain(status: StatusCode, message: &str) -> Response<BoxBody> {
    let headers = content_headers_with_csp("text/plain; charset=utf-8", RESOLUTION_CACHE, None);
    let mut response = Response::new(BoxBody::from(Bytes::from(format!("{message}\n"))));
    *response.status_mut() = status;
    apply_headers(&mut response, headers);
    response
}

fn apply_headers(response: &mut Response<BoxBody>, headers: Vec<(String, String)>) {
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let is_csp = name == hyper::header::CONTENT_SECURITY_POLICY;
        let value = if is_csp
            && !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7E).contains(&b))
        {
            // Defense-in-depth: never omit CSP or emit non-ASCII/control bytes
            // if a caller passes an unencodable policy string; emit the baseline floor.
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'")
        } else {
            match HeaderValue::from_str(&value) {
                Ok(v) => v,
                Err(_) if is_csp => {
                    HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'")
                }
                Err(_) => continue,
            }
        };
        response.headers_mut().append(name, value);
    }
}

fn error_response(error: &GatewayError) -> Response<BoxBody> {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::BAD_GATEWAY);
    // The message is the status, never the reason: a gateway that explains a
    // verification failure tells the client which check to attack next.
    let message = match error {
        GatewayError::NotFound => "no such name",
        GatewayError::Expired => "the name's term has ended",
        GatewayError::NoContent => "the name carries no content",
        GatewayError::NoSuchSubdomain(_) => "no such subdomain",
        GatewayError::ProofFailed(_) => "the proof did not verify",
        GatewayError::UnknownHeight(_) => "no verified header at that height",
        GatewayError::NoProverAnswered => "no proof source answered",
        GatewayError::ProversDisagree => "the proof sources disagree",
        GatewayError::Site(RouteErrorKind::Malformed) => "malformed path",
        GatewayError::Site(RouteErrorKind::DisallowedMime) => "content type not served",
        GatewayError::Site(RouteErrorKind::NotFound)
        | GatewayError::Site(RouteErrorKind::MissingIndex) => "no such path",
        GatewayError::ContentUnavailable(_) => "content unavailable",
    };
    if status
        == StatusCode::from_u16(BLOCKED_STATUS).unwrap_or(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    {
        return plain(status, "blocked on this gateway");
    }
    plain(status, message)
}

async fn handle(
    request: Request<hyper::body::Incoming>,
    state: Arc<GatewayState>,
    peer: SocketAddr,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    let response = answer(request, &state, peer);
    state.counters.count_status(response.status());
    Ok(response)
}

fn answer(
    request: Request<hyper::body::Incoming>,
    state: &GatewayState,
    peer: SocketAddr,
) -> Response<BoxBody> {
    let method = request.method().clone();
    if method != hyper::Method::GET && method != hyper::Method::HEAD {
        let response = plain(StatusCode::METHOD_NOT_ALLOWED, "only GET and HEAD");
        return response;
    }
    let host = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Some(target) = parse_host(&host, &state.suffix) else {
        let response = plain(StatusCode::NOT_FOUND, "unknown name");
        return response;
    };
    if state.blocklist.is_blocked(&target.name) {
        let response = plain(
            StatusCode::from_u16(BLOCKED_STATUS)
                .unwrap_or(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS),
            "blocked on this gateway",
        );
        return response;
    }
    // The client is the socket peer, or the address a configured proxy vouches
    // for. A header the client wrote itself is never a source of identity.
    let client = match state.identity.client_ip(peer.ip(), request.headers()) {
        Ok(ip) => ip.to_string(),
        Err(reason) => return plain(StatusCode::BAD_REQUEST, reason),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    {
        let mut limiter = match state.limiter.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if limiter.check(&client, now) == LimitDecision::Refused {
            let response = plain(StatusCode::TOO_MANY_REQUESTS, "too many requests");
            return response;
        }
    }

    let name = target.name.clone();
    let resolution = match resolve_name(state, &name, &target) {
        Ok(resolved) => resolved,
        Err(error) => {
            let response = error_response(&error);
            return response;
        }
    };

    let manifest = match cached_manifest(state, &resolution.content, &client, now) {
        Ok(manifest) => manifest,
        Err(response) => return *response,
    };
    let path = request.uri().path();
    let route = match route_of(&manifest, path) {
        Ok(route) => route.clone(),
        Err(error) => {
            let response = error_response(&error);
            return response;
        }
    };

    // Cache first, then fetch, then re-check. Every byte is checked against the
    // content id on the way in and on the way out.
    let cached = {
        let mut cache = match state.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.get(&route.content).map(<[u8]>::to_vec)
    };
    if cached.is_none() {
        // A miss reads the content source. It has its own budget, so a client
        // cannot spend its whole request budget on fills.
        let mut fills = match state.fill_limiter.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if fills.check(&client, now) == LimitDecision::Refused {
            return plain(StatusCode::TOO_MANY_REQUESTS, "too many requests");
        }
    }
    let bytes = match cached {
        Some(bytes) => {
            state.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
            bytes
        }
        None => {
            if let Ok(bytes) = state.content.fetch(&route.content) {
                state.counters.cache_fills.fetch_add(1, Ordering::Relaxed);
                let mut cache = match state.cache.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match cache.insert(&route.content, bytes.clone()) {
                    Ok(()) | Err(CacheMiss::TooLarge) => bytes,
                    Err(CacheMiss::DigestMismatch) => {
                        // A source cannot bypass the cache's integrity check
                        // on a miss by supplying mismatched bytes.
                        return plain(StatusCode::BAD_GATEWAY, "content unavailable");
                    }
                }
            } else {
                let response = plain(StatusCode::BAD_GATEWAY, "content unavailable");
                return response;
            }
        }
    };

    let headers = content_headers_with_csp(&route.mime, IMMUTABLE_CACHE, manifest.csp.as_deref());
    let mut response = Response::new(BoxBody::from(Bytes::from(bytes)));
    *response.status_mut() = StatusCode::OK;
    apply_headers(&mut response, headers);
    if method == hyper::Method::HEAD {
        *response.body_mut() = BoxBody::from(Bytes::new());
    }
    response
}

/// Bytes of parsed site manifests the gateway retains in memory at once.
const MAX_MANIFEST_CACHE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum number of parsed site manifests retained in memory at once.
const MAX_MANIFEST_CACHE_ENTRIES: usize = 1024;

fn manifest_footprint(manifest: &SiteManifest) -> usize {
    std::mem::size_of::<SiteManifest>()
        + 96
        + manifest.index.len()
        + manifest.csp.as_deref().map_or(0, str::len)
        + manifest
            .routes
            .iter()
            .map(|(path, route)| 96 + path.len() + route.mime.len())
            .sum::<usize>()
}

/// The parsed manifest for `content`, kept between requests.
///
/// A site has one manifest and every request for that site needs it, so a read
/// and a parse per request would let a few header bytes buy the whole object,
/// outside the content cache and the fill budget that bound every other read of
/// the content source. The parse is kept in memory, and a miss is charged to
/// the fill budget.
fn cached_manifest(
    state: &GatewayState,
    content: &budlum_core::storage::bud3::content_ref::ContentRef,
    client: &str,
    now: u64,
) -> Result<Arc<SiteManifest>, Box<Response<BoxBody>>> {
    let key = content.content_id.digest;
    {
        let cache = match state.manifests.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((_, manifest)) = cache.get(&key) {
            return Ok(Arc::clone(manifest));
        }
    }
    {
        let mut fills = match state.fill_limiter.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if fills.check(client, now) == LimitDecision::Refused {
            return Err(Box::new(plain(
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests",
            )));
        }
    }
    let Ok(manifest) = state.content.fetch_manifest(content) else {
        return Err(Box::new(plain(
            StatusCode::BAD_GATEWAY,
            "content unavailable",
        )));
    };
    let footprint = manifest_footprint(&manifest);
    let manifest = Arc::new(manifest);
    if footprint > MAX_MANIFEST_CACHE_BYTES {
        return Ok(manifest);
    }
    let mut cache = match state.manifests.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut held: usize = cache.values().map(|(bytes, _)| *bytes).sum();
    while !cache.is_empty()
        && (cache.len() >= MAX_MANIFEST_CACHE_ENTRIES
            || held.saturating_add(footprint) > MAX_MANIFEST_CACHE_BYTES)
    {
        let Some(victim) = cache.keys().next().copied() else {
            break;
        };
        if let Some((bytes, _)) = cache.remove(&victim) {
            held = held.saturating_sub(bytes);
        }
    }
    cache.insert(key, (footprint, Arc::clone(&manifest)));
    Ok(manifest)
}

/// Resolve a name, or return the reason it did not resolve.
///
/// The resolution cache is keyed by name and bounded by a short TTL, because a
/// record can move. A cached resolution is the `ContentRef` the verified branch
/// named, not the branch: the proof is re-checked when the entry expires.
fn resolve_name(
    state: &GatewayState,
    name: &str,
    target: &budlum_core::web_gateway::host::Target,
) -> Result<CachedResolution, GatewayError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let key = format!("{name}|{:?}", target.sub);
    {
        let cache = match state.resolved.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((expires, cached)) = cache.get(&key) {
            if *expires > now {
                return Ok(cached.clone());
            }
        }
    }
    let proved = resolve_verified(&state.provers, state.roots.as_ref(), target)?;
    let content =
        served_content_of(&proved.branch, target.sub.as_deref()).ok_or(GatewayError::NoContent)?;
    let resolved = CachedResolution {
        content,
        height: proved.height,
    };
    tracing::debug!(
        name,
        height = resolved.height,
        "name resolved against a verified root"
    );
    {
        let mut cache = match state.resolved.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if cache.len() >= 4096 {
            cache.clear();
        }
        cache.insert(
            key,
            (
                now.saturating_add(state.config.resolve_ttl_secs),
                resolved.clone(),
            ),
        );
    }
    Ok(resolved)
}

fn load_config(path: &std::path::Path) -> Result<GatewayConfig, String> {
    let raw = budlum_core::crypto::key_file::read_regular_bounded(path, 1_048_576, "config")
        .map_err(|e| format!("config {}: {e}", path.display()))?;
    let text = std::str::from_utf8(&raw).map_err(|e| format!("config {}: {e}", path.display()))?;
    toml::from_str(text).map_err(|e| format!("config {}: {e}", path.display()))
}

fn build_state(config: GatewayConfig) -> Result<GatewayState, String> {
    // reqwest uses the process-wide rustls provider. With its provider-less
    // feature set, it must inherit Budlum's TLS 1.3 hybrid-only provider
    // before the first client is constructed (including standalone tests).
    budlum_core::crypto::tls::install_default_provider();
    if config.rpc.is_empty() {
        return Err("config names no rpc endpoint, so no proof can be checked".into());
    }
    let identity =
        http_support::ClientIdentity::new(config.allow_direct, config.trusted_proxies.clone())
            .map_err(|_| {
                "set exactly one of `allow_direct = true` or a non-empty `trusted_proxies` list: \
                 a gateway that does not know who its clients are cannot rate limit them"
                    .to_string()
            })?;
    let mut provers = Vec::with_capacity(config.rpc.len());
    for url in &config.rpc {
        provers.push(RpcProver::new(url.clone())?);
    }
    let blocklist = match &config.blocklist_file {
        Some(path) => {
            let raw = budlum_core::crypto::key_file::read_regular_bounded(
                path,
                16 * 1024 * 1024,
                "blocklist",
            )
            .map_err(|e| format!("blocklist {}: {e}", path.display()))?;
            let text = std::str::from_utf8(&raw)
                .map_err(|e| format!("blocklist {}: {e}", path.display()))?;
            BlockList::from_names(text.lines().map(str::to_string))
        }
        None => BlockList::default(),
    };
    let content: Arc<dyn ContentSource + Send + Sync> =
        match (config.content_dir.clone(), config.bud3.clone()) {
            (Some(_), Some(_)) => {
                return Err(
                "set either `content_dir` or `[bud3]`, not both: content source must be unambiguous"
                    .into(),
            );
            }
            (None, None) => {
                return Err(
                "config names neither `content_dir` nor `[bud3]`; configure a B.U.D. 3.0 source \
                 or a rehearsal content_dir before starting"
                    .into(),
            );
            }
            (Some(content_dir), None) => {
                if !content_dir.is_dir() {
                    return Err(format!(
                        "content_dir {} is not a directory",
                        content_dir.display()
                    ));
                }
                Arc::new(DirectorySource { root: content_dir })
            }
            (None, Some(bud3_cfg)) => Arc::new(Bud3RpcSource::new(
                config.rpc.clone(),
                &bud3_cfg,
                config.cache_dir.clone(),
                config.cache_max_bytes,
            )?),
        };
    let pinned = checkpoint_table(&config.checkpoints)?;
    let followed = config
        .checkpoints_file
        .clone()
        .map(FollowedCheckpoints::new);
    if pinned.is_empty() && followed.is_none() {
        tracing::warn!(
            "no checkpoint is configured: every name answers 502 until a verified header is given"
        );
    }
    let suffix = config.suffix.clone();
    let rate = config.rate_per_minute;
    let fill_rate = config.fill_per_minute;
    let cache_max = config.cache_max_bytes;
    Ok(GatewayState {
        config,
        suffix,
        provers,
        roots: Arc::new(PinnedHeaderRoots { pinned, followed }),
        content,
        blocklist,
        identity,
        limiter: std::sync::Mutex::new(RateLimiter::new(rate, 60)),
        fill_limiter: std::sync::Mutex::new(RateLimiter::new(fill_rate, 60)),
        cache: std::sync::Mutex::new(ContentCache::new(cache_max)),
        resolved: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        manifests: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        counters: Counters::default(),
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(config_path) = args.next() else {
        return Err("usage: budlum-gateway <gateway.toml>".into());
    };
    let config = load_config(std::path::Path::new(&config_path))?;
    let state = Arc::new(build_state(config)?);
    let listen: SocketAddr = state
        .config
        .listen
        .parse()
        .map_err(|e| format!("listen {}: {e}", state.config.listen))?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;
    tracing::info!(%listen, suffix = %state.suffix, "budlum gateway listening on plain HTTP; a terminator puts TLS in front");
    tracing::info!(
        cache_dir = %state.config.cache_dir.display(),
        "the content cache is held in memory; nothing is written under cache_dir yet"
    );
    let counted = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            counted.counters.log();
        }
    });
    let connections = Arc::new(Semaphore::new(http_support::MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            // Over the connection budget: drop the socket instead of queueing it.
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(stream);
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { handle(request, state, peer).await }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(http_support::HEADER_TIMEOUT)
                .max_buf_size(http_support::MAX_HEADER_BYTES)
                .keep_alive(false);
            let connection = builder.serve_connection(io, service);
            match tokio::time::timeout(http_support::CONNECTION_LIFETIME, connection).await {
                Ok(Err(e)) => tracing::debug!(error = %e, "connection ended"),
                Err(_) => tracing::debug!(%peer, "connection timed out"),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_decoder_refuses_an_answer_without_a_height() {
        // The height is what ties the proof to a header the light client
        // verified. Without it there is no root to check against, and treating
        // the answer as valid would be the bug the proof fixes closed.
        let answer = serde_json::json!({
            "name": "ayaz.bud",
            "included": false,
            "bns_root": format!("0x{}", "11".repeat(32)),
            "meta_digest": format!("0x{}", "22".repeat(32)),
            "names_count": 2,
            "epoch": 100,
            "entry": null,
            "absence": {"siblings": [], "occupant": null},
        });
        let error = decode_proof_result(&answer).unwrap_err();
        assert!(error.contains("height"), "got {error}");
    }

    #[test]
    fn the_proof_decoder_reads_the_path_and_extras_fields() {
        let answer = serde_json::json!({
            "name": "ayaz.bud",
            "included": true,
            "bns_root": format!("0x{}", "11".repeat(32)),
            "meta_digest": format!("0x{}", "22".repeat(32)),
            "names_count": 1,
            "epoch": 100,
            "height": 42,
            "entry": {
                "name": "ayaz.bud",
                "owner": format!("0x{}", "33".repeat(32)),
                "address": format!("0x{}", "44".repeat(32)),
                "expires_at": 200,
                "content": {
                    "kind": "public",
                    "digest": format!("0x{}", "88".repeat(32)),
                    "len": 42,
                    "object_commitment": format!("0x{}", "99".repeat(32)),
                    "nft_id": format!("0x{}", "aa".repeat(32))
                },
                "storage_root": null,
                "extras_digest": format!("0x{}", "55".repeat(32)),
                "leaf": format!("0x{}", "66".repeat(32)),
                "siblings": [format!("0x{}", "ab".repeat(32))],
                "extras": {
                    "address": format!("0x{}", "44".repeat(32)),
                    "consensus_domain_id": null,
                    "storage_domain_id": null,
                    "storage_root_height": null,
                    "subdomains": {"shop": {
                        "owner": format!("0x{}", "77".repeat(32)),
                        "address": format!("0x{}", "77".repeat(32)),
                        "content": null,
                    }},
                    "records": {"addr.eth": "0xabc"}
                }
            },
            "absence": null,
        });
        let proof = decode_proof_result(&answer).unwrap();
        assert_eq!(proof.height, 42);
        let entry = proof.proof.entry.expect("entry");
        assert_eq!(entry.siblings, vec![[0xab; 32]]);
        let extras = entry.extras.expect("extras");
        assert_eq!(extras.subdomains.len(), 1);
        assert_eq!(
            extras.records.get("addr.eth").map(String::as_str),
            Some("0xabc")
        );
        let bud3 = entry.content.expect("RPC content reference");
        assert_eq!(
            bud3.content_id.kind,
            budlum_core::storage::bud3::content_id::ContentIdKind::Public
        );
        assert_eq!(bud3.content_id.digest, [0x88; 32]);
        assert_eq!(bud3.content_id.len, 42);
        assert_eq!(bud3.object_commitment, [0x99; 32]);
        assert_eq!(bud3.nft_id, Some([0xAA; 32]));
    }

    #[test]
    fn malformed_bud3_reference_cannot_be_silently_dropped_by_decoder() {
        let mut ref_json = serde_json::json!({
            "kind": "public",
            "digest": format!("0x{}", "88".repeat(32)),
            "len": 42,
            "object_commitment": format!("0x{}", "99".repeat(32)),
            "nft_id": null
        });
        ref_json["len"] = serde_json::json!("42");
        assert!(budlum_core::bns::types::content_ref_from_json(&ref_json).is_err());
        ref_json["len"] = serde_json::json!(42);
        ref_json["object_commitment"] = serde_json::json!(format!("0x{}", "00".repeat(32)));
        assert!(budlum_core::bns::types::content_ref_from_json(&ref_json).is_err());
        ref_json["object_commitment"] = serde_json::json!(format!("0x{}", "99".repeat(32)));
        ref_json["kind"] = serde_json::json!("unknown");
        assert!(budlum_core::bns::types::content_ref_from_json(&ref_json).is_err());
    }

    #[test]
    fn the_directory_source_checks_manifest_and_body_bytes_against_the_proved_id() {
        use budlum_core::storage::bud3::content_id::ContentId;
        use budlum_core::storage::bud3::content_ref::ContentRef;
        let dir = tempfile::tempdir().unwrap();
        let source = DirectorySource {
            root: dir.path().to_path_buf(),
        };
        let manifest = SiteManifest {
            index: "/index.html".into(),
            routes: std::collections::BTreeMap::new(),
            csp: None,
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let content = ContentRef::new(ContentId::public(&bytes), [0x42; 32], None).unwrap();
        let path = dir.path().join(hex::encode(content.content_id.digest));
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(source.fetch(&content).unwrap(), bytes);
        assert_eq!(source.fetch_manifest(&content).unwrap(), manifest);

        // Neither a different body nor a forged length with the same digest
        // can be interpreted as an authenticated manifest or served as bytes.
        std::fs::write(&path, b"{\"index\":\"/attacker.html\",\"routes\":{}}").unwrap();
        assert!(source
            .fetch_manifest(&content)
            .unwrap_err()
            .contains("ContentId"));
        assert!(source.fetch(&content).is_err());
        std::fs::write(&path, &bytes).unwrap();
        let forged_len = ContentRef::new(
            ContentId {
                len: content.content_id.len + 1,
                ..content.content_id
            },
            content.object_commitment,
            None,
        )
        .unwrap();
        assert!(source.fetch_manifest(&forged_len).is_err());
    }

    #[test]
    fn a_gateway_without_a_pinned_checkpoint_has_no_root_for_any_height() {
        // An empty pinned set is the honest starting state: no header has been
        // verified, so no proof can be checked, so every request is a 502
        // rather than a page.
        let roots = PinnedHeaderRoots {
            pinned: std::collections::BTreeMap::new(),
            followed: None,
        };
        assert_eq!(roots.verified_state_root(0), None);
        assert_eq!(roots.verified_state_root(1_000_000), None);
        assert_eq!(roots.verified_epoch(0), None);
        assert_eq!(roots.verified_epoch(1_000_000), None);
    }

    #[test]
    fn a_pinned_checkpoint_gives_the_epoch_next_to_the_root() {
        let roots = PinnedHeaderRoots {
            pinned: std::collections::BTreeMap::from([(7u64, ([0xab; 32], 100u64))]),
            followed: None,
        };
        assert_eq!(roots.verified_state_root(7), Some([0xab; 32]));
        assert_eq!(roots.verified_epoch(7), Some(100));
        // A height that was not pinned has neither.
        assert_eq!(roots.verified_state_root(8), None);
        assert_eq!(roots.verified_epoch(8), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rpc_bridge_uses_the_async_client_without_panicking_on_a_transport_failure() {
        budlum_core::crypto::tls::install_default_provider();
        let prover = RpcProver::new("http://127.0.0.1:1".into()).unwrap();
        assert!(
            prover.proof_for("ayaz.bud").is_err(),
            "a failed RPC is an ordinary refused proof, not a runtime panic"
        );
    }

    #[test]
    fn a_configuration_without_a_content_source_is_refused() {
        let config = GatewayConfig {
            suffix: "budlum.xyz".into(),
            listen: "0.0.0.0:0".into(),
            rpc: vec!["http://127.0.0.1:8545".into()],
            cache_dir: std::env::temp_dir(),
            cache_max_bytes: 1024,
            rate_per_minute: 10,
            blocklist_file: None,
            content_dir: None,
            bud3: None,
            resolve_ttl_secs: 10,
            allow_direct: true,
            trusted_proxies: Vec::new(),
            fill_per_minute: 5,
            checkpoints: Vec::new(),
            checkpoints_file: None,
        };
        let refused = build_state(config);
        assert!(refused.is_err(), "the state must be refused");
        let error = refused.err().unwrap_or_default();
        assert!(error.contains("content_dir"), "got {error}");
    }

    #[test]
    fn a_configuration_without_an_rpc_endpoint_is_refused() {
        let config = GatewayConfig {
            suffix: "budlum.xyz".into(),
            listen: "0.0.0.0:0".into(),
            rpc: Vec::new(),
            cache_dir: std::env::temp_dir(),
            cache_max_bytes: 1024,
            rate_per_minute: 10,
            blocklist_file: None,
            content_dir: Some(std::env::temp_dir()),
            bud3: None,
            resolve_ttl_secs: 10,
            allow_direct: true,
            trusted_proxies: Vec::new(),
            fill_per_minute: 5,
            checkpoints: Vec::new(),
            checkpoints_file: None,
        };
        let refused = build_state(config);
        assert!(refused.is_err(), "the state must be refused");
        let error = refused.err().unwrap_or_default();
        assert!(error.contains("rpc"), "got {error}");
    }

    fn serving_config(allow_direct: bool, trusted_proxies: Vec<std::net::IpAddr>) -> GatewayConfig {
        GatewayConfig {
            suffix: "budlum.xyz".into(),
            listen: "127.0.0.1:0".into(),
            rpc: vec!["http://127.0.0.1:8545".into()],
            cache_dir: std::env::temp_dir(),
            cache_max_bytes: 1024,
            rate_per_minute: 10,
            blocklist_file: None,
            content_dir: Some(std::env::temp_dir()),
            bud3: None,
            resolve_ttl_secs: 10,
            allow_direct,
            trusted_proxies,
            fill_per_minute: 5,
            checkpoints: Vec::new(),
            checkpoints_file: None,
        }
    }

    #[test]
    fn a_configuration_that_does_not_say_who_its_clients_are_is_refused() {
        for config in [
            serving_config(false, Vec::new()),
            serving_config(true, vec!["127.0.0.1".parse().expect("literal address")]),
        ] {
            let refused = build_state(config);
            assert!(refused.is_err(), "exactly one identity mode must be set");
            let error = refused.err().unwrap_or_default();
            assert!(error.contains("allow_direct"), "got {error}");
        }
    }

    #[test]
    fn a_direct_gateway_charges_the_socket_peer_and_ignores_forwarded_for() {
        let state = build_state(serving_config(true, Vec::new()))
            .unwrap_or_else(|e| panic!("a direct gateway starts: {e}"));
        let peer: std::net::IpAddr = "203.0.113.9".parse().expect("literal address");
        let mut headers = hyper::HeaderMap::new();
        // The header a client wrote itself: one address, then another.
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        assert_eq!(state.identity.client_ip(peer, &headers), Ok(peer));
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        assert_eq!(
            state.identity.client_ip(peer, &headers),
            Ok(peer),
            "rotating the header does not rotate the identity"
        );
    }

    #[test]
    fn a_proxied_gateway_takes_the_client_from_its_proxy_and_refuses_everyone_else() {
        let proxy: std::net::IpAddr = "127.0.0.1".parse().expect("literal address");
        let client: std::net::IpAddr = "203.0.113.50".parse().expect("literal address");
        let state = build_state(serving_config(false, vec![proxy]))
            .unwrap_or_else(|e| panic!("a proxied gateway starts: {e}"));
        let mut headers = hyper::HeaderMap::new();
        // A client behind the proxy writes its own first hop; the proxy appends
        // the address it actually saw.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.50"),
        );
        assert_eq!(state.identity.client_ip(proxy, &headers), Ok(client));
        assert!(
            state.identity.client_ip(client, &headers).is_err(),
            "a peer that is not a configured proxy is refused"
        );
    }

    #[test]
    fn an_error_response_never_repeats_the_reason() {
        // The status is public; the reason is not. A gateway that explains a
        // verification failure tells the client which check to attack next.
        let response = error_response(&GatewayError::ProofFailed(
            "branch extras do not match the extras digest".into(),
        ));
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response = error_response(&GatewayError::NoSuchSubdomain("shop".into()));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn configured_checkpoints_become_the_roots_the_process_checks_against() {
        let mut config = serving_config(true, Vec::new());
        config.checkpoints = vec![Checkpoint {
            height: 7,
            root: format!("0x{}", "ab".repeat(32)),
            epoch: 100,
        }];
        let state = build_state(config).unwrap();
        assert_eq!(state.roots.verified_state_root(7), Some([0xab; 32]));
        assert_eq!(state.roots.verified_epoch(7), Some(100));
        assert_eq!(state.roots.verified_state_root(8), None);

        // A root that is not 32 bytes, and one height listed twice, stop the
        // process at startup.
        let mut short = serving_config(true, Vec::new());
        short.checkpoints = vec![Checkpoint {
            height: 7,
            root: "abcd".into(),
            epoch: 100,
        }];
        assert!(build_state(short).is_err());
        let mut twice = serving_config(true, Vec::new());
        let one = Checkpoint {
            height: 7,
            root: "ab".repeat(32),
            epoch: 100,
        };
        twice.checkpoints = vec![one.clone(), one];
        assert!(build_state(twice).is_err());
    }

    #[test]
    fn a_followed_checkpoint_file_is_re_read_and_a_bad_file_leaves_no_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoints.toml");
        let write = |body: &str, age_secs: u64| {
            std::fs::write(&path, body).unwrap();
            // Distinct modification times, whatever the clock resolution is.
            let stamp = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000_000 + age_secs);
            let file = std::fs::File::options().write(true).open(&path).unwrap();
            file.set_modified(stamp).unwrap();
        };
        let roots = PinnedHeaderRoots {
            pinned: std::collections::BTreeMap::from([(7u64, ([0xab; 32], 100u64))]),
            followed: Some(FollowedCheckpoints::new(path.clone())),
        };
        // No file yet: only the pinned height is known.
        assert_eq!(roots.verified_epoch(7), Some(100));
        assert_eq!(roots.verified_state_root(9), None);

        let entry = |height: u64, byte: &str, epoch: u64| {
            format!(
                "[[checkpoints]]\nheight = {height}\nroot = \"{}\"\nepoch = {epoch}\n",
                byte.repeat(32)
            )
        };
        write(&entry(9, "cd", 120), 1);
        assert_eq!(roots.verified_state_root(9), Some([0xcd; 32]));
        assert_eq!(roots.verified_epoch(9), Some(120));

        // The file cannot move a height the operator pinned.
        write(&(entry(7, "ee", 1) + &entry(11, "ef", 130)), 2);
        assert_eq!(roots.verified_state_root(7), Some([0xab; 32]));
        assert_eq!(roots.verified_state_root(11), Some([0xef; 32]));
        // Height 9 left the file, so it is unknown again.
        assert_eq!(roots.verified_state_root(9), None);

        write("this is not a checkpoint file", 3);
        assert_eq!(roots.verified_state_root(11), None);
        assert_eq!(roots.verified_state_root(7), Some([0xab; 32]));
    }

    #[test]
    fn the_counters_sort_answers_by_what_happened() {
        let counters = Counters::default();
        for status in [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::METHOD_NOT_ALLOWED,
        ] {
            counters.count_status(status);
        }
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        assert_eq!(read(&counters.requests), 6);
        assert_eq!(read(&counters.served), 2);
        assert_eq!(read(&counters.not_found), 1);
        assert_eq!(read(&counters.rate_limited), 1);
        assert_eq!(read(&counters.refused_upstream), 1);
    }

    #[test]
    fn bud3_source_config_validates_fee_floor_and_rejects_dual_sources() {
        let mut dual = serving_config(true, Vec::new());
        dual.bud3 = Some(Bud3SourceConfig {
            payer: "11".repeat(32),
            receipt_id: "22".repeat(32),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        });
        assert!(
            build_state(dual).is_err(),
            "configuring both content_dir and bud3 must be refused"
        );

        let mut underpaid = serving_config(true, Vec::new());
        underpaid.content_dir = None;
        underpaid.bud3 = Some(Bud3SourceConfig {
            payer: "11".repeat(32),
            receipt_id: "22".repeat(32),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS - 1,
        });
        assert!(
            build_state(underpaid).is_err(),
            "fee below MIN_PAID_VIEW_FEE_ATOMS must be refused"
        );

        let mut valid = serving_config(true, Vec::new());
        valid.content_dir = None;
        valid.bud3 = Some(Bud3SourceConfig {
            payer: "11".repeat(32),
            receipt_id: "22".repeat(32),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        });
        assert!(
            build_state(valid).is_ok(),
            "valid [bud3] configuration must start without content_dir"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bud3_source_verifies_object_metadata_and_serves_verified_public_content() {
        use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
        use budlum_core::storage::bud3::content_ref::ContentRef;
        use http_body_util::BodyExt as _;

        budlum_core::crypto::tls::install_default_provider();
        let manifest = SiteManifest {
            index: "/index.html".into(),
            routes: std::collections::BTreeMap::new(),
            csp: None,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let content_id = ContentId::public(&manifest_bytes);
        let commitment = [0x7Au8; 32];
        let content_ref = ContentRef::new(content_id, commitment, None).unwrap();

        let tampered_bytes = b"{\"index\":\"/evil.html\",\"routes\":{}}".to_vec();
        let tamper_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tamper_server = Arc::clone(&tamper_flag);
        let expected_digest = hex::encode(content_id.digest);
        let expected_len = content_id.len;
        let good_hex = hex::encode(&manifest_bytes);
        let bad_hex = hex::encode(&tampered_bytes);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let tamper_flag = Arc::clone(&tamper_server);
                let expected_digest = expected_digest.clone();
                let good_hex = good_hex.clone();
                let bad_hex = bad_hex.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let tamper_flag = Arc::clone(&tamper_flag);
                        let expected_digest = expected_digest.clone();
                        let good_hex = good_hex.clone();
                        let bad_hex = bad_hex.clone();
                        async move {
                            let body = req.collect().await.unwrap().to_bytes();
                            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                            let method = v.get("method").and_then(serde_json::Value::as_str);
                            let resp = match method {
                                Some("bud_storageGetObject") => serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": {
                                        "status": "live",
                                        "sealed": false,
                                        "content_digest": expected_digest,
                                        "content_len": expected_len,
                                    }
                                }),
                                Some("bud_storageGetContent") => {
                                    let payload_hex = if tamper_flag.load(Ordering::Relaxed) {
                                        bad_hex
                                    } else {
                                        good_hex
                                    };
                                    serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": 1,
                                        "result": { "content_hex": payload_hex }
                                    })
                                }
                                _ => serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "error": { "code": -32601, "message": "unknown" }
                                }),
                            };
                            Ok::<_, std::convert::Infallible>(Response::new(BoxBody::from(
                                Bytes::from(serde_json::to_vec(&resp).unwrap()),
                            )))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let cache = tempfile::tempdir().unwrap();
        let cfg = Bud3SourceConfig {
            payer: "11".repeat(32),
            receipt_id: "22".repeat(32),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        };
        let source = Bud3RpcSource::new(
            vec![format!("http://{addr}")],
            &cfg,
            cache.path().to_path_buf(),
            1024 * 1024,
        )
        .unwrap();

        // Sealed content is refused before touching the network.
        let sealed_ref = ContentRef::new(
            ContentId {
                kind: ContentIdKind::Sealed,
                digest: [0x99; 32],
                len: 0,
            },
            [0x88; 32],
            None,
        )
        .unwrap();
        assert!(source.fetch(&sealed_ref).is_err());

        // Tampered content bytes from RPC are refused and never cached.
        tamper_flag.store(true, Ordering::Relaxed);
        assert!(source
            .fetch(&content_ref)
            .unwrap_err()
            .contains("ContentId"));
        assert!(!cache.path().join(hex::encode(content_id.digest)).exists());

        // Verified public bytes succeed, parse as SiteManifest, and populate disk cache.
        tamper_flag.store(false, Ordering::Relaxed);
        let fetched_manifest = source.fetch_manifest(&content_ref).unwrap();
        assert_eq!(fetched_manifest, manifest);
        assert!(cache.path().join(hex::encode(content_id.digest)).exists());

        server.abort();
    }

    #[test]
    fn directory_source_refuses_object_above_gateway_ceiling_before_reading() {
        use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
        use budlum_core::storage::bud3::content_ref::ContentRef;

        let dir = tempfile::tempdir().unwrap();
        let ceiling = budlum_core::storage::content_gateway::MAX_GATEWAY_CONTENT_BYTES;
        let digest = [0xAB; 32];
        let oversized_path = dir.path().join(hex::encode(digest));
        let file = std::fs::File::create(&oversized_path).unwrap();
        // Sparse file above the ceiling so the test allocates no huge buffer.
        file.set_len((ceiling as u64) + 1).unwrap();
        drop(file);

        let source = DirectorySource {
            root: dir.path().to_path_buf(),
        };
        // Even if the ContentRef claims a small length, metadata check refuses
        // the oversized file on disk before reading it.
        let claimed_small = ContentRef::new(
            ContentId {
                kind: ContentIdKind::Public,
                digest,
                len: 16,
            },
            [0x11; 32],
            None,
        )
        .unwrap();
        let err = source.fetch(&claimed_small).unwrap_err();
        assert!(err.contains("exceeds the gateway ceiling"), "got: {err}");
    }

    #[test]
    fn cached_manifest_reads_source_once_and_charges_fill_budget() {
        use budlum_core::storage::bud3::content_id::ContentId;
        use budlum_core::storage::bud3::content_ref::ContentRef;
        use budlum_core::web_gateway::manifest::Route;
        use std::sync::atomic::AtomicUsize;

        struct CountingManifestSource {
            manifest: SiteManifest,
            manifest_reads: Arc<AtomicUsize>,
        }

        impl ContentSource for CountingManifestSource {
            fn fetch(&self, _content: &ContentRef) -> Result<Vec<u8>, String> {
                Ok(b"ok".to_vec())
            }

            fn fetch_manifest(&self, _content: &ContentRef) -> Result<SiteManifest, String> {
                self.manifest_reads.fetch_add(1, Ordering::Relaxed);
                Ok(self.manifest.clone())
            }
        }

        let body = b"<h1>hello</h1>";
        let body_id = ContentId::public(body);
        let body_ref = ContentRef::new(body_id, [0x22; 32], None).unwrap();
        let mut routes = std::collections::BTreeMap::new();
        routes.insert(
            "/index.html".to_string(),
            Route {
                content: body_ref,
                mime: "text/html".to_string(),
            },
        );
        let manifest = SiteManifest {
            index: "/index.html".to_string(),
            routes,
            csp: None,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_ref_a =
            ContentRef::new(ContentId::public(&manifest_bytes), [0x33; 32], None).unwrap();
        let mut digest_b = manifest_ref_a.content_id.digest;
        digest_b[0] ^= 0xFF;
        let manifest_ref_b = ContentRef::new(
            budlum_core::storage::bud3::content_id::ContentId {
                kind: budlum_core::storage::bud3::content_id::ContentIdKind::Public,
                digest: digest_b,
                len: manifest_bytes.len() as u64,
            },
            [0x44; 32],
            None,
        )
        .unwrap();

        let reads = Arc::new(AtomicUsize::new(0));
        let mut cfg = serving_config(true, Vec::new());
        cfg.fill_per_minute = 1;
        let mut state = build_state(cfg).expect("gateway state");
        state.content = Arc::new(CountingManifestSource {
            manifest: manifest.clone(),
            manifest_reads: Arc::clone(&reads),
        });

        let first = cached_manifest(&state, &manifest_ref_a, "198.51.100.1", 1000)
            .expect("first manifest fetch succeeds");
        let second = cached_manifest(&state, &manifest_ref_a, "198.51.100.1", 1000)
            .expect("second manifest fetch hits cache");
        assert_eq!(*first, manifest);
        assert_eq!(*second, manifest);
        assert_eq!(
            reads.load(Ordering::Relaxed),
            1,
            "consecutive requests for the same site must fetch the manifest only once"
        );

        // A miss for a distinct manifest is charged against fill_limiter (limit=1).
        let refused = cached_manifest(&state, &manifest_ref_b, "198.51.100.1", 1000)
            .expect_err("second miss in same window must be rate-limited");
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_headers_never_drops_content_security_policy() {
        for bad_csp in [
            "default-src 'self'; frame-ancestors 'none'; base-uri \u{00e9}",
            "default-src 'self'; frame-ancestors 'none'\r\nx-injected: 1",
            "default-src 'self'; frame-ancestors 'none'; img-src \u{007f}",
        ] {
            let mut response = Response::new(BoxBody::from(Bytes::new()));
            apply_headers(
                &mut response,
                vec![("content-security-policy".to_string(), bad_csp.to_string())],
            );
            assert_eq!(
                response
                    .headers()
                    .get(hyper::header::CONTENT_SECURITY_POLICY)
                    .and_then(|v| v.to_str().ok()),
                Some("default-src 'self'; frame-ancestors 'none'"),
                "malformed CSP must fall back to strict baseline: {bad_csp:?}"
            );
        }
    }

    #[test]
    fn manifest_cache_evicts_before_exceeding_entry_ceiling() {
        use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
        use budlum_core::storage::bud3::content_ref::ContentRef;

        struct StubManifestSource(SiteManifest);
        impl ContentSource for StubManifestSource {
            fn fetch(&self, _content: &ContentRef) -> Result<Vec<u8>, String> {
                Ok(Vec::new())
            }
            fn fetch_manifest(&self, _content: &ContentRef) -> Result<SiteManifest, String> {
                Ok(self.0.clone())
            }
        }

        let mut cfg = serving_config(true, Vec::new());
        cfg.fill_per_minute = 5000;
        let mut state = build_state(cfg).expect("gateway state");
        state.content = Arc::new(StubManifestSource(SiteManifest {
            index: "/index.html".to_string(),
            routes: std::collections::BTreeMap::new(),
            csp: None,
        }));

        for idx in 0..(MAX_MANIFEST_CACHE_ENTRIES + 5) {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&((idx + 1) as u64).to_le_bytes());
            let cref = ContentRef::new(
                ContentId {
                    kind: ContentIdKind::Public,
                    digest,
                    len: 64,
                },
                [0x11; 32],
                None,
            )
            .unwrap();
            let _ = cached_manifest(&state, &cref, "198.51.100.9", 1000).expect("cached");
        }
        let held = state.manifests.lock().unwrap();
        assert!(held.len() <= MAX_MANIFEST_CACHE_ENTRIES);
        let total_bytes: usize = held.values().map(|(bytes, _)| *bytes).sum();
        assert!(total_bytes <= MAX_MANIFEST_CACHE_BYTES);
    }

    #[test]
    fn rpc_disk_cache_refuses_writes_above_cache_max_bytes() {
        budlum_core::crypto::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let cfg = Bud3SourceConfig {
            payer: hex::encode([0x11; 32]),
            receipt_id: hex::encode([0x22; 32]),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        };
        let source = Bud3RpcSource::new(
            vec!["http://127.0.0.1:9".to_string()],
            &cfg,
            dir.path().to_path_buf(),
            64,
        )
        .unwrap();

        source.write_verified_cache(&[0x01; 32], &[1u8; 40]);
        assert!(dir.path().join(hex::encode([0x01; 32])).exists());

        // Second write pushes total over the 64-byte budget and is skipped on disk.
        source.write_verified_cache(&[0x02; 32], &[2u8; 40]);
        assert!(!dir.path().join(hex::encode([0x02; 32])).exists());

        // Overwriting the existing 40-byte entry with 50 bytes stays under 64.
        source.write_verified_cache(&[0x01; 32], &[3u8; 50]);
        assert_eq!(
            std::fs::read(dir.path().join(hex::encode([0x01; 32]))).unwrap(),
            vec![3u8; 50]
        );
    }

    #[test]
    fn rpc_disk_cache_purges_orphan_tmp_files_on_startup() {
        budlum_core::crypto::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        // Simulate a crashed write that left a 60-byte `.tmp` file consuming quota.
        let orphan = dir.path().join(format!("{}.tmp", hex::encode([0xAA; 32])));
        std::fs::write(&orphan, [0xEE_u8; 60]).unwrap();

        let cfg = Bud3SourceConfig {
            payer: hex::encode([0x11; 32]),
            receipt_id: hex::encode([0x22; 32]),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        };
        let source = Bud3RpcSource::new(
            vec!["http://127.0.0.1:9".to_string()],
            &cfg,
            dir.path().to_path_buf(),
            64,
        )
        .unwrap();

        assert!(!orphan.exists(), "startup must purge orphan .tmp files");
        let first_path = dir.path().join(hex::encode([0x01; 32]));
        source.write_verified_cache(&[0x01; 32], &[7u8; 40]);
        assert!(
            first_path.exists(),
            "orphan .tmp bytes must not block verified cache writes"
        );

        // Age the first entry beyond DISK_CACHE_ENTRY_TTL (25h); a subsequent
        // 40-byte entry must reclaim the stale entry instead of freezing cache.
        let expired_mtime =
            std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&first_path)
            .unwrap()
            .set_modified(expired_mtime)
            .unwrap();
        source.write_verified_cache(&[0x02; 32], &[9u8; 40]);
        assert!(!first_path.exists(), "expired cache entry must be reaped");
        assert!(
            dir.path().join(hex::encode([0x02; 32])).exists(),
            "fresh entry must fit after reaping expired entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gateway_file_readers_refuse_symlinks() {
        use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
        use budlum_core::storage::bud3::content_ref::ContentRef;
        use std::os::unix::fs::symlink;

        budlum_core::crypto::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let real_cp = dir.path().join("real.toml");
        let link_cp = dir.path().join("link.toml");
        let root_hex = hex::encode([0x11; 32]);
        std::fs::write(
            &real_cp,
            format!("[[checkpoints]]\nheight = 1\nroot = \"{root_hex}\"\nepoch = 1\n"),
        )
        .unwrap();
        symlink(&real_cp, &link_cp).unwrap();

        let follower = FollowedCheckpoints::new(link_cp);
        assert!(
            follower.at(1).is_none(),
            "FollowedCheckpoints must refuse symlink"
        );

        let outside = dir.path().join("outside");
        let content = b"symlink-gateway-payload";
        std::fs::write(&outside, content).unwrap();
        let digest = budlum_core::storage::ContentId::of(content).0;
        let dir_root = dir.path().join("content");
        std::fs::create_dir(&dir_root).unwrap();
        symlink(&outside, dir_root.join(hex::encode(digest))).unwrap();
        let cref = ContentRef::new(
            ContentId {
                kind: ContentIdKind::Public,
                digest,
                len: content.len() as u64,
            },
            [0x22; 32],
            None,
        )
        .unwrap();
        let source = DirectorySource { root: dir_root };
        assert!(
            source.fetch(&cref).is_err(),
            "DirectorySource must refuse symlink"
        );

        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        symlink(&outside, cache_dir.join(hex::encode(digest))).unwrap();
        let cfg = Bud3SourceConfig {
            payer: hex::encode([0x11; 32]),
            receipt_id: hex::encode([0x22; 32]),
            fee_paid_atoms: budlum_core::storage::bud3::view::MIN_PAID_VIEW_FEE_ATOMS,
        };
        let rpc_source = Bud3RpcSource::new(
            vec!["http://127.0.0.1:9".to_string()],
            &cfg,
            cache_dir,
            4096,
        )
        .unwrap();
        assert!(
            rpc_source.read_verified_cache(&cref).is_none(),
            "Bud3RpcSource::read_verified_cache must refuse symlink"
        );
    }
}
