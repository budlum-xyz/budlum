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
//! # What this binary does not do yet
//!
//! It does not fetch content. `ContentSource` is implemented for a local
//! directory so an operator can serve a rehearsal site, and the B.U.D. 3.0
//! backed implementation is the next piece: it needs a node to answer
//! `bud_storage*` and a paid-view receipt for the cache fill. Until then the
//! content path is wired to the directory source and the binary refuses to
//! start without `content_dir`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use budlum_core::web_gateway::host::{parse_host, DEFAULT_GATEWAY_SUFFIX};
use budlum_core::web_gateway::manifest::{RouteError as RouteErrorKind, SiteManifest};
use budlum_core::web_gateway::policy::{
    content_headers_with_csp, BlockList, LimitDecision, RateLimiter, BLOCKED_STATUS,
    IMMUTABLE_CACHE, RESOLUTION_CACHE,
};
use budlum_core::web_gateway::resolve::{
    content_ref_of, resolve_verified, route_of, CacheMiss, ContentCache, ContentSource,
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

/// Everything a request handler needs, built once at startup.
struct GatewayState {
    config: GatewayConfig,
    suffix: String,
    provers: Vec<RpcProver>,
    roots: Arc<dyn StateRoots + Send + Sync>,
    content: Arc<dyn ContentSource + Send + Sync>,
    blocklist: BlockList,
    identity: http_support::ClientIdentity,
    limiter: std::sync::Mutex<RateLimiter>,
    cache: std::sync::Mutex<ContentCache>,
    resolved: std::sync::Mutex<std::collections::BTreeMap<String, (u64, CachedResolution)>>,
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
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("rpc client for {url}: {e}"))?;
        Ok(Self { url, client })
    }
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
            self.client
                .post(&self.url)
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await
        };
        let json =
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(request))
                .map_err(|e| format!("{}: {e}", self.url))?;
        if let Some(error) = json.get("error") {
            return Err(format!("{}: rpc error {error}", self.url));
        }
        let result = json.get("result").ok_or("rpc answer has no result")?;
        decode_proof_result(result)
    }
}

/// Read a `bud_bnsGetProof` answer into the proof type the module checks.
///
/// The three fields the proof fixes added are read here as they are written by
/// the node: `leaf_index`, `tree_size` and `extras`. A missing one leaves the
/// branch usable for inclusion only, which is what the module's own verifier
/// already refuses for an absence proof.
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
            content_id: optional_hex32(value, "content_id")?.map(budlum_core::storage::ContentId),
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
            directions: value
                .get("directions")
                .and_then(serde_json::Value::as_array)
                .ok_or("branch.directions")?
                .iter()
                .map(|v| v.as_bool().ok_or("branch.directions[]"))
                .collect::<Result<Vec<_>, _>>()?,
            leaf_index: value.get("leaf_index").and_then(serde_json::Value::as_u64),
            tree_size: value.get("tree_size").and_then(serde_json::Value::as_u64),
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
        predecessor: match result.get("predecessor") {
            Some(v) if !v.is_null() => Some(branch(v)?),
            _ => None,
        },
        successor: match result.get("successor") {
            Some(v) if !v.is_null() => Some(branch(v)?),
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
        for (label, owner) in map {
            subdomains.insert(label.clone(), address_json(owner, "extras.subdomains[]")?);
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
        resolver: optional_address(value, "resolver")?,
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
        // The RPC encodes this reference as {kind, digest, len,
        // object_commitment, nft_id}, not a serde ContentRef. Dropping a
        // non-null value here changes the committed extras and would make
        // every real B.U.D. 3.0 site fail proof verification.
        bud3_content: match value.get("bud3_content") {
            Some(v) if !v.is_null() => Some(decode_bud3_ref(v)?),
            _ => None,
        },
        subdomains,
        records,
    })
}

fn decode_bud3_ref(
    value: &serde_json::Value,
) -> Result<budlum_core::storage::bud3::content_ref::ContentRef, String> {
    use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
    let kind = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("public") => ContentIdKind::Public,
        Some("sealed") => ContentIdKind::Sealed,
        _ => return Err("extras.bud3_content.kind is missing or invalid".into()),
    };
    let content_id = ContentId {
        kind,
        digest: hex32_field(value, "digest")?,
        len: value
            .get("len")
            .and_then(serde_json::Value::as_u64)
            .ok_or("extras.bud3_content.len is missing or invalid")?,
    };
    let commitment = hex32_field(value, "object_commitment")?;
    let nft_id = optional_hex32(value, "nft_id")?;
    budlum_core::storage::bud3::content_ref::ContentRef::new(content_id, commitment, nft_id)
        .map_err(|e| format!("invalid extras.bud3_content: {e:?}"))
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
/// The gateway will not take a root from the answer it is checking. Until the
/// process runs a light client, this source asks a node for the header and
/// verifies the header hash chain from a checkpoint the operator pins in the
/// configuration. An empty set of pinned checkpoints means the process has no
/// root for any height, and every request answers 502: a gateway with no
/// verified header is a gateway with nothing to say.
struct PinnedHeaderRoots {
    /// Height to root, pinned by the operator from a header they checked.
    pinned: std::collections::BTreeMap<u64, [u8; 32]>,
}

impl StateRoots for PinnedHeaderRoots {
    fn verified_state_root(&self, height: u64) -> Option<[u8; 32]> {
        self.pinned.get(&height).copied()
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
        let path = self.root.join(hex::encode(content.content_id.digest));
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
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
        serde_json::from_slice(&bytes).map_err(|e| format!("manifest: {e}"))
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
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
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
    let method = request.method().clone();
    if method != hyper::Method::GET && method != hyper::Method::HEAD {
        let response = plain(StatusCode::METHOD_NOT_ALLOWED, "only GET and HEAD");
        return Ok(response);
    }
    let host = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Some(target) = parse_host(&host, &state.suffix) else {
        let response = plain(StatusCode::NOT_FOUND, "unknown name");
        return Ok(response);
    };
    if state.blocklist.is_blocked(&target.name) {
        let response = plain(
            StatusCode::from_u16(BLOCKED_STATUS)
                .unwrap_or(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS),
            "blocked on this gateway",
        );
        return Ok(response);
    }
    // The client is the socket peer, or the address a configured proxy vouches
    // for. A header the client wrote itself is never a source of identity.
    let client = match state.identity.client_ip(peer.ip(), request.headers()) {
        Ok(ip) => ip.to_string(),
        Err(reason) => return Ok(plain(StatusCode::BAD_REQUEST, reason)),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    {
        let mut limiter = match state.limiter.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if limiter.check(&client, now) == LimitDecision::Refused {
            let response = plain(StatusCode::TOO_MANY_REQUESTS, "too many requests");
            return Ok(response);
        }
    }

    let name = target.name.clone();
    let resolution = match resolve_name(&state, &name, &target) {
        Ok(resolved) => resolved,
        Err(error) => {
            let response = error_response(&error);
            return Ok(response);
        }
    };

    let manifest = match state.content.fetch_manifest(&resolution.content) {
        Ok(manifest) => manifest,
        Err(_) => {
            let response = plain(StatusCode::BAD_GATEWAY, "content unavailable");
            return Ok(response);
        }
    };
    let path = request.uri().path();
    let route = match route_of(&manifest, path) {
        Ok(route) => route.clone(),
        Err(error) => {
            let response = error_response(&error);
            return Ok(response);
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
    let bytes = match cached {
        Some(bytes) => bytes,
        None => match state.content.fetch(&route.content) {
            Ok(bytes) => {
                let mut cache = match state.cache.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match cache.insert(&route.content, bytes.clone()) {
                    Ok(()) | Err(CacheMiss::TooLarge) => bytes,
                    Err(CacheMiss::DigestMismatch) => {
                        // A source cannot bypass the cache's integrity check
                        // on a miss by supplying mismatched bytes.
                        return Ok(plain(StatusCode::BAD_GATEWAY, "content unavailable"));
                    }
                }
            }
            Err(_) => {
                let response = plain(StatusCode::BAD_GATEWAY, "content unavailable");
                return Ok(response);
            }
        },
    };

    let headers = content_headers_with_csp(&route.mime, IMMUTABLE_CACHE, manifest.csp.as_deref());
    let mut response = Response::new(BoxBody::from(Bytes::from(bytes)));
    *response.status_mut() = StatusCode::OK;
    apply_headers(&mut response, headers);
    if method == hyper::Method::HEAD {
        *response.body_mut() = BoxBody::from(Bytes::new());
    }
    Ok(response)
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
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
    let content = content_ref_of(&proved.branch).ok_or(GatewayError::NoContent)?;
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
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("config {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("config {}: {e}", path.display()))
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
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("blocklist {}: {e}", path.display()))?;
            BlockList::from_names(raw.lines().map(str::to_string))
        }
        None => BlockList::default(),
    };
    let Some(content_dir) = config.content_dir.clone() else {
        return Err(
            "config names no content_dir; the B.U.D. 3.0 content source is not wired yet, so the \
             process refuses to start rather than answer every request with a 502"
                .into(),
        );
    };
    if !content_dir.is_dir() {
        return Err(format!(
            "content_dir {} is not a directory",
            content_dir.display()
        ));
    }
    let suffix = config.suffix.clone();
    let rate = config.rate_per_minute;
    let cache_max = config.cache_max_bytes;
    Ok(GatewayState {
        config,
        suffix,
        provers,
        // A gateway with no pinned checkpoint has no verified root and answers
        // 502. That is the honest state: the light-client wiring is the piece
        // that turns this into a service.
        roots: Arc::new(PinnedHeaderRoots {
            pinned: std::collections::BTreeMap::new(),
        }),
        content: Arc::new(DirectorySource { root: content_dir }),
        blocklist,
        identity,
        limiter: std::sync::Mutex::new(RateLimiter::new(rate, 60)),
        cache: std::sync::Mutex::new(ContentCache::new(cache_max)),
        resolved: std::sync::Mutex::new(std::collections::BTreeMap::new()),
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
            "predecessor": null,
            "successor": null,
        });
        let error = decode_proof_result(&answer).unwrap_err();
        assert!(error.contains("height"), "got {error}");
    }

    #[test]
    fn the_proof_decoder_reads_the_position_and_extras_fields() {
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
                "content_id": null,
                "storage_root": null,
                "extras_digest": format!("0x{}", "55".repeat(32)),
                "leaf": format!("0x{}", "66".repeat(32)),
                "siblings": [],
                "directions": [],
                "leaf_index": 0,
                "tree_size": 1,
                "extras": {
                    "resolver": null,
                    "address": format!("0x{}", "44".repeat(32)),
                    "consensus_domain_id": null,
                    "storage_domain_id": null,
                    "storage_root_height": null,
                    "bud3_content": {
                        "kind": "public",
                        "digest": format!("0x{}", "88".repeat(32)),
                        "len": 42,
                        "object_commitment": format!("0x{}", "99".repeat(32)),
                        "nft_id": format!("0x{}", "aa".repeat(32))
                    },
                    "subdomains": {"shop": format!("0x{}", "77".repeat(32))},
                    "records": {"addr.eth": "0xabc"}
                }
            },
            "predecessor": null,
            "successor": null,
        });
        let proof = decode_proof_result(&answer).unwrap();
        assert_eq!(proof.height, 42);
        let entry = proof.proof.entry.expect("entry");
        assert_eq!(entry.leaf_index, Some(0));
        assert_eq!(entry.tree_size, Some(1));
        let extras = entry.extras.expect("extras");
        assert_eq!(extras.subdomains.len(), 1);
        assert_eq!(
            extras.records.get("addr.eth").map(String::as_str),
            Some("0xabc")
        );
        let bud3 = extras.bud3_content.expect("RPC B.U.D. 3.0 reference");
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
        assert!(decode_bud3_ref(&ref_json).is_err());
        ref_json["len"] = serde_json::json!(42);
        ref_json["object_commitment"] = serde_json::json!(format!("0x{}", "00".repeat(32)));
        assert!(decode_bud3_ref(&ref_json).is_err());
        ref_json["object_commitment"] = serde_json::json!(format!("0x{}", "99".repeat(32)));
        ref_json["kind"] = serde_json::json!("unknown");
        assert!(decode_bud3_ref(&ref_json).is_err());
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
        };
        assert_eq!(roots.verified_state_root(0), None);
        assert_eq!(roots.verified_state_root(1_000_000), None);
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
            resolve_ttl_secs: 10,
            allow_direct: true,
            trusted_proxies: Vec::new(),
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
            resolve_ttl_secs: 10,
            allow_direct: true,
            trusted_proxies: Vec::new(),
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
            resolve_ttl_secs: 10,
            allow_direct,
            trusted_proxies,
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
}
