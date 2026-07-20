use super::api::BudlumApiServer;
use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::domain::storage_deal::{
    RetrievalChallenge, RetrievalChallengeRequest, RetrievalResponse, StorageDeal, StorageRegistry,
};
use crate::network::node::NodeClient;
use crate::storage::content_id::ContentId;
use bincode;
use futures::future::BoxFuture;
use hex;
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::StatusCode;
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde_json;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::{Layer, Service, ServiceBuilder};
use tracing::info;

/// Hard ceiling for the per-IP sliding-window map. Without a bound, an attacker
/// rotating source addresses can turn rate limiting itself into a memory DoS.
const MAX_TRACKED_RPC_CLIENTS: usize = 10_000;

// Phase 0.10 (security audit §5): `auth_required` defaults to `true` (secure
// by default). Operators that explicitly want an unauthenticated RPC
// must call [`RpcSecurityConfig::operator_default`], which logs a
// prominent warning at server startup.
#[derive(Clone, Debug)]
pub struct RpcSecurityConfig {
    pub auth_required: bool,
    pub api_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub cors_origins: Vec<String>,
    pub rate_limit_per_minute: Option<u64>,
    pub trusted_proxies: Vec<String>,
    pub max_request_body_size: Option<u32>,
    pub max_connections: Option<u32>,
}

impl Default for RpcSecurityConfig {
    fn default() -> Self {
        // Phase 0.10 (security audit §5): secure default — auth ON, no API key
        // (caller must configure `api_key` before serving). This is what
        // [`Self::operator_default`] used to be (auth OFF); the prior
        // behaviour is preserved under that explicit name for trusted
        // local deployments.
        Self {
            auth_required: true,
            api_key: None,
            allowed_ips: vec!["127.0.0.1".into(), "::1".into()],
            cors_origins: Vec::new(),
            rate_limit_per_minute: None,
            trusted_proxies: Vec::new(),
            max_request_body_size: Some(50 * 1024 * 1024),
            max_connections: Some(10),
        }
    }
}

impl RpcSecurityConfig {
    pub fn operator_default() -> Self {
        // Phase 0.10 SECURITY WARNING: this constructor explicitly disables
        // authentication. It is intended for trusted local / private
        // network deployments only. A loud, multi-line `warn!` is logged
        // at every server start so an operator cannot accidentally ship
        // an unauthenticated RPC to the public internet.
        tracing::warn!(
            "[GUVENLIK] Operator RPC auth_required=false — yalnizca localhost/ozel ag icindir."
        );
        tracing::warn!(
            "[GUVENLIK] Yonetim metodlari public listener'da reddedilir; operator listener yine hassastir."
        );
        tracing::warn!(
            "[GUVENLIK] Yalnizca guvenilir / ozel ag uzerinde calistirin (auth_required=true onerilir)."
        );
        Self {
            auth_required: false,
            api_key: None,
            allowed_ips: vec!["127.0.0.1".into(), "::1".into()],
            cors_origins: Vec::new(),
            rate_limit_per_minute: Some(120),
            trusted_proxies: Vec::new(),
            max_request_body_size: Some(50 * 1024 * 1024),
            max_connections: Some(10),
        }
    }

    pub fn from_env(
        auth_required: bool,
        api_key_env: Option<&str>,
        allowed_ips: Vec<String>,
        cors_origins: Vec<String>,
        rate_limit_per_minute: Option<u64>,
    ) -> Result<Self, String> {
        let api_key = match api_key_env {
            Some(env_name) if auth_required => Some(std::env::var(env_name).map_err(|_| {
                format!("RPC auth is required but environment variable {env_name} is not set")
            })?),
            Some(env_name) => std::env::var(env_name).ok(),
            None => None,
        };

        if auth_required && api_key.as_deref().unwrap_or_default().is_empty() {
            return Err("RPC auth is required but no API key was configured".into());
        }

        Ok(Self {
            auth_required,
            api_key,
            allowed_ips,
            cors_origins,
            rate_limit_per_minute,
            trusted_proxies: Vec::new(),
            max_request_body_size: None,
            max_connections: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcMode {
    Public,
    Operator,
}

#[derive(Clone)]
struct RpcSecurityLayer {
    config: Arc<RpcSecurityConfig>,
    per_ip_rates: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
    metrics: Option<Arc<crate::core::metrics::Metrics>>,
}

impl RpcSecurityLayer {
    fn new(config: RpcSecurityConfig, metrics: Option<Arc<crate::core::metrics::Metrics>>) -> Self {
        Self {
            config: Arc::new(config),
            per_ip_rates: Arc::new(Mutex::new(HashMap::new())),
            metrics,
        }
    }
}

impl<S> Layer<S> for RpcSecurityLayer {
    type Service = RpcSecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcSecurityService {
            inner,
            config: self.config.clone(),
            per_ip_rates: self.per_ip_rates.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Clone)]
struct RpcSecurityService<S> {
    inner: S,
    config: Arc<RpcSecurityConfig>,
    per_ip_rates: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
    metrics: Option<Arc<crate::core::metrics::Metrics>>,
}

impl<S, B> Service<HttpRequest<B>> for RpcSecurityService<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest<B>) -> Self::Future {
        if !is_ip_allowed(&self.config, &req) {
            return Box::pin(async { Ok(text_response(StatusCode::FORBIDDEN, "Forbidden")) });
        }

        if !is_origin_allowed(&self.config, &req) {
            return Box::pin(async { Ok(text_response(StatusCode::FORBIDDEN, "Forbidden")) });
        }

        if !is_authorized(&self.config, &req) {
            return Box::pin(async { Ok(text_response(StatusCode::UNAUTHORIZED, "Unauthorized")) });
        }

        let client_ip = extract_client_ip(&self.config, &req);
        if !is_per_ip_rate_limited(&self.config, &self.per_ip_rates, client_ip) {
            if let Some(ref m) = self.metrics {
                m.rpc_rate_limited_total.inc();
            }
            return Box::pin(async {
                Ok(text_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many requests",
                ))
            });
        }
        if let Some(ref m) = self.metrics {
            m.rpc_requests_total.inc();
        }

        let start = std::time::Instant::now();
        let metrics = self.metrics.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.call(req).await;
            if let Some(ref m) = metrics {
                m.rpc_request_duration_seconds
                    .observe(start.elapsed().as_secs_f64());
            }
            result
        })
    }
}

pub struct RpcServer {
    chain: ChainHandle,
    node: NodeClient,
    security: RpcSecurityConfig,
    mode: RpcMode,
    /// B.U.D. storage registry (Phase 0.38, Faz 5). Wrapped in `Arc<Mutex<_>>`
    /// so the same registry is shared with future consensus-side
    /// producers. The public RPC surface mutates it; the chain layer reads
    /// from a snapshot at block-application time.
    storage: Arc<Mutex<StorageRegistry>>,
    /// Prometheus metrics handle for RPC latency and rate-limit counters.
    /// If `None`, metrics are silently skipped (e.g. in tests without a
    /// global registry).
    metrics: Option<Arc<crate::core::metrics::Metrics>>,
}

impl RpcServer {
    pub fn new(chain: ChainHandle, node: NodeClient) -> Self {
        Self {
            chain,
            node,
            security: RpcSecurityConfig::default(),
            mode: RpcMode::Public,
            storage: Arc::new(Mutex::new(StorageRegistry::new())),
            metrics: None,
        }
    }

    pub fn with_security(
        chain: ChainHandle,
        node: NodeClient,
        security: RpcSecurityConfig,
    ) -> Self {
        Self {
            chain,
            node,
            security,
            mode: RpcMode::Public,
            storage: Arc::new(Mutex::new(StorageRegistry::new())),
            metrics: None,
        }
    }

    pub fn with_security_and_mode(
        chain: ChainHandle,
        node: NodeClient,
        security: RpcSecurityConfig,
        mode: RpcMode,
    ) -> Self {
        Self {
            chain,
            node,
            security,
            mode,
            storage: Arc::new(Mutex::new(StorageRegistry::new())),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<crate::core::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Construct with a shared storage registry (e.g. a chain-level one).
    pub fn with_storage(
        chain: ChainHandle,
        node: NodeClient,
        storage: Arc<Mutex<StorageRegistry>>,
    ) -> Self {
        Self {
            chain,
            node,
            security: RpcSecurityConfig::default(),
            mode: RpcMode::Public,
            storage,
            metrics: None,
        }
    }

    pub async fn run(self, addr: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use jsonrpsee::server::ServerBuilder;
        let http_middleware = ServiceBuilder::new().layer(RpcSecurityLayer::new(
            self.security.clone(),
            self.metrics.clone(),
        ));
        let mut builder = ServerBuilder::default().set_http_middleware(http_middleware);

        if let Some(limit) = self.security.max_request_body_size {
            builder = builder.max_request_body_size(limit);
        }
        if let Some(limit) = self.security.max_connections {
            builder = builder.max_connections(limit);
        }

        let server = builder.build(addr.clone()).await?;

        let mode_label = match self.mode {
            RpcMode::Public => "public",
            RpcMode::Operator => "operator",
        };
        info!("RPC Server ({}) started on {}", mode_label, addr);
        let handle = server.start(self.into_rpc());
        tokio::spawn(handle.stopped());
        Ok(())
    }

    fn require_operator(&self, method: &str) -> Result<(), ErrorObjectOwned> {
        if self.mode == RpcMode::Operator {
            Ok(())
        } else {
            Err(ErrorObjectOwned::owned(
                -32004,
                format!("{method} is available only on the operator RPC listener"),
                None::<()>,
            ))
        }
    }

    fn to_hex(n: u64) -> String {
        format!("0x{:x}", n)
    }

    fn to_0x_hash(h: String) -> String {
        if h.is_empty() {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        } else if h.starts_with("0x") {
            h
        } else {
            format!("0x{h}")
        }
    }

    fn block_to_json(b: Block) -> serde_json::Value {
        serde_json::json!({
            "number": Self::to_hex(b.index),
            "hash": Self::to_0x_hash(b.hash),
            "parentHash": Self::to_0x_hash(b.previous_hash),
            "timestamp": Self::to_hex(b.timestamp as u64),
            "transactions": b.transactions.into_iter().map(Self::tx_to_json).collect::<Vec<_>>(),
            "producer": b.producer.map(|p| p.to_string()),
            "signature": b.signature.map(|s| format!("0x{}", hex::encode(s))),
            "stateRoot": if b.state_root.is_empty() { serde_json::Value::Null } else { serde_json::json!(Self::to_0x_hash(b.state_root)) },
            "txRoot": if b.tx_root.is_empty() { serde_json::Value::Null } else { serde_json::json!(Self::to_0x_hash(b.tx_root)) },
        })
    }

    fn tx_to_json(t: Transaction) -> serde_json::Value {
        serde_json::json!({
            "hash": Self::to_0x_hash(t.hash),
            "from": t.from.to_string(),
            "to": t.to.to_string(),
            "amount": Self::to_hex(t.amount),
            "fee": Self::to_hex(t.fee),
            "nonce": Self::to_hex(t.nonce),
            "timestamp": Self::to_hex(t.timestamp as u64),
            "type": format!("{:?}", t.tx_type),
            "chainId": Self::to_hex(t.chain_id),
            "signature": t.signature.map(|s| format!("0x{}", hex::encode(s))),
        })
    }

    fn bytes32_to_0x(bytes: [u8; 32]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn global_header_to_json(h: crate::settlement::GlobalBlockHeader) -> serde_json::Value {
        serde_json::json!({
            "version": Self::to_hex(h.version as u64),
            "globalHeight": Self::to_hex(h.global_height),
            "hash": Self::bytes32_to_0x(h.calculate_hash_bytes()),
            "previousGlobalHash": Self::bytes32_to_0x(h.previous_global_hash),
            "chainId": Self::to_hex(h.chain_id),
            "timestamp": Self::to_hex(h.timestamp_ms as u64),
            "domainRegistryRoot": Self::bytes32_to_0x(h.domain_registry_root),
            "domainCommitmentRoot": Self::bytes32_to_0x(h.domain_commitment_root),
            "messageRoot": Self::bytes32_to_0x(h.message_root),
            "bridgeStateRoot": Self::bytes32_to_0x(h.bridge_state_root),
            "replayNonceRoot": Self::bytes32_to_0x(h.replay_nonce_root),
            "proposer": h.proposer.map(|p| p.to_string()),
            "settlementFinalityRoot": Self::bytes32_to_0x(h.settlement_finality_root),
            // B.U.D. Faz 4 (ARENA2): storage_root anchoring — null when no
            // storage proofs in this block, 0x-prefixed hex when present.
            "storageRoot": h.storage_root.map(Self::bytes32_to_0x),
        })
    }

    fn domain_commitment_to_json(c: crate::domain::DomainCommitment) -> serde_json::Value {
        serde_json::json!({
            "domainId": c.domain_id,
            "domainHeight": Self::to_hex(c.domain_height),
            "domainBlockHash": Self::bytes32_to_0x(c.domain_block_hash),
            "parentDomainBlockHash": Self::bytes32_to_0x(c.parent_domain_block_hash),
            "stateRoot": Self::bytes32_to_0x(c.state_root),
            "txRoot": Self::bytes32_to_0x(c.tx_root),
            "eventRoot": Self::bytes32_to_0x(c.event_root),
            "finalityProofHash": Self::bytes32_to_0x(c.finality_proof_hash),
            "consensusKind": format!("{:?}", c.consensus_kind),
            "validatorSetHash": Self::bytes32_to_0x(c.validator_set_hash),
            "timestamp": Self::to_hex(c.timestamp_ms as u64),
            "sequence": Self::to_hex(c.sequence),
            "producer": c.producer.map(|p| p.to_string()),
            "leafHash": Self::bytes32_to_0x(c.leaf_hash()),
        })
    }

    fn consensus_domain_to_json(d: crate::domain::ConsensusDomain) -> serde_json::Value {
        serde_json::json!({
            "domainId": d.id,
            "consensusKind": format!("{:?}", d.kind),
            "status": format!("{:?}", d.status),
            "domainChainId": Self::to_hex(d.domain_chain_id),
            "configHash": Self::bytes32_to_0x(d.config_hash),
            "validatorSetHash": Self::bytes32_to_0x(d.validator_set_hash),
            "finalityAdapter": d.finality_adapter,
            "minConfirmations": Self::to_hex(d.min_confirmations),
            "powParameters": d.pow_parameters,
            "bridgeEnabled": d.bridge_enabled,
            "blockHashScheme": format!("{:?}", d.block_hash_scheme),
            "stateRootScheme": format!("{:?}", d.state_root_scheme),
            "txRootScheme": format!("{:?}", d.tx_root_scheme),
        })
    }

    async fn bridge_roots_json(&self, label: &str) -> serde_json::Value {
        let info = self.chain.get_settlement_info().await;
        serde_json::json!({
            "status": label,
            "bridgeStateRoot": info["bridgeStateRoot"].clone(),
            "replayNonceRoot": info["replayNonceRoot"].clone(),
        })
    }
}

/// Phase 8.6: `benches/micro/timing_safe.rs` regresyon bench'i bu fonksiyona
/// erişir; bu yüzden `pub`'tır. Public API yüzeyinin parçası DEĞİLDİR
/// (`#[doc(hidden)]`); dış kullanıcılar için stabilite garantisi yoktur.
/// Değiştirilirse timing-safe CI kapısı (statik tarama + dudect-tarzı
/// istatistiksel test) yeşil kalmak zorundadır.
#[doc(hidden)]
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    // Length mismatch must still run a dummy compare to avoid leaking length via early return
    // of short-circuit equality on the string content alone.
    let a_b = a.as_bytes();
    let b_b = b.as_bytes();
    if a_b.len() != b_b.len() {
        let _ = a_b.ct_eq(a_b);
        return false;
    }
    bool::from(a_b.ct_eq(b_b))
}

fn is_authorized<B>(config: &RpcSecurityConfig, req: &HttpRequest<B>) -> bool {
    if !config.auth_required {
        return true;
    }

    let Some(expected) = config.api_key.as_deref() else {
        return false;
    };

    // Phase 0.35 / B3: constant-time compare of provided secret material.
    let api_ok = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|provided| constant_time_eq_str(provided, expected));

    let bearer_expected = format!("Bearer {expected}");
    let bearer_ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|provided| constant_time_eq_str(provided, &bearer_expected));

    api_ok || bearer_ok
}

fn extract_client_ip<B>(config: &RpcSecurityConfig, req: &HttpRequest<B>) -> Option<IpAddr> {
    // If trusted proxies are configured, extract the real client IP from X-Forwarded-For
    // This is checked after validate_trusted_proxy has already identified the request came
    // from a trusted source (the actual validation of the proxy IP is complex without
    // socket-level info from hyper, so we rely on network-level firewall rules).

    // Try X-Forwarded-For first (standard proxy header)
    if !config.trusted_proxies.is_empty() {
        if let Some(forwarded_ip) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        {
            return Some(forwarded_ip);
        }
    }

    // Phase 0.35 / B2: X-Real-IP is client-spoofable unless the request
    // actually came through a reverse proxy we trust. Only honor it when
    // `trusted_proxies` is non-empty (same gate as X-Forwarded-For).
    if !config.trusted_proxies.is_empty() {
        if let Some(real_ip) = req
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        {
            return Some(real_ip);
        }
    }

    // No identifiable IP — reject (callers should rely on ConnectInfo /
    // network policy when headers are absent).
    None
}

fn is_ip_allowed<B>(config: &RpcSecurityConfig, req: &HttpRequest<B>) -> bool {
    if config.allowed_ips.is_empty() {
        return true;
    }

    let client_ip = extract_client_ip(config, req);
    let Some(ip) = client_ip else {
        return false;
    };

    let ip_str = ip.to_string();
    config
        .allowed_ips
        .iter()
        .any(|allowed| allowed == "*" || allowed == &ip_str)
}

fn is_origin_allowed<B>(config: &RpcSecurityConfig, req: &HttpRequest<B>) -> bool {
    if config.cors_origins.is_empty() {
        return true;
    }

    let Some(origin) = req
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };

    config
        .cors_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed == origin)
}

fn is_per_ip_rate_limited(
    config: &RpcSecurityConfig,
    per_ip_rates: &Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
    client_ip: Option<IpAddr>,
) -> bool {
    let Some(limit) = config.rate_limit_per_minute else {
        return true;
    };
    if limit == 0 {
        return false;
    }

    let ip = match client_ip {
        Some(ip) => ip,
        None => return false,
    };

    let now = Instant::now();
    let cutoff = now - Duration::from_secs(60);
    let mut rates = match per_ip_rates.lock() {
        Ok(rates) => rates,
        Err(_) => return false,
    };

    // Opportunistically evict expired clients before admitting a new address.
    // The retain scan happens only at the ceiling, not on every request.
    if !rates.contains_key(&ip) && rates.len() >= MAX_TRACKED_RPC_CLIENTS {
        rates.retain(|_, window| {
            while window.front().is_some_and(|instant| *instant < cutoff) {
                window.pop_front();
            }
            !window.is_empty()
        });
        if rates.len() >= MAX_TRACKED_RPC_CLIENTS {
            return false;
        }
    }

    let window = rates.entry(ip).or_default();
    while window.front().is_some_and(|instant| *instant < cutoff) {
        window.pop_front();
    }
    if window.len() >= limit as usize {
        return false;
    }
    window.push_back(now);
    true
}

fn text_response(status: StatusCode, body: &'static str) -> HttpResponse {
    HttpResponse::builder()
        .status(status)
        .header("content-type", HeaderValue::from_static("text/plain"))
        .body(HttpBody::from(body))
        .expect("static RPC security response is valid")
}

fn parse_hex32_field(hex_str: &str, field_name: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("Invalid {field_name} hex: {e}"), None::<()>)
    })?;
    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("{field_name} must be 32 bytes"),
            None::<()>,
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_content_id(hex_str: &str) -> Result<ContentId, ErrorObjectOwned> {
    Ok(ContentId(parse_hex32_field(hex_str, "ContentId")?))
}

fn parse_pollen_asset_id(hex_str: &str) -> Result<crate::pollen::AssetId, ErrorObjectOwned> {
    Ok(crate::pollen::AssetId(parse_hex32_field(
        hex_str, "AssetId",
    )?))
}

fn storage_deal_to_json(deal: &StorageDeal) -> serde_json::Value {
    serde_json::json!({
        "dealId": deal.deal_id,
        "domainId": deal.domain_id,
        "manifestId": format!("0x{}", hex::encode(deal.manifest_id.0)),
        "shardId": format!("0x{}", hex::encode(deal.shard_id.0)),
        "operator": format!("0x{}", deal.operator.to_hex()),
        "replicaIndex": deal.replica_index,
        "startEpoch": deal.deal_start_epoch,
        "endEpoch": deal.deal_end_epoch,
        "status": format!("{:?}", deal.status),
    })
}

fn retrieval_challenge_to_json(challenge: &RetrievalChallenge) -> serde_json::Value {
    serde_json::json!({
        "challengeId": challenge.challenge_id,
        "dealId": challenge.deal_id,
        "shardId": format!("0x{}", hex::encode(challenge.shard_id.0)),
        "byteStart": challenge.byte_start,
        "byteEnd": challenge.byte_end,
        "challengeEpoch": challenge.challenge_epoch,
        "deadlineEpoch": challenge.deadline_epoch,
        "opener": format!("0x{}", challenge.opener.to_hex()),
        "openerBond": challenge.opener_bond,
    })
}

fn storage_economics_event_to_json(
    event: &crate::chain::blockchain::StorageEconomicsEvent,
) -> serde_json::Value {
    serde_json::json!({
        "epoch": event.epoch,
        "dealId": event.deal_id,
        "operator": format!("0x{}", event.operator.to_hex()),
        "amount": event.amount,
        "balanceEffect": event.balance_effect,
        "kind": format!("{:?}", event.kind),
    })
}

#[jsonrpsee::core::async_trait]
impl BudlumApiServer for RpcServer {
    async fn chain_id(&self) -> Result<String, ErrorObjectOwned> {
        let chain_id = self.chain.get_chain_id().await;
        Ok(Self::to_hex(chain_id))
    }

    async fn block_number(&self) -> Result<String, ErrorObjectOwned> {
        let height = self.chain.get_height().await;
        Ok(Self::to_hex(height))
    }

    async fn get_block_by_number(
        &self,
        number: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.chain.get_block(number).await {
            Some(b) => Ok(Self::block_to_json(b)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_hash = hash.strip_prefix("0x").unwrap_or(&hash);
        match self.chain.get_block_by_hash(clean_hash.to_string()).await {
            Some(b) => Ok(Self::block_to_json(b)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        let balance = self.chain.get_balance(&addr).await;
        Ok(Self::to_hex(balance))
    }

    async fn get_nonce(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        let nonce = self.chain.get_nonce(&addr).await;
        Ok(Self::to_hex(nonce))
    }

    async fn send_raw_transaction(&self, tx: Transaction) -> Result<String, ErrorObjectOwned> {
        if let Err(e) = crate::network::protocol::NetworkMessage::validate_tx_size(&tx) {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!("Transaction too large: {:?}", e),
                None::<()>,
            ));
        }

        if !tx.verify() {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "Invalid transaction signature",
                None::<()>,
            ));
        }

        let tx_hash = tx.hash.clone();
        let tx_clone = tx.clone();
        self.chain.add_transaction(tx).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid params: {e}"), None::<()>)
        })?;
        self.node.broadcast_tx_sync(tx_clone);
        Ok(Self::to_0x_hash(tx_hash))
    }

    async fn get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_hash = hash.strip_prefix("0x").unwrap_or(&hash);
        match self
            .chain
            .get_transaction_by_hash(clean_hash.to_string())
            .await
        {
            Some(t) => Ok(Self::tx_to_json(t)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_hash = hash.strip_prefix("0x").unwrap_or(&hash);
        match self.chain.get_tx_receipt(clean_hash.to_string()).await {
            Some(receipt) => Ok(receipt),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn gas_price(&self) -> Result<String, ErrorObjectOwned> {
        let fee = self.chain.get_base_fee().await;
        Ok(Self::to_hex(fee))
    }

    async fn estimate_gas(&self, tx: Transaction) -> Result<String, ErrorObjectOwned> {
        if let Err(_e) = crate::network::protocol::NetworkMessage::validate_tx_size(&tx) {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!("Transaction too large: {:?}", _e),
                None::<()>,
            ));
        }
        Ok(Self::to_hex(21000))
    }

    async fn tx_precheck(&self, tx: Transaction) -> Result<serde_json::Value, ErrorObjectOwned> {
        if let Err(_e) = crate::network::protocol::NetworkMessage::validate_tx_size(&tx) {
            return Ok(serde_json::json!({
                "accepted": false,
                "reasons": ["transaction_too_large"]
            }));
        }
        Ok(self.chain.tx_precheck(tx).await)
    }

    async fn syncing(&self) -> Result<bool, ErrorObjectOwned> {
        Ok(self.node.is_syncing())
    }

    async fn net_version(&self) -> Result<String, ErrorObjectOwned> {
        let chain_id = self.chain.get_chain_id().await;
        Ok(chain_id.to_string())
    }

    async fn net_listening(&self) -> Result<bool, ErrorObjectOwned> {
        Ok(true)
    }

    async fn net_peer_count(&self) -> Result<String, ErrorObjectOwned> {
        Ok(Self::to_hex(
            self.node
                .peer_count
                .load(std::sync::atomic::Ordering::SeqCst) as u64,
        ))
    }

    async fn get_settlement_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        Ok(self.chain.get_settlement_info().await)
    }

    async fn get_global_header(&self, height: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.chain.get_global_header(height).await {
            Some(header) => Ok(Self::global_header_to_json(header)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn get_domain_commitments(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let commitments = self.chain.get_domain_commitments().await;
        Ok(serde_json::Value::Array(
            commitments
                .into_iter()
                .map(Self::domain_commitment_to_json)
                .collect(),
        ))
    }

    async fn get_consensus_domains(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let domains = self.chain.get_consensus_domains().await;
        Ok(serde_json::Value::Array(
            domains
                .into_iter()
                .map(Self::consensus_domain_to_json)
                .collect(),
        ))
    }

    async fn register_consensus_domain(
        &self,
        domain: crate::domain::ConsensusDomain,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("bud_registerConsensusDomain")?;
        let domain_id = domain.id;
        self.chain
            .register_consensus_domain(domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid consensus domain: {e}"),
                    None::<()>,
                )
            })?;

        let info = self.chain.get_settlement_info().await;
        let registry_root = info["domainRegistryRoot"]
            .as_str()
            .map(|root| format!("0x{root}"))
            .unwrap_or_else(|| "0x".to_string());
        Ok(serde_json::json!({
            "domainId": domain_id,
            "domainRegistryRoot": registry_root,
        }))
    }

    async fn submit_domain_commitment(
        &self,
        commitment: crate::domain::DomainCommitment,
    ) -> Result<String, ErrorObjectOwned> {
        let _ = commitment;
        Err(ErrorObjectOwned::owned(
            -32602,
            "Raw domain commitment submission is disabled; use bud_submitVerifiedDomainCommitment with a finality proof",
            None::<()>,
        ))
    }

    async fn submit_verified_domain_commitment(
        &self,
        payload: crate::domain::VerifiedDomainCommitment,
    ) -> Result<String, ErrorObjectOwned> {
        let hash = hex::encode(payload.leaf_hash());
        let payload_clone = payload.clone();

        self.chain
            .submit_verified_domain_commitment(payload)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid verified domain commitment: {e}"),
                    None::<()>,
                )
            })?;

        self.node
            .broadcast_verified_domain_commitment_sync(payload_clone);
        Ok(format!("0x{hash}"))
    }

    async fn submit_cross_domain_message(
        &self,
        msg: crate::cross_domain::CrossDomainMessage,
    ) -> Result<String, ErrorObjectOwned> {
        let msg_id = hex::encode(msg.message_id);
        let msg_clone = msg.clone();

        // Relayer-gated: the message sender must be an active relayer in the
        // permissionless registry (no whitelist, only stake).
        self.chain
            .submit_relayed_cross_domain_message(msg)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid cross domain message: {e}"),
                    None::<()>,
                )
            })?;

        self.node.broadcast_cross_domain_message_sync(msg_clone);
        Ok(format!("0x{msg_id}"))
    }

    async fn register_bridge_asset(
        &self,
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("bud_registerBridgeAsset")?;
        self.chain
            .register_bridge_asset(asset_id, domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge asset registration: {e}"),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("registered").await)
    }

    async fn mint_bridge_transfer(
        &self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
        relayer: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .mint_bridge_transfer_from_verified_event(
                source_domain,
                source_height,
                sequence,
                expected_block_hash,
                event,
                proof,
                relayer,
            )
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge mint transfer: {e}"),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("minted").await)
    }

    async fn burn_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .burn_bridge_transfer(message_id, domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge burn transfer: {e}"),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("burned").await)
    }

    async fn burn_bridge_transfer_with_event(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let event = self
            .chain
            .burn_bridge_transfer_with_event(
                message_id,
                domain,
                domain_height,
                event_index,
                expiry_height,
            )
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge burn transfer: {e}"),
                    None::<()>,
                )
            })?;
        let mut roots = self.bridge_roots_json("burned").await;
        roots["event"] = serde_json::to_value(event).unwrap_or(serde_json::Value::Null);
        Ok(roots)
    }

    async fn unlock_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        source_domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .unlock_bridge_transfer(message_id, source_domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge unlock transfer: {e}"),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("unlocked").await)
    }

    async fn unlock_bridge_transfer_verified(
        &self,
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .unlock_bridge_transfer_from_verified_event(
                target_domain,
                target_height,
                sequence,
                expected_block_hash,
                event,
                proof,
            )
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid bridge unlock transfer: {e}"),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("unlocked").await)
    }

    async fn submit_relay_proof(
        &self,
        message_id: crate::cross_domain::message::MessageId,
        relayer: String,
        proof: crate::cross_domain::event_tree::MerkleProof,
        source_domain: crate::domain::types::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_addr = relayer.strip_prefix("0x").unwrap_or(&relayer);
        let relayer_addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid relayer address: {e}"), None::<()>)
        })?;

        let message = self
            .chain
            .submit_relay_proof(message_id, relayer_addr, proof, source_domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Relay proof submission failed: {e}"),
                    None::<()>,
                )
            })?;

        Ok(serde_json::json!({
            "status": "success",
            "message_id": hex::encode(message.message_id),
            "kind": format!("{:?}", message.kind),
        }))
    }

    async fn seal_global_header(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("bud_sealGlobalHeader")?;
        let header = self.chain.seal_global_header().await.map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Unable to seal global header: {e}"),
                None::<()>,
            )
        })?;
        Ok(Self::global_header_to_json(header))
    }

    async fn registry_register(
        &self,
        tx: Transaction,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Registration is just a Stake transaction: staking == being registered.
        // Reuse the same permissionless path as a normal tx — no whitelist, no
        // approval, only signature + stake validation done downstream.
        if !matches!(tx.tx_type, crate::core::transaction::TransactionType::Stake) {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "registry_register requires a Stake transaction (tx_type=Stake)",
                None::<()>,
            ));
        }
        if !tx.verify() {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "Invalid transaction signature",
                None::<()>,
            ));
        }
        let tx_hash = tx.hash.clone();
        let tx_clone = tx.clone();
        self.chain.add_transaction(tx).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid params: {e}"), None::<()>)
        })?;
        self.node.broadcast_tx_sync(tx_clone);
        Ok(serde_json::json!({
            "txHash": Self::to_0x_hash(tx_hash),
            "status": "pending",
            "note": "staking == registration; active once the stake tx is applied",
        }))
    }

    async fn registry_bond_relayer(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // This legacy helper mutates stake without a signed transaction. Keep
        // it operator-only; permissionless users use `bud_registryRegister`
        // with a signed Stake transaction.
        self.require_operator("bud_registryBondRelayer")?;
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        self.chain.bond_relayer(addr, amount).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Relayer bond failed: {e}"), None::<()>)
        })?;
        let role = crate::registry::role::roles::RELAYER;
        let active = self
            .chain
            .get_registry_member(addr, role)
            .await
            .map(|r| r.is_active())
            .unwrap_or(false);
        Ok(serde_json::json!({
            "address": Self::to_0x_hash(addr.to_hex()),
            "role": "relayer",
            "active": active,
        }))
    }

    async fn registry_bond_prover(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("bud_registryBondProver")?;
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        self.chain.bond_prover(addr, amount).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Prover bond failed: {e}"), None::<()>)
        })?;
        let role = crate::registry::role::roles::PROVER;
        let active = self
            .chain
            .get_registry_member(addr, role)
            .await
            .map(|r| r.is_active())
            .unwrap_or(false);
        Ok(serde_json::json!({
            "address": Self::to_0x_hash(addr.to_hex()),
            "role": "prover",
            "active": active,
        }))
    }

    async fn submit_zk_proof(
        &self,
        submission: crate::prover::ZkProofSubmission,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.chain.submit_zk_proof(submission).await {
            Ok(crate::prover::ProofAcceptance::Accepted { rewarded, reward }) => {
                Ok(serde_json::json!({
                    "accepted": true,
                    "status": "accepted",
                    "rewarded": rewarded,
                    "reward": reward,
                }))
            }
            Ok(crate::prover::ProofAcceptance::Idempotent) => Ok(serde_json::json!({
                "accepted": true,
                "status": "idempotent",
                "rewarded": false,
                "reward": 0,
            })),
            Err(e) => Err(ErrorObjectOwned::owned(
                -32602,
                format!("Proof rejected: {e}"),
                None::<()>,
            )),
        }
    }

    async fn registry_query(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        let role = crate::registry::RoleId::new(role_id);
        match self.chain.get_registry_member(addr, role).await {
            Some(reg) => Ok(serde_json::json!({
                "address": Self::to_0x_hash(addr.to_hex()),
                "roleId": role_id,
                "registered": true,
                "active": reg.is_active(),
                "stake": reg.stake,
                "status": format!("{:?}", reg.status),
                "registeredEpoch": reg.registered_epoch,
            })),
            None => Ok(serde_json::json!({
                "address": Self::to_0x_hash(addr.to_hex()),
                "roleId": role_id,
                "registered": false,
                "active": false,
            })),
        }
    }

    async fn registry_active_members(
        &self,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let role = crate::registry::RoleId::new(role_id);
        let members = self.chain.get_registry_active_members(role).await;
        let list: Vec<serde_json::Value> = members
            .iter()
            .map(|reg| {
                serde_json::json!({
                    "address": Self::to_0x_hash(reg.account.to_hex()),
                    "stake": reg.stake,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "roleId": role_id,
            "count": list.len(),
            "members": list,
        }))
    }

    async fn submit_slashing_report(
        &self,
        mut report: crate::registry::SlashingReport,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Security: never trust caller-supplied provenance. An external
        // submitter cannot self-certify a report as ConsensusVerified to force a
        // slash — the RPC path is always Unverified. Only the node's own
        // consensus layer emits ConsensusVerified reports internally.
        report.provenance = crate::registry::ProofProvenance::Unverified;
        // A reporter is required so the anti-spam fee can be charged.
        if report.reporter.is_none() {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "slashing report must include a 'reporter' (fee is charged to it)",
                None::<()>,
            ));
        }
        // Permissionless submission; the chain layer decides actionability.
        match self.chain.submit_registry_slashing_report(report).await {
            Ok(Some(outcome)) => Ok(serde_json::json!({
                "slashed": true,
                "condition": format!("{:?}", outcome.condition),
                "penalty": outcome.penalty,
                "remainingStake": outcome.remaining_stake,
            })),
            Ok(None) => Ok(serde_json::json!({
                "slashed": false,
                "note": "report accepted but offender not registered for that role",
            })),
            Err(e) => Err(ErrorObjectOwned::owned(
                -32602,
                format!("Rejected slashing report: {e}"),
                None::<()>,
            )),
        }
    }

    async fn submit_qc_fault_proof(
        &self,
        proof: crate::consensus::qc::QcFaultProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Phase 0.17 (security audit §4): permissionless entry-point.
        // The proof's correctness is enforced by
        // `handle_qc_fault_proof` (merkle inclusion +
        // cryptographic dilithium verification), which is the
        // only acceptable gate — it costs ~millions of dollars
        // of compute to forge a valid proof, so a fee gate is
        // not required. On a successful proof the underlying
        // QC blob's finality is invalidated from the proof's
        // checkpoint height (see
        // `Blockchain::apply_qc_fault_verdict`).
        match self.chain.handle_qc_fault_proof(proof).await {
            Ok(()) => Ok(serde_json::json!({
                "accepted": true,
                "effect": "finality_invalidation",
                "note": "QC blob finality has been invalidated from the proof's checkpoint height",
            })),
            Err(e) => Err(ErrorObjectOwned::owned(
                -32602,
                format!("Invalid QC fault proof: {e}"),
                None::<()>,
            )),
        }
    }

    async fn health(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let height = self.chain.get_height().await;
        let syncing = self.node.is_syncing();
        let peer_count = self
            .node
            .peer_count
            .load(std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({
            "status": if syncing { "syncing" } else { "healthy" },
            "blockHeight": Self::to_hex(height),
            "peerCount": peer_count,
            "syncing": syncing,
        }))
    }

    async fn node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let chain_id = self.chain.get_chain_id().await;
        let height = self.chain.get_height().await;
        let validator_set_hash = self.chain.get_validator_set_hash().await;
        let sync_state = if self.node.is_syncing() { 1u64 } else { 0u64 };
        let peer_count = self
            .node
            .peer_count
            .load(std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({
            "chainId": Self::to_hex(chain_id),
            "blockHeight": Self::to_hex(height),
            "validatorSetHash": validator_set_hash,
            "syncState": sync_state,
            "peerCount": peer_count,
            "peerId": self.node.peer_id.to_string(),
            "rpcMode": match self.mode { RpcMode::Public => "public", RpcMode::Operator => "operator" },
        }))
    }

    // === Phase 0.38 — B.U.D. Storage RPC implementations ====================
    // The chain layer does not yet own a storage registry; we hold one on
    // the RPC server (`Arc<Mutex<StorageRegistry>>`) and snapshot it for
    // the chain-side accounting at block-application time (Faz 5 follow-up
    // in Phase 0.40). For Phase 0.38 the registry is RPC-driven and survives only
    // for the life of the process — that is the documented scope of this
    // iskeleton's RPC surface (vision §8.1 "accounting only").

    async fn storage_register_manifest(
        &self,
        manifest: crate::storage::ContentManifest,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let manifest_id = manifest.manifest_id;
        let mut reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        reg.register_manifest(&manifest);
        Ok(serde_json::json!({
            "manifestId": format!("0x{}", hex::encode(manifest_id.0)),
            "totalSize": manifest.total_size,
            "shardCount": manifest.shard_count,
        }))
    }

    async fn storage_open_deal(
        &self,
        domain_id: u32,
        manifest: crate::storage::ContentManifest,
        shard_id: String,
        operator: String,
        payer: String,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: crate::domain::storage_deal::StorageEconomicsParams,
        domain_params: crate::domain::storage_params::StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<crate::domain::Hash32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_shard = shard_id.strip_prefix("0x").unwrap_or(&shard_id);
        let s_bytes = hex::decode(clean_shard).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid shard_id hex: {e}"), None::<()>)
        })?;
        if s_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "shard_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);
        let s_id = ContentId(s_arr);

        let op_addr = Address::from_hex(&operator).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid operator hex: {e}"), None::<()>)
        })?;

        let payer_addr = Address::from_hex(&payer).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid payer hex: {e}"), None::<()>)
        })?;

        let deal_id = self
            .chain
            .open_storage_deal(
                domain_id,
                manifest.clone(),
                s_id,
                op_addr,
                payer_addr,
                replica_index,
                start_epoch,
                end_epoch,
                economics.clone(),
                domain_params,
                merkle_proof.clone(),
                storage_root,
            )
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("open_deal failed: {e}"), None::<()>)
            })?;

        // Sync the deal to the RPC server's local StorageRegistry so that
        // subsequent storage_open_challenge / storage_answer_challenge calls
        // (which use self.storage) can find the deal.
        // TODO(ARENA2): unify the two registries into a single source of truth.
        {
            let mut reg = self.storage.lock().map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("storage registry lock poisoned: {e}"),
                    None::<()>,
                )
            })?;
            reg.register_manifest(&manifest);
            let _ = reg.open_deal(
                domain_id,
                &manifest,
                s_id,
                op_addr,
                replica_index,
                start_epoch,
                end_epoch,
                economics,
                &crate::domain::storage_params::StorageDomainParams::default(),
                merkle_proof,
                storage_root,
            );
        }

        Ok(serde_json::json!({
            "dealId": deal_id,
            "status": "Active",
            "operator": operator,
        }))
    }

    async fn storage_get_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean = manifest_id.strip_prefix("0x").unwrap_or(&manifest_id);
        let bytes = hex::decode(clean).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid manifest_id hex: {e}"), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "manifest_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let id = ContentId(arr);
        // Look across deals for the (manifest, shard) pairs to reconstruct
        // the original manifest from per-shard deals (since the registry
        // itself does not duplicate manifest bytes).
        let reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        if let Some(manifest) = reg.get_manifest(&id) {
            let shards: Vec<serde_json::Value> = manifest
                .shards
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "shardId": format!("0x{}", hex::encode(s.shard_id.0)),
                        "size": s.size,
                    })
                })
                .collect();
            return Ok(serde_json::json!({
                "manifestId": format!("0x{}", hex::encode(id.0)),
                "found": true,
                "totalSize": manifest.total_size,
                "shardCount": manifest.shard_count,
                "shards": shards,
            }));
        }
        let shards: Vec<serde_json::Value> = reg
            .deals_for_manifest(&id)
            .iter()
            .map(|d| {
                serde_json::json!({
                    "shardId": format!("0x{}", hex::encode(d.shard_id.0)),
                    "size": d.shard_id.0.len(),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "manifestId": format!("0x{}", hex::encode(id.0)),
            "found": !shards.is_empty(),
            "dealsObserved": shards.len(),
            "shards": shards,
        }))
    }

    async fn storage_get_deals_by_manifest(
        &self,
        manifest_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let id = parse_content_id(&manifest_id)?;
        let reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        let deals: Vec<serde_json::Value> = reg
            .deals_for_manifest(&id)
            .into_iter()
            .map(storage_deal_to_json)
            .collect();
        Ok(serde_json::json!({
            "manifestId": format!("0x{}", hex::encode(id.0)),
            "count": deals.len(),
            "deals": deals,
        }))
    }

    async fn storage_get_deals_by_shard(
        &self,
        manifest_id: String,
        shard_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let mid = parse_content_id(&manifest_id)?;
        let sid = parse_content_id(&shard_id)?;
        let reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        let deals: Vec<serde_json::Value> = reg
            .deals_for_shard(&mid, &sid)
            .into_iter()
            .map(storage_deal_to_json)
            .collect();
        Ok(serde_json::json!({
            "manifestId": format!("0x{}", hex::encode(mid.0)),
            "shardId": format!("0x{}", hex::encode(sid.0)),
            "count": deals.len(),
            "deals": deals,
        }))
    }

    async fn storage_open_challenge(
        &self,
        request: RetrievalChallengeRequest,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Phase 3 §0.2 + H1 fix (ARENA3 sürekli denetim): opener zorunlu ve non-zero olmalı
        let opener = request.opener.ok_or_else(|| {
            ErrorObjectOwned::owned(-32602, "opener is required (Phase 3 §0.2 / H1)", None::<()>)
        })?;
        if opener == crate::core::address::Address::zero() {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "opener must not be zero address (H1)",
                None::<()>,
            ));
        }

        // Phase 3 §0.2: opener must cryptographically prove ownership of the
        // declared address. Without this, any caller can self-report any
        // address as the opener, rendering the opener_bond anti-spam gate
        // economically meaningless.
        let opener_sig = request.opener_signature.as_deref().ok_or_else(|| {
            ErrorObjectOwned::owned(
                -32602,
                "opener_signature is required (Phase 3 §0.2)",
                None::<()>,
            )
        })?;
        let msg = crate::core::hash::hash_fields_bytes(&[
            b"BUD_OPEN_CHALLENGE_V1",
            &request.deal_id.to_le_bytes(),
            &request.byte_start.to_le_bytes(),
            &request.byte_end.to_le_bytes(),
            &request.challenge_epoch.to_le_bytes(),
            &request.deadline_epoch.to_le_bytes(),
            &request.opener_bond.to_le_bytes(),
            opener.as_bytes(),
        ]);
        crate::crypto::primitives::verify_signature(&msg, opener_sig, opener.as_bytes()).map_err(
            |e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid opener signature: {e}"),
                    None::<()>,
                )
            },
        )?;

        let mut reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        let challenge_id = reg
            .open_challenge(
                request.deal_id,
                request.byte_start,
                request.byte_end,
                request.challenge_epoch,
                request.deadline_epoch,
                opener,
                request.opener_bond,
            )
            .map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("Invalid challenge: {e}"), None::<()>)
            })?;
        let challenge = reg.get_challenge(challenge_id).cloned();
        Ok(serde_json::json!({
            "challengeId": challenge_id,
            "challenge": challenge.as_ref().map(retrieval_challenge_to_json),
        }))
    }

    async fn storage_answer_challenge(
        &self,
        response: RetrievalResponse,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let responder = response.responder;

        // Phase 3 §0.2: responder must cryptographically prove ownership of the
        // declared address. Without this, any caller can set responder to the
        // deal's operator address and bypass the NotTheOperator registry check.
        let responder_sig = response.responder_signature.as_deref().ok_or_else(|| {
            ErrorObjectOwned::owned(
                -32602,
                "responder_signature is required (Phase 3 §0.2)",
                None::<()>,
            )
        })?;
        let msg = crate::core::hash::hash_fields_bytes(&[
            b"BUD_ANSWER_CHALLENGE_V1",
            &response.challenge_id.to_le_bytes(),
            &response._range_hash.0,
            responder.as_bytes(),
            &response.response_epoch.to_le_bytes(),
        ]);
        crate::crypto::primitives::verify_signature(&msg, responder_sig, responder.as_bytes())
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid responder signature: {e}"),
                    None::<()>,
                )
            })?;

        let mut reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        let result = reg
            .answer_challenge(
                response.challenge_id,
                response._range_hash,
                responder,
                response.response_epoch,
            )
            .map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("Invalid response: {e}"), None::<()>)
            })?;
        Ok(serde_json::json!({
            "challengeId": result.challenge_id,
            "dealId": result.deal_id,
            "outcome": format!("{:?}", result.outcome),
            "finalizedEpoch": result.finalized_epoch,
            "slashedBond": result.slashed_bond,
        }))
    }

    async fn storage_get_economics_summary(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .get_storage_economics_summary()
            .await
            .map_err(|e| ErrorObjectOwned::owned(-32000, e, None::<()>))
    }

    async fn storage_get_economics_events(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let events = self
            .chain
            .get_storage_economics_events()
            .await
            .map_err(|e| ErrorObjectOwned::owned(-32000, e, None::<()>))?;
        Ok(serde_json::json!({
            "count": events.len(),
            "events": events.iter().map(storage_economics_event_to_json).collect::<Vec<_>>(),
        }))
    }

    async fn storage_get_outcome(
        &self,
        challenge_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let reg = self.storage.lock().map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("storage registry lock poisoned: {e}"),
                None::<()>,
            )
        })?;
        match reg.get_result(challenge_id) {
            Some(r) => Ok(serde_json::json!({
                "challengeId": r.challenge_id,
                "dealId": r.deal_id,
                "outcome": format!("{:?}", r.outcome),
                "finalizedEpoch": r.finalized_epoch,
                "slashedBond": r.slashed_bond,
            })),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn storage_active_operators(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Phase 3 §0.3: ghost RPC was documented but not implemented.
        // Implementation: query PermissionlessRegistry active members for STORAGE_OPERATOR (RoleId 5).
        // No admin gate, no whitelist — permissionless read, same as bud_registryActiveMembers.
        let role = crate::registry::role::roles::STORAGE_OPERATOR;
        let members = self.chain.get_registry_active_members(role).await;
        let list: Vec<serde_json::Value> = members
            .iter()
            .map(|reg| {
                serde_json::json!({
                    "address": Self::to_0x_hash(reg.account.to_hex()),
                    "stake": reg.stake,
                    "role": "storage_operator",
                })
            })
            .collect();
        Ok(serde_json::json!({
            "roleId": role.value(),
            "role": "storage_operator",
            "count": list.len(),
            "operators": list,
        }))
    }

    async fn bns_resolve(&self, name: String) -> Result<Option<String>, ErrorObjectOwned> {
        let addr = self.chain.bns_resolve(name).await;
        Ok(addr.map(|a| Self::to_0x_hash(a.to_hex())))
    }

    async fn bns_resolve_full(&self, name: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        if let Some(resolved) = self.chain.bns_resolve_full(name.clone()).await {
            Ok(serde_json::json!({
                "name": resolved.name,
                "owner": Self::to_0x_hash(resolved.owner.to_hex()),
                "address": resolved.address.map(|a| Self::to_0x_hash(a.to_hex())),
                "storage_root": resolved.storage_root.map(|r| format!("0x{}", hex::encode(r))),
                "storage_domain_id": resolved.storage_domain_id,
                "content_id": resolved.content_id.map(|c| format!("0x{}", hex::encode(c.0))),
                "is_expired": resolved.is_expired,
            }))
        } else {
            Ok(serde_json::json!(null))
        }
    }

    async fn bns_resolve_content(&self, name: String) -> Result<Option<String>, ErrorObjectOwned> {
        let cid = self.chain.bns_resolve_content(name).await;
        Ok(cid.map(|c| format!("0x{}", hex::encode(c.0))))
    }

    async fn bns_resolve_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
    ) -> Result<Option<String>, ErrorObjectOwned> {
        let addr = self
            .chain
            .bns_resolve_subdomain(parent_name, sub_label)
            .await;
        Ok(addr.map(|a| Self::to_0x_hash(a.to_hex())))
    }

    async fn bns_prepare_register(
        &self,
        name: String,
        owner: String,
        duration: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_owner = owner.strip_prefix("0x").unwrap_or(&owner);
        let owner_addr = Address::from_hex(clean_owner).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid owner address: {e}"), None::<()>)
        })?;

        let data = bincode::serialize(&(name.clone(), duration))
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let cost = self.chain.bns_calculate_cost(name.clone(), duration).await;

        let tx = crate::core::transaction::Transaction {
            from: owner_addr,
            to: Address::zero(),
            amount: cost,
            fee: 1000,
            nonce: self.chain.get_nonce(&owner_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::BnsRegister,
        };

        Ok(serde_json::json!({
            "name": name,
            "owner": owner,
            "duration": duration,
            "cost": cost,
            "tx_template": tx,
        }))
    }

    async fn bns_prepare_register_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
        sub_owner: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_owner = sub_owner.strip_prefix("0x").unwrap_or(&sub_owner);
        let owner_addr = Address::from_hex(clean_owner).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid owner address: {e}"), None::<()>)
        })?;

        let data = bincode::serialize(&(parent_name.clone(), sub_label.clone(), owner_addr))
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: Address::zero(),
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: 0,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::BnsRegisterSubdomain,
        };

        Ok(serde_json::json!({
            "parent": parent_name,
            "sub_label": sub_label,
            "sub_owner": sub_owner,
            "tx_template": tx,
        }))
    }

    async fn bns_prepare_set_content(
        &self,
        name: String,
        owner: String,
        cid: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_owner = owner.strip_prefix("0x").unwrap_or(&owner);
        let owner_addr = Address::from_hex(clean_owner).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid owner address: {e}"), None::<()>)
        })?;

        let clean_cid = cid.strip_prefix("0x").unwrap_or(&cid);
        let cid_bytes = hex::decode(clean_cid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid CID hex: {e}"), None::<()>)
        })?;
        if cid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "CID must be 32 bytes",
                None::<()>,
            ));
        }
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);
        let cid_obj = crate::storage::content_id::ContentId(cid_arr);

        let data = bincode::serialize(&(name.clone(), cid_obj))
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: owner_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&owner_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::BnsSetContent,
        };
        Ok(serde_json::json!({
            "name": name,
            "owner": owner,
            "cid": cid,
            "tx_template": tx,
        }))
    }

    async fn social_get_post(&self, id: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        if let Some(nft) = self.chain.nft_get(id).await {
            Ok(serde_json::json!({
                "id": nft.id,
                "owner": Self::to_0x_hash(nft.owner.to_hex()),
                "content_id": format!("0x{}", hex::encode(nft.content_id.0)),
                "minted_at": nft.minted_at_epoch,
                "author": nft.author_name,
            }))
        } else {
            Ok(serde_json::json!(null))
        }
    }

    async fn social_get_profile(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {e}"), None::<()>)
        })?;
        let nfts = self.chain.nft_get_by_owner(addr).await;
        let list: Vec<_> = nfts
            .into_iter()
            .map(|nft| {
                serde_json::json!({
                    "id": nft.id,
                    "content_id": format!("0x{}", hex::encode(nft.content_id.0)),
                    "minted_at": nft.minted_at_epoch,
                    "author": nft.author_name,
                })
            })
            .collect();
        Ok(serde_json::Value::Array(list))
    }

    async fn social_get_feed(&self, limit: usize) -> Result<serde_json::Value, ErrorObjectOwned> {
        let nfts = self.chain.nft_get_feed(limit).await;
        let list: Vec<_> = nfts
            .into_iter()
            .map(|nft| {
                serde_json::json!({
                    "id": nft.id,
                    "owner": Self::to_0x_hash(nft.owner.to_hex()),
                    "content_id": format!("0x{}", hex::encode(nft.content_id.0)),
                    "minted_at": nft.minted_at_epoch,
                    "author": nft.author_name,
                })
            })
            .collect();
        Ok(serde_json::Value::Array(list))
    }

    async fn social_prepare_post(
        &self,
        author: String,
        cid: String,
        author_name: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_author = author.strip_prefix("0x").unwrap_or(&author);
        let author_addr = Address::from_hex(clean_author).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid author address: {e}"), None::<()>)
        })?;

        let clean_cid = cid.strip_prefix("0x").unwrap_or(&cid);
        let cid_bytes = hex::decode(clean_cid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid CID hex: {e}"), None::<()>)
        })?;
        if cid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "CID must be 32 bytes",
                None::<()>,
            ));
        }
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);
        let cid_obj = crate::storage::content_id::ContentId(cid_arr);

        let data = bincode::serialize(&(cid_obj, author_name.clone()))
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: author_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&author_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::NftMint,
        };

        Ok(serde_json::json!({
            "author": author,
            "cid": cid,
            "author_name": author_name,
            "tx_template": tx,
        }))
    }

    async fn social_prepare_burn(
        &self,
        owner: String,
        nft_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_owner = owner.strip_prefix("0x").unwrap_or(&owner);
        let owner_addr = Address::from_hex(clean_owner).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid owner address: {e}"), None::<()>)
        })?;

        let data = bincode::serialize(&nft_id)
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: owner_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&owner_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::NftBurn,
        };

        Ok(serde_json::json!({
            "owner": owner,
            "nft_id": nft_id,
            "tx_template": tx,
        }))
    }

    async fn social_prepare_boost(
        &self,
        booster: String,
        nft_id: u64,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_booster = booster.strip_prefix("0x").unwrap_or(&booster);
        let booster_addr = Address::from_hex(clean_booster).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid booster address: {e}"), None::<()>)
        })?;

        let tx = crate::core::transaction::Transaction {
            from: booster_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&booster_addr).await,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::NftBoost { nft_id, amount },
        };

        Ok(serde_json::json!({
            "booster": booster,
            "nft_id": nft_id,
            "amount": amount,
            "tx_template": tx,
        }))
    }

    async fn market_get_offers(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let offers = self.chain.market_get_offers().await;
        Ok(serde_json::json!(offers))
    }

    async fn market_prepare_offer(
        &self,
        seller: String,
        cid: String,
        price: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_seller = seller.strip_prefix("0x").unwrap_or(&seller);
        let seller_addr = Address::from_hex(clean_seller).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid seller address: {e}"), None::<()>)
        })?;

        let clean_cid = cid.strip_prefix("0x").unwrap_or(&cid);
        let cid_bytes = hex::decode(clean_cid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid CID hex: {e}"), None::<()>)
        })?;
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);
        let cid_obj = crate::storage::content_id::ContentId(cid_arr);

        let data = bincode::serialize(&(cid_obj, price))
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: seller_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&seller_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiOfferData {
                cid: cid_obj,
                price,
            },
        };

        Ok(serde_json::json!({
            "seller": seller,
            "cid": cid,
            "price": price,
            "tx_template": tx,
        }))
    }

    async fn market_prepare_purchase(
        &self,
        buyer: String,
        offer_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_buyer = buyer.strip_prefix("0x").unwrap_or(&buyer);
        let buyer_addr = Address::from_hex(clean_buyer).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid buyer address: {e}"), None::<()>)
        })?;

        let data = bincode::serialize(&offer_id)
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        let tx = crate::core::transaction::Transaction {
            from: buyer_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&buyer_addr).await,
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiPurchaseData { offer_id },
        };

        Ok(serde_json::json!({
            "buyer": buyer,
            "offer_id": offer_id,
            "tx_template": tx,
        }))
    }

    async fn pollen_get_data_assets(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let assets = self.chain.pollen_get_data_assets().await;
        Ok(serde_json::json!(assets))
    }

    async fn pollen_get_access_grants(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let grants = self.chain.pollen_get_access_grants().await;
        Ok(serde_json::json!(grants))
    }

    async fn pollen_get_sale_authorizations(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let authorizations = self.chain.pollen_get_sale_authorizations().await;
        Ok(serde_json::json!(authorizations))
    }

    async fn pollen_build_ai_input_ref(
        &self,
        asset_id: String,
        grant_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let asset_id = parse_pollen_asset_id(&asset_id)?;
        let grant_id = parse_pollen_asset_id(&grant_id)?;
        let input_ref = crate::pollen::AiDataInputRef { asset_id, grant_id }.encode();
        Ok(serde_json::json!({
            "assetId": asset_id.to_hex(),
            "grantId": grant_id.to_hex(),
            "inputRefHex": format!("0x{}", hex::encode(&input_ref)),
            "inputRefBytes": input_ref,
            "prefix": String::from_utf8_lossy(crate::pollen::POLLEN_AI_INPUT_REF_PREFIX),
        }))
    }

    async fn pollen_prepare_sale_authorization(
        &self,
        seller: String,
        asset_id: String,
        unit_price: u64,
        expires_at_block: u64,
        max_grants: u32,
        terms_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_seller = seller.strip_prefix("0x").unwrap_or(&seller);
        let seller_addr = Address::from_hex(clean_seller).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid seller address: {e}"), None::<()>)
        })?;
        if unit_price == 0 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "unit_price must be greater than zero",
                None::<()>,
            ));
        }
        if max_grants == 0 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "max_grants must be greater than zero",
                None::<()>,
            ));
        }
        let asset_id = parse_pollen_asset_id(&asset_id)?;
        let terms_hash = parse_hex32_field(&terms_hash, "termsHash")?;
        let valid_from_block = self.chain.get_height().await;
        if expires_at_block <= valid_from_block {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!(
                    "expires_at_block must be greater than current finalized height {valid_from_block}"
                ),
                None::<()>,
            ));
        }
        let authorization = crate::pollen::SaleAuthorization::new_unsigned(
            asset_id,
            seller_addr,
            unit_price,
            valid_from_block,
            expires_at_block,
            max_grants,
            terms_hash,
        );
        Ok(serde_json::json!({
            "seller": seller_addr.to_hex(),
            "assetId": asset_id.to_hex(),
            "authorizationId": authorization.authorization_id.to_hex(),
            "signingHash": format!("0x{}", hex::encode(authorization.signing_hash())),
            "unsignedAuthorization": authorization,
            "note": "seller_signature is sentinel until the owner signs this authorization; sentinel signatures are rejected on-chain",
        }))
    }

    async fn hub_get_apps(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let apps = self.chain.hub_get_apps().await;
        Ok(serde_json::json!(apps))
    }

    async fn hub_prepare_register(
        &self,
        developer: String,
        name: String,
        category: crate::hub::types::AppCategory,
        website_url: String,
        manifest_id: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_dev = developer.strip_prefix("0x").unwrap_or(&developer);
        let dev_addr = Address::from_hex(clean_dev).map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid developer address: {e}"),
                None::<()>,
            )
        })?;

        let m_id = if let Some(m_str) = manifest_id {
            let clean_m = m_str.strip_prefix("0x").unwrap_or(&m_str);
            let m_bytes = hex::decode(clean_m).map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("Invalid manifest hex: {e}"), None::<()>)
            })?;
            let mut m_arr = [0u8; 32];
            m_arr.copy_from_slice(&m_bytes);
            Some(crate::storage::content_id::ContentId(m_arr))
        } else {
            None
        };

        let tx = crate::core::transaction::Transaction {
            from: dev_addr,
            to: Address::zero(),
            amount: 0,
            fee: 500,
            nonce: self.chain.get_nonce(&dev_addr).await,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::HubRegisterApp {
                name,
                category,
                website_url,
                manifest_id: m_id,
            },
        };

        Ok(serde_json::json!({
            "developer": developer,
            "name": tx.from.to_hex(),
            "tx_template": tx,
        }))
    }

    async fn relayer_prepare_external_tx(
        &self,
        from: String,
        chain: crate::core::transaction::ExternalChain,
        target_address: String,
        payload: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_from = from.strip_prefix("0x").unwrap_or(&from);
        let from_addr = Address::from_hex(clean_from).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid from address: {e}"), None::<()>)
        })?;

        let payload_bytes =
            hex::decode(payload.strip_prefix("0x").unwrap_or(&payload)).map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("Invalid payload hex: {e}"), None::<()>)
            })?;

        let ext_tx = crate::core::transaction::ExternalTransaction {
            chain,
            target_address,
            payload: payload_bytes,
            external_nonce: 0,
        };

        let tx = crate::core::transaction::Transaction {
            from: from_addr,
            to: Address::zero(),
            amount: 0,
            fee: 2000,
            nonce: self.chain.get_nonce(&from_addr).await,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::UniversalRelay(ext_tx),
        };

        Ok(serde_json::json!({
            "from": from,
            "tx_template": tx,
        }))
    }

    async fn gateway_fetch_content(&self, name: String) -> Result<String, ErrorObjectOwned> {
        let gateway = crate::gateway::BudGateway::new(self.chain.clone(), None);
        let data = gateway.fetch_name_content(&name).await.map_err(|e| {
            ErrorObjectOwned::owned(
                -32000,
                format!("Gateway resolution failed: {e}"),
                None::<()>,
            )
        })?;
        Ok(hex::encode(data))
    }

    async fn passport_get_profile(
        &self,
        name: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let resolved = self.chain.bns_resolve_full(name.clone()).await;
        let manifest_id = resolved.as_ref().and_then(|r| {
            r.content_id
                .or(r.storage_root.map(crate::storage::ContentId))
        });
        let manifest = if let Some(id) = manifest_id {
            let reg = self.storage.lock().map_err(|e| {
                ErrorObjectOwned::owned(
                    -32603,
                    format!("storage registry lock poisoned: {e}"),
                    None::<()>,
                )
            })?;
            reg.get_manifest(&id).cloned()
        } else {
            None
        };
        let data_assets = self.chain.pollen_get_data_assets().await;
        let access_grants = self.chain.pollen_get_access_grants().await;
        let sale_authorizations = self.chain.pollen_get_sale_authorizations().await;
        let profile = crate::gateway::build_passport_profile(
            name,
            resolved,
            manifest,
            &data_assets,
            &access_grants,
            &sale_authorizations,
        );
        serde_json::to_value(profile).map_err(|e| {
            ErrorObjectOwned::owned(
                -32603,
                format!("failed to serialize passport profile: {e}"),
                None::<()>,
            )
        })
    }

    async fn atlas_get_wallet_context(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean = address.strip_prefix("0x").unwrap_or(&address);
        let address = Address::from_hex(clean).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid wallet address: {e}"), None::<()>)
        })?;
        let balance = self.chain.get_balance(&address).await;
        let nonce = self.chain.get_nonce(&address).await;
        let data_assets = self.chain.pollen_get_data_assets().await;
        let access_grants = self.chain.pollen_get_access_grants().await;
        let sale_authorizations = self.chain.pollen_get_sale_authorizations().await;
        let context = crate::gateway::build_wallet_context(
            address,
            balance,
            nonce,
            &data_assets,
            &access_grants,
            &sale_authorizations,
        );
        serde_json::to_value(context).map_err(|e| {
            ErrorObjectOwned::owned(
                -32603,
                format!("failed to serialize atlas wallet context: {e}"),
                None::<()>,
            )
        })
    }

    // --- Phase 10 (§1): AI Inference & Verifier Layer ---

    async fn ai_get_model(&self, model_id: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_id = model_id.strip_prefix("0x").unwrap_or(&model_id);
        let id_bytes = hex::decode(clean_id).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid model_id hex: {e}"), None::<()>)
        })?;
        if id_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "model_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        match self
            .chain
            .get_ai_model(crate::ai::types::AiModelId(arr))
            .await
        {
            Some(spec) => Ok(serde_json::to_value(&spec).unwrap_or(serde_json::Value::Null)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn ai_register_model(
        &self,
        owner: String,
        model_hash: String,
        min_verifier_count: u32,
        agreement_threshold: u32,
        max_input_ref_bytes: u64,
        max_output_ref_bytes: u64,
        request_deadline_blocks: u64,
        result_deadline_blocks: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_owner = owner.strip_prefix("0x").unwrap_or(&owner);
        let owner_addr = crate::core::address::Address::from_hex(clean_owner).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid owner address: {e}"), None::<()>)
        })?;

        let clean_hash = model_hash.strip_prefix("0x").unwrap_or(&model_hash);
        let hash_bytes = hex::decode(clean_hash).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid model_hash hex: {e}"), None::<()>)
        })?;
        if hash_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "model_hash must be 32 bytes",
                None::<()>,
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash_bytes);

        let model_id = crate::ai::types::AiModelId::of(&owner_addr, &arr, 1);
        let spec = crate::ai::types::AiModelSpec {
            model_id,
            model_hash: arr,
            owner: owner_addr,
            min_verifier_count,
            agreement_threshold,
            max_input_ref_bytes,
            max_output_ref_bytes,
            request_deadline_blocks,
            result_deadline_blocks,
            version: 1,
            active: true,
        };

        let tx = crate::core::transaction::Transaction {
            from: owner_addr,
            to: crate::core::address::Address::zero(),
            amount: 0,
            fee: crate::core::account::MIN_TX_FEE,
            nonce: 0,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiModelRegister(spec),
        };

        Ok(serde_json::json!({
            "model_id": model_id.to_hex(),
            "owner": owner_addr.to_hex(),
            "tx_template": tx,
        }))
    }

    async fn ai_submit_request(
        &self,
        requester: String,
        model_id: String,
        input_commitment: String,
        input_ref_hex: String,
        max_fee: u64,
        callback: Option<String>,
        deadline_block: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_req = requester.strip_prefix("0x").unwrap_or(&requester);
        let req_addr = crate::core::address::Address::from_hex(clean_req).map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid requester address: {e}"),
                None::<()>,
            )
        })?;

        let clean_mid = model_id.strip_prefix("0x").unwrap_or(&model_id);
        let mid_bytes = hex::decode(clean_mid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid model_id hex: {e}"), None::<()>)
        })?;
        if mid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "model_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut mid = [0u8; 32];
        mid.copy_from_slice(&mid_bytes);

        let clean_com = input_commitment
            .strip_prefix("0x")
            .unwrap_or(&input_commitment);
        let com_bytes = hex::decode(clean_com).map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid input_commitment hex: {e}"),
                None::<()>,
            )
        })?;
        if com_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "input_commitment must be 32 bytes",
                None::<()>,
            ));
        }
        let mut icom = [0u8; 32];
        icom.copy_from_slice(&com_bytes);

        let clean_ref = input_ref_hex.strip_prefix("0x").unwrap_or(&input_ref_hex);
        let ref_bytes = hex::decode(clean_ref).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid input_ref hex: {e}"), None::<()>)
        })?;
        let input_ref = crate::ai::types::BoundedBytes::try_new(ref_bytes)
            .map_err(|e| ErrorObjectOwned::owned(-32602, e, None::<()>))?;

        let cb = match callback {
            Some(c) if !c.is_empty() => {
                let clean_cb = c.strip_prefix("0x").unwrap_or(&c);
                Some(
                    crate::core::address::Address::from_hex(clean_cb).map_err(|e| {
                        ErrorObjectOwned::owned(
                            -32602,
                            format!("Invalid callback address: {e}"),
                            None::<()>,
                        )
                    })?,
                )
            }
            _ => None,
        };

        let current_height = self.chain.get_height().await;
        let mut req = crate::ai::types::AiInferenceRequest {
            request_id: crate::ai::types::AiRequestId::default(),
            requester: req_addr,
            model_id: crate::ai::types::AiModelId(mid),
            input_commitment: icom,
            input_ref,
            max_fee,
            callback: cb,
            submitted_at_block: current_height,
            deadline_block,
        };
        req.request_id = req.calculate_id();

        let tx = crate::core::transaction::Transaction {
            from: req_addr,
            to: crate::core::address::Address::zero(),
            amount: 0,
            fee: crate::core::account::MIN_TX_FEE,
            nonce: 0,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiInferenceRequest(req.clone()),
        };

        Ok(serde_json::json!({
            "request_id": req.request_id.to_hex(),
            "requester": req_addr.to_hex(),
            "tx_template": tx,
        }))
    }

    async fn ai_submit_result(
        &self,
        verifier: String,
        request_id: String,
        output_commitment: String,
        output_ref_hex: String,
        result_nonce: u64,
        signature_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        let clean_rid = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_rid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut rid = [0u8; 32];
        rid.copy_from_slice(&rid_bytes);

        let clean_ocom = output_commitment
            .strip_prefix("0x")
            .unwrap_or(&output_commitment);
        let com_bytes = hex::decode(clean_ocom).map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid output_commitment hex: {e}"),
                None::<()>,
            )
        })?;
        if com_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "output_commitment must be 32 bytes",
                None::<()>,
            ));
        }
        let mut ocom = [0u8; 32];
        ocom.copy_from_slice(&com_bytes);

        let clean_oref = output_ref_hex.strip_prefix("0x").unwrap_or(&output_ref_hex);
        let ref_bytes = hex::decode(clean_oref).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid output_ref hex: {e}"), None::<()>)
        })?;
        let output_ref = crate::ai::types::BoundedBytes::try_new(ref_bytes)
            .map_err(|e| ErrorObjectOwned::owned(-32602, e, None::<()>))?;

        let clean_sig = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
        let sig_bytes = hex::decode(clean_sig).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid signature hex: {e}"), None::<()>)
        })?;

        let current_height = self.chain.get_height().await;
        let res = crate::ai::types::AiInferenceResult {
            request_id: crate::ai::types::AiRequestId(rid),
            verifier: v_addr,
            output_commitment: ocom,
            output_ref,
            result_nonce,
            signature: sig_bytes,
            submitted_at_block: current_height,
        };

        let tx = crate::core::transaction::Transaction {
            from: v_addr,
            to: crate::core::address::Address::zero(),
            amount: 0,
            fee: crate::core::account::MIN_TX_FEE,
            nonce: 0,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiInferenceResult(res),
        };

        Ok(serde_json::json!({
            "verifier": v_addr.to_hex(),
            "tx_template": tx,
        }))
    }

    async fn ai_get_outcome(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_id = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let id_bytes = hex::decode(clean_id).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if id_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        match self
            .chain
            .get_ai_outcome(crate::ai::types::AiRequestId(arr))
            .await
        {
            Some(outcome) => Ok(serde_json::to_value(&outcome).unwrap_or(serde_json::Value::Null)),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn ai_get_active_verifiers(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let role = crate::registry::role::roles::AI_VERIFIER;
        let members = self.chain.get_registry_active_members(role).await;
        let list: Vec<serde_json::Value> = members
            .iter()
            .map(|reg| {
                serde_json::json!({
                    "address": Self::to_0x_hash(reg.account.to_hex()),
                    "stake": reg.stake,
                    "active": reg.is_active(),
                })
            })
            .collect();
        Ok(serde_json::Value::Array(list))
    }

    async fn ai_reclaim_fee(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_id = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_id).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes (64 hex chars)".to_string(),
                None::<()>,
            ));
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&rid_bytes);
        let rid = crate::ai::types::AiRequestId::new(id_bytes);

        match self.chain.get_ai_fee_reclaim_status(rid).await {
            Ok((requester, max_fee)) => Ok(serde_json::json!({
                "status": "reclaimable",
                "request_id": request_id,
                "requester": Self::to_0x_hash(requester.to_hex()),
                "max_fee": max_fee,
            })),
            Err(e) => Ok(serde_json::json!({
                "status": "error",
                "request_id": request_id,
                "message": e,
            })),
        }
    }

    async fn ai_equivocation_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_id = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_id).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes (64 hex chars)".to_string(),
                None::<()>,
            ));
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&rid_bytes);
        let rid = crate::ai::types::AiRequestId::new(id_bytes);

        let clean_verifier = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let verifier_addr =
            crate::core::address::Address::from_hex(clean_verifier).map_err(|e| {
                ErrorObjectOwned::owned(
                    -32602,
                    format!("Invalid verifier address: {e}"),
                    None::<()>,
                )
            })?;

        let has_equivocated = self
            .chain
            .get_ai_equivocation_status(rid, verifier_addr)
            .await;

        Ok(serde_json::json!({
            "request_id": request_id,
            "verifier": verifier,
            "has_equivocated": has_equivocated,
        }))
    }

    async fn ai_cancel_status(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_id = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_id).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes (64 hex chars)".to_string(),
                None::<()>,
            ));
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&rid_bytes);
        let rid = crate::ai::types::AiRequestId::new(id_bytes);

        let is_cancelled = self.chain.get_ai_cancel_status(rid).await;

        Ok(serde_json::json!({
            "request_id": request_id,
            "is_cancelled": is_cancelled,
        }))
    }

    async fn ai_dispute_slash(
        &self,
        submitter: String,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_sub = submitter.strip_prefix("0x").unwrap_or(&submitter);
        let sub_addr = crate::core::address::Address::from_hex(clean_sub).map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid submitter address: {e}"),
                None::<()>,
            )
        })?;

        let clean_rid = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_rid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes (64 hex chars)".to_string(),
                None::<()>,
            ));
        }
        let mut rid_arr = [0u8; 32];
        rid_arr.copy_from_slice(&rid_bytes);
        let rid = crate::ai::types::AiRequestId::new(rid_arr);

        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        // Check dispute status before preparing tx
        let status = self.chain.get_ai_dispute_status(rid, v_addr).await;
        if !status.has_equivocated {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!(
                    "No equivocation record for verifier {} on request {}",
                    v_addr.to_hex(),
                    rid.to_hex()
                ),
                None::<()>,
            ));
        }
        if !status.is_disputable {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!(
                    "Dispute window expired for verifier {} on request {}",
                    v_addr.to_hex(),
                    rid.to_hex()
                ),
                None::<()>,
            ));
        }

        let tx = crate::core::transaction::Transaction {
            from: sub_addr,
            to: crate::core::address::Address::zero(),
            amount: 0,
            fee: crate::core::account::MIN_TX_FEE,
            nonce: 0,
            data: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            hash: String::new(),
            signature: None,
            chain_id: self.chain.get_chain_id().await,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: crate::core::transaction::TransactionType::AiDisputeSlash {
                request_id: rid,
                verifier: v_addr,
            },
        };

        Ok(serde_json::json!({
            "submitter": submitter,
            "request_id": request_id,
            "verifier": verifier,
            "tx_template": tx,
            "dispute_status": {
                "has_equivocated": status.has_equivocated,
                "is_disputable": status.is_disputable,
                "detected_block": status.detected_block,
                "stake_at_risk": status.stake_amount,
            },
        }))
    }

    async fn ai_slashing_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_rid = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let rid_bytes = hex::decode(clean_rid).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if rid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes (64 hex chars)".to_string(),
                None::<()>,
            ));
        }
        let mut rid_arr = [0u8; 32];
        rid_arr.copy_from_slice(&rid_bytes);
        let rid = crate::ai::types::AiRequestId::new(rid_arr);

        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        let status = self.chain.get_ai_dispute_status(rid, v_addr).await;

        Ok(serde_json::json!({
            "request_id": request_id,
            "verifier": verifier,
            "has_equivocated": status.has_equivocated,
            "is_disputable": status.is_disputable,
            "detected_block": status.detected_block,
            "dispute_window_remaining": status.dispute_window_remaining,
            "is_staked": status.is_staked,
            "stake_amount": status.stake_amount,
        }))
    }

    async fn ai_verifier_stake(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        let info = self.chain.get_ai_verifier_stake(v_addr).await;

        Ok(serde_json::json!({
            "verifier": verifier,
            "is_staked": info.is_staked,
            "stake_amount": info.stake_amount,
            "total_equivocations": info.total_equivocations,
        }))
    }

    async fn ai_callback_queue(
        &self,
        callback_address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_cb = callback_address
            .strip_prefix("0x")
            .unwrap_or(&callback_address);
        let cb_addr = crate::core::address::Address::from_hex(clean_cb).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid callback address: {e}"), None::<()>)
        })?;

        let events = self.chain.get_ai_callback_queue(cb_addr).await;
        let events_json: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "request_id": format!("0x{}", e.request_id.to_hex()),
                    "output_commitment": format!("0x{}", hex::encode(e.output_commitment)),
                    "finalized_at_block": e.finalized_at_block,
                    "callback_address": format!("0x{}", e.callback_address.to_hex()),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "callback_address": callback_address,
            "pending_count": events_json.len(),
            "events": events_json,
        }))
    }

    /// P5 ADIM11 Bulgu 29: Query ZKVM execution proof for a (request, verifier) pair.
    async fn ai_execution_proof(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_req = request_id.strip_prefix("0x").unwrap_or(&request_id);
        let req_bytes = hex::decode(clean_req).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid request_id hex: {e}"), None::<()>)
        })?;
        if req_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "request_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut req_arr = [0u8; 32];
        req_arr.copy_from_slice(&req_bytes);
        let req_id = crate::ai::types::AiRequestId::new(req_arr);
        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        let proof = self.chain.get_ai_execution_proof(req_id, v_addr).await;

        match proof {
            Some(p) => Ok(serde_json::json!({
                "request_id": request_id,
                "verifier": verifier,
                "has_proof": true,
                "model_id": format!("0x{}", p.model_id.to_hex()),
                "input_commitment": format!("0x{}", hex::encode(p.input_commitment)),
                "output_commitment": format!("0x{}", hex::encode(p.output_commitment)),
                "program_hash": format!("0x{}", hex::encode(p.program_hash)),
                "steps": p.steps,
                "gas_used": p.gas_used,
                "proof_size_bytes": p.proof_bytes.len(),
                "trustless": true,
            })),
            None => Ok(serde_json::json!({
                "request_id": request_id,
                "verifier": verifier,
                "has_proof": false,
                "trustless": false,
            })),
        }
    }

    /// P5 ADIM11 Bulgu 30: Query QoS metrics for a verifier.
    async fn ai_verifier_qos(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean_v = verifier.strip_prefix("0x").unwrap_or(&verifier);
        let v_addr = crate::core::address::Address::from_hex(clean_v).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid verifier address: {e}"), None::<()>)
        })?;

        let qos = self.chain.get_ai_verifier_qos(v_addr).await;

        match qos {
            Some(q) => Ok(serde_json::json!({
                "verifier": verifier,
                "total_results_submitted": q.total_results_submitted,
                "successful_finalizations": q.successful_finalizations,
                "equivocation_count": q.equivocation_count,
                "avg_response_blocks": q.avg_response_blocks,
                "last_active_block": q.last_active_block,
                "reliability_score": q.reliability_score(),
                "finalization_rate": if q.total_results_submitted > 0 {
                    q.successful_finalizations as f64 / q.total_results_submitted as f64
                } else {
                    0.0
                },
            })),
            None => Ok(serde_json::json!({
                "verifier": verifier,
                "has_qos": false,
                "reliability_score": 0.0,
            })),
        }
    }

    /// P5 ADIM11 Bulgu 30: Get all verifiers ranked by reliability score.
    async fn ai_verifier_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ranking = self.chain.get_ai_verifiers_by_reliability().await;
        let ranking_json: Vec<serde_json::Value> = ranking
            .iter()
            .enumerate()
            .map(|(i, q)| {
                serde_json::json!({
                    "rank": i + 1,
                    "verifier": format!("0x{}", q.verifier.to_hex()),
                    "reliability_score": q.reliability_score(),
                    "total_results_submitted": q.total_results_submitted,
                    "successful_finalizations": q.successful_finalizations,
                    "equivocation_count": q.equivocation_count,
                    "avg_response_blocks": q.avg_response_blocks,
                    "last_active_block": q.last_active_block,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "total_verifiers": ranking_json.len(),
            "ranking": ranking_json,
        }))
    }

    /// P5 ADIM11 Bulgu 31: Query an agent-to-agent payment by ID.
    async fn ai_agent_payment(
        &self,
        payment_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean = payment_id.strip_prefix("0x").unwrap_or(&payment_id);
        let pid_bytes = hex::decode(clean).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid payment_id hex: {e}"), None::<()>)
        })?;
        if pid_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "payment_id must be 32 bytes",
                None::<()>,
            ));
        }
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&pid_bytes);

        let payment = self.chain.get_ai_agent_payment(pid).await;

        match payment {
            Some(p) => Ok(serde_json::json!({
                "payment_id": payment_id,
                "from_agent": format!("0x{}", p.from_agent.to_hex()),
                "to_agent": format!("0x{}", p.to_agent.to_hex()),
                "amount": p.amount,
                "escrowed": p.is_escrowed(),
                "request_id": p.request_id.map(|rid| format!("0x{}", rid.to_hex())),
                "require_proof": p.require_proof,
                "submitted_at_block": p.submitted_at_block,
                "expiry_block": p.expiry_block,
            })),
            None => Ok(serde_json::json!({
                "payment_id": payment_id,
                "found": false,
            })),
        }
    }

    /// P5 ADIM11 Bulgu 31: Query payments for an agent.
    async fn ai_agent_payments(
        &self,
        agent: String,
        direction: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let clean = agent.strip_prefix("0x").unwrap_or(&agent);
        let addr = crate::core::address::Address::from_hex(clean).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid agent address: {e}"), None::<()>)
        })?;
        let dir = match direction.to_lowercase().as_str() {
            "from" => crate::chain::chain_actor::AiPaymentDirection::From,
            "to" => crate::chain::chain_actor::AiPaymentDirection::To,
            _ => {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "direction must be 'from' or 'to'",
                    None::<()>,
                ))
            }
        };

        let payments = self.chain.get_ai_agent_payments(addr, dir).await;
        let payments_json: Vec<serde_json::Value> = payments
            .iter()
            .map(|p| {
                serde_json::json!({
                    "payment_id": format!("0x{}", hex::encode(p.payment_id)),
                    "from_agent": format!("0x{}", p.from_agent.to_hex()),
                    "to_agent": format!("0x{}", p.to_agent.to_hex()),
                    "amount": p.amount,
                    "escrowed": p.is_escrowed(),
                    "request_id": p.request_id.map(|rid| format!("0x{}", rid.to_hex())),
                    "require_proof": p.require_proof,
                    "submitted_at_block": p.submitted_at_block,
                    "expiry_block": p.expiry_block,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "agent": agent,
            "direction": direction,
            "payment_count": payments_json.len(),
            "payments": payments_json,
        }))
    }

    /// P5 ADIM11 Bulgu 33: Query the verifier whitelist.
    async fn ai_verifier_whitelist(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let whitelist = self.chain.get_ai_verifier_whitelist().await;
        let list: Vec<serde_json::Value> = whitelist
            .iter()
            .map(|v| serde_json::json!(format!("0x{}", v.to_hex())))
            .collect();
        Ok(serde_json::json!({
            "whitelist_mode": !list.is_empty(),
            "verifier_count": list.len(),
            "verifiers": list,
        }))
    }

    async fn ai_agent_reputation(
        &self,
        agent: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let rep = self.chain.get_ai_agent_reputation(agent).await;
        match rep {
            Some(r) => Ok(serde_json::json!({
                "agent": format!("0x{}", r.agent.to_hex()),
                "payments_completed": r.payments_completed,
                "payments_defaulted": r.payments_defaulted,
                "requests_submitted": r.requests_submitted,
                "results_submitted": r.results_submitted,
                "results_finalized": r.results_finalized,
                "equivocations": r.equivocations,
                "trust_score": r.trust_score(),
                "active_block_span": r.active_block_span,
                "first_active_block": r.first_active_block,
                "last_active_block": r.last_active_block,
            })),
            None => Ok(serde_json::json!({
                "error": "agent not found",
                "agent": format!("0x{}", agent.to_hex()),
            })),
        }
    }

    async fn ai_agent_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ranking = self.chain.get_ai_agent_ranking().await;
        let entries: Vec<serde_json::Value> = ranking
            .iter()
            .map(|(addr, score)| {
                serde_json::json!({
                    "agent": format!("0x{}", addr.to_hex()),
                    "trust_score": score,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "agent_count": entries.len(),
            "ranking": entries,
        }))
    }

    async fn prune_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain.get_prune_status().await.map_err(|e| {
            ErrorObjectOwned::owned(
                -32000,
                format!("Failed to get prune status: {e}"),
                None::<()>,
            )
        })
    }

    async fn request_prune(
        &self,
        min_blocks_to_keep: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let pruned_count = self
            .chain
            .request_prune(min_blocks_to_keep)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(-32000, format!("Pruning failed: {e}"), None::<()>)
            })?;

        Ok(serde_json::json!({
            "status": "completed",
            "pruned_blocks": pruned_count,
        }))
    }

    /// Phase 11.3 Task 1: Read-only status.
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let height = self.chain.get_height().await;
        let chain_id = self.chain.get_chain_id().await;
        let mempool = self.chain.get_mempool_size().await;
        let base_fee = self.chain.get_base_fee().await;
        let validator_set_hash = self.chain.get_validator_set_hash().await;
        Ok(serde_json::json!({
            "blockNumber": height,
            "chainId": chain_id,
            "mempoolSize": mempool,
            "baseFee": base_fee,
            "validatorSetHash": validator_set_hash,
        }))
    }

    async fn get_validator_set(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let validator = self.chain.get_validator_address().await;
        let set_hash = self.chain.get_validator_set_hash().await;
        Ok(serde_json::json!({
            "validatorAddress": validator.map(|a| format!("0x{}", a.to_hex())).unwrap_or_default(),
            "validatorSetHash": set_hash,
        }))
    }

    async fn get_domain_info(&self, domain_id: u32) -> Result<serde_json::Value, ErrorObjectOwned> {
        Ok(serde_json::json!({
            "domain_id": domain_id,
            "registered": false,
            "note": "domain registry lookup — wire to ChainActor",
        }))
    }

    async fn get_slashing_history(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Phase 11.3: slashing history RPC — ChainActor'e getSlashingHistory
        // komutu eklenene kadar minimal cevap.
        Ok(serde_json::json!({
            "history": [],
            "note": "slashing history query — wire to ChainActor in next iteration",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_per_ip_rate_limiting() {
        let config = RpcSecurityConfig {
            rate_limit_per_minute: Some(2),
            ..Default::default()
        };
        let per_ip_rates = Arc::new(Mutex::new(HashMap::new()));
        let ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // First request: allowed
        assert!(is_per_ip_rate_limited(&config, &per_ip_rates, ip));
        // Second request: allowed
        assert!(is_per_ip_rate_limited(&config, &per_ip_rates, ip));
        // Third request: rate limited (exceeds limit of 2)
        assert!(!is_per_ip_rate_limited(&config, &per_ip_rates, ip));
    }
}
