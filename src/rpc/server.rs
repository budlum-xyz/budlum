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

fn parse_content_id(hex_str: &str) -> Result<ContentId, ErrorObjectOwned> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("Invalid ContentId hex: {e}"), None::<()>)
    })?;
    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "ContentId must be 32 bytes",
            None::<()>,
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ContentId(arr))
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
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.chain
            .mint_bridge_transfer_from_verified_event(
                source_domain,
                source_height,
                sequence,
                expected_block_hash,
                event,
                proof,
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
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid relayer address: {e}"),
                None::<()>,
            )
        })?;

        let message = self
            .chain
            .submit_relay_proof(message_id, relayer_addr, proof, source_domain)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("Relay proof submission failed: {e}"), None::<()>)
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
            tx_type: crate::core::transaction::TransactionType::AiPurchaseData { offer_id },
        };

        Ok(serde_json::json!({
            "buyer": buyer,
            "offer_id": offer_id,
            "tx_template": tx,
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
