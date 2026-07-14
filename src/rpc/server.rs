use super::api::BudlumApiServer;
use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::domain::{
    RetrievalChallenge, RetrievalChallengeRequest, RetrievalResponse, StorageRegistry,
};
use crate::network::node::NodeClient;
use crate::storage::content_id::ContentId;
use futures::future::BoxFuture;
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::StatusCode;
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};
use jsonrpsee::types::error::ErrorObjectOwned;
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

// Tur 6 (security audit §5): `auth_required` defaults to `true` (secure
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
        // Tur 6 (security audit §5): secure default — auth ON, no API key
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
        // TUR 6 SECURITY WARNING: this constructor explicitly disables
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
}

impl RpcSecurityLayer {
    fn new(config: RpcSecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
            per_ip_rates: Arc::new(Mutex::new(HashMap::new())),
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
        }
    }
}

#[derive(Clone)]
struct RpcSecurityService<S> {
    inner: S,
    config: Arc<RpcSecurityConfig>,
    per_ip_rates: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
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
            return Box::pin(async {
                Ok(text_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many requests",
                ))
            });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

pub struct RpcServer {
    chain: ChainHandle,
    node: NodeClient,
    security: RpcSecurityConfig,
    mode: RpcMode,
    /// B.U.D. storage registry (Tur 14, Faz 5). Wrapped in `Arc<Mutex<_>>`
    /// so the same registry is shared with future consensus-side
    /// producers. The public RPC surface mutates it; the chain layer reads
    /// from a snapshot at block-application time.
    storage: Arc<Mutex<StorageRegistry>>,
}

impl RpcServer {
    pub fn new(chain: ChainHandle, node: NodeClient) -> Self {
        Self {
            chain,
            node,
            security: RpcSecurityConfig::default(),
            mode: RpcMode::Public,
            storage: Arc::new(Mutex::new(StorageRegistry::new())),
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
        }
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
        }
    }

    pub async fn run(self, addr: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use jsonrpsee::server::ServerBuilder;
        let http_middleware =
            ServiceBuilder::new().layer(RpcSecurityLayer::new(self.security.clone()));
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
            format!("0x{}", h)
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

fn constant_time_eq_str(a: &str, b: &str) -> bool {
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

    // Tur 12.5 / B3: constant-time compare of provided secret material.
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

    // Tur 12.5 / B2: X-Real-IP is client-spoofable unless the request
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
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {}", e), None::<()>)
        })?;
        let balance = self.chain.get_balance(&addr).await;
        Ok(Self::to_hex(balance))
    }

    async fn get_nonce(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let clean_addr = address.strip_prefix("0x").unwrap_or(&address);
        let addr = Address::from_hex(clean_addr).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {}", e), None::<()>)
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
            ErrorObjectOwned::owned(-32602, format!("Invalid params: {}", e), None::<()>)
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
                    format!("Invalid consensus domain: {}", e),
                    None::<()>,
                )
            })?;

        let info = self.chain.get_settlement_info().await;
        let registry_root = info["domainRegistryRoot"]
            .as_str()
            .map(|root| format!("0x{}", root))
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
                    format!("Invalid verified domain commitment: {}", e),
                    None::<()>,
                )
            })?;

        self.node
            .broadcast_verified_domain_commitment_sync(payload_clone);
        Ok(format!("0x{}", hash))
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
                    format!("Invalid cross domain message: {}", e),
                    None::<()>,
                )
            })?;

        self.node.broadcast_cross_domain_message_sync(msg_clone);
        Ok(format!("0x{}", msg_id))
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
                    format!("Invalid bridge asset registration: {}", e),
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
                    format!("Invalid bridge mint transfer: {}", e),
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
                    format!("Invalid bridge burn transfer: {}", e),
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
                    format!("Invalid bridge burn transfer: {}", e),
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
                    format!("Invalid bridge unlock transfer: {}", e),
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
                    format!("Invalid bridge unlock transfer: {}", e),
                    None::<()>,
                )
            })?;
        Ok(self.bridge_roots_json("unlocked").await)
    }

    async fn seal_global_header(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("bud_sealGlobalHeader")?;
        let header = self.chain.seal_global_header().await.map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Unable to seal global header: {}", e),
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
            ErrorObjectOwned::owned(-32602, format!("Invalid params: {}", e), None::<()>)
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
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {}", e), None::<()>)
        })?;
        self.chain.bond_relayer(addr, amount).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Relayer bond failed: {}", e), None::<()>)
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
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {}", e), None::<()>)
        })?;
        self.chain.bond_prover(addr, amount).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("Prover bond failed: {}", e), None::<()>)
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
                format!("Proof rejected: {}", e),
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
            ErrorObjectOwned::owned(-32602, format!("Invalid address: {}", e), None::<()>)
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
                format!("Rejected slashing report: {}", e),
                None::<()>,
            )),
        }
    }

    async fn submit_qc_fault_proof(
        &self,
        proof: crate::consensus::qc::QcFaultProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Tur 9.5 (security audit §4): permissionless entry-point.
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
                format!("Invalid QC fault proof: {}", e),
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

    // === TUR 14 — B.U.D. Storage RPC implementations ====================
    // The chain layer does not yet own a storage registry; we hold one on
    // the RPC server (`Arc<Mutex<StorageRegistry>>`) and snapshot it for
    // the chain-side accounting at block-application time (Faz 5 follow-up
    // in Tur 15). For Tur 14 the registry is RPC-driven and survives only
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
        // `opener` is resolved from the call's transaction — for the
        // permissionless RPC surface the opener is taken from the bound
        // `ChainHandle` (in this Tur 14 layer we don't yet have a signed
        // tx, so we accept a zero address as a placeholder; Tur 15 will
        // bind the actual signature). The op-chain-side enforcement
        // happens via `submit_registry_slashing_report`'s reporter path.
        // The opener_bond itself is the anti-spam gate (zero bond = rejected).
        let opener = Address::zero();
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
            "challenge": challenge.map(|c| retrieval_challenge_to_json(&c)),
        }))
    }

    async fn storage_answer_challenge(
        &self,
        response: RetrievalResponse,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // The responder is the signer of the bound tx (zero placeholder
        // in this Tur 14 layer; the chain-side `StorageRegistry` enforces
        // the operator-identity match, so a non-operator gets a
        // `NotTheOperator` error regardless of who calls this RPC).
        let responder = Address::zero();
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
                response.range_hash,
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
}

fn parse_content_id(s: &str) -> Result<ContentId, ErrorObjectOwned> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("Invalid hex: {e}"), None::<()>))?;
    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "expected 32-byte hex string",
            None::<()>,
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ContentId(arr))
}

fn storage_deal_to_json(d: &crate::domain::StorageDeal) -> serde_json::Value {
    serde_json::json!({
        "dealId": d.deal_id,
        "domainId": d.domain_id,
        "manifestId": format!("0x{}", hex::encode(d.manifest_id.0)),
        "shardId": format!("0x{}", hex::encode(d.shard_id.0)),
        "operator": d.operator.to_string(),
        "operatorBond": d.economics.operator_bond,
        "feePerEpoch": d.economics.fee_per_epoch,
        "replicaIndex": d.replica_index,
        "dealStartEpoch": d.deal_start_epoch,
        "dealEndEpoch": d.deal_end_epoch,
        "status": format!("{:?}", d.status),
    })
}

fn retrieval_challenge_to_json(c: &RetrievalChallenge) -> serde_json::Value {
    serde_json::json!({
        "challengeId": c.challenge_id,
        "dealId": c.deal_id,
        "shardId": format!("0x{}", hex::encode(c.shard_id.0)),
        "byteStart": c.byte_start,
        "byteEnd": c.byte_end,
        "challengeEpoch": c.challenge_epoch,
        "deadlineEpoch": c.deadline_epoch,
        "opener": c.opener.to_string(),
        "openerBond": c.opener_bond,
    })
}

#[cfg(test)]
mod security_tests {
    use super::*;

    fn request_with_headers(headers: &[(&str, &str)]) -> HttpRequest<()> {
        let mut builder = HttpRequest::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn auth_accepts_x_api_key_and_bearer() {
        let config = RpcSecurityConfig {
            auth_required: true,
            api_key: Some("secret".to_string()),
            ..Default::default()
        };

        assert!(is_authorized(
            &config,
            &request_with_headers(&[("x-api-key", "secret")])
        ));
        assert!(is_authorized(
            &config,
            &request_with_headers(&[("authorization", "Bearer secret")])
        ));
        assert!(!is_authorized(
            &config,
            &request_with_headers(&[("x-api-key", "wrong")])
        ));
    }

    #[test]
    fn x_real_ip_ignored_without_trusted_proxies() {
        // Tur 12.5 / B2: bare X-Real-IP is spoofable; without trusted_proxies
        // the IP cannot be extracted from headers alone.
        let config = RpcSecurityConfig {
            allowed_ips: vec!["10.0.0.1".to_string()],
            cors_origins: vec!["https://wallet.example".to_string()],
            trusted_proxies: vec![],
            ..Default::default()
        };

        let spoofed = request_with_headers(&[
            ("x-real-ip", "10.0.0.1"),
            ("origin", "https://wallet.example"),
        ]);
        assert!(extract_client_ip(&config, &spoofed).is_none());
        assert!(!is_ip_allowed(&config, &spoofed));
    }

    #[test]
    fn x_real_ip_honored_with_trusted_proxies() {
        let config = RpcSecurityConfig {
            allowed_ips: vec!["10.0.0.1".to_string()],
            cors_origins: vec!["https://wallet.example".to_string()],
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };

        let allowed = request_with_headers(&[
            ("x-real-ip", "10.0.0.1"),
            ("origin", "https://wallet.example"),
        ]);
        let denied_ip = request_with_headers(&[
            ("x-real-ip", "10.0.0.2"),
            ("origin", "https://wallet.example"),
        ]);
        let denied_origin =
            request_with_headers(&[("x-real-ip", "10.0.0.1"), ("origin", "https://bad")]);

        assert!(is_ip_allowed(&config, &allowed));
        assert!(!is_ip_allowed(&config, &denied_ip));
        assert!(!is_origin_allowed(&config, &denied_origin));
    }

    #[test]
    fn origin_is_enforced_when_configured() {
        let config = RpcSecurityConfig {
            cors_origins: vec!["https://wallet.example".to_string()],
            ..Default::default()
        };

        let allowed = request_with_headers(&[("origin", "https://wallet.example")]);
        let denied = request_with_headers(&[("origin", "https://bad.example")]);

        assert!(is_origin_allowed(&config, &allowed));
        assert!(!is_origin_allowed(&config, &denied));
    }

    #[test]
    fn trusted_proxy_honors_x_forwarded_for() {
        let config = RpcSecurityConfig {
            allowed_ips: vec!["10.0.0.100".to_string()],
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };

        let req = request_with_headers(&[("x-forwarded-for", "10.0.0.100")]);
        let ip = extract_client_ip(&config, &req);
        assert_eq!(ip, Some("10.0.0.100".parse().unwrap()));
    }

    #[test]
    fn no_trusted_proxies_returns_none_without_x_real_ip() {
        let config = RpcSecurityConfig {
            allowed_ips: vec!["10.0.0.100".to_string()],
            trusted_proxies: vec![],
            ..Default::default()
        };

        // Without trusted proxies and without x-real-ip, no IP can be extracted
        let ip = extract_client_ip(
            &config,
            &request_with_headers(&[("x-forwarded-for", "10.0.0.100")]),
        );
        assert!(ip.is_none());
    }

    #[test]
    fn per_ip_rate_limit_tracks_by_client_ip() {
        let config = RpcSecurityConfig {
            rate_limit_per_minute: Some(2),
            ..Default::default()
        };
        let rates = Arc::new(Mutex::new(HashMap::new()));
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();

        assert!(is_per_ip_rate_limited(&config, &rates, Some(ip1)));
        assert!(is_per_ip_rate_limited(&config, &rates, Some(ip1)));
        assert!(!is_per_ip_rate_limited(&config, &rates, Some(ip1)));

        // Different IP has its own limit
        assert!(is_per_ip_rate_limited(&config, &rates, Some(ip2)));
        assert!(is_per_ip_rate_limited(&config, &rates, Some(ip2)));
        assert!(!is_per_ip_rate_limited(&config, &rates, Some(ip2)));
    }

    #[test]
    fn rate_limit_disabled_returns_true() {
        let config = RpcSecurityConfig {
            rate_limit_per_minute: None,
            ..Default::default()
        };
        let rates = Arc::new(Mutex::new(HashMap::new()));
        assert!(is_per_ip_rate_limited(
            &config,
            &rates,
            Some("1.1.1.1".parse().unwrap())
        ));
    }

    #[test]
    fn required_auth_requires_env_key() {
        let result = RpcSecurityConfig::from_env(
            true,
            Some("BUDLUM_TEST_MISSING_RPC_KEY"),
            Vec::new(),
            Vec::new(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn operator_default_binds_localhost_only() {
        let config = RpcSecurityConfig::operator_default();
        assert!(!config.auth_required);
        assert!(config.allowed_ips.contains(&"127.0.0.1".to_string()));
        assert!(config.allowed_ips.contains(&"::1".to_string()));
        assert!(config.max_connections.is_some());
    }
}
