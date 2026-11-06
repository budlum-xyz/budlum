//! Ethereum JSON-RPC compatibility gateway (`127.0.0.1:18547`, `Section 8.11.2`, `WP-28`,
//! closing `BLG-249` Ethereum leg).
//!
//! Serves HTTP + WebSocket JSON-RPC via `jsonrpsee`, enforces [`ETH_METHOD_CLASSES`]
//! at startup, exposes Budlum's `execution_root` (`BDLM_UEL_ROOT_V1`) in block
//! `stateRoot`, deterministically refuses `eth_getProof` with `-32601`, restricts
//! `debug_traceTransaction` and `debug_traceCall` to the operator listener, and bounds
//! filter and WebSocket subscription lifetimes and quotas.

pub mod filters;
pub mod method_class;
pub mod types;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use jsonrpsee::core::server::Methods;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{ConnectionId, Extensions};
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder, ServerConfig, ServerHandle};
use jsonrpsee::types::error::ErrorObjectOwned;
use tokio::sync::broadcast;

use crate::cli::commands::CompatEthereumSection;
use crate::execution::coordinator::foreign::ethereum::{
    decode_and_recover_eth_tx, DecodedEthTx, BUDLUM_EVM_CHAIN_ID,
};
use crate::execution::coordinator::foreign::ForeignCoordinatorBook;
use crate::rpc::server::RpcMode;

use self::filters::{
    BoundedEthFilters, EthFilterKind, FilterError, ParsedLogFilter, RawEthFilter,
    DEFAULT_FILTER_TTL_MS, DEFAULT_MAX_FILTERS, DEFAULT_MAX_FILTERS_PER_PEER,
    DEFAULT_MAX_LOG_BLOCK_RANGE, DEFAULT_MAX_LOG_RESULTS, DEFAULT_MAX_SUBSCRIPTIONS,
};
use self::method_class::{check_served_eth_methods, CompatListener, ETH_METHOD_CLASSES};
use self::types::{
    format_bytes_hex, format_u128_hex, format_u64_hex, parse_eth_address, parse_eth_word32,
    parse_quantity_u64, BlockSelector, EthBlockRecord, EthCallObject, EthLogEntry, EthStoredTx,
};

/// Default loopback HTTP + WebSocket bind address (`Section 8.11.1`).
pub const DEFAULT_ETH_RPC_LISTENER: &str = "127.0.0.1:18547";
/// Default loopback operator listener for `debug_trace*` (`Section 8.11.2`).
pub const DEFAULT_ETH_OPERATOR_LISTENER: &str = "127.0.0.1:18557";
/// Default EVM soft block gas limit (`30_000_000` BGU, `Section 8.9.3`).
pub const DEFAULT_EVM_SOFT_BLOCK_GAS: u64 = 30_000_000;
/// Default initial EIP-1559 base fee (`1` gwei = `1_000_000_000` attoBUD/BGU).
pub const DEFAULT_BASE_FEE_WEI: u128 = 1_000_000_000;
/// Default suggested priority fee (`100_000_000` wei = `0.1` gwei).
pub const DEFAULT_PRIORITY_FEE_WEI: u128 = 100_000_000;

/// JSON-RPC `-32601` Method Not Found error code (`eth_getProof` + public `debug_trace*`).
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC `-32602` Invalid Params error code.
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC `-32000` Execution / mempool rejection error code.
pub const JSONRPC_EXECUTION_ERROR: i32 = -32000;
/// JSON-RPC `-32005` Resource limit exceeded error code (`EIP-1474`).
pub const JSONRPC_LIMIT_EXCEEDED: i32 = -32005;

/// Runtime configuration for the Ethereum compatibility gateway (`[compat.ethereum]`).
///
/// Convenience: constructed from `NodeConfig` or test harnesses.
#[derive(Debug, Clone)]
pub struct EthRpcConfig {
    pub enabled: bool,
    pub chain_id: u64,
    pub listener: String,
    pub operator_listener: String,
    pub max_filters: usize,
    pub max_filters_per_peer: usize,
    pub filter_ttl_ms: u64,
    pub max_subscriptions: usize,
}

impl Default for EthRpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            chain_id: BUDLUM_EVM_CHAIN_ID,
            listener: DEFAULT_ETH_RPC_LISTENER.to_string(),
            operator_listener: DEFAULT_ETH_OPERATOR_LISTENER.to_string(),
            max_filters: DEFAULT_MAX_FILTERS,
            max_filters_per_peer: DEFAULT_MAX_FILTERS_PER_PEER,
            filter_ttl_ms: DEFAULT_FILTER_TTL_MS,
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
        }
    }
}

impl EthRpcConfig {
    /// Build [`EthRpcConfig`] from a parsed `[compat.ethereum]` TOML section.
    ///
    /// Convenience: bridges `FileConfig::compat` into the Ethereum gateway.
    #[must_use]
    pub fn from_section(sec: &CompatEthereumSection, chain_id: u64) -> Self {
        let base = Self {
            chain_id: if chain_id == 0 {
                BUDLUM_EVM_CHAIN_ID
            } else {
                chain_id
            },
            ..Self::default()
        };
        Self {
            enabled: sec.enabled.unwrap_or(base.enabled),
            chain_id: base.chain_id,
            listener: sec.listener.clone().unwrap_or(base.listener),
            operator_listener: sec
                .operator_listener
                .clone()
                .unwrap_or(base.operator_listener),
            max_filters: sec.max_filters.unwrap_or(base.max_filters),
            max_filters_per_peer: sec
                .max_filters_per_peer
                .unwrap_or(base.max_filters_per_peer),
            filter_ttl_ms: sec
                .filter_ttl_secs
                .map_or(base.filter_ttl_ms, |s| s.saturating_mul(1_000)),
            max_subscriptions: sec.max_subscriptions.unwrap_or(base.max_subscriptions),
        }
    }
}

/// Call simulation callback hook (`(call, block_height) -> Result<output_bytes, revert_msg>`).
pub type CallSimulator =
    Arc<dyn Fn(&EthCallObject, u64) -> Result<(Vec<u8>, u64), String> + Send + Sync>;

/// Mutable inner ledger view & filter table shared behind `EthCompatBackend`.
pub struct EthCompatInner {
    pub chain_id: u64,
    pub syncing: bool,
    pub base_fee_wei: u128,
    pub priority_fee_wei: u128,
    pub balances: BTreeMap<[u8; 20], u128>,
    pub nonces: BTreeMap<[u8; 20], u64>,
    pub code: BTreeMap<[u8; 20], Vec<u8>>,
    pub storage: BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>,
    pub blocks_by_num: BTreeMap<u64, EthBlockRecord>,
    pub block_num_by_hash: BTreeMap<[u8; 32], u64>,
    pub txs_by_hash: BTreeMap<[u8; 32], EthStoredTx>,
    pub pending_raw_txs: Vec<DecodedEthTx>,
    pub foreign_book: ForeignCoordinatorBook,
    pub filters: BoundedEthFilters,
}

impl EthCompatInner {
    fn new(cfg: &EthRpcConfig) -> Self {
        let genesis = EthBlockRecord {
            number: 0,
            hash: [0x10; 32],
            parent_hash: [0u8; 32],
            execution_root: [0xEE; 32],
            transactions_root: [0u8; 32],
            receipts_root: [0u8; 32],
            beneficiary: [0u8; 20],
            gas_limit: DEFAULT_EVM_SOFT_BLOCK_GAS,
            gas_used: 0,
            base_fee_per_gas_wei: DEFAULT_BASE_FEE_WEI,
            timestamp_secs: 1_762_000_000,
            tx_hashes: Vec::new(),
            logs_bloom: [0u8; 256],
        };
        let mut blocks_by_num = BTreeMap::new();
        let mut block_num_by_hash = BTreeMap::new();
        block_num_by_hash.insert(genesis.hash, 0);
        blocks_by_num.insert(0, genesis);
        Self {
            chain_id: cfg.chain_id,
            syncing: false,
            base_fee_wei: DEFAULT_BASE_FEE_WEI,
            priority_fee_wei: DEFAULT_PRIORITY_FEE_WEI,
            balances: BTreeMap::new(),
            nonces: BTreeMap::new(),
            code: BTreeMap::new(),
            storage: BTreeMap::new(),
            blocks_by_num,
            block_num_by_hash,
            txs_by_hash: BTreeMap::new(),
            pending_raw_txs: Vec::new(),
            foreign_book: ForeignCoordinatorBook::new(),
            filters: BoundedEthFilters::new(
                cfg.max_filters,
                cfg.max_filters_per_peer,
                cfg.filter_ttl_ms,
            ),
        }
    }

    fn head_height(&self) -> u64 {
        self.blocks_by_num.keys().next_back().copied().unwrap_or(0)
    }
}

/// Shared state handle for `EthCompatServer` (`Public` and `Operator` listeners).
///
/// Convenience: thread-safe gateway backend shared between HTTP/WS handlers and block committers.
#[derive(Clone)]
pub struct EthCompatBackend {
    pub inner: Arc<Mutex<EthCompatInner>>,
    pub head_tx: broadcast::Sender<EthBlockRecord>,
    pub log_tx: broadcast::Sender<EthLogEntry>,
    pub pending_tx: broadcast::Sender<[u8; 32]>,
    pub active_subs: Arc<AtomicUsize>,
    pub max_subs: usize,
    pub simulator: Option<CallSimulator>,
}

impl EthCompatBackend {
    /// Construct a fresh backend from `cfg`.
    ///
    /// Convenience: entry point for node startup and compatibility gateway tests.
    #[must_use]
    pub fn new(cfg: &EthRpcConfig) -> Self {
        let (head_tx, _) = broadcast::channel(128);
        let (log_tx, _) = broadcast::channel(512);
        let (pending_tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Mutex::new(EthCompatInner::new(cfg))),
            head_tx,
            log_tx,
            pending_tx,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subs: cfg.max_subscriptions.max(1),
            simulator: None,
        }
    }

    /// Attach an EVM call simulator (`revm` worker / coordinator read adapter).
    ///
    /// Convenience: wires live `eth_call` and `eth_estimateGas` execution.
    #[must_use]
    pub fn with_simulator(mut self, sim: CallSimulator) -> Self {
        self.simulator = Some(sim);
        self
    }

    /// Record a committed block with its UEL `execution_root` and executed EVM transactions,
    /// broadcasting to `newHeads` and `logs` subscribers.
    ///
    /// Convenience: called by the block committer when a new Budlum block finalizes.
    pub fn record_committed_block(&self, block: EthBlockRecord, txs: Vec<EthStoredTx>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.base_fee_wei = block.base_fee_per_gas_wei;
            guard.block_num_by_hash.insert(block.hash, block.number);
            guard.blocks_by_num.insert(block.number, block.clone());
            for tx in &txs {
                guard.txs_by_hash.insert(tx.hash, tx.clone());
                let next_nonce = tx.nonce.saturating_add(1);
                let cur = guard.nonces.get(&tx.from).copied().unwrap_or(0);
                if next_nonce > cur {
                    guard.nonces.insert(tx.from, next_nonce);
                }
            }
        }
        let _ = self.head_tx.send(block);
        for tx in txs {
            for log in tx.logs {
                let _ = self.log_tx.send(log);
            }
        }
    }
}

struct SubPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for SubPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_sub_permit(counter: &Arc<AtomicUsize>, max: usize) -> Option<SubPermit> {
    let mut cur = counter.load(Ordering::Acquire);
    loop {
        if cur >= max {
            return None;
        }
        match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(SubPermit {
                    counter: Arc::clone(counter),
                });
            }
            Err(actual) => cur = actual,
        }
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn err_invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_INVALID_PARAMS, msg.into(), None::<()>)
}

fn err_method_not_found(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_METHOD_NOT_FOUND, msg.into(), None::<()>)
}

fn err_execution(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_EXECUTION_ERROR, msg.into(), None::<()>)
}

/// Return a server-assigned identity for the transport connection that owns a
/// stateful filter. Never use a client-supplied JSON-RPC parameter as this key.
fn filter_owner(extensions: &Extensions) -> Result<String, ErrorObjectOwned> {
    let connection_id = extensions
        .get::<ConnectionId>()
        .ok_or_else(|| err_execution("RPC connection identity is unavailable"))?;
    Ok(format!("connection:{}", connection_id.0))
}

fn err_filter(err: FilterError) -> ErrorObjectOwned {
    match err {
        FilterError::GlobalCapReached(_) | FilterError::PeerQuotaReached { .. } => {
            ErrorObjectOwned::owned(JSONRPC_LIMIT_EXCEEDED, err.to_string(), None::<()>)
        }
        FilterError::NotFound(_) => err_execution(err.to_string()),
        FilterError::InvalidFilter(m) => err_invalid_params(m),
    }
}

fn parse_filter_id_u128(raw: &str) -> Result<u128, ErrorObjectOwned> {
    let clean = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if clean.is_empty() || clean.len() > 32 {
        return Err(err_invalid_params("invalid filter id"));
    }
    u128::from_str_radix(clean, 16).map_err(|_| err_invalid_params("invalid hex filter id"))
}

/// Complete Ethereum JSON-RPC interface (`Section 8.11.2` + `eth_getProof` refusal).
#[rpc(server)]
pub trait EthCompatApi {
    #[method(name = "web3_clientVersion")]
    async fn web3_client_version(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "net_version")]
    async fn net_version(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "net_listening")]
    async fn net_listening(&self) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "eth_chainId")]
    async fn eth_chain_id(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_syncing")]
    async fn eth_syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getCode")]
    async fn eth_get_code(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getStorageAt")]
    async fn eth_get_storage_at(
        &self,
        address: String,
        slot: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getTransactionCount")]
    async fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_call")]
    async fn eth_call(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_estimateGas")]
    async fn eth_estimate_gas(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_createAccessList")]
    async fn eth_create_access_list(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_gasPrice")]
    async fn eth_gas_price(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_maxPriorityFeePerGas")]
    async fn eth_max_priority_fee_per_gas(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_feeHistory")]
    async fn eth_fee_history(
        &self,
        block_count: serde_json::Value,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, raw_tx: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getBlockByNumber")]
    async fn eth_get_block_by_number(
        &self,
        block: String,
        full_txs: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getBlockByHash")]
    async fn eth_get_block_by_hash(
        &self,
        hash: String,
        full_txs: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getBlockTransactionCountByNumber")]
    async fn eth_get_block_tx_count_by_number(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getBlockTransactionCountByHash")]
    async fn eth_get_block_tx_count_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getTransactionByHash")]
    async fn eth_get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getTransactionByBlockNumberAndIndex")]
    async fn eth_get_transaction_by_block_number_and_index(
        &self,
        block: String,
        index: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getTransactionReceipt")]
    async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getBlockReceipts")]
    async fn eth_get_block_receipts(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "eth_getLogs")]
    async fn eth_get_logs(
        &self,
        filter: RawEthFilter,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned>;

    #[method(name = "eth_newFilter", with_extensions)]
    async fn eth_new_filter(&self, filter: RawEthFilter) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_newBlockFilter", with_extensions)]
    async fn eth_new_block_filter(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_getFilterChanges", with_extensions)]
    async fn eth_get_filter_changes(
        &self,
        filter_id: String,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned>;

    #[method(name = "eth_getFilterLogs", with_extensions)]
    async fn eth_get_filter_logs(
        &self,
        filter_id: String,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned>;

    #[method(name = "eth_uninstallFilter", with_extensions)]
    async fn eth_uninstall_filter(&self, filter_id: String) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "eth_accounts")]
    async fn eth_accounts(&self) -> Result<Vec<String>, ErrorObjectOwned>;

    #[method(name = "eth_getProof")]
    async fn eth_get_proof(
        &self,
        address: String,
        storage_keys: Vec<String>,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "debug_traceTransaction")]
    async fn debug_trace_transaction(
        &self,
        tx_hash: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "debug_traceCall")]
    async fn debug_trace_call(
        &self,
        call: EthCallObject,
        block: Option<String>,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[subscription(
        name = "eth_subscribe" => "eth_subscription",
        unsubscribe = "eth_unsubscribe",
        item = serde_json::Value
    )]
    async fn eth_subscribe(
        &self,
        kind: String,
        filter: Option<RawEthFilter>,
    ) -> jsonrpsee::core::SubscriptionResult;
}

/// Ethereum compatibility RPC server (`Public` on `127.0.0.1:18547`,
/// `Operator` for `debug_trace*`).
///
/// Convenience: instantiated per listener mode over a shared [`EthCompatBackend`].
#[derive(Clone)]
pub struct EthCompatServer {
    backend: EthCompatBackend,
    mode: RpcMode,
}

impl EthCompatServer {
    /// Create a public listener server (`127.0.0.1:18547`).
    ///
    /// Convenience: standard constructor for public Ethereum compatibility RPC.
    #[must_use]
    pub fn new_public(backend: EthCompatBackend) -> Self {
        Self {
            backend,
            mode: RpcMode::Public,
        }
    }

    /// Create an operator listener server (`debug_traceTransaction` + `debug_traceCall` enabled).
    ///
    /// Convenience: constructor for loopback operator trace RPC.
    #[must_use]
    pub fn new_operator(backend: EthCompatBackend) -> Self {
        Self {
            backend,
            mode: RpcMode::Operator,
        }
    }

    fn require_operator(&self, method_name: &str) -> Result<(), ErrorObjectOwned> {
        let Some(row) = method_class::lookup_eth_method(method_name) else {
            return Err(err_method_not_found("unclassified method"));
        };
        if row.listener == CompatListener::Operator && !matches!(self.mode, RpcMode::Operator) {
            return Err(err_method_not_found(format!(
                "{method_name} is served only on the operator listener"
            )));
        }
        Ok(())
    }

    fn query_logs_in_inner(
        inner: &EthCompatInner,
        parsed: &ParsedLogFilter,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
        let head = inner.head_height();
        let (from_h, to_h) = if let Some(bh) = parsed.block_hash {
            let Some(&num) = inner.block_num_by_hash.get(&bh) else {
                return Ok(Vec::new());
            };
            (num, num)
        } else {
            let Some(f) = parsed.from_block.resolve(head) else {
                return Ok(Vec::new());
            };
            let to_raw = match parsed.to_block {
                BlockSelector::Number(n) => n.min(head),
                other => other.resolve(head).unwrap_or(head),
            };
            if f > to_raw {
                return Ok(Vec::new());
            }
            if to_raw.saturating_sub(f) > DEFAULT_MAX_LOG_BLOCK_RANGE {
                return Err(ErrorObjectOwned::owned(
                    JSONRPC_LIMIT_EXCEEDED,
                    format!(
                        "eth_getLogs block range exceeds maximum {DEFAULT_MAX_LOG_BLOCK_RANGE}"
                    ),
                    None::<()>,
                ));
            }
            (f, to_raw)
        };

        let mut out = Vec::new();
        for height in from_h..=to_h {
            let Some(blk) = inner.blocks_by_num.get(&height) else {
                continue;
            };
            for tx_hash in &blk.tx_hashes {
                let Some(tx) = inner.txs_by_hash.get(tx_hash) else {
                    continue;
                };
                for log in &tx.logs {
                    if parsed.matches_log(log) {
                        if out.len() >= DEFAULT_MAX_LOG_RESULTS {
                            let msg = format!(
                                "eth_getLogs result count exceeds {DEFAULT_MAX_LOG_RESULTS}"
                            );
                            return Err(ErrorObjectOwned::owned(
                                JSONRPC_LIMIT_EXCEEDED,
                                msg,
                                None::<()>,
                            ));
                        }
                        out.push(log.to_rpc_json());
                    }
                }
            }
        }
        Ok(out)
    }

    /// Bind and start the HTTP + WebSocket Ethereum JSON-RPC server after verifying
    /// [`ETH_METHOD_CLASSES`] completeness.
    ///
    /// Convenience: launches the live `127.0.0.1:18547` listener.
    pub async fn start(
        self,
        bind_addr: SocketAddr,
    ) -> Result<(SocketAddr, ServerHandle), Box<dyn std::error::Error + Send + Sync>> {
        if matches!(self.mode, RpcMode::Operator) && !bind_addr.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Ethereum operator listener must bind to a loopback address",
            )
            .into());
        }
        let methods: Methods = self.into_rpc().into();
        check_served_eth_methods(methods.method_names()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("ETH_METHOD_CLASSES mismatch: {e}"),
            )
        })?;

        let cfg = ServerConfig::builder()
            .max_request_body_size(16 * 1024 * 1024)
            .max_connections(500)
            .set_batch_request_config(BatchRequestConfig::Limit(100))
            .build();
        let server = ServerBuilder::default()
            .set_config(cfg)
            .build(bind_addr)
            .await?;
        let local_addr = server.local_addr()?;
        let handle = server.start(methods);
        Ok((local_addr, handle))
    }
}

#[jsonrpsee::core::async_trait]
impl EthCompatApiServer for EthCompatServer {
    async fn web3_client_version(&self) -> Result<String, ErrorObjectOwned> {
        Ok("Budlum/v0.1.0/uel-evm-osaka".into())
    }

    async fn net_version(&self) -> Result<String, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(guard.chain_id.to_string())
    }

    async fn net_listening(&self) -> Result<bool, ErrorObjectOwned> {
        Ok(true)
    }

    async fn eth_chain_id(&self) -> Result<String, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(format_u64_hex(guard.chain_id))
    }

    async fn eth_syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        if guard.syncing {
            let head = format_u64_hex(guard.head_height());
            Ok(serde_json::json!({
                "startingBlock": "0x0",
                "currentBlock": head,
                "highestBlock": head,
            }))
        } else {
            Ok(serde_json::Value::Bool(false))
        }
    }

    async fn eth_block_number(&self) -> Result<String, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(format_u64_hex(guard.head_height()))
    }

    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_eth_address(&address).map_err(err_invalid_params)?;
        let _ = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let bal = guard.balances.get(&addr).copied().unwrap_or(0);
        Ok(format_u128_hex(bal))
    }

    async fn eth_get_code(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_eth_address(&address).map_err(err_invalid_params)?;
        let _ = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let bytes = guard.code.get(&addr).map_or(&[] as &[u8], Vec::as_slice);
        Ok(format_bytes_hex(bytes))
    }

    async fn eth_get_storage_at(
        &self,
        address: String,
        slot: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_eth_address(&address).map_err(err_invalid_params)?;
        let slot_key = parse_eth_word32(&slot, true).map_err(err_invalid_params)?;
        let _ = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let word = guard
            .storage
            .get(&(addr, slot_key))
            .copied()
            .unwrap_or([0u8; 32]);
        Ok(format_bytes_hex(&word))
    }

    async fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_eth_address(&address).map_err(err_invalid_params)?;
        let _ = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let nonce = guard.nonces.get(&addr).copied().unwrap_or(0);
        Ok(format_u64_hex(nonce))
    }

    async fn eth_call(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let _ = call.decoded_input().map_err(err_invalid_params)?;
        let head = {
            let guard = self
                .backend
                .inner
                .lock()
                .map_err(|_| err_execution("lock poisoned"))?;
            sel.resolve(guard.head_height()).unwrap_or(0)
        };
        if let Some(sim) = &self.backend.simulator {
            let (out, _) = sim(&call, head).map_err(err_execution)?;
            return Ok(format_bytes_hex(&out));
        }
        Ok("0x".into())
    }

    async fn eth_estimate_gas(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(block.as_deref()).map_err(err_invalid_params)?;
        let input = call.decoded_input().map_err(err_invalid_params)?;
        let head = {
            let guard = self
                .backend
                .inner
                .lock()
                .map_err(|_| err_execution("lock poisoned"))?;
            sel.resolve(guard.head_height()).unwrap_or(0)
        };
        if let Some(sim) = &self.backend.simulator {
            let (_, gas_used) = sim(&call, head).map_err(err_execution)?;
            return Ok(format_u64_hex(gas_used.max(21_000)));
        }
        // Standard intrinsic gas baseline (21_000 call or 53_000 deploy + calldata bytes).
        let base: u64 = if call.to.is_some() { 21_000 } else { 53_000 };
        let calldata_cost = input
            .iter()
            .fold(0u64, |acc, &b| acc.saturating_add(if b == 0 { 4 } else { 16 }));
        Ok(format_u64_hex(base.saturating_add(calldata_cost)))
    }

    async fn eth_create_access_list(
        &self,
        call: EthCallObject,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let gas_hex = self.eth_estimate_gas(call, block).await?;
        Ok(serde_json::json!({
            "accessList": [],
            "gasUsed": gas_hex,
        }))
    }

    async fn eth_gas_price(&self) -> Result<String, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(format_u128_hex(
            guard.base_fee_wei.saturating_add(guard.priority_fee_wei),
        ))
    }

    async fn eth_max_priority_fee_per_gas(&self) -> Result<String, ErrorObjectOwned> {
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(format_u128_hex(guard.priority_fee_wei))
    }

    async fn eth_fee_history(
        &self,
        block_count: serde_json::Value,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let count_raw = match &block_count {
            serde_json::Value::Number(n) => {
                n.as_u64().ok_or_else(|| err_invalid_params("bad blockCount"))?
            }
            serde_json::Value::String(s) => parse_quantity_u64(s).map_err(err_invalid_params)?,
            _ => return Err(err_invalid_params("blockCount must be quantity or integer")),
        };
        if count_raw == 0 || count_raw > 1_024 {
            return Err(err_invalid_params("blockCount must be between 1 and 1024"));
        }
        let newest_sel = BlockSelector::parse_opt(Some(&newest_block)).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let head = guard.head_height();
        let end_h = newest_sel.resolve(head).unwrap_or(head);
        let span = count_raw.min(end_h.saturating_add(1));
        let oldest_h = end_h.saturating_add(1).saturating_sub(span);

        let mut base_fees = Vec::with_capacity((span as usize) + 1);
        let mut ratios = Vec::with_capacity(span as usize);
        let mut rewards = Vec::new();
        let pct_len = reward_percentiles.as_ref().map_or(0, Vec::len);

        for h in oldest_h..=end_h {
            if let Some(blk) = guard.blocks_by_num.get(&h) {
                base_fees.push(format_u128_hex(blk.base_fee_per_gas_wei));
                let ratio = if blk.gas_limit == 0 {
                    0.0
                } else {
                    (blk.gas_used as f64) / (blk.gas_limit as f64)
                };
                ratios.push(ratio);
            } else {
                base_fees.push(format_u128_hex(guard.base_fee_wei));
                ratios.push(0.0);
            }
            if pct_len > 0 {
                rewards.push(vec![format_u128_hex(guard.priority_fee_wei); pct_len]);
            }
        }
        // EIP-1559 feeHistory includes next block's baseFeePerGas as the N+1th element.
        base_fees.push(format_u128_hex(guard.base_fee_wei));

        Ok(serde_json::json!({
            "oldestBlock": format_u64_hex(oldest_h),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": ratios,
            "reward": rewards,
        }))
    }

    async fn eth_send_raw_transaction(&self, raw_tx: String) -> Result<String, ErrorObjectOwned> {
        let clean = raw_tx
            .strip_prefix("0x")
            .or_else(|| raw_tx.strip_prefix("0X"))
            .unwrap_or(&raw_tx);
        let raw_bytes =
            hex::decode(clean).map_err(|e| err_invalid_params(format!("bad hex: {e}")))?;
        let tx_hash = {
            let mut guard = self
                .backend
                .inner
                .lock()
                .map_err(|_| err_execution("lock poisoned"))?;
            let chain_id = guard.chain_id;
            let decoded = decode_and_recover_eth_tx(&raw_bytes, chain_id)
                .map_err(|e| err_execution(e.to_string()))?;
            if guard.foreign_book.is_evm_alias_registered(&decoded.sender) {
                return Err(err_execution("sender collides with post-quantum local alias"));
            }
            let hash = decoded.tx_hash;
            guard.pending_raw_txs.push(decoded);
            hash
        };
        let _ = self.backend.pending_tx.send(tx_hash);
        Ok(format_bytes_hex(&tx_hash))
    }

    async fn eth_get_block_by_number(
        &self,
        block: String,
        full_txs: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(Some(&block)).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(h) = sel.resolve(guard.head_height()) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        if full_txs {
            let txs: Vec<EthStoredTx> = blk
                .tx_hashes
                .iter()
                .filter_map(|th| guard.txs_by_hash.get(th).cloned())
                .collect();
            Ok(blk.to_rpc_json(Some(&txs)))
        } else {
            Ok(blk.to_rpc_json(None))
        }
    }

    async fn eth_get_block_by_hash(
        &self,
        hash: String,
        full_txs: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let bh = parse_eth_word32(&hash, false).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(&h) = guard.block_num_by_hash.get(&bh) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        if full_txs {
            let txs: Vec<EthStoredTx> = blk
                .tx_hashes
                .iter()
                .filter_map(|th| guard.txs_by_hash.get(th).cloned())
                .collect();
            Ok(blk.to_rpc_json(Some(&txs)))
        } else {
            Ok(blk.to_rpc_json(None))
        }
    }

    async fn eth_get_block_tx_count_by_number(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(Some(&block)).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(h) = sel.resolve(guard.head_height()) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        Ok(serde_json::Value::String(format_u64_hex(
            blk.tx_hashes.len() as u64,
        )))
    }

    async fn eth_get_block_tx_count_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let bh = parse_eth_word32(&hash, false).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(&h) = guard.block_num_by_hash.get(&bh) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        Ok(serde_json::Value::String(format_u64_hex(
            blk.tx_hashes.len() as u64,
        )))
    }

    async fn eth_get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let th = parse_eth_word32(&hash, false).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(guard
            .txs_by_hash
            .get(&th)
            .map_or(serde_json::Value::Null, EthStoredTx::to_tx_json))
    }

    async fn eth_get_transaction_by_block_number_and_index(
        &self,
        block: String,
        index: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(Some(&block)).map_err(err_invalid_params)?;
        let idx = usize::try_from(parse_quantity_u64(&index).map_err(err_invalid_params)?)
            .map_err(|_| err_invalid_params("tx index overflow"))?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(h) = sel.resolve(guard.head_height()) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(th) = blk.tx_hashes.get(idx) else {
            return Ok(serde_json::Value::Null);
        };
        Ok(guard
            .txs_by_hash
            .get(th)
            .map_or(serde_json::Value::Null, EthStoredTx::to_tx_json))
    }

    async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let th = parse_eth_word32(&hash, false).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(guard
            .txs_by_hash
            .get(&th)
            .map_or(serde_json::Value::Null, EthStoredTx::to_receipt_json))
    }

    async fn eth_get_block_receipts(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let sel = BlockSelector::parse_opt(Some(&block)).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(h) = sel.resolve(guard.head_height()) else {
            return Ok(serde_json::Value::Null);
        };
        let Some(blk) = guard.blocks_by_num.get(&h) else {
            return Ok(serde_json::Value::Null);
        };
        let receipts: Vec<serde_json::Value> = blk
            .tx_hashes
            .iter()
            .filter_map(|th| guard.txs_by_hash.get(th).map(EthStoredTx::to_receipt_json))
            .collect();
        Ok(serde_json::Value::Array(receipts))
    }

    async fn eth_get_logs(
        &self,
        filter: RawEthFilter,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
        let parsed = ParsedLogFilter::from_raw(&filter).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Self::query_logs_in_inner(&guard, &parsed)
    }

    async fn eth_new_filter(
        &self,
        extensions: &Extensions,
        filter: RawEthFilter,
    ) -> Result<String, ErrorObjectOwned> {
        let peer = filter_owner(extensions)?;
        let mut guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let head = guard.head_height();
        let id = guard
            .filters
            .install_log_filter(&peer, &filter, head, now_epoch_ms())
            .map_err(err_filter)?;
        Ok(format_u128_hex(id))
    }

    async fn eth_new_block_filter(
        &self,
        extensions: &Extensions,
    ) -> Result<String, ErrorObjectOwned> {
        let peer = filter_owner(extensions)?;
        let mut guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let head = guard.head_height();
        let id = guard
            .filters
            .install_block_filter(&peer, head, now_epoch_ms())
            .map_err(err_filter)?;
        Ok(format_u128_hex(id))
    }

    async fn eth_get_filter_changes(
        &self,
        extensions: &Extensions,
        filter_id: String,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
        let peer = filter_owner(extensions)?;
        let id = parse_filter_id_u128(&filter_id)?;
        let mut guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let head = guard.head_height();
        let (kind, prev) = guard
            .filters
            .poll_filter(&peer, id, head, now_epoch_ms())
            .map_err(err_filter)?;
        if head <= prev {
            return Ok(Vec::new());
        }
        match kind {
            EthFilterKind::Blocks => {
                let mut hashes = Vec::new();
                for h in prev.saturating_add(1)..=head {
                    if let Some(blk) = guard.blocks_by_num.get(&h) {
                        hashes.push(serde_json::Value::String(format_bytes_hex(&blk.hash)));
                    }
                }
                Ok(hashes)
            }
            EthFilterKind::Logs(mut parsed) => {
                parsed.block_hash = None;
                parsed.from_block = BlockSelector::Number(prev.saturating_add(1));
                parsed.to_block = BlockSelector::Number(head);
                Self::query_logs_in_inner(&guard, &parsed)
            }
        }
    }

    async fn eth_get_filter_logs(
        &self,
        extensions: &Extensions,
        filter_id: String,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
        let peer = filter_owner(extensions)?;
        let id = parse_filter_id_u128(&filter_id)?;
        let mut guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let parsed = guard
            .filters
            .inspect_log_filter(&peer, id, now_epoch_ms())
            .map_err(err_filter)?;
        Self::query_logs_in_inner(&guard, &parsed)
    }

    async fn eth_uninstall_filter(
        &self,
        extensions: &Extensions,
        filter_id: String,
    ) -> Result<bool, ErrorObjectOwned> {
        let peer = filter_owner(extensions)?;
        let id = parse_filter_id_u128(&filter_id)?;
        let mut guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        Ok(guard.filters.uninstall(&peer, id, now_epoch_ms()))
    }

    async fn eth_accounts(&self) -> Result<Vec<String>, ErrorObjectOwned> {
        Ok(Vec::new())
    }

    async fn eth_get_proof(
        &self,
        _address: String,
        _storage_keys: Vec<String>,
        _block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Section 8.10 item 6: stateRoot is BDLM_UEL_ROOT_V1 sparse-Merkle execution_root,
        // NOT an Ethereum Patricia MPT root; eth_getProof returns -32601 at T-Genesis.
        Err(err_method_not_found(concat!(
            "Method not found: eth_getProof is unavailable; ",
            "stateRoot is BDLM_UEL_ROOT_V1 execution_root, use bud_getExecutionProof",
        )))
    }

    async fn debug_trace_transaction(
        &self,
        tx_hash: String,
        _opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("debug_traceTransaction")?;
        let th = parse_eth_word32(&tx_hash, false).map_err(err_invalid_params)?;
        let guard = self
            .backend
            .inner
            .lock()
            .map_err(|_| err_execution("lock poisoned"))?;
        let Some(tx) = guard.txs_by_hash.get(&th) else {
            return Err(err_execution("transaction not found"));
        };
        Ok(serde_json::json!({
            "gas": tx.gas_used,
            "failed": !tx.status_success,
            "returnValue": "",
            "structLogs": [],
        }))
    }

    async fn debug_trace_call(
        &self,
        call: EthCallObject,
        block: Option<String>,
        _opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.require_operator("debug_traceCall")?;
        let out_hex = self.eth_call(call.clone(), block.clone()).await?;
        let gas_hex = self.eth_estimate_gas(call, block).await?;
        let gas = parse_quantity_u64(&gas_hex).unwrap_or(21_000);
        Ok(serde_json::json!({
            "gas": gas,
            "failed": false,
            "returnValue": out_hex.strip_prefix("0x").unwrap_or(&out_hex),
            "structLogs": [],
        }))
    }

    async fn eth_subscribe(
        &self,
        pending: jsonrpsee::PendingSubscriptionSink,
        kind: String,
        filter: Option<RawEthFilter>,
    ) -> jsonrpsee::core::SubscriptionResult {
        enum EthFeed {
            NewHeads(broadcast::Receiver<EthBlockRecord>),
            Logs(broadcast::Receiver<EthLogEntry>, ParsedLogFilter),
            PendingTxs(broadcast::Receiver<[u8; 32]>),
        }

        let feed = match kind.as_str() {
            "newHeads" => EthFeed::NewHeads(self.backend.head_tx.subscribe()),
            "newPendingTransactions" => EthFeed::PendingTxs(self.backend.pending_tx.subscribe()),
            "logs" => {
                let raw = filter.unwrap_or_default();
                let parsed = match ParsedLogFilter::from_raw(&raw) {
                    Ok(p) => p,
                    Err(msg) => {
                        pending.reject(err_invalid_params(msg)).await;
                        return Ok(());
                    }
                };
                EthFeed::Logs(self.backend.log_tx.subscribe(), parsed)
            }
            other => {
                let msg = format!(
                    "unsupported eth_subscribe kind '{other}' (newHeads, logs, newPendingTransactions)"
                );
                pending.reject(err_invalid_params(msg)).await;
                return Ok(());
            }
        };

        let Some(permit) =
            try_acquire_sub_permit(&self.backend.active_subs, self.backend.max_subs)
        else {
            pending
                .reject(ErrorObjectOwned::owned(
                    JSONRPC_LIMIT_EXCEEDED,
                    "subscription limit reached",
                    None::<()>,
                ))
                .await;
            return Ok(());
        };

        let sink = pending.accept().await?;
        tokio::spawn(async move {
            let _permit = permit;
            match feed {
                EthFeed::NewHeads(mut rx) => loop {
                    tokio::select! {
                        () = sink.closed() => break,
                        item = rx.recv() => {
                            let Ok(blk) = item else { break; };
                            let json = blk.to_rpc_json(None);
                            if let Ok(raw) = serde_json::value::to_raw_value(&json) {
                                if sink.send(raw).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                },
                EthFeed::Logs(mut rx, pred) => loop {
                    tokio::select! {
                        () = sink.closed() => break,
                        item = rx.recv() => {
                            let Ok(log) = item else { break; };
                            if pred.matches_log(&log) {
                                let json = log.to_rpc_json();
                                if let Ok(raw) = serde_json::value::to_raw_value(&json) {
                                    if sink.send(raw).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                },
                EthFeed::PendingTxs(mut rx) => loop {
                    tokio::select! {
                        () = sink.closed() => break,
                        item = rx.recv() => {
                            let Ok(th) = item else { break; };
                            let s = serde_json::Value::String(format_bytes_hex(&th));
                            if let Ok(raw) = serde_json::value::to_raw_value(&s) {
                                if sink.send(raw).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                },
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_rpc_method_table_is_complete() {
        let backend = EthCompatBackend::new(&EthRpcConfig::default());
        let server = EthCompatServer::new_public(backend);
        let methods: Methods = server.into_rpc().into();

        check_served_eth_methods(methods.method_names()).unwrap();

        // Section 8.11.2 mandatory method checklist:
        let required = [
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
            "eth_getProof",
            "debug_traceTransaction",
            "debug_traceCall",
        ];
        for name in required {
            assert!(
                method_class::lookup_eth_method(name).is_some(),
                "missing classified method {name}"
            );
        }
        assert_eq!(ETH_METHOD_CLASSES.len(), required.len());
    }

    #[tokio::test]
    async fn eth_get_proof_returns_method_not_found() {
        let backend = EthCompatBackend::new(&EthRpcConfig::default());
        let pub_srv = EthCompatServer::new_public(backend.clone());
        let err = pub_srv
            .eth_get_proof("0x1111111111111111111111111111111111111111".into(), vec![], None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32601);
        assert!(err.message().contains("bud_getExecutionProof"));

        // debug_trace* refused on Public listener (-32601) and served on Operator listener.
        let trace_err = pub_srv
            .debug_trace_call(EthCallObject::default(), None, None)
            .await
            .unwrap_err();
        assert_eq!(trace_err.code(), -32601);

        let op_srv = EthCompatServer::new_operator(backend.clone());
        let trace_ok = op_srv
            .debug_trace_call(EthCallObject::default(), None, None)
            .await
            .unwrap();
        assert_eq!(trace_ok["failed"], serde_json::Value::Bool(false));

        // Block stateRoot carries UEL execution_root (0xeeee...ee in default genesis).
        let blk = pub_srv
            .eth_get_block_by_number("0x0".into(), false)
            .await
            .unwrap();
        assert_eq!(
            blk["stateRoot"],
            serde_json::Value::String(format!("0x{}", "ee".repeat(32)))
        );
    }

    #[test]
    fn filter_owner_comes_from_the_server_connection_extension() {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectionId(17));
        assert_eq!(filter_owner(&extensions).unwrap(), "connection:17");

        let no_connection = Extensions::new();
        assert!(filter_owner(&no_connection).is_err());
    }

    #[test]
    fn eth_filters_are_bounded() {
        let mut table = BoundedEthFilters::new(4, 2, 10_000);
        let raw = RawEthFilter::default();

        // Peer A hits per-peer quota at 2 even though global cap is 4.
        let f1 = table.install_log_filter("peer-a", &raw, 0, 1_000).unwrap();
        let _f2 = table.install_block_filter("peer-a", 0, 1_000).unwrap();
        assert_eq!(
            table.install_log_filter("peer-a", &raw, 0, 1_000),
            Err(FilterError::PeerQuotaReached {
                peer: "peer-a".into(),
                max: 2,
            })
        );

        // Peer B fills remaining 2 global slots; Peer C hits GlobalCapReached(4).
        let _f3 = table.install_block_filter("peer-b", 0, 1_000).unwrap();
        let _f4 = table.install_block_filter("peer-b", 0, 1_000).unwrap();
        assert_eq!(
            table.install_block_filter("peer-c", 0, 1_000),
            Err(FilterError::GlobalCapReached(4))
        );

        // A different connection cannot inspect, advance, or remove peer A's
        // filter, even when it knows the sequential filter id.
        assert_eq!(
            table.poll_filter("peer-b", f1, 5, 2_000),
            Err(FilterError::NotFound(f1))
        );
        assert_eq!(
            table.inspect_log_filter("peer-b", f1, 2_000),
            Err(FilterError::NotFound(f1))
        );
        assert!(!table.uninstall("peer-b", f1, 2_000));
        assert_eq!(table.len(), 4);

        // Refresh f1 at t = 8_000; advance to t = 12_000 so f2, f3, f4 expire (> 10_000ms idle)
        // while f1 remains live!
        let _ = table.poll_filter("peer-a", f1, 5, 8_000).unwrap();
        let c_id = table.install_block_filter("peer-c", 5, 12_000).unwrap();
        assert_eq!(table.len(), 2); // f1 + c_id
        assert!(table.uninstall("peer-c", c_id, 12_000));
        assert_eq!(table.len(), 1);
    }
}
