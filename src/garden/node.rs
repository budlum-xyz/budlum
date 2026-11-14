use crate::crypto::primitives::KeyPair;
use crate::domain::types::DomainStatus;
use crate::garden::consensus::GardenChainState;
use crate::garden::invite::GardenInvitePayload;
use crate::garden::settlement::GardenBudlumSettlement;
use crate::garden::storage::GardenStoredObject;
use crate::garden::types::{
    verify_garden_execution_chain, GardenBlock, GardenGenesis, GardenLimits, GardenTrace, GardenTx,
    GardenTxKind, GardenVote, SignedGardenTx,
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

/// Status snapshot returned by `bud_gardenStatus` and `GardenNode::status_snapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenStatusSnapshot {
    pub chain_id: u64,
    pub title: String,
    pub status: String,
    pub height: u64,
    pub current_round: u64,
    pub head_hash_hex: String,
    pub host_pubkey_hex: String,
    pub host_present: bool,
    pub active_validators: usize,
    pub message_count: usize,
    pub post_count: usize,
    pub image_count: usize,
    pub stored_object_count: usize,
    pub budlum_domain_id: Option<u32>,
    pub budlum_domain_status: Option<String>,
    pub budlum_anchored_height: Option<u64>,
    pub limits: GardenLimits,
}

/// Request/response wire protocol for separate-process Garden nodes over TCP.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "args")]
pub enum GardenPeerRequest {
    GetStatus,
    GetInvite,
    GetGenesis,
    GetBlock { height: u64 },
    ApplyBlock(GardenBlock),
    SignVote { block: GardenBlock },
    PublishTx(SignedGardenTx),
    ResolveContent { content_id_hex: String },
    QueryTrace { id_hex: String },
    LeaveNode,
    ReturnNode,
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GardenPeerResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub data: serde_json::Value,
}

impl GardenPeerResponse {
    fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: serde_json::Value::Null,
        }
    }
}

/// Local disk-backed Garden participant node.
///
/// Creating, joining, and leaving are node-local operations (Directive 4.9,
/// 6.22.2) that commit state transitions strictly inside PoA finalized blocks.
pub struct GardenNode {
    pub keypair: KeyPair,
    pub display_name: String,
    pub storage_root: Option<PathBuf>,
    pub state: Option<GardenChainState>,
    pub settlement: GardenBudlumSettlement,
    pub host_multiaddr: String,
    pub relay_multiaddrs: Vec<String>,
    pub next_tx_nonce: u64,
    pub rate_window_epoch: u64,
    pub rate_window_count: u32,
}

impl GardenNode {
    /// Create a fresh local node with an automatic ephemeral PoA identity
    /// (no pre-existing account or setup required per Directive 3.6).
    pub fn new(display_name: String, storage_root: Option<PathBuf>) -> Result<Self, String> {
        let keypair =
            KeyPair::generate().map_err(|e| format!("failed to generate Garden keypair: {e}"))?;
        Ok(Self {
            keypair,
            display_name,
            storage_root,
            state: None,
            settlement: GardenBudlumSettlement::new(),
            host_multiaddr: "/ip4/127.0.0.1/tcp/0".to_string(),
            relay_multiaddrs: Vec::new(),
            next_tx_nonce: 0,
            rate_window_epoch: 0,
            rate_window_count: 0,
        })
    }

    pub fn from_keypair(
        keypair: KeyPair,
        display_name: String,
        storage_root: Option<PathBuf>,
    ) -> Self {
        Self {
            keypair,
            display_name,
            storage_root,
            state: None,
            settlement: GardenBudlumSettlement::new(),
            host_multiaddr: "/ip4/127.0.0.1/tcp/0".to_string(),
            relay_multiaddrs: Vec::new(),
            next_tx_nonce: 0,
            rate_window_epoch: 0,
            rate_window_count: 0,
        }
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.keypair.public_key_bytes()
    }

    pub fn set_network_addrs(&mut self, host_multiaddr: String, relay_multiaddrs: Vec<String>) {
        self.host_multiaddr = host_multiaddr;
        self.relay_multiaddrs = relay_multiaddrs;
    }

    fn check_rate_limit(&mut self, limits: &GardenLimits) -> Result<(), String> {
        let current_epoch = self
            .state
            .as_ref()
            .map(|s| s.liveness.current_epoch)
            .unwrap_or(0);
        if current_epoch != self.rate_window_epoch {
            self.rate_window_epoch = current_epoch;
            self.rate_window_count = 0;
        }
        if self.rate_window_count >= limits.max_requests_per_window {
            return Err(format!(
                "garden node rate limit {} requests/window exceeded (TESTNET-DEFAULT)",
                limits.max_requests_per_window
            ));
        }
        self.rate_window_count = self.rate_window_count.saturating_add(1);
        Ok(())
    }

    /// Create a new Garden hosted by this node and register its sovereign PoA
    /// domain in Budlum's `ConsensusDomainRegistry`.
    pub fn create_garden(
        &mut self,
        title: String,
        created_unix_ms: u64,
        nonce: u64,
        limits: GardenLimits,
    ) -> Result<GardenInvitePayload, String> {
        if let Some(existing) = &self.state {
            if existing.status() != DomainStatus::Retired {
                return Err("node is already participating in an active or frozen Garden".into());
            }
        }
        let genesis = GardenGenesis::new(
            title,
            self.keypair.public_key_bytes(),
            created_unix_ms,
            nonce,
            limits,
        )?;
        let mut state = GardenChainState::new(
            genesis.clone(),
            self.display_name.clone(),
            self.storage_root.as_deref(),
        )?;
        let domain_id = self
            .settlement
            .register_garden_domain(&genesis, &[self.keypair.public_key_bytes()])?;
        state.budlum_domain_id = Some(domain_id);
        self.next_tx_nonce = 0;
        self.state = Some(state);

        GardenInvitePayload::from_genesis(
            &genesis,
            self.host_multiaddr.clone(),
            self.relay_multiaddrs.clone(),
        )
    }

    /// Initialize this node from an invite link/QR payload as a replica node
    /// ready to synchronize Genesis and blocks (node-local join preparation).
    pub fn init_from_invite(
        &mut self,
        invite: &GardenInvitePayload,
        genesis: GardenGenesis,
    ) -> Result<(), String> {
        invite.validate()?;
        genesis.verify()?;
        if genesis.chain_id.value() != invite.chain_id {
            return Err("genesis chain_id does not match invite".into());
        }
        if invite.genesis_hash_bytes()? != genesis.genesis_hash {
            return Err("genesis_hash does not match invite".into());
        }
        if invite.host_pubkey_bytes()? != genesis.host_pubkey {
            return Err("host_pubkey does not match invite".into());
        }
        let mut state = GardenChainState::new(
            genesis.clone(),
            "host".to_string(),
            self.storage_root.as_deref(),
        )?;
        let domain_id = self
            .settlement
            .register_garden_domain(&genesis, &[genesis.host_pubkey])?;
        state.budlum_domain_id = Some(domain_id);
        self.next_tx_nonce = 0;
        self.state = Some(state);
        Ok(())
    }

    pub fn invite_payload(&self) -> Result<GardenInvitePayload, String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| "node has no active Garden".to_string())?;
        GardenInvitePayload::from_genesis(
            &state.genesis,
            self.host_multiaddr.clone(),
            self.relay_multiaddrs.clone(),
        )
    }

    pub fn sign_tx(&mut self, chain_id: u64, kind: GardenTxKind) -> Result<SignedGardenTx, String> {
        verify_garden_execution_chain(chain_id)?;
        let limits = self
            .state
            .as_ref()
            .map(|s| s.genesis.limits.clone())
            .unwrap_or_default();
        self.check_rate_limit(&limits)?;
        let tx = GardenTx {
            chain_id,
            sender: self.keypair.public_key_bytes(),
            nonce: self.next_tx_nonce,
            kind,
        };
        let signed = tx.sign(&self.keypair)?;
        self.next_tx_nonce = self.next_tx_nonce.saturating_add(1);
        Ok(signed)
    }

    /// Sign a PoA vote on a candidate block received from the proposer.
    pub fn vote_on_block(&self, block: &GardenBlock) -> Result<GardenVote, String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| "node has no Garden state".to_string())?;
        if !state
            .liveness
            .is_active_validator(&self.keypair.public_key_bytes())
        {
            return Err("inactive or non-member node cannot vote on Garden blocks".into());
        }
        if block.chain_id != state.genesis.chain_id {
            return Err("candidate block chain_id mismatch".into());
        }
        Ok(GardenVote::sign(
            &self.keypair,
            block.chain_id,
            block.height,
            block.round,
            block.block_hash,
        ))
    }

    pub fn apply_finalized_block(&mut self, block: GardenBlock) -> Result<(), String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| "node has no Garden state".to_string())?;
        let prev_status = state.status();
        state.apply_finalized_block(block)?;
        let new_status = state.status();
        if new_status != prev_status {
            let chain_id = state.genesis.chain_id.value();
            self.settlement.sync_domain_status(chain_id, new_status)?;
        }
        if new_status == DomainStatus::Retired {
            state.store.wipe_all()?;
        }
        Ok(())
    }

    /// Explicitly check and wipe local node disk data if the Garden is Retired
    /// or if this node has departed and is no longer an active validator.
    pub fn leave_local_cleanup(&mut self) -> Result<(), String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| "node has no Garden state".to_string())?;
        let my_pk = self.keypair.public_key_bytes();
        if state.status() == DomainStatus::Retired || !state.liveness.is_active_validator(&my_pk) {
            state.store.wipe_all()?;
        }
        Ok(())
    }

    pub fn status_snapshot(&self) -> Result<GardenStatusSnapshot, String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| "node has no Garden state".to_string())?;
        let status_str = format!("{:?}", state.liveness.status);
        let budlum_status = self
            .settlement
            .budlum_domain_status(state.genesis.chain_id.value())
            .map(|s| format!("{:?}", s));
        Ok(GardenStatusSnapshot {
            chain_id: state.genesis.chain_id.value(),
            title: state.genesis.title.clone(),
            status: status_str,
            height: state.height,
            current_round: state.current_round,
            head_hash_hex: hex::encode(state.head_hash),
            host_pubkey_hex: hex::encode(state.genesis.host_pubkey),
            host_present: state.liveness.host_present,
            active_validators: state.liveness.active_validator_count(),
            message_count: state.messages.len(),
            post_count: state.posts.len(),
            image_count: state.images.len(),
            stored_object_count: state.store.object_count(),
            budlum_domain_id: state.budlum_domain_id,
            budlum_domain_status: budlum_status,
            budlum_anchored_height: state.last_anchored_budlum_height,
            limits: state.genesis.limits.clone(),
        })
    }

    pub fn resolve_content(&self, content_id_hex: &str) -> Result<GardenStoredObject, String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| "node has no Garden state".to_string())?;
        state.store.resolve_and_verify(content_id_hex)
    }

    pub fn query_trace(&self, id_hex: &str) -> Option<GardenTrace> {
        self.state
            .as_ref()
            .and_then(|s| s.query_trace_by_tx_or_content(id_hex))
    }

    pub fn storage_dir(&self) -> Option<PathBuf> {
        self.state
            .as_ref()
            .and_then(|s| s.store.storage_dir().map(Path::to_path_buf))
    }
}

/// Separate-process TCP server wrapping a `GardenNode` for real multi-process
/// tests (Directive Section 9).
pub struct GardenNodeServer {
    pub addr: SocketAddr,
    pub node: Arc<Mutex<GardenNode>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl GardenNodeServer {
    pub fn start(bind_addr: &str, mut node: GardenNode) -> Result<Self, String> {
        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| format!("failed to bind GardenNodeServer: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("failed to read GardenNodeServer local_addr: {e}"))?;
        node.set_network_addrs(
            format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()),
            node.relay_multiaddrs.clone(),
        );
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set nonblocking listener: {e}"))?;

        let shared = Arc::new(Mutex::new(node));
        let shutdown = Arc::new(AtomicBool::new(false));
        let shared_clone = Arc::clone(&shared);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_peer_stream(stream, &shared_clone, &shutdown_clone);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            node: shared,
            shutdown,
            handle: Some(handle),
        })
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Drop for GardenNodeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_peer_stream(
    mut stream: TcpStream,
    node: &Arc<Mutex<GardenNode>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("failed to clone tcp stream: {e}"))?,
    );
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read peer request: {e}"))?;
    if bytes == 0 {
        return Ok(());
    }
    let response = match serde_json::from_str::<GardenPeerRequest>(line.trim()) {
        Ok(req) => dispatch_peer_request(req, node, shutdown),
        Err(e) => GardenPeerResponse::err(format!("invalid GardenPeerRequest: {e}")),
    };
    let encoded = serde_json::to_string(&response)
        .map_err(|e| format!("failed to encode GardenPeerResponse: {e}"))?;
    stream
        .write_all(format!("{encoded}\n").as_bytes())
        .map_err(|e| format!("failed to write peer response: {e}"))?;
    let _ = stream.flush();
    Ok(())
}

fn dispatch_peer_request(
    req: GardenPeerRequest,
    node_arc: &Arc<Mutex<GardenNode>>,
    shutdown: &Arc<AtomicBool>,
) -> GardenPeerResponse {
    let Ok(mut node) = node_arc.lock() else {
        return GardenPeerResponse::err("garden node mutex poisoned");
    };
    match req {
        GardenPeerRequest::GetStatus => match node.status_snapshot() {
            Ok(snap) => match serde_json::to_value(snap) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            },
            Err(e) => GardenPeerResponse::err(e),
        },
        GardenPeerRequest::GetInvite => match node.invite_payload() {
            Ok(inv) => match serde_json::to_value(inv) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            },
            Err(e) => GardenPeerResponse::err(e),
        },
        GardenPeerRequest::GetGenesis => match node.state.as_ref().map(|s| s.genesis.clone()) {
            Some(g) => match serde_json::to_value(g) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            },
            None => GardenPeerResponse::err("node has no Garden genesis"),
        },
        GardenPeerRequest::GetBlock { height } => {
            let block = node
                .state
                .as_ref()
                .and_then(|s| s.blocks.iter().find(|b| b.height == height).cloned());
            match serde_json::to_value(block) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            }
        }
        GardenPeerRequest::ApplyBlock(block) => match node.apply_finalized_block(block) {
            Ok(()) => GardenPeerResponse::success(serde_json::json!({ "applied": true })),
            Err(e) => GardenPeerResponse::err(e),
        },
        GardenPeerRequest::SignVote { block } => match node.vote_on_block(&block) {
            Ok(vote) => match serde_json::to_value(vote) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            },
            Err(e) => GardenPeerResponse::err(e),
        },
        GardenPeerRequest::PublishTx(tx) => {
            let Some(state) = node.state.as_ref() else {
                return GardenPeerResponse::err("node has no Garden state");
            };
            match state.validate_tx(&tx) {
                Ok(()) => GardenPeerResponse::success(serde_json::json!({ "accepted": true })),
                Err(e) => GardenPeerResponse::err(e),
            }
        }
        GardenPeerRequest::ResolveContent { content_id_hex } => {
            match node.resolve_content(&content_id_hex) {
                Ok(obj) => match serde_json::to_value(obj) {
                    Ok(v) => GardenPeerResponse::success(v),
                    Err(e) => GardenPeerResponse::err(e.to_string()),
                },
                Err(e) => GardenPeerResponse::err(e),
            }
        }
        GardenPeerRequest::QueryTrace { id_hex } => match node.query_trace(&id_hex) {
            Some(trace) => match serde_json::to_value(trace) {
                Ok(v) => GardenPeerResponse::success(v),
                Err(e) => GardenPeerResponse::err(e.to_string()),
            },
            None => GardenPeerResponse::err("trace not found"),
        },
        GardenPeerRequest::LeaveNode => match node.leave_local_cleanup() {
            Ok(()) => GardenPeerResponse::success(serde_json::json!({ "cleaned": true })),
            Err(e) => GardenPeerResponse::err(e),
        },
        GardenPeerRequest::ReturnNode => {
            GardenPeerResponse::success(serde_json::json!({ "ready": true }))
        }
        GardenPeerRequest::Shutdown => {
            shutdown.store(true, Ordering::Relaxed);
            GardenPeerResponse::success(serde_json::json!({ "shutting_down": true }))
        }
    }
}

/// TCP client for talking to a separate-process `GardenNodeServer`.
pub struct GardenNodeClient;

impl GardenNodeClient {
    pub fn call(addr: SocketAddr, req: &GardenPeerRequest) -> Result<GardenPeerResponse, String> {
        Self::call_with_timeout(addr, req, std::time::Duration::from_secs(5))
    }

    fn call_with_timeout(
        addr: SocketAddr,
        req: &GardenPeerRequest,
        timeout: std::time::Duration,
    ) -> Result<GardenPeerResponse, String> {
        const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("failed to connect to Garden peer {addr}: {e}"))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("failed to set Garden peer read timeout: {e}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("failed to set Garden peer write timeout: {e}"))?;
        let encoded = serde_json::to_string(req)
            .map_err(|e| format!("failed to encode GardenPeerRequest: {e}"))?;
        stream
            .write_all(format!("{encoded}\n").as_bytes())
            .map_err(|e| format!("failed to send GardenPeerRequest: {e}"))?;
        let _ = stream.flush();

        let mut reader = BufReader::new(stream.take(MAX_RESPONSE_BYTES + 1));
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("failed to read GardenPeerResponse: {e}"))?;
        if (n as u64) > MAX_RESPONSE_BYTES {
            return Err("Garden peer response exceeded size limit".into());
        }
        let resp: GardenPeerResponse = serde_json::from_str(line.trim())
            .map_err(|e| format!("failed to decode GardenPeerResponse: {e}"))?;
        if resp.ok {
            Ok(resp)
        } else {
            Err(resp
                .error
                .unwrap_or_else(|| "unknown Garden peer error".into()))
        }
    }

    /// Connect using an invite payload, trying the direct host multiaddr first
    /// and falling back to advertised 7.11 relay multiaddrs when behind NAT.
    /// Returns `(response, used_relay)`.
    pub fn call_via_invite(
        invite: &GardenInvitePayload,
        req: &GardenPeerRequest,
    ) -> Result<(GardenPeerResponse, bool), String> {
        if let Some(direct) = invite.host_socket_addr() {
            if let Ok(resp) =
                Self::call_with_timeout(direct, req, std::time::Duration::from_millis(250))
            {
                return Ok((resp, false));
            }
        }
        let mut last_err = String::from("no reachable direct or relay address in invite");
        for relay in invite.relay_socket_addrs() {
            match Self::call_with_timeout(relay, req, std::time::Duration::from_secs(5)) {
                Ok(resp) => return Ok((resp, true)),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}
