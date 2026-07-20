use crate::network::protocol::NetworkMessage;
use libp2p::{
    futures::StreamExt,
    gossipsub, identify, identity,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    },
    mdns, noise, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// V117 fix (ARENAS): Maximum seconds a sync cycle may remain in
/// "syncing" state (sync_state == 1) before it is considered orphaned
/// and automatically reset. Prevents nodes from reporting stale
/// "syncing" status indefinitely when a peer disconnects mid-sync or
/// when gossipsub publish fails without a corresponding reset.
const SYNC_TIMEOUT_SECS: u64 = 60;

/// Phase 0.04 SECURITY FIX (Güvenlik Denetimi Madde 2):
/// SnapshotChunk mesajının `total` alanı için üst sınır. Saldırgan
/// `total = u32::MAX` göndererek alıcı node'u sınırsız bellek ayırmaya
/// zorlayabilir; bu da Rust'ın varsayılan abort davranışıyla süreci
/// çökertir (kimliksiz tek-paket DoS). 4096 chunk × 512KB/chunk = 2GB
/// tavanı, 36K satırlık codebase için makul (gerçek snapshot'lar ~10-50
/// chunk). Aşan SnapshotChunk'lar reddedilir (allocation yok, side effect
/// yok).
pub const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
/// Maximum number of concurrent in-flight snapshot assembly sessions
/// (Phase 0.10, security audit §2). Prevents a peer from forcing us to hold
/// unbounded `in_progress_snapshots` state by initiating many sessions.
pub const MAX_CONCURRENT_SNAPSHOTS: usize = 10;
/// Idle timeout for a snapshot assembly session: if no chunk arrives for
/// this many seconds the session is dropped, freeing the per-height
/// `Vec<Option<Vec<u8>>>` buffer.
pub const SNAPSHOT_SESSION_TIMEOUT_SECS: u64 = 60;

/// H5.1: extract IPv4 /24 key from a multiaddr (first 3 octets), if present.
pub fn ipv4_slash24(addr: &Multiaddr) -> Option<[u8; 3]> {
    for proto in addr.iter() {
        if let libp2p::multiaddr::Protocol::Ip4(ip) = proto {
            let o = ip.octets();
            return Some([o[0], o[1], o[2]]);
        }
    }
    None
}

#[derive(NetworkBehaviour)]
pub struct BudlumBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    gossipsub: gossipsub::Behaviour,
    kad: Kademlia<MemoryStore>,
    sync: request_response::Behaviour<crate::network::sync_codec::SyncCodec>,
    bitswap: request_response::Behaviour<bud_node::BitswapCodec>,
}
use crate::chain::chain_actor::ChainHandle;
use crate::chain::finality::{Precommit, Prevote};
use crate::network::peer_manager::PeerManager;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
#[allow(clippy::large_enum_variant)]
pub enum NodeCommand {
    Subscribe(String),
    Broadcast(String, NetworkMessage),
    BroadcastTx(crate::core::transaction::Transaction),
    ListPeers,
    /// F1 fix (ARENAX): Hard Pruning — physical deletion of B.U.D. content.
    /// Triggered ONLY by local Executor after verified NftBurn (SECURITY_AUDIT_HACKER.md).
    /// Payload is 32-byte ContentId (mirrors budlum_core::storage::content_id::ContentId and bud_node::store::ContentId).
    StoragePrune {
        cid: [u8; 32],
    },
}
#[derive(Clone)]
pub struct NodeClient {
    sender: mpsc::Sender<NodeCommand>,
    pub peer_id: PeerId,
    pub peer_count: Arc<AtomicUsize>,
    sync_state: Arc<AtomicUsize>,
    /// V117 fix (ARENAS): Timestamp (UNIX epoch secs) when sync_state was set to 1.
    /// Used to detect orphaned sync states and auto-reset after SYNC_TIMEOUT_SECS.
    sync_started_at: Arc<AtomicU64>,
}
impl NodeClient {
    pub async fn subscribe(&self, topic: String) {
        let _ = self.sender.send(NodeCommand::Subscribe(topic)).await;
    }
    pub async fn broadcast(&self, topic: String, msg: NetworkMessage) {
        let _ = self.sender.send(NodeCommand::Broadcast(topic, msg)).await;
    }
    pub async fn broadcast_tx(&self, tx: crate::core::transaction::Transaction) {
        let _ = self.sender.send(NodeCommand::BroadcastTx(tx)).await;
    }
    pub fn broadcast_tx_sync(&self, tx: crate::core::transaction::Transaction) {
        let _ = self.sender.try_send(NodeCommand::BroadcastTx(tx));
    }
    pub async fn list_peers(&self) {
        let _ = self.sender.send(NodeCommand::ListPeers).await;
    }
    pub fn is_syncing(&self) -> bool {
        self.sync_state.load(Ordering::SeqCst) == 1
    }
    pub fn broadcast_domain_commitment_sync(&self, commitment: crate::domain::DomainCommitment) {
        let _ = self.sender.try_send(NodeCommand::Broadcast(
            "blocks".into(),
            NetworkMessage::DomainCommitment(commitment),
        ));
    }
    pub fn broadcast_verified_domain_commitment_sync(
        &self,
        payload: crate::domain::VerifiedDomainCommitment,
    ) {
        let _ = self.sender.try_send(NodeCommand::Broadcast(
            "blocks".into(),
            NetworkMessage::VerifiedDomainCommitment(payload),
        ));
    }
    pub fn broadcast_cross_domain_message_sync(
        &self,
        msg: crate::cross_domain::CrossDomainMessage,
    ) {
        let _ = self.sender.try_send(NodeCommand::Broadcast(
            "blocks".into(),
            NetworkMessage::CrossDomainMessage(msg),
        ));
    }
    pub fn broadcast_slashing_evidence_sync(
        &self,
        evidence: crate::consensus::pos::SlashingEvidence,
    ) {
        let _ = self.sender.try_send(NodeCommand::Broadcast(
            "blocks".into(),
            NetworkMessage::SlashingEvidence(evidence),
        ));
    }

    /// F1: Trigger local hard prune of B.U.D. content (only via local executor, not P2P).
    pub fn storage_prune_sync(&self, cid: [u8; 32]) {
        let _ = self.sender.try_send(NodeCommand::StoragePrune { cid });
    }

    pub async fn storage_prune(&self, cid: [u8; 32]) {
        let _ = self.sender.send(NodeCommand::StoragePrune { cid }).await;
    }
}
#[tokio::test]
async fn test_node_creation() {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::ChainActor;
    use crate::consensus::pow::PoWEngine;
    let consensus = std::sync::Arc::new(PoWEngine::new(2));
    let blockchain = Blockchain::new(consensus, None, 1337, None);
    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(async move {
        chain_actor.run().await;
    });
    let node = Node::new(chain);
    assert!(node.is_ok());
}
pub const MAX_PEERS: usize = 50;
pub const DHT_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300);

pub fn load_or_generate_identity_key(path: Option<&str>) -> identity::Keypair {
    if let Some(p) = path {
        let file_path = std::path::Path::new(p);
        if file_path.exists() {
            match std::fs::read(file_path) {
                Ok(bytes) => {
                    if let Ok(keypair) = identity::Keypair::from_protobuf_encoding(&bytes) {
                        info!("Loaded persistent P2P identity from {}", p);
                        return keypair;
                    }
                    warn!("Failed to decode identity file {}, generating new key", p);
                }
                Err(e) => warn!("Cannot read identity file {}: {}, generating new key", p, e),
            }
        }
        let key = identity::Keypair::generate_ed25519();
        if let Some(parent) = file_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match key.to_protobuf_encoding() {
            Ok(encoded) => {
                if let Err(e) = std::fs::write(file_path, &encoded) {
                    warn!("Failed to save identity key to {}: {}", p, e);
                } else {
                    info!("Saved new P2P identity key to {}", p);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600));
                }
            }
            Err(e) => warn!("Failed to encode identity key: {}", e),
        }
        key
    } else {
        let key = identity::Keypair::generate_ed25519();
        info!("Generated ephemeral P2P identity (no identity file configured)");
        key
    }
}

pub fn resolve_dns_seeds(seeds: &[String], port: u16) -> Vec<String> {
    let mut addrs = Vec::new();
    for seed in seeds {
        let dns_host = format!("{}:{}", seed, if seed.contains(':') { 0 } else { port });
        match std::net::ToSocketAddrs::to_socket_addrs(&dns_host.as_str()) {
            Ok(socket_addrs) => {
                for sa in socket_addrs {
                    let multiaddr: String = match sa {
                        std::net::SocketAddr::V4(addr) => {
                            format!("/ip4/{}/tcp/{}", addr.ip(), addr.port())
                        }
                        std::net::SocketAddr::V6(addr) => {
                            format!("/ip6/{}/tcp/{}", addr.ip(), addr.port())
                        }
                    };
                    addrs.push(multiaddr);
                }
            }
            Err(e) => warn!("DNS seed resolution failed for {}: {}", seed, e),
        }
    }
    addrs
}

pub struct Node {
    swarm: Swarm<BudlumBehaviour>,
    command_rx: mpsc::Receiver<NodeCommand>,
    command_tx: mpsc::Sender<NodeCommand>,
    pub peer_id: PeerId,
    pub chain: ChainHandle,
    pub peer_manager: Arc<Mutex<PeerManager>>,
    pub bootstrap_peers: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub peer_count: Arc<AtomicUsize>,
    pub sync_state: Arc<AtomicUsize>,
    /// V117 fix (ARENAS): Timestamp when sync_state was set to 1.
    pub sync_started_at: Arc<AtomicU64>,
    #[allow(clippy::type_complexity)]
    pub in_progress_snapshots: HashMap<u64, (u64, Instant, Vec<Option<Vec<u8>>>)>,
    pub max_peers: usize,
    pub validator_address: Option<crate::core::address::Address>,
    pub last_precommit_height: u64,
    pub identity_path: Option<std::path::PathBuf>,
    pub banned_peer_db: Option<std::path::PathBuf>,
    pub mdns_enabled: bool,
    pub metrics: Option<Arc<crate::core::metrics::Metrics>>,
    pub storage_node: Option<Arc<bud_node::BudBitswap>>,
    pub shard_manager: Option<Arc<bud_node::ShardManager>>,
    pub mobile_mode: bool,
}

impl Node {
    pub fn new(chain: ChainHandle) -> Result<Self, Box<dyn Error>> {
        let local_key = identity::Keypair::generate_ed25519();
        Self::with_key(chain, local_key, true, None, None)
    }

    pub fn with_key(
        chain: ChainHandle,
        local_key: identity::Keypair,
        mdns_enabled: bool,
        storage_node: Option<Arc<bud_node::BudBitswap>>,
        sharding_config: Option<bud_node::ShardingConfig>,
    ) -> Result<Self, Box<dyn Error>> {
        let peer_id = PeerId::from(local_key.public());
        let mobile_mode = sharding_config
            .as_ref()
            .map(|c| c.mobile_mode)
            .unwrap_or(false);

        let shard_manager =
            sharding_config.map(|config| Arc::new(bud_node::ShardManager::new(peer_id, config)));
        info!(
            "Node ID: {} (mDNS: {}, Mobile: {})",
            peer_id, mdns_enabled, mobile_mode
        );
        // V114 fix (ARENAS): Replace DefaultHasher (64-bit, collision-prone) with
        // SHA-256 for gossipsub MessageId. The previous implementation used
        // `DefaultHasher::finish()` which returns u64 — birthday attack gives
        // collision probability at ~2^32 messages. SHA-256 eliminates this.
        let message_id_fn = |message: &gossipsub::Message| {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&message.data);
            gossipsub::MessageId::from(hex::encode(hash))
        };

        // ADIM 5 §5.2: Lightweight Gossipsub for mobile
        let mut gossipsub_config_builder = gossipsub::ConfigBuilder::default();
        if mobile_mode {
            gossipsub_config_builder
                .heartbeat_interval(Duration::from_secs(30)) // Less frequent heartbeats
                .history_length(3) // Smaller history
                .history_gossip(3);
        } else {
            gossipsub_config_builder.heartbeat_interval(Duration::from_secs(10));
        }

        let gossipsub_config = gossipsub_config_builder
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(crate::network::protocol::MAX_MESSAGE_SIZE)
            .build()
            .map_err(std::io::Error::other)?;
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;
                let kad_store = MemoryStore::new(key.public().to_peer_id());
                // ADIM 5 §5.2: Lightweight Kademlia for mobile
                let mut kad_config =
                    KademliaConfig::new(libp2p::StreamProtocol::new("/budlum/kad/1.0.0"));
                if mobile_mode {
                    kad_config.set_parallelism(std::num::NonZeroUsize::new(1).unwrap());
                    kad_config.set_publication_interval(Some(Duration::from_secs(24 * 3600)));
                }

                let kademlia =
                    Kademlia::with_config(key.public().to_peer_id(), kad_store, kad_config);
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/budlum/1.0.0".to_string(),
                    key.public(),
                ));
                let sync = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new("/budlum/sync/1.0.0"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );
                let bitswap = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new(bud_node::BITSWAP_PROTOCOL_NAME),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                Ok(BudlumBehaviour {
                    ping: ping::Behaviour::new(
                        ping::Config::new().with_interval(Duration::from_secs(15)),
                    ),
                    identify,
                    mdns,
                    gossipsub,
                    kad: kademlia,
                    sync,
                    bitswap,
                })
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let (command_tx, command_rx) = mpsc::channel(32);
        let peer_manager = Arc::new(Mutex::new(PeerManager::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let sync_state = Arc::new(AtomicUsize::new(0));
        let sync_started_at = Arc::new(AtomicU64::new(0));
        Ok(Node {
            swarm,
            peer_id,
            command_tx,
            command_rx,
            chain,
            peer_manager,
            bootstrap_peers: Vec::new(),
            dns_seeds: Vec::new(),
            peer_count,
            sync_state,
            sync_started_at,
            in_progress_snapshots: HashMap::new(),
            max_peers: if mobile_mode { 10 } else { MAX_PEERS },
            validator_address: None,
            last_precommit_height: 0,
            identity_path: None,
            banned_peer_db: None,
            mdns_enabled,
            metrics: None,
            storage_node,
            shard_manager,
            mobile_mode,
        })
    }

    /// Phase 0.10 (security audit §2): drop snapshot sessions that have been
    /// idle for longer than `SNAPSHOT_SESSION_TIMEOUT_SECS`. Prevents an
    /// attacker (or buggy peer) from accumulating per-height buffers
    /// forever by starting a session and then never completing it.
    pub fn sweep_stale_snapshot_sessions(&mut self) -> usize {
        let now = Instant::now();
        let before = self.in_progress_snapshots.len();
        self.in_progress_snapshots
            .retain(|_height, (_sid, ts, _buf)| {
                now.duration_since(*ts).as_secs() <= SNAPSHOT_SESSION_TIMEOUT_SECS
            });
        before - self.in_progress_snapshots.len()
    }

    /// Phase 0.10 (security audit §2): active session count — used by tests
    /// and by the new `MAX_CONCURRENT_SNAPSHOTS` enforcement.
    pub fn active_snapshot_sessions(&self) -> usize {
        self.in_progress_snapshots.len()
    }
    pub fn new_with_bootstrap(
        chain: ChainHandle,
        bootstrap_peers: Vec<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut node = Self::new(chain)?;
        node.bootstrap_peers = bootstrap_peers;
        Ok(node)
    }
    pub fn apply_network_security(&mut self, network: crate::core::chain_config::Network) {
        let security = network.security_config();
        self.max_peers = security.max_peers;
        self.mdns_enabled = security.mdns_enabled;
        // Phase 3 §3.4: wire peer_rate_limit_per_minute into PeerManager token bucket.
        if let Ok(mut pm) = self.peer_manager.lock() {
            pm.apply_security_config(security);
        }
        if security.persist_banned_peers && self.banned_peer_db.is_none() {
            self.banned_peer_db = Some(std::path::PathBuf::from(
                format!("./data/{:?}/banned-peers.json", network).to_lowercase(),
            ));
        }
    }

    pub fn with_identity(mut self, path: Option<String>) -> Self {
        self.identity_path = path.map(std::path::PathBuf::from);
        self
    }

    pub fn with_banned_peer_db(mut self, path: Option<String>) -> Self {
        self.banned_peer_db = path.map(std::path::PathBuf::from);
        self
    }

    pub fn with_dns_seeds(mut self, seeds: Vec<String>) -> Self {
        self.dns_seeds = seeds;
        self
    }

    pub fn with_bootstrap_peers(mut self, peers: Vec<String>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<crate::core::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    pub fn get_client(&self) -> NodeClient {
        NodeClient {
            sender: self.command_tx.clone(),
            peer_id: self.peer_id,
            peer_count: self.peer_count.clone(),
            sync_state: self.sync_state.clone(),
            sync_started_at: self.sync_started_at.clone(),
        }
    }
    pub fn listen(&mut self, port: u16) -> Result<(), Box<dyn Error>> {
        let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
        self.swarm.listen_on(addr)?;
        info!("Listening on port {}", port);
        Ok(())
    }
    pub fn dial(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let remote: Multiaddr = addr.parse()?;
        self.swarm.dial(remote)?;
        info!("Dialing {}", addr);
        Ok(())
    }
    pub fn bootstrap(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let multiaddr: Multiaddr = addr.parse()?;
        let peer_id = match multiaddr
            .iter()
            .find(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        {
            Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => peer_id,
            _ => return Err("Bootstrap address must contain /p2p/<ID>".into()),
        };
        info!("Bootstrapping via {}", addr);
        self.swarm
            .behaviour_mut()
            .kad
            .add_address(&peer_id, multiaddr);
        self.swarm.behaviour_mut().kad.bootstrap()?;
        Ok(())
    }
    fn load_banned_peers_from_db(&self) {
        let Some(ref db_path) = self.banned_peer_db else {
            return;
        };
        match std::fs::read_to_string(db_path) {
            Ok(data) => {
                // Phase 0.334 / A4: prefer absolute-expiry records; accept legacy
                // string-only lists for one-version migration.
                #[derive(serde::Deserialize)]
                struct BanListV2 {
                    banned_peers: Vec<crate::network::peer_manager::PersistedBan>,
                }
                #[derive(serde::Deserialize)]
                struct BanListLegacy {
                    banned_peers: Vec<String>,
                }

                if let Ok(list) = serde_json::from_str::<BanListV2>(&data) {
                    if !list.banned_peers.is_empty() {
                        if let Ok(mut pm) = self.peer_manager.lock() {
                            let n = list.banned_peers.len();
                            pm.reload_banned_peers(&list.banned_peers);
                            info!(
                                "Reloaded {} banned peers (with expiry) from {}",
                                n,
                                db_path.display()
                            );
                        }
                    }
                } else if let Ok(list) = serde_json::from_str::<BanListLegacy>(&data) {
                    if !list.banned_peers.is_empty() {
                        if let Ok(mut pm) = self.peer_manager.lock() {
                            let n = list.banned_peers.len();
                            pm.reload_banned_peers_legacy(&list.banned_peers);
                            info!(
                                "Reloaded {} banned peers (legacy full-window) from {}",
                                n,
                                db_path.display()
                            );
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Failed to read banned peer DB: {}", e);
                }
            }
        }
    }

    fn save_banned_peers_to_db(&self) {
        let Some(ref db_path) = self.banned_peer_db else {
            return;
        };
        let banned_peers = match self.peer_manager.lock() {
            Ok(pm) => pm.get_persisted_banned_peers(),
            Err(_) => return,
        };
        if banned_peers.is_empty() {
            return;
        }
        let json = serde_json::json!({ "banned_peers": banned_peers });
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
            // Phase 0.32: serializing an already-built serde_json::Value cannot fail
            // in practice, but log if it ever does instead of writing empty.
            let json_str = serde_json::to_string_pretty(&json).unwrap_or_else(|e| {
                warn!("Failed to serialize banned peers JSON: {}", e);
                String::new()
            });
            if let Err(e) = std::fs::write(db_path, json_str) {
                warn!("Failed to persist banned peers: {}", e);
            }
        }
    }

    pub async fn run(&mut self) {
        info!("Node running...");

        // Load durable banned peers
        self.load_banned_peers_from_db();

        // Bootstrap from configured peers
        for addr in self.bootstrap_peers.clone() {
            if let Err(e) = self.bootstrap(&addr) {
                warn!("Bootstrap dial failed for {}: {}", addr, e);
            }
        }

        // Resolve and dial DNS seeds
        if !self.dns_seeds.is_empty() {
            let dns_addrs = resolve_dns_seeds(&self.dns_seeds, 0);
            for addr in &dns_addrs {
                if let Err(e) = self.dial(addr) {
                    warn!("DNS seed dial failed for {}: {}", addr, e);
                }
            }
        }

        let mut gc_interval = tokio::time::interval(Duration::from_secs(60));
        let mut discovery_interval = tokio::time::interval(Duration::from_secs(300));
        let mut finality_interval = tokio::time::interval(Duration::from_secs(30));
        let mut slashing_gossip_interval = tokio::time::interval(Duration::from_secs(5));
        let mut dht_interval = tokio::time::interval(DHT_BOOTSTRAP_INTERVAL);
        let mut banning_interval = tokio::time::interval(Duration::from_secs(60));
        let mut ban_persist_interval = tokio::time::interval(Duration::from_secs(300));
        let mut storage_announce_interval = tokio::time::interval(if self.mobile_mode {
            Duration::from_secs(24 * 3600) // Daily on mobile
        } else {
            Duration::from_secs(3600) // Hourly on server
        });
        let mut storage_sharding_check_interval = tokio::time::interval(if self.mobile_mode {
            Duration::from_secs(3600) // Hourly on mobile
        } else {
            Duration::from_secs(600) // 10 mins on server
        });
        let mut last_voted_height: u64 = 0;

        loop {
            tokio::select! {
                _ = gc_interval.tick() => {
                    let removed = self.chain.cleanup_mempool().await;
                    if removed > 0 {
                        info!("Cleaned up {} expired transactions from mempool", removed);
                    }

                    let mut pm = self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); });
                    pm.cleanup_expired_bans();

                    // V117 fix (ARENAS): Auto-reset orphaned sync_state.
                    // If sync_state has been 1 for longer than SYNC_TIMEOUT_SECS,
                    // the sync cycle is considered stuck (e.g., peer disconnected
                    // mid-sync) and we reset it to 0 so the node reports correct
                    // status and can initiate a new sync.
                    if self.sync_state.load(Ordering::SeqCst) == 1 {
                        let started = self.sync_started_at.load(Ordering::SeqCst);
                        if started > 0 {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            if now.saturating_sub(started) > SYNC_TIMEOUT_SECS {
                                warn!(
                                    "Sync state stuck for {}s (timeout={}s), resetting to 0",
                                    now.saturating_sub(started),
                                    SYNC_TIMEOUT_SECS,
                                );
                                self.sync_state.store(0, Ordering::SeqCst);
                                self.sync_started_at.store(0, Ordering::SeqCst);
                            }
                        }
                    }
                }
                _ = discovery_interval.tick() => {
                    info!("Running periodic peer discovery...");
                    for addr in self.bootstrap_peers.clone() {
                        if let Err(e) = self.bootstrap(&addr) {
                            warn!("Periodic bootstrap failed for {}: {}", addr, e);
                        }
                    }
                }
                _ = finality_interval.tick() => {
                    // Resolve validator address lazily
                    if self.validator_address.is_none() {
                        self.validator_address = self.chain.get_validator_address().await;
                    }

                    let Some(voter_addr) = self.validator_address else {
                        continue;
                    };

                    let height = self.chain.get_height().await;
                    let checkpoint_interval = crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
                    let checkpoint_height = (height / checkpoint_interval) * checkpoint_interval;

                    // --- Check aggregator state for auto-precommit ---
                    let agg_state = self.chain.get_aggregator_state().await;
                    if agg_state.active
                        && agg_state.prevote_quorum_reached
                        && !agg_state.precommit_quorum_reached
                        && checkpoint_height > self.last_precommit_height
                    {
                        match self.chain.sign_precommit(
                            agg_state.epoch,
                            agg_state.checkpoint_height,
                            agg_state.checkpoint_hash.clone(),
                            voter_addr,
                        ).await {
                            Ok(precommit) => {
                                info!(
                                    "Finality: auto-precommit for checkpoint height {} (epoch {})",
                                    agg_state.checkpoint_height, agg_state.epoch
                                );
                                let vote_msg = NetworkMessage::Precommit {
                                    epoch: precommit.epoch,
                                    checkpoint_height: precommit.checkpoint_height,
                                    checkpoint_hash: precommit.checkpoint_hash,
                                    voter_id: voter_addr.to_hex(),
                                    sig_bls: precommit.sig_bls,
                                };
                                let topic = gossipsub::IdentTopic::new("blocks");
                                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, vote_msg.to_bytes());
                                self.last_precommit_height = agg_state.checkpoint_height;
                            }
                            Err(e) => {
                                warn!("Failed to sign precommit: {}", e);
                            }
                        }
                    }

                    // --- Periodic prevote ---
                    if checkpoint_height > 0 && checkpoint_height > last_voted_height {
                        if let Some(block) = self.chain.get_block(checkpoint_height).await {
                            let epoch = checkpoint_height / checkpoint_interval;
                            match self.chain.sign_prevote(
                                epoch,
                                checkpoint_height,
                                block.hash.clone(),
                                voter_addr,
                            ).await {
                                Ok(prevote) => {
                                    info!(
                                        "Finality: voting for checkpoint height {} (epoch {})",
                                        checkpoint_height, epoch
                                    );
                                    let vote_msg = NetworkMessage::Prevote {
                                        epoch: prevote.epoch,
                                        checkpoint_height: prevote.checkpoint_height,
                                        checkpoint_hash: prevote.checkpoint_hash,
                                        voter_id: voter_addr.to_hex(),
                                        sig_bls: prevote.sig_bls,
                                    };
                                    let topic = gossipsub::IdentTopic::new("blocks");
                                    let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, vote_msg.to_bytes());
                                    last_voted_height = checkpoint_height;
                                }
                                Err(e) => {
                                    warn!("Failed to sign prevote: {}", e);
                                }
                            }
                        }
                    }
                }
                _ = slashing_gossip_interval.tick() => {
                    for evidence in self.chain.drain_slashing_evidence().await {
                        let topic = gossipsub::IdentTopic::new("blocks");
                        let msg = NetworkMessage::SlashingEvidence(evidence);
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, msg.to_bytes()) {
                            warn!("Failed to gossip slashing evidence: {}", e);
                        }
                    }
                }
                _ = dht_interval.tick() => {
                    info!("Running periodic DHT bootstrapping...");
                    let _ = self.swarm.behaviour_mut().kad.bootstrap();
                }
                _ = storage_announce_interval.tick() => {
                    if let Some(ref bitswap) = self.storage_node {
                        #[allow(clippy::single_match)]
                        let cids = bitswap.store().list_cids();
                        info!("Storage: Announcing {} local chunks to DHT...", cids.len());
                        for cid in cids {
                            let key = bud_node::ContentDiscovery::cid_to_key(&cid);
                            let _ = self.swarm.behaviour_mut().kad.start_providing(key);
                        }
                    }
                }
                _ = storage_sharding_check_interval.tick() => {
                    if let (Some(ref _bitswap), Some(ref _shard_manager)) = (&self.storage_node, &self.shard_manager) {
                        // This logic is for User Decision 5: mandatory_sharding.
                        // We check if there are deals near us that we aren't hosting.
                        // For now, we log the health.
                        info!("Storage: Running active sharding health check (XOR distance)...");
                        // Future improvement: proactively query DHT for near-CIDs.
                    }
                }
                _ = banning_interval.tick() => {
                    let banned_peers = {
                        match self.peer_manager.lock() {
                            Ok(pm) => pm.get_banned_peers(),
                            Err(e) => {
                                tracing::error!("PeerManager lock poisoned in banning task: {}", e);
                                Vec::new()
                            }
                        }
                    };
                    for peer_id in banned_peers {
                        warn!("Proactively disconnecting banned peer: {}", peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    }
                }
                _ = ban_persist_interval.tick() => {
                    self.save_banned_peers_to_db();
                }
                cmd = self.command_rx.recv() => {
                    if let Some(cmd) = cmd {
                        match cmd {
                            NodeCommand::Subscribe(topic) => {
                                let topic = gossipsub::IdentTopic::new(topic);
                                if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                                    warn!("Failed to subscribe: {}", e);
                                } else {
                                    info!("Subscribed to topic: {}", topic);
                                }
                            }
                            NodeCommand::Broadcast(topic, msg) => {
                                let topic = gossipsub::IdentTopic::new(topic);
                                let data = msg.to_bytes();
                                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                                    warn!("Failed to publish: {}", e);
                                } else {
                                    info!("Broadcasted to {}: {:?}", topic, msg);
                                }
                            }
                            NodeCommand::ListPeers => {
                                let peers: Vec<_> = self.swarm.behaviour().gossipsub.all_peers().collect();
                                info!("Connected peers: {:?}", peers.len());
                                for (peer, _topics) in peers {
                                    info!(" - {}", peer);
                                }
                            }
                            NodeCommand::BroadcastTx(tx) => {
                                let msg = NetworkMessage::Transaction(tx);
                                let topic = gossipsub::IdentTopic::new("transactions");
                                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, msg.to_bytes()) {
                                    warn!("Failed to gossip transaction: {}", e);
                                }
                            }
                            NodeCommand::StoragePrune { cid } => {
                                // F1 fix: Hard Pruning worker — physical deletion from local B.U.D. store.
                                // Only triggered by local Executor (not via P2P gossip), per SECURITY_AUDIT_HACKER.md.
                                if let Some(ref storage_node) = self.storage_node {
                                    let content_id = bud_node::store::ContentId(cid);
                                    match storage_node.store().delete(&content_id) {
                                        Ok(()) => {
                                            info!(
                                                cid = %hex::encode(cid),
                                                "B.U.D. hard prune executed: content physically deleted from local store (NftBurn)"
                                            );
                                        }
                                        Err(e) => {
                                            // Not found is not an error — content may have been pruned already or never stored locally
                                            tracing::debug!(
                                                cid = %hex::encode(cid),
                                                error = %e,
                                                "B.U.D. hard prune: content not found locally (already pruned or not stored)"
                                            );
                                        }
                                    }
                                } else {
                                    warn!(
                                        cid = %hex::encode(cid),
                                        "StoragePrune received but storage_node is None — no-op (node without B.U.D. storage)"
                                    );
                                }
                            }
                        }
                    }
                }
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            let remote = endpoint.get_remote_address();
                            let subnet = ipv4_slash24(remote);
                            // H5.1 eclipse bound before admitting.
                            let admit = self
                                .peer_manager
                                .lock()
                                .map(|pm| pm.can_admit_subnet(subnet))
                                .unwrap_or(true);
                            if !admit {
                                warn!(
                                    "Eclipse bound: rejecting {} from {:?} (/24 limit)",
                                    peer_id, subnet
                                );
                                let _ = self.swarm.disconnect_peer_id(peer_id);
                                continue;
                            }
                            let count = self.peer_count.fetch_add(1, Ordering::SeqCst) + 1;
                            if count > self.max_peers {
                                warn!("Max peers reached ({}/{}), disconnecting {}", count, self.max_peers, peer_id);
                                let _ = self.swarm.disconnect_peer_id(peer_id);
                                self.peer_count.fetch_sub(1, Ordering::SeqCst);
                                continue;
                            }
                            if let Ok(mut pm) = self.peer_manager.lock() {
                                pm.note_connected(peer_id, subnet);
                            }
                            if let Some(ref m) = self.metrics {
                                m.p2p_peers_connected.set(count as i64);
                            }
                            info!("Connected to {}, Peers: {}", peer_id, count);

                            let handshake = NetworkMessage::Handshake {
                                version_major: crate::core::encoding::PROTOCOL_VERSION_MAJOR,
                                version_minor: crate::core::encoding::PROTOCOL_VERSION_MINOR,
                                chain_id: self.chain.get_chain_id().await,
                                best_height: self.chain.get_height().await + 1,
                                validator_set_hash: self.chain.get_validator_set_hash().await,
                                supported_schemes: vec!["ED25519".to_string(), "BLS".to_string(), "DILITHIUM".to_string()],
                            };

                            let chain_len = self.chain.get_height().await + 1;
                            info!("DEBUG: Connected to {}, Chain length: {}, sending Handshake", peer_id, chain_len);

                            let topic = gossipsub::IdentTopic::new("blocks");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, handshake.to_bytes()) {
                                warn!("Failed to send Handshake: {}", e);
                            }

                            if self.chain.get_height().await == 0 {
                                if let Some(last_block) = self.chain.get_block(0).await {
                                    let locator = vec![last_block.hash];
                                    info!("New connection, requesting headers...");
                                    let topic = gossipsub::IdentTopic::new("blocks");
                                    let msg = NetworkMessage::GetHeaders {
                                        locator,
                                        limit: 2000,
                                    };
                                    self.sync_state.store(1, Ordering::SeqCst);
                                    self.sync_started_at.store(
                                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        Ordering::SeqCst,
                                    );
                                    if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, msg.to_bytes()) {
                                        warn!("Failed to request headers: {}", e);
                                        self.sync_state.store(0, Ordering::SeqCst);
                                        self.sync_started_at.store(0, Ordering::SeqCst);
                                    }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            if let Ok(mut pm) = self.peer_manager.lock() {
                                pm.note_disconnected(&peer_id);
                            }
                            self.peer_count.fetch_sub(1, Ordering::SeqCst);
                            if let Some(ref m) = self.metrics {
                                m.p2p_peers_connected.set(self.peer_count.load(Ordering::SeqCst) as i64);
                            }
                            warn!("Disconnected from {}, Peers: {}", peer_id, self.peer_count.load(Ordering::SeqCst));
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Ping(_event)) => {
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Mdns(event)) => {
                            if !self.mdns_enabled {
                                continue;
                            }
                            match event {
                                mdns::Event::Discovered(peers) => {
                                    for (peer_id, addr) in peers {
                                        info!("mDNS discovered: {} at {}", peer_id, addr);
                                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                        if let Err(e) = self.swarm.dial(addr.clone()) {
                                            warn!("Failed to dial discovered peer: {}", e);
                                        }
                                    }
                                }
                                mdns::Event::Expired(peers) => {
                                    for (peer_id, _) in peers {
                                        info!("mDNS expired: {}", peer_id);
                                        self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source: peer_id,
                            message_id: id,
                            message,
                        })) => {

                            if let Ok(pm) = self.peer_manager.lock() {
                                if pm.is_banned(&peer_id) {
                                    warn!("Ignoring message from banned peer {}", peer_id);
                                    continue;
                                }
                            }

                            if !self.peer_manager.lock().map_or(false, |mut pm| pm.check_rate_limit(&peer_id)) {
                                warn!("Rate limit exceeded or lock error for peer {}", peer_id);
                                continue;
                            }

                            if let Some(ref m) = self.metrics {
                                m.p2p_messages_received.inc();
                            }

                            info!("Received from {}: id={}", peer_id, id);
                            match NetworkMessage::from_bytes_validated(&message.data) {
                                Ok(msg) => {
                                    let is_handshake_msg = matches!(
                                        msg,
                                        NetworkMessage::Handshake { .. } | NetworkMessage::HandshakeAck { .. }
                                    );

                                    let is_handshaked = self.peer_manager.lock()
                                        .map(|pm| pm.is_handshaked(&peer_id))
                                        .unwrap_or(false);

                                    if !is_handshake_msg && !is_handshaked {
                                        warn!("Peer {} sent {:?} before completing handshake, dropping.", peer_id, msg);

                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_invalid_tx(&peer_id);
                                        }
                                        continue;
                                    }

                                    match msg {
                                        NetworkMessage::Block(block) => {
                                        if let Some(metrics) = &self.metrics {
                                            if let Ok(now) = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                            {
                                                let observed_ms = now.as_millis().saturating_sub(block.timestamp);
                                                metrics
                                                    .block_propagation_seconds
                                                    .observe(observed_ms as f64 / 1_000.0);
                                            }
                                        }
                                        if let Err(e) = NetworkMessage::validate_block_size(&block) {
                                            warn!("Received oversized block from {}: {:?}", peer_id, e);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).report_oversized_message(&peer_id);
                                            continue;
                                        }
                                        info!("BLOCK: #{} Hash: {}...", block.index, &block.hash[..8.min(block.hash.len())]);
                                        let our_height = self.chain.get_height().await;
                                        if block.index == our_height + 1 {
                                            match self.chain.validate_and_add_block(block.clone()).await {
                                                Ok(pruned_cids) => {
                                                    info!("Added block #{} to local chain", block.index);
                                                    for cid in pruned_cids {
                                                        let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                    }
                                                    if let Ok(mut pm) = self.peer_manager.lock() {
                                                        pm.report_good_behavior(&peer_id);
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Block validation failed: {}", e);
                                                    if let Ok(mut pm) = self.peer_manager.lock() {
                                                        pm.report_invalid_block(&peer_id);
                                                    }
                                                }
                                            }
                                        } else if block.index <= our_height {
                                            if let Some(our_block) = self.chain.get_block(block.index).await {
                                                if our_block.hash != block.hash {
                                                    info!("Fork detected at height {} (ours: {}... theirs: {}...)", block.index, &our_block.hash[..8.min(our_block.hash.len())], &block.hash[..8.min(block.hash.len())]);

                                                    info!("Fork detected at height {} - initiating sync to resolve fork", block.index);
                                                    let locator = self.chain.get_locator().await;
                                                    let req = NetworkMessage::GetHeaders { locator, limit: 500 };
                                                    let topic = gossipsub::IdentTopic::new("blocks");
                                                    self.sync_state.store(1, Ordering::SeqCst);
                                                    self.sync_started_at.store(
                                                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                        Ordering::SeqCst,
                                                    );
                                                    let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes());
                                                }
                                            }
                                        } else {
                                            info!("Block #{} is ahead of our chain (height={}), requesting sync", block.index, our_height);
                                            let locator = self.chain.get_locator().await;
                                            let req = NetworkMessage::GetHeaders { locator, limit: 500 };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            self.sync_state.store(1, Ordering::SeqCst);
                                            self.sync_started_at.store(
                                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                Ordering::SeqCst,
                                            );
                                            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes());
                                        }
                                    }
                                    NetworkMessage::Transaction(tx) => {
                                        if let Err(e) = NetworkMessage::validate_tx_size(&tx) {
                                            warn!("Received oversized transaction from {}: {:?}", peer_id, e);
                                            if let Ok(mut pm) = self.peer_manager.lock() {
                                                pm.report_oversized_message(&peer_id);
                                            }
                                            continue;
                                        }
                                        info!("Broadcasted tx: {} from: {} to: {} amount: {}",
                            &tx.hash[..8], tx.from, tx.to, tx.amount);
                                        match self.chain.add_transaction(tx).await {
                                            Ok(_) => {
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to add transaction: {}", e);
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_invalid_tx(&peer_id);
                                                }
                                            }
                                        }
                                    }

                                    NetworkMessage::SlashingEvidence(evidence) => {
                                        match self.chain.submit_slashing_evidence(evidence.clone()).await {
                                            Ok(_) => {
                                                info!("Accepted slashing evidence from {}", peer_id);
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                                let topic = gossipsub::IdentTopic::new("blocks");
                                                let _ = self.swarm.behaviour_mut().gossipsub.publish(
                                                    topic,
                                                    NetworkMessage::SlashingEvidence(evidence).to_bytes(),
                                                );
                                            }
                                            Err(e) => {
                                                warn!("Rejected slashing evidence from {}: {}", peer_id, e);
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_invalid_block(&peer_id);
                                                }
                                            }
                                        }
                                    }

                                    NetworkMessage::GetHeaders { locator, limit } => {
                                        info!("GetHeaders request from {} (locator: {} hashes, limit: {})",
                                            peer_id, locator.len(), limit);

                                        let start_idx_opt = self.chain.find_common_height(locator).await;
                                        let start_idx = start_idx_opt.map_or(0, |i| i + 1) as usize;

                                        let height = self.chain.get_height().await + 1;
                                        let end_idx = (start_idx + limit as usize).min(height as usize);

                                        let mut headers = Vec::new();
                                        for h in start_idx..end_idx {
                                            if let Some(block) = self.chain.get_block(h as u64).await {
                                                headers.push(crate::core::block::BlockHeader::from_block(&block));
                                            }
                                        }

                                        info!("Sending {} headers to {}", headers.len(), peer_id);
                                        let response = NetworkMessage::Headers(headers);
                                        let topic = gossipsub::IdentTopic::new("blocks");
                                        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, response.to_bytes());
                                    }

                                    NetworkMessage::Headers(headers) => {
                                        if headers.len() > crate::network::protocol::MAX_HEADERS_PER_REQUEST as usize {
                                            if let Ok(mut pm) = self.peer_manager.lock() {
                                                pm.report_invalid_block(&peer_id);
                                            }
                                            continue;
                                        }
                                        if let Some(last_header) = headers.last() {
                                            let from = headers[0].index;
                                            let to = last_header.index;
                                            let req = NetworkMessage::GetBlocksRange { from, to };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes());
                                        }
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_good_behavior(&peer_id);
                                        }
                                    }

                                    NetworkMessage::GetBlocksRange { from, to } => {
                                        info!("GetBlocksRange request from {} ({}..{})", peer_id, from, to);
                                        let our_height = self.chain.get_height().await + 1;

                                        let from_idx = from as usize;
                                        let to_idx = (to as usize).min(our_height as usize);
                                        let max_blocks = crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS;
                                        let to_idx = to_idx.min(from_idx + max_blocks);

                                        if (from_idx as u64) < our_height {
                                            let mut blocks = Vec::new();
                                            for h in from_idx..to_idx {
                                                if let Some(block) = self.chain.get_block(h as u64).await {
                                                    blocks.push(block);
                                                }
                                            }
                                            info!("Sending {} blocks to {}", blocks.len(), peer_id);
                                            let response = NetworkMessage::Blocks(blocks);
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, response.to_bytes());
                                        }
                                    }

                                    NetworkMessage::Blocks(blocks) => {
                                        if blocks.len() > crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS {
                                            if let Ok(mut pm) = self.peer_manager.lock() {
                                                pm.report_invalid_block(&peer_id);
                                            }
                                            continue;
                                        }
                                        if !blocks.is_empty() {
                                            let start_idx = blocks[0].index;
                                            let our_block_at_start = self.chain.get_block(start_idx).await;
                                            if let Some(our_b) = our_block_at_start {
                                                if our_b.hash != blocks[0].hash {
                                                    let _ = self.chain.try_reorg(blocks.clone()).await;
                                                } else {
                                                    for block in blocks {
                                                        let h = self.chain.get_height().await;
                                                        if block.index == h + 1 {
                                                            if let Ok(pruned_cids) = self.chain.validate_and_add_block(block.clone()).await {
                                                                for cid in pruned_cids {
                                                                    let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                for block in blocks {
                                                    let h = self.chain.get_height().await;
                                                    if block.index == h + 1 {
                                                        if let Ok(pruned_cids) = self.chain.validate_and_add_block(block.clone()).await {
                                                            for cid in pruned_cids {
                                                                let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_good_behavior(&peer_id);
                                        }
                                    }

                                    NetworkMessage::NewTip { height, hash: _ } => {
                                        let our_height = self.chain.get_height().await;
                                        if height > our_height {
                                            let locator = self.chain.get_locator().await;
                                            let req = NetworkMessage::GetHeaders { locator, limit: 500 };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            self.sync_state.store(1, Ordering::SeqCst);
                                            self.sync_started_at.store(
                                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                Ordering::SeqCst,
                                            );
                                            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes());
                                        }
                                    }

                                    NetworkMessage::StateSnapshotResponse { height, state_root, ok } => {
                                        if ok {
                                            info!("Received StateSnapshotResponse: height={}, root={}", height, state_root);
                                        } else {
                                            warn!("Peer {} reported snapshot unavailable at height {}", peer_id, height);
                                        }
                                    }

                                    NetworkMessage::GetStateSnapshot { height } => {
                                        info!("GetStateSnapshot request from {} (height: {})", peer_id, height);
                                        // Phase 0.10 SECURITY FIX: cap concurrent snapshot sessions
                                        // and evict stale ones before recording this new request.
                                        // Without this, a peer can initiate many sessions and
                                        // grow `in_progress_snapshots` without bound (audit §2).
                                        if self.in_progress_snapshots.len() >= MAX_CONCURRENT_SNAPSHOTS {
                                            self.sweep_stale_snapshot_sessions();
                                            if self.in_progress_snapshots.len() >= MAX_CONCURRENT_SNAPSHOTS {
                                                warn!(
                                                    "Rejecting GetStateSnapshot from {} for height {}: max concurrent sessions ({}) reached",
                                                    peer_id, height, MAX_CONCURRENT_SNAPSHOTS
                                                );
                                                continue;
                                            }
                                        }
                                        let snapshot_opt = self.chain.get_state_snapshot_data(height).await;
                                        if let Some(snapshot) = snapshot_opt {
                                            let chunks = snapshot.chunk(512 * 1024); // 512KB chunks
                                            let total = chunks.len() as u32;
                                            let session_id = rand::random::<u64>();
                                            for (i, chunk_data) in chunks.into_iter().enumerate() {
                                                let chunk_msg = NetworkMessage::SnapshotChunk {
                                                    height,
                                                    index: i as u32,
                                                    total,
                                                    data: chunk_data,
                                                    session_id,
                                                };
                                                let topic = gossipsub::IdentTopic::new("blocks");
                                                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, chunk_msg.to_bytes());
                                            }
                                            info!("Sent {} snapshot chunks for height {} (session={})", total, height, session_id);
                                        } else {
                                            let response = NetworkMessage::StateSnapshotResponse { height, state_root: "".into(), ok: false };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, response.to_bytes());
                                        }
                                    }

                                    NetworkMessage::SnapshotChunk { height, index, total, data, session_id } => {
                                        info!("Received snapshot chunk {}/{} for height {} (session={})", index + 1, total, height, session_id);

                                        // === Phase 0.04 SECURITY FIX (Güvenlik Denetimi Madde 2) ===
                                        // Kimliksiz uzaktan DoS saldırısını önle:
                                        // (a) Üst sınır kontrolü: total > MAX_SNAPSHOT_CHUNKS ise reddet.
                                        //     Saldırgan `total = 4_294_967_295` göndererek node'u
                                        //     sınırsız bellek ayırmaya zorlayabilir; bu da Rust'ın
                                        //     varsayılan abort davranışıyla süreci çökertir.
                                        // (b) Aktif-talep filtresi: Bu node aktif olarak
                                        //     `GetStateSnapshot` istemediği bir height için gelen
                        //     SnapshotChunk'ı tamamen yoksay. (Önceki kodda
                                        //     `or_insert_with` ile yeni entry oluşturuluyordu,
                                        //     bu da herhangi bir peer'den gelen chunk'ı kabul
                                        //     ediyordu — saldırı yüzeyi açık.)
                                        if total > MAX_SNAPSHOT_CHUNKS {
                                            warn!(
                                                "Rejecting SnapshotChunk: total={} exceeds MAX_SNAPSHOT_CHUNKS={} for height {} (DoS protection)",
                                                total, MAX_SNAPSHOT_CHUNKS, height
                                            );
                                            continue;
                                        }
                                        if (index as usize) >= total as usize {
                                            warn!(
                                                "Rejecting SnapshotChunk: index={} >= total={} for height {}",
                                                index, total, height
                                            );
                                            continue;
                                        }

                                        // Aktif-talep kontrolü: Bu height için bir
                                        // `in_progress_snapshots` entry'si yoksa, bu node
                                        // bu snapshot'ı talep etmemiş demektir — unsolicited
                                        // chunk'ı yoksay (allocation yok, side effect yok).
                                        // Phase 0.10: Session'ı burada insert ediyoruz (eğer
                                        // yoksa), böylece alan tarafın GetStateSnapshot
                                        // request öncesi hand-shake'ine gerek kalmıyor —
                                        // ilk gelen chunk session'ı başlatır.
                                        let active_session = if let Some((s, ts, _)) = self.in_progress_snapshots.get(&height).cloned() {
                                            // Phase 0.10: timeout kontrolü — stale session'ı düşür
                                            if ts.elapsed().as_secs() > SNAPSHOT_SESSION_TIMEOUT_SECS {
                                                warn!(
                                                    "Evicting stale snapshot session for height {} (idle >{}s)",
                                                    height, SNAPSHOT_SESSION_TIMEOUT_SECS
                                                );
                                                self.in_progress_snapshots.remove(&height);
                                                // Insert a fresh one below.
                                                0u64
                                            } else {
                                                s
                                            }
                                        } else {
                                            // Phase 0.10: ilk kez gelen chunk — yeni session başlat
                                            // (max concurrent kontrolü yukarıda yapıldı).
                                            0u64
                                        };

                                        if active_session != 0 && active_session != session_id {
                                            warn!(
                                                "Rejecting snapshot chunk from stale session {} (current {}) for height {}",
                                                session_id, active_session, height
                                            );
                                            continue;
                                        }

                                        // Session yoksa veya stale ise, yenisini insert et.
                                        self.in_progress_snapshots.entry(height).or_insert_with(|| (session_id, Instant::now(), Vec::new()));

                                        // Güvenli: total üst sınırı zaten doğrulandı (max 4096).
                                        // Toplam allocation `total * chunk_size` ile sınırlı
                                        // (her chunk 512KB; 4096 * 512KB = 2GB) — bu DoS sınırı
                                        // güvenlik denetimi gereksinimini karşılar.
                                        // Phase 0.10: ayrıca bu height'ın session'ının son aktivite
                                        // zamanını da yenilememiz gerek (timeout reset).
                                        let (_, last_active, chunk_buf) = self
                                            .in_progress_snapshots
                                            .entry(height)
                                            .or_insert_with(|| (session_id, Instant::now(), Vec::new()));
                                        *last_active = Instant::now();
                                        // Vec'i tam boyuta genişlet (None ile doldur)
                                        if chunk_buf.len() < total as usize {
                                            chunk_buf.resize(total as usize, None);
                                        }
                                        chunk_buf[index as usize] = Some(data);

                                        if chunk_buf.iter().all(|c| c.is_some()) {
                                            info!("Snapshot reassembly complete for height {} (session={})", height, session_id);
                                            let mut full_data = Vec::new();
                                            for chunk_bytes in chunk_buf.drain(..).flatten() {
                                                full_data.extend(chunk_bytes);
                                            }
                                            self.in_progress_snapshots.remove(&height);

                                            match crate::chain::snapshot::StateSnapshot::from_bytes(&full_data) {
                                                Ok(snapshot) => {
                                                    let our_chain_id = self.chain.get_chain_id().await;
                                                    if snapshot.chain_id != our_chain_id {
                                                        warn!("Received snapshot with invalid chain_id: expected {}, got {}", our_chain_id, snapshot.chain_id);
                                                        continue;
                                                    }
                                                    let our_height = self.chain.get_height().await;
                                                    if snapshot.height < our_height.saturating_sub(100) {
                                                        warn!("Received snapshot for too old height: {}", snapshot.height);
                                                        continue;
                                                    }
                                                    info!("Applying snapshot at height {}", snapshot.height);
                                                    let chain = self.chain.clone();
                                                    tokio::spawn(async move {
                                                        if let Err(e) = chain.apply_snapshot(snapshot).await {
                                                            warn!("Failed to apply snapshot: {}", e);
                                                        }
                                                    });
                                                }
                                                Err(e) => warn!("Failed to parse reassembled snapshot: {}", e),
                                            }
                                        }
                                    }

                                    NetworkMessage::GetBlocksByHeight { from_height, to_height } => {
                                        info!("GetBlocksByHeight [{}, {}] from {}", from_height, to_height, peer_id);
                                        let mut blocks = Vec::new();
                                        for h in from_height..=to_height {
                                            if let Some(b) = self.chain.get_block(h).await {
                                                blocks.push(b);
                                                if blocks.len() >= crate::network::protocol::MAX_SNAP_BATCH as usize {
                                                    break;
                                                }
                                            } else {
                                                break;
                                            }
                                        }
                                        info!("Sending {} blocks by height to {}", blocks.len(), peer_id);
                                        let response = NetworkMessage::BlocksByHeight(blocks);
                                        let topic = gossipsub::IdentTopic::new("blocks");
                                        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, response.to_bytes());
                                    }

                                    NetworkMessage::BlocksByHeight(blocks) => {
                                        if blocks.len() > crate::network::protocol::MAX_SNAP_BATCH as usize {
                                            warn!("Too many snap-sync blocks from {}", peer_id);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).report_invalid_block(&peer_id);
                                            continue;
                                        }
                                        info!("Snap-sync: {} blocks from {}", blocks.len(), peer_id);
                                        for block in blocks {
                                            let h = self.chain.get_height().await;
                                            if block.index > h {
                                                match self.chain.validate_and_add_block(block.clone()).await {
                                                    Ok(pruned_cids) => {
                                                        info!("Snap-sync applied block #{}", block.index);
                                                        for cid in pruned_cids {
                                                            let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                        }
                                                    }
                                                    Err(e) => warn!("Snap-sync block #{} failed: {}", block.index, e),
                                                }
                                            }
                                        }
                                        self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).report_good_behavior(&peer_id);
                                    }

                                    NetworkMessage::Handshake { version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes } => {
                                        let my_chain_id = self.chain.get_chain_id().await;
                                        if chain_id != my_chain_id {
                                            warn!("Peer {} has wrong chain_id {} (expected {}). Banning.", peer_id, chain_id, my_chain_id);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).ban_peer(&peer_id);
                                            continue;
                                        }
                                        if !crate::core::encoding::is_compatible_version(version_major, version_minor) {
                                            warn!("Peer {} has incompatible protocol v{}.{}. Banning.", peer_id, version_major, version_minor);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).ban_peer(&peer_id);
                                            continue;
                                        }
                                        info!("Handshake from {}: v{}.{}, chain={}, height={}, val_set={}, schemes={:?}",
                                            peer_id, version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes);
                                        self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).set_handshaked(&peer_id, true);
                                        let our_height = self.chain.get_height().await;
                                        if best_height > our_height {
                                            let locator = self.chain.get_locator().await;
                                            let req = NetworkMessage::GetHeaders { locator, limit: 500 };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            self.sync_state.store(1, Ordering::SeqCst);
                                            self.sync_started_at.store(
                                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                Ordering::SeqCst,
                                            );
                                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes()) {
                                                warn!("Failed to request headers after handshake: {}", e);
                                                self.sync_state.store(0, Ordering::SeqCst);
                                                self.sync_started_at.store(0, Ordering::SeqCst);
                                            }
                                        }

                                        let response = NetworkMessage::HandshakeAck {
                                            version_major: crate::core::encoding::PROTOCOL_VERSION_MAJOR,
                                            version_minor: crate::core::encoding::PROTOCOL_VERSION_MINOR,
                                            chain_id: my_chain_id,
                                            best_height: self.chain.get_height().await + 1,
                                            validator_set_hash: self.chain.get_validator_set_hash().await,
                                            supported_schemes: vec!["ED25519".to_string(), "BLS".to_string(), "DILITHIUM".to_string()],
                                        };
                                        let topic = gossipsub::IdentTopic::new("blocks");
                                        let data = response.to_bytes();
                                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                            warn!("Failed to send HandshakeAck: {}", e);
                                        }
                                    }

                                    NetworkMessage::HandshakeAck { version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes } => {
                                        let my_chain_id = self.chain.get_chain_id().await;
                                        if chain_id != my_chain_id {
                                            warn!("Peer {} Ack with wrong chain_id {} (expected {}). Banning.", peer_id, chain_id, my_chain_id);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).ban_peer(&peer_id);
                                            continue;
                                        }
                                        if !crate::core::encoding::is_compatible_version(version_major, version_minor) {
                                            warn!("Peer {} Ack has incompatible protocol v{}.{}. Banning.", peer_id, version_major, version_minor);
                                            self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).ban_peer(&peer_id);
                                            continue;
                                        }
                                        info!("HandshakeAck from {}: v{}.{}, chain={}, height={}, val_set={}, schemes={:?}",
                                            peer_id, version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes);
                                        {
                                            let mut pm = self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); });
                                            pm.set_handshaked(&peer_id, true);
                                            pm.report_good_behavior(&peer_id);
                                        }
                                        let our_height = self.chain.get_height().await;
                                        if best_height > our_height {
                                            let locator = self.chain.get_locator().await;
                                            let req = NetworkMessage::GetHeaders { locator, limit: 500 };
                                            let topic = gossipsub::IdentTopic::new("blocks");
                                            self.sync_state.store(1, Ordering::SeqCst);
                                            self.sync_started_at.store(
                                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                Ordering::SeqCst,
                                            );
                                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes()) {
                                                warn!("Failed to request headers after handshake ack: {}", e);
                                                self.sync_state.store(0, Ordering::SeqCst);
                                                self.sync_started_at.store(0, Ordering::SeqCst);
                                            }
                                        }
                                    }

                                    NetworkMessage::Prevote { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_vote_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            warn!("Peer {} exceeded vote rate limit or lock error. Ignoring Prevote.", peer_id);
                                            continue;
                                        }
                                        info!("Prevote from {}: epoch={}, height={}, hash={}..., voter={}",
                                            peer_id, epoch, checkpoint_height, &checkpoint_hash[..16.min(checkpoint_hash.len())], voter_id);

                                        let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                            Ok(addr) => addr,
                                            Err(e) => {
                                                warn!("Invalid voter_id in Prevote: {}", e);
                                                continue;
                                            }
                                        };

                                        let prevote = Prevote {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            voter_id: voter_addr,
                                            sig_bls,
                                        };
                                        match self.chain.handle_prevote(prevote).await {
                                            Ok(_) => {
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Prevote from {} rejected: {}", peer_id, e);
                                            }
                                        }
                                    }

                                    NetworkMessage::Precommit { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_vote_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            warn!("Peer {} exceeded vote rate limit or lock error. Ignoring Precommit.", peer_id);
                                            continue;
                                        }
                                        info!("Precommit from {}: epoch={}, height={}, hash={}..., voter={}",
                                            peer_id, epoch, checkpoint_height, &checkpoint_hash[..16.min(checkpoint_hash.len())], voter_id);

                                        let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                            Ok(addr) => addr,
                                            Err(e) => {
                                                warn!("Invalid voter_id in Precommit: {}", e);
                                                continue;
                                            }
                                        };

                                        let precommit = Precommit {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            voter_id: voter_addr,
                                            sig_bls,
                                        };
                                        match self.chain.handle_precommit(precommit).await {
                                            Ok(Some(cert)) => {
                                                info!("FinalityCert produced from precommit: epoch={}, height={}", cert.epoch, cert.checkpoint_height);
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                                let topic = gossipsub::IdentTopic::new("blocks");
                                                let _ = self.swarm.behaviour_mut().gossipsub.publish(
                                                    topic,
                                                    NetworkMessage::FinalityCert {
                                                        epoch: cert.epoch,
                                                        checkpoint_height: cert.checkpoint_height,
                                                        checkpoint_hash: cert.checkpoint_hash,
                                                        agg_sig_bls: cert.agg_sig_bls,
                                                        bitmap: cert.bitmap,
                                                        set_hash: cert.set_hash,
                                                    }
                                                    .to_bytes(),
                                                );
                                            }
                                            Ok(None) => {
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Precommit from {} rejected: {}", peer_id, e);
                                            }
                                        }
                                    }

                                    NetworkMessage::FinalityCert { epoch, checkpoint_height, checkpoint_hash, agg_sig_bls, bitmap, set_hash } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_vote_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            warn!("Peer {} exceeded vote rate limit or lock error. Ignoring FinalityCert.", peer_id);
                                            continue;
                                        }
                                        info!("FinalityCert from {}: epoch={}, height={}, hash={}...",
                                            peer_id, epoch, checkpoint_height, &checkpoint_hash[..16.min(checkpoint_hash.len())]);

                                        let cert = crate::chain::finality::FinalityCert {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            agg_sig_bls,
                                            bitmap,
                                            set_hash,
                                        };

                                        match self.chain.handle_finality_cert(cert).await {
                                            Ok(_) => {
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_good_behavior(&peer_id);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to apply FinalityCert from {}: {}", peer_id, e);
                                                if e.contains("Missing verified QC blob") {
                                                    let topic = gossipsub::IdentTopic::new("blocks");
                                                    let req = NetworkMessage::GetQcBlob {
                                                        epoch,
                                                        checkpoint_height,
                                                    };
                                                    let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, req.to_bytes());
                                                } else if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_bad_behavior(&peer_id);
                                                }
                                            }
                                        }
                                    }

                                    NetworkMessage::GetQcBlob { epoch, checkpoint_height } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            continue;
                                        }
                                        info!("GetQcBlob from {}: epoch={}, height={}", peer_id, epoch, checkpoint_height);

                                        let blob = self.chain.get_qc_blob(checkpoint_height).await;
                                        let found = blob.is_some();
                                        let response = NetworkMessage::QcBlobResponse {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash: blob.as_ref().map(|b| b.checkpoint_hash.clone()).unwrap_or_default(),
                                            blob_data: blob.as_ref().map(|b| serde_json::to_vec(b).unwrap_or_else(|e| { tracing::error!("Failed to serialize QcBlob for response: {}", e); Vec::new() })).unwrap_or_default(),
                                            found,
                                        };
                                        let topic = gossipsub::IdentTopic::new("blocks");
                                        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, response.to_bytes());
                                    }

                                    NetworkMessage::QcBlobResponse { epoch, checkpoint_height, found, blob_data, .. } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_blob_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            warn!("Peer {} exceeded blob rate limit or lock error. Ignoring QcBlobResponse.", peer_id);
                                            continue;
                                        }
                                        info!("QcBlobResponse from {}: epoch={}, height={}, found={}",
                                            peer_id, epoch, checkpoint_height, found);

                                        if found {
                                            match serde_json::from_slice::<crate::consensus::qc::QcBlob>(&blob_data) {
                                                Ok(blob) => {
                                                    if blob.epoch != epoch || blob.checkpoint_height != checkpoint_height {
                                                        warn!(
                                                            "QcBlobResponse metadata mismatch from {}: expected epoch={}, height={}, got epoch={}, height={}",
                                                            peer_id,
                                                            epoch,
                                                            checkpoint_height,
                                                            blob.epoch,
                                                            blob.checkpoint_height
                                                        );
                                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                                            pm.report_bad_behavior(&peer_id);
                                                        }
                                                        continue;
                                                    }

                                                    match self.chain.import_qc_blob(blob).await {
                                                        Ok(_) => {
                                                            if let Ok(mut pm) = self.peer_manager.lock() {
                                                                pm.report_good_behavior(&peer_id);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to import QcBlob from {}: {}", peer_id, e);
                                                            if let Ok(mut pm) = self.peer_manager.lock() {
                                                                pm.report_bad_behavior(&peer_id);
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Failed to parse QcBlobResponse from {}: {}", peer_id, e);
                                                    if let Ok(mut pm) = self.peer_manager.lock() {
                                                        pm.report_bad_behavior(&peer_id);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    NetworkMessage::QcFaultProof { proof_data } => {
                                        let rate_limit_ok = self.peer_manager.lock()
                                            .map(|mut pm| pm.check_blob_rate_limit(&peer_id))
                                            .unwrap_or(false);
                                        if !rate_limit_ok {
                                            warn!("Peer {} exceeded blob rate limit or lock error. Ignoring QcFaultProof.", peer_id);
                                            continue;
                                        }

                                        match serde_json::from_slice::<crate::consensus::qc::QcFaultProof>(&proof_data) {
                                            Ok(proof) => {
                                                match self.chain.handle_qc_fault_proof(proof).await {
                                                    Ok(_) => {
                                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                                            pm.report_good_behavior(&peer_id);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to apply QcFaultProof from {}: {}", peer_id, e);
                                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                                            pm.report_bad_behavior(&peer_id);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to parse QcFaultProof from {}: {}", peer_id, e);
                                                if let Ok(mut pm) = self.peer_manager.lock() {
                                                    pm.report_bad_behavior(&peer_id);
                                                }
                                            }
                                        }
                                    }
                                    NetworkMessage::DomainCommitment(commitment) => {
                                        warn!(
                                            "Ignoring raw DomainCommitment from {} for domain {}; verified finality proof is required",
                                            peer_id, commitment.domain_id
                                        );
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_bad_behavior(&peer_id);
                                        }
                                    }
                                    NetworkMessage::VerifiedDomainCommitment(payload) => {
                                        info!(
                                            "Received VerifiedDomainCommitment from {} for domain {}",
                                            peer_id, payload.commitment.domain_id
                                        );
                                        let payload_clone = payload.clone();
                                        let chain = self.chain.clone();
                                        let swarm_cmd_tx = self.command_tx.clone();
                                        tokio::spawn(async move {
                                            match chain.submit_verified_domain_commitment(payload_clone.clone()).await {
                                                Ok(_) => {
                                                    let msg = NetworkMessage::VerifiedDomainCommitment(payload_clone);
                                                    let _ = swarm_cmd_tx.send(NodeCommand::Broadcast("blocks".into(), msg)).await;
                                                }
                                                Err(e) => {
                                                    warn!("Failed to process VerifiedDomainCommitment from {}: {}", peer_id, e);
                                                }
                                            }
                                        });
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_good_behavior(&peer_id);
                                        }
                                    }
                                    NetworkMessage::CrossDomainMessage(msg_obj) => {
                                        info!("Received CrossDomainMessage from {} for bridge", peer_id);
                                        let msg_clone = msg_obj.clone();
                                        let chain = self.chain.clone();
                                        let swarm_cmd_tx = self.command_tx.clone();
                                        tokio::spawn(async move {
                                            match chain.submit_relayed_cross_domain_message(msg_clone.clone()).await {
                                                Ok(_) => {
                                                    let msg = NetworkMessage::CrossDomainMessage(msg_clone);
                                                    let _ = swarm_cmd_tx.send(NodeCommand::Broadcast("blocks".into(), msg)).await;
                                                }
                                                Err(e) => {
                                                    warn!("Failed to process CrossDomainMessage from {}: {}", peer_id, e);
                                                }
                                            }
                                        });
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_good_behavior(&peer_id);
                                        }
                                    }
                                    NetworkMessage::GlobalHeader(header) => {
                                        info!(
                                            "GlobalHeader from {}: height={}, hash={}...",
                                            peer_id,
                                            header.global_height,
                                            &header.calculate_hash()[..16]
                                        );
                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                            pm.report_good_behavior(&peer_id);
                                        }
                                    }
                                }
                                }
                                Err(e) => {
                                    warn!("Computed invalid message from {}: {:?}", peer_id, e);

                                    self.peer_manager.lock().unwrap_or_else(|e| { tracing::error!("PeerManager lock poisoned: {}", e); std::process::exit(1); }).report_oversized_message(&peer_id);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                            info!("Received identity from {:?}", info.public_key.to_peer_id());
                            for addr in info.listen_addrs {
                                self.swarm.behaviour_mut().kad.add_address(&info.public_key.to_peer_id(), addr);
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Kad(KademliaEvent::RoutingUpdated { peer, .. })) => {
                            info!("Kademlia: Routing updated for peer {}", peer);
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Sync(event)) => {
                            match event {
                                request_response::Event::Message { peer, message, .. } => {
                                    match message {
                                        request_response::Message::Request { request, channel, .. } => {
                                            if let Ok(msg) = NetworkMessage::from_bytes(&request) {
                                                match msg {
                                                    NetworkMessage::GetHeaders { locator, limit } => {
                                                        let start_idx_opt = self.chain.find_common_height(locator).await;
                                                        let start_idx = start_idx_opt.map_or(0, |i| i + 1) as usize;
                                                        let height = self.chain.get_height().await + 1;
                                                        let end_idx = (start_idx + limit as usize).min(height as usize);

                                                        let mut headers = Vec::new();
                                                        for h in start_idx..end_idx {
                                                            if let Some(block) = self.chain.get_block(h as u64).await {
                                                                headers.push(crate::core::block::BlockHeader::from_block(&block));
                                                            }
                                                        }
                                                        let response = NetworkMessage::Headers(headers);
                                                        let _ = self.swarm.behaviour_mut().sync.send_response(channel, response.to_bytes());
                                                    }
                                                    NetworkMessage::GetBlocksRange { from, to } => {
                                                        let our_height = self.chain.get_height().await + 1;
                                                        let from_idx = from as usize;
                                                        let to_idx = (to as usize).min(our_height as usize);
                                                        let max_blocks = crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS;
                                                        let to_idx = to_idx.min(from_idx + max_blocks);

                                                        let mut blocks = Vec::new();
                                                        if (from_idx as u64) < our_height {
                                                            for h in from_idx..to_idx {
                                                                if let Some(block) = self.chain.get_block(h as u64).await {
                                                                    blocks.push(block);
                                                                }
                                                            }
                                                        }
                                                        let response = NetworkMessage::Blocks(blocks);
                                                        let _ = self.swarm.behaviour_mut().sync.send_response(channel, response.to_bytes());
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        request_response::Message::Response { response, .. } => {
                                            if let Ok(msg) = NetworkMessage::from_bytes(&response) {
                                                match msg {
                                                    NetworkMessage::Headers(headers) => {
                                                        if !headers.is_empty() {
                                                            let from = headers[0].index;
                                                            if let Some(last) = headers.last() {
                                                                let to = last.index;
                                                                let req = NetworkMessage::GetBlocksRange { from, to };
                                                                self.sync_state.store(1, Ordering::SeqCst);
                                                                self.sync_started_at.store(
                                                                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                                    Ordering::SeqCst,
                                                                );
                                                                let _ = self.swarm.behaviour_mut().sync.send_request(&peer, req.to_bytes());
                                                            }
                                                        }
                                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                                            pm.report_good_behavior(&peer);
                                                        }
                                                    }
                                                    NetworkMessage::Blocks(blocks) => {
                                                        if !blocks.is_empty() {
                                                            let start_idx = blocks[0].index;
                                                            let our_block = self.chain.get_block(start_idx).await;
                                                            if let Some(our_b) = our_block {
                                                                if our_b.hash != blocks[0].hash {
                                                                    let _ = self.chain.try_reorg(blocks).await;
                                                                } else {
                                                                    for block in blocks {
                                                                        let h = self.chain.get_height().await;
                                                                        if block.index == h + 1 {
                                                                            if let Ok(pruned_cids) = self.chain.validate_and_add_block(block).await {
                                                                                for cid in pruned_cids {
                                                                                    let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                for block in blocks {
                                                                    let h = self.chain.get_height().await;
                                                                    if block.index == h + 1 {
                                                                        if let Ok(pruned_cids) = self.chain.validate_and_add_block(block).await {
                                                                            for cid in pruned_cids {
                                                                                let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        self.sync_state.store(0, Ordering::SeqCst);
                                                        self.sync_started_at.store(0, Ordering::SeqCst);
                                                        if let Ok(mut pm) = self.peer_manager.lock() {
                                                            pm.report_good_behavior(&peer);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, error, .. } => {
                                    warn!("Outbound sync failure to {}: {:?}", peer, error);
                                    if let Ok(mut pm) = self.peer_manager.lock() {
                                        pm.report_timeout(&peer);
                                    }
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    warn!("Inbound sync failure from {}: {:?}", peer, error);
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Bitswap(event)) => {
                            if let Some(ref bitswap) = self.storage_node {
                                if let request_response::Event::Message { peer, message, .. } = event
                                {
                                    match message {
                                        request_response::Message::Request {
                                            request,
                                            channel,
                                            ..
                                        } => {
                                            let response = bitswap.handle_request(request);
                                            let _ = self
                                                .swarm
                                                .behaviour_mut()
                                                .bitswap
                                                .send_response(channel, response);
                                        }
                                        request_response::Message::Response { response, .. } => {
                                            if let Err(e) = bitswap.handle_response(response) {
                                                warn!(
                                                    "Bitswap response from {} failed: {}",
                                                    peer, e
                                                );
                                            } else if let Ok(mut pm) = self.peer_manager.lock() {
                                                pm.report_good_behavior(&peer);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
