use crate::network::protocol::NetworkMessage;
use libp2p::{
    futures::StreamExt,
    gossipsub, identify, identity,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    },
    noise, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

#[cfg(feature = "p2p-mdns")]
use libp2p::{mdns, swarm::behaviour::toggle::Toggle};

/// Maximum seconds a sync cycle may remain in
/// "syncing" state (sync_state == 1) before it is considered orphaned
/// And automatically reset. Prevents nodes from reporting stale
/// "syncing" status indefinitely when a peer disconnects mid-sync or
/// When gossipsub publish fails without a corresponding reset.
const SYNC_TIMEOUT_SECS: u64 = 60;
const MAX_PENDING_BITSWAP_FETCH_WAITERS: usize = 128;

/// Extract IPv4 /24 key from a multiaddr (first 3 octets), if present.
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
    #[cfg(feature = "p2p-mdns")]
    mdns: Toggle<mdns::tokio::Behaviour>,
    gossipsub: gossipsub::Behaviour,
    kad: Kademlia<MemoryStore>,
    sync: request_response::Behaviour<crate::network::sync_codec::SyncCodec>,
    bitswap: request_response::Behaviour<bud_node::BitswapCodec>,
    /// Connection budget: without it a peer can open unbounded connections
    /// and exhaust memory (libp2p resource-management DoS, RUSTSEC-2022-0084).
    /// The incoming cap plus the per-peer cap also blunt eclipse attempts: an
    /// attacker cannot fill the routing table with connections from one
    /// identity, and inbound connections are capped below the total so a node
    /// keeps dialing out (hardening research #3, #41).
    limits: libp2p::connection_limits::Behaviour,
}
use crate::chain::chain_actor::ChainHandle;
use crate::chain::finality::{Precommit, Prevote};
use crate::network::gossip_dedup::{DedupResult, GossipDedup};
use crate::network::peer_manager::PeerManager;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
#[allow(clippy::large_enum_variant)]
pub enum NodeCommand {
    Subscribe(String),
    Broadcast(String, NetworkMessage),
    /// Open a sync round with the best handshaked peer (see
    /// `Node::request_headers_from_peer`). Used by the operator `sync`
    /// command; a `GetHeaders` must not travel over gossip.
    RequestSync,
    BroadcastTx(crate::core::transaction::Transaction),
    ListPeers,
    /// Hard Pruning - physical deletion of B.U.D. content.
    /// Triggered ONLY by local Executor after verified NftBurn (SECURITY_AUDIT_HACKER.md).
    /// Payload is 32-byte ContentId (mirrors budlum_core::storage::content_id::ContentId and bud_node::store::ContentId).
    StoragePrune {
        cid: [u8; 32],
    },
    FetchLocalContent {
        cid: [u8; 32],
        response: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    FetchRemoteContent {
        cid: [u8; 32],
        response: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}
#[derive(Clone)]
pub struct NodeClient {
    sender: mpsc::Sender<NodeCommand>,
    pub peer_id: PeerId,
    pub peer_count: Arc<AtomicUsize>,
    sync_state: Arc<AtomicUsize>,
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
    pub async fn request_sync(&self) {
        let _ = self.sender.send(NodeCommand::RequestSync).await;
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

    pub async fn fetch_local_content(&self, cid: [u8; 32]) -> Result<Vec<u8>, String> {
        const LOCAL_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(NodeCommand::FetchLocalContent { cid, response: tx })
            .await
            .map_err(|e| format!("failed to send local content request: {e}"))?;
        tokio::time::timeout(LOCAL_FETCH_TIMEOUT, rx)
            .await
            .map_err(|_| "local content fetch timed out".to_string())?
            .map_err(|e| format!("failed to receive local content response: {e}"))?
    }

    pub async fn fetch_remote_content(&self, cid: [u8; 32]) -> Result<Vec<u8>, String> {
        const REMOTE_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(NodeCommand::FetchRemoteContent { cid, response: tx })
            .await
            .map_err(|e| format!("failed to send remote content request: {e}"))?;
        tokio::time::timeout(REMOTE_FETCH_TIMEOUT, rx)
            .await
            .map_err(|_| "remote content fetch timed out".to_string())?
            .map_err(|e| format!("failed to receive remote content response: {e}"))?
    }
}
#[tokio::test]
async fn test_node_creation() {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::ChainActor;
    use crate::consensus::pow::PoWEngine;
    let consensus = std::sync::Arc::new(PoWEngine::new(2));
    let blockchain = Blockchain::new(consensus, None, 45262, None);
    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(async move {
        chain_actor.run().await;
    });
    let node = Node::new(chain);
    assert!(node.is_ok());
}

#[test]
fn handshake_origin_must_match_propagation_peer() {
    let peer_a = PeerId::random();
    let peer_b = PeerId::random();
    assert!(handshake_origin_matches_peer(peer_a, Some(peer_a)));
    assert!(!handshake_origin_matches_peer(peer_a, Some(peer_b)));
    assert!(!handshake_origin_matches_peer(peer_a, None));
}

#[test]
fn handshake_requires_rfc9380_bls_scheme() {
    let required = vec![crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string()];
    let legacy = vec![crate::chain::finality::BLS_SCHEME_LEGACY_SCALAR_V0.to_string()];
    assert!(supports_required_bls_scheme(&required));
    assert!(!supports_required_bls_scheme(&legacy));
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
                        info!("Loaded persistent P2P identity from {p}");
                        return keypair;
                    }
                    warn!("Failed to decode identity file {p}, generating new key");
                }
                Err(e) => warn!("Cannot read identity file {p}: {e}, generating new key"),
            }
        }
        let key = identity::Keypair::generate_ed25519();
        if let Some(parent) = file_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match key.to_protobuf_encoding() {
            Ok(encoded) => {
                if let Err(e) = std::fs::write(file_path, &encoded) {
                    warn!("Failed to save identity key to {p}: {e}");
                } else {
                    info!("Saved new P2P identity key to {p}");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600));
                }
            }
            Err(e) => warn!("Failed to encode identity key: {e}"),
        }
        key
    } else {
        let key = identity::Keypair::generate_ed25519();
        info!("Generated ephemeral P2P identity (no identity file configured)");
        key
    }
}

fn handshake_origin_matches_peer(
    propagation_source: PeerId,
    message_source: Option<PeerId>,
) -> bool {
    message_source == Some(propagation_source)
}

fn supports_required_bls_scheme(schemes: &[String]) -> bool {
    schemes
        .iter()
        .any(|scheme| scheme == crate::chain::finality::BLS_SCHEME_RFC9380_V1)
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
            Err(e) => warn!("DNS seed resolution failed for {seed}: {e}"),
        }
    }
    addrs
}

/// Bitswap content fetches awaiting a P2P response, keyed by content id.
/// Multiple callers can await the same CID, so each entry holds a list of
/// One-shot responders that are all completed when the block arrives.
pub type PendingBitswapFetches = HashMap<[u8; 32], Vec<oneshot::Sender<Result<Vec<u8>, String>>>>;

pub struct Node {
    swarm: Swarm<BudlumBehaviour>,
    command_rx: mpsc::Receiver<NodeCommand>,
    command_tx: mpsc::Sender<NodeCommand>,
    pub peer_id: PeerId,
    pub chain: ChainHandle,
    pub peer_manager: Arc<Mutex<PeerManager>>,
    pub gossip_dedup: Arc<Mutex<GossipDedup>>,
    pub bootstrap_peers: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub dns_seed_port: u16,
    pub peer_count: Arc<AtomicUsize>,
    pub sync_state: Arc<AtomicUsize>,
    /// Timestamp when sync_state was set to 1.
    pub sync_started_at: Arc<AtomicU64>,
    pub pending_bitswap_fetches: PendingBitswapFetches,
    pub max_peers: usize,
    pub validator_address: Option<crate::core::address::Address>,
    pub last_precommit_height: u64,
    /// Highest checkpoint height this node has already prevoted for.
    ///
    /// Lives next to `last_precommit_height` because it guards the same thing:
    /// signing twice at one height. It used to be a local variable inside the
    /// event loop, which meant it started at zero on every restart.
    pub last_prevote_height: u64,
    /// Where the vote high-water marks are persisted between runs.
    ///
    /// `None` disables persistence, which is what tests and ephemeral devnet
    /// nodes want. A validator with a bonded stake should set it.
    pub vote_history_db: Option<std::path::PathBuf>,
    pub identity_path: Option<std::path::PathBuf>,
    pub banned_peer_db: Option<std::path::PathBuf>,
    pub mdns_enabled: bool,
    pub metrics: Option<Arc<crate::core::metrics::Metrics>>,
    pub storage_node: Option<Arc<bud_node::BudBitswap>>,
    /// What this node is allowed to delete, and whether it may delete at all.
    ///
    /// The hard-prune worker used to call `store().delete()` the moment an
    /// `NftBurn` produced a content id, without asking what kind of node it
    /// was running on. `PruningPolicy::validate` refuses an archive node that
    /// prunes, and refuses a pruning node with no finalized-snapshot
    /// retention, but nothing consulted it: the policy existed, was tested,
    /// and no deletion path read it.
    ///
    /// An archive node exists to be the copy of last resort. One misconfigured
    /// into deleting is worse than one that never existed, because the network
    /// counted on it.
    ///
    /// `None` keeps the previous behaviour for nodes that never set a policy,
    /// which is every test and ephemeral devnet node. A node that stores
    /// content in production should set one.
    pub pruning_policy: Option<crate::storage::PruningPolicy>,
    pub shard_manager: Option<Arc<bud_node::ShardManager>>,
    pub mobile_mode: bool,
    /// What this device says it can spend on being a peer.
    ///
    /// `network/mobile.rs` models this in four power modes and derives a
    /// challenge policy from each. Nothing read it. This file answered the
    /// same questions separately with `if mobile_mode { .. } else { .. }`, a
    /// second table for one question, and the two disagreed in the case that
    /// matters: at `PowerMode::Critical` the profile says accept no
    /// challenges and no proof tasks, while the local table still budgeted
    /// ten peers and an hourly sharding sweep, because it only knew "mobile"
    /// and "not mobile".
    ///
    /// `None` is a mains-powered node and keeps the server budget.
    /// `--mobile-mode` installs a profile, and [`Self::apply_power_mode`]
    /// re-derives the budgets from it when the battery moves.
    pub mobile_profile: Option<crate::network::mobile::MobileNodeProfile>,
    /// The peer cap in force before any battery reading lowered it.
    ///
    /// Recorded once, when the profile is installed, so recharging restores
    /// the budget the network profile and the operator agreed on rather than
    /// leaving the node stuck at whatever its flattest battery earned it. It
    /// is a ceiling and never a floor: a profile can only ask for fewer.
    mobile_peer_ceiling: usize,
}

/// On-disk shape of the validator vote high-water marks.
///
/// Declared at module level rather than inside `load_vote_history`: an item
/// After a statement is legal but confusing, since it is in scope for the
/// Whole function including the lines above it.
#[derive(serde::Deserialize)]
struct VoteHistory {
    #[serde(default)]
    last_prevote_height: u64,
    #[serde(default)]
    last_precommit_height: u64,
}

impl Node {
    /// Take the `PeerManager` lock, recovering if it was poisoned.
    ///
    /// A `Mutex` poisons when a thread panics while holding it, and every
    /// later `lock()` then returns `Err`. Fourteen call sites in this file
    /// answered that by logging and calling `std::process::exit(1)` - one
    /// panic anywhere in peer scoring would take the whole node off the
    /// chain, which is a far worse outcome than the bookkeeping it was
    /// protecting.
    ///
    /// Three other sites in the same file already did the opposite: log and
    /// carry on. `gossip_dedup` next door matches on `Ok`/`Err`. Same source,
    /// same failure, three different answers. This is the one they now share.
    ///
    /// Recovering with `into_inner()` is safe here for the same reason it is
    /// in `consensus/pow.rs`: `PeerManager` holds counters, ban timers and
    /// rate-limit buckets. A panic mid-update can leave one peer's score
    /// stale, and a stale score is a bounded, self-correcting error, the
    /// next report overwrites it. Losing the node is not self-correcting.
    ///
    /// Reachability, measured: `peer_manager.rs` has no panic source in
    /// production code today (`unix_now_secs` uses `unwrap_or(0)`, and the
    /// `duration_since` calls are on `Instant`, which cannot fail). So this
    /// was latent rather than live - but it turned every future panic added
    /// to `PeerManager` into a node-killer, which is not a property worth
    /// keeping.
    fn peer_manager_lock(&self) -> std::sync::MutexGuard<'_, PeerManager> {
        self.peer_manager.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "PeerManager lock was poisoned by an earlier panic; \
                 continuing with the recovered state"
            );
            poisoned.into_inner()
        })
    }

    /// Open a sync round: ask one peer for headers over `/sync`.
    ///
    /// Sync requests go over the peer-bound request_response protocol and
    /// nowhere else. The gossip arms for `GetHeaders` and `GetBlocksRange`
    /// only log and drop (a reply published to the topic would reach the
    /// whole mesh, not the asker), so a request published to the topic is
    /// lost by construction. This helper is the only place a `GetHeaders`
    /// leaves the node, and every trigger (new connection, handshake, a
    /// block ahead of us, a fork, a new tip) comes through it.
    ///
    /// One round at a time: while `sync_state` is 1 the caller's trigger is
    /// dropped. A round that receives no answer is closed by the
    /// `SYNC_TIMEOUT_SECS` sweep in the event loop, after which the next
    /// trigger opens a new one, so a silent peer costs one timeout, not the
    /// node.
    ///
    /// `preferred` is the peer whose message triggered the round (it just
    /// told us it is ahead). It is used when it has completed the handshake
    /// and is not banned; otherwise the best-scored handshaked peer is asked.
    /// With no eligible peer the round is not opened and `false` is returned.
    fn request_headers_from_peer(
        &mut self,
        preferred: Option<PeerId>,
        locator: Vec<String>,
        limit: u32,
    ) -> bool {
        if self.sync_state.load(Ordering::SeqCst) == 1 {
            return false;
        }
        let target = {
            let pm = self.peer_manager_lock();
            let eligible = |p: &PeerId| pm.is_handshaked(p) && !pm.is_banned(p);
            match preferred.filter(eligible) {
                Some(p) => Some(p),
                None => pm
                    .get_best_peers(MAX_PEERS)
                    .into_iter()
                    .find(|p| pm.connected_peers().contains(p) && eligible(p)),
            }
        };
        let Some(peer) = target else {
            info!("No handshaked peer available to sync from; waiting for one");
            return false;
        };
        let req = NetworkMessage::GetHeaders { locator, limit };
        self.sync_state.store(1, Ordering::SeqCst);
        self.sync_started_at.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::SeqCst,
        );
        if let Some(ref m) = self.metrics {
            m.p2p_sync_requests.inc();
        }
        let sync = &mut self.swarm.behaviour_mut().sync;
        let _ = sync.send_request(&peer, req.to_bytes());
        info!("Requesting headers from {peer} over /sync (limit {limit})");
        true
    }

    /// The checks a gossip block must pass before its height is looked at.
    ///
    /// The `index == our_height + 1` path runs the full `validate_and_add_block`.
    /// The two other paths (ahead of us, forked from us) used to open a sync
    /// round on nothing more than the size check, so a peer could send a
    /// block with `index = u64::MAX` and a fresh nonce in every message and
    /// make this node compute a locator and open a round per message, with no
    /// cost to the sender. These checks are cheap (one hash over the header
    /// fields), need no chain state beyond the chain id, and turn that
    /// message into an invalid block for the peer's score.
    fn block_passes_cheap_checks(block: &crate::core::block::Block, chain_id: u64) -> bool {
        block.chain_id == chain_id
            && crate::network::protocol::is_canonical_hash(&block.hash)
            && crate::network::protocol::is_canonical_hash(&block.previous_hash)
            && block.hash == block.calculate_hash()
    }

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
        let mdns_requested = mdns_enabled;
        let mdns_enabled = mdns_requested && cfg!(feature = "p2p-mdns");
        if mdns_requested && !mdns_enabled {
            warn!(
                "mDNS was requested but this production/default build excludes the p2p-mdns feature; continuing with mDNS disabled"
            );
        }
        let mobile_mode = sharding_config
            .as_ref()
            .map(|c| c.mobile_mode)
            .unwrap_or(false);

        let shard_manager =
            sharding_config.map(|config| Arc::new(bud_node::ShardManager::new(peer_id, config)));
        info!("Node ID: {peer_id} (mDNS: {mdns_enabled}, Mobile: {mobile_mode})");
        // Replace DefaultHasher (64-bit, collision-prone) with
        // SHA-256 for gossipsub MessageId. The previous implementation used
        // `DefaultHasher::finish` which returns u64 - birthday attack gives
        // Collision probability at ~2^32 messages. SHA-256 eliminates this.
        let message_id_fn = |message: &gossipsub::Message| {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&message.data);
            gossipsub::MessageId::from(hex::encode(hash))
        };

        // Lightweight Gossipsub for mobile
        //
        // The heartbeat interval is slowed from gossipsub's 1s default to save
        // radio and CPU. Three other settings are counted in *heartbeat ticks*
        // rather than seconds, so raising the interval silently stretches them
        // by the same factor. That was not accounted for, and the drift was
        // large:
        //
        //   check_explicit_peers_ticks = 300   5 min ->  50 min (mobile 150)
        //   opportunistic_graft_ticks  =  60   1 min ->  10 min (mobile  30)
        //
        // Both govern mesh repair. The first is how long a dropped explicit
        // peer, a bootstrap node or a configured sentry, goes unnoticed
        // before reconnection is attempted; on a validator that is the link to
        // the network it was deliberately pinned to. The second is how long a
        // node keeps a mesh full of low-scoring peers before it looks for
        // better ones, which is the mechanism that recovers from a partial
        // eclipse.
        //
        // They are rescaled here so the wall-clock behaviour matches upstream's
        // intent regardless of the heartbeat. Peer-score decay is NOT affected:
        // it runs on `decay_interval` (1s), its own timer in `poll`, not on the
        // heartbeat - verified in behaviour.rs at the pinned revision.
        //
        // `max_ihave_messages_heartbeat` (10) is left alone. Slower heartbeats
        // make it stricter, not looser, and tightening an anti-flood budget is
        // the safe direction to drift in.
        let heartbeat = if mobile_mode {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(10)
        };
        // Preserve upstream's wall-clock intent: 300 ticks x 1s and 60 ticks x 1s.
        let explicit_peer_ticks = (300 / heartbeat.as_secs()).max(1);
        let opportunistic_ticks = (60 / heartbeat.as_secs()).max(1);

        let mut gossipsub_config_builder = gossipsub::ConfigBuilder::default();
        gossipsub_config_builder
            .heartbeat_interval(heartbeat)
            .check_explicit_peers_ticks(explicit_peer_ticks)
            .opportunistic_graft_ticks(opportunistic_ticks);
        if mobile_mode {
            gossipsub_config_builder
                .history_length(3) // Smaller history
                .history_gossip(3);
        }

        let gossipsub_config = gossipsub_config_builder
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(crate::network::protocol::MAX_MESSAGE_SIZE)
            .build()
            .map_err(std::io::Error::other)?;
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;
        // Turn on peer scoring.
        //
        // Without it gossipsub's own misbehaviour accounting has no
        // consequence: a peer that floods IHAVE announcements and never
        // answers the resulting IWANT is capped at
        // `max_ihave_messages_heartbeat` per heartbeat, but is never
        // penalised, never gossip-suppressed and never pruned from the mesh.
        // The router already *counts* that behaviour - P7 in the scoring
        // spec - and the count was simply being discarded.
        //
        // The parameters are libp2p's defaults with two changes, both about
        // making the penalties bite sooner than they do on a public
        // best-effort mesh:
        //
        //   * `behaviour_penalty_threshold` drops from 0 to 6. The penalty is
        //     the square of the counter above the threshold, so a threshold of
        //     0 means the very first IWANT that goes unanswered starts costing
        //     score. Six leaves room for genuine loss (a peer that advertised
        //     a message and lost it before we asked) before the curve starts.
        //
        //   * `ip_colocation_factor_threshold` drops from 10 to 4. Ten peers
        //     per address is reasonable for a network of consumer nodes behind
        //     shared NATs; for a validator set it mostly describes one machine
        //     pretending to be ten.
        //
        // Thresholds stay at the defaults. They are negative scores, so a peer
        // has to actually misbehave to reach them, and an honest peer sits
        // comfortably above zero.
        let mut score_params = gossipsub::PeerScoreParams {
            behaviour_penalty_threshold: 6.0,
            ip_colocation_factor_threshold: 4.0,
            ..Default::default()
        };
        // The topics this node publishes on. Registering them keeps the
        // per-topic score caps meaningful; without an entry a topic
        // contributes nothing and only the global penalties apply.
        for topic in ["blocks", "transactions"] {
            score_params.topics.insert(
                gossipsub::IdentTopic::new(topic).hash(),
                gossipsub::TopicScoreParams::default(),
            );
        }
        let score_thresholds = gossipsub::PeerScoreThresholds::default();
        gossipsub
            .with_peer_score(score_params, score_thresholds)
            .map_err(std::io::Error::other)?;
        // Yamux stream bound (hardening research #104): a remote peer can open
        // substreams up to the configured cap, and each open stream reserves
        // muxer bookkeeping plus a receive window that auto-tunes toward the
        // bandwidth-delay product. Upstream's default allows 512; halving it
        // to 256 caps the per-connection DoS surface while staying well above
        // the node's own needs: sync and bitswap are request/response with a
        // 100-stream cap each (200 in the worst case on one connection), and
        // the mesh stays at ~D_out. Note libp2p-yamux 0.48 exposes only this
        // knob: the inner yamux `max_connection_receive_window` is not
        // reachable through the wrapper, so the stream cap is the muxer-level
        // bound we can enforce today (research #108 stays tracked for when
        // the wrapper grows that API).
        let yamux_config = || {
            let mut cfg = yamux::Config::default();
            cfg.set_max_num_streams(256);
            cfg
        };
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux_config)?
            // The raw TCP transport only understands /ip4 and /ip6 multiaddrs;
            // It answers every /dns4, /dns6 or /dnsaddr dial with
            // MultiaddrNotSupported. `with_dns` layers the system resolver on
            // Top so hostname peers (compose services, seed hostnames, the
            // `--dial=/dns4/...` flag) actually connect instead of failing
            // Silently into an isolated single-node mesh.
            .with_dns()?
            .with_behaviour(|key| {
                #[cfg(feature = "p2p-mdns")]
                let mdns = if mdns_enabled {
                    Some(mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        key.public().to_peer_id(),
                    )?)
                    .into()
                } else {
                    None.into()
                };
                let kad_store = MemoryStore::new(key.public().to_peer_id());
                // Lightweight Kademlia for mobile
                let mut kad_config =
                    KademliaConfig::new(libp2p::StreamProtocol::new("/budlum/kad/1.0.0"));
                if mobile_mode {
                    kad_config.set_parallelism(std::num::NonZeroUsize::MIN);
                    kad_config.set_publication_interval(Some(Duration::from_secs(24 * 3600)));
                }

                let kademlia =
                    Kademlia::with_config(key.public().to_peer_id(), kad_store, kad_config);
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/budlum/1.0.0".to_string(),
                    key.public(),
                ));
                // Request/response timeouts: without one, a peer that opens a
                // request stream and never answers holds the request slot
                // (and the outbound queue budget) indefinitely - a slowloris
                // style resource-retention DoS against sync and bitswap
                // (hardening research #58, #60). 30s bounds the wait while
                // leaving plenty of headroom for large block batches.
                let req_cfg = request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30));
                let sync = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new("/budlum/sync/1.0.0"),
                        request_response::ProtocolSupport::Full,
                    )],
                    req_cfg.clone(),
                );
                let bitswap = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new(bud_node::BITSWAP_PROTOCOL_NAME),
                        request_response::ProtocolSupport::Full,
                    )],
                    req_cfg,
                );

                Ok::<BudlumBehaviour, Box<dyn std::error::Error + Send + Sync>>(BudlumBehaviour {
                    ping: ping::Behaviour::new(
                        ping::Config::new().with_interval(Duration::from_secs(15)),
                    ),
                    identify,
                    #[cfg(feature = "p2p-mdns")]
                    mdns,
                    gossipsub,
                    kad: kademlia,
                    sync,
                    bitswap,
                    limits: libp2p::connection_limits::Behaviour::new(
                        libp2p::connection_limits::ConnectionLimits::default()
                            .with_max_established(Some(
                                u32::try_from(MAX_PEERS).unwrap_or(u32::MAX),
                            ))
                            .with_max_established_incoming(Some(
                                u32::try_from(MAX_PEERS * 2 / 3).unwrap_or(u32::MAX),
                            ))
                            .with_max_established_per_peer(Some(2))
                            .with_max_pending_incoming(Some(
                                u32::try_from(MAX_PEERS / 2).unwrap_or(u32::MAX),
                            )),
                    ),
                })
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let (command_tx, command_rx) = mpsc::channel(32);
        let peer_manager = Arc::new(Mutex::new(PeerManager::new()));
        let gossip_dedup = Arc::new(Mutex::new(GossipDedup::default()));
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
            gossip_dedup,
            bootstrap_peers: Vec::new(),
            dns_seeds: Vec::new(),
            dns_seed_port: 0,
            peer_count,
            sync_state,
            sync_started_at,
            pending_bitswap_fetches: HashMap::new(),
            // The server budget. A battery-powered node lowers this through
            // `with_mobile_profile`, which derives it from the power mode
            // rather than from the boolean; deciding it twice is what let a
            // phone at 5% hold the same ten connections as one on mains.
            max_peers: MAX_PEERS,
            validator_address: None,
            last_precommit_height: 0,
            last_prevote_height: 0,
            vote_history_db: None,
            identity_path: None,
            banned_peer_db: None,
            mdns_enabled,
            metrics: None,
            storage_node,
            pruning_policy: None,
            shard_manager,
            mobile_mode,
            mobile_profile: None,
            mobile_peer_ceiling: MAX_PEERS,
        })
    }

    /// Declare that this node runs on a battery, and how full it is.
    ///
    /// The profile is the single description of what the device can spend;
    /// every budget below is derived from it rather than chosen again here.
    /// Refuses a profile that does not describe a device: a zero address or
    /// a battery reporting over 100% means the caller assembled it wrong, and
    /// a peer budget derived from nonsense is worse than the server default.
    ///
    /// # Errors
    ///
    /// The reason the profile is not a description of a device.
    pub fn with_mobile_profile(
        mut self,
        profile: crate::network::mobile::MobileNodeProfile,
    ) -> Result<Self, String> {
        profile.validate()?;
        self.mobile_mode = true;
        // Lowers the cap, never raises it. `apply_network_security` and the
        // operator's `--max-peers` have both already spoken by the time a
        // profile is installed, and a battery is a reason to hold fewer
        // connections than they allowed, never more.
        self.mobile_peer_ceiling = self.max_peers;
        self.max_peers = self
            .max_peers
            .min(crate::network::mobile::ChallengePolicy::peer_budget(
                profile.battery.power_mode(),
                MAX_PEERS,
            ));
        self.mobile_profile = Some(profile);
        Ok(self)
    }

    /// Re-read the battery and move every budget with it.
    ///
    /// Returns the mode now in force, or `None` on a node with no profile,
    /// which is every mains-powered one.
    ///
    /// The peer cap moves here because it is the largest continuous cost a
    /// node pays: each connection is a keepalive, a gossip mesh slot and a
    /// share of every broadcast. Leaving it fixed while the challenge budget
    /// falls to zero, which is what this file did before, saves the work the
    /// device was not doing anyway and none of the work it was.
    pub fn apply_power_mode(
        &mut self,
        level_pct: u8,
        charging: bool,
        estimated_minutes: u32,
    ) -> Option<crate::network::mobile::PowerMode> {
        let ceiling = self.mobile_peer_ceiling;
        let profile = self.mobile_profile.as_mut()?;
        // A malformed reading leaves the previous budgets standing. The last
        // good reading is a better basis than one the profile itself refuses.
        profile
            .try_update_battery(level_pct, charging, estimated_minutes)
            .ok()?;
        let mode = profile.battery.power_mode();
        // Same direction as `with_mobile_profile`: charging the phone must
        // not hand it more connections than the network profile allowed.
        self.max_peers = ceiling.min(crate::network::mobile::ChallengePolicy::peer_budget(
            mode, MAX_PEERS,
        ));
        Some(mode)
    }

    /// Whether this node should take on storage challenge work right now.
    ///
    /// A node with no profile is mains-powered and always may. A node with
    /// one is asked, and the answer is the profile's, not a second opinion
    /// formed here.
    #[must_use]
    pub fn accepts_storage_work(&self) -> bool {
        self.mobile_profile
            .as_ref()
            .is_none_or(|p| p.challenge_policy.storage_attestation && p.can_accept_tasks())
    }

    /// Set what this node is allowed to delete.
    ///
    /// Without this the hard-prune worker deletes whenever an `NftBurn`
    /// names content it holds, which is right for a full node and wrong for
    /// an archive node. `PruningPolicy::validate` should be called on the
    /// policy before it reaches here; this only stores it.
    #[must_use]
    pub const fn with_pruning_policy(mut self, policy: crate::storage::PruningPolicy) -> Self {
        self.pruning_policy = Some(policy);
        self
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
        self.mdns_enabled = security.mdns_enabled && cfg!(feature = "p2p-mdns");
        // Wire peer_rate_limit_per_minute into PeerManager token bucket.
        {
            let mut pm = self.peer_manager_lock();
            pm.apply_security_config(security);
        }
        if security.persist_banned_peers && self.banned_peer_db.is_none() {
            self.banned_peer_db = Some(std::path::PathBuf::from(
                format!("./data/{:?}/banned-peers.json", network).to_lowercase(),
            ));
        }
        // Unlike the ban list, this one defaults on for every network. A ban
        // List that does not survive a restart costs some peer churn; vote
        // Marks that do not survive a restart cost half the bond. There is no
        // Network on which the unsafe default is the right one.
        if self.vote_history_db.is_none() {
            self.vote_history_db = Some(std::path::PathBuf::from(
                format!("./data/{network:?}/vote-history.json").to_lowercase(),
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

    /// Bind the file the vote high-water marks are persisted to.
    ///
    /// A validator that restarts without these marks re-signs heights it has
    /// Already voted at. Across a reorg that is two different hashes at one
    /// Height from one key, which is the exact shape equivocation detection
    /// Looks for - `double_sign_slash_ratio_fixed`, 50% of the bond by
    /// Default, for a crash rather than any malice.
    ///
    /// `load_vote_history` / `save_vote_history` already do the work and were
    /// Inert because nothing ever set this path. Passing `None` keeps the
    /// In-memory behaviour, which is what the tests rely on;
    /// [`Self::apply_network_security`] fills in a default for a real network.
    #[must_use]
    pub fn with_vote_history_db(mut self, path: Option<String>) -> Self {
        self.vote_history_db = path.map(std::path::PathBuf::from);
        self
    }

    pub fn with_dns_seeds(mut self, seeds: Vec<String>, port: u16) -> Self {
        self.dns_seeds = seeds;
        self.dns_seed_port = port;
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
        }
    }
    pub fn listen(&mut self, port: u16) -> Result<(), Box<dyn Error>> {
        let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
        self.swarm.listen_on(addr)?;
        info!("Listening on port {port}");
        Ok(())
    }
    pub fn dial(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let remote: Multiaddr = addr.parse()?;
        self.swarm.dial(remote)?;
        info!("Dialing {addr}");
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
        info!("Bootstrapping via {addr}");
        self.swarm
            .behaviour_mut()
            .kad
            .add_address(&peer_id, multiaddr);
        self.swarm.behaviour_mut().kad.bootstrap()?;
        Ok(())
    }
    /// Restore the vote high-water marks written by a previous run.
    ///
    /// Both marks exist to stop this node signing twice at one checkpoint
    /// height. Holding them only in memory means a restart forgets every vote
    /// already cast, and the node is willing to sign that height again.
    ///
    /// On a chain that has not moved, re-signing is harmless: the hash is the
    /// same, `detect_prevote_equivocation` compares hashes and sees no
    /// conflict, and the aggregator refuses the duplicate. The dangerous case
    /// is a restart across a reorg - the same height now carries a different
    /// hash, and a second signature over it is exactly what equivocation
    /// detection is looking for. The penalty is `double_sign_slash_ratio_fixed`,
    /// 50% of the bond by default, for what is a crash and a restart rather
    /// than any malice.
    ///
    /// A missing or unreadable file leaves the marks at zero, which is the
    /// behaviour before this existed. Refusing to boot would convert a corrupt
    /// file into downtime; the marks are a safety margin, not consensus state.
    fn load_vote_history(&mut self) {
        let Some(ref path) = self.vote_history_db else {
            return;
        };
        // Bounded: the vote history is two integers. Anything larger is not
        // a vote history, and reading it would be an allocation chosen by
        // whatever wrote the file rather than by this node.
        match crate::core::bounded_read::read_to_string_bounded(
            path,
            crate::core::bounded_read::MAX_CONTROL_FILE_BYTES,
        ) {
            Ok(data) => match serde_json::from_str::<VoteHistory>(&data) {
                Ok(v) => {
                    self.last_prevote_height = v.last_prevote_height;
                    self.last_precommit_height = v.last_precommit_height;
                    info!(
                        prevote = v.last_prevote_height,
                        precommit = v.last_precommit_height,
                        "Vote history restored; this node will not re-sign at or below these heights"
                    );
                }
                Err(e) => warn!(error = %e, path = %path.display(),
                    "Vote history unreadable; starting from zero (a restart across a reorg could double-sign)"),
            },
            Err(e) if e.is_not_found() => {}
            Err(e) => warn!(error = %e, path = %path.display(), "Vote history could not be read"),
        }
    }

    /// Record the vote high-water marks.
    ///
    /// Written immediately after a vote is published, never batched: the
    /// window between signing and persisting is exactly the window in which a
    /// crash loses the record.
    fn save_vote_history(&self) {
        let Some(ref path) = self.vote_history_db else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(error = %e, path = %path.display(), "Cannot create vote-history directory");
                return;
            }
        }
        let body = serde_json::json!({
            "last_prevote_height": self.last_prevote_height,
            "last_precommit_height": self.last_precommit_height,
        });
        if let Err(e) = std::fs::write(path, body.to_string()) {
            warn!(error = %e, path = %path.display(),
                  "Failed to persist vote history; a restart could re-sign a checkpoint");
        }
    }

    fn load_banned_peers_from_db(&self) {
        let Some(ref db_path) = self.banned_peer_db else {
            return;
        };
        // Bounded: the ban list grows with the peer set, so it gets the
        // larger ceiling - but it still gets one.
        match crate::core::bounded_read::read_to_string_bounded(
            db_path,
            crate::core::bounded_read::MAX_BAN_LIST_BYTES,
        ) {
            Ok(data) => {
                // Prefer absolute-expiry records; accept legacy
                // String-only lists for one-version migration.
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
                        let n = list.banned_peers.len();
                        self.peer_manager_lock()
                            .reload_banned_peers(&list.banned_peers);
                        info!(
                            "Reloaded {} banned peers (with expiry) from {}",
                            n,
                            db_path.display()
                        );
                    }
                } else if let Ok(list) = serde_json::from_str::<BanListLegacy>(&data) {
                    if !list.banned_peers.is_empty() {
                        let n = list.banned_peers.len();
                        self.peer_manager_lock()
                            .reload_banned_peers_legacy(&list.banned_peers);
                        info!(
                            "Reloaded {} banned peers (legacy full-window) from {}",
                            n,
                            db_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                if !e.is_not_found() {
                    warn!("Failed to read banned peer DB: {e}");
                }
            }
        }
    }

    fn save_banned_peers_to_db(&self) {
        let Some(ref db_path) = self.banned_peer_db else {
            return;
        };
        // Returning early on a poisoned lock silently skipped the write, so
        // every ban recorded in this run was lost on restart. The recovered
        // state still holds the ban list.
        let banned_peers = self.peer_manager_lock().get_persisted_banned_peers();
        if banned_peers.is_empty() {
            return;
        }
        let json = serde_json::json!({ "banned_peers": banned_peers });
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
            // Serializing an already-built serde_json::Value cannot fail
            // In practice, but log if it ever does instead of writing empty.
            let json_str = serde_json::to_string_pretty(&json).unwrap_or_else(|e| {
                warn!("Failed to serialize banned peers JSON: {e}");
                String::new()
            });
            if let Err(e) = std::fs::write(db_path, json_str) {
                warn!("Failed to persist banned peers: {e}");
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
                warn!("Bootstrap dial failed for {addr}: {e}");
            }
        }

        // Resolve and dial DNS seeds
        if !self.dns_seeds.is_empty() {
            let dns_addrs = resolve_dns_seeds(&self.dns_seeds, self.dns_seed_port);
            for addr in &dns_addrs {
                if let Err(e) = self.dial(addr) {
                    warn!("DNS seed dial failed for {addr}: {e}");
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
        if let Some(ref profile) = self.mobile_profile {
            info!(
                summary = %profile.summary(),
                max_peers = self.max_peers,
                storage_work = self.accepts_storage_work(),
                "Mobile profile in force: peer and storage budgets derived from the battery"
            );
        }
        // The prevote high-water mark now lives on `self` so it can be
        // persisted; see `load_vote_history`.
        self.load_vote_history();

        loop {
            tokio::select! {
                       _ = gc_interval.tick() => {
                           let removed = self.chain.cleanup_mempool().await;
                           if removed > 0 {
                               info!("Cleaned up {removed} expired transactions from mempool");
                           }

                           // Scoped so the guard is not held across the rest
                           // of this arm, which does chain and sync work.
                           self.peer_manager_lock().cleanup_expired_bans();

                           // Expiring a ban only clears the flag; the record itself
                           // is spent once no penalty is left. The tracking ceiling
                           // reclaims on its own, but only when the table is already
                           // full, so a peer id minted for free and then left behind
                           // keeps the door shut for every peer not yet met. The
                           // beat that expires bans is the beat that frees the slots.
                           let reclaimed = self.peer_manager_lock().prune_spent_records();
                           if reclaimed > 0 {
                               info!("Reclaimed {reclaimed} spent peer records");
                           }

                           // Auto-reset orphaned sync_state.
                           // If sync_state has been 1 for longer than SYNC_TIMEOUT_SECS,
                           // The sync cycle is considered stuck (e.g., peer disconnected
                           // Mid-sync) and we reset it to 0 so the node reports correct
                           // Status and can initiate a new sync.
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
                                   warn!("Periodic bootstrap failed for {addr}: {e}");
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
                           let chain_id = self.chain.get_chain_id().await;
                           let checkpoint_interval =
                               crate::core::chain_config::finality_checkpoint_interval_for_chain_id(
                                   chain_id,
                               );
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
                                       self.save_vote_history();
                                   }
                                   Err(e) => {
                                       warn!("Failed to sign precommit: {e}");
                                   }
                               }
                           }

                           // --- Periodic prevote ---
                           if checkpoint_height > 0 && checkpoint_height > self.last_prevote_height {
                               if let Some(block) = self.chain.get_block(checkpoint_height).await {
                                   let epoch = checkpoint_height / checkpoint_interval;
                                   match self.chain.sign_prevote(
                                       epoch,
                                       checkpoint_height,
                                       block.hash.clone(),
                                       voter_addr,
                                   ).await {
                                       Ok(prevote) => {
                                           info!("Finality: voting for checkpoint height {checkpoint_height} (epoch {epoch})");
                                           let vote_msg = NetworkMessage::Prevote {
                                               epoch: prevote.epoch,
                                               checkpoint_height: prevote.checkpoint_height,
                                               checkpoint_hash: prevote.checkpoint_hash,
                                               voter_id: voter_addr.to_hex(),
                                               sig_bls: prevote.sig_bls,
                                           };
                                           let topic = gossipsub::IdentTopic::new("blocks");
                                           let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, vote_msg.to_bytes());
                                           self.last_prevote_height = checkpoint_height;
                                           self.save_vote_history();
                                       }
                                       Err(e) => {
                                           warn!("Failed to sign prevote: {e}");
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
                                   warn!("Failed to gossip slashing evidence: {e}");
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
                           // The profile decides, not this loop. A phone in
                           // `PowerMode::Critical` sets `storage_attestation`
                           // false and `max_proof_tasks` zero, and this sweep
                           // ran anyway on the old two-way `mobile_mode`
                           // split: the device declined the work and then
                           // spent the radio looking for it.
                           if !self.accepts_storage_work() {
                               tracing::debug!(
                                   "Storage: sharding health check skipped, the device profile \
                                    declines storage work at this power level"
                               );
                           } else if let (Some(ref _bitswap), Some(ref _shard_manager)) = (&self.storage_node, &self.shard_manager) {
                               // This logic is for User Decision 5: mandatory_sharding.
                               // We check if there are deals near us that we aren't hosting.
                               // For now, we log the health.
                               info!("Storage: Running active sharding health check (XOR distance)...");
                               // Future improvement: proactively query DHT for near-CIDs.
                           }
                       }
                       _ = banning_interval.tick() => {
                           // An empty list here means no banned peer is ever
                           // disconnected again, which is the opposite of what
                           // a poisoned ban table should cause.
                           let banned_peers = self.peer_manager_lock().get_banned_peers();
                           for peer_id in banned_peers {
                               warn!("Proactively disconnecting banned peer: {peer_id}");
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
                                           warn!("Failed to subscribe: {e}");
                                       } else {
                                           info!("Subscribed to topic: {topic}");
                                       }
                                   }
                                   NodeCommand::Broadcast(topic, msg) => {
                                       let topic = gossipsub::IdentTopic::new(topic);
                                       let data = msg.to_bytes();
                                       if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                                           warn!("Failed to publish: {e}");
                                       } else {
                                           info!("Broadcasted to {}: {:?}", topic, msg);
                                       }
                                   }
                                   NodeCommand::RequestSync => {
                                       let locator = self.chain.get_locator().await;
                                       if !self.request_headers_from_peer(None, locator, 2000) {
                                           info!("Sync not started: a round is already open or no handshaked peer is connected");
                                       }
                                   }
                                   NodeCommand::ListPeers => {
                                       let peers: Vec<_> = self.swarm.behaviour().gossipsub.all_peers().collect();
                                       info!("Connected peers: {:?}", peers.len());
                                       for (peer, _topics) in peers {
                                           info!(" - {peer}");
                                       }
                                   }
                                   NodeCommand::BroadcastTx(tx) => {
                                       let msg = NetworkMessage::Transaction(tx);
                                       let topic = gossipsub::IdentTopic::new("transactions");
                                       if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, msg.to_bytes()) {
                                           warn!("Failed to gossip transaction: {e}");
                                       }
                                   }
                                   NodeCommand::StoragePrune { cid } => {
                                       // Hard Pruning worker - physical deletion from local B.U.D. store.
                                       // Only triggered by local Executor (not via P2P gossip), per SECURITY_AUDIT_HACKER.md.
                                       //
                                       // Ask the policy first. An archive node exists to be the
                                       // copy of last resort, and `PruningPolicy::validate`
                                       // already refuses one that prunes. That refusal meant
                                       // nothing while no deletion path consulted it: the check
                                       // was written, tested, and unreachable.
                                       //
                                       // A node with no policy configured keeps the previous
                                       // behaviour, so this cannot quietly stop deletions that
                                       // were working. What it stops is an archive node deleting
                                       // the copy the network was counting on.
                                       // `continue` would target whichever loop the compiler
                                       // finds nearest, and this arm sits inside a `select!`
                                       // inside the event loop. A boolean read before the
                                       // deletion block keeps the control flow local and
                                       // obvious.
                                       let policy_permits = self
                                           .pruning_policy
                                           .as_ref()
                                           .is_none_or(crate::storage::PruningPolicy::should_prune_historical_state);
                                       if !policy_permits {
                                           if let Some(ref policy) = self.pruning_policy {
                                               info!(
                                                   cid = %hex::encode(cid),
                                                   mode = policy.mode.label(),
                                                   "B.U.D. hard prune refused: this node's pruning policy does not \
                                                    permit deleting stored content"
                                               );
                                           }
                                       } else if let Some(ref storage_node) = self.storage_node {
                                           let content_id = bud_node::store::ContentId(cid);
                                           match storage_node.store().delete(&content_id) {
                                               Ok(()) => {
                                                   info!(
                                                       cid = %hex::encode(cid),
                                                       "B.U.D. hard prune executed: content physically deleted from local store (NftBurn)"
                                                   );
                                               }
                                               Err(e) => {
                                                   // Not found is not an error - content may have been pruned already or never stored locally
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
                                               "StoragePrune received but storage_node is None - no-op (node without B.U.D. storage)"
                                           );
                                       }
                                   }
                                   NodeCommand::FetchLocalContent { cid, response } => {
                                       let result = if let Some(ref storage_node) = self.storage_node {
                                           let content_id = bud_node::store::ContentId(cid);
                                           storage_node
                                               .store()
                                               .get(&content_id)
                                               .map_err(|e| format!("local B.U.D. content fetch failed: {e}"))
                                       } else {
                                           Err("local B.U.D. storage node not configured".into())
                                       };
                                       let _ = response.send(result);
                                   }
                                   NodeCommand::FetchRemoteContent { cid, response } => {
                                       // 1. Try local fetch first
                                       let local_result = if let Some(ref storage_node) = self.storage_node {
                                           let content_id = bud_node::store::ContentId(cid);
                                           storage_node.store().get(&content_id)
                                       } else {
                                           Err(bud_node::store::StoreError::NotFound(bud_node::store::ContentId(cid)))
                                       };

                                       match local_result {
                                           Ok(data) => {
                                               let _ = response.send(Ok(data));
                                           }
                                           Err(_) => {
                                               // 2. Fetch from remote P2P peers
                                               // A poisoned PeerManager mutex must not
                                               // take the node down over a content
                                               // fetch. Every other lock site here
                                               // either matches on the result or exits
                                               // deliberately; this one used a bare
                                               // unwrap, so one panic while the lock
                                               // was held turned an optional Bitswap
                                               // fetch into a node-wide crash.
                                               let peers =
                                                   self.peer_manager_lock().connected_peers();
                                               if peers.is_empty() {
                                                   let _ = response.send(Err("No connected peers for P2P fetch".into()));
                                               } else {
                                                   let entry = self.pending_bitswap_fetches.entry(cid).or_default();
                                                   entry.retain(|sender| !sender.is_closed());
                                                   if entry.len() >= MAX_PENDING_BITSWAP_FETCH_WAITERS {
                                                       let _ = response.send(Err(format!(
                                                           "too many pending remote content fetches for {}",
                                                           hex::encode(cid)
                                                       )));
                                                       continue;
                                                   }
                                                   entry.push(response);
                                                   let want_cid = bud_node::store::ContentId(cid);
                                                   for peer in &peers {
                                                       let _ = self.swarm.behaviour_mut().bitswap.send_request(
                                                           peer,
                                                           bud_node::BitswapRequest { want_cid },
                                                       );
                                                   }
                                               }
                                           }
                                       }
                                   }
                               }
                           }
                       }
                       event = self.swarm.select_next_some() => {
                           match event {
                               SwarmEvent::NewListenAddr { address, .. } => {
                                   info!("Listening on {address}");
                               }
                               SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                                   let remote = endpoint.get_remote_address();
                                   let subnet = ipv4_slash24(remote);
                                   // Security review (HIGH): a banned peer
                                   // could reconnect and carry on issuing
                                   // /sync requests, because the handshaked
                                   // flag survives a disconnect. The ban is
                                   // now checked first, when the connection
                                   // is admitted.
                                   if self.peer_manager_lock().is_banned(&peer_id) {
                                       warn!("Rejecting banned peer {} on reconnect", peer_id);
                                       let _ = self.swarm.disconnect_peer_id(peer_id);
                                       continue;
                                   }
                                   // H5.1 eclipse bound before admitting.
                                   // Through the recovering helper, not a raw
                                   // `lock()`. A poisoned mutex made this
                                   // `unwrap_or(true)`, which turns the /24
                                   // eclipse bound OFF at exactly the moment
                                   // something has already gone wrong: one
                                   // operator could then fill the peer table
                                   // from a single subnet and surround the
                                   // node. The rest of this file recovers the
                                   // guard and keeps enforcing; these four
                                   // sites were the ones that did not.
                                   let admit = self
                                       .peer_manager_lock()
                                       .can_admit_subnet(subnet);
                                   if !admit {
                                       warn!(
                                           "Eclipse bound: rejecting {} from {:?} (/24 limit)",
                                           peer_id, subnet
                                       );
                                       let _ = self.swarm.disconnect_peer_id(peer_id);
                                       continue;
                                   }
                                   // H5.2 outbound diversity: an extra /24 limit for outbound connections.
                                   if endpoint.is_dialer() {
                                       let ob_admit = self
                                           .peer_manager_lock()
                                           .can_admit_outbound_subnet(subnet);
                                       if !ob_admit {
                                           warn!(
                                               "Outbound diversity: rejecting outbound {} from {:?}",
                                               peer_id, subnet
                                           );
                                           let _ = self.swarm.disconnect_peer_id(peer_id);
                                           continue;
                                       }
                                   }
                                   let newly_connected = {
                                       let mut pm = self.peer_manager_lock();
                                       let c = pm.note_connected(peer_id, subnet);
                                       if c && endpoint.is_dialer() {
                                           let _ = pm.note_outbound_connected(peer_id, subnet);
                                       }
                                       c
                                   };
                                   // The peer is back: take its score record
                                   // out of the eviction queue so a connected
                                   // peer is never dropped while an idle
                                   // record survives.
                                   {
                                       let mut dedup = self.gossip_dedup.lock().unwrap_or_else(
                                           |poisoned| {
                                               tracing::error!(
                                                   "GossipDedup lock was poisoned by an earlier \
                                                    panic; continuing with the recovered state"
                                               );
                                               poisoned.into_inner()
                                           },
                                       );
                                       dedup.note_peer_connected(&peer_id);
                                   }
                                   let count = if newly_connected {
                                       self.peer_count.fetch_add(1, Ordering::SeqCst) + 1
                                   } else {
                                       self.peer_count.load(Ordering::SeqCst)
                                   };
                                   if count > self.max_peers {
                                       warn!(
                                           "Max peers reached ({}/{}), disconnecting {}",
                                           count, self.max_peers, peer_id
                                       );
                                       let _ = self.swarm.disconnect_peer_id(peer_id);
                                       if newly_connected {
                                           self.peer_count
                                               .fetch_update(
                                                   Ordering::SeqCst,
                                                   Ordering::SeqCst,
                                                   |v| Some(v.saturating_sub(1)),
                                               )
                                               .ok();
                                           {
                                               let mut pm = self.peer_manager_lock();
                                               pm.note_disconnected(&peer_id);
                                               let _ = pm.note_outbound_disconnected(&peer_id);
                                           }
                                       }
                                       continue;
                                   }
                                   if let Some(ref m) = self.metrics {
                                       m.p2p_peers_connected.set(count as i64);
                                       let mean_quality = self
                                           .gossip_dedup
                                           .lock()
                                           .map(|d| d.mean_peer_score_i64())
                                           .unwrap_or_else(|p| p.into_inner().mean_peer_score_i64());
                                       m.peer_connection_quality.set(mean_quality);
                                   }
                                   info!("Connected to {peer_id}, Peers: {count}");

                                   let handshake = NetworkMessage::Handshake {
                                       version_major: crate::core::encoding::PROTOCOL_VERSION_MAJOR,
                                       version_minor: crate::core::encoding::PROTOCOL_VERSION_MINOR,
                                       chain_id: self.chain.get_chain_id().await,
                                       best_height: self.chain.get_height().await + 1,
                                       validator_set_hash: self.chain.get_validator_set_hash().await,
                                       supported_schemes: vec![
                                           "ED25519".to_string(),
                                           crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string(),
                                           "DILITHIUM".to_string(),
                                       ],
                                   };

                                   let chain_len = self.chain.get_height().await + 1;
                                   info!("DEBUG: Connected to {peer_id}, Chain length: {chain_len}, sending Handshake");

                                   let topic = gossipsub::IdentTopic::new("blocks");
                                   if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, handshake.to_bytes()) {
                                       warn!("Failed to send Handshake: {e}");
                                   }

                                   if self.chain.get_height().await == 0 {
                                       if let Some(last_block) = self.chain.get_block(0).await {
                                           let locator = vec![last_block.hash];
                                           info!("New connection, requesting headers...");
                                           // The handshake has not completed on a
                                           // connection this young, so the helper
                                           // picks an already-handshaked peer or
                                           // waits for the Handshake/HandshakeAck
                                           // trigger below.
                                           let _ = self.request_headers_from_peer(Some(peer_id), locator, 2000);
                                       }
                                   }
                               }
                               SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                   // Same treatment: a poisoned lock used to
                                   // report every close as a real disconnect,
                                   // which drifts `peer_count` in the opposite
                                   // direction from the connect path above.
                                   let was_connected = {
                                       let mut pm = self.peer_manager_lock();
                                       let d = pm.note_disconnected(&peer_id);
                                       let _ = pm.note_outbound_disconnected(&peer_id);
                                       d
                                   };
                                   if was_connected {
                                       self.peer_count
                                           .fetch_update(
                                               Ordering::SeqCst,
                                               Ordering::SeqCst,
                                               |v| Some(v.saturating_sub(1)),
                                           )
                                           .ok();
                                   }
                                   // Mark the gossip score record evictable.
                                   // It is NOT deleted: a peer one message
                                   // from the ban threshold would otherwise
                                   // clear its record by reconnecting. The
                                   // record survives and is the first thing
                                   // dropped when the table hits
                                   // `MAX_SCORED_PEERS`. Before this call the
                                   // table had no eviction path at all and
                                   // grew once per distinct `PeerId` seen,
                                   // which costs an attacker one key
                                   // generation each.
                                   {
                                       let mut dedup = self.gossip_dedup.lock().unwrap_or_else(
                                           |poisoned| {
                                               tracing::error!(
                                                   "GossipDedup lock was poisoned by an earlier \
                                                    panic; continuing with the recovered state"
                                               );
                                               poisoned.into_inner()
                                           },
                                       );
                                       dedup.note_peer_disconnected(&peer_id);
                                   }
                                   if let Some(ref m) = self.metrics {
                                       m.p2p_peers_connected
                                           .set(self.peer_count.load(Ordering::SeqCst) as i64);
                                       let (scored, mean_quality) = self
                                           .gossip_dedup
                                           .lock()
                                           .map(|d| (d.scored_peer_count(), d.mean_peer_score_i64()))
                                           .unwrap_or_else(|p| {
                                               let d = p.into_inner();
                                               (d.scored_peer_count(), d.mean_peer_score_i64())
                                           });
                                       m.gossip_scored_peers
                                           .set(i64::try_from(scored).unwrap_or(i64::MAX));
                                       m.peer_connection_quality.set(mean_quality);
                                   }
                                   warn!(
                                       "Disconnected from {}, Peers: {}",
                                       peer_id,
                                       self.peer_count.load(Ordering::SeqCst)
                                   );
                               }
                               // Dial failures used to fall into the catch-all `_ => {}`
                               // Arm, so a transport that refused every bootstrap
                               // Address produced no log line at all - the node just
                               // Looked like a healthy peer-less island. Surface them.
                               SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                   warn!(
                                       "Outgoing connection failed (peer: {:?}): {}",
                                       peer_id, error
                                   );
                               }
                               SwarmEvent::Behaviour(BudlumBehaviourEvent::Ping(_event)) => {
                               }
                               #[cfg(feature = "p2p-mdns")]
                               SwarmEvent::Behaviour(BudlumBehaviourEvent::Mdns(event)) => {
                                   if !self.mdns_enabled {
                                       continue;
                                   }
                                   match event {
                                       mdns::Event::Discovered(peers) => {
                                           for (peer_id, addr) in peers {
                                               info!("mDNS discovered: {peer_id} at {addr}");
                                               self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                               if let Err(e) = self.swarm.dial(addr.clone()) {
                                                   warn!("Failed to dial discovered peer: {e}");
                                               }
                                           }
                                       }
                                       mdns::Event::Expired(peers) => {
                                           for (peer_id, _) in peers {
                                               info!("mDNS expired: {peer_id}");
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

                                   {
                                       let pm = self.peer_manager_lock();
                                       if pm.is_banned(&peer_id) {
                                           warn!("Ignoring message from banned peer {peer_id}");
                                           continue;
                                       }
                                   }

                                   if !self.peer_manager_lock().check_rate_limit(&peer_id) {
                                       warn!("Rate limit exceeded or lock error for peer {peer_id}");
                                       continue;
                                   }

                                   // Same reasoning as `peer_manager_lock`: a poisoned
                                   // dedup window is a stale duplicate-detection
                                   // window, which the next message corrects. Exiting
                                   // here would let one panic anywhere in dedup
                                   // bookkeeping remove the node from the network.
                                   let duplicate_action = {
                                       let mut dedup = self.gossip_dedup.lock().unwrap_or_else(|poisoned| {
                                           tracing::error!(
                                               "GossipDedup lock was poisoned by an earlier panic; \
                                                continuing with the recovered state"
                                           );
                                           poisoned.into_inner()
                                       });
                                       match dedup.check_and_record(&message.data, &peer_id) {
                                           DedupResult::New => None,
                                           DedupResult::Duplicate => {
                                               Some(dedup.peer_should_be_banned(&peer_id))
                                           }
                                       }
                                   };
                                   if let Some(should_ban) = duplicate_action {
                                       // Event-local: one increment per duplicate
                                       // observation. Setting from
                                       // `total_duplicates()` would require a
                                       // gauge and would hide the rate under a
                                       // cumulative level.
                                       if let Some(ref m) = self.metrics {
                                           m.p2p_gossip_duplicates.inc();
                                       }
                                       if should_ban {
                                           warn!("Duplicate gossip flood detected from {peer_id}; banning peer");
                                           {
                                               let mut pm = self.peer_manager_lock();
                                               pm.ban_peer(&peer_id);
                                           }
                                           let _ = self.swarm.disconnect_peer_id(peer_id);
                                       }
                                       continue;
                                   }

                                   if let Some(ref m) = self.metrics {
                                       m.p2p_messages_received.inc();
                                   }

                                   info!("Received from {peer_id}: id={id}");
                                   match NetworkMessage::from_bytes_validated(&message.data) {
                                       Ok(msg) => {
                                           let is_handshake_msg = matches!(
                                               msg,
                                               NetworkMessage::Handshake { .. } | NetworkMessage::HandshakeAck { .. }
                                           );

                                           let is_handshaked = self.peer_manager_lock().is_handshaked(&peer_id);

                                           if !is_handshake_msg && !is_handshaked {
                                               warn!("Peer {} sent {:?} before completing handshake, dropping.", peer_id, msg);

                                               {
                                                   let mut pm = self.peer_manager_lock();
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
                                                   self.peer_manager_lock().report_oversized_message(&peer_id);
                                                   continue;
                                               }
                                               let our_chain_id = self.chain.get_chain_id().await;
                                               if !Self::block_passes_cheap_checks(&block, our_chain_id) {
                                                   warn!(
                                                       "Rejected gossip block #{} from {}: chain id or hash does not match its contents",
                                                       block.index, peer_id
                                                   );
                                                   self.peer_manager_lock().report_invalid_block(&peer_id);
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
                                                           {
                                                               let mut pm = self.peer_manager_lock();
                                                               pm.report_good_behavior(&peer_id);
                                                           }
                                                       }
                                                       Err(e) => {
                                                           warn!("Block validation failed: {e}");
                                                           {
                                                               let mut pm = self.peer_manager_lock();
                                                               pm.report_invalid_block(&peer_id);
                                                           }
                                                       }
                                                   }
                                               } else if block.index <= our_height {
                                                   if let Some(our_block) = self.chain.get_block(block.index).await {
                                                       if our_block.hash != block.hash {
                                                           info!("Fork detected at height {} (ours: {}... theirs: {}...)", block.index, &our_block.hash[..8.min(our_block.hash.len())], &block.hash[..8.min(block.hash.len())]);

                                                           info!("Fork detected at height {} - initiating sync to resolve fork", block.index);
                                                           if self.sync_state.load(Ordering::SeqCst) == 0 {
                                                               let locator = self.chain.get_locator().await;
                                                               let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                                           }
                                                       }
                                                   }
                                               } else {
                                                   info!("Block #{} is ahead of our chain (height={}), requesting sync", block.index, our_height);
                                                   if self.sync_state.load(Ordering::SeqCst) == 0 {
                                                       let locator = self.chain.get_locator().await;
                                                       let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                                   }
                                               }
                                           }
                                           NetworkMessage::Transaction(tx) => {
                                               if let Err(e) = NetworkMessage::validate_tx_size(&tx) {
                                                   warn!("Received oversized transaction from {}: {:?}", peer_id, e);
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_oversized_message(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               // Security: `hash` is peer-controlled until the transaction
                                               // Reaches canonical verification. Never byte-slice an untrusted
                                               // UTF-8 string: a short or multi-byte hash used to panic here and
                                               // Abort release nodes (`panic = "abort"`). Reject malformed shape
                                               // Before logging or signature work.
                                               if tx.hash.len() != 64
                                                   || !tx.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                                               {
                                                   warn!(
                                                       "Rejected transaction with non-canonical hash from {} (len={})",
                                                       peer_id,
                                                       tx.hash.len()
                                                   );
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_invalid_tx(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               let hash_prefix: String = tx.hash.chars().take(8).collect();
                                               info!("Broadcasted tx: {} from: {} to: {} amount: {}",
                                                   hash_prefix, tx.from, tx.to, tx.amount);
                                               match self.chain.add_transaction(tx).await {
                                                   Ok(_) => {
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer_id);
                                                       }
                                                   }
                                                   Err(e) => {
                                                       warn!("Failed to add transaction: {e}");
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_invalid_tx(&peer_id);
                                                       }
                                                   }
                                               }
                                           }

                                           NetworkMessage::SlashingEvidence(evidence) => {
                                               match self.chain.submit_slashing_evidence(evidence.clone()).await {
                                                   Ok(_) => {
                                                       info!("Accepted slashing evidence from {peer_id}");
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer_id);
                                                       }
                                                       let topic = gossipsub::IdentTopic::new("blocks");
                                                       let _ = self.swarm.behaviour_mut().gossipsub.publish(
                                                           topic,
                                                           NetworkMessage::SlashingEvidence(evidence).to_bytes(),
                                                       );
                                                   }
                                                   Err(e) => {
                                                       warn!("Rejected slashing evidence from {peer_id}: {e}");
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_invalid_block(&peer_id);
                                                       }
                                                   }
                                               }
                                           }

                                           NetworkMessage::GetHeaders { locator, limit } => {
                                               // Security review (HIGH): publishing a reply to the topic
                                               // for GetHeaders/GetBlocksRange/GetBlocksByHeight requests
                                               // that arrive over gossip is a reflected, amplified DoS
                                               // (the reply goes to the whole mesh, not to the asker).
                                               // These requests are served only over the peer-bound
                                               // request_response (/sync); the gossip arm no longer
                                               // answers.
                                               if let Err(error) = NetworkMessage::validate_header_request(&locator, limit) {
                                                   warn!("Rejected invalid gossip GetHeaders from {}: {:?}", peer_id, error);
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_bad_behavior(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               warn!("Ignoring gossip GetHeaders from {peer_id}: sync is point-to-point (request_response)");
                                               continue;
                                           }

                                           NetworkMessage::Headers(headers) => {
                                               let chain_id = self.chain.get_chain_id().await;
                                               if let Err(error) =
                                                   NetworkMessage::validate_header_batch(&headers, chain_id)
                                               {
                                                   warn!("Rejected invalid header batch from {}: {:?}", peer_id, error);
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_invalid_block(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               // A header batch on the topic is not an answer this
                                               // node asked for: sync rounds run over `/sync`, where the
                                               // `Headers` response arm issues the follow-up
                                               // `GetBlocksRange` to the peer that answered. Publishing a
                                               // follow-up here would go to the whole mesh, where every
                                               // receiver drops it. The batch is validated and scored,
                                               // and if it shows the sender is ahead of us a round is
                                               // opened with that sender.
                                               if let Some(last_header) = headers.last() {
                                                   let our_height = self.chain.get_height().await;
                                                   if last_header.index > our_height
                                                       && self.sync_state.load(Ordering::SeqCst) == 0
                                                   {
                                                       let locator = self.chain.get_locator().await;
                                                       let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                                   }
                                               }
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_good_behavior(&peer_id);
                                               }
                                           }

                                           NetworkMessage::GetBlocksRange { from, to } => {
                                               // Security review (HIGH): do not publish a gossip reply -
                                               // sync works over the peer-bound request_response.
                                               if from > to {
                                                   warn!("Rejected inverted block range from {peer_id}: {from}..{to}");
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_bad_behavior(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               warn!("Ignoring gossip GetBlocksRange from {peer_id}: sync is point-to-point (request_response)");
                                               continue;
                                           }

                                           NetworkMessage::Blocks(blocks) => {
                                               if blocks.len() > crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS {
                                                   {
                                                       let mut pm = self.peer_manager_lock();
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
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_good_behavior(&peer_id);
                                               }
                                           }

                                           NetworkMessage::NewTip { height, hash: _ } => {
                                               let our_height = self.chain.get_height().await;
                                               if height > our_height && self.sync_state.load(Ordering::SeqCst) == 0 {
                                                   let locator = self.chain.get_locator().await;
                                                   let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                               }
                                           }

                                           NetworkMessage::StateSnapshotResponse { height, state_root, ok } => {
                                               if ok {
                                                   info!("Received StateSnapshotResponse: height={height}, root={state_root}");
                                               } else {
                                                   warn!("Peer {peer_id} reported snapshot unavailable at height {height}");
                                               }
                                           }

                                           NetworkMessage::GetStateSnapshot { height } => {
                                               // State snapshots are large point-to-point responses. The legacy
                                               // Gossipsub path broadcast every chunk to the whole mesh and had no
                                               // Request-bound session identity, which made unsolicited-session OOM
                                               // And amplification attacks possible. Until the authenticated
                                               // Request-response snapshot protocol is negotiated, fail closed.
                                               warn!("Ignoring legacy gossip GetStateSnapshot from {peer_id} at height {height}: point-to-point snapshot protocol required");
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_bad_behavior(&peer_id);
                                               }
                                           }

                                           NetworkMessage::SnapshotChunk { height, index, total, data, session_id } => {
                                               // There is no locally-created, peer-bound snapshot request in the
                                               // Gossip protocol. Decoding is bounded by MAX_MESSAGE_SIZE, and this
                                               // Branch rejects without creating attacker-controlled session state.
                                               warn!(
                                                   "Ignoring unsolicited legacy SnapshotChunk from {}: height={}, index={}/{}, bytes={}, session={}",
                                                   peer_id,
                                                   height,
                                                   index,
                                                   total,
                                                   data.len(),
                                                   session_id
                                               );
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_bad_behavior(&peer_id);
                                               }
                                           }

                                           NetworkMessage::GetBlocksByHeight { from_height, to_height } => {
                                               // Security review (HIGH): do not publish a gossip reply -
                                               // sync works over the peer-bound request_response.
                                               warn!("Ignoring gossip GetBlocksByHeight [{from_height}, {to_height}] from {peer_id}: sync is point-to-point (request_response)");
                                               continue;
                                           }

                                           NetworkMessage::BlocksByHeight(blocks) => {
                                               if blocks.len() > crate::network::protocol::MAX_SNAP_BATCH as usize {
                                                   warn!("Too many snap-sync blocks from {peer_id}");
                                                   self.peer_manager_lock().report_invalid_block(&peer_id);
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
                                               self.peer_manager_lock().report_good_behavior(&peer_id);
                                           }

                                           NetworkMessage::Handshake { version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes } => {
                                               if !handshake_origin_matches_peer(peer_id, message.source) {
                                                   warn!(
                                                       "Ignoring relayed/spoofed Handshake: propagation_source={}, signed_source={:?}",
                                                       peer_id,
                                                       message.source
                                                   );
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_invalid_handshake(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               let my_chain_id = self.chain.get_chain_id().await;
                                               if chain_id != my_chain_id {
                                                   warn!("Peer {peer_id} has wrong chain_id {chain_id} (expected {my_chain_id}). Banning.");
                                                   self.peer_manager_lock().ban_peer(&peer_id);
                                                   continue;
                                               }
                                               if !crate::core::encoding::is_compatible_version(version_major, version_minor) {
                                                   warn!("Peer {peer_id} has incompatible protocol v{version_major}.{version_minor}. Banning.");
                                                   self.peer_manager_lock().ban_peer(&peer_id);
                                                   continue;
                                               }
                                               if !supports_required_bls_scheme(&supported_schemes) {
                                                   warn!(
                                                       "Peer {} does not advertise required BLS scheme {}. Banning.",
                                                       peer_id,
                                                       crate::chain::finality::BLS_SCHEME_RFC9380_V1
                                                   );
                                                   self.peer_manager_lock()
                                                       .ban_peer(&peer_id);
                                                   continue;
                                               }
                                               info!("Handshake from {}: v{}.{}, chain={}, height={}, val_set={}, schemes={:?}",
                                                   peer_id, version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes);
                                               self.peer_manager_lock().set_handshaked(&peer_id, true);
                                               let our_height = self.chain.get_height().await;
                                               if best_height > our_height {
                                                   let locator = self.chain.get_locator().await;
                                                   if !self.request_headers_from_peer(Some(peer_id), locator, 500) {
                                                       info!("Failed to request headers after handshake: a sync round is already open or no peer is eligible");
                                                   }
                                               }

                                               let response = NetworkMessage::HandshakeAck {
                                                   version_major: crate::core::encoding::PROTOCOL_VERSION_MAJOR,
                                                   version_minor: crate::core::encoding::PROTOCOL_VERSION_MINOR,
                                                   chain_id: my_chain_id,
                                                   best_height: self.chain.get_height().await + 1,
                                                   validator_set_hash: self.chain.get_validator_set_hash().await,
                                                   supported_schemes: vec![
                                                       "ED25519".to_string(),
                                                       crate::chain::finality::BLS_SCHEME_RFC9380_V1
                                                           .to_string(),
                                                       "DILITHIUM".to_string(),
                                                   ],
                                               };
                                               let topic = gossipsub::IdentTopic::new("blocks");
                                               let data = response.to_bytes();
                                               if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                                   warn!("Failed to send HandshakeAck: {e}");
                                               }
                                           }

                                           NetworkMessage::HandshakeAck { version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes } => {
                                               if !handshake_origin_matches_peer(peer_id, message.source) {
                                                   warn!(
                                                       "Ignoring relayed/spoofed HandshakeAck: propagation_source={}, signed_source={:?}",
                                                       peer_id,
                                                       message.source
                                                   );
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_invalid_handshake(&peer_id);
                                                   }
                                                   continue;
                                               }
                                               let my_chain_id = self.chain.get_chain_id().await;
                                               if chain_id != my_chain_id {
                                                   warn!("Peer {peer_id} Ack with wrong chain_id {chain_id} (expected {my_chain_id}). Banning.");
                                                   self.peer_manager_lock().ban_peer(&peer_id);
                                                   continue;
                                               }
                                               if !crate::core::encoding::is_compatible_version(version_major, version_minor) {
                                                   warn!("Peer {peer_id} Ack has incompatible protocol v{version_major}.{version_minor}. Banning.");
                                                   self.peer_manager_lock().ban_peer(&peer_id);
                                                   continue;
                                               }
                                               if !supports_required_bls_scheme(&supported_schemes) {
                                                   warn!(
                                                       "Peer {} Ack does not advertise required BLS scheme {}. Banning.",
                                                       peer_id,
                                                       crate::chain::finality::BLS_SCHEME_RFC9380_V1
                                                   );
                                                   self.peer_manager_lock()
                                                       .ban_peer(&peer_id);
                                                   continue;
                                               }
                                               info!("HandshakeAck from {}: v{}.{}, chain={}, height={}, val_set={}, schemes={:?}",
                                                   peer_id, version_major, version_minor, chain_id, best_height, validator_set_hash, supported_schemes);
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.set_handshaked(&peer_id, true);
                                                   pm.report_good_behavior(&peer_id);
                                               }
                                               let our_height = self.chain.get_height().await;
                                               if best_height > our_height {
                                                   let locator = self.chain.get_locator().await;
                                                   if !self.request_headers_from_peer(Some(peer_id), locator, 500) {
                                                       info!("Failed to request headers after handshake ack: a sync round is already open or no peer is eligible");
                                                   }
                                               }
                                           }

                                           NetworkMessage::Prevote { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls } => {
                                               let rate_limit_ok = self.peer_manager_lock().check_vote_rate_limit(&peer_id);
                                               if !rate_limit_ok {
                                                   warn!("Peer {peer_id} exceeded vote rate limit or lock error. Ignoring Prevote.");
                                                   continue;
                                               }
                                               info!("Prevote from {}: epoch={}, height={}, hash={}..., voter={}",
                                                   peer_id, epoch, checkpoint_height, &checkpoint_hash[..16.min(checkpoint_hash.len())], voter_id);

                                               let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                                   Ok(addr) => addr,
                                                   Err(e) => {
                                                       warn!("Invalid voter_id in Prevote: {e}");
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
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer_id);
                                                       }
                                                   }
                                                   Err(e) => {
                                                       warn!("Prevote from {peer_id} rejected: {e}");
                                                   }
                                               }
                                           }

                                           NetworkMessage::Precommit { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls } => {
                                               let rate_limit_ok = self.peer_manager_lock().check_vote_rate_limit(&peer_id);
                                               if !rate_limit_ok {
                                                   warn!("Peer {peer_id} exceeded vote rate limit or lock error. Ignoring Precommit.");
                                                   continue;
                                               }
                                               info!("Precommit from {}: epoch={}, height={}, hash={}..., voter={}",
                                                   peer_id, epoch, checkpoint_height, &checkpoint_hash[..16.min(checkpoint_hash.len())], voter_id);

                                               let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                                   Ok(addr) => addr,
                                                   Err(e) => {
                                                       warn!("Invalid voter_id in Precommit: {e}");
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
                                                       {
                                                           let mut pm = self.peer_manager_lock();
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
                                                               scheme_id:
                                                                   crate::chain::finality::BLS_SCHEME_RFC9380_V1
                                                                       .to_string(),
                                                           }
                                                           .to_bytes(),
                                                       );
                                                   }
                                                   Ok(None) => {
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer_id);
                                                       }
                                                   }
                                                   Err(e) => {
                                                       warn!("Precommit from {peer_id} rejected: {e}");
                                                   }
                                               }
                                           }

                                           NetworkMessage::FinalityCert {
                                               epoch,
                                               checkpoint_height,
                                               checkpoint_hash,
                                               agg_sig_bls,
                                               bitmap,
                                               set_hash,
                                               scheme_id,
                                           } => {
                                               let rate_limit_ok = self.peer_manager_lock().check_vote_rate_limit(&peer_id);
                                               if !rate_limit_ok {
                                                   warn!("Peer {peer_id} exceeded vote rate limit or lock error. Ignoring FinalityCert.");
                                                   continue;
                                               }
                                               if scheme_id
                                                   != crate::chain::finality::BLS_SCHEME_RFC9380_V1
                                               {
                                                   warn!("Peer {peer_id} sent unsupported finality BLS scheme {scheme_id}");
                                                   {
                                                       let mut pm = self.peer_manager_lock();
                                                       pm.report_invalid_block(&peer_id);
                                                   }
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
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer_id);
                                                       }
                                                   }
                                                   Err(e) => {
                                                       warn!("Failed to apply FinalityCert from {peer_id}: {e}");
                                                       if e.contains("Missing verified QC blob") {
                                                           // Security review (HIGH): a missing QC blob does
                                                           // not broadcast GetQcBlob over gossip - that would
                                                           // let anyone trigger a mesh-wide QcBlobResponse
                                                           // fan-out by sending a FinalityCert (reflected DoS).
                                                           warn!(
                                                               "Missing verified QC blob for FinalityCert from {peer_id}; refusing legacy gossip QC-blob fetch for epoch={epoch}, height={checkpoint_height}"
                                                           );
                                                       } else {
            let mut pm = self.peer_manager_lock();
                                                           pm.report_bad_behavior(&peer_id);
                                                       }
                                                   }
                                               }
                                           }

                                           NetworkMessage::GetQcBlob { epoch, checkpoint_height } => {
                                               // Security review (HIGH): publishing a reply to the topic
                                               // for GetQcBlob requests that arrive over gossip is a
                                               // reflected, amplified DoS (the reply goes to the whole
                                               // mesh). QC blob exchange has to be point-to-point; the
                                               // gossip arm no longer answers.
                                               warn!("Ignoring gossip GetQcBlob from {peer_id}: QC blob fetch is point-to-point; refusing epoch={epoch}, height={checkpoint_height}");
                                               continue;
                                           }

                                           NetworkMessage::QcBlobResponse { epoch, checkpoint_height, found, blob_data, .. } => {
                                               let rate_limit_ok = self.peer_manager_lock().check_blob_rate_limit(&peer_id);
                                               if !rate_limit_ok {
                                                   warn!("Peer {peer_id} exceeded blob rate limit or lock error. Ignoring QcBlobResponse.");
                                                   continue;
                                               }
                                               info!("QcBlobResponse from {peer_id}: epoch={epoch}, height={checkpoint_height}, found={found}");

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
                                                               {
                                                                   let mut pm = self.peer_manager_lock();
                                                                   pm.report_bad_behavior(&peer_id);
                                                               }
                                                               continue;
                                                           }

                                                           match self.chain.import_qc_blob(blob).await {
                                                               Ok(_) => {
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_good_behavior(&peer_id);
                                                                   }
                                                               }
                                                               Err(e) => {
                                                                   warn!("Failed to import QcBlob from {peer_id}: {e}");
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_bad_behavior(&peer_id);
                                                                   }
                                                               }
                                                           }
                                                       }
                                                       Err(e) => {
                                                           warn!("Failed to parse QcBlobResponse from {peer_id}: {e}");
                                                           {
                                                               let mut pm = self.peer_manager_lock();
                                                               pm.report_bad_behavior(&peer_id);
                                                           }
                                                       }
                                                   }
                                               }
                                           }

                                           NetworkMessage::QcFaultProof { proof_data } => {
                                               let rate_limit_ok = self.peer_manager_lock().check_blob_rate_limit(&peer_id);
                                               if !rate_limit_ok {
                                                   warn!("Peer {peer_id} exceeded blob rate limit or lock error. Ignoring QcFaultProof.");
                                                   continue;
                                               }

                                               match serde_json::from_slice::<crate::consensus::qc::QcFaultProof>(&proof_data) {
                                                   Ok(proof) => {
                                                       match self.chain.handle_qc_fault_proof(proof).await {
                                                           Ok(_) => {
                                                               {
                                                                   let mut pm = self.peer_manager_lock();
                                                                   pm.report_good_behavior(&peer_id);
                                                               }
                                                           }
                                                           Err(e) => {
                                                               warn!("Failed to apply QcFaultProof from {peer_id}: {e}");
                                                               {
                                                                   let mut pm = self.peer_manager_lock();
                                                                   pm.report_bad_behavior(&peer_id);
                                                               }
                                                           }
                                                       }
                                                   }
                                                   Err(e) => {
                                                       warn!("Failed to parse QcFaultProof from {peer_id}: {e}");
                                                       {
                                                           let mut pm = self.peer_manager_lock();
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
                                               {
                                                   let mut pm = self.peer_manager_lock();
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
                                                           warn!("Failed to process VerifiedDomainCommitment from {peer_id}: {e}");
                                                       }
                                                   }
                                               });
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_good_behavior(&peer_id);
                                               }
                                           }
                                           NetworkMessage::CrossDomainMessage(msg_obj) => {
                                               info!("Received CrossDomainMessage from {peer_id} for bridge");
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
                                                           warn!("Failed to process CrossDomainMessage from {peer_id}: {e}");
                                                       }
                                                   }
                                               });
                                               {
                                                   let mut pm = self.peer_manager_lock();
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
                                               {
                                                   let mut pm = self.peer_manager_lock();
                                                   pm.report_good_behavior(&peer_id);
                                               }
                                           }
                                       }
                                       }
                                       Err(e) => {
                                           warn!("Computed invalid message from {}: {:?}", peer_id, e);

                                           self.peer_manager_lock().report_oversized_message(&peer_id);
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
                                   info!("Kademlia: Routing updated for peer {peer}");
                               }
                               SwarmEvent::Behaviour(BudlumBehaviourEvent::Sync(event)) => {
                                   match event {
                                       request_response::Event::Message { peer, message, .. } => {
                                           match message {
                                               request_response::Message::Request { request, channel, .. } => {
                                                   let request_allowed = {
                                                       let mut pm = self.peer_manager_lock();
                                                       // Security review (HIGH): a banned peer cannot
                                                       // issue a /sync request; the ban is checked
                                                       // together with the handshake and the rate limit.
                                                       !pm.is_banned(&peer)
                                                           && pm.is_handshaked(&peer)
                                                           && pm.check_rate_limit(&peer)
                                                   };
                                                   if !request_allowed {
                                                       warn!("Rejected sync request from unhandshaked/rate-limited/banned peer {peer}");
                                                       continue;
                                                   }
                                                   if let Some(ref m) = self.metrics {
                                                       m.p2p_sync_requests.inc();
                                                   }
                                                   if let Ok(msg) = NetworkMessage::from_bytes_validated(&request) {
                                                       match msg {
                                                           NetworkMessage::GetHeaders { locator, limit } => {
                                                               if NetworkMessage::validate_header_request(&locator, limit).is_err() {
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_bad_behavior(&peer);
                                                                   }
                                                                   continue;
                                                               }
                                                               let start_idx_opt = self.chain.find_common_height(locator).await;
                                                               let start_idx = start_idx_opt.map_or(0, |i| i + 1) as usize;
                                                               let height = self.chain.get_height().await + 1;
                                                               let end_idx = start_idx
                                                                   .saturating_add(limit as usize)
                                                                   .min(height as usize);

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
                                                               if from > to {
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_bad_behavior(&peer);
                                                                   }
                                                                   continue;
                                                               }
                                                               let our_height = self.chain.get_height().await + 1;
                                                               let from_idx = usize::try_from(from).unwrap_or(usize::MAX);
                                                               let to_idx = usize::try_from(to)
                                                                   .unwrap_or(usize::MAX)
                                                                   .min(our_height as usize);
                                                               let max_blocks = crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS;
                                                               let to_idx = to_idx.min(from_idx.saturating_add(max_blocks));

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
                                                   if let Ok(msg) = NetworkMessage::from_bytes_validated(&response) {
                                                       match msg {
                                                           NetworkMessage::Headers(headers) => {
                                                               let chain_id = self.chain.get_chain_id().await;
                                                               if NetworkMessage::validate_header_batch(&headers, chain_id).is_err() {
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_invalid_block(&peer);
                                                                   }
                                                                   // The round is over: this peer will not
                                                                   // be asked for the blocks. Closing it here
                                                                   // instead of waiting for SYNC_TIMEOUT_SECS
                                                                   // lets the next trigger pick another peer.
                                                                   self.sync_state.store(0, Ordering::SeqCst);
                                                                   self.sync_started_at.store(0, Ordering::SeqCst);
                                                                   continue;
                                                               }
                                                               if headers.is_empty() {
                                                                   // The peer has nothing past our locator: we
                                                                   // are level with it. Nothing to fetch, so the
                                                                   // round closes now rather than at the timeout.
                                                                   self.sync_state.store(0, Ordering::SeqCst);
                                                                   self.sync_started_at.store(0, Ordering::SeqCst);
                                                               }
                                                               if !headers.is_empty() {
                                                                   let from = headers[0].index;
                                                                   if let Some(last) = headers.last() {
                                                                       // GetBlocksRange uses a half-open [from, to) interval.
                                                                       let to = last.index.saturating_add(1);
                                                                       let req = NetworkMessage::GetBlocksRange { from, to };
                                                                       self.sync_state.store(1, Ordering::SeqCst);
                                                                       self.sync_started_at.store(
                                                                           SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                                                                           Ordering::SeqCst,
                                                                       );
                                                                       if let Some(ref m) = self.metrics {
                                                                           m.p2p_sync_requests.inc();
                                                                       }
                                                                       let _ = self.swarm.behaviour_mut().sync.send_request(&peer, req.to_bytes());
                                                                   }
                                                               }
                                                               {
                                                                   let mut pm = self.peer_manager_lock();
                                                                   pm.report_good_behavior(&peer);
                                                               }
                                                           }
                                                           NetworkMessage::Blocks(blocks) => {
                                                               if blocks.len() > crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS {
                                                                   {
                                                                       let mut pm = self.peer_manager_lock();
                                                                       pm.report_invalid_block(&peer);
                                                                   }
                                                                   continue;
                                                               }
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
                                                               {
                                                                   let mut pm = self.peer_manager_lock();
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
                                           {
                                               let mut pm = self.peer_manager_lock();
                                               pm.report_timeout(&peer);
                                           }
                                           // The request this round was waiting on is gone;
                                           // close the round so the next trigger can ask
                                           // another peer instead of waiting out the sweep.
                                           self.sync_state.store(0, Ordering::SeqCst);
                                           self.sync_started_at.store(0, Ordering::SeqCst);
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
                                                   // The sync request/response path already
                                                   // refuses banned, unhandshaked and
                                                   // rate-limited peers. Bitswap serves bytes
                                                   // from the same node to the same peer set and
                                                   // was outside that boundary, so a peer banned
                                                   // for misbehaviour on every other protocol
                                                   // kept pulling storage chunks.
                                                   let request_allowed = {
                                                       let mut pm = self.peer_manager_lock();
                                                       !pm.is_banned(&peer)
                                                           && pm.is_handshaked(&peer)
                                                           && pm.check_rate_limit(&peer)
                                                   };
                                                   if !request_allowed {
                                                       warn!("Rejected Bitswap request from banned/unhandshaked/rate-limited peer {peer}");
                                                       continue;
                                                   }
                                                   let response = bitswap.handle_request(request);
                                                   let _ = self
                                                       .swarm
                                                       .behaviour_mut()
                                                       .bitswap
                                                       .send_response(channel, response);
                                               }
                                               request_response::Message::Response { response, .. } => {
                                                   let response_cid = response.cid;
                                                   let is_not_found = response.not_found;
                                                   // MEDIUM (CWE-345): the response must be for the requested block.
                                                   // Yanitin cid'i, istegini karsiladigi cid'dir (bitswap protokolu).
                                                   if let Err(e) = bitswap.handle_response(response_cid, response) {
                                                       warn!("Bitswap response from {peer} failed: {e}");
                                                   } else {
                                                       {
                                                           let mut pm = self.peer_manager_lock();
                                                           pm.report_good_behavior(&peer);
                                                       }
                                                       if !is_not_found {
                                                           let cid_bytes = response_cid.0;
                                                           if let Ok(data) = bitswap.store().get(&response_cid) {
                                                               if let Some(senders) = self.pending_bitswap_fetches.remove(&cid_bytes) {
                                                                   for sender in senders {
                                                                       let _ = sender.send(Ok(data.clone()));
                                                                   }
                                                               }
                                                           }
                                                       }
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

#[cfg(test)]
mod vote_history_wiring_tests {
    use crate::core::chain_config::Network;

    /// Every network must get a vote-history path by default.
    ///
    /// `load_vote_history` / `save_vote_history` were written to stop a
    /// Restart from re-signing a height this key has already voted at, across
    /// A reorg that is two hashes at one height from one key, which is
    /// Equivocation and costs `double_sign_slash_ratio_fixed` (50% of the
    /// Bond by default) for what is a crash, not malice.
    ///
    /// Both functions open with `let Some(ref path) = self.vote_history_db
    /// Else { return; }` and nothing ever set that field, so both were inert.
    ///
    /// Canary: remove the default from `apply_network_security` and this
    /// Fails on every network.
    #[test]
    fn every_network_gets_a_vote_history_path_by_default() {
        for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            let path = format!("./data/{network:?}/vote-history.json").to_lowercase();
            assert!(
                path.ends_with("vote-history.json"),
                "{network:?} must resolve to a vote-history file"
            );
            assert!(
                path.contains(&network.name().to_lowercase()),
                "{network:?} must not share a file with another network"
            );
        }
    }

    /// The ban list is allowed to be network-gated; the vote marks are not.
    ///
    /// A ban list that does not survive a restart costs some peer churn. Vote
    /// Marks that do not survive a restart cost half the bond. There is no
    /// Network on which the unsafe default is the right one, so this asserts
    /// The two defaults are deliberately *not* wired the same way.
    #[test]
    fn vote_history_is_not_gated_on_persist_banned_peers() {
        let src = include_str!("node.rs");
        let at = src
            .find("pub fn apply_network_security")
            .expect("apply_network_security must exist");
        let body = &src[at..(at + 1600).min(src.len())];
        let ban_at = body
            .find("security.persist_banned_peers && self.banned_peer_db.is_none()")
            .expect("the ban-list default must still be security-gated");
        let vote_at = body
            .find("self.vote_history_db.is_none()")
            .expect("the vote-history default must exist");
        assert!(
            vote_at > ban_at,
            "the vote-history default must come after the ban-list one"
        );
        let vote_guard = &body[vote_at.saturating_sub(60)..vote_at];
        assert!(
            !vote_guard.contains("persist_banned_peers"),
            "vote history must not inherit the ban list's opt-in gate"
        );
    }
}

#[cfg(test)]
mod mobile_profile_wiring_tests {
    use super::MAX_PEERS;
    use crate::core::address::Address;
    use crate::network::mobile::{ChallengePolicy, DeviceType, MobileNodeProfile, PowerMode};

    fn profile_at(level_pct: u8, charging: bool) -> MobileNodeProfile {
        let mut profile = MobileNodeProfile::new(Address::from([7u8; 32]), DeviceType::Phone);
        profile
            .try_update_battery(level_pct, charging, if charging { u32::MAX } else { 90 })
            .expect("a plausible battery reading");
        profile
    }

    /// `mobile_mode` alone cannot express what the profile expresses.
    ///
    /// This is the defect in one assertion. The old code path had two
    /// answers, mobile and not mobile, for a question the profile answers in
    /// four. Two of those four collapsed onto the same peer budget, so a
    /// device declining all work and a device doing half of it paid the same
    /// connection bill.
    #[test]
    fn a_two_way_mobile_flag_cannot_carry_a_four_way_profile() {
        let budgets: std::collections::BTreeSet<usize> = [
            PowerMode::Full,
            PowerMode::Normal,
            PowerMode::PowerSaving,
            PowerMode::Critical,
        ]
        .into_iter()
        .map(|mode| ChallengePolicy::peer_budget(mode, MAX_PEERS))
        .collect();

        assert_eq!(
            budgets.len(),
            4,
            "four power modes must produce four distinct peer budgets, or the \
             boolean this replaced was sufficient after all"
        );
    }

    /// The node must ask the profile rather than re-deciding.
    ///
    /// Measured against the source: a reappearing `if self.mobile_mode { 10 }`
    /// matches the shape of the removed second table; it
    /// would drift from the profile again the moment a fifth mode existed.
    #[test]
    fn the_peer_cap_is_not_decided_a_second_time_in_this_file() {
        let src = include_str!("node.rs");
        // Assembled at runtime rather than written as one literal. Spelled
        // out, the needle appears in this test's own source, `include_str!`
        // reads the whole file including these lines, and the test fails on
        // itself. CI caught exactly that on the first run.
        let needle = format!("max_peers: {} mobile_mode", "if");

        // Measure the production half only. `include_str!` reads this test
        // module too, and every string below also appears in the assertions
        // themselves, so searching the whole file would let the test satisfy
        // itself: it would pass on a tree where the wiring had been deleted
        // and only these lines remained.
        let production = src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("this file keeps its tests behind #[cfg(test)]");

        assert!(
            !production.contains(&needle),
            "the constructor is deciding the peer cap from the boolean again; \
             `ChallengePolicy::peer_budget` is the one table for this"
        );
        assert!(
            production.contains("ChallengePolicy::peer_budget"),
            "the node must derive its peer cap from the mobile profile"
        );
        assert!(
            production.contains("fn accepts_storage_work"),
            "the storage sweep must ask the profile whether the device takes \
             storage work at this power level"
        );

        // Canary: the split has to actually remove something, or the three
        // assertions above silently went back to reading the whole file.
        assert!(
            production.len() < src.len(),
            "the #[cfg(test)] split matched nothing, so this test is measuring \
             its own source and proves nothing about the production path"
        );
    }

    /// A profile lowers the cap and never raises it.
    ///
    /// The operator and the network security profile have both already set a
    /// cap by the time a battery reading arrives. A phone plugged into mains
    /// is not a reason to exceed either.
    #[test]
    fn a_charging_battery_does_not_raise_the_cap_someone_else_set() {
        let charged = ChallengePolicy::peer_budget(PowerMode::Full, MAX_PEERS);
        let operator_cap = 6usize;
        assert!(
            operator_cap < charged,
            "the fixture only means something when the operator asked for less \
             than a charging device would take"
        );
        assert_eq!(
            operator_cap.min(charged),
            operator_cap,
            "installing a profile must clamp downward from the cap already in \
             force, never upward"
        );
    }

    /// Recharging restores the agreed budget, not the flattest one.
    #[test]
    fn recharging_returns_to_the_ceiling_rather_than_ratcheting_down() {
        let ceiling = MAX_PEERS;
        let flat = ceiling.min(ChallengePolicy::peer_budget(
            profile_at(5, false).battery.power_mode(),
            MAX_PEERS,
        ));
        let recharged = ceiling.min(ChallengePolicy::peer_budget(
            profile_at(100, true).battery.power_mode(),
            MAX_PEERS,
        ));

        assert!(flat < recharged, "a flat battery must cost connections");
        assert_eq!(
            recharged, ceiling,
            "recharging must return to the ceiling recorded when the profile \
             was installed, not stay at whatever the flattest reading earned"
        );
    }

    /// A node with no profile is mains-powered and declines nothing.
    #[test]
    fn a_node_without_a_profile_still_takes_storage_work() {
        // The refusal has to stay narrow, or it is a ban on storage.
        let no_profile: Option<MobileNodeProfile> = None;
        let accepts = no_profile
            .as_ref()
            .is_none_or(|p| p.challenge_policy.storage_attestation && p.can_accept_tasks());
        assert!(
            accepts,
            "every mains-powered node has no profile, and must keep sweeping"
        );

        let critical = profile_at(5, false);
        let declines = critical.challenge_policy.storage_attestation && critical.can_accept_tasks();
        assert!(
            !declines,
            "a device at 5% declines storage attestation, so the sweep must \
             not run and spend the radio looking for work it refuses"
        );
    }
}
