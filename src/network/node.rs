use crate::network::protocol::NetworkMessage;
use libp2p::{
    futures::StreamExt,
    gossipsub, identify, identity,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    },
    noise, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, tls, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::{HashMap, VecDeque};
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
/// Concurrent request/response streams per connection. The libp2p default is
/// 100; with a 1 MiB request ceiling that pins 100 MiB or more per peer.
const MAX_SYNC_CONCURRENT_STREAMS: usize = 16;
const MAX_PENDING_BITSWAP_FETCH_WAITERS: usize = 128;
/// QC blobs assembled at once, across all peers.
const MAX_QC_ASSEMBLIES: usize = 8;
/// A slow or malicious peer cannot occupy every outbound fetch slot.
const MAX_QC_FETCHES_PER_PEER: usize = 1;
/// A single peer cannot occupy the entire global serve table.
const MAX_QC_SERVES_PER_PEER: usize = 2;
/// Pending validated certificates retained for fetching when all slots are
/// busy. The chain retains 100 pending certificates by default.
const MAX_PENDING_QC_REQUESTS: usize = 128;
const QC_RETRY_DELAY: Duration = Duration::from_secs(5);
/// How long a partly received QC blob is kept.
const QC_ASSEMBLY_TTL: Duration = Duration::from_secs(120);
/// Most validators a QC blob may name on the wire. The snapshot check at
/// import is the exact bound; this one only limits what is buffered before it.
const MAX_QC_WIRE_VALIDATORS: usize = 2048;

/// A QC response is accepted only for a request we made to this peer. Each
/// request asks for exactly one chunk; the next is requested after validation.
#[derive(Clone)]
struct QcFetch {
    peer: PeerId,
    epoch: u64,
    height: u64,
    checkpoint_hash: String,
    chunk_index: u32,
    chunk_count: Option<u32>,
}

#[derive(Clone)]
struct PendingQcFetch {
    epoch: u64,
    height: u64,
    checkpoint_hash: String,
    preferred: Option<PeerId>,
    last_peer: Option<PeerId>,
    ready_at: std::time::Instant,
}

fn enqueue_qc_fetch(queue: &mut VecDeque<PendingQcFetch>, pending: PendingQcFetch) {
    if let Some(existing) = queue.iter_mut().find(|existing| {
        existing.epoch == pending.epoch
            && existing.height == pending.height
            && existing.checkpoint_hash == pending.checkpoint_hash
    }) {
        // A new announcing peer is an opportunity to retry, not a second job.
        if pending.preferred.is_some() && pending.preferred != existing.last_peer {
            existing.preferred = pending.preferred;
            existing.ready_at = pending.ready_at;
        }
        return;
    }
    if queue.len() >= MAX_PENDING_QC_REQUESTS {
        // The chain's own pending-cert book also evicts oldest entries.
        queue.pop_front();
        warn!("QC retry queue full; dropped its oldest request");
    }
    queue.push_back(pending);
}

fn select_qc_peer(
    peers: &[PeerId],
    occupied: &HashMap<PeerId, usize>,
    preferred: Option<PeerId>,
    last_peer: Option<PeerId>,
) -> Option<PeerId> {
    let mut ordered: Vec<_> = peers
        .iter()
        .copied()
        .filter(|peer| occupied.get(peer).copied().unwrap_or(0) < MAX_QC_FETCHES_PER_PEER)
        .collect();
    if let Some(peer) = preferred.filter(|p| Some(*p) != last_peer && ordered.contains(p)) {
        return Some(peer);
    }
    // Visit every eligible peer before cycling, not merely the first peer
    // different from the previous one (which can starve a third peer).
    ordered.sort_by_key(|peer| peer.to_bytes());
    if ordered.is_empty() {
        return None;
    }
    let next = last_peer
        .and_then(|last| ordered.iter().position(|peer| *peer == last))
        .map_or(0, |index| (index + 1) % ordered.len());
    Some(ordered[next])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QcServeAdmission {
    Start,
    Continue,
    Busy,
    Invalid,
}

type QcServeTable = HashMap<(PeerId, u64, u64), (std::time::Instant, u32)>;

fn qc_serve_admission(
    serves: &QcServeTable,
    peer: PeerId,
    epoch: u64,
    height: u64,
    chunk_index: u32,
    max_chunks: usize,
) -> QcServeAdmission {
    if height == 0 || chunk_index as usize >= max_chunks {
        return QcServeAdmission::Invalid;
    }
    let key = (peer, epoch, height);
    if chunk_index == 0 {
        if serves.contains_key(&key)
            || serves.len() >= MAX_QC_ASSEMBLIES
            || serves
                .keys()
                .filter(|(holder, _, _)| *holder == peer)
                .count()
                >= MAX_QC_SERVES_PER_PEER
        {
            QcServeAdmission::Busy
        } else {
            QcServeAdmission::Start
        }
    } else {
        match serves.get(&key) {
            Some((_, next)) if *next == chunk_index => QcServeAdmission::Continue,
            Some(_) => QcServeAdmission::Invalid,
            // A server may have released an old/expired transfer while the
            // client was in flight. Ask it to restart; do not blame the peer.
            None => QcServeAdmission::Busy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QcResponseAction {
    InProgress,
    Imported,
    Missing,
}

/// Build a single bounded peer-bound response, never a gossip broadcast.
fn qc_chunk_response(
    epoch: u64,
    height: u64,
    index: u32,
    blob: Option<crate::consensus::qc::QcBlob>,
) -> Result<NetworkMessage, String> {
    let missing = || NetworkMessage::QcBlobResponse {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: String::new(),
        blob_data: Vec::new(),
        found: false,
        chunk_index: index,
        chunk_count: 0,
    };
    let Some(blob) = blob else {
        return Ok(missing());
    };
    if height == 0
        || blob.epoch != epoch
        || blob.checkpoint_height != height
        || !blob.verify_merkle_root()
        || blob.pq_signatures.len() > MAX_QC_WIRE_VALIDATORS
    {
        return Ok(missing());
    }
    let payload = blob.to_bytes()?;
    let chunk_bytes = crate::consensus::qc::QC_CHUNK_BYTES;
    let count =
        u32::try_from(payload.len().div_ceil(chunk_bytes)).map_err(|_| "too many QC chunks")?;
    if count == 0 || index >= count {
        return Ok(missing());
    }
    let start = index as usize * chunk_bytes;
    Ok(NetworkMessage::QcBlobResponse {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: blob.checkpoint_hash,
        blob_data: payload[start..payload.len().min(start + chunk_bytes)].to_vec(),
        found: true,
        chunk_index: index,
        chunk_count: count,
    })
}

/// Double sign guard for precommits.
///
/// The node signs the aggregator's checkpoint, so the guard must compare that
/// height, not the height of the local tip checkpoint. A precommit at or below
/// the last one signed could carry a different hash after a reorg, which is a
/// slashable double sign, and would move the persisted mark backwards.
fn precommit_height_is_new(signed_height: u64, last_precommit_height: u64) -> bool {
    signed_height > last_precommit_height
}

/// Whether a refused vote was refused for belonging to another round rather
/// than for being wrong.
///
/// A vote only counts in an aggregator holding its own checkpoint, and an
/// aggregator holds one round at a time: a validator one block behind signs
/// the checkpoint it sees, and every node whose round has already moved on
/// refuses it. That voter is honest - it is at a different tip, which the
/// fork choice resolves - so the refusal says nothing about the sender.
/// Charging bad behaviour for it is how a mesh bans its own validators, which
/// is what the devnet did once the vote beat got fast enough to produce
/// cross-round votes.
///
/// Membership belongs on the same list. An aggregator checks a vote against
/// the validator snapshot it built for its own epoch, and that snapshot is
/// taken from the state this node holds: across an epoch boundary a node one
/// block behind still has the previous set, so a vote from a validator that
/// joined - or one whose keys landed in the current block - reads as a
/// stranger. The voter is a member; the reader is late.
fn refusal_is_round_scope(error: &str) -> bool {
    [
        "Prevote epoch mismatch",
        "Prevote checkpoint height mismatch",
        "Precommit epoch mismatch",
        "Precommit checkpoint height mismatch",
        "Duplicate prevote",
        "Duplicate precommit",
        "Cannot precommit before prevote quorum",
        "No active finality aggregator",
        "Voter not in validator set",
    ]
    .iter()
    .any(|refusal| error.contains(refusal))
}

/// First `max_chars` characters of a peer controlled string, for log lines.
///
/// A byte slice such as `&s[..16]` panics when byte 16 is inside a multi byte
/// character, and a release node aborts on panic.
fn log_prefix(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

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
    /// `/budlum/witness/1.0.0`: witnesses of a block for a node that
    /// pruned them, checked against the block's `witness_root`.
    witness: request_response::Behaviour<crate::network::witness_protocol::WitnessCodec>,
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
use crate::network::regen_health_tick::{Checkpoint, CheckpointView, RegenHealthTick, TickOutcome};
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
    /// Operator RPC (`bud_adminBanPeer`): ban a peer through the same peer
    /// manager the gossip path consults; ban persistence stays on its
    /// existing cadence.
    AdminBanPeer {
        peer_id: PeerId,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Operator RPC (`bud_adminUnbanPeer`): lift a ban by peer id.
    AdminUnbanPeer {
        peer_id: PeerId,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Operator RPC (`bud_adminListBannedPeers`): list currently banned ids.
    AdminListBannedPeers {
        response: oneshot::Sender<Result<Vec<String>, String>>,
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

    /// Convenience: the backpressured twin of [`Self::storage_prune_sync`]
    /// for async embedders of this client. The in-tree console keeps the
    /// sync form on purpose: it fires just after block production, where a
    /// saturated command channel must not stall production.
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

    /// Bans a peer by id through the node loop (`bud_adminBanPeer`). The
    /// public RPC listener never reaches this; the operator listener calls
    /// it after its own mode check.
    pub async fn admin_ban_peer(&self, peer_id: PeerId) -> Result<(), String> {
        const ADMIN_BAN_TIMEOUT: Duration = Duration::from_secs(5);
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(NodeCommand::AdminBanPeer {
                peer_id,
                response: tx,
            })
            .await
            .map_err(|e| format!("failed to send ban request: {e}"))?;
        tokio::time::timeout(ADMIN_BAN_TIMEOUT, rx)
            .await
            .map_err(|_| "peer ban timed out".to_string())?
            .map_err(|e| format!("failed to receive ban response: {e}"))?
    }

    /// Lifts a ban by peer id (`bud_adminUnbanPeer`); operator listener only.
    pub async fn admin_unban_peer(&self, peer_id: PeerId) -> Result<(), String> {
        const ADMIN_UNBAN_TIMEOUT: Duration = Duration::from_secs(5);
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(NodeCommand::AdminUnbanPeer {
                peer_id,
                response: tx,
            })
            .await
            .map_err(|e| format!("failed to send unban request: {e}"))?;
        tokio::time::timeout(ADMIN_UNBAN_TIMEOUT, rx)
            .await
            .map_err(|_| "peer unban timed out".to_string())?
            .map_err(|e| format!("failed to receive unban response: {e}"))?
    }

    /// Lists currently banned peer ids (`bud_adminListBannedPeers`);
    /// operator listener only.
    pub async fn admin_list_banned_peers(&self) -> Result<Vec<String>, String> {
        const ADMIN_LIST_TIMEOUT: Duration = Duration::from_secs(5);
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(NodeCommand::AdminListBannedPeers { response: tx })
            .await
            .map_err(|e| format!("failed to send banned-peer list request: {e}"))?;
        tokio::time::timeout(ADMIN_LIST_TIMEOUT, rx)
            .await
            .map_err(|_| "banned-peer list timed out".to_string())?
            .map_err(|e| format!("failed to receive banned-peer list response: {e}"))?
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

/// Writes the identity key file. On unix the file is created with mode 0600,
/// so it is never readable by other users, not even briefly.
fn write_identity_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

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
                if let Err(e) = write_identity_file(file_path, &encoded) {
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

/// The gossipsub author signature is not a consensus input.
///
/// `MessageAuthenticity::Signed` makes the swarm sign every message with the
/// node's Ed25519 identity key. That signature only says which peer relayed or
/// authored a gossip frame; it is a classical signature and carries no
/// security weight. No consensus decision rests on it: a block, a vote, an
/// evidence record or a certificate is accepted on the composite signature
/// inside its own payload, never on the gossip author. The one place the author
/// field is read is the handshake, where it ties the handshake to the sending
/// connection, and a forged author there only gets the frame dropped. The
/// `gossip_author_is_not_a_consensus_input` test pins this by scanning this
/// file for every read of the field.
fn handshake_origin_matches_peer(
    propagation_source: PeerId,
    message_source: Option<PeerId>,
) -> bool {
    message_source == Some(propagation_source)
}

/// What a peer says about itself when it handshakes, in either direction.
struct HandshakeFields {
    version_major: u32,
    version_minor: u32,
    chain_id: u64,
    best_height: u64,
    validator_set_hash: String,
    supported_schemes: Vec<String>,
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
    /// QC blobs in flight, one assembly per `(peer, epoch, height)`. At most
    /// [`MAX_QC_ASSEMBLIES`] at once, and each one expires after
    /// [`QC_ASSEMBLY_TTL`].
    qc_assemblies:
        HashMap<(PeerId, u64, u64), (std::time::Instant, crate::consensus::qc::QcBlobAssembler)>,
    qc_fetches: HashMap<request_response::OutboundRequestId, QcFetch>,
    /// Bounded work deferred by capacity, missing responses, or disconnects.
    pending_qc_fetches: VecDeque<PendingQcFetch>,
    /// Bounded in-progress deliveries: subsequent chunks spend the first
    /// chunk's blob rate token, never a new token per 256 KiB frame.
    qc_serves: QcServeTable,
    pub bootstrap_peers: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub dns_seed_port: u16,
    pub peer_count: Arc<AtomicUsize>,
    pub sync_state: Arc<AtomicUsize>,
    /// Timestamp when sync_state was set to 1.
    pub sync_started_at: Arc<AtomicU64>,
    /// Outbound request currently responsible for the one active sync round.
    active_sync_request: Option<request_response::OutboundRequestId>,
    pub pending_bitswap_fetches: PendingBitswapFetches,
    /// The content id each outbound Bitswap request asked for. A response is
    /// checked against this, not against the cid the response claims.
    bitswap_requests: HashMap<request_response::OutboundRequestId, bud_node::store::ContentId>,
    /// Target peer for each in-flight Bitswap request so `ConnectionClosed`
    /// retires only requests sent to the peer whose connection actually closed.
    bitswap_request_peers: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Outstanding Bitswap answers per content id. A
    /// waiters list used to be removed only when a response delivered data;
    /// every `not_found`, every malformed response and every disconnected
    /// peer left the entry - and the callers in it - in the map forever.
    /// Each outbound request per peer is one attempt; when the last attempt
    /// fails by any route, the waiters are answered with the failure and the
    /// entry is dropped.
    bitswap_pending_attempts: HashMap<[u8; 32], usize>,
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
    /// The reversion ledger the regeneration health tick assesses and moves.
    ///
    /// Node-local and in memory: the ledger records what this node verified
    /// about its own view against the finality certificates, and it starts
    /// again from the live checkpoint on restart.
    regen_health: RegenHealthTick,
    /// Transactions a reversion gave up, offered again after re-growth
    ///, and the height the stash starts above.
    regen_mempool: crate::domain::RegenMempool,
    regen_stash_from: Option<u64>,
    /// Witness requests in flight, with the root the answer must hash to.
    witness_requests: HashMap<
        request_response::OutboundRequestId,
        (
            crate::network::witness_protocol::WitnessRequest,
            [u8; 32],
            PeerId,
        ),
    >,
    /// Single-flight guard ensuring peer-supplied fork batches can keep at
    /// most one `reorg_to_peer_suffix` task running at a time (CWE-407).
    reorg_in_flight: Arc<std::sync::atomic::AtomicBool>,
    /// When the last peer-triggered reconstruction FINISHED, in Unix seconds.
    ///
    /// Single-flight bounds how many reconstructions overlap, not how often
    /// they happen: a peer that publishes a fork batch every block keeps the
    /// node rebuilding its chain forever, one at a time. The interval is
    /// measured from completion, not from start, so a slow reconstruction is
    /// never doubled up by the next one starting while its cost is still
    /// being paid.
    reorg_last_completed_at: Arc<AtomicU64>,
}

/// RAII token releasing [`Node::reorg_in_flight`] when the active reorg task exits.
struct ReorgFlightGuard(Arc<std::sync::atomic::AtomicBool>);

impl ReorgFlightGuard {
    fn try_acquire(flag: &Arc<std::sync::atomic::AtomicBool>) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(Arc::clone(flag)))
    }
}

impl Drop for ReorgFlightGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Shortest interval between two peer-triggered chain reconstructions.
///
/// Five minutes: long enough that a peer broadcasting a fork batch every block
/// cannot make the node re-walk its chain continuously, short enough that a
/// genuine fork seen from a new peer is still adopted long before a human
/// notices. A node that is actually behind does not depend on this path - it
/// asks for the blocks it is missing over `/sync`, which is self-initiated and
/// not throttled here.
const REORG_MIN_INTERVAL_SECS: u64 = 300;

/// Has the minimum interval passed since the last reconstruction finished?
///
/// `>=` on the boundary, and `saturating_sub` so a clock that steps backwards
/// reads as "no time has passed" rather than as an enormous elapsed interval.
fn reorg_interval_elapsed(last_completed: &AtomicU64, now: u64) -> bool {
    now.saturating_sub(last_completed.load(Ordering::Acquire)) >= REORG_MIN_INTERVAL_SECS
}

/// One attempted reconstruction: releases the single-flight flag and stamps
/// the completion time when the attempt ends, however it ends.
struct ReorgSlot {
    reorg: ReorgFlightGuard,
    last_completed: Arc<AtomicU64>,
}

impl Drop for ReorgSlot {
    fn drop(&mut self) {
        // Touch the guard so its ownership is part of what this value holds:
        // it is released when this slot drops, right after the stamp below.
        let _ = &self.reorg;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_completed.store(now, Ordering::Release);
    }
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
    /// Adds one chunk of a QC blob to its assembly. Returns the blob when the
    /// last chunk arrives, `None` while chunks are missing.
    ///
    /// # Errors
    ///
    /// A message when the chunk is out of range, repeated, oversize, the
    /// assembly table is full of other blobs, or the finished bytes do not
    /// decode.
    /// PARTIAL: allowed - a chunk that fails to push discards the whole
    /// assembly on purpose: a half-assembled blob whose failed chunk
    /// vanished could later complete from chunks the failure already
    /// rejected; the error tells the peer to restart the transfer.
    fn assemble_qc_chunk(
        &mut self,
        peer: PeerId,
        epoch: u64,
        height: u64,
        chunk_index: u32,
        chunk_count: u32,
        chunk: Vec<u8>,
    ) -> Result<Option<crate::consensus::qc::QcBlob>, String> {
        use crate::consensus::qc::QcBlobAssembler;
        let now = std::time::Instant::now();
        self.qc_assemblies
            .retain(|_, (started, _)| now.duration_since(*started) < QC_ASSEMBLY_TTL);
        let key = (peer, epoch, height);
        if !self.qc_assemblies.contains_key(&key) {
            if self.qc_assemblies.len() >= MAX_QC_ASSEMBLIES {
                return Err("too many QC blobs are being assembled".into());
            }
            let assembler = QcBlobAssembler::new(MAX_QC_WIRE_VALIDATORS, chunk_count as usize)?;
            self.qc_assemblies.insert(key, (now, assembler));
        }
        let outcome = match self.qc_assemblies.get_mut(&key) {
            Some((_, assembler)) => assembler.push(chunk_index as usize, chunk),
            None => Err("QC assembly vanished".to_string()),
        };
        if let Err(e) = outcome {
            self.qc_assemblies.remove(&key);
            return Err(e);
        }
        let complete = self
            .qc_assemblies
            .get(&key)
            .is_some_and(|(_, assembler)| assembler.is_complete());
        if !complete {
            return Ok(None);
        }
        match self.qc_assemblies.remove(&key) {
            Some((_, assembler)) => assembler.finish().map(Some),
            None => Err("QC assembly vanished".into()),
        }
    }

    /// Queue a validated missing QC, even when all fetch slots are busy.
    fn request_qc_blob(&mut self, peer: PeerId, epoch: u64, height: u64, hash: String) {
        if height == 0
            || hash.len() > 128
            || self
                .qc_fetches
                .values()
                .any(|f| f.epoch == epoch && f.height == height && f.checkpoint_hash == hash)
        {
            return;
        }
        enqueue_qc_fetch(
            &mut self.pending_qc_fetches,
            PendingQcFetch {
                epoch,
                height,
                checkpoint_hash: hash,
                preferred: Some(peer),
                last_peer: None,
                ready_at: std::time::Instant::now(),
            },
        );
        self.drain_qc_fetches();
    }

    fn retry_qc_fetch(&mut self, fetch: &QcFetch) {
        enqueue_qc_fetch(
            &mut self.pending_qc_fetches,
            PendingQcFetch {
                epoch: fetch.epoch,
                height: fetch.height,
                checkpoint_hash: fetch.checkpoint_hash.clone(),
                preferred: None,
                last_peer: Some(fetch.peer),
                ready_at: std::time::Instant::now() + QC_RETRY_DELAY,
            },
        );
    }

    /// Drain at most the queue's initial size: disconnected peers and retry
    /// delays cannot make the node loop spin. Each retry chooses a different
    /// eligible peer when available and starts again at chunk zero.
    fn drain_qc_fetches(&mut self) {
        let count = self.pending_qc_fetches.len();
        for _ in 0..count {
            if self.qc_fetches.len() >= MAX_QC_ASSEMBLIES {
                break;
            }
            let Some(pending) = self.pending_qc_fetches.pop_front() else {
                break;
            };
            if pending.ready_at > std::time::Instant::now() {
                self.pending_qc_fetches.push_back(pending);
                continue;
            }
            let occupied: HashMap<PeerId, usize> =
                self.qc_fetches
                    .values()
                    .fold(HashMap::new(), |mut counts, fetch| {
                        *counts.entry(fetch.peer).or_default() += 1;
                        counts
                    });
            let peers = {
                let pm = self.peer_manager_lock();
                pm.connected_peers()
                    .into_iter()
                    .filter(|peer| pm.is_handshaked(peer) && !pm.is_banned(peer))
                    .collect::<Vec<_>>()
            };
            let Some(peer) =
                select_qc_peer(&peers, &occupied, pending.preferred, pending.last_peer)
            else {
                self.pending_qc_fetches.push_back(pending);
                continue;
            };
            let request = NetworkMessage::GetQcBlob {
                epoch: pending.epoch,
                checkpoint_height: pending.height,
                chunk_index: 0,
            };
            let id = self
                .swarm
                .behaviour_mut()
                .sync
                .send_request(&peer, request.to_bytes());
            self.qc_fetches.insert(
                id,
                QcFetch {
                    peer,
                    epoch: pending.epoch,
                    height: pending.height,
                    checkpoint_hash: pending.checkpoint_hash,
                    chunk_index: 0,
                    chunk_count: None,
                },
            );
        }
    }

    /// Continue a peer-bound fetch, importing only a complete, matching blob.
    /// PARTIAL: allowed - the removes are branch-local: the missing-response
    /// path discards the assembly and returns before any later error, and
    /// the metadata errors below run only on the found path, where no remove
    /// has happened yet; text order after a remove is not control flow after
    /// it.
    async fn accept_qc_response(
        &mut self,
        fetch: QcFetch,
        peer: PeerId,
        response: NetworkMessage,
    ) -> Result<QcResponseAction, String> {
        let NetworkMessage::QcBlobResponse {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            blob_data,
            found,
            chunk_index,
            chunk_count,
        } = response
        else {
            return Err("unexpected QC response type".into());
        };
        if peer != fetch.peer
            || epoch != fetch.epoch
            || checkpoint_height != fetch.height
            || chunk_index != fetch.chunk_index
        {
            return Err("QC response does not match the outbound request".into());
        }
        if !found {
            if chunk_count != 0 || !blob_data.is_empty() || !checkpoint_hash.is_empty() {
                return Err("malformed missing QC response".into());
            }
            self.qc_assemblies.remove(&(peer, epoch, checkpoint_height));
            return Ok(QcResponseAction::Missing);
        }
        let max_chunks = crate::consensus::qc::qc_blob_max_bytes(MAX_QC_WIRE_VALIDATORS)
            .div_ceil(crate::consensus::qc::QC_CHUNK_BYTES);
        if checkpoint_hash != fetch.checkpoint_hash
            || chunk_count == 0
            || chunk_count as usize > max_chunks
            || chunk_index >= chunk_count
            || fetch
                .chunk_count
                .is_some_and(|previous| previous != chunk_count)
            || blob_data.is_empty()
        {
            return Err("invalid QC response metadata".into());
        }
        let blob = self.assemble_qc_chunk(
            peer,
            epoch,
            checkpoint_height,
            chunk_index,
            chunk_count,
            blob_data,
        )?;
        if let Some(blob) = blob {
            if chunk_index + 1 != chunk_count
                || blob.epoch != epoch
                || blob.checkpoint_height != checkpoint_height
                || blob.checkpoint_hash != fetch.checkpoint_hash
            {
                return Err("assembled QC blob does not match its request".into());
            }
            self.chain.import_qc_blob(blob).await?;
            self.peer_manager_lock().report_good_behavior(&peer);
            return Ok(QcResponseAction::Imported);
        } else {
            let next = chunk_index + 1;
            if next >= chunk_count {
                return Err("incomplete QC blob".into());
            }
            let request = NetworkMessage::GetQcBlob {
                epoch,
                checkpoint_height,
                chunk_index: next,
            };
            let id = self
                .swarm
                .behaviour_mut()
                .sync
                .send_request(&peer, request.to_bytes());
            self.qc_fetches.insert(
                id,
                QcFetch {
                    chunk_index: next,
                    chunk_count: Some(chunk_count),
                    ..fetch
                },
            );
        }
        Ok(QcResponseAction::InProgress)
    }

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

    /// Tell gossipsub whether a received message may be forwarded.
    ///
    /// The mesh runs with `validate_messages`: a message is held back until
    /// the application reports a verdict, so a malformed message is not
    /// relayed to the rest of the network.
    fn report_gossip(
        &mut self,
        id: &gossipsub::MessageId,
        source: &PeerId,
        verdict: gossipsub::MessageAcceptance,
    ) {
        let _ = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(id, source, verdict);
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
        self.active_sync_request = Some(sync.send_request(&peer, req.to_bytes()));
        info!("Requesting headers from {peer} over /sync (limit {limit})");
        true
    }

    /// One regeneration health tick against the finalized checkpoints.
    ///
    /// The canonical commitment of each stage comes from the post-quantum
    /// source (Root Seal, verified anchor, finality checkpoint with its QC);
    /// the held one is this node's own. [`RegenHealthTick::observe`] decides
    /// and moves the reversion ledger. This method gathers the view and acts on the
    /// outcome: repair and revert open a sync round, alarms are logged as
    /// errors with their stable kind label.
    async fn regen_health_tick(&mut self) {
        use crate::domain::regeneration_stage::Stage;
        let live = self.chain.get_finalized_height().await;
        let (polyp, previous) = self.chain.pq_sealed_heights(live).await;
        // Every stage is read through the post-quantum canonical source: a
        // BLS-only certificate or an unverified anchor yields no seal, and the
        // tick treats a commitment without a seal as absent.
        let mut wanted = vec![(Stage::Medusa, live)];
        wanted.extend(previous.map(|height| (Stage::Ephyra, height)));
        wanted.extend(polyp.map(|height| (Stage::Polyp, height)));
        let held = (
            self.regen_health.held_stage(),
            self.regen_health.held_height(),
        );
        if !wanted.contains(&held) {
            wanted.push(held);
        }
        let mut checkpoints = Vec::with_capacity(wanted.len());
        for (stage, height) in wanted {
            let observed = self.chain.pq_stage_observation(stage, height).await;
            checkpoints.push(Checkpoint {
                stage,
                height,
                local: observed.local,
                canonical: observed.canonical,
                seal: observed.seal,
            });
        }
        let view = CheckpointView {
            live,
            previous,
            polyp,
            checkpoints,
        };
        let outcome = self.regen_health.observe(&view);
        match &outcome {
            TickOutcome::Idle | TickOutcome::Healthy => {}
            TickOutcome::Repair {
                stress,
                repair_cost,
                regrowth_cost,
            } => warn!(
                ?stress,
                repair_cost,
                regrowth_cost,
                height = live,
                "Regeneration health: view diverges from the finality certificate, repair by sync"
            ),
            TickOutcome::Reverted(reversion) => warn!(
                from = ?reversion.from,
                to = ?reversion.to,
                stress = ?reversion.stress,
                height_after = reversion.height_after,
                event = reversion.event_number,
                "Regeneration health: reversion ledger reverted, re-growing by sync"
            ),
            TickOutcome::RevertRefused(error) => tracing::error!(
                %error,
                height = live,
                "Regeneration health: the ledger refused the reversion verdict"
            ),
            TickOutcome::Alarm { reason, stress } => tracing::error!(
                kind = reason.kind(),
                ?reason,
                ?stress,
                height = live,
                "Regeneration health alarm: self-recovery is impossible or unsafe"
            ),
        }
        match &outcome {
            TickOutcome::Reverted(reversion) => {
                self.stash_reverted_transactions(reversion.height_after, live)
                    .await;
            }
            TickOutcome::Healthy if self.regen_health.held_stage() == Stage::Medusa => {
                self.rebroadcast_stashed_transactions(live).await;
            }
            _ => {}
        }
        if outcome.opens_sync() {
            let locator = self.chain.get_locator().await;
            if !self.request_headers_from_peer(None, locator, 500) {
                info!("Regeneration health: no sync round opened, one is open or no peer fits");
            }
        }
    }

    /// Ask `peer` for the witnesses of transactions of one block. The answer is
    /// admitted only when it hashes to `witness_root` (the root the block
    /// header commits); a peer that answers anything else is reported.
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn request_witnesses(
        &mut self,
        peer: PeerId,
        request: crate::network::witness_protocol::WitnessRequest,
        witness_root: [u8; 32],
    ) {
        let id = self
            .swarm
            .behaviour_mut()
            .witness
            .send_request(&peer, request.encode());
        self.witness_requests
            .insert(id, (request, witness_root, peer));
    }

    /// The most blocks one reversion stashes transactions of.
    const REGEN_STASH_MAX_BLOCKS: u64 = 2_000;

    /// Keep the transactions of the heights a reversion gave up: the
    /// view above `target` is rolled back, so what sat in it would vanish.
    async fn stash_reverted_transactions(&mut self, target: u64, live: u64) {
        let first = target.saturating_add(1);
        let last = live.min(target.saturating_add(Self::REGEN_STASH_MAX_BLOCKS));
        let mut kept = 0;
        for height in first..=last {
            let Some(block) = self.chain.get_block(height).await else {
                continue;
            };
            kept += self.regen_mempool.stash(
                &block.transactions,
                height,
                &crate::mempool::pool::charged_bytes,
            );
        }
        self.regen_stash_from = Some(
            self.regen_stash_from
                .map_or(target, |held| held.min(target)),
        );
        info!(
            kept,
            target, live, "Regeneration: stashed the transactions of the reverted heights"
        );
    }

    /// After the ledger is back at the adult stage, offer the stashed
    /// transactions the canonical chain did not include to the mempool and the
    /// network again. The mempool door validates them like any other.
    async fn rebroadcast_stashed_transactions(&mut self, live: u64) {
        let Some(from) = self.regen_stash_from else {
            return;
        };
        if self.regen_mempool.is_empty() {
            self.regen_stash_from = None;
            return;
        }
        let mut confirmed = std::collections::HashSet::new();
        let last = live.min(from.saturating_add(Self::REGEN_STASH_MAX_BLOCKS * 2));
        for height in from.saturating_add(1)..=last {
            if let Some(block) = self.chain.get_block(height).await {
                confirmed.extend(block.transactions.iter().map(|tx| tx.hash.clone()));
            }
        }
        let txs = self
            .regen_mempool
            .take_unconfirmed(live, &|hash| confirmed.contains(hash));
        self.regen_stash_from = None;
        let mut accepted = 0;
        for tx in txs {
            if self.chain.add_transaction(tx.clone()).await.is_ok() {
                accepted += 1;
                let msg = NetworkMessage::Transaction(tx);
                let topic = gossipsub::IdentTopic::new("transactions");
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, msg.to_bytes())
                {
                    warn!("Failed to gossip a re-offered transaction: {e}");
                }
            }
        }
        info!(
            accepted,
            "Regeneration: re-offered the stashed transactions after re-growth"
        );
    }

    fn clear_sync_round(&mut self) {
        self.sync_state.store(0, Ordering::SeqCst);
        self.sync_started_at.store(0, Ordering::SeqCst);
        self.active_sync_request = None;
    }

    /// Try to switch to the fork that `suffix` belongs to.
    ///
    /// The peer sends only the blocks from its fork height; the shared prefix
    /// is joined to them by the chain actor, which already holds it. The
    /// result is logged, never dropped.
    async fn reorg_to_peer_suffix(
        chain: ChainHandle,
        suffix: Vec<crate::core::block::Block>,
        peer: PeerId,
        flight_guard: ReorgFlightGuard,
        last_completed: Arc<AtomicU64>,
    ) {
        // Peer-independent throttle (CWE-407). A batch is cheap to send and
        // proportional to the node's own chain to act on, so an attacker who
        // can gossip can otherwise keep this actor rebuilding forever. Counted
        // from completion, and applied before any chain read: a frame that
        // arrives inside the window is dropped without the node paying for the
        // work it would have triggered.
        //
        // The throttle is decided BEFORE the slot exists. Charging the
        // interval on the refusal path let a peer roll the window forward with
        // every cheap attempt - and `try_reorg` is reachable from nowhere else
        // - so one peer could keep every honest reconstruction out for as long
        // as it kept trying (CWE-400).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !reorg_interval_elapsed(&last_completed, now) {
            warn!(
                "Reorg from {peer} ignored: a peer-triggered reconstruction finished less than {REORG_MIN_INTERVAL_SECS}s ago"
            );
            return;
        }
        let Some(first) = suffix.first() else {
            return;
        };
        let start = first.index;
        // The interval has already been decided, so nothing below this point
        // may stamp it until the batch has cleared the checks that cost the
        // node nothing. Those checks are the deadline for the slot: see where
        // it is created, after the fork-depth and parent-hash tests. The
        // single-flight guard is a parameter, so every early return still
        // releases it whether or not the slot exists yet.
        //
        // The cost that has to be bounded here is the work one peer batch can
        // make this node do, not the height the fork happens to sit at. It is
        // bounded twice over below: the fork depth (`MAX_REORG_DEPTH`) and the
        // size of the peer's own suffix, which the caller already capped. A
        // cap on the absolute fork height used to stand here instead, and
        // because this helper is the only path that reaches a reorg it made
        // fork recovery impossible for every chain taller than that cap, with
        // nothing but a `warn!` to show for it.
        let tip = chain.get_height().await;
        if tip.saturating_sub(start) > crate::consensus::MAX_REORG_DEPTH as u64 {
            warn!(
                "Reorg from {peer} refused: fork depth {} exceeds MAX_REORG_DEPTH ({})",
                tip.saturating_sub(start),
                crate::consensus::MAX_REORG_DEPTH
            );
            return;
        }
        // A suffix that does not name the local block at `start - 1` as its
        // parent cannot join the prefix, so refuse it with one chain read
        // instead of walking `start` heights for a candidate that
        // `join_reorg_candidate` would reject anyway (CWE-407).
        if start > 0 {
            match chain.get_block(start - 1).await {
                Some(parent) if parent.hash == first.previous_hash => {}
                _ => {
                    warn!(
                        "Reorg from {peer} refused: fork at {start} does not continue the local chain"
                    );
                    return;
                }
            }
        }
        // The batch cleared the depth and parent checks, so the work below is
        // real: a fork-choice evaluation over the peer's suffix and, if it
        // wins, a reconstruction. Only from here on does the attempt charge
        // the interval. Stamping it earlier let a peer occupy the one global
        // window with a batch refused for depth or for not continuing this
        // chain - work the node did not do - and every other peer's genuine
        // batch then arrived inside a closed window, so one peer could deny
        // this node fork recovery for as long as it kept sending (CWE-400).
        let _slot = ReorgSlot {
            last_completed: Arc::clone(&last_completed),
            reorg: flight_guard,
        };
        // The join happens on the chain actor's side of the boundary
        // (CWE-400). Reading the prefix here meant a genesis-wide copy whose
        // size the peer chose with `start`, every five minutes, whether or not
        // the candidate could win fork choice; the actor already holds the
        // chain and joins the suffix before copying anything, refusing a batch
        // that cannot make the chain longer for two integer comparisons.
        match chain.try_reorg_suffix(suffix).await {
            Ok(true) => info!("Reorg to the chain of {peer} done"),
            Ok(false) => info!("Reorg to the chain of {peer} not needed: not a better chain"),
            Err(error) => warn!("Reorg to the chain of {peer} failed: {error}"),
        }
    }

    /// The fields a peer advertises in its `Handshake` or `HandshakeAck`.
    fn handshake_fields(msg: NetworkMessage) -> Option<(&'static str, HandshakeFields)> {
        match msg {
            NetworkMessage::Handshake {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            } => Some((
                "Handshake",
                HandshakeFields {
                    version_major,
                    version_minor,
                    chain_id,
                    best_height,
                    validator_set_hash,
                    supported_schemes,
                },
            )),
            NetworkMessage::HandshakeAck {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            } => Some((
                "HandshakeAck",
                HandshakeFields {
                    version_major,
                    version_minor,
                    chain_id,
                    best_height,
                    validator_set_hash,
                    supported_schemes,
                },
            )),
            _ => None,
        }
    }

    /// Our side of the handshake: the same fields whether it opens the
    /// exchange (`Handshake`) or answers it (`HandshakeAck`).
    ///
    /// Takes the chain handle rather than `&self`: `Node` is not `Sync`
    /// (the swarm), so holding `&Node` across an await would make the
    /// event loop's future `!Send`, and `tokio::spawn(node.run())` in the
    /// distributed settlement test would not compile.
    async fn handshake_message(chain: &ChainHandle, ack: bool) -> NetworkMessage {
        let version_major = crate::core::encoding::PROTOCOL_VERSION_MAJOR;
        let version_minor = crate::core::encoding::PROTOCOL_VERSION_MINOR;
        let chain_id = chain.get_chain_id().await;
        // UNIT: this is a chain LENGTH, not a height, and the field name says
        // the opposite. `get_height` returns the index of the last block, so a
        // chain holding only genesis answers 0 and its length is 1.
        //
        // The `+1` is not a bug and must not be "fixed" on one side alone:
        // `sync_if_behind` applies the same `saturating_add(1)` to our own
        // height before comparing, so `peer_best_height > our_chain_length`
        // is exactly `peer_height > our_height`. Removing the increment here
        // and not there would make every peer look one block ahead forever and
        // open a sync round on every handshake.
        //
        // One consequence worth knowing: `get_height` answers 0 when the chain
        // actor does not reply, so an unreachable actor advertises length 1.
        // That is an overstatement, not an understatement, so it cannot make a
        // peer skip syncing - the failure direction is a wasted round, not a
        // missed one.
        let best_height = chain.get_height().await.saturating_add(1);
        let validator_set_hash = chain.get_validator_set_hash().await;
        let supported_schemes = vec![
            "ED25519".to_string(),
            crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string(),
            "DILITHIUM".to_string(),
        ];
        if ack {
            NetworkMessage::HandshakeAck {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            }
        } else {
            NetworkMessage::Handshake {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            }
        }
    }

    /// Admit or ban a peer on the fields of its `Handshake` / `HandshakeAck`.
    ///
    /// Returns the peer's advertised height when the handshake is accepted,
    /// `None` when the peer was banned. The same rule for both directions
    /// and both transports.
    async fn admit_handshake(
        &mut self,
        peer_id: PeerId,
        what: &str,
        fields: HandshakeFields,
    ) -> Option<u64> {
        let HandshakeFields {
            version_major,
            version_minor,
            chain_id,
            best_height,
            validator_set_hash,
            supported_schemes,
        } = fields;
        let supported_schemes = supported_schemes.as_slice();
        let my_chain_id = self.chain.get_chain_id().await;
        if chain_id != my_chain_id {
            warn!("Peer {peer_id} {what} has wrong chain_id {chain_id} (expected {my_chain_id}). Banning.");
            self.peer_manager_lock().ban_peer(&peer_id);
            return None;
        }
        if !crate::core::encoding::is_compatible_version(version_major, version_minor) {
            warn!("Peer {peer_id} {what} has incompatible protocol v{version_major}.{version_minor}. Banning.");
            self.peer_manager_lock().ban_peer(&peer_id);
            return None;
        }
        if !supports_required_bls_scheme(supported_schemes) {
            warn!(
                "Peer {} {} does not advertise required BLS scheme {}. Banning.",
                peer_id,
                what,
                crate::chain::finality::BLS_SCHEME_RFC9380_V1
            );
            self.peer_manager_lock().ban_peer(&peer_id);
            return None;
        }
        info!(
            "{what} from {}: v{}.{}, chain={}, height={}, val_set={}, schemes={:?}",
            peer_id,
            version_major,
            version_minor,
            chain_id,
            best_height,
            validator_set_hash,
            supported_schemes
        );
        {
            let mut pm = self.peer_manager_lock();
            pm.set_handshaked(&peer_id, true);
            pm.report_good_behavior(&peer_id);
        }
        Some(best_height)
    }

    /// Open a sync round with a peer that just told us it is ahead.
    async fn sync_if_behind(&mut self, peer_id: PeerId, peer_best_height: u64) {
        let our_chain_length = self.chain.get_height().await.saturating_add(1);
        if peer_best_height > our_chain_length {
            let locator = self.chain.get_locator().await;
            if !self.request_headers_from_peer(Some(peer_id), locator, 500) {
                info!("Failed to request headers after handshake: a sync round is already open or no peer is eligible");
            }
        }
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
        let mobile_mode = sharding_config.as_ref().is_some_and(|c| c.mobile_mode);

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
            .validate_messages()
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
            .with_tcp(
                tcp::Config::default(),
                // TLS 1.3 first, Noise as the fallback the devnet
                // still speaks. The security upgrade is negotiated per
                // connection, so a TLS-only peer and a Noise-only peer both
                // connect to this node.
                (tls::Config::new, noise::Config::new),
                yamux_config,
            )?
            // QUIC carries TLS 1.3 itself.
            .with_quic()
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
                //
                // The stream cap bounds memory per connection: each inbound
                // stream may buffer up to the codec ceiling until the timeout.
                let req_cfg = request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(MAX_SYNC_CONCURRENT_STREAMS);
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
                    req_cfg.clone(),
                );
                let witness = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new(crate::network::witness_protocol::WITNESS_PROTOCOL),
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
                    witness,
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
            qc_assemblies: HashMap::new(),
            qc_fetches: HashMap::new(),
            pending_qc_fetches: VecDeque::new(),
            qc_serves: HashMap::new(),
            bootstrap_peers: Vec::new(),
            dns_seeds: Vec::new(),
            dns_seed_port: 0,
            peer_count,
            sync_state,
            sync_started_at,
            active_sync_request: None,
            pending_bitswap_fetches: HashMap::new(),
            bitswap_pending_attempts: HashMap::new(),
            bitswap_requests: HashMap::new(),
            bitswap_request_peers: HashMap::new(),
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
            regen_health: RegenHealthTick::default(),
            regen_mempool: crate::domain::RegenMempool::new(),
            regen_stash_from: None,
            witness_requests: HashMap::new(),
            reorg_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reorg_last_completed_at: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
                format!("./data/{network:?}/banned-peers.json").to_lowercase(),
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
        // The same port over QUIC (UDP),.
        let quic: Multiaddr = format!("/ip4/0.0.0.0/udp/{port}/quic-v1").parse()?;
        if let Err(e) = self.swarm.listen_on(quic) {
            warn!("QUIC listener not started: {e}");
        }
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
    /// Written BEFORE the vote is published, never
    /// batched, and atomically. Persist-then-publish can at worst lose a
    /// round (mark ahead of the wire); the old publish-then-persist order lost
    /// the record of a vote everyone else saw.
    fn save_vote_history(&self) {
        let Some(ref path) = self.vote_history_db else {
            return;
        };
        let Some(parent) = path.parent() else {
            warn!(path = %path.display(), "vote-history path has no parent directory");
            return;
        };
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!(error = %e, path = %path.display(), "Cannot create vote-history directory");
            return;
        }
        let body = serde_json::json!({
            "last_prevote_height": self.last_prevote_height,
            "last_precommit_height": self.last_precommit_height,
        });
        // Tmp + fsync + rename. A plain `fs::write` left
        // a truncated file behind when a crash landed mid-write; the loader
        // parsed nothing, reset BOTH high-water marks to zero, and the vote
        // that triggered the write was already on the wire - the exact
        // double-sign window the marks exist to close.
        let tmp = parent.join(format!(
            ".{}.tmp",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let write = (|| -> std::io::Result<()> {
            {
                use std::io::Write;
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(body.to_string().as_bytes())?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, path)?;
            // Durability of the rename itself; directory sync is best-effort.
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
            Ok(())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
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
        // The vote beat. A checkpoint is `finality_checkpoint_interval` blocks
        // away (two on the devnet, about 2.4 s) and an aggregator holds one
        // round at a time, so the beat has to be well inside a round: on a
        // 30 s beat the devnet mesh started 445 rounds and cast five votes,
        // and every round was displaced before a quorum could form. One
        // command round trip per beat is the cost.
        let mut finality_interval = tokio::time::interval(Duration::from_millis(250));
        // The health tick keeps its own, slower beat - it used to share the
        // finality beat, and at 250 ms it would fire four times a second.
        let mut finality_health_interval = tokio::time::interval(Duration::from_secs(30));
        let mut qc_retry_interval = tokio::time::interval(QC_RETRY_DELAY);
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
                                self.clear_sync_round();
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
                _ = qc_retry_interval.tick() => {
                    // Later finality makes older pending requests unnecessary.
                    let finalized = self.chain.get_finalized_height().await;
                    self.pending_qc_fetches.retain(|pending| pending.height > finalized);
                    self.drain_qc_fetches();
                }
                _ = finality_health_interval.tick() => {
                    // Every node checks its own view, validator or not,
                    // so the health tick runs on a beat of its own.
                    self.regen_health_tick().await;
                }
                _ = finality_interval.tick() => {
                    // Resolve validator address lazily
                    if self.validator_address.is_none() {
                        self.validator_address = self.chain.get_validator_address().await;
                    }

                    let Some(voter_addr) = self.validator_address else {
                        continue;
                    };

                    // --- Check aggregator state for auto-precommit ---
                    //
                    // The aggregator also names the round this node votes in.
                    // Deriving the checkpoint from the local tip instead made
                    // nodes one block apart vote at different heights, and a
                    // vote only counts in an aggregator that holds its own
                    // height: no round ever saw a quorum.
                    let agg_state = self.chain.get_aggregator_state().await;
                    if agg_state.active
                        && agg_state.prevote_quorum_reached
                        && !agg_state.precommit_quorum_reached
                        && precommit_height_is_new(
                            agg_state.checkpoint_height,
                            self.last_precommit_height,
                        )
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
                                    auth_sig: precommit.auth_sig,
                                    pq_sig: precommit.pq_sig,
                                };
                                // The mark is durable before the
                                // bytes leave on the wire.
                                self.last_precommit_height = agg_state.checkpoint_height;
                                self.save_vote_history();
                                let topic = gossipsub::IdentTopic::new("blocks");
                                if let Err(e) = self
                                    .swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic, vote_msg.to_bytes())
                                {
                                    // A vote that never reaches the mesh is
                                    // indistinguishable from a vote that was
                                    // never cast, and finality simply stops.
                                    warn!("Failed to gossip a finality vote: {e}");
                                }
                            }
                            Err(e) => {
                                warn!("Failed to sign precommit: {e}");
                            }
                        }
                    }

                    // --- Periodic prevote ---
                    //
                    // The round named by the aggregator, not this node's own
                    // tip. A vote counts only in an aggregator holding the
                    // same height, so a node voting at its own checkpoint
                    // (one or two blocks ahead of its peers) contributed to
                    // no round at all.
                    if agg_state.active
                        && agg_state.checkpoint_height > 0
                        && agg_state.checkpoint_height > self.last_prevote_height
                    {
                        // The epoch the aggregator was started with, and the
                        // round's own hash. Signing with the checkpoint-
                        // interval divisor instead of the epoch length made
                        // every honest prevote fail `add_prevote` with
                        // "Prevote epoch mismatch" wherever the two divisors
                        // differ.
                        let epoch = agg_state.epoch;
                        let checkpoint_height = agg_state.checkpoint_height;
                        match self
                            .chain
                            .sign_prevote(
                                epoch,
                                checkpoint_height,
                                agg_state.checkpoint_hash.clone(),
                                voter_addr,
                            )
                            .await
                        {
                            Ok(prevote) => {
                                info!("Finality: voting for checkpoint height {checkpoint_height} (epoch {epoch})");
                                let vote_msg = NetworkMessage::Prevote {
                                    epoch: prevote.epoch,
                                    checkpoint_height: prevote.checkpoint_height,
                                    checkpoint_hash: prevote.checkpoint_hash,
                                    voter_id: voter_addr.to_hex(),
                                    sig_bls: prevote.sig_bls,
                                    auth_sig: prevote.auth_sig,
                                };
                                // Persist-before-publish, as for the
                                // precommit above.
                                self.last_prevote_height = checkpoint_height;
                                self.save_vote_history();
                                let topic = gossipsub::IdentTopic::new("blocks");
                                if let Err(e) =
                                    self.swarm.behaviour_mut().gossipsub.publish(topic, vote_msg.to_bytes())
                                {
                                    // A vote that never reaches the mesh is
                                    // indistinguishable from a vote that was
                                    // never cast, and finality simply stops.
                                    warn!("Failed to gossip a finality vote: {e}");
                                }
                            }
                            Err(e) => {
                                warn!("Failed to sign prevote: {e}");
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
                            NodeCommand::AdminBanPeer { peer_id, response } => {
                                let result = self
                                    .peer_manager
                                    .lock()
                                    .map_err(|_| "peer manager lock poisoned".to_string())
                                    .map(|mut pm| pm.ban_peer(&peer_id));
                                let _ = response.send(result);
                            }
                            NodeCommand::AdminUnbanPeer { peer_id, response } => {
                                let result = self
                                    .peer_manager
                                    .lock()
                                    .map_err(|_| "peer manager lock poisoned".to_string())
                                    .map(|mut pm| pm.unban_peer(&peer_id));
                                let _ = response.send(result);
                            }
                            NodeCommand::AdminListBannedPeers { response } => {
                                let result = self
                                    .peer_manager
                                    .lock()
                                    .map_err(|_| "peer manager lock poisoned".to_string())
                                    .map(|pm| {
                                        pm.get_banned_peers()
                                            .iter()
                                            .map(ToString::to_string)
                                            .collect::<Vec<String>>()
                                    });
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
                                            // One attempt per peer asked;
                                            // the counter is what lets a failing route
                                            // (not_found, bad response, disconnect)
                                            // retire the waiters instead of parking them.
                                            *self
                                                .bitswap_pending_attempts
                                                .entry(cid)
                                                .or_insert(0) += peers.len();
                                            for peer in &peers {
                                                let request_id = self.swarm.behaviour_mut().bitswap.send_request(
                                                    peer,
                                                    bud_node::BitswapRequest { want_cid },
                                                );
                                                self.bitswap_requests.insert(request_id, want_cid);
                                                self.bitswap_request_peers.insert(request_id, *peer);
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
                                    .lock().map_or_else(|p| p.into_inner().mean_peer_score_i64(), |d| d.mean_peer_score_i64());
                                m.peer_connection_quality.set(mean_quality);
                            }
                            info!("Connected to {peer_id}, Peers: {count}");

                            // The handshake goes to this peer over `/sync`, the
                            // peer-bound request_response protocol. It used to be
                            // published to the gossip topic, and on a connection
                            // this young the mesh does not exist yet: every node
                            // logged `NoPeersSubscribedToTopic`, no peer ever
                            // became handshaked, and every later block from the
                            // producer was dropped as "before completing
                            // handshake". A follower could not follow at all.
                            let handshake = Self::handshake_message(&self.chain, false).await;
                            let chain_len = self.chain.get_height().await + 1;
                            info!("Connected to {peer_id}, Chain length: {chain_len}, sending Handshake over /sync");
                            let sync = &mut self.swarm.behaviour_mut().sync;
                            let _ = sync.send_request(&peer_id, handshake.to_bytes());

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
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established,
                            ..
                        } => {
                            // Retire ONLY Bitswap requests addressed to `peer_id` when its
                            // last connection closes, and recompute remaining live asks per
                            // cid from `bitswap_requests` so unrelated peer churn never
                            // drains in-flight fetches (CWE-404).
                            if num_established == 0 {
                                let retired_ids: Vec<_> = self
                                    .bitswap_request_peers
                                    .iter()
                                    .filter_map(|(req_id, p)| (*p == peer_id).then_some(*req_id))
                                    .collect();
                                let mut affected_cids = std::collections::BTreeSet::new();
                                for req_id in retired_ids {
                                    self.bitswap_request_peers.remove(&req_id);
                                    if let Some(want) = self.bitswap_requests.remove(&req_id) {
                                        affected_cids.insert(want.0);
                                    }
                                }
                                for cid in affected_cids {
                                    let outstanding = self
                                        .bitswap_requests
                                        .values()
                                        .filter(|want| want.0 == cid)
                                        .count();
                                    if outstanding == 0 {
                                        self.bitswap_pending_attempts.remove(&cid);
                                        if let Some(senders) = self.pending_bitswap_fetches.remove(&cid) {
                                            for sender in senders {
                                                let _ = sender.send(Err(format!(
                                                    "no peer served content {} (peers disconnected)",
                                                    hex::encode(cid)
                                                )));
                                            }
                                        }
                                    } else {
                                        self.bitswap_pending_attempts.insert(cid, outstanding);
                                    }
                                }
                            }
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
                                    .lock().map_or_else(|p| {
                                        let d = p.into_inner();
                                        (d.scored_peer_count(), d.mean_peer_score_i64())
                                    }, |d| (d.scored_peer_count(), d.mean_peer_score_i64()));
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
                                    drop(pm);
                                    warn!("Ignoring message from banned peer {peer_id}");
                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                    continue;
                                }
                            }

                            if !self.peer_manager_lock().check_rate_limit(&peer_id) {
                                warn!("Rate limit exceeded or lock error for peer {peer_id}");
                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
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
                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
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
                                        // Dropped for the sender's state, not for the
                                        // content: an honest copy must stay new.
                                        self.gossip_dedup
                                            .lock()
                                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                                            .forget(&message.data);
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }

                                    // Forward verdicts and `record_valid` credit are earned ONLY
                                    // after the per-arm content validation below succeeds (CWE-693).
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let our_chain_id = self.chain.get_chain_id().await;
                                        if !Self::block_passes_cheap_checks(&block, our_chain_id) {
                                            warn!(
                                                "Rejected gossip block #{} from {}: chain id or hash does not match its contents",
                                                block.index, peer_id
                                            );
                                            self.peer_manager_lock().report_invalid_block(&peer_id);
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        info!("BLOCK: #{} Hash: {}...", block.index, log_prefix(&block.hash, 8));
                                        let our_height = self.chain.get_height().await;
                                        if block.index == our_height + 1 {
                                            if let Ok(now) = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                            {
                                                let now_ms = now.as_millis();
                                                let block_lag =
                                                    now_ms.saturating_sub(block.timestamp);
                                                if block_lag > crate::consensus::MAX_PAST_BLOCK_TIME_MS {
                                                    let tip_stale = match self
                                                        .chain
                                                        .get_block(our_height)
                                                        .await
                                                    {
                                                        Some(tip) => {
                                                            now_ms.saturating_sub(tip.timestamp)
                                                                > crate::consensus::MAX_PAST_BLOCK_TIME_MS
                                                        }
                                                        None => true,
                                                    };
                                                    if !tip_stale {
                                                        warn!(
                                                            "Rejected gossip block #{} from {}: timestamp lags the wall clock by {} ms (max {})",
                                                            block.index,
                                                            peer_id,
                                                            block_lag,
                                                            crate::consensus::MAX_PAST_BLOCK_TIME_MS
                                                        );
                                                        self.peer_manager_lock()
                                                            .report_invalid_block(&peer_id);
                                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                        continue;
                                                    }
                                                }
                                            }
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
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                    continue;
                                                }
                                            }
                                        } else if block.index <= our_height {
                                            if let Some(our_block) = self.chain.get_block(block.index).await {
                                                if our_block.hash != block.hash {
                                                    info!("Fork detected at height {} (ours: {}... theirs: {}...)", block.index, log_prefix(&our_block.hash, 8), log_prefix(&block.hash, 8));

                                                    info!("Fork detected at height {} - initiating sync to resolve fork", block.index);
                                                    if self.sync_state.load(Ordering::SeqCst) == 0 {
                                                        let locator = self.chain.get_locator().await;
                                                        let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                                    }
                                                }
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        } else {
                                            info!("Block #{} is ahead of our chain (height={}), requesting sync", block.index, our_height);
                                            if self.sync_state.load(Ordering::SeqCst) == 0 {
                                                let locator = self.chain.get_locator().await;
                                                let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        }
                                    }
                                    NetworkMessage::Transaction(tx) => {
                                        if let Err(e) = NetworkMessage::validate_tx_size(&tx) {
                                            warn!("Received oversized transaction from {}: {:?}", peer_id, e);
                                            {
                                                let mut pm = self.peer_manager_lock();
                                                pm.report_oversized_message(&peer_id);
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
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
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
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
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
                                            }
                                        }
                                    }

                                    NetworkMessage::GetHeaders { locator, limit } => {
                                        if let Err(error) = NetworkMessage::validate_header_request(&locator, limit) {
                                            warn!("Rejected invalid gossip GetHeaders from {}: {:?}", peer_id, error);
                                            {
                                                let mut pm = self.peer_manager_lock();
                                                pm.report_bad_behavior(&peer_id);
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        warn!("Ignoring gossip GetHeaders from {peer_id}: sync is point-to-point (request_response)");
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
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
                                        if from > to {
                                            warn!("Rejected inverted block range from {peer_id}: {from}..{to}");
                                            {
                                                let mut pm = self.peer_manager_lock();
                                                pm.report_bad_behavior(&peer_id);
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        warn!("Ignoring gossip GetBlocksRange from {peer_id}: sync is point-to-point (request_response)");
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }

                                    NetworkMessage::Blocks(blocks) => {
                                        if blocks.len() > crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS {
                                            {
                                                let mut pm = self.peer_manager_lock();
                                                pm.report_invalid_block(&peer_id);
                                            }
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let batch_chain_id = self.chain.get_chain_id().await;
                                        if !blocks.iter().all(|b| {
                                            Self::block_passes_cheap_checks(b, batch_chain_id)
                                        }) {
                                            warn!("Rejected gossip block batch from {peer_id}: cheap checks failed");
                                            self.peer_manager_lock().report_invalid_block(&peer_id);
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let height_before = self.chain.get_height().await;
                                        if !blocks.is_empty() {
                                            let start_idx = blocks[0].index;
                                            let our_block_at_start = self.chain.get_block(start_idx).await;
                                            if let Some(our_b) = our_block_at_start {
                                                if our_b.hash != blocks[0].hash {
                                                    // An unsolicited batch on a fork does NOT
                                                    // start a reconstruction. Adopting a fork
                                                    // means rebuilding the whole chain from
                                                    // genesis inside the chain actor, and
                                                    // anybody who completes the handshake can
                                                    // publish a batch - so the work has to be
                                                    // self-initiated to be worth paying for.
                                                    // A node that is genuinely behind asks for
                                                    // the blocks it lacks (`/sync`, `GetBlocksRange`)
                                                    // and the answer to that request is the only
                                                    // peer-driven path into a reconstruction.
                                                    warn!("Ignoring gossip block batch from {peer_id}: fork at {} (reorgs follow our own /sync)", blocks[0].index);
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                                    continue;
                                                } else {
                                                    for block in blocks {
                                                        let h = self.chain.get_height().await;
                                                        if block.index == h + 1 {
                                                            match self.chain.validate_and_add_block(block.clone()).await {
                                                                Ok(pruned_cids) => {
                                                                    for cid in pruned_cids {
                                                                        let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                    }
                                                                }
                                                                Err(e) => warn!(
                                                                    peer = %peer_id,
                                                                    index = block.index,
                                                                    error = %e,
                                                                    "gossip block refused"
                                                                ),
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                for block in blocks {
                                                    let h = self.chain.get_height().await;
                                                    if block.index == h + 1 {
                                                        match self.chain.validate_and_add_block(block.clone()).await {
                                                            Ok(pruned_cids) => {
                                                                for cid in pruned_cids {
                                                                    let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                }
                                                            }
                                                            Err(e) => warn!(
                                                                peer = %peer_id,
                                                                index = block.index,
                                                                error = %e,
                                                                "gossip block refused"
                                                            ),
                                                        }
                                                        }
                                                }
                                            }
                                        }
                                        if self.chain.get_height().await > height_before {
                                            let mut pm = self.peer_manager_lock();
                                            pm.report_good_behavior(&peer_id);
                                        } else {
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        }
                                    }

                                    NetworkMessage::NewTip { height, hash: _ } => {
                                        let our_height = self.chain.get_height().await;
                                        if height > our_height && self.sync_state.load(Ordering::SeqCst) == 0 {
                                            let locator = self.chain.get_locator().await;
                                            let _ = self.request_headers_from_peer(Some(peer_id), locator, 500);
                                        }
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }

                                    NetworkMessage::StateSnapshotResponse { height, state_root, ok } => {
                                        if ok {
                                            info!("Received StateSnapshotResponse: height={height}, root={state_root}");
                                        } else {
                                            warn!("Peer {peer_id} reported snapshot unavailable at height {height}");
                                        }
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }

                                    NetworkMessage::GetStateSnapshot { height } => {
                                        warn!("Ignoring legacy gossip GetStateSnapshot from {peer_id} at height {height}: point-to-point snapshot protocol required");
                                        {
                                            let mut pm = self.peer_manager_lock();
                                            pm.report_bad_behavior(&peer_id);
                                        }
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }

                                    NetworkMessage::SnapshotChunk { height, index, total, data, session_id } => {
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
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }

                                    NetworkMessage::GetBlocksByHeight { from_height, to_height } => {
                                        warn!("Ignoring gossip GetBlocksByHeight [{from_height}, {to_height}] from {peer_id}: sync is point-to-point (request_response)");
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }

                                    NetworkMessage::BlocksByHeight(blocks) => {
                                        if blocks.len() > crate::network::protocol::MAX_SNAP_BATCH as usize {
                                            warn!("Too many snap-sync blocks from {peer_id}");
                                            self.peer_manager_lock().report_invalid_block(&peer_id);
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let snap_chain_id = self.chain.get_chain_id().await;
                                        if !blocks.iter().all(|b| {
                                            Self::block_passes_cheap_checks(b, snap_chain_id)
                                        }) {
                                            warn!("Rejected snap-sync batch from {peer_id}: cheap checks failed");
                                            self.peer_manager_lock().report_invalid_block(&peer_id);
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        info!("Snap-sync: {} blocks from {}", blocks.len(), peer_id);
                                        let snap_height_before = self.chain.get_height().await;
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
                                        if self.chain.get_height().await > snap_height_before {
                                            self.peer_manager_lock().report_good_behavior(&peer_id);
                                        } else {
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        }
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let fields = HandshakeFields {
                                            version_major,
                                            version_minor,
                                            chain_id,
                                            best_height,
                                            validator_set_hash,
                                            supported_schemes,
                                        };
                                        let Some(peer_best_height) =
                                            self.admit_handshake(peer_id, "Handshake", fields).await
                                        else {
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        };
                                        self.sync_if_behind(peer_id, peer_best_height).await;
                                        let response = Self::handshake_message(&self.chain, true).await;
                                        let sync = &mut self.swarm.behaviour_mut().sync;
                                        let _ = sync.send_request(&peer_id, response.to_bytes());
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        let fields = HandshakeFields {
                                            version_major,
                                            version_minor,
                                            chain_id,
                                            best_height,
                                            validator_set_hash,
                                            supported_schemes,
                                        };
                                        let Some(peer_best_height) =
                                            self.admit_handshake(peer_id, "HandshakeAck", fields).await
                                        else {
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        };
                                        self.sync_if_behind(peer_id, peer_best_height).await;
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }

                                    NetworkMessage::Prevote { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls, auth_sig } => {
                                        let rate_limit_ok = self.peer_manager_lock().check_vote_rate_limit(&peer_id);
                                        if !rate_limit_ok {
                                            warn!("Peer {peer_id} exceeded vote rate limit or lock error. Ignoring Prevote.");
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        }
                                        info!("Prevote from {}: epoch={}, height={}, hash={}..., voter={}",
                                            peer_id, epoch, checkpoint_height, log_prefix(&checkpoint_hash, 16), voter_id);

                                        let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                            Ok(addr) => addr,
                                            Err(e) => {
                                                warn!("Invalid voter_id in Prevote: {e}");
                                                self.peer_manager_lock().report_bad_behavior(&peer_id);
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
                                            }
                                        };

                                        // Stamp OUR chain id, never one the
                                        // peer supplies: the signature is then
                                        // checked against this chain's
                                        // preimage, so a vote signed for
                                        // another network cannot count here.
                                        let our_chain_id = self.chain.get_chain_id().await;
                                        let prevote = Prevote {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            chain_id: our_chain_id,
                                            voter_id: voter_addr,
                                            sig_bls,
                                            auth_sig,
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
                                                if refusal_is_round_scope(&e) {
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                                    continue;
                                                }
                                                self.peer_manager_lock().report_bad_behavior(&peer_id);
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
                                            }
                                        }
                                    }

                                    NetworkMessage::Precommit { epoch, checkpoint_height, checkpoint_hash, voter_id, sig_bls, auth_sig, pq_sig } => {
                                        let rate_limit_ok = self.peer_manager_lock().check_vote_rate_limit(&peer_id);
                                        if !rate_limit_ok {
                                            warn!("Peer {peer_id} exceeded vote rate limit or lock error. Ignoring Precommit.");
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                            continue;
                                        }
                                        info!("Precommit from {}: epoch={}, height={}, hash={}..., voter={}",
                                            peer_id, epoch, checkpoint_height, log_prefix(&checkpoint_hash, 16), voter_id);

                                        let voter_addr = match crate::core::address::Address::from_hex(&voter_id) {
                                            Ok(addr) => addr,
                                            Err(e) => {
                                                warn!("Invalid voter_id in Precommit: {e}");
                                                self.peer_manager_lock().report_bad_behavior(&peer_id);
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
                                            }
                                        };

                                        let our_chain_id = self.chain.get_chain_id().await;
                                        let precommit = Precommit {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            chain_id: our_chain_id,
                                            voter_id: voter_addr,
                                            sig_bls,
                                            auth_sig,
                                            pq_sig,
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
                                                if refusal_is_round_scope(&e) {
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                                    continue;
                                                }
                                                self.peer_manager_lock().report_bad_behavior(&peer_id);
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
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
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                            continue;
                                        }
                                        info!("FinalityCert from {}: epoch={}, height={}, hash={}...",
                                            peer_id, epoch, checkpoint_height, log_prefix(&checkpoint_hash, 16));

                                        // The certificate commits to the chain
                                        // its signatures were produced for;
                                        // stamp ours so a certificate from
                                        // another network cannot verify here.
                                        let cert_chain_id = self.chain.get_chain_id().await;
                                        let cert = crate::chain::finality::FinalityCert {
                                            epoch,
                                            checkpoint_height,
                                            checkpoint_hash,
                                            chain_id: cert_chain_id,
                                            agg_sig_bls,
                                            bitmap,
                                            set_hash,
                                        };

                                        let qc_checkpoint_hash = cert.checkpoint_hash.clone();
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
                                                    warn!(
                                                        "Missing verified QC blob for FinalityCert from {peer_id}; requesting over /sync for epoch={epoch}, height={checkpoint_height}"
                                                    );
                                                    self.request_qc_blob(peer_id, epoch, checkpoint_height, qc_checkpoint_hash);
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                                } else {
                                                    self.peer_manager_lock().report_bad_behavior(&peer_id);
                                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                }
                                                continue;
                                            }
                                        }
                                    }

                                    NetworkMessage::GetQcBlob { epoch, checkpoint_height, .. } => {
                                        warn!("Ignoring gossip GetQcBlob from {peer_id}: QC blob fetch is point-to-point; refusing epoch={epoch}, height={checkpoint_height}");
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }
                                    NetworkMessage::QcBlobResponse { .. } => {
                                        // No unsolicited or gossip-sourced QC blobs. Only a
                                        // matching /sync request ID may open an assembly.
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }

                                    NetworkMessage::QcFaultProof { proof_data } => {
                                        let rate_limit_ok = self.peer_manager_lock().check_blob_rate_limit(&peer_id);
                                        if !rate_limit_ok {
                                            warn!("Peer {peer_id} exceeded blob rate limit or lock error. Ignoring QcFaultProof.");
                                            self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
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
                                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                        continue;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to parse QcFaultProof from {peer_id}: {e}");
                                                {
                                                    let mut pm = self.peer_manager_lock();
                                                    pm.report_bad_behavior(&peer_id);
                                                }
                                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                                continue;
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
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }
                                    NetworkMessage::VerifiedDomainCommitment(payload) => {
                                        // Consensus-state isolation, same rule as
                                        // the raw `DomainCommitment` arm above:
                                        // applying a commitment writes
                                        // `external_roots`, which
                                        // `AccountState::calculate_state_root`
                                        // folds into the state root, and no
                                        // block-execution path reproduces that
                                        // write. A commitment enters through the
                                        // `Settlement` transaction (its verified
                                        // finality plus its in-block state
                                        // update); the gossip form is refused
                                        // here, reported, and not forwarded.
                                        warn!(
                                            "Ignoring gossiped VerifiedDomainCommitment from {} for domain {}; commitments travel as Settlement transactions",
                                            peer_id, payload.commitment.domain_id
                                        );
                                        {
                                            let mut pm = self.peer_manager_lock();
                                            pm.report_bad_behavior(&peer_id);
                                        }
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);
                                        continue;
                                    }
                                    NetworkMessage::CrossDomainMessage(msg_obj) => {
                                        // a gossiped message used to be
                                        // inserted into the message registry
                                        // (state-root bearing) whenever it
                                        // arrived, so two nodes held different
                                        // registries at the same height. A
                                        // relayed message enters through the
                                        // `RelayCrossDomainMessage` transaction
                                        // now; the gossip form is dropped and
                                        // not forwarded.
                                        tracing::debug!(
                                            "Dropping gossiped CrossDomainMessage {} from {peer_id}: relayed messages travel as RelayCrossDomainMessage transactions",
                                            hex::encode(msg_obj.message_id)
                                        );
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }
                                    NetworkMessage::GlobalHeader(header) => {
                                        info!(
                                            "GlobalHeader from {}: height={}, hash={}...",
                                            peer_id,
                                            header.global_height,
                                            &header.calculate_hash()[..16]
                                        );
                                        // Nothing about the header is validated here, so it
                                        // earns neither a forward verdict nor score credit.
                                        self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Ignore);
                                        continue;
                                    }
                                }
                                // Reaching here means the arm above validated content and accepted it:
                                // only now may gossipsub forward the frame and grant peer credit.
                                self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Accept);
                                if let Ok(now) = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                {
                                    self.gossip_dedup
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .record_valid(&peer_id, now.as_millis() as u64);
                                }
                                }
                                Err(e) => {
                                    warn!("Computed invalid message from {}: {:?}", peer_id, e);
                                    self.report_gossip(&id, &peer_id, gossipsub::MessageAcceptance::Reject);

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
                                            // The handshake itself arrives here before the
                                            // peer is handshaked: it is what makes it so. It
                                            // still costs a rate token and a banned peer is
                                            // still refused; only the handshaked check is
                                            // what this message establishes.
                                            //
                                            // Ban and rate limit run before the decode: a
                                            // banned or flooding peer must not cost a full
                                            // protobuf decode per request.
                                            let pre_allowed = {
                                                let mut pm = self.peer_manager_lock();
                                                // Security review (HIGH): a banned peer cannot
                                                // issue a /sync request.
                                                !pm.is_banned(&peer) && pm.check_rate_limit(&peer)
                                            };
                                            if !pre_allowed {
                                                warn!("Rejected sync request from banned/rate-limited peer {peer}");
                                                continue;
                                            }
                                            let parsed = NetworkMessage::from_bytes_validated(&request);
                                            let is_handshake = matches!(
                                                parsed,
                                                Ok(NetworkMessage::Handshake { .. })
                                                    | Ok(NetworkMessage::HandshakeAck { .. })
                                            );
                                            let handshaked = is_handshake
                                                || self.peer_manager_lock().is_handshaked(&peer);
                                            if !handshaked {
                                                warn!("Rejected sync request from unhandshaked peer {peer}");
                                                continue;
                                            }
                                            if is_handshake {
                                                let Some((what, fields)) = parsed.ok().and_then(Self::handshake_fields) else {
                                                    continue;
                                                };
                                                let ack = what == "HandshakeAck";
                                                // The channel is answered so the requester's
                                                // request_response state machine closes
                                                // cleanly; the ack itself travels as its own
                                                // request, like the opening message.
                                                let sync = &mut self.swarm.behaviour_mut().sync;
                                                let _ = sync.send_response(channel, Vec::new());
                                                let Some(peer_best_height) =
                                                    self.admit_handshake(peer, what, fields).await
                                                else {
                                                    continue;
                                                };
                                                self.sync_if_behind(peer, peer_best_height).await;
                                                if !ack {
                                                    let response = Self::handshake_message(&self.chain, true).await;
                                                    let sync = &mut self.swarm.behaviour_mut().sync;
                                                    let _ = sync.send_request(&peer, response.to_bytes());
                                                }
                                                continue;
                                            }
                                            if let Some(ref m) = self.metrics {
                                                m.p2p_sync_requests.inc();
                                            }
                                            if let Ok(msg) = parsed {
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
                                                    NetworkMessage::GetQcBlob { epoch, checkpoint_height, chunk_index } => {
                                                        let max_chunks = crate::consensus::qc::qc_blob_max_bytes(MAX_QC_WIRE_VALIDATORS)
                                                            .div_ceil(crate::consensus::qc::QC_CHUNK_BYTES);
                                                        let now = std::time::Instant::now();
                                                        self.qc_serves.retain(|_, (started, _)| now.duration_since(*started) < QC_ASSEMBLY_TTL);
                                                        let key = (peer, epoch, checkpoint_height);
                                                        let admission = qc_serve_admission(
                                                            &self.qc_serves, peer, epoch, checkpoint_height, chunk_index, max_chunks,
                                                        );
                                                        if admission == QcServeAdmission::Invalid {
                                                            self.peer_manager_lock().report_bad_behavior(&peer);
                                                            continue;
                                                        }
                                                        // A saturated table, duplicate start or exhausted rate
                                                        // budget is not an invalid request and must not ban an
                                                        // honest peer. Reply missing so the fetcher can retry.
                                                        let busy = admission == QcServeAdmission::Busy
                                                            || (admission == QcServeAdmission::Start
                                                                && !self.peer_manager_lock().check_blob_rate_limit(&peer));
                                                        if busy {
                                                            if let Ok(answer) = qc_chunk_response(epoch, checkpoint_height, chunk_index, None) {
                                                                let _ = self.swarm.behaviour_mut().sync.send_response(channel, answer.to_bytes());
                                                            }
                                                            continue;
                                                        }
                                                        let blob = self.chain.get_qc_blob(checkpoint_height).await;
                                                        match qc_chunk_response(epoch, checkpoint_height, chunk_index, blob) {
                                                            Ok(answer @ NetworkMessage::QcBlobResponse { found: true, chunk_count, .. }) => {
                                                                if chunk_index + 1 == chunk_count {
                                                                    self.qc_serves.remove(&key);
                                                                } else {
                                                                    self.qc_serves.insert(key, (now, chunk_index + 1));
                                                                }
                                                                let _ = self.swarm.behaviour_mut().sync.send_response(channel, answer.to_bytes());
                                                            }
                                                            Ok(answer) => {
                                                                self.qc_serves.remove(&key);
                                                                let _ = self.swarm.behaviour_mut().sync.send_response(channel, answer.to_bytes());
                                                            }
                                                            Err(e) => warn!("QC blob at height {checkpoint_height} cannot be served: {e}"),
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        request_response::Message::Response { request_id, response } => {
                                            if let Some(fetch) = self.qc_fetches.remove(&request_id) {
                                                let key = (fetch.peer, fetch.epoch, fetch.height);
                                                let result = NetworkMessage::from_bytes_validated(&response)
                                                    .map_err(|e| format!("{e:?}"));
                                                let retry = fetch.clone();
                                                let result = match result {
                                                    Ok(msg) => self.accept_qc_response(fetch, peer, msg).await,
                                                    Err(e) => Err(e),
                                                };
                                                match result {
                                                    Ok(QcResponseAction::Missing) => self.retry_qc_fetch(&retry),
                                                    Ok(QcResponseAction::Imported | QcResponseAction::InProgress) => {},
                                                    Err(e) => {
                                                        self.qc_assemblies.remove(&key);
                                                        warn!("QC response from {peer} rejected: {e}");
                                                        self.peer_manager_lock().report_bad_behavior(&peer);
                                                        self.retry_qc_fetch(&retry);
                                                    }
                                                }
                                                self.drain_qc_fetches();
                                                continue;
                                            }
                                            if let Ok(msg) = NetworkMessage::from_bytes_validated(&response) {
                                                match msg {
                                                    NetworkMessage::Headers(headers) => {
                                                        if self.active_sync_request != Some(request_id) {
                                                            continue;
                                                        }
                                                        let chain_id = self.chain.get_chain_id().await;
                                                        if let Err(error) =
                                                            NetworkMessage::validate_header_batch(&headers, chain_id)
                                                        {
                                                            // Loud on purpose: this refusal ends
                                                            // the round without the follower moving,
                                                            // and a silent one is indistinguishable
                                                            // from a peer that simply has nothing new.
                                                            warn!(
                                                                peer = %peer,
                                                                error = ?error,
                                                                count = headers.len(),
                                                                first = headers.first().map(|h| h.index),
                                                                last = headers.last().map(|h| h.index),
                                                                "header batch refused; the sync round is closed"
                                                            );
                                                            {
                                                                let mut pm = self.peer_manager_lock();
                                                                pm.report_invalid_block(&peer);
                                                            }
                                                            // The round is over: this peer will not
                                                            // be asked for the blocks. Closing it here
                                                            // instead of waiting for SYNC_TIMEOUT_SECS
                                                            // lets the next trigger pick another peer.
                                                            self.clear_sync_round();
                                                            continue;
                                                        }
                                                        if headers.is_empty() {
                                                            // The peer has nothing past our locator: we
                                                            // are level with it. Nothing to fetch, so the
                                                            // round closes now rather than at the timeout.
                                                            // Said out loud: an empty answer from a peer
                                                            // that just announced a higher block is a
                                                            // locator disagreement, and it is the one way
                                                            // a follower can re-ask forever.
                                                            let our_height = self.chain.get_height().await;
                                                            info!(
                                                                peer = %peer,
                                                                our_height,
                                                                "peer returned no headers past our locator"
                                                            );
                                                            self.clear_sync_round();
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
                                                                self.active_sync_request = Some(
                                                                    self.swarm
                                                                        .behaviour_mut()
                                                                        .sync
                                                                        .send_request(&peer, req.to_bytes()),
                                                                );
                                                            }
                                                        }
                                                        {
                                                            let mut pm = self.peer_manager_lock();
                                                            pm.report_good_behavior(&peer);
                                                        }
                                                    }
                                                    NetworkMessage::Blocks(blocks) => {
                                                        if self.active_sync_request != Some(request_id) {
                                                            continue;
                                                        }
                                                        if blocks.len() > crate::network::protocol::MAX_CHAIN_SYNC_BLOCKS {
                                                            {
                                                                let mut pm = self.peer_manager_lock();
                                                                pm.report_invalid_block(&peer);
                                                            }
                                                            self.clear_sync_round();
                                                            continue;
                                                        }
                                                        if !blocks.is_empty() {
                                                            let start_idx = blocks[0].index;
                                                            let our_block = self.chain.get_block(start_idx).await;
                                                            if let Some(our_b) = our_block {
                                                            if our_b.hash != blocks[0].hash {
                                                                if let Some(flight_guard) = ReorgFlightGuard::try_acquire(&self.reorg_in_flight) {
                                                                    let reorg_chain = self.chain.clone();
                                                                    let reorg_peer = peer;
                                                                    let last_completed = Arc::clone(&self.reorg_last_completed_at);
                                                                    tokio::spawn(async move {
                                                                        Self::reorg_to_peer_suffix(reorg_chain, blocks, reorg_peer, flight_guard, last_completed).await;
                                                                    });
                                                                } else {
                                                                    warn!("Sync reorg from {peer} ignored: another reorg attempt is already in flight");
                                                                }
                                                                } else {
                                                                    for block in blocks {
                                                                        let h = self.chain.get_height().await;
                                                                        if block.index == h + 1 {
                                                                            let index = block.index;
                                                                            match self.chain.validate_and_add_block(block).await {
                                                                                Ok(pruned_cids) => {
                                                                                    info!("Added block #{index} to local chain");
                                                                                    for cid in pruned_cids {
                                                                                        let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                                    }
                                                                                }
                                                                                // Silent refusal is how a follower can fetch the
                                                                                // same range every second and never move: the
                                                                                // round closes as a success, the height does not.
                                                                                Err(e) => warn!(
                                                                                    peer = %peer,
                                                                                    index,
                                                                                    error = %e,
                                                                                    "sync block refused"
                                                                                ),
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                for block in blocks {
                                                                    let h = self.chain.get_height().await;
                                                                    if block.index == h + 1 {
                                                                        let index = block.index;
                                                                        match self.chain.validate_and_add_block(block).await {
                                                                            Ok(pruned_cids) => {
                                                                                info!("Added block #{index} to local chain");
                                                                                for cid in pruned_cids {
                                                                                    let _ = self.command_tx.send(NodeCommand::StoragePrune { cid }).await;
                                                                                }
                                                                            }
                                                                            Err(e) => warn!(
                                                                                peer = %peer,
                                                                                index,
                                                                                error = %e,
                                                                                "sync block refused"
                                                                            ),
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        self.clear_sync_round();
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
                                request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                                    if let Some(fetch) = self.qc_fetches.remove(&request_id) {
                                        self.qc_assemblies.remove(&(fetch.peer, fetch.epoch, fetch.height));
                                        self.retry_qc_fetch(&fetch);
                                        self.drain_qc_fetches();
                                    }
                                    warn!("Outbound sync failure to {}: {:?}", peer, error);
                                    {
                                        // A request this node chose to send
                                        // that came back unanswered costs the
                                        // peer its place in the sync order,
                                        // not an hour of silence: the devnet
                                        // lost its own validators to that ban
                                        // and then could not finalize.
                                        let mut pm = self.peer_manager_lock();
                                        pm.report_unanswered_request(&peer);
                                    }
                                    // Handshake requests share `/sync` with chain sync.
                                    // Only the request that owns the active round may
                                    // close it; an unrelated failure must leave it alone.
                                    if self.active_sync_request == Some(request_id) {
                                        self.clear_sync_round();
                                    }
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    warn!("Inbound sync failure from {}: {:?}", peer, error);
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Bitswap(event)) => {
                            if let request_response::Event::OutboundFailure { request_id, .. } = &event {
                                self.bitswap_request_peers.remove(request_id);
                                if let Some(want) = self.bitswap_requests.remove(request_id) {
                                    let cid = want.0;
                                    let outstanding = self
                                        .bitswap_requests
                                        .values()
                                        .filter(|other| other.0 == cid)
                                        .count();
                                    if outstanding == 0 {
                                        self.bitswap_pending_attempts.remove(&cid);
                                        if let Some(senders) = self.pending_bitswap_fetches.remove(&cid) {
                                            for sender in senders {
                                                let _ = sender.send(Err(format!(
                                                    "no peer served content {} (all attempts failed)",
                                                    hex::encode(cid)
                                                )));
                                            }
                                        }
                                    } else {
                                        self.bitswap_pending_attempts.insert(cid, outstanding);
                                    }
                                }
                            }
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
                                        request_response::Message::Response { request_id, response } => {
                                            let response_cid = response.cid;
                                            let is_not_found = response.not_found;
                                            // MEDIUM (CWE-345): the response must be for the
                                            // requested block. The requested cid comes from the
                                            // request we sent, never from the response itself.
                                            self.bitswap_request_peers.remove(&request_id);
                                            let Some(requested_cid) = self.bitswap_requests.remove(&request_id) else {
                                                warn!("Unsolicited Bitswap response from {peer}");
                                                self.peer_manager_lock().report_bad_behavior(&peer);
                                                continue;
                                            };
                                            let mut attempt_failed = true;
                                            if let Err(e) = bitswap.handle_response(requested_cid, response) {
                                                self.peer_manager_lock().report_bad_behavior(&peer);
                                                warn!("Bitswap response from {peer} failed: {e}");
                                            } else {
                                                {
                                                    let mut pm = self.peer_manager_lock();
                                                    pm.report_good_behavior(&peer);
                                                }
                                                if !is_not_found {
                                                    let cid_bytes = requested_cid.0;
                                                    if let Ok(data) = bitswap.store().get(&response_cid) {
                                                        // Delivered: retire the waiters and
                                                        // every bookkeeping entry for the cid.
                                                        attempt_failed = false;
                                                        self.bitswap_pending_attempts.remove(&cid_bytes);
                                                        if let Some(senders) = self.pending_bitswap_fetches.remove(&cid_bytes) {
                                                            for sender in senders {
                                                                let _ = sender.send(Ok(data.clone()));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // Recompute remaining live asks from
                                            // `bitswap_requests` using `requested_cid` (never
                                            // `response_cid`, which is peer-chosen!).
                                            if attempt_failed {
                                                let cid_bytes = requested_cid.0;
                                                let outstanding = self
                                                    .bitswap_requests
                                                    .values()
                                                    .filter(|want| want.0 == cid_bytes)
                                                    .count();
                                                if outstanding == 0 {
                                                    self.bitswap_pending_attempts.remove(&cid_bytes);
                                                    if let Some(senders) = self.pending_bitswap_fetches.remove(&cid_bytes) {
                                                        for sender in senders {
                                                            let _ = sender.send(Err(format!(
                                                                "no peer served content {} (all attempts failed)",
                                                                hex::encode(cid_bytes)
                                                            )));
                                                        }
                                                    }
                                                } else {
                                                    self.bitswap_pending_attempts.insert(cid_bytes, outstanding);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BudlumBehaviourEvent::Witness(event)) => {
                            use crate::network::witness_protocol::{
                                check_witnesses, WitnessRequest, WitnessResponse,
                            };
                            match event {
                                request_response::Event::Message {
                                    peer,
                                    message:
                                        request_response::Message::Request {
                                            request, channel, ..
                                        },
                                    ..
                                } => {
                                    // Same boundary as /sync and Bitswap: a banned,
                                    // unhandshaked or rate-limited peer gets nothing.
                                    let allowed = {
                                        let mut pm = self.peer_manager_lock();
                                        !pm.is_banned(&peer)
                                            && pm.is_handshaked(&peer)
                                            && pm.check_rate_limit(&peer)
                                    };
                                    if !allowed {
                                        warn!("Rejected a witness request from banned/unhandshaked/rate-limited peer {peer}");
                                        continue;
                                    }
                                    if WitnessRequest::decode(&request).is_none() {
                                        self.peer_manager_lock().report_bad_behavior(&peer);
                                        continue;
                                    }
                                    // No witness storage yet: say so, never
                                    // invent a witness.
                                    let _ = self
                                        .swarm
                                        .behaviour_mut()
                                        .witness
                                        .send_response(channel, WitnessResponse::NotAvailable.encode());
                                }
                                request_response::Event::Message {
                                    peer,
                                    message:
                                        request_response::Message::Response {
                                            request_id,
                                            response,
                                        },
                                    ..
                                } => {
                                    let Some((request, root, asked)) =
                                        self.witness_requests.remove(&request_id)
                                    else {
                                        warn!("Unsolicited witness response from {peer}");
                                        self.peer_manager_lock().report_bad_behavior(&peer);
                                        continue;
                                    };
                                    if asked != peer {
                                        self.peer_manager_lock().report_bad_behavior(&peer);
                                        continue;
                                    }
                                    let verdict = WitnessResponse::decode(&response)
                                        .ok_or(None)
                                        .and_then(|decoded| {
                                            check_witnesses(&request, &decoded, &root).map_err(Some)
                                        });
                                    match verdict {
                                        Ok(()) => {
                                            self.peer_manager_lock().report_good_behavior(&peer);
                                            info!(
                                                height = request.block_height,
                                                count = request.tx_ids.len(),
                                                "Witnesses verified against the witness_root"
                                            );
                                        }
                                        Err(reason) => {
                                            self.peer_manager_lock().report_bad_behavior(&peer);
                                            warn!(?reason, "Witness response from {peer} refused");
                                        }
                                    }
                                }
                                request_response::Event::OutboundFailure { request_id, .. } => {
                                    self.witness_requests.remove(&request_id);
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// `Node::run()` must stay spawnable on a multi-threaded runtime.
///
/// `Node` is not `Sync` (the swarm), so any helper that holds `&self` across
/// an `.await` makes the event loop's future `!Send`, and `tokio::spawn`
/// in `src/tests/distributed_settlement.rs` stops compiling. That break
/// is visible only when the test target is built, which the 2 GB sandbox
/// cannot do; this check is compiled with the library, so `cargo check
/// --lib` reports it. Helpers that need chain state across an await take
/// the `ChainHandle` (which is `Send + Sync`) instead of `&self`.
const _: fn(&mut Node) = |node| {
    fn assert_send<T: Send>(_: T) {}
    assert_send(node.run());
};

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
        // The production half only: the needles below also sit in this test.
        let whole = include_str!("node.rs");
        let parts = whole.split_once("#[cfg(test)]");
        let src = parts
            .map(|(before, _)| before)
            .expect("this file keeps its tests behind #[cfg(test)]");
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
        let whole = include_str!("node.rs");
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
        let parts = whole.split_once("#[cfg(test)]");
        let production = parts
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
            production.len() < whole.len(),
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

#[cfg(test)]
mod sync_handler_order_tests {
    #[test]
    fn qc_serve_capacity_is_per_peer_and_full_is_not_invalid() {
        use super::{qc_serve_admission, QcServeAdmission, QcServeTable, MAX_QC_ASSEMBLIES};
        use libp2p::PeerId;
        let now = std::time::Instant::now();
        let attacker = PeerId::random();
        let honest = PeerId::random();
        let mut table = QcServeTable::new();
        table.insert((attacker, 1, 10), (now, 1));
        table.insert((attacker, 1, 20), (now, 1));
        assert_eq!(
            qc_serve_admission(&table, attacker, 1, 30, 0, 100),
            QcServeAdmission::Busy
        );
        assert_eq!(
            qc_serve_admission(&table, honest, 1, 30, 0, 100),
            QcServeAdmission::Start
        );
        assert_eq!(
            qc_serve_admission(&table, attacker, 1, 10, 1, 100),
            QcServeAdmission::Continue
        );
        assert_eq!(
            qc_serve_admission(&table, attacker, 1, 10, 2, 100),
            QcServeAdmission::Invalid
        );
        assert_eq!(
            qc_serve_admission(&table, honest, 1, 99, 1, 100),
            QcServeAdmission::Busy
        );
        while table.len() < MAX_QC_ASSEMBLIES {
            table.insert((PeerId::random(), 1, 30), (now, 1));
        }
        assert_eq!(
            qc_serve_admission(&table, honest, 1, 30, 0, 100),
            QcServeAdmission::Busy
        );
    }

    #[test]
    fn qc_fetch_queue_defers_capacity_and_retries_other_peers() {
        use super::{enqueue_qc_fetch, select_qc_peer, PendingQcFetch, MAX_PENDING_QC_REQUESTS};
        use libp2p::PeerId;
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let now = std::time::Instant::now();
        let request = |height, preferred, last_peer| PendingQcFetch {
            epoch: 1,
            height,
            checkpoint_hash: format!("{height:064x}"),
            preferred,
            last_peer,
            ready_at: now,
        };
        let mut queue = std::collections::VecDeque::new();
        for h in 1..=MAX_PENDING_QC_REQUESTS as u64 {
            enqueue_qc_fetch(&mut queue, request(h, Some(peer_a), None));
        }
        assert_eq!(queue.len(), MAX_PENDING_QC_REQUESTS);
        enqueue_qc_fetch(&mut queue, request(1, Some(peer_b), Some(peer_a)));
        assert_eq!(
            queue.len(),
            MAX_PENDING_QC_REQUESTS,
            "duplicate announcements do not consume slots"
        );
        let mut occupied = std::collections::HashMap::new();
        assert_eq!(
            select_qc_peer(&[peer_a, peer_b], &occupied, None, Some(peer_a)),
            Some(peer_b)
        );
        assert_eq!(
            select_qc_peer(&[peer_a], &occupied, None, Some(peer_a)),
            Some(peer_a)
        );
        assert_eq!(select_qc_peer(&[], &occupied, Some(peer_a), None), None);
        occupied.insert(peer_a, 1);
        assert_eq!(
            select_qc_peer(&[peer_a, peer_b], &occupied, Some(peer_a), None),
            Some(peer_b),
            "one slow peer cannot consume every fetch slot"
        );
        occupied.insert(peer_b, 1);
        assert_eq!(
            select_qc_peer(&[peer_a, peer_b], &occupied, None, None),
            None
        );
        occupied.clear();
        let peer_c = PeerId::random();
        let peers = [peer_a, peer_b, peer_c];
        let mut visited = std::collections::HashSet::new();
        let mut last = None;
        for _ in 0..3 {
            let next = select_qc_peer(&peers, &occupied, None, last).unwrap();
            visited.insert(next);
            last = Some(next);
        }
        assert_eq!(visited.len(), 3, "every connected peer gets a retry");
        enqueue_qc_fetch(
            &mut queue,
            request(MAX_PENDING_QC_REQUESTS as u64 + 1, None, None),
        );
        assert_eq!(queue.len(), MAX_PENDING_QC_REQUESTS);
        assert_eq!(queue.front().unwrap().height, 2);
    }

    #[test]
    fn thousand_validator_qc_is_served_in_binary_chunks_and_reassembled() {
        use crate::consensus::qc::{PqSignatureEntry, QcBlob, QcBlobAssembler, QC_CHUNK_BYTES};
        use crate::network::protocol::NetworkMessage;
        let blob = QcBlob::new(
            4,
            100,
            "checkpoint".into(),
            (0..1000)
                .map(|i| PqSignatureEntry {
                    validator_index: i,
                    validator_address: format!("validator-{i}"),
                    // Synthetic bytes exercise the transport, not signature verification.
                    pq_signature: vec![7; 3309],
                })
                .collect(),
        );
        let first = super::qc_chunk_response(4, 100, 0, Some(blob.clone())).unwrap();
        let NetworkMessage::QcBlobResponse {
            found: true,
            chunk_count,
            ..
        } = first
        else {
            panic!("QC blob should be found");
        };
        assert!(chunk_count > 1);
        let mut assembler = QcBlobAssembler::new(1000, chunk_count as usize).unwrap();
        for index in 0..chunk_count {
            let response = super::qc_chunk_response(4, 100, index, Some(blob.clone())).unwrap();
            let received = NetworkMessage::from_bytes_validated(&response.to_bytes()).unwrap();
            let NetworkMessage::QcBlobResponse {
                found: true,
                epoch,
                checkpoint_height,
                checkpoint_hash,
                blob_data,
                chunk_index,
                chunk_count: count,
            } = received
            else {
                panic!("expected QC response");
            };
            assert_eq!(
                (epoch, checkpoint_height, checkpoint_hash.as_str()),
                (4, 100, "checkpoint")
            );
            assert_eq!((chunk_index, count), (index, chunk_count));
            assert!(blob_data.len() <= QC_CHUNK_BYTES);
            assembler.push(chunk_index as usize, blob_data).unwrap();
        }
        let decoded = assembler.finish().unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), blob.to_bytes().unwrap());
    }

    #[test]
    fn qc_serving_refuses_missing_epoch_and_invalid_chunk() {
        use crate::consensus::qc::{PqSignatureEntry, QcBlob};
        use crate::network::protocol::NetworkMessage;
        let blob = QcBlob::new(
            4,
            100,
            "checkpoint".into(),
            vec![PqSignatureEntry {
                validator_index: 0,
                validator_address: "validator".into(),
                pq_signature: vec![7; 3309],
            }],
        );
        for response in [
            super::qc_chunk_response(5, 100, 0, Some(blob.clone())).unwrap(),
            super::qc_chunk_response(4, 100, 1, Some(blob)).unwrap(),
            super::qc_chunk_response(4, 100, 0, None).unwrap(),
        ] {
            let NetworkMessage::QcBlobResponse {
                found,
                blob_data,
                chunk_count,
                ..
            } = response
            else {
                panic!("expected QC response");
            };
            assert!(!found);
            assert!(blob_data.is_empty());
            assert_eq!(chunk_count, 0);
        }
        let request = NetworkMessage::GetQcBlob {
            epoch: 4,
            checkpoint_height: 100,
            chunk_index: 1,
        };
        assert!(matches!(
            NetworkMessage::from_bytes_validated(&request.to_bytes()),
            Ok(NetworkMessage::GetQcBlob { chunk_index: 1, .. })
        ));
    }

    /// Production half of this file; the test modules would match their own text.
    fn production() -> &'static str {
        include_str!("node.rs")
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or("")
    }

    /// A multi byte character on the cut must not panic.
    #[test]
    fn log_prefix_survives_multibyte_input() {
        let hostile = format!("{}{}", "a".repeat(15), "\u{20ac}\u{20ac}");
        assert_eq!(super::log_prefix(&hostile, 16).chars().count(), 16);
        assert_eq!(super::log_prefix("abc", 16), "abc");
    }

    /// No byte slice of a peer string is left in the production path.
    #[test]
    fn no_byte_slice_of_checkpoint_hash_in_logs() {
        let needle = format!("{}[..16", "checkpoint_hash");
        let needle2 = format!("&{}.hash[..8", "block");
        let code = production();
        assert!(!code.contains(&needle) && !code.contains(&needle2));
    }

    /// / CWE-693: gossipsub holds messages until per-arm validation
    /// succeeds; neither `Accept` nor `record_valid` may precede `match msg`.
    #[test]
    fn gossipsub_forwarding_waits_for_the_application_verdict() {
        let code = production();
        assert!(code.contains(".validate_messages()"));
        for verdict in ["Accept", "Reject", "Ignore"] {
            let needle = format!("gossipsub::MessageAcceptance::{verdict}");
            assert!(code.contains(&needle), "missing verdict {verdict}");
        }
        let match_pos = code
            .find("match msg {")
            .expect("gossip handler dispatches on decoded NetworkMessage");
        let accept_pos = code
            .find("gossipsub::MessageAcceptance::Accept")
            .expect("Accept verdict exists after validation");
        let credit_pos = code
            .find(".record_valid(&peer_id")
            .expect("peer score credit exists after validation");
        assert!(
            accept_pos > match_pos && credit_pos > match_pos,
            "Accept and record_valid must run ONLY after `match msg` content validation"
        );
    }

    /// Gossip batches get the cheap checks and earn credit only
    /// when the chain moved.
    #[test]
    fn gossip_block_batches_are_prechecked_and_not_credited_blindly() {
        let code = production();
        for marker in ["batch_chain_id", "snap_chain_id"] {
            assert!(code.contains(&format!("block_passes_cheap_checks(b, {marker})")));
        }
        assert!(code.contains("> height_before"));
        assert!(code.contains("> snap_height_before"));
        // An unvalidated GlobalHeader earns no credit.
        let arm = code
            .split_once("NetworkMessage::GlobalHeader(header) => {")
            .and_then(|(_, rest)| rest.split_once("Computed invalid message"))
            .map(|(arm, _)| arm)
            .unwrap_or("report_good_behavior");
        assert!(!arm.contains("report_good_behavior"));
    }

    /// The guard compares the height that is signed.
    #[test]
    fn precommit_guard_blocks_equal_and_lower_aggregator_heights() {
        assert!(!super::precommit_height_is_new(100, 100));
        assert!(!super::precommit_height_is_new(50, 100));
        assert!(super::precommit_height_is_new(101, 100));
        let code = production();
        let old = format!("checkpoint_height > self.{}", "last_precommit_height");
        assert!(
            !code.contains(&old),
            "the guard must use the aggregator height"
        );
    }

    /// The cid a Bitswap response is checked against comes from the
    /// request we sent.
    #[test]
    fn bitswap_response_is_checked_against_the_requested_cid() {
        let code = production();
        let own = format!("handle_response({}, response)", "response_cid");
        assert!(
            !code.contains(&own),
            "the response must not vouch for itself"
        );
        assert!(code.contains("handle_response(requested_cid, response)"));
        assert!(code.contains("self.bitswap_requests.insert(request_id, want_cid)"));
        assert!(code.contains("self.bitswap_requests.remove(request_id)"));
    }

    /// Ban and rate limit run before the protobuf decode.
    #[test]
    fn sync_request_checks_ban_and_rate_before_decode() {
        let code = production();
        let arm = code
            .split_once("request_response::Message::Request { request, channel")
            .map(|(_, after)| after)
            .unwrap_or("");
        let decode = format!("{}from_bytes_validated(&request)", "NetworkMessage::");
        let rate = arm.find("pm.check_rate_limit(&peer)");
        let parse = arm.find(&decode);
        assert!(rate.is_some() && parse.is_some(), "handler shape changed");
        assert!(rate < parse, "the decode must come after the rate limit");
    }

    /// The stream cap is set on the request/response config.
    #[test]
    fn request_response_config_caps_concurrent_streams() {
        let code = production();
        assert!(
            code.contains(".with_max_concurrent_streams(MAX_SYNC_CONCURRENT_STREAMS)"),
            "the request/response config must cap streams per connection"
        );
    }

    #[test]
    fn reorg_single_flight_guard_enforces_mutual_exclusion_and_parent_precheck() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_guard = super::ReorgFlightGuard::try_acquire(&flag);
        assert!(
            first_guard.is_some(),
            "first reorg attempt must acquire guard"
        );
        assert!(
            super::ReorgFlightGuard::try_acquire(&flag).is_none(),
            "concurrent reorg attempt must be refused while one is in flight"
        );
        drop(first_guard);
        assert!(
            super::ReorgFlightGuard::try_acquire(&flag).is_some(),
            "dropping the guard must allow a subsequent reorg attempt"
        );
        let code = production();
        assert!(
            code.contains("Some(parent) if parent.hash == first.previous_hash => {}"),
            "reorg_to_peer_suffix must pre-check parent hash at start - 1 before walking prefix"
        );
    }

    /// A peer-triggered reconstruction is throttled from completion, and an
    /// unsolicited gossip batch no longer triggers one at all.
    ///
    /// Single-flight alone bounds how many reconstructions overlap, not how
    /// often they happen: a peer publishing a fork batch every block kept the
    /// chain actor rebuilding its whole chain, one attempt at a time. Two
    /// properties close that: the interval (measured from completion, checked
    /// before any chain read) and the missing gossip trigger - only the answer
    /// to our own `/sync` request reaches a reconstruction.
    #[test]
    fn peer_triggered_reorgs_are_throttled_and_never_started_from_gossip() {
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Within the window: refused.
        completed.store(now, std::sync::atomic::Ordering::Release);
        assert!(
            !super::reorg_interval_elapsed(&completed, now),
            "a second attempt inside the interval must be refused"
        );
        // Past the window: allowed again.
        completed.store(
            now.saturating_sub(super::REORG_MIN_INTERVAL_SECS),
            std::sync::atomic::Ordering::Release,
        );
        assert!(
            super::reorg_interval_elapsed(&completed, now),
            "the interval must expire measured from completion"
        );

        // A batch refused for depth or for not continuing the local chain does
        // no work, so it must not charge the interval that every other peer
        // competes for. Pinned as source order in the one function that has
        // the throttle: the stamping slot is created after both structural
        // checks, and before the call that starts the real work.
        let body = production();
        let slot = body
            .find("let _slot = ReorgSlot {")
            .expect("the throttle must still stamp through a slot");
        let depth_check = body
            .find("MAX_REORG_DEPTH as u64")
            .expect("the depth check must still exist");
        let parent_check = body
            .find("does not continue the local chain")
            .expect("the parent-hash check must still exist");
        let actor_call = body
            .find("match chain.try_reorg_suffix(suffix).await {")
            .expect("the suffix must be handed to the chain actor");
        assert!(
            depth_check < slot && parent_check < slot,
            "a batch refused for depth or parent must not stamp the reorg window"
        );
        assert!(
            slot < actor_call,
            "an attempt that reaches the actor must stamp the window"
        );
        // CWE-400: the peer's fork height used to size a genesis-wide chain
        // read on this side of the actor boundary. Nothing here may read the
        // prefix again; the actor joins it from the chain it already holds.
        assert!(
            !body.contains("get_blocks_range(0,"),
            "the peer-chosen fork height must not size a chain read in the network layer"
        );

        let code = production();
        // `production()` is the file before its test module, so this counts
        // production call sites: exactly one, the /sync answer.
        assert_eq!(
            code.matches("Self::reorg_to_peer_suffix(").count(),
            1,
            "exactly one path may reach a reconstruction: the answer to our own sync request"
        );
        assert!(
            !code.contains("reorg_blocks"),
            "the unsolicited gossip batch must not be handed to a reconstruction"
        );
    }
}

#[cfg(test)]
mod gossip_author_tests {
    use super::*;

    /// A spoofed gossip author must not change consensus state: the author
    /// field of a gossip frame is read only to tie a handshake to its
    /// connection. Reading it anywhere else in this file would let a classical
    /// signature steer a decision.
    #[test]
    fn gossip_author_is_not_a_consensus_input() {
        let whole = include_str!("node.rs");
        let production = whole
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("this file keeps its tests behind #[cfg(test)]");
        let reads: Vec<&str> = production
            .lines()
            .filter(|line| line.contains("message.source"))
            .collect();
        assert!(
            !reads.is_empty(),
            "the handshake check reads the author; the scan is measuring nothing"
        );
        for line in &reads {
            assert!(
                line.contains("handshake_origin_matches_peer")
                    || line.trim_start().starts_with("message.source"),
                "gossip author read outside the handshake origin check: {line}"
            );
        }
    }

    /// A relayed handshake (author is not the sending peer) is dropped, and a
    /// frame with no author is dropped too.
    #[test]
    fn spoofed_handshake_author_is_rejected() {
        let relay = PeerId::random();
        let author = PeerId::random();
        assert!(handshake_origin_matches_peer(relay, Some(relay)));
        assert!(!handshake_origin_matches_peer(relay, Some(author)));
        assert!(!handshake_origin_matches_peer(relay, None));
    }
}
