//! The Garden network: a dedicated libp2p swarm and one protocol.
//!
//! A Garden never shares a connection with the Budlum network. Each node
//! opens a swarm of its own (TCP, Noise, Yamux) whose identity is the
//! validator key, and speaks one request and response protocol on it.
//!
//! Every frame is bounded. A peer has to show the invite before anything
//! but the greeting is answered.

use super::types::{
    GardenAdmissionState, GardenBlock, GardenCommit, GardenGenesis, GardenKey, GardenPresence,
    GardenVote, SignedGardenTx,
};
use crate::domain::types::Hash32;
use futures::prelude::*;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    identity, noise, request_response, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Transport,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

/// The one protocol a Garden swarm speaks.
const GARDEN_PROTOCOL: &str = "/budlum/garden/1";
/// Largest request frame. A request carries at most one block or one object.
pub const MAX_REQUEST_BYTES: usize = 18 * 1024 * 1024;
/// Largest request frame accepted from a peer before it has passed `Hello`.
const MAX_UNADMITTED_REQUEST_BYTES: usize = 1024;
/// Maximum unauthenticated greetings accepted per second across all strangers.
const MAX_UNADMITTED_HELLOS_PER_SEC: usize = 32;
/// Maximum requests accepted from a single unadmitted peer before disconnecting it.
const MAX_UNADMITTED_REQUESTS_PER_PEER: u8 = 12;
/// Maximum greetings accepted per second from one already-admitted peer.
/// Each greeting triggers an invite check and a genesis-sized reply.
const MAX_HELLOS_PER_PEER_PER_SEC: usize = 8;
/// Largest number of bytes buffered in frames above
/// `MAX_UNADMITTED_REQUEST_BYTES` across all streams of one Garden swarm.
/// Exceeds both `max_established_per_peer` (2) and the unadmitted inbound cap
/// (4), so neither a single peer nor every unadmitted slot combined can exhaust
/// the pool and starve admitted validators.
const MAX_LARGE_FRAME_BYTES_IN_FLIGHT: usize = 8 * MAX_REQUEST_BYTES;
/// Per-connection share of buffered large-request bytes so one connection
/// (and, under `max_established_per_peer = 2`, one peer) can never drain the
/// swarm-wide pool and block other validators' `Gossip` or `PutObject` frames.
const MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT: usize = MAX_REQUEST_BYTES;
/// Granularity in which a large request or response frame is charged to the
/// swarm-wide in-flight byte budget.
const LARGE_FRAME_UNIT_BYTES: usize = 64 * 1024;
/// Maximum idle gap between chunks of an in-flight request or response frame
/// before the stream is aborted and its byte permits are returned.
const FRAME_CHUNK_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time a TCP connection may spend in Noise + Yamux setup before the
/// transport closes it and returns its pending inbound slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest response frame. A response carries at most one object or a batch
/// of commits.
pub const MAX_RESPONSE_BYTES: usize = 18 * 1024 * 1024;
/// Largest number of response bytes buffered concurrently across all streams
/// of one Garden swarm, charged at `LARGE_FRAME_UNIT_BYTES` granularity for
/// bytes actually received.
const MAX_RESPONSE_FRAME_BYTES_IN_FLIGHT: usize = 8 * MAX_RESPONSE_BYTES;
/// Per-connection share of buffered response bytes.
const MAX_CONN_RESPONSE_FRAME_BYTES_IN_FLIGHT: usize = MAX_RESPONSE_BYTES;
/// Concurrent streams per connection.
const MAX_CONCURRENT_STREAMS: usize = 16;
/// Most connections a Garden swarm keeps.
const MAX_CONNECTIONS: u32 = 96;
/// Most commits one sync response carries.
pub const MAX_SYNC_COMMITS: u32 = 32;
/// Most gossip items one request carries. A validator sends one gossip
/// request to a peer at a time, so this also bounds what a peer can queue.
pub const MAX_GOSSIP_BATCH: usize = 64;
/// Events held for the validator before the swarm stops being read.
const EVENT_BACKLOG: usize = 256;

/// A signed item that floods through the Garden.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GardenGossip {
    Tx(SignedGardenTx),
    Proposal(GardenBlock),
    Vote(GardenVote),
    Commit(GardenCommit),
    Presence(GardenPresence),
}

/// A request on the Garden protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GardenRequest {
    /// The greeting. The signature is made with the invite key over the
    /// sender's own key, so it shows that the sender holds the invite.
    Hello {
        chain_id: u64,
        key: GardenKey,
        invite_signature: Vec<u8>,
    },
    /// Signed items, at most `MAX_GOSSIP_BATCH` of them.
    Gossip(Vec<GardenGossip>),
    /// Finalized blocks from `from_height` on, at most `max` of them.
    GetCommits { from_height: u64, max: u32 },
    /// The bytes of an object. With `relay` the peer may ask its own peers.
    GetObject { content_id: Hash32, relay: bool },
    /// Bytes for the peer to hold. The peer keeps them under the id they
    /// hash to and nowhere else.
    PutObject { bytes: Vec<u8> },
    /// Ask whether this caller's own key is pending, waiting, seated, or
    /// turned away in `HostApproval` mode, without exposing blocks or captions.
    AdmissionStatus,
}

/// A response on the Garden protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GardenResponse {
    Ack,
    Welcome {
        genesis: Box<GardenGenesis>,
        height: u64,
        key: GardenKey,
        invite_signature: Vec<u8>,
    },
    Commits(Vec<GardenCommit>),
    Object(Option<Vec<u8>>),
    Refused(String),
    AdmissionStatus(GardenAdmissionState),
}

/// The libp2p peer id of a Garden key.
pub fn peer_id_of(key: &GardenKey) -> Result<PeerId, String> {
    let public = identity::ed25519::PublicKey::try_from_bytes(key)
        .map_err(|e| format!("garden key is not an ed25519 public key: {e}"))?;
    Ok(identity::PublicKey::from(public).to_peer_id())
}

/// The address a validator announces: its listen address and its peer id.
pub fn announced_address(listen: &Multiaddr, key: &GardenKey) -> Result<String, String> {
    Ok(format!("{listen}/p2p/{}", peer_id_of(key)?))
}

/// Lowest TCP port a Garden address may name. TESTNET-DEFAULT. The ports
/// below it belong to the services of a machine, and no Garden node listens
/// there, so no peer has a reason to send this node to one.
const MIN_DIAL_PORT: u16 = 1024;

/// Parse an address that somebody else supplied and that this node would
/// dial, and return it with the peer id it leads to.
///
/// The address is one host, one TCP port and one peer id, in that order and
/// with nothing before, between or after them. The socket a dial opens is
/// the one the address ends in, so an address that only carries a peer id
/// somewhere binds nothing. The host is an address one machine answers at:
/// not the unspecified address, not multicast and not broadcast. Private
/// and loopback hosts stay: a Garden runs in a home network and on one
/// machine. What such a dial can do there is open a connection that must
/// pass the Noise handshake of the named peer id before a byte of the
const fn ipv4_is_dialable(ip: std::net::Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_link_local())
}

const fn ipv6_is_dialable(ip: std::net::Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    // Reject IPv6 link-local (fe80::/10).
    if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_is_dialable(v4);
    }
    true
}

/// Garden protocol is sent.
pub fn dial_address(address: &str) -> Result<(Multiaddr, PeerId), String> {
    use libp2p::multiaddr::Protocol;
    let parsed: Multiaddr = address
        .parse()
        .map_err(|e| format!("address is not a multiaddr: {e}"))?;
    let mut parts = parsed.iter();
    let one_host = match parts.next() {
        Some(Protocol::Ip4(ip)) => ipv4_is_dialable(ip),
        Some(Protocol::Ip6(ip)) => ipv6_is_dialable(ip),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => true,
        _ => false,
    };
    if !one_host {
        return Err("address must start with the host one machine answers at".into());
    }
    match parts.next() {
        Some(Protocol::Tcp(port)) if port >= MIN_DIAL_PORT => {}
        _ => {
            return Err(format!(
                "address must name a TCP port from {MIN_DIAL_PORT} up after the host"
            ))
        }
    }
    let Some(Protocol::P2p(id)) = parts.next() else {
        return Err("address must end in the peer id of the validator it leads to".into());
    };
    if parts.next().is_some() {
        return Err("address carries more than a host, a port and a peer id".into());
    }
    Ok((parsed, id))
}

/// Parse an address a validator announced and check that it names `key`.
///
/// A validator can only make its peers dial an address that ends in its own
/// peer id. The dial then fails the Noise handshake unless the validator
/// really answers there.
pub fn validator_dial_address(address: &str, key: &GardenKey) -> Result<Multiaddr, String> {
    let (parsed, id) = dial_address(address)?;
    if id != peer_id_of(key)? {
        return Err("announced address does not end in the validator's own peer id".into());
    }
    Ok(parsed)
}

/// Parse an address a validator other than the host announced.
///
/// On top of [`validator_dial_address`] the host of the address is a number,
/// not a name. Every other validator dials what one validator announced, so
/// a name would be looked up by each of them, in the network each of them
/// stands in: one member would choose what the resolvers of the others are
/// asked. The host of a Garden may announce a name. It is in the invite, and
/// whoever uses an invite already goes where the host says.
pub fn member_dial_address(address: &str, key: &GardenKey) -> Result<Multiaddr, String> {
    use libp2p::multiaddr::Protocol;
    let parsed = validator_dial_address(address, key)?;
    if !matches!(
        parsed.iter().next(),
        Some(Protocol::Ip4(_) | Protocol::Ip6(_))
    ) {
        return Err("a validator announces the address it answers at, not a name".into());
    }
    Ok(parsed)
}

/// Scope of a [`GardenCodec`] instance inside `libp2p::request_response`.
///
/// `Behaviour` holds one [`CodecScope::Swarm`] prototype and clones it once per
/// established connection; `Handler` then clones that per-connection codec once
/// per substream. Transitioning `Swarm -> Connection` on the first clone mints
/// one semaphore pair per connection while sharing that pair across every
/// concurrent substream opened on the same connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodecScope {
    Swarm,
    Connection,
}

/// Owned semaphore permits keeping a received Garden frame charged against both
/// its per-connection and swarm-wide byte budgets until the consumer finishes
/// processing (and for `PutObject`, writing) the frame payload.
#[derive(Debug, Default)]
pub(super) struct FramePermits {
    _conn: Vec<tokio::sync::OwnedSemaphorePermit>,
    _swarm: Vec<tokio::sync::OwnedSemaphorePermit>,
}

/// Bounded wire frame paired with the in-flight byte permits charged while
/// reading it from the socket. Outbound frames carry empty permits.
#[derive(Debug, Default)]
pub(super) struct BudgetedFrame {
    bytes: Vec<u8>,
    permits: FramePermits,
}

impl BudgetedFrame {
    fn outbound(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            permits: FramePermits::default(),
        }
    }
}

/// The codec: one bounded frame per request and per response, with both a
/// per-connection share and a swarm-wide byte-granular budget held across read,
/// queueing, and consumer processing.
#[derive(Debug)]
struct GardenCodec {
    scope: CodecScope,
    large_frames: Arc<Semaphore>,
    conn_large_frames: Arc<Semaphore>,
    response_frames: Arc<Semaphore>,
    conn_response_frames: Arc<Semaphore>,
}

impl Clone for GardenCodec {
    fn clone(&self) -> Self {
        match self.scope {
            CodecScope::Swarm => Self {
                scope: CodecScope::Connection,
                large_frames: Arc::clone(&self.large_frames),
                conn_large_frames: Arc::new(Semaphore::new(
                    MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
                )),
                response_frames: Arc::clone(&self.response_frames),
                conn_response_frames: Arc::new(Semaphore::new(
                    MAX_CONN_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
                )),
            },
            CodecScope::Connection => Self {
                scope: CodecScope::Connection,
                large_frames: Arc::clone(&self.large_frames),
                conn_large_frames: Arc::clone(&self.conn_large_frames),
                response_frames: Arc::clone(&self.response_frames),
                conn_response_frames: Arc::clone(&self.conn_response_frames),
            },
        }
    }
}

impl Default for GardenCodec {
    fn default() -> Self {
        Self {
            scope: CodecScope::Swarm,
            large_frames: Arc::new(Semaphore::new(
                MAX_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
            )),
            conn_large_frames: Arc::new(Semaphore::new(
                MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
            )),
            response_frames: Arc::new(Semaphore::new(
                MAX_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
            )),
            conn_response_frames: Arc::new(Semaphore::new(
                MAX_CONN_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
            )),
        }
    }
}

/// Read up to `limit` total bytes (including any already-read `prefix`),
/// charging `conn_budget` first and `swarm_budget` second in
/// `LARGE_FRAME_UNIT_BYTES` increments strictly for bytes actually received and
/// returning the permits inside [`BudgetedFrame`] so the budget remains held
/// until the queued frame is consumed or dropped.
async fn read_bounded_budgeted<T>(
    io: &mut T,
    prefix: &[u8],
    limit: usize,
    conn_budget: Option<&Arc<Semaphore>>,
    swarm_budget: Option<&Arc<Semaphore>>,
    budget_err: &'static str,
) -> std::io::Result<BudgetedFrame>
where
    T: AsyncRead + Unpin + Send,
{
    let rest_limit = limit.saturating_sub(prefix.len());
    let mut buf = Vec::with_capacity(prefix.len());
    buf.extend_from_slice(prefix);
    let mut chunk = vec![0u8; LARGE_FRAME_UNIT_BYTES];
    let mut conn_charged = Vec::new();
    let mut swarm_charged = Vec::new();
    let mut charged_units = 0usize;
    let in_tokio = tokio::runtime::Handle::try_current().is_ok();
    loop {
        let read = if in_tokio {
            tokio::time::timeout(FRAME_CHUNK_TIMEOUT, io.read(&mut chunk))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "garden frame chunk read timed out",
                    )
                })??
        } else {
            io.read(&mut chunk).await?
        };
        if read == 0 {
            break;
        }
        let new_payload_len = buf.len().saturating_sub(prefix.len()).saturating_add(read);
        if new_payload_len > rest_limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("garden frame exceeds {limit} bytes"),
            ));
        }
        if conn_budget.is_some() || swarm_budget.is_some() {
            let needed_units = new_payload_len.div_ceil(LARGE_FRAME_UNIT_BYTES);
            let delta = needed_units.saturating_sub(charged_units);
            if delta > 0 {
                let delta_u32 = u32::try_from(delta)
                    .map_err(|_| std::io::Error::other("garden frame budget overflow"))?;
                let conn_permit = match conn_budget {
                    Some(sem) => Some(
                        sem.clone()
                            .try_acquire_many_owned(delta_u32)
                            .map_err(|_| std::io::Error::other(budget_err))?,
                    ),
                    None => None,
                };
                let swarm_permit = match swarm_budget {
                    Some(sem) => Some(
                        sem.clone()
                            .try_acquire_many_owned(delta_u32)
                            .map_err(|_| std::io::Error::other(budget_err))?,
                    ),
                    None => None,
                };
                if let Some(permit) = conn_permit {
                    conn_charged.push(permit);
                }
                if let Some(permit) = swarm_permit {
                    swarm_charged.push(permit);
                }
                charged_units = needed_units;
            }
        }
        let Some(slice) = chunk.get(..read) else {
            return Err(std::io::Error::other("short read chunk"));
        };
        buf.extend_from_slice(slice);
    }
    Ok(BudgetedFrame {
        bytes: buf,
        permits: FramePermits {
            _conn: conn_charged,
            _swarm: swarm_charged,
        },
    })
}

#[cfg(test)]
async fn read_bounded<T>(io: &mut T, limit: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    Ok(read_bounded_budgeted(io, &[], limit, None, None, "")
        .await?
        .bytes)
}

impl request_response::Codec for GardenCodec {
    type Protocol = StreamProtocol;
    type Request = BudgetedFrame;
    type Response = BudgetedFrame;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<BudgetedFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Peek the 4-byte bincode enum variant tag of GardenRequest so small
        // control requests (notably Hello, GetCommits, GetObject,
        // AdmissionStatus) never allocate up to MAX_REQUEST_BYTES before
        // reaching the swarm.
        let mut tag = [0u8; 4];
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::time::timeout(FRAME_CHUNK_TIMEOUT, io.read_exact(&mut tag))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "garden request tag read timed out",
                    )
                })??;
        } else {
            io.read_exact(&mut tag).await?;
        }
        let variant = u32::from_le_bytes(tag);
        let limit = match variant {
            0 => MAX_UNADMITTED_REQUEST_BYTES, // Hello
            2 | 5 => 64,                       // GetCommits | AdmissionStatus
            3 => 128,                          // GetObject
            1 | 4 => MAX_REQUEST_BYTES,        // Gossip | PutObject
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown garden request variant",
                ));
            }
        };
        // Charge the connection's own share first, then the swarm budget,
        // strictly for bytes actually received on large frames.
        let is_large = limit > MAX_UNADMITTED_REQUEST_BYTES;
        let conn_budget = is_large.then_some(&self.conn_large_frames);
        let swarm_budget = is_large.then_some(&self.large_frames);
        read_bounded_budgeted(
            io,
            &tag,
            limit,
            conn_budget,
            swarm_budget,
            "garden large frame budget is full",
        )
        .await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<BudgetedFrame>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded_budgeted(
            io,
            &[],
            MAX_RESPONSE_BYTES,
            Some(&self.conn_response_frames),
            Some(&self.response_frames),
            "garden response frame budget is full",
        )
        .await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: BudgetedFrame,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req.bytes).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: BudgetedFrame,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&resp.bytes).await?;
        io.close().await
    }
}

/// How many pending inbound handshakes one source prefix may hold in the
/// Garden's inbound pool. `libp2p::connection_limits` counts pending inbound
/// connections globally by id, so without a per-source cap one address fills
/// the pool and locks out every other validator.
const MAX_PENDING_INCOMING_PER_SOURCE: usize = 2;

/// Source prefix of a pending or unjoined inbound peer, grouped by IPv4 `/24`
/// or IPv6 `/64` so one host rotating addresses inside its prefix shares a cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceKey {
    V4([u8; 3]),
    V6([u8; 8]),
    Relay(PeerId),
}

impl SourceKey {
    /// True for loopback prefixes (`127.0.0.0/8` and `::1`), where in-process
    /// integration suites run multiple distinct nodes on one host.
    pub const fn is_loopback(self) -> bool {
        match self {
            Self::V4(octets) => octets[0] == 127,
            Self::V6(octets) => {
                octets[0] == 0
                    && octets[1] == 0
                    && octets[2] == 0
                    && octets[3] == 0
                    && octets[4] == 0
                    && octets[5] == 0
                    && octets[6] == 0
                    && octets[7] == 0
            }
            Self::Relay(_) => false,
        }
    }
}

fn source_key(address: &Multiaddr) -> Option<SourceKey> {
    let mut last_peer = None;
    let mut relay_peer = None;
    for part in address {
        match part {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                let octets = ip.octets();
                return Some(SourceKey::V4([octets[0], octets[1], octets[2]]));
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                if let Some(mapped) = ip.to_ipv4_mapped() {
                    let octets = mapped.octets();
                    return Some(SourceKey::V4([octets[0], octets[1], octets[2]]));
                }
                let octets = ip.octets();
                return Some(SourceKey::V6([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                    octets[7],
                ]));
            }
            libp2p::multiaddr::Protocol::P2p(peer) => {
                last_peer = Some(peer);
            }
            libp2p::multiaddr::Protocol::P2pCircuit if relay_peer.is_none() => {
                relay_peer = last_peer;
            }
            _ => {}
        }
    }
    relay_peer.map(SourceKey::Relay)
}

/// Refuses a pending inbound handshake from a source prefix that already holds
/// `MAX_PENDING_INCOMING_PER_SOURCE` pending handshakes.
#[derive(Default)]
struct PendingPerSource {
    pending: BTreeMap<SourceKey, HashSet<libp2p::swarm::ConnectionId>>,
}

impl PendingPerSource {
    fn forget(&mut self, source: SourceKey, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(held) = self.pending.get_mut(&source) {
            held.remove(&connection_id);
            if held.is_empty() {
                self.pending.remove(&source);
            }
        }
    }
}

impl NetworkBehaviour for PendingPerSource {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        _: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), libp2p::swarm::ConnectionDenied> {
        let source = source_key(remote_addr).ok_or_else(|| {
            libp2p::swarm::ConnectionDenied::new("garden handshake without a source address")
        })?;
        let held = self.pending.entry(source).or_default();
        if held.len() >= MAX_PENDING_INCOMING_PER_SOURCE {
            return Err(libp2p::swarm::ConnectionDenied::new(
                "too many pending garden handshakes from one source",
            ));
        }
        held.insert(connection_id);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        _: libp2p::PeerId,
        _: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        if let Some(source) = source_key(remote_addr) {
            self.forget(source, connection_id);
        }
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: Option<libp2p::PeerId>,
        _: &[Multiaddr],
        _: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, libp2p::swarm::ConnectionDenied> {
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: libp2p::PeerId,
        _: &Multiaddr,
        _: libp2p::core::Endpoint,
        _: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm<'_>) {
        if let libp2p::swarm::FromSwarm::ListenFailure(failure) = event {
            if let Some(source) = source_key(failure.send_back_addr) {
                self.forget(source, failure.connection_id);
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: libp2p::PeerId,
        _: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        std::task::Poll::Pending
    }
}

#[derive(NetworkBehaviour)]
struct GardenBehaviour {
    rpc: request_response::Behaviour<GardenCodec>,
    limits: libp2p::connection_limits::Behaviour,
    pending_per_source: PendingPerSource,
}

/// What the node asks of its swarm.
#[derive(Debug)]
pub(super) enum NetCommand {
    Dial(Multiaddr),
    /// Mark a peer as admitted after it proved possession of the invite.
    Admit(PeerId),
    /// Send a request. The response comes back as [`NetEvent::Response`]
    /// carrying the same `tag`.
    Send {
        peer: PeerId,
        request: GardenRequest,
        tag: u64,
    },
    Respond {
        channel: request_response::ResponseChannel<BudgetedFrame>,
        response: GardenResponse,
    },
    /// Close every connection to a peer.
    Disconnect(PeerId),
    Shutdown,
}

/// What the swarm tells the node.
#[derive(Debug)]
pub(super) enum NetEvent {
    Connected(PeerId),
    Disconnected(PeerId),
    DialFailed {
        peer: PeerId,
        wrong_peer_id: bool,
    },
    Request {
        peer: PeerId,
        request: GardenRequest,
        channel: request_response::ResponseChannel<BudgetedFrame>,
        budget: FramePermits,
    },
    Response {
        peer: PeerId,
        tag: u64,
        response: Result<GardenResponse, String>,
        budget: FramePermits,
    },
}

/// A running Garden swarm.
#[derive(Debug)]
pub(super) struct GardenNet {
    pub commands: mpsc::Sender<NetCommand>,
    pub events: mpsc::Receiver<NetEvent>,
    /// Source prefix observed for each currently connected peer.
    pub peer_sources: Arc<std::sync::Mutex<BTreeMap<PeerId, SourceKey>>>,
    /// The address the swarm is bound to.
    pub listen: Multiaddr,
}

/// True when `address` names every interface instead of one. Such a listen
/// address says nothing about where the node can be reached.
pub fn is_unspecified(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_unspecified(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

/// Open a swarm with the validator key as its identity and listen on
/// `listen`.
pub(super) async fn start(secret_key: [u8; 32], listen: &str) -> Result<GardenNet, String> {
    start_with(
        secret_key,
        listen,
        MAX_CONNECTIONS,
        libp2p::dns::tokio::Transport::system,
    )
    .await
}

/// [`start`] with the number of connections the swarm keeps.
async fn start_with<F>(
    secret_key: [u8; 32],
    listen: &str,
    max_connections: u32,
    build_dns: F,
) -> Result<GardenNet, String>
where
    F: FnOnce(
        tcp::tokio::Transport,
    ) -> std::io::Result<libp2p::dns::tokio::Transport<tcp::tokio::Transport>>,
{
    let listen: Multiaddr = listen
        .parse()
        .map_err(|e| format!("garden listen address is not a multiaddr: {e}"))?;
    let identity = identity::Keypair::ed25519_from_bytes(secret_key)
        .map_err(|e| format!("garden key cannot be a libp2p identity: {e}"))?;
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_other_transport(|key| {
            let noise_cfg = noise::Config::new(key)?;
            let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default());
            let upgraded = match build_dns(tcp_transport) {
                Ok(dns) => dns
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise_cfg)
                    .multiplex(yamux::Config::default())
                    .boxed(),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "garden system DNS resolver unavailable; falling back to direct IP/TCP transport"
                    );
                    tcp::tokio::Transport::new(tcp::Config::default())
                        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                        .authenticate(noise_cfg)
                        .multiplex(yamux::Config::default())
                        .boxed()
                }
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                libp2p::core::transport::timeout::TransportTimeout::new(
                    upgraded,
                    HANDSHAKE_TIMEOUT,
                ),
            )
        })
        .map_err(|e| format!("garden transport cannot start: {e}"))?
        .with_behaviour(|_| GardenBehaviour {
            rpc: request_response::Behaviour::new(
                [(
                    StreamProtocol::new(GARDEN_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(20))
                    .with_max_concurrent_streams(MAX_CONCURRENT_STREAMS),
            ),
            limits: libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(max_connections))
                    // Peers that dial in never take every slot: a third is
                    // kept for the dials of this node, so a crowd at the
                    // door cannot cut it off from its own Garden.
                    .with_max_established_incoming(Some(max_connections * 2 / 3))
                    .with_max_established_per_peer(Some(2))
                    // Backstop only: `PendingPerSource` caps each source prefix
                    // to `MAX_PENDING_INCOMING_PER_SOURCE` handshakes, so one
                    // address cannot spend the swarm-wide pool.
                    .with_max_pending_incoming(Some(max_connections))
                    .with_max_pending_outgoing(Some(max_connections / 3)),
            ),
            pending_per_source: PendingPerSource::default(),
        })
        .map_err(|e| format!("garden behaviour cannot start: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_mins(1)))
        .build();
    swarm
        .listen_on(listen)
        .map_err(|e| format!("garden swarm cannot listen: {e}"))?;
    let bound = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .map_err(|_| "garden swarm did not start listening".to_string())?;

    let (command_tx, mut command_rx) = mpsc::channel::<NetCommand>(1024);
    let (event_tx, event_rx) = mpsc::channel::<NetEvent>(1024);
    let peer_sources: Arc<std::sync::Mutex<BTreeMap<PeerId, SourceKey>>> =
        Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let peer_sources_task = Arc::clone(&peer_sources);
    let max_unadmitted_in = (max_connections as usize / 6).clamp(1, 4);
    tokio::spawn(async move {
        let mut tags = BTreeMap::new();
        let mut admitted: HashSet<PeerId> = HashSet::new();
        let mut unadmitted_in: VecDeque<PeerId> = VecDeque::new();
        let mut unadmitted_attempts: BTreeMap<PeerId, u8> = BTreeMap::new();
        let mut hello_window_start = Instant::now();
        let mut hello_window_count: usize = 0;
        let mut admitted_hellos: BTreeMap<PeerId, (Instant, usize)> = BTreeMap::new();
        // Events wait here, not in a blocking send: the task keeps taking
        // commands while the validator is busy, so the two channels can
        // never wait on each other. A full backlog stops the swarm from
        // being read, which pushes back on the remote side.
        let mut backlog: VecDeque<NetEvent> = VecDeque::new();
        loop {
            tokio::select! {
                permit = event_tx.reserve(), if !backlog.is_empty() => match permit {
                    Ok(permit) => {
                        if let Some(event) = backlog.pop_front() {
                            permit.send(event);
                        }
                    }
                    Err(_) => break,
                },
                command = command_rx.recv() => match command {
                    None | Some(NetCommand::Shutdown) => break,
                    Some(NetCommand::Dial(address)) => {
                        // Dial from a fresh port. Reusing the listen port
                        // binds it on every interface, and that bind fails
                        // for good once any other program holds the port
                        // on one of them. A Garden punches no holes, so
                        // the source port carries nothing. Bind the dial to
                        // the expected peer id when present so Noise rejects
                        // any mismatched remote immediately.
                        let target_peer = address.iter().find_map(|part| match part {
                            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                            _ => None,
                        });
                        let dial = match target_peer {
                            Some(peer_id) => DialOpts::peer_id(peer_id)
                                .addresses(vec![address])
                                .allocate_new_port()
                                .build(),
                            None => DialOpts::unknown_peer_id()
                                .address(address)
                                .allocate_new_port()
                                .build(),
                        };
                        if let Err(e) = swarm.dial(dial) {
                            tracing::debug!(error = %e, "garden dial refused");
                        }
                    }
                    Some(NetCommand::Admit(peer)) => {
                        admitted.insert(peer);
                        unadmitted_in.retain(|p| *p != peer);
                        unadmitted_attempts.remove(&peer);
                    }
                    Some(NetCommand::Send { peer, request, tag }) => match bincode::serialized_size(&request) {
                        Ok(size) if size <= MAX_REQUEST_BYTES as u64 => match bincode::serialize(&request) {
                            Ok(bytes) => {
                                let id = swarm
                                    .behaviour_mut()
                                    .rpc
                                    .send_request(&peer, BudgetedFrame::outbound(bytes));
                                tags.insert(id, tag);
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "garden request cannot be encoded");
                                backlog.push_back(NetEvent::Response {
                                    peer,
                                    tag,
                                    response: Err(format!("garden request cannot be encoded: {e}")),
                                    budget: FramePermits::default(),
                                });
                            }
                        },
                        Ok(size) => {
                            tracing::warn!(
                                bytes = size,
                                limit = MAX_REQUEST_BYTES,
                                "garden request exceeds frame limit"
                            );
                            backlog.push_back(NetEvent::Response {
                                peer,
                                tag,
                                response: Err(format!(
                                    "garden request exceeds {MAX_REQUEST_BYTES} bytes"
                                )),
                                budget: FramePermits::default(),
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "garden request cannot be sized");
                            backlog.push_back(NetEvent::Response {
                                peer,
                                tag,
                                response: Err(format!("garden request cannot be encoded: {e}")),
                                budget: FramePermits::default(),
                            });
                        }
                    },
                    Some(NetCommand::Respond { channel, response }) => {
                        let bytes = match bincode::serialized_size(&response) {
                            Ok(size) if size <= MAX_RESPONSE_BYTES as u64 => {
                                bincode::serialize(&response).ok()
                            }
                            Ok(size) => {
                                tracing::warn!(
                                    bytes = size,
                                    limit = MAX_RESPONSE_BYTES,
                                    "garden response exceeds frame limit"
                                );
                                bincode::serialize(&GardenResponse::Refused(format!(
                                    "garden response exceeds {MAX_RESPONSE_BYTES} bytes"
                                )))
                                .ok()
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "garden response cannot be sized");
                                None
                            }
                        };
                        if let Some(bytes) = bytes {
                            let _ = swarm
                                .behaviour_mut()
                                .rpc
                                .send_response(channel, BudgetedFrame::outbound(bytes));
                        }
                    }
                    Some(NetCommand::Disconnect(peer)) => {
                        admitted.remove(&peer);
                        unadmitted_in.retain(|p| *p != peer);
                        unadmitted_attempts.remove(&peer);
                        admitted_hellos.remove(&peer);
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                },
                event = swarm.select_next_some(), if backlog.len() < EVENT_BACKLOG => {
                    let out = match event {
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
                            if let Some(src) = source_key(endpoint.get_remote_address()) {
                                if let Ok(mut map) = peer_sources_task.lock() {
                                    map.entry(peer_id).or_insert(src);
                                }
                            }
                            if endpoint.is_listener() && !admitted.contains(&peer_id) {
                                unadmitted_in.retain(|p| *p != peer_id);
                                unadmitted_in.push_back(peer_id);
                                while unadmitted_in.len() > max_unadmitted_in {
                                    if let Some(oldest) = unadmitted_in.pop_front() {
                                        unadmitted_attempts.remove(&oldest);
                                        let _ = swarm.disconnect_peer_id(oldest);
                                    }
                                }
                            }
                            (num_established.get() == 1).then_some(NetEvent::Connected(peer_id))
                        }
                        SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                            if let Ok(mut map) = peer_sources_task.lock() {
                                map.remove(&peer_id);
                            }
                            admitted.remove(&peer_id);
                            unadmitted_in.retain(|p| *p != peer_id);
                            unadmitted_attempts.remove(&peer_id);
                            admitted_hellos.remove(&peer_id);
                            Some(NetEvent::Disconnected(peer_id))
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), error, .. } => {
                            let wrong_peer_id = matches!(
                                error,
                                libp2p::swarm::DialError::WrongPeerId { .. }
                            );
                            Some(NetEvent::DialFailed { peer, wrong_peer_id })
                        }
                        SwarmEvent::Behaviour(GardenBehaviourEvent::Rpc(
                            request_response::Event::Message { peer, message, .. },
                        )) => match message {
                            request_response::Message::Request { request, channel, .. } => {
                                let BudgetedFrame {
                                    bytes: request,
                                    permits: budget,
                                } = request;
                                if unadmitted_in.contains(&peer) && !admitted.contains(&peer) {
                                    let attempts = unadmitted_attempts.entry(peer).or_insert(0);
                                    *attempts = attempts.saturating_add(1);
                                    let too_many_from_peer = *attempts > MAX_UNADMITTED_REQUESTS_PER_PEER;
                                    if too_many_from_peer {
                                        let refusal = GardenResponse::Refused("too many greetings".into());
                                        if let Ok(bytes) = bincode::serialize(&refusal) {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .rpc
                                                .send_response(channel, BudgetedFrame::outbound(bytes));
                                        }
                                        unadmitted_in.retain(|p| *p != peer);
                                        unadmitted_attempts.remove(&peer);
                                        let _ = swarm.disconnect_peer_id(peer);
                                        None
                                    } else if request.len() > MAX_UNADMITTED_REQUEST_BYTES {
                                        let refusal = GardenResponse::Refused("show the invite first".into());
                                        if let Ok(bytes) = bincode::serialize(&refusal) {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .rpc
                                                .send_response(channel, BudgetedFrame::outbound(bytes));
                                        }
                                        unadmitted_in.retain(|p| *p != peer);
                                        unadmitted_attempts.remove(&peer);
                                        let _ = swarm.disconnect_peer_id(peer);
                                        None
                                    } else {
                                        if hello_window_start.elapsed() >= Duration::from_secs(1) {
                                            hello_window_start = Instant::now();
                                            hello_window_count = 0;
                                        }
                                        // A connection's first frame is its join greeting: serve it
                                        // without letting repeat traffic from other strangers starve
                                        // or disconnect a legitimate joiner. Only repeat frames draw
                                        // from the swarm-wide budget, and budget overflow refuses
                                        // the frame without disconnecting the peer.
                                        let first_frame = *attempts <= 1;
                                        let throttled = if first_frame {
                                            false
                                        } else {
                                            hello_window_count = hello_window_count.saturating_add(1);
                                            hello_window_count > MAX_UNADMITTED_HELLOS_PER_SEC
                                        };
                                        if throttled {
                                            let refusal = GardenResponse::Refused("too many greetings".into());
                                            if let Ok(bytes) = bincode::serialize(&refusal) {
                                                let _ = swarm
                                                    .behaviour_mut()
                                                    .rpc
                                                    .send_response(channel, BudgetedFrame::outbound(bytes));
                                            }
                                            None
                                        } else {
                                            match crate::network::bounded_bincode::decode_bounded_bincode::<GardenRequest>(
                                                &request,
                                                MAX_UNADMITTED_REQUEST_BYTES,
                                            ) {
                                                Ok(request @ GardenRequest::Hello { .. }) => {
                                                    Some(NetEvent::Request { peer, request, channel, budget })
                                                }
                                                Ok(_) => {
                                                    let refusal = GardenResponse::Refused("show the invite first".into());
                                                    if let Ok(bytes) = bincode::serialize(&refusal) {
                                                        let _ = swarm
                                                            .behaviour_mut()
                                                            .rpc
                                                            .send_response(channel, BudgetedFrame::outbound(bytes));
                                                    }
                                                    None
                                                }
                                                Err(_) => {
                                                    let refusal = GardenResponse::Refused("malformed request".into());
                                                    if let Ok(bytes) = bincode::serialize(&refusal) {
                                                        let _ = swarm
                                                            .behaviour_mut()
                                                            .rpc
                                                            .send_response(channel, BudgetedFrame::outbound(bytes));
                                                    }
                                                    None
                                                }
                                            }
                                        }
                                    }
                                } else if let Ok(request) = crate::network::bounded_bincode::decode_bounded_bincode::<GardenRequest>(
                                    &request,
                                    MAX_REQUEST_BYTES,
                                ) {
                                    // Rate-limit repeated greetings and admission polls from
                                    // already-admitted peers so one member cannot spend the
                                    // validator loop on invite signature checks and genesis copies.
                                    if matches!(
                                        request,
                                        GardenRequest::Hello { .. } | GardenRequest::AdmissionStatus
                                    ) {
                                        let entry = admitted_hellos
                                            .entry(peer)
                                            .or_insert_with(|| (Instant::now(), 0));
                                        if entry.0.elapsed() >= Duration::from_secs(1) {
                                            *entry = (Instant::now(), 0);
                                        }
                                        entry.1 = entry.1.saturating_add(1);
                                        if entry.1 > MAX_HELLOS_PER_PEER_PER_SEC {
                                            let refusal = GardenResponse::Refused("too many greetings".into());
                                            if let Ok(bytes) = bincode::serialize(&refusal) {
                                                let _ = swarm
                                                    .behaviour_mut()
                                                    .rpc
                                                    .send_response(channel, BudgetedFrame::outbound(bytes));
                                            }
                                            None
                                        } else {
                                            Some(NetEvent::Request { peer, request, channel, budget })
                                        }
                                    } else {
                                        Some(NetEvent::Request { peer, request, channel, budget })
                                    }
                                } else {
                                    let refusal = GardenResponse::Refused("malformed request".into());
                                    if let Ok(bytes) = bincode::serialize(&refusal) {
                                        let _ = swarm
                                            .behaviour_mut()
                                            .rpc
                                            .send_response(channel, BudgetedFrame::outbound(bytes));
                                    }
                                    None
                                }
                            }
                            request_response::Message::Response { request_id, response } => {
                                let BudgetedFrame {
                                    bytes: response,
                                    permits: budget,
                                } = response;
                                tags.remove(&request_id).map(|tag| NetEvent::Response {
                                    peer,
                                    tag,
                                    response: crate::network::bounded_bincode::decode_bounded_bincode::<GardenResponse>(
                                        &response,
                                        MAX_RESPONSE_BYTES,
                                    )
                                    .map_err(|_| "malformed response".to_string()),
                                    budget,
                                })
                            }
                        },
                        SwarmEvent::Behaviour(GardenBehaviourEvent::Rpc(
                            request_response::Event::OutboundFailure { peer, request_id, error, .. },
                        )) => tags.remove(&request_id).map(|tag| NetEvent::Response {
                            peer,
                            tag,
                            response: Err(error.to_string()),
                            budget: FramePermits::default(),
                        }),
                        _ => None,
                    };
                    if let Some(out) = out {
                        backlog.push_back(out);
                    }
                }
            }
        }
    });
    Ok(GardenNet {
        commands: command_tx,
        events: event_rx,
        peer_sources,
        listen: bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::KeyPair;

    #[test]
    fn garden_announced_address_must_name_the_announcing_validator() {
        let me = KeyPair::generate().unwrap().public_key_bytes();
        let other = KeyPair::generate().unwrap().public_key_bytes();
        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let address = announced_address(&listen, &me).unwrap();
        validator_dial_address(&address, &me).unwrap();
        assert!(validator_dial_address(&address, &other).is_err());
        assert!(validator_dial_address("/ip4/10.0.0.1/tcp/22", &me).is_err());
        assert!(validator_dial_address("http://10.0.0.1/", &me).is_err());
        let id = peer_id_of(&me).unwrap();
        for bad in [
            format!("/ip4/169.254.169.254/tcp/4001/p2p/{id}"),
            format!("/ip6/fe80::1/tcp/4001/p2p/{id}"),
            format!("/ip6/::ffff:169.254.169.254/tcp/4001/p2p/{id}"),
            format!("/ip6/::ffff:0.0.0.0/tcp/4001/p2p/{id}"),
        ] {
            assert!(
                validator_dial_address(&bad, &me).is_err(),
                "expected link-local or invalid mapped address refusal for {bad}"
            );
        }
    }

    #[test]
    fn garden_frame_past_the_limit_is_refused_not_truncated() {
        use futures::executor::block_on;
        use futures::io::Cursor;
        let mut ok = Cursor::new(vec![1u8; 8]);
        assert_eq!(block_on(read_bounded(&mut ok, 8)).unwrap().len(), 8);
        let mut long = Cursor::new(vec![1u8; 9]);
        assert!(block_on(read_bounded(&mut long, 8)).is_err());
    }

    /// Another program holds the Garden port on a second interface; a port
    /// forwarder does exactly that. The dial must still go out.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn garden_dial_survives_a_foreign_socket_on_the_listen_port() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let mut net_a = start(a.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let net_b = start(b.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let port = net_a
            .listen
            .iter()
            .find_map(|part| match part {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap();
        let _foreign = std::net::TcpListener::bind(("127.0.0.2", port)).unwrap();
        let b_id = peer_id_of(&b.public_key_bytes()).unwrap();
        let address = announced_address(&net_b.listen, &b.public_key_bytes()).unwrap();
        net_a
            .commands
            .send(NetCommand::Dial(address.parse().unwrap()))
            .await
            .unwrap();
        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(NetEvent::Connected(peer)) = net_a.events.recv().await {
                    return peer;
                }
            }
        })
        .await
        .expect("the dial never connected");
        assert_eq!(connected, b_id);
    }

    /// What a validator announces is dialed by everybody else, so it is one
    /// host, one TCP port and the validator's own peer id at the end, and
    /// nothing else. A peer id anywhere else binds nothing: the socket that
    /// is dialed is the one the address ends in.
    #[test]
    fn garden_dial_address_is_one_host_one_port_and_the_validator_behind_it() {
        let me = KeyPair::generate().unwrap().public_key_bytes();
        let id = peer_id_of(&me).unwrap();
        for good in [
            format!("/ip4/192.168.1.20/tcp/4001/p2p/{id}"),
            format!("/ip6/::1/tcp/4001/p2p/{id}"),
            format!("/dns4/garden.example/tcp/4001/p2p/{id}"),
        ] {
            validator_dial_address(&good, &me).unwrap();
        }
        for bad in [
            format!("/p2p/{id}/ip4/10.0.0.9/tcp/6379"),
            format!("/ip4/10.0.0.9/tcp/4001/p2p/{id}/ip4/10.0.0.9/tcp/6379"),
            format!("/ip4/10.0.0.9/tcp/22/p2p/{id}"),
            format!("/ip4/10.0.0.9/tcp/0/p2p/{id}"),
            format!("/ip4/0.0.0.0/tcp/4001/p2p/{id}"),
            format!("/ip4/224.0.0.1/tcp/4001/p2p/{id}"),
            format!("/ip4/255.255.255.255/tcp/4001/p2p/{id}"),
            format!("/ip6/::/tcp/4001/p2p/{id}"),
            format!("/ip4/10.0.0.9/udp/4001/p2p/{id}"),
        ] {
            assert!(validator_dial_address(&bad, &me).is_err(), "{bad}");
        }
    }

    /// Peers that dial in must not take the slots this node dials out with:
    /// a node whose every slot is held by strangers cannot reach its own
    /// Garden any more.
    #[tokio::test]
    async fn garden_inbound_peers_leave_room_for_the_dials_of_this_node() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let mut net_a = start_with(
            a.private_key_bytes(),
            "/ip4/127.0.0.1/tcp/0",
            6,
            libp2p::dns::tokio::Transport::system,
        )
        .await
        .unwrap();
        let net_b = start(b.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let a_address: Multiaddr = announced_address(&net_a.listen, &a.public_key_bytes())
            .unwrap()
            .parse()
            .unwrap();
        let mut strangers = Vec::new();
        for _ in 0..6 {
            let key = KeyPair::generate().unwrap();
            let net = start(key.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
                .await
                .unwrap();
            net.commands
                .send(NetCommand::Dial(a_address.clone()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            strangers.push(net);
        }
        // Let every stranger that gets in get in.
        let mut inside = 0;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_secs(2), net_a.events.recv()).await
        {
            if matches!(event, NetEvent::Connected(_)) {
                inside += 1;
            }
        }
        assert!(inside >= 3, "only {inside} strangers connected");

        let b_id = peer_id_of(&b.public_key_bytes()).unwrap();
        let address = announced_address(&net_b.listen, &b.public_key_bytes()).unwrap();
        net_a
            .commands
            .send(NetCommand::Dial(address.parse().unwrap()))
            .await
            .unwrap();
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match net_a.events.recv().await {
                    Some(NetEvent::Connected(peer)) if peer == b_id => return true,
                    Some(_) => {}
                    None => return false,
                }
            }
        })
        .await;
        assert_eq!(reached, Ok(true), "inbound peers took every slot");
        drop(strangers);
    }

    #[tokio::test]
    async fn garden_swarms_exchange_a_request_over_noise() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let mut net_a = start(a.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let mut net_b = start(b.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let a_id = peer_id_of(&a.public_key_bytes()).unwrap();
        let b_id = peer_id_of(&b.public_key_bytes()).unwrap();
        let address = announced_address(&net_b.listen, &b.public_key_bytes()).unwrap();
        net_a
            .commands
            .send(NetCommand::Dial(address.parse().unwrap()))
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Connected(peer)) = net_a.events.recv().await {
                assert_eq!(peer, b_id);
                break;
            }
        }
        loop {
            if let Some(NetEvent::Connected(peer)) = net_b.events.recv().await {
                assert_eq!(peer, a_id);
                net_b.commands.send(NetCommand::Admit(a_id)).await.unwrap();
                break;
            }
        }
        net_a
            .commands
            .send(NetCommand::Send {
                peer: b_id,
                request: GardenRequest::GetCommits {
                    from_height: 1,
                    max: 4,
                },
                tag: 7,
            })
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Request {
                request, channel, ..
            }) = net_b.events.recv().await
            {
                assert!(matches!(
                    request,
                    GardenRequest::GetCommits {
                        from_height: 1,
                        max: 4
                    }
                ));
                net_b
                    .commands
                    .send(NetCommand::Respond {
                        channel,
                        response: GardenResponse::Commits(Vec::new()),
                    })
                    .await
                    .unwrap();
                break;
            }
        }
        loop {
            if let Some(NetEvent::Response { tag, response, .. }) = net_a.events.recv().await {
                assert_eq!(tag, 7);
                assert!(matches!(response, Ok(GardenResponse::Commits(c)) if c.is_empty()));
                break;
            }
        }
    }

    #[test]
    fn garden_codec_bounds_hello_frames_below_max_request_bytes() {
        use futures::executor::block_on;
        use futures::io::Cursor;
        use libp2p::request_response::Codec;
        let proto = StreamProtocol::new(GARDEN_PROTOCOL);
        let mut codec = GardenCodec::default();
        // Variant 0 (Hello) larger than MAX_UNADMITTED_REQUEST_BYTES is refused.
        let mut oversized = vec![0u8; MAX_UNADMITTED_REQUEST_BYTES + 64];
        if let Some(prefix) = oversized.get_mut(..4) {
            prefix.copy_from_slice(&0u32.to_le_bytes());
        }
        let mut cursor = Cursor::new(oversized);
        assert!(block_on(codec.read_request(&proto, &mut cursor)).is_err());

        // Variant 5 (AdmissionStatus) larger than 64 bytes is refused.
        let mut oversized_status = vec![0u8; 128];
        if let Some(prefix) = oversized_status.get_mut(..4) {
            prefix.copy_from_slice(&5u32.to_le_bytes());
        }
        let mut status_cursor = Cursor::new(oversized_status);
        assert!(block_on(codec.read_request(&proto, &mut status_cursor)).is_err());

        // Unknown variant tag is also refused immediately.
        let mut unknown = Cursor::new(99u32.to_le_bytes().to_vec());
        assert!(block_on(codec.read_request(&proto, &mut unknown)).is_err());

        // Large-frame and response-frame byte budgets are initialized to full
        // unit capacity.
        assert_eq!(
            codec.large_frames.available_permits(),
            MAX_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES
        );
        assert_eq!(
            codec.response_frames.available_permits(),
            MAX_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES
        );
    }

    #[tokio::test]
    async fn garden_admitted_peer_greetings_are_rate_limited() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let mut net_a = start(a.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let mut net_b = start(b.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let a_id = peer_id_of(&a.public_key_bytes()).unwrap();
        let b_id = peer_id_of(&b.public_key_bytes()).unwrap();
        let address = announced_address(&net_b.listen, &b.public_key_bytes()).unwrap();
        net_a
            .commands
            .send(NetCommand::Dial(address.parse().unwrap()))
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Connected(peer)) = net_a.events.recv().await {
                if peer == b_id {
                    break;
                }
            }
        }
        loop {
            if let Some(NetEvent::Connected(peer)) = net_b.events.recv().await {
                if peer == a_id {
                    net_b.commands.send(NetCommand::Admit(a_id)).await.unwrap();
                    break;
                }
            }
        }
        let hello = GardenRequest::Hello {
            chain_id: 7,
            key: a.public_key_bytes(),
            invite_signature: vec![0u8; 64],
        };
        let total = MAX_HELLOS_PER_PEER_PER_SEC + 4;
        for i in 0..total {
            net_a
                .commands
                .send(NetCommand::Send {
                    peer: b_id,
                    request: hello.clone(),
                    tag: i as u64,
                })
                .await
                .unwrap();
        }
        let mut forwarded = 0usize;
        let mut refused = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while forwarded + refused < total && tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(NetEvent::Request { channel, .. }) = net_b.events.recv() => {
                    forwarded += 1;
                    let _ = net_b.commands.send(NetCommand::Respond {
                        channel,
                        response: GardenResponse::Ack,
                    }).await;
                }
                Some(NetEvent::Response { response, .. }) = net_a.events.recv() => {
                    if let Ok(GardenResponse::Refused(msg)) = response {
                        if msg.contains("too many greetings") {
                            refused += 1;
                        }
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(
            forwarded <= MAX_HELLOS_PER_PEER_PER_SEC,
            "forwarded={forwarded} exceeded cap {MAX_HELLOS_PER_PEER_PER_SEC}"
        );
        assert!(
            refused >= 4,
            "expected excess admitted greetings to be refused, got refused={refused}"
        );
    }

    #[tokio::test]
    async fn garden_unadmitted_first_greeting_survives_stranger_burst() {
        let host = KeyPair::generate().unwrap();
        let spammer = KeyPair::generate().unwrap();
        let joiner = KeyPair::generate().unwrap();
        let mut net_host = start(host.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let mut net_spam = start(spammer.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let mut net_join = start(joiner.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let host_id = peer_id_of(&host.public_key_bytes()).unwrap();
        let join_id = peer_id_of(&joiner.public_key_bytes()).unwrap();
        let address: Multiaddr = announced_address(&net_host.listen, &host.public_key_bytes())
            .unwrap()
            .parse()
            .unwrap();
        net_spam
            .commands
            .send(NetCommand::Dial(address.clone()))
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Connected(p)) = net_spam.events.recv().await {
                if p == host_id {
                    break;
                }
            }
        }
        // Exhaust the swarm-wide repeat-greeting budget with multiple spammer connections.
        for tag in 0..u64::from(MAX_UNADMITTED_REQUESTS_PER_PEER) {
            let _ = net_spam
                .commands
                .send(NetCommand::Send {
                    peer: host_id,
                    request: GardenRequest::Hello {
                        chain_id: 7,
                        key: spammer.public_key_bytes(),
                        invite_signature: vec![0u8; 64],
                    },
                    tag,
                })
                .await;
        }
        // Now a fresh invited joiner connects and sends its first Hello; it
        // must still reach the host instead of being dropped or disconnected.
        net_join
            .commands
            .send(NetCommand::Dial(address))
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Connected(p)) = net_join.events.recv().await {
                if p == host_id {
                    break;
                }
            }
        }
        net_join
            .commands
            .send(NetCommand::Send {
                peer: host_id,
                request: GardenRequest::Hello {
                    chain_id: 7,
                    key: joiner.public_key_bytes(),
                    invite_signature: vec![1u8; 64],
                },
                tag: 99,
            })
            .await
            .unwrap();
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(NetEvent::Request { peer, .. }) = net_host.events.recv().await {
                    if peer == join_id {
                        return true;
                    }
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(reached, "invited joiner's first greeting was dropped");
    }

    #[tokio::test]
    async fn garden_half_open_tcp_sockets_time_out_and_free_pending_slots() {
        let host = KeyPair::generate().unwrap();
        let joiner = KeyPair::generate().unwrap();
        let net_host = start_with(
            host.private_key_bytes(),
            "/ip4/127.0.0.1/tcp/0",
            24,
            libp2p::dns::tokio::Transport::system,
        )
        .await
        .unwrap();
        let mut net_join = start(joiner.private_key_bytes(), "/ip4/127.0.0.1/tcp/0")
            .await
            .unwrap();
        let port = net_host
            .listen
            .iter()
            .find_map(|p| match p {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap();
        // Open more silent TCP sockets than `max_pending_incoming` (24/6 = 4).
        let mut silent = Vec::new();
        for _ in 0..6 {
            silent.push(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap(),
            );
        }
        // Wait past HANDSHAKE_TIMEOUT so the silent sockets are closed and
        // pending inbound slots are reclaimed.
        tokio::time::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(600)).await;
        let host_id = peer_id_of(&host.public_key_bytes()).unwrap();
        let address: Multiaddr = announced_address(&net_host.listen, &host.public_key_bytes())
            .unwrap()
            .parse()
            .unwrap();
        net_join
            .commands
            .send(NetCommand::Dial(address))
            .await
            .unwrap();
        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(NetEvent::Connected(peer)) = net_join.events.recv().await {
                    if peer == host_id {
                        return true;
                    }
                }
            }
        })
        .await
        .unwrap_or(false);
        drop(silent);
        assert!(
            connected,
            "legitimate peer could not connect after half-open TCP timeout"
        );
        let _ = net_host.commands.send(NetCommand::Shutdown).await;
        let _ = net_join.commands.send(NetCommand::Shutdown).await;
    }

    #[tokio::test]
    async fn garden_codec_charges_large_frames_and_responses_by_bytes_received_not_stalled_tag() {
        use futures::io::Cursor;
        use libp2p::request_response::Codec;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        /// Sends a 4-byte `Gossip` tag and then stalls forever.
        struct StalledAfterTag {
            tag: [u8; 4],
            offset: usize,
        }

        impl AsyncRead for StalledAfterTag {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                if self.offset < self.tag.len() {
                    let take = (self.tag.len() - self.offset).min(buf.len());
                    buf[..take].copy_from_slice(&self.tag[self.offset..self.offset + take]);
                    self.offset += take;
                    Poll::Ready(Ok(take))
                } else {
                    Poll::Pending
                }
            }
        }

        let proto = StreamProtocol::new(GARDEN_PROTOCOL);
        let mut codec = GardenCodec::default();
        let full_req_units = codec.large_frames.available_permits();
        let full_resp_units = codec.response_frames.available_permits();

        // A peer that writes only the 4-byte Gossip tag and stalls holds zero
        // units from the large-frame budget.
        let mut stalled_codec = codec.clone();
        let mut stalled = StalledAfterTag {
            tag: 1u32.to_le_bytes(),
            offset: 0,
        };
        let stalled_res = tokio::time::timeout(
            Duration::from_millis(50),
            stalled_codec.read_request(&proto, &mut stalled),
        )
        .await;
        assert!(stalled_res.is_err(), "stalled stream must stay pending");
        assert_eq!(
            codec.large_frames.available_permits(),
            full_req_units,
            "stalled peer must hold zero large-frame units before sending payload bytes"
        );

        // Exhaust the response budget and confirm read_response fails fast
        // rather than buffering unbounded response frames.
        let held = codec
            .response_frames
            .clone()
            .try_acquire_many_owned(u32::try_from(full_resp_units).unwrap())
            .unwrap();
        let mut resp_cursor = Cursor::new(vec![0xAAu8; 16]);
        let err = codec
            .read_response(&proto, &mut resp_cursor)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("response frame budget"),
            "unexpected error: {err}"
        );
        drop(held);
        assert_eq!(codec.response_frames.available_permits(), full_resp_units);
        let mut ok_cursor = Cursor::new(vec![0xBBu8; 16]);
        let read_back = codec.read_response(&proto, &mut ok_cursor).await.unwrap();
        assert_eq!(read_back.bytes, vec![0xBBu8; 16]);
        assert_eq!(
            codec.response_frames.available_permits(),
            full_resp_units - 1
        );
        drop(read_back);
        assert_eq!(codec.response_frames.available_permits(), full_resp_units);
    }

    #[test]
    fn pending_per_source_caps_one_prefix_without_blocking_other_prefixes() {
        let mut limiter = PendingPerSource::default();
        let local: Multiaddr = "/ip4/127.0.0.1/tcp/7000".parse().unwrap();
        let same_net_a: Multiaddr = "/ip4/198.51.100.10/tcp/40001".parse().unwrap();
        let same_net_b: Multiaddr = "/ip4/198.51.100.99/tcp/40002".parse().unwrap();
        let same_net_c: Multiaddr = "/ip4/198.51.100.200/tcp/40003".parse().unwrap();
        let other_net: Multiaddr = "/ip4/203.0.113.5/tcp/40004".parse().unwrap();

        let id1 = libp2p::swarm::ConnectionId::new_unchecked(1);
        let id2 = libp2p::swarm::ConnectionId::new_unchecked(2);
        let id3 = libp2p::swarm::ConnectionId::new_unchecked(3);
        let id4 = libp2p::swarm::ConnectionId::new_unchecked(4);

        assert!(limiter
            .handle_pending_inbound_connection(id1, &local, &same_net_a)
            .is_ok());
        assert!(limiter
            .handle_pending_inbound_connection(id2, &local, &same_net_b)
            .is_ok());
        // Third pending handshake from the same /24 prefix is refused.
        assert!(limiter
            .handle_pending_inbound_connection(id3, &local, &same_net_c)
            .is_err());
        // Another /24 prefix is completely unaffected.
        assert!(limiter
            .handle_pending_inbound_connection(id4, &local, &other_net)
            .is_ok());

        // Completing one handshake releases its slot for that prefix.
        let peer = PeerId::random();
        assert!(limiter
            .handle_established_inbound_connection(id1, peer, &local, &same_net_a)
            .is_ok());
        assert!(limiter
            .handle_pending_inbound_connection(id3, &local, &same_net_c)
            .is_ok());
    }

    #[test]
    fn garden_codec_clone_isolates_per_connection_large_and_response_shares() {
        let base = GardenCodec::default();
        let conn_a = base.clone();
        let conn_b = base;

        let per_conn_req =
            u32::try_from(MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES).unwrap();
        // Connection A consumes its entire per-connection large-request share.
        let held_conn_a = conn_a
            .conn_large_frames
            .clone()
            .try_acquire_many_owned(per_conn_req)
            .expect("connection A acquires its full large-frame share");
        let held_swarm_a = conn_a
            .large_frames
            .clone()
            .try_acquire_many_owned(per_conn_req)
            .expect("swarm grants connection A's share");
        // Connection A cannot take one more unit on a second concurrent stream.
        assert!(conn_a.conn_large_frames.try_acquire().is_err());
        // Connection B still gets its own full large-request share and swarm budget.
        let held_conn_b = conn_b
            .conn_large_frames
            .clone()
            .try_acquire_many_owned(per_conn_req)
            .expect("connection B retains its own large-frame share");
        let held_swarm_b = conn_b
            .large_frames
            .clone()
            .try_acquire_many_owned(per_conn_req)
            .expect("swarm still has room for connection B");
        drop((held_conn_a, held_swarm_a, held_conn_b, held_swarm_b));

        // Same isolation holds for response frame budgets.
        let per_conn_resp =
            u32::try_from(MAX_CONN_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES)
                .unwrap();
        let _resp_a = conn_a
            .conn_response_frames
            .clone()
            .try_acquire_many_owned(per_conn_resp)
            .unwrap();
        assert!(conn_a.conn_response_frames.try_acquire().is_err());
        assert!(conn_b
            .conn_response_frames
            .try_acquire_many_owned(per_conn_resp)
            .is_ok());
    }

    #[test]
    fn source_key_groups_public_prefixes_and_detects_loopback() {
        let pub_a: Multiaddr = "/ip4/198.51.100.10/tcp/4001".parse().unwrap();
        let pub_b: Multiaddr = "/ip4/198.51.100.250/tcp/4002".parse().unwrap();
        let mapped: Multiaddr = "/ip6/::ffff:198.51.100.77/tcp/4003".parse().unwrap();
        let loop4: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let loop6: Multiaddr = "/ip6/::1/tcp/4001".parse().unwrap();
        let k_a = source_key(&pub_a).unwrap();
        assert_eq!(k_a, source_key(&pub_b).unwrap());
        assert_eq!(k_a, source_key(&mapped).unwrap());
        assert!(!k_a.is_loopback());
        assert!(source_key(&loop4).unwrap().is_loopback());
        assert!(source_key(&loop6).unwrap().is_loopback());
    }

    #[test]
    fn garden_codec_substream_clones_share_connection_frame_budget() {
        // `Behaviour` holds the swarm prototype and clones once per connection;
        // `Handler` then clones each per-connection codec once per substream.
        let swarm_proto = GardenCodec::default();
        let conn_a = swarm_proto.clone();
        let conn_b = swarm_proto.clone();

        let stream_a1 = conn_a.clone();
        let stream_a2 = conn_a.clone();

        let per_conn_req =
            u32::try_from(MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES).unwrap();
        let _held = stream_a1
            .conn_large_frames
            .try_acquire_many_owned(per_conn_req)
            .expect("first substream acquires connection A budget");
        assert!(
            stream_a2.conn_large_frames.try_acquire().is_err(),
            "sibling substream on connection A must share connection A frame budget"
        );
        assert!(
            conn_b
                .clone()
                .conn_large_frames
                .try_acquire_many_owned(per_conn_req)
                .is_ok(),
            "substream on independent connection B retains its own share"
        );
    }

    #[tokio::test]
    async fn completed_frame_holds_connection_and_swarm_budget_until_dropped() {
        let conn_sem = Arc::new(Semaphore::new(2));
        let swarm_sem = Arc::new(Semaphore::new(3));
        let payload = vec![0xA5u8; LARGE_FRAME_UNIT_BYTES * 2];
        let mut cursor = futures::io::Cursor::new(payload.clone());

        let queued_frame = read_bounded_budgeted(
            &mut cursor,
            &[],
            MAX_REQUEST_BYTES,
            Some(&conn_sem),
            Some(&swarm_sem),
            "budget full",
        )
        .await
        .expect("frame within budget succeeds");

        // While `queued_frame` remains buffered in the handler/channel/node,
        // both the per-connection and swarm semaphores must stay charged.
        assert_eq!(
            conn_sem.available_permits(),
            0,
            "buffered frame must hold its per-connection permits until consumed"
        );
        assert_eq!(
            swarm_sem.available_permits(),
            1,
            "buffered frame must hold its swarm permits until consumed"
        );

        let mut second = futures::io::Cursor::new(vec![0x5Au8; LARGE_FRAME_UNIT_BYTES]);
        let denied = read_bounded_budgeted(
            &mut second,
            &[],
            MAX_REQUEST_BYTES,
            Some(&conn_sem),
            Some(&swarm_sem),
            "budget full",
        )
        .await;
        assert!(
            denied.is_err(),
            "concurrent read exceeding held connection budget must fail closed"
        );

        drop(queued_frame);
        assert_eq!(conn_sem.available_permits(), 2);
        assert_eq!(swarm_sem.available_permits(), 3);
    }

    #[tokio::test]
    async fn garden_starts_and_connects_over_ip_without_system_dns() {
        let missing_dns = |_: tcp::tokio::Transport| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing /etc/resolv.conf",
            ))
        };
        let mut host = start_with(
            [0x31u8; 32],
            "/ip4/127.0.0.1/tcp/0",
            MAX_CONNECTIONS,
            missing_dns,
        )
        .await
        .expect("host swarm falls back to IP/TCP when system DNS is absent");
        let peer = start_with(
            [0x32u8; 32],
            "/ip4/127.0.0.1/tcp/0",
            MAX_CONNECTIONS,
            missing_dns,
        )
        .await
        .expect("peer swarm falls back to IP/TCP when system DNS is absent");
        let host_addr = host.listen.clone();
        peer.commands
            .send(NetCommand::Dial(host_addr))
            .await
            .expect("send dial");
        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(host.events.recv().await, Some(NetEvent::Connected(_))) {
                    return true;
                }
            }
        })
        .await
        .expect("loopback IP connection completes without DNS");
        assert!(connected);
        let _ = peer.commands.send(NetCommand::Shutdown).await;
        let _ = host.commands.send(NetCommand::Shutdown).await;

        // Also exercise the public `start()` entrypoint directly (used inside
        // isolated DNS-less mount namespaces during end-to-end verification).
        let live = start([0x33u8; 32], "/ip4/127.0.0.1/tcp/0")
            .await
            .expect("public start succeeds with or without /etc/resolv.conf");
        let _ = live.commands.send(NetCommand::Shutdown).await;
    }

    #[test]
    fn forged_length_prefix_garden_frames_are_rejected_without_allocating() {
        let forged_frame = |variant: u32| {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&variant.to_le_bytes());
            buf.extend_from_slice(&0x0000_FFFF_FFFF_FFFFu64.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf
        };
        assert!(
            crate::network::bounded_bincode::decode_bounded_bincode::<GardenRequest>(
                &forged_frame(1),
                MAX_UNADMITTED_REQUEST_BYTES,
            )
            .is_err()
        );
        assert!(
            crate::network::bounded_bincode::decode_bounded_bincode::<GardenResponse>(
                &forged_frame(2),
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );
        assert!(
            crate::network::bounded_bincode::decode_bounded_bincode::<GardenResponse>(
                &forged_frame(4),
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn source_key_buckets_circuit_only_relay_multiaddr_by_relay_peer() {
        let relay = PeerId::random();
        let client_a = PeerId::random();
        let client_b = PeerId::random();
        let addr_a: Multiaddr = format!("/p2p/{relay}/p2p-circuit/p2p/{client_a}")
            .parse()
            .expect("valid circuit multiaddr");
        let addr_b: Multiaddr = format!("/p2p/{relay}/p2p-circuit/p2p/{client_b}")
            .parse()
            .expect("valid circuit multiaddr");
        let other_relay = PeerId::random();
        let addr_c: Multiaddr = format!("/p2p/{other_relay}/p2p-circuit/p2p/{client_a}")
            .parse()
            .expect("valid circuit multiaddr");
        let key_a = source_key(&addr_a).expect("circuit-only relay multiaddr must yield a key");
        let key_b = source_key(&addr_b).expect("circuit-only relay multiaddr must yield a key");
        let key_c = source_key(&addr_c).expect("distinct relay multiaddr must yield a key");
        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
        assert!(!key_a.is_loopback());
    }
}
