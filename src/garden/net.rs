//! The Garden network: a dedicated libp2p swarm and one protocol.
//!
//! A Garden never shares a connection with the Budlum network. Each node
//! opens a swarm of its own (TCP, Noise, Yamux) whose identity is the
//! validator key, and speaks one request and response protocol on it.
//!
//! Every frame is bounded. A peer has to show the invite before anything
//! but the greeting is answered.

use super::types::{
    GardenBlock, GardenCommit, GardenGenesis, GardenKey, GardenPresence, GardenVote, SignedGardenTx,
};
use crate::domain::types::Hash32;
use futures::prelude::*;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, request_response, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;

/// The one protocol a Garden swarm speaks.
const GARDEN_PROTOCOL: &str = "/budlum/garden/1";
/// Largest request frame. A request carries at most one block or one object.
pub const MAX_REQUEST_BYTES: usize = 18 * 1024 * 1024;
/// Largest response frame. A response carries at most one object or a batch
/// of commits.
const MAX_RESPONSE_BYTES: usize = 18 * 1024 * 1024;
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

/// Parse an address a validator announced and check that it names `key`.
///
/// A validator can only make its peers dial an address that ends in its own
/// peer id. The dial then fails the Noise handshake unless the validator
/// really answers there, so an announced address cannot aim a node at
/// someone else's service.
pub fn validator_dial_address(address: &str, key: &GardenKey) -> Result<Multiaddr, String> {
    let parsed: Multiaddr = address
        .parse()
        .map_err(|e| format!("announced address is not a multiaddr: {e}"))?;
    let expected = peer_id_of(key)?;
    let names_key = parsed
        .iter()
        .any(|part| matches!(part, libp2p::multiaddr::Protocol::P2p(id) if id == expected));
    if !names_key {
        return Err("announced address does not end in the validator's own peer id".into());
    }
    Ok(parsed)
}

/// The codec: one bounded frame per request and per response.
#[derive(Debug, Clone, Default)]
struct GardenCodec;

async fn read_bounded<T>(io: &mut T, limit: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(limit as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("garden frame exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

impl request_response::Codec for GardenCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded(io, MAX_REQUEST_BYTES).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded(io, MAX_RESPONSE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&resp).await?;
        io.close().await
    }
}

#[derive(NetworkBehaviour)]
struct GardenBehaviour {
    rpc: request_response::Behaviour<GardenCodec>,
    limits: libp2p::connection_limits::Behaviour,
}

/// What the node asks of its swarm.
#[derive(Debug)]
pub enum NetCommand {
    Dial(Multiaddr),
    /// Send a request. The response comes back as [`NetEvent::Response`]
    /// carrying the same `tag`.
    Send {
        peer: PeerId,
        request: GardenRequest,
        tag: u64,
    },
    Respond {
        channel: request_response::ResponseChannel<Vec<u8>>,
        response: GardenResponse,
    },
    Disconnect(PeerId),
    Shutdown,
}

/// What the swarm tells the node.
#[derive(Debug)]
pub enum NetEvent {
    Connected(PeerId),
    Disconnected(PeerId),
    Request {
        peer: PeerId,
        request: GardenRequest,
        channel: request_response::ResponseChannel<Vec<u8>>,
    },
    Response {
        peer: PeerId,
        tag: u64,
        response: Result<GardenResponse, String>,
    },
}

/// A running Garden swarm.
#[derive(Debug)]
pub struct GardenNet {
    pub commands: mpsc::Sender<NetCommand>,
    pub events: mpsc::Receiver<NetEvent>,
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
pub async fn start(secret_key: [u8; 32], listen: &str) -> Result<GardenNet, String> {
    let listen: Multiaddr = listen
        .parse()
        .map_err(|e| format!("garden listen address is not a multiaddr: {e}"))?;
    let identity = identity::Keypair::ed25519_from_bytes(secret_key)
        .map_err(|e| format!("garden key cannot be a libp2p identity: {e}"))?;
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("garden transport cannot start: {e}"))?
        .with_dns()
        .map_err(|e| format!("garden resolver cannot start: {e}"))?
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
                    .with_max_established(Some(MAX_CONNECTIONS))
                    .with_max_established_per_peer(Some(2)),
            ),
        })
        .map_err(|e| format!("garden behaviour cannot start: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
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
    tokio::spawn(async move {
        let mut tags = std::collections::BTreeMap::new();
        // Events wait here, not in a blocking send: the task keeps taking
        // commands while the validator is busy, so the two channels can
        // never wait on each other. A full backlog stops the swarm from
        // being read, which pushes back on the remote side.
        let mut backlog: std::collections::VecDeque<NetEvent> = std::collections::VecDeque::new();
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
                        // the source port carries nothing.
                        let dial = DialOpts::unknown_peer_id()
                            .address(address)
                            .allocate_new_port()
                            .build();
                        if let Err(e) = swarm.dial(dial) {
                            tracing::debug!(error = %e, "garden dial refused");
                        }
                    }
                    Some(NetCommand::Send { peer, request, tag }) => match bincode::serialize(&request) {
                        Ok(bytes) => {
                            let id = swarm.behaviour_mut().rpc.send_request(&peer, bytes);
                            tags.insert(id, tag);
                        }
                        Err(e) => tracing::warn!(error = %e, "garden request cannot be encoded"),
                    },
                    Some(NetCommand::Respond { channel, response }) => {
                        if let Ok(bytes) = bincode::serialize(&response) {
                            let _ = swarm.behaviour_mut().rpc.send_response(channel, bytes);
                        }
                    }
                    Some(NetCommand::Disconnect(peer)) => {
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                },
                event = swarm.select_next_some(), if backlog.len() < EVENT_BACKLOG => {
                    let out = match event {
                        SwarmEvent::ConnectionEstablished { peer_id, num_established, .. }
                            if num_established.get() == 1 => Some(NetEvent::Connected(peer_id)),
                        SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                            Some(NetEvent::Disconnected(peer_id))
                        }
                        SwarmEvent::Behaviour(GardenBehaviourEvent::Rpc(
                            request_response::Event::Message { peer, message, .. },
                        )) => match message {
                            request_response::Message::Request { request, channel, .. } => {
                                match bincode::deserialize::<GardenRequest>(&request) {
                                    Ok(request) => Some(NetEvent::Request { peer, request, channel }),
                                    Err(_) => {
                                        let refusal = GardenResponse::Refused("malformed request".into());
                                        if let Ok(bytes) = bincode::serialize(&refusal) {
                                            let _ = swarm.behaviour_mut().rpc.send_response(channel, bytes);
                                        }
                                        None
                                    }
                                }
                            }
                            request_response::Message::Response { request_id, response } => {
                                tags.remove(&request_id).map(|tag| NetEvent::Response {
                                    peer,
                                    tag,
                                    response: bincode::deserialize::<GardenResponse>(&response)
                                        .map_err(|_| "malformed response".to_string()),
                                })
                            }
                        },
                        SwarmEvent::Behaviour(GardenBehaviourEvent::Rpc(
                            request_response::Event::OutboundFailure { peer, request_id, error, .. },
                        )) => tags.remove(&request_id).map(|tag| NetEvent::Response {
                            peer,
                            tag,
                            response: Err(error.to_string()),
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
}
