//! Sentry node shield topology and swarm-boundary connection admission gate.
//!
//! A shielded validator places one or more public-facing sentry nodes in front
//! of itself:
//!
//! - **Validator shield mode** (`role = "validator"` with `sentry_peers`):
//!   - `SentryGateBehaviour` rejects every inbound connection whose
//!     authenticated transport `PeerId` is not in `sentry_peers` before any
//!     application protocol (`identify`, `ping`, `gossipsub`, `kad`, `sync`,
//!     `bitswap`, `witness`) opens a substream.
//!   - `SentryGateBehaviour` rejects every pending or established outbound dial
//!     whose target `PeerId` is not in `sentry_peers` before any socket opens.
//!   - Public discovery (`bootnodes`, `dns_seeds`, mDNS, Kademlia DHT server
//!     mode, provider announcements, and periodic DHT walks) is disabled so
//!     the validator speaks solely with its sentry nodes.
//!
//! - **Sentry shield mode** (`role = "sentry"` with `validator_peers`):
//!   - Connects simultaneously to the public P2P mesh and to its protected
//!     upstream validators (either dialed outbound over a private link or
//!     accepted inbound from a zero-inbound-port validator authenticated by
//!     `PeerId`).
//!   - Reserves dedicated connection headroom (`RESERVED_SHIELD_SLOTS`) so
//!     public connection floods reaching `max_peers` cannot block or evict
//!     validator links.
//!   - Suppresses Kademlia routing insertion (`Identify` and `RoutingUpdated`)
//!     for every protected validator `PeerId` so public `FIND_NODE` queries
//!     never learn a validator's IP address or listen multiaddr.

use libp2p::{
    core::{transport::PortUse, Endpoint},
    multiaddr::Protocol,
    swarm::{
        dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::task::{Context, Poll};

/// Dedicated swarm connection slots reserved above the public `max_peers`
/// ceiling for authenticated validator-sentry shield links.
pub const RESERVED_SHIELD_SLOTS: usize = 16;

/// Maximum number of configured shield peers on one node, matched to the
/// reserved swarm headroom so every configured shield peer has a guaranteed slot.
const MAX_CONFIGURED_SHIELD_PEERS: usize = RESERVED_SHIELD_SLOTS;

/// Per-source cap on concurrent unauthenticated pending inbound handshakes
/// while a validator runs in sentry-shielded mode.
const MAX_SHIELD_PENDING_PER_SOURCE: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DialEndpoint {
    peer_id: PeerId,
    dial_addr: Multiaddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatorEndpoint {
    peer_id: PeerId,
    dial_addr: Option<Multiaddr>,
}

/// Validated sentry-validator shield topology for a P2P node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SentryShieldConfig {
    sentry_endpoints: Vec<DialEndpoint>,
    sentry_peer_ids: BTreeSet<PeerId>,
    validator_endpoints: Vec<ValidatorEndpoint>,
    validator_peer_ids: BTreeSet<PeerId>,
}

/// Extract the trailing `/p2p/<PeerId>` component from a multiaddr.
#[must_use]
pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last()? {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    }
}

fn validate_dialable_multiaddr(raw: &str, label: &str) -> Result<(PeerId, Multiaddr), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} entry cannot be empty"));
    }
    let addr: Multiaddr = trimmed
        .parse()
        .map_err(|e| format!("invalid {label} multiaddr '{trimmed}': {e}"))?;

    let mut has_host = false;
    let mut has_port = false;
    let components: Vec<Protocol<'_>> = addr.iter().collect();
    let Some((Protocol::P2p(peer_id), prefix)) = components.split_last() else {
        return Err(format!(
            "{label} multiaddr '{trimmed}' must end with /p2p/<PeerId>"
        ));
    };
    let peer_id = *peer_id;
    if prefix.is_empty() {
        return Err(format!(
            "{label} multiaddr '{trimmed}' must include a transport host and port before /p2p/<PeerId>"
        ));
    }

    for proto in prefix {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                    return Err(format!(
                        "{label} multiaddr '{trimmed}' cannot target unspecified, broadcast, or multicast IPv4 address {ip}"
                    ));
                }
                has_host = true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_unspecified() || ip.is_multicast() {
                    return Err(format!(
                        "{label} multiaddr '{trimmed}' cannot target unspecified or multicast IPv6 address {ip}"
                    ));
                }
                has_host = true;
            }
            Protocol::Dns(host)
            | Protocol::Dns4(host)
            | Protocol::Dns6(host)
            | Protocol::Dnsaddr(host) => {
                if host.trim().is_empty() {
                    return Err(format!(
                        "{label} multiaddr '{trimmed}' has an empty DNS host"
                    ));
                }
                has_host = true;
            }
            Protocol::Tcp(port) | Protocol::Udp(port) => {
                if *port == 0 {
                    return Err(format!(
                        "{label} multiaddr '{trimmed}' must specify a non-zero port"
                    ));
                }
                has_port = true;
            }
            Protocol::Memory(port) => {
                if *port == 0 {
                    return Err(format!(
                        "{label} memory multiaddr '{trimmed}' must specify a non-zero port"
                    ));
                }
                has_host = true;
                has_port = true;
            }
            Protocol::P2p(_) => {
                return Err(format!(
                    "{label} multiaddr '{trimmed}' cannot embed multiple /p2p/<PeerId> segments"
                ));
            }
            _ => {}
        }
    }

    if !has_host || !has_port {
        return Err(format!(
            "{label} multiaddr '{trimmed}' must include both a target host and non-zero port"
        ));
    }

    Ok((peer_id, addr))
}

fn parse_validator_spec(raw: &str) -> Result<ValidatorEndpoint, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("validator_peers entry cannot be empty".into());
    }
    if !trimmed.contains('/') {
        let peer_id = trimmed.parse::<PeerId>().map_err(|e| {
            format!(
                "invalid validator_peers entry '{trimmed}': expected <PeerId> or <Multiaddr>/p2p/<PeerId> ({e})"
            )
        })?;
        return Ok(ValidatorEndpoint {
            peer_id,
            dial_addr: None,
        });
    }
    let (peer_id, addr) = validate_dialable_multiaddr(trimmed, "validator_peers")?;
    Ok(ValidatorEndpoint {
        peer_id,
        dial_addr: Some(addr),
    })
}

impl SentryShieldConfig {
    /// Validate role compatibility and parse `sentry_peers` / `validator_peers`.
    ///
    /// # Errors
    ///
    /// Returns a descriptive configuration error when role constraints,
    /// multiaddr syntax, `/p2p/<PeerId>` pinning, capacity bounds, or
    /// self-identity checks fail.
    pub fn from_role_and_peers(
        role: &str,
        raw_sentry_peers: &[String],
        raw_validator_peers: &[String],
        local_peer_id: Option<&PeerId>,
    ) -> Result<Self, String> {
        let sentry_non_empty: Vec<&str> = raw_sentry_peers
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let validator_non_empty: Vec<&str> = raw_validator_peers
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if !sentry_non_empty.is_empty() && role != "validator" {
            return Err(format!(
                "sentry_peers may only be configured when role = 'validator' (current role = '{role}')"
            ));
        }
        if !validator_non_empty.is_empty() && role != "sentry" {
            return Err(format!(
                "validator_peers may only be configured when role = 'sentry' (current role = '{role}')"
            ));
        }
        if sentry_non_empty.len() > MAX_CONFIGURED_SHIELD_PEERS {
            return Err(format!(
                "sentry_peers lists {} endpoints, exceeding maximum {MAX_CONFIGURED_SHIELD_PEERS}",
                sentry_non_empty.len()
            ));
        }
        if validator_non_empty.len() > MAX_CONFIGURED_SHIELD_PEERS {
            return Err(format!(
                "validator_peers lists {} endpoints, exceeding maximum {MAX_CONFIGURED_SHIELD_PEERS}",
                validator_non_empty.len()
            ));
        }

        let mut sentry_endpoints = Vec::new();
        let mut sentry_peer_ids = BTreeSet::new();
        for raw in sentry_non_empty {
            let (peer_id, dial_addr) = validate_dialable_multiaddr(raw, "sentry_peers")?;
            if local_peer_id == Some(&peer_id) {
                return Err(format!(
                    "sentry_peers cannot contain this validator's own PeerId ({peer_id})"
                ));
            }
            if !sentry_peer_ids.insert(peer_id) {
                return Err(format!("duplicate sentry PeerId {peer_id} in sentry_peers"));
            }
            sentry_endpoints.push(DialEndpoint { peer_id, dial_addr });
        }

        let mut validator_endpoints = Vec::new();
        let mut validator_peer_ids = BTreeSet::new();
        for raw in validator_non_empty {
            let spec = parse_validator_spec(raw)?;
            if local_peer_id == Some(&spec.peer_id) {
                return Err(format!(
                    "validator_peers cannot contain this sentry node's own PeerId ({})",
                    spec.peer_id
                ));
            }
            if !validator_peer_ids.insert(spec.peer_id) {
                return Err(format!(
                    "duplicate validator PeerId {} in validator_peers",
                    spec.peer_id
                ));
            }
            validator_endpoints.push(spec);
        }

        Ok(Self {
            sentry_endpoints,
            sentry_peer_ids,
            validator_endpoints,
            validator_peer_ids,
        })
    }

    /// Build a swarm-boundary shield configuration mirroring a validated
    /// [`super::sentry::SentryPolicy`] (used on startup and after live
    /// `bud_adminUpdateSentries` rotations).
    #[must_use]
    pub fn from_policy(policy: &super::sentry::SentryPolicy) -> Self {
        let mut sentry_endpoints = Vec::new();
        let mut sentry_peer_ids = BTreeSet::new();
        let mut validator_endpoints = Vec::new();
        let mut validator_peer_ids = BTreeSet::new();

        match policy.role() {
            super::sentry::SentryRole::ShieldedValidator => {
                for (peer_id, dial_addr) in policy.sentry_addrs() {
                    sentry_peer_ids.insert(peer_id);
                    sentry_endpoints.push(DialEndpoint { peer_id, dial_addr });
                }
            }
            super::sentry::SentryRole::Sentry => {
                for peer_id in policy.private_peer_ids() {
                    if validator_peer_ids.insert(peer_id) {
                        validator_endpoints.push(ValidatorEndpoint {
                            peer_id,
                            dial_addr: None,
                        });
                    }
                }
            }
            super::sentry::SentryRole::Standard => {}
        }

        Self {
            sentry_endpoints,
            sentry_peer_ids,
            validator_endpoints,
            validator_peer_ids,
        }
    }

    /// True when this validator is shielded behind one or more sentry peers
    /// and must reject all non-sentry inbound and outbound P2P communication.
    #[must_use]
    pub fn is_validator_shielded(&self) -> bool {
        !self.sentry_peer_ids.is_empty()
    }

    /// True when this sentry node protects one or more upstream validators.
    #[must_use]
    pub fn is_sentry_protecting_validators(&self) -> bool {
        !self.validator_peer_ids.is_empty()
    }

    /// Whether an authenticated remote `PeerId` may establish a session with
    /// this node.
    #[must_use]
    pub fn allows_inbound_peer(&self, peer_id: &PeerId) -> bool {
        if self.is_validator_shielded() {
            return self.sentry_peer_ids.contains(peer_id);
        }
        true
    }

    /// Whether an outbound dial to `maybe_peer` / `addrs` is permitted.
    #[must_use]
    pub fn allows_outbound_dial(&self, maybe_peer: Option<PeerId>, addrs: &[Multiaddr]) -> bool {
        if !self.is_validator_shielded() {
            return true;
        }
        if let Some(peer_id) = maybe_peer {
            if !self.sentry_peer_ids.contains(&peer_id) {
                return false;
            }
            return addrs.iter().all(|addr| match peer_id_from_multiaddr(addr) {
                Some(addr_peer) => addr_peer == peer_id,
                None => true,
            });
        }
        if addrs.is_empty() {
            return false;
        }
        addrs.iter().all(|addr| {
            peer_id_from_multiaddr(addr)
                .is_some_and(|addr_peer| self.sentry_peer_ids.contains(&addr_peer))
        })
    }

    /// True for configured sentry peers (on a validator) and configured
    /// upstream validator peers (on a sentry).
    #[must_use]
    pub fn is_protected_peer(&self, peer_id: &PeerId) -> bool {
        self.sentry_peer_ids.contains(peer_id) || self.validator_peer_ids.contains(peer_id)
    }

    /// True when `peer_id`'s addresses must never enter Kademlia or be served
    /// in public routing responses.
    #[must_use]
    pub fn hides_from_public_routing(&self, peer_id: &PeerId) -> bool {
        self.is_validator_shielded() || self.validator_peer_ids.contains(peer_id)
    }

    /// All protected `PeerId`s (`sentry_peers` union `validator_peers`).
    #[must_use]
    pub fn protected_peer_ids(&self) -> Vec<PeerId> {
        self.sentry_peer_ids
            .iter()
            .chain(self.validator_peer_ids.iter())
            .copied()
            .collect()
    }

    /// Protected upstream validator `PeerId`s configured on a sentry node.
    #[must_use]
    pub fn validator_peer_ids(&self) -> Vec<PeerId> {
        self.validator_peer_ids.iter().copied().collect()
    }

    /// Dialable shield endpoints `(PeerId, Multiaddr)` that the node maintains
    /// across startup and periodic reconnect ticks.
    #[must_use]
    pub fn dial_targets(&self) -> Vec<(PeerId, Multiaddr)> {
        let mut out: Vec<(PeerId, Multiaddr)> = self
            .sentry_endpoints
            .iter()
            .map(|ep| (ep.peer_id, ep.dial_addr.clone()))
            .collect();
        for vp in &self.validator_endpoints {
            if let Some(ref addr) = vp.dial_addr {
                out.push((vp.peer_id, addr.clone()));
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PendingSourcePrefix {
    V4([u8; 3]),
    V6([u8; 8]),
    Other,
}

fn pending_source_prefix(addr: &Multiaddr) -> Option<PendingSourcePrefix> {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_loopback() {
                    return None;
                }
                let [a, b, c, _] = ip.octets();
                return Some(PendingSourcePrefix::V4([a, b, c]));
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()) {
                    return None;
                }
                if let Some(v4) = ip.to_ipv4_mapped() {
                    let [a, b, c, _] = v4.octets();
                    return Some(PendingSourcePrefix::V4([a, b, c]));
                }
                let [p0, p1, p2, p3, p4, p5, p6, p7, ..] = ip.octets();
                return Some(PendingSourcePrefix::V6([p0, p1, p2, p3, p4, p5, p6, p7]));
            }
            Protocol::Memory(_) => return None,
            _ => {}
        }
    }
    Some(PendingSourcePrefix::Other)
}

/// Inhabited event marker for [`SentryGateBehaviour`]. Never emitted at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentryGateEvent;

/// Swarm-level admission gate enforcing validator sentry allowlisting and
/// reserved sentry-validator connection slots ahead of protocol behaviours.
pub struct SentryGateBehaviour {
    shield: SentryShieldConfig,
    max_public_peers: usize,
    max_public_incoming: usize,
    established: BTreeMap<ConnectionId, (PeerId, bool)>,
    pending_inbound: BTreeMap<ConnectionId, PendingSourcePrefix>,
    pending_by_source: BTreeMap<PendingSourcePrefix, usize>,
}

impl SentryGateBehaviour {
    /// Construct a gate enforcing `max_public_peers` total and
    /// `max_public_incoming` inbound non-shield peers.
    #[must_use]
    pub fn new(max_public_peers: usize, max_public_incoming: usize) -> Self {
        Self {
            shield: SentryShieldConfig::default(),
            max_public_peers: max_public_peers.max(1),
            max_public_incoming: max_public_incoming.max(1),
            established: BTreeMap::new(),
            pending_inbound: BTreeMap::new(),
            pending_by_source: BTreeMap::new(),
        }
    }

    /// Install or update the active sentry shield configuration.
    pub fn set_shield(&mut self, shield: SentryShieldConfig) {
        self.shield = shield;
    }

    /// Synchronize public peer ceilings when network or mobile profiles change
    /// `Node::max_peers`.
    pub fn set_public_caps(&mut self, max_public_peers: usize, max_public_incoming: usize) {
        self.max_public_peers = max_public_peers.max(1);
        self.max_public_incoming = max_public_incoming.max(1);
    }

    fn clear_pending(&mut self, connection_id: ConnectionId) {
        if let Some(prefix) = self.pending_inbound.remove(&connection_id) {
            if let Some(count) = self.pending_by_source.get_mut(&prefix) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.pending_by_source.remove(&prefix);
                }
            }
        }
    }

    fn admit_public_peer(&self, candidate: PeerId, incoming: bool) -> Result<(), ConnectionDenied> {
        let mut distinct_public = BTreeSet::new();
        let mut distinct_public_incoming = BTreeSet::new();
        for &(peer_id, is_incoming) in self.established.values() {
            if self.shield.is_protected_peer(&peer_id) {
                continue;
            }
            distinct_public.insert(peer_id);
            if is_incoming {
                distinct_public_incoming.insert(peer_id);
            }
        }
        // Additional connection streams for an already-admitted public peer are
        // bounded by `connection_limits::with_max_established_per_peer`.
        if distinct_public.contains(&candidate) {
            return Ok(());
        }
        if distinct_public.len() >= self.max_public_peers {
            return Err(ConnectionDenied::new(
                "public peer limit reached; remaining swarm slots are reserved for sentry shield peers",
            ));
        }
        if incoming && distinct_public_incoming.len() >= self.max_public_incoming {
            return Err(ConnectionDenied::new(
                "public inbound peer limit reached; remaining inbound slots are reserved for sentry shield peers",
            ));
        }
        Ok(())
    }
}

impl NetworkBehaviour for SentryGateBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = SentryGateEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.shield.is_validator_shielded() {
            if let Some(prefix) = pending_source_prefix(remote_addr) {
                let in_flight = self.pending_by_source.get(&prefix).copied().unwrap_or(0);
                if in_flight >= MAX_SHIELD_PENDING_PER_SOURCE {
                    return Err(ConnectionDenied::new(
                        "too many concurrent pending handshakes from one source against shielded validator",
                    ));
                }
                self.pending_inbound.insert(connection_id, prefix);
                *self.pending_by_source.entry(prefix).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.clear_pending(connection_id);
        if !self.shield.allows_inbound_peer(&peer) {
            return Err(ConnectionDenied::new(
                "validator sentry shield rejected inbound connection from non-sentry peer",
            ));
        }
        if !self.shield.is_protected_peer(&peer) {
            self.admit_public_peer(peer, true)?;
        }
        self.established.insert(connection_id, (peer, true));
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if !self.shield.allows_outbound_dial(maybe_peer, addresses) {
            return Err(ConnectionDenied::new(
                "validator sentry shield blocked outbound dial to non-sentry peer",
            ));
        }
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.shield.allows_inbound_peer(&peer) {
            return Err(ConnectionDenied::new(
                "validator sentry shield rejected outbound session with non-sentry peer",
            ));
        }
        if !self.shield.is_protected_peer(&peer) {
            self.admit_public_peer(peer, false)?;
        }
        self.established.insert(connection_id, (peer, false));
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionClosed(closed) => {
                self.clear_pending(closed.connection_id);
                self.established.remove(&closed.connection_id);
            }
            FromSwarm::ListenFailure(failure) => {
                self.clear_pending(failure.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::{transport::MemoryTransport, upgrade},
        futures::StreamExt,
        identity, noise, ping,
        swarm::{dial_opts::DialOpts, SwarmEvent},
        yamux, Swarm, Transport,
    };
    use std::time::Duration;

    #[derive(NetworkBehaviour)]
    struct TestShieldBehaviour {
        gate: SentryGateBehaviour,
        ping: ping::Behaviour,
    }

    fn build_memory_swarm(
        key: identity::Keypair,
        shield: SentryShieldConfig,
        max_public_peers: usize,
        max_public_incoming: usize,
        port: u64,
    ) -> (Swarm<TestShieldBehaviour>, Multiaddr) {
        let peer_id = key.public().to_peer_id();
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&key).expect("noise config"))
            .multiplex(yamux::Config::default())
            .boxed();
        let mut gate = SentryGateBehaviour::new(max_public_peers, max_public_incoming);
        gate.set_shield(shield);
        let behaviour = TestShieldBehaviour {
            gate,
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_millis(50)),
            ),
        };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(10)),
        );
        let listen_addr: Multiaddr = format!("/memory/{port}").parse().expect("memory addr");
        swarm.listen_on(listen_addr.clone()).expect("listen_on");
        let full_addr: Multiaddr = format!("{listen_addr}/p2p/{peer_id}")
            .parse()
            .expect("full addr");
        (swarm, full_addr)
    }

    #[test]
    fn config_rejects_wrong_roles_missing_p2p_self_loop_and_bad_hosts() {
        let sentry_id = PeerId::random();
        let validator_id = PeerId::random();
        let good_sentry = format!("/ip4/203.0.113.10/tcp/26656/p2p/{sentry_id}");

        // sentry_peers on non-validator role must fail closed.
        let err = SentryShieldConfig::from_role_and_peers(
            "rpc",
            std::slice::from_ref(&good_sentry),
            &[],
            None,
        )
        .expect_err("rpc cannot set sentry_peers");
        assert!(
            err.contains("role = 'validator'"),
            "unexpected error: {err}"
        );

        // validator_peers on non-sentry role must fail closed.
        let err = SentryShieldConfig::from_role_and_peers(
            "validator",
            &[],
            &[validator_id.to_string()],
            None,
        )
        .expect_err("validator cannot set validator_peers");
        assert!(err.contains("role = 'sentry'"), "unexpected error: {err}");

        // Unauthenticated multiaddr without /p2p/<PeerId> must fail closed.
        let err = SentryShieldConfig::from_role_and_peers(
            "validator",
            &["/ip4/203.0.113.10/tcp/26656".to_string()],
            &[],
            None,
        )
        .expect_err("missing /p2p must fail");
        assert!(err.contains("/p2p/<PeerId>"), "unexpected error: {err}");

        // Unspecified host (0.0.0.0) or zero port must fail closed.
        assert!(SentryShieldConfig::from_role_and_peers(
            "validator",
            &[format!("/ip4/0.0.0.0/tcp/26656/p2p/{sentry_id}")],
            &[],
            None,
        )
        .is_err());
        assert!(SentryShieldConfig::from_role_and_peers(
            "validator",
            &[format!("/ip4/203.0.113.10/tcp/0/p2p/{sentry_id}")],
            &[],
            None,
        )
        .is_err());

        // Self-PeerId loop must fail closed on both validator and sentry.
        assert!(SentryShieldConfig::from_role_and_peers(
            "validator",
            std::slice::from_ref(&good_sentry),
            &[],
            Some(&sentry_id),
        )
        .is_err());
        assert!(SentryShieldConfig::from_role_and_peers(
            "sentry",
            &[],
            &[validator_id.to_string()],
            Some(&validator_id),
        )
        .is_err());
    }

    #[test]
    fn config_supports_stealth_peer_id_and_private_wireguard_validator_specs() {
        let v1 = PeerId::random();
        let v2 = PeerId::random();
        let public_peer = PeerId::random();
        let cfg = SentryShieldConfig::from_role_and_peers(
            "sentry",
            &[],
            &[v1.to_string(), format!("/ip4/10.99.0.5/tcp/26656/p2p/{v2}")],
            None,
        )
        .expect("valid sentry config");

        assert!(!cfg.is_validator_shielded());
        assert!(cfg.is_sentry_protecting_validators());
        assert!(cfg.is_protected_peer(&v1));
        assert!(cfg.is_protected_peer(&v2));
        assert!(!cfg.is_protected_peer(&public_peer));

        // Protected validators must be hidden from public Kademlia routing,
        // while ordinary public peers remain routable on a sentry node.
        assert!(cfg.hides_from_public_routing(&v1));
        assert!(cfg.hides_from_public_routing(&v2));
        assert!(!cfg.hides_from_public_routing(&public_peer));

        // Only v2 carried a dial multiaddr; v1 dials inbound from behind its firewall.
        let targets = cfg.dial_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, v2);
    }

    #[tokio::test]
    async fn shielded_validator_blocks_stranger_inbound_and_outbound_but_admits_sentry() {
        let val_key = identity::Keypair::generate_ed25519();
        let sentry_key = identity::Keypair::generate_ed25519();
        let stranger_key = identity::Keypair::generate_ed25519();

        let sentry_id = sentry_key.public().to_peer_id();
        let stranger_id = stranger_key.public().to_peer_id();

        let (mut sentry_swarm, sentry_addr) = build_memory_swarm(
            sentry_key,
            SentryShieldConfig::from_role_and_peers(
                "sentry",
                &[],
                &[val_key.public().to_peer_id().to_string()],
                None,
            )
            .expect("sentry shield"),
            8,
            8,
            9101,
        );
        let val_shield = SentryShieldConfig::from_role_and_peers(
            "validator",
            &[sentry_addr.to_string()],
            &[],
            Some(&val_key.public().to_peer_id()),
        )
        .expect("validator shield");
        let (mut val_swarm, val_addr) = build_memory_swarm(val_key, val_shield, 8, 8, 9102);
        let (mut stranger_swarm, stranger_addr) =
            build_memory_swarm(stranger_key, SentryShieldConfig::default(), 8, 8, 9103);

        // 1. Outbound dial from shielded validator to stranger is denied before socket open.
        let outbound_err = val_swarm
            .dial(stranger_addr.clone())
            .expect_err("validator must refuse dialing non-sentry peer");
        let outbound_dbg = format!("{outbound_err:?}");
        assert!(
            matches!(outbound_err, libp2p::swarm::DialError::Denied { .. })
                && outbound_dbg.contains("sentry shield"),
            "unexpected dial error: {outbound_dbg}"
        );

        // 2. Inbound dial from stranger to shielded validator is rejected at gate admission.
        let val_bare: Multiaddr = "/memory/9102".parse().expect("bare addr");
        stranger_swarm
            .dial(DialOpts::unknown_peer_id().address(val_bare).build())
            .expect("stranger initiates transport dial");

        let mut val_rejected_stranger = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline && !val_rejected_stranger {
            tokio::select! {
                ev = val_swarm.select_next_some() => {
                    match ev {
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            let err_dbg = format!("{error:?}");
                            if matches!(error, libp2p::swarm::ListenError::Denied { .. })
                                && err_dbg.contains("sentry shield")
                            {
                                val_rejected_stranger = true;
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            panic!("shielded validator must NEVER establish connection with stranger {peer_id}");
                        }
                        _ => {}
                    }
                }
                _ = stranger_swarm.select_next_some() => {}
            }
        }
        assert!(
            val_rejected_stranger,
            "shielded validator must reject stranger {stranger_id} in IncomingConnectionError"
        );
        assert!(!val_swarm.is_connected(&stranger_id));

        // 3. Configured sentry connects cleanly with the shielded validator.
        val_swarm
            .dial(sentry_addr)
            .expect("validator dials configured sentry");
        let mut val_connected_sentry = false;
        let mut sentry_connected_val = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline
            && (!val_connected_sentry || !sentry_connected_val)
        {
            tokio::select! {
                ev = val_swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        assert_eq!(peer_id, sentry_id);
                        val_connected_sentry = true;
                    }
                }
                ev = sentry_swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        assert_eq!(peer_id.to_string(), val_addr.iter().last().and_then(|p| match p { Protocol::P2p(id) => Some(id.to_string()), _ => None }).unwrap());
                        sentry_connected_val = true;
                    }
                }
            }
        }
        assert!(val_connected_sentry && sentry_connected_val);
    }

    #[tokio::test]
    async fn sentry_reserved_slot_admits_validator_when_public_slots_are_saturated() {
        let sentry_key = identity::Keypair::generate_ed25519();
        let val_key = identity::Keypair::generate_ed25519();
        let pub1_key = identity::Keypair::generate_ed25519();
        let pub2_key = identity::Keypair::generate_ed25519();

        let val_id = val_key.public().to_peer_id();
        let pub1_id = pub1_key.public().to_peer_id();
        let pub2_id = pub2_key.public().to_peer_id();

        // Sentry allows only 1 public peer (`max_public_peers = 1`, `max_public_incoming = 1`),
        // while protecting `val_id` in reserved shield headroom.
        let sentry_shield = SentryShieldConfig::from_role_and_peers(
            "sentry",
            &[],
            &[val_id.to_string()],
            Some(&sentry_key.public().to_peer_id()),
        )
        .expect("sentry config");
        let (mut sentry_swarm, sentry_addr) =
            build_memory_swarm(sentry_key, sentry_shield, 1, 1, 9201);
        let (mut pub1_swarm, _) =
            build_memory_swarm(pub1_key, SentryShieldConfig::default(), 4, 4, 9202);
        let (mut pub2_swarm, _) =
            build_memory_swarm(pub2_key, SentryShieldConfig::default(), 4, 4, 9203);
        let (mut val_swarm, _) = build_memory_swarm(
            val_key,
            SentryShieldConfig::from_role_and_peers(
                "validator",
                &[sentry_addr.to_string()],
                &[],
                None,
            )
            .expect("val config"),
            4,
            4,
            9204,
        );

        // First public peer fills the 1 public slot on the sentry.
        pub1_swarm.dial(sentry_addr.clone()).expect("pub1 dial");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline && !sentry_swarm.is_connected(&pub1_id) {
            tokio::select! {
                _ = sentry_swarm.select_next_some() => {}
                _ = pub1_swarm.select_next_some() => {}
            }
        }
        assert!(sentry_swarm.is_connected(&pub1_id));

        // Second public peer is denied because the public cap (1) is saturated.
        pub2_swarm.dial(sentry_addr.clone()).expect("pub2 dial");
        let mut pub2_denied = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline && !pub2_denied {
            tokio::select! {
                ev = sentry_swarm.select_next_some() => {
                    if let SwarmEvent::IncomingConnectionError { error, .. } = ev {
                        let err_dbg = format!("{error:?}");
                        if matches!(error, libp2p::swarm::ListenError::Denied { .. })
                            && err_dbg.contains("reserved for sentry shield")
                        {
                            pub2_denied = true;
                        }
                    }
                }
                _ = pub1_swarm.select_next_some() => {}
                _ = pub2_swarm.select_next_some() => {}
            }
        }
        assert!(pub2_denied && !sentry_swarm.is_connected(&pub2_id));

        // Zero-inbound-port protected validator dials inbound to the saturated sentry and SUCCEEDS.
        val_swarm.dial(sentry_addr).expect("validator dial");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline && !sentry_swarm.is_connected(&val_id) {
            tokio::select! {
                _ = sentry_swarm.select_next_some() => {}
                _ = pub1_swarm.select_next_some() => {}
                _ = val_swarm.select_next_some() => {}
            }
        }
        assert!(
            sentry_swarm.is_connected(&val_id),
            "protected validator must connect via reserved shield slot even when public slots are full"
        );
    }
}
