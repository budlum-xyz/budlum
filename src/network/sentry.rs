//! Sentry node architecture: shields private validators behind public sentry
//! full nodes over a private VPC/VPN link.
//!
//! Topology:
//! ```text
//! Public Internet <-> Sentry A <->
//!                     Sentry B <-> Shielded Validator (private VPC/VPN)
//!                     Sentry C <->
//! ```
//!
//! Guarantees enforced by [`SentryPolicy`]:
//! 1. **Shielded validator (`SentryRole::ShieldedValidator`)**:
//!    - Peer discovery (Kademlia DHT bootstrap/routing, mDNS, DNS seeds, public
//!      bootnodes) is forced off.
//!    - Inbound and outbound connections are restricted strictly to configured
//!      `sentry_peers` (authenticated by `PeerId`) and private VPC/VPN CIDRs
//!      when `strict_private_network` or `allowed_private_cidrs` is set.
//!    - Sentries are pinned as explicit gossipsub peers and unconditional peers
//!      so a shared VPC `/24` never trips eclipse subnet limits.
//!    - Live sentry rotation (`update_sentries`) swaps compromised or DDoS'd
//!      sentries at runtime without restarting or exporting validator keys.
//! 2. **Sentry shield node (`SentryRole::Sentry`)**:
//!    - Participates normally in public peer discovery, sync, and gossip.
//!    - Protects every shielded validator listed in `private_peers` as an
//!      unconditional explicit peer (immune to `max_peers` eviction and `/24`
//!      subnet caps during public DDoS floods).
//!    - Never inserts `private_peers` into Kademlia or peer-exchange responses,
//!      hiding the validator's `PeerId` and private IP from the public network.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// Operating role of this node within the sentry-shield architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentryRole {
    /// Ordinary peer with standard discovery and peer admission.
    #[default]
    Standard,
    /// Private validator connected exclusively to its configured sentry peers.
    ShieldedValidator,
    /// Public full node shielding one or more private validators behind it.
    Sentry,
}

/// Maximum number of sentry addresses accepted in config or live rotation.
/// Bounds unconditional/explicit gossipsub peer sets against accidental bloat.
const MAX_SENTRY_PEERS: usize = 64;

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) produced by
/// dual-stack sockets into plain IPv4 so CIDR and private-network checks
/// enforce identical rules on IPv4 and dual-stack IPv6 listeners.
#[must_use]
const fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// IPv4 or IPv6 CIDR prefix (`address/prefix_len`) used to constrain private
/// validator <-> sentry links to a VPC or VPN address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// Parses a CIDR string such as `"10.10.0.0/16"`, `"100.64.0.0/10"`, or
    /// `"fd00::/8"`. Bare IPs without `/prefix` are treated as `/32` or `/128`.
    ///
    /// # Errors
    ///
    /// Returns [`SentryConfigError::InvalidCidr`] if the IP or prefix length
    /// cannot be parsed or exceeds the address bit width.
    fn parse(raw: &str) -> Result<Self, SentryConfigError> {
        let trimmed = raw.trim();
        let (ip_str, prefix_opt) = match trimmed.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (trimmed, None),
        };
        let ip = IpAddr::from_str(ip_str)
            .map_err(|_| SentryConfigError::InvalidCidr(trimmed.to_string()))?;
        let max_bits = match ip {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len = match prefix_opt {
            Some(p) => {
                let parsed = p
                    .parse::<u8>()
                    .map_err(|_| SentryConfigError::InvalidCidr(trimmed.to_string()))?;
                if parsed > max_bits {
                    return Err(SentryConfigError::InvalidCidr(trimmed.to_string()));
                }
                parsed
            }
            None => max_bits,
        };
        let network = mask_ip(ip, prefix_len);
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Returns `true` when `ip` falls inside this CIDR prefix.
    #[must_use]
    fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(cand)) => {
                let mask = ipv4_mask(self.prefix_len);
                (u32::from(cand) & mask) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(cand)) => {
                let mask = ipv6_mask(self.prefix_len);
                (u128::from(cand) & mask) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & ipv4_mask(prefix_len))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & ipv6_mask(prefix_len))),
    }
}

/// Returns `true` when `ip` belongs to a private VPC, VPN (CGNAT / WireGuard /
/// Tailscale `100.64.0.0/10`), loopback, link-local, or IPv6 ULA (`fc00::/7`)
/// range and is therefore non-routable on the public internet.
#[must_use]
const fn is_private_or_vpn_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (a == 100 && (b & 0b1100_0000) == 64) // RFC 6598 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Extracts the `/p2p/<PeerId>` component from a multiaddr, if present.
#[must_use]
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// Extracts the first IPv4 or IPv6 component from a multiaddr, if present.
#[must_use]
fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// Raw operator configuration parsed from CLI flags and TOML `[p2p]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SentryConfig {
    /// Configured node role string (`"validator"`, `"sentry"`, `"rpc"`, etc.).
    pub role: String,
    /// Multiaddrs (`/ip4/.../tcp/.../p2p/<PeerId>`) of sentries shielding this
    /// validator. Non-empty on `role == "validator"` enables
    /// [`SentryRole::ShieldedValidator`].
    pub sentry_peers: Vec<String>,
    /// `PeerId`s (or multiaddrs containing `/p2p/<PeerId>`) of private
    /// validators shielded behind this sentry node.
    pub private_peers: Vec<String>,
    /// `PeerId`s exempt from `max_peers` eviction and `/24` subnet caps.
    pub unconditional_peers: Vec<String>,
    /// Allowed VPC/VPN CIDRs for private validator <-> sentry connections.
    pub allowed_private_cidrs: Vec<String>,
    /// Explicit peer-discovery disable override. Forced `true` for shielded
    /// validators.
    pub disable_peer_discovery: Option<bool>,
    /// When `true` (default for shielded validators), connections on the
    /// private link must originate from a private/VPN IP or an entry in
    /// `allowed_private_cidrs`.
    pub strict_private_network: Option<bool>,
}

/// Configuration or live-rotation validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentryConfigError {
    /// A `sentry_peers` multiaddr failed to parse or lacked `/p2p/<PeerId>`.
    InvalidSentryMultiaddr(String),
    /// A `private_peers` or `unconditional_peers` entry is not a valid `PeerId`.
    InvalidPeerId(String),
    /// An entry in `allowed_private_cidrs` is not a valid IPv4/IPv6 CIDR.
    InvalidCidr(String),
    /// A sentry peer address is not inside the allowed private network.
    PublicSentryAddressDisallowed(String),
    /// Conflicting role flags (for example `role = "sentry"` with `sentry_peers` set).
    ConflictingRole(&'static str),
    /// Shielded validator attempted to enable discovery or remove all sentries.
    SafetyInvariantViolation(&'static str),
}

impl std::fmt::Display for SentryConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSentryMultiaddr(s) => {
                write!(f, "invalid sentry multiaddr (must include /p2p/<ID>): {s}")
            }
            Self::InvalidPeerId(s) => write!(f, "invalid peer id in sentry config: {s}"),
            Self::InvalidCidr(s) => write!(f, "invalid CIDR in allowed_private_cidrs: {s}"),
            Self::PublicSentryAddressDisallowed(s) => write!(
                f,
                "sentry address is outside allowed private VPC/VPN network: {s}"
            ),
            Self::ConflictingRole(msg) | Self::SafetyInvariantViolation(msg) => {
                write!(f, "sentry configuration error: {msg}")
            }
        }
    }
}

impl std::error::Error for SentryConfigError {}

/// Why [`SentryPolicy`] refused a connection or outbound dial attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionRefusal {
    /// A shielded validator only communicates with its configured `sentry_peers`.
    NotASentry,
    /// The remote address is outside the permitted private VPC/VPN CIDRs.
    DisallowedAddress,
    /// Outbound dial target did not name an authorized sentry `PeerId`.
    MissingTargetPeerId,
}

impl std::fmt::Display for ConnectionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotASentry => {
                write!(f, "shielded validator refused non-sentry peer")
            }
            Self::DisallowedAddress => {
                write!(f, "peer address is outside allowed private VPC/VPN range")
            }
            Self::MissingTargetPeerId => {
                write!(f, "shielded validator dial requires /p2p/<PeerId>")
            }
        }
    }
}

impl std::error::Error for ConnectionRefusal {}

/// Summary of an atomic live sentry rotation (`bud_adminUpdateSentries`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentryRotationDiff {
    /// Newly added sentry peer IDs and multiaddrs to dial immediately.
    pub added: Vec<(PeerId, Multiaddr)>,
    /// Removed sentry peer IDs to disconnect and drop from explicit gossip.
    pub removed: Vec<PeerId>,
    /// Resulting active sentry peer IDs after the atomic swap.
    pub active_sentries: Vec<String>,
}

/// Safe diagnostic status returned by operator RPC `bud_adminSentryStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentryStatus {
    /// Active sentry-architecture role (`standard`, `shielded_validator`, `sentry`).
    pub role: SentryRole,
    /// Whether peer discovery (Kademlia/mDNS/DNS/bootnodes) is disabled.
    pub discovery_disabled: bool,
    /// Whether strict private VPC/VPN IP checks are enforced on private links.
    pub strict_private_network: bool,
    /// Configured sentry peer IDs (populated for `ShieldedValidator`).
    pub configured_sentries: Vec<String>,
    /// Currently connected sentry peer IDs.
    pub connected_sentries: Vec<String>,
    /// Number of hidden validator peers shielded by this sentry (IDs kept private).
    pub private_peer_count: usize,
    /// Number of currently connected shielded validator peers.
    pub connected_private_peer_count: usize,
    /// Number of unconditional peers protected from eviction and subnet caps.
    pub unconditional_peer_count: usize,
    /// Configured private CIDR allowlist strings.
    pub allowed_private_cidrs: Vec<String>,
}

/// Live runtime policy enforcing the Budlum Sentry Node Architecture.
#[derive(Debug, Clone, Default)]
pub struct SentryPolicy {
    role: SentryRole,
    sentry_peers: BTreeMap<PeerId, Vec<Multiaddr>>,
    private_peers: BTreeSet<PeerId>,
    unconditional_peers: BTreeSet<PeerId>,
    allowed_private_cidrs: Vec<IpCidr>,
    disable_peer_discovery: bool,
    strict_private_network: bool,
}

fn parse_peer_id_or_multiaddr(raw: &str) -> Result<(PeerId, Option<Multiaddr>), SentryConfigError> {
    let trimmed = raw.trim();
    if let Ok(id) = PeerId::from_str(trimmed) {
        return Ok((id, None));
    }
    if let Ok(ma) = trimmed.parse::<Multiaddr>() {
        if let Some(id) = extract_peer_id(&ma) {
            return Ok((id, Some(ma)));
        }
    }
    Err(SentryConfigError::InvalidPeerId(trimmed.to_string()))
}

fn parse_sentry_multiaddr(
    raw: &str,
    strict_private: bool,
    cidrs: &[IpCidr],
) -> Result<(PeerId, Multiaddr), SentryConfigError> {
    let trimmed = raw.trim();
    let ma = trimmed
        .parse::<Multiaddr>()
        .map_err(|_| SentryConfigError::InvalidSentryMultiaddr(trimmed.to_string()))?;
    let peer_id = extract_peer_id(&ma)
        .ok_or_else(|| SentryConfigError::InvalidSentryMultiaddr(trimmed.to_string()))?;
    if !ip_permitted_by_private_policy(extract_ip(&ma), strict_private, cidrs) {
        return Err(SentryConfigError::PublicSentryAddressDisallowed(
            trimmed.to_string(),
        ));
    }
    Ok((peer_id, ma))
}

fn ip_permitted_by_private_policy(
    ip: Option<IpAddr>,
    strict_private: bool,
    cidrs: &[IpCidr],
) -> bool {
    if !cidrs.is_empty() {
        return ip.is_some_and(|addr| cidrs.iter().any(|c| c.contains(addr)));
    }
    if strict_private {
        return ip.is_some_and(is_private_or_vpn_ip);
    }
    true
}

impl SentryPolicy {
    /// Builds and validates a [`SentryPolicy`] from operator configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SentryConfigError`] if any multiaddr, peer id, CIDR, or role
    /// invariant is invalid. Fails closed on unsafe validator combinations.
    pub fn from_config(cfg: &SentryConfig) -> Result<Self, SentryConfigError> {
        let mut allowed_private_cidrs = Vec::with_capacity(cfg.allowed_private_cidrs.len());
        for raw in &cfg.allowed_private_cidrs {
            allowed_private_cidrs.push(IpCidr::parse(raw)?);
        }

        let role_norm = cfg.role.trim().to_ascii_lowercase();
        let role = if role_norm == "sentry" {
            if !cfg.sentry_peers.is_empty() {
                return Err(SentryConfigError::ConflictingRole(
                    "a sentry node must not configure sentry_peers; use private_peers for shielded validators",
                ));
            }
            SentryRole::Sentry
        } else if !cfg.sentry_peers.is_empty() {
            if role_norm != "validator" {
                return Err(SentryConfigError::ConflictingRole(
                    "sentry_peers is only valid when role = \"validator\"",
                ));
            }
            SentryRole::ShieldedValidator
        } else {
            SentryRole::Standard
        };

        let strict_private_network = cfg
            .strict_private_network
            .unwrap_or(role == SentryRole::ShieldedValidator);

        let disable_peer_discovery = match role {
            SentryRole::ShieldedValidator => {
                if cfg.disable_peer_discovery == Some(false) {
                    return Err(SentryConfigError::SafetyInvariantViolation(
                        "shielded validator cannot run with disable_peer_discovery = false",
                    ));
                }
                true
            }
            SentryRole::Sentry | SentryRole::Standard => {
                cfg.disable_peer_discovery.unwrap_or(false)
            }
        };

        if cfg.sentry_peers.len() > MAX_SENTRY_PEERS {
            return Err(SentryConfigError::SafetyInvariantViolation(
                "sentry_peers exceeds maximum allowed count (64)",
            ));
        }
        let mut sentry_peers: BTreeMap<PeerId, Vec<Multiaddr>> = BTreeMap::new();
        for raw in &cfg.sentry_peers {
            let (id, ma) =
                parse_sentry_multiaddr(raw, strict_private_network, &allowed_private_cidrs)?;
            sentry_peers.entry(id).or_default().push(ma);
        }

        let mut private_peers = BTreeSet::new();
        for raw in &cfg.private_peers {
            let (id, _) = parse_peer_id_or_multiaddr(raw)?;
            private_peers.insert(id);
        }

        let mut unconditional_peers = BTreeSet::new();
        for raw in &cfg.unconditional_peers {
            let (id, _) = parse_peer_id_or_multiaddr(raw)?;
            unconditional_peers.insert(id);
        }
        // Sentries on a shielded validator and private validators on a sentry
        // are always unconditional so public churn or VPC subnet caps never
        // sever the consensus shield.
        unconditional_peers.extend(sentry_peers.keys().copied());
        unconditional_peers.extend(private_peers.iter().copied());

        Ok(Self {
            role,
            sentry_peers,
            private_peers,
            unconditional_peers,
            allowed_private_cidrs,
            disable_peer_discovery,
            strict_private_network,
        })
    }

    /// Returns the active [`SentryRole`].
    #[must_use]
    pub const fn role(&self) -> SentryRole {
        self.role
    }

    /// Returns `true` when Kademlia, mDNS, DNS seeds, and public bootnode
    /// discovery must remain disabled.
    #[must_use]
    pub const fn is_discovery_disabled(&self) -> bool {
        self.disable_peer_discovery
    }

    /// Returns `true` when this node is allowed to advertise external/listen
    /// addresses into public discovery. Always `false` for shielded validators.
    #[must_use]
    pub const fn should_advertise_external(&self) -> bool {
        !matches!(self.role, SentryRole::ShieldedValidator)
    }

    /// Returns `true` when `peer_id` is a private shielded validator whose
    /// identity and addresses must never be gossiped or entered into Kademlia.
    #[must_use]
    pub fn is_private_peer(&self, peer_id: &PeerId) -> bool {
        self.private_peers.contains(peer_id)
    }

    /// Returns `true` when `peer_id` is exempt from `max_peers` eviction and
    /// `/24` per-subnet eclipse bounds.
    #[must_use]
    pub fn is_unconditional(&self, peer_id: &PeerId) -> bool {
        self.unconditional_peers.contains(peer_id)
    }

    /// Returns `true` when `peer_id`'s addresses may be inserted into Kademlia
    /// and shared via peer discovery.
    ///
    /// Always `false` when discovery is disabled (shielded validator) or when
    /// `peer_id` is in `private_peers` (sentry hiding its validator).
    #[must_use]
    pub fn can_share_in_dht(&self, peer_id: &PeerId) -> bool {
        !self.disable_peer_discovery && !self.private_peers.contains(peer_id)
    }

    /// Returns `true` when a private/VPC address advertised by `peer_id` may be
    /// accepted for direct communication.
    ///
    /// Unconditional peers (configured sentries or private validators) always
    /// talk over private VPC/VPN links even on mainnet, while untrusted public
    /// peers remain governed by `global_accept_private`.
    #[must_use]
    pub fn accept_private_addr_from(&self, peer_id: &PeerId, global_accept_private: bool) -> bool {
        self.is_unconditional(peer_id) || global_accept_private
    }

    /// Checks whether an established connection with `(peer_id, remote)` is
    /// permitted under this sentry policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRefusal`] when a shielded validator receives a
    /// non-sentry peer or an address outside its private VPC/VPN allowlist, or
    /// when a private validator connects to a sentry from outside the sentry's
    /// configured `allowed_private_cidrs`.
    pub(crate) fn check_connection(
        &self,
        peer_id: &PeerId,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionRefusal> {
        match self.role {
            SentryRole::ShieldedValidator => {
                if !self.sentry_peers.contains_key(peer_id) {
                    return Err(ConnectionRefusal::NotASentry);
                }
                if !ip_permitted_by_private_policy(
                    extract_ip(remote),
                    self.strict_private_network,
                    &self.allowed_private_cidrs,
                ) {
                    return Err(ConnectionRefusal::DisallowedAddress);
                }
                Ok(())
            }
            SentryRole::Sentry => {
                if self.private_peers.contains(peer_id)
                    && (self.strict_private_network || !self.allowed_private_cidrs.is_empty())
                    && !ip_permitted_by_private_policy(
                        extract_ip(remote),
                        self.strict_private_network,
                        &self.allowed_private_cidrs,
                    )
                {
                    return Err(ConnectionRefusal::DisallowedAddress);
                }
                Ok(())
            }
            SentryRole::Standard => Ok(()),
        }
    }

    /// Checks whether an outbound dial to `addr` (targeting `peer_id` if known)
    /// is permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRefusal`] if a shielded validator attempts to dial
    /// anything other than a configured sentry peer over a permitted private
    /// address.
    pub(crate) fn can_dial(
        &self,
        peer_id: Option<&PeerId>,
        addr: &Multiaddr,
    ) -> Result<(), ConnectionRefusal> {
        if self.role != SentryRole::ShieldedValidator {
            return Ok(());
        }
        let target = peer_id
            .copied()
            .or_else(|| extract_peer_id(addr))
            .ok_or(ConnectionRefusal::MissingTargetPeerId)?;
        self.check_connection(&target, addr)
    }

    /// Returns all `(PeerId, Multiaddr)` endpoints of configured sentries.
    #[must_use]
    pub fn sentry_addrs(&self) -> Vec<(PeerId, Multiaddr)> {
        self.sentry_peers
            .iter()
            .flat_map(|(id, addrs)| addrs.iter().cloned().map(|ma| (*id, ma)))
            .collect()
    }

    /// Returns all peers that should be pinned as gossipsub explicit peers.
    #[must_use]
    pub fn explicit_gossip_peers(&self) -> Vec<PeerId> {
        self.unconditional_peers.iter().copied().collect()
    }

    /// Filters a peer list before exposing it publicly, stripping every
    /// shielded validator in `private_peers`.
    #[must_use]
    pub fn scrub_public_peers(&self, peers: &[PeerId]) -> Vec<PeerId> {
        peers
            .iter()
            .copied()
            .filter(|id| !self.private_peers.contains(id))
            .collect()
    }

    /// Atomically replaces the sentry set of a [`SentryRole::ShieldedValidator`]
    /// at runtime (live failover when a sentry is under attack).
    ///
    /// Fails closed if called on a non-shielded node, if `new_addrs` is empty,
    /// or if any address is malformed or outside the allowed private CIDRs.
    ///
    /// # Errors
    ///
    /// Returns [`SentryConfigError`] without mutating the active sentry set.
    pub fn update_sentries(
        &mut self,
        new_addrs: &[String],
    ) -> Result<SentryRotationDiff, SentryConfigError> {
        if self.role != SentryRole::ShieldedValidator {
            return Err(SentryConfigError::ConflictingRole(
                "live sentry rotation is only available on a shielded validator",
            ));
        }
        if new_addrs.is_empty() {
            return Err(SentryConfigError::SafetyInvariantViolation(
                "cannot replace sentry_peers with an empty list",
            ));
        }
        if new_addrs.len() > MAX_SENTRY_PEERS {
            return Err(SentryConfigError::SafetyInvariantViolation(
                "sentry_peers exceeds maximum allowed count (64)",
            ));
        }

        let mut next: BTreeMap<PeerId, Vec<Multiaddr>> = BTreeMap::new();
        for raw in new_addrs {
            let (id, ma) = parse_sentry_multiaddr(
                raw,
                self.strict_private_network,
                &self.allowed_private_cidrs,
            )?;
            next.entry(id).or_default().push(ma);
        }

        let removed: Vec<PeerId> = self
            .sentry_peers
            .keys()
            .filter(|id| !next.contains_key(id))
            .copied()
            .collect();
        // Include both newly added PeerIds and newly rotated multiaddrs for
        // an existing sentry PeerId (for example, same node key moved to a new
        // VPC IP during live failover).
        let added: Vec<(PeerId, Multiaddr)> = next
            .iter()
            .flat_map(|(id, addrs)| {
                let existing = self.sentry_peers.get(id);
                addrs
                    .iter()
                    .filter(move |ma| !existing.is_some_and(|prev| prev.contains(ma)))
                    .cloned()
                    .map(|ma| (*id, ma))
            })
            .collect();

        for old_id in &removed {
            if !self.private_peers.contains(old_id) {
                self.unconditional_peers.remove(old_id);
            }
        }
        for id in next.keys() {
            self.unconditional_peers.insert(*id);
        }
        self.sentry_peers = next;

        let active_sentries = self.sentry_peers.keys().map(ToString::to_string).collect();

        Ok(SentryRotationDiff {
            added,
            removed,
            active_sentries,
        })
    }

    /// Produces a safe operator-RPC status snapshot without leaking hidden
    /// validator `PeerId`s or private IPs.
    #[must_use]
    pub fn status(&self, connected: &BTreeSet<PeerId>) -> SentryStatus {
        let configured_sentries = self.sentry_peers.keys().map(ToString::to_string).collect();
        let connected_sentries = self
            .sentry_peers
            .keys()
            .filter(|id| connected.contains(id))
            .map(ToString::to_string)
            .collect();
        let connected_private_peer_count = self
            .private_peers
            .iter()
            .filter(|id| connected.contains(id))
            .count();
        SentryStatus {
            role: self.role,
            discovery_disabled: self.disable_peer_discovery,
            strict_private_network: self.strict_private_network,
            configured_sentries,
            connected_sentries,
            private_peer_count: self.private_peers.len(),
            connected_private_peer_count,
            unconditional_peer_count: self.unconditional_peers.len(),
            allowed_private_cidrs: self
                .allowed_private_cidrs
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_peer() -> PeerId {
        PeerId::random()
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn shielded_validator_allows_only_configured_private_sentries() {
        let sentry_a = random_peer();
        let sentry_b = random_peer();
        let attacker = random_peer();
        let cfg = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![
                format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}"),
                format!("/ip4/10.10.0.12/tcp/30333/p2p/{sentry_b}"),
            ],
            allowed_private_cidrs: vec!["10.10.0.0/16".to_string()],
            ..Default::default()
        };
        let policy = SentryPolicy::from_config(&cfg).expect("valid shielded validator");
        assert_eq!(policy.role(), SentryRole::ShieldedValidator);
        assert!(policy.is_discovery_disabled());
        assert!(!policy.should_advertise_external());
        assert!(policy.is_unconditional(&sentry_a));
        assert!(policy.is_unconditional(&sentry_b));
        assert!(!policy.is_unconditional(&attacker));
        assert!(!policy.can_share_in_dht(&sentry_a));

        // Private VPC links to Sentry A/B pass.
        assert!(policy
            .check_connection(&sentry_a, &ma("/ip4/10.10.0.11/tcp/30333"))
            .is_ok());
        assert!(policy
            .can_dial(Some(&sentry_b), &ma("/ip4/10.10.0.12/tcp/30333"))
            .is_ok());

        // Unknown public or private peer is refused.
        assert_eq!(
            policy.check_connection(&attacker, &ma("/ip4/10.10.0.99/tcp/30333")),
            Err(ConnectionRefusal::NotASentry)
        );
        // Even a known sentry PeerId arriving from a public IP or outside the
        // VPC CIDR is refused.
        assert_eq!(
            policy.check_connection(&sentry_a, &ma("/ip4/203.0.113.5/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
        assert_eq!(
            policy.check_connection(&sentry_a, &ma("/ip4/192.168.1.11/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
    }

    #[test]
    fn sentry_shields_private_validator_from_dht_and_eviction() {
        let validator = random_peer();
        let public_peer = random_peer();
        let cfg = SentryConfig {
            role: "sentry".to_string(),
            private_peers: vec![validator.to_string()],
            allowed_private_cidrs: vec!["10.10.0.0/16".to_string()],
            ..Default::default()
        };
        let policy = SentryPolicy::from_config(&cfg).expect("valid sentry");
        assert_eq!(policy.role(), SentryRole::Sentry);
        assert!(!policy.is_discovery_disabled());
        assert!(policy.should_advertise_external());
        assert!(policy.is_private_peer(&validator));
        assert!(policy.is_unconditional(&validator));
        assert!(!policy.is_unconditional(&public_peer));

        // Public peers enter Kademlia normally; shielded validator NEVER does.
        assert!(policy.can_share_in_dht(&public_peer));
        assert!(!policy.can_share_in_dht(&validator));

        // Public peer list scrubbing strips the shielded validator.
        let scrubbed = policy.scrub_public_peers(&[validator, public_peer]);
        assert_eq!(scrubbed, vec![public_peer]);

        // Public peer connects freely; private validator must use VPC CIDR.
        assert!(policy
            .check_connection(&public_peer, &ma("/ip4/198.51.100.7/tcp/30333"))
            .is_ok());
        assert!(policy
            .check_connection(&validator, &ma("/ip4/10.10.0.5/tcp/30334"))
            .is_ok());
        assert_eq!(
            policy.check_connection(&validator, &ma("/ip4/198.51.100.9/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
        // Mainnet rejects private advertisements globally, but still permits
        // the direct private link with the authenticated validator.
        assert!(policy.accept_private_addr_from(&validator, false));
        assert!(!policy.accept_private_addr_from(&public_peer, false));
    }

    #[test]
    fn live_sentry_rotation_replaces_compromised_sentry_atomically() {
        let sentry_a = random_peer();
        let sentry_b = random_peer();
        let sentry_c = random_peer();
        let cfg = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![
                format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}"),
                format!("/ip4/10.10.0.12/tcp/30333/p2p/{sentry_b}"),
            ],
            ..Default::default()
        };
        let mut policy = SentryPolicy::from_config(&cfg).expect("init");

        // Fail closed on empty rotation or public IP under strict private mode.
        assert!(policy.update_sentries(&[]).is_err());
        assert!(policy
            .update_sentries(&[format!("/ip4/203.0.113.10/tcp/30333/p2p/{sentry_c}")])
            .is_err());
        // Active set remains untouched after refused rotation.
        assert!(policy.is_unconditional(&sentry_a));

        // Replace attacked Sentry A with fresh Sentry C over WireGuard CGNAT.
        let diff = policy
            .update_sentries(&[
                format!("/ip4/10.10.0.12/tcp/30333/p2p/{sentry_b}"),
                format!("/ip4/100.64.0.13/tcp/30333/p2p/{sentry_c}"),
            ])
            .expect("rotate sentry");
        assert_eq!(diff.removed, vec![sentry_a]);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].0, sentry_c);
        assert!(!policy.is_unconditional(&sentry_a));
        assert!(policy.is_unconditional(&sentry_b));
        assert!(policy.is_unconditional(&sentry_c));
        assert_eq!(
            policy.check_connection(&sentry_a, &ma("/ip4/10.10.0.11/tcp/30333")),
            Err(ConnectionRefusal::NotASentry)
        );
        assert!(policy
            .check_connection(&sentry_c, &ma("/ip4/100.64.0.13/tcp/30333"))
            .is_ok());
    }

    #[test]
    fn config_rejects_unsafe_combinations() {
        let sentry_a = random_peer();
        // Shielded validator cannot re-enable discovery.
        let bad_disc = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}")],
            disable_peer_discovery: Some(false),
            ..Default::default()
        };
        assert!(SentryPolicy::from_config(&bad_disc).is_err());

        // Sentry cannot also configure sentry_peers.
        let bad_role = SentryConfig {
            role: "sentry".to_string(),
            sentry_peers: vec![format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}")],
            ..Default::default()
        };
        assert!(SentryPolicy::from_config(&bad_role).is_err());

        // Public IP sentry refused when strict_private_network defaults to true.
        let bad_pub = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![format!("/ip4/198.51.100.11/tcp/30333/p2p/{sentry_a}")],
            ..Default::default()
        };
        assert!(SentryPolicy::from_config(&bad_pub).is_err());

        // Invalid CIDR refused.
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("not-an-ip/24").is_err());
    }

    #[tokio::test]
    async fn live_shielded_validator_rejects_attacker_and_rotates_sentries_without_restart() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;
        use std::time::Duration;

        use crate::chain::blockchain::Blockchain;
        use crate::chain::chain_actor::ChainActor;
        use crate::consensus::pow::PoWEngine;
        use crate::network::node::Node;

        fn pick_free_port() -> u16 {
            let listener =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral port");
            listener.local_addr().expect("local addr").port()
        }

        fn make_chain() -> crate::chain::chain_actor::ChainHandle {
            let consensus = Arc::new(PoWEngine::new(0));
            let blockchain = Blockchain::new(consensus, None, 45265, None);
            let (actor, client) = ChainActor::new(blockchain);
            tokio::spawn(async move { actor.run().await });
            client
        }

        // Start Sentry A and Sentry B plus an unauthorized public attacker node.
        let mut sentry_a = Node::new(make_chain()).expect("sentry A");
        let sentry_a_id = sentry_a.peer_id;
        let port_a = pick_free_port();
        sentry_a
            .listen_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a)
            .expect("listen sentry A");

        let mut sentry_b = Node::new(make_chain()).expect("sentry B");
        let sentry_b_id = sentry_b.peer_id;
        let port_b = pick_free_port();
        sentry_b
            .listen_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b)
            .expect("listen sentry B");

        let mut attacker = Node::new(make_chain()).expect("attacker");
        let port_att = pick_free_port();
        attacker
            .listen_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port_att)
            .expect("listen attacker");

        let sentry_a_addr = format!("/ip4/127.0.0.1/tcp/{port_a}/p2p/{sentry_a_id}");
        let sentry_b_addr = format!("/ip4/127.0.0.1/tcp/{port_b}/p2p/{sentry_b_id}");
        let attacker_addr = format!("/ip4/127.0.0.1/tcp/{port_att}/p2p/{}", attacker.peer_id);

        // Configure Shielded Validator pointing ONLY to Sentry A over loopback CIDR.
        let val_policy = SentryPolicy::from_config(&SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![sentry_a_addr.clone()],
            allowed_private_cidrs: vec!["127.0.0.1/32".to_string()],
            ..Default::default()
        })
        .expect("validator policy");
        let mut validator = Node::new(make_chain())
            .expect("validator")
            .with_sentry_policy(val_policy);
        let validator_id = validator.peer_id;
        let port_val = pick_free_port();
        validator
            .listen_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port_val)
            .expect("listen validator");
        let validator_addr = format!("/ip4/127.0.0.1/tcp/{port_val}/p2p/{validator_id}");

        // Validator MUST refuse dialing the unauthorized attacker.
        assert!(validator.dial(&attacker_addr).is_err());

        // Sentry A and B register the validator as a private, unconditional peer.
        let sentry_policy = SentryPolicy::from_config(&SentryConfig {
            role: "sentry".to_string(),
            private_peers: vec![validator_id.to_string()],
            allowed_private_cidrs: vec!["127.0.0.1/32".to_string()],
            ..Default::default()
        })
        .expect("sentry policy");
        let mut sentry_a = sentry_a.with_sentry_policy(sentry_policy.clone());
        let mut sentry_b = sentry_b.with_sentry_policy(sentry_policy);

        let val_client = validator.get_client();
        let sa_client = sentry_a.get_client();
        let sb_client = sentry_b.get_client();

        // Attacker tries to dial the shielded validator directly.
        attacker.dial(&validator_addr).expect("attacker dials");

        let h_sa = tokio::spawn(async move { sentry_a.run().await });
        let h_sb = tokio::spawn(async move { sentry_b.run().await });
        let h_att = tokio::spawn(async move { attacker.run().await });
        let h_val = tokio::spawn(async move { validator.run().await });

        // Wait for Validator <-> Sentry A connection to come up.
        let mut connected_a = false;
        for _ in 0..40 {
            let st = val_client.admin_sentry_status().await.expect("status");
            if st.connected_sentries == vec![sentry_a_id.to_string()] {
                connected_a = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connected_a, "validator should connect to Sentry A");
        // Attacker must NOT remain connected to the shielded validator.
        assert_eq!(
            val_client
                .peer_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // Sentry A reports 1 connected private validator while keeping its ID
        // hidden from Kademlia and public status.
        let sa_status = sa_client
            .admin_sentry_status()
            .await
            .expect("sentry A status");
        assert_eq!(sa_status.role, SentryRole::Sentry);
        assert_eq!(sa_status.private_peer_count, 1);
        assert_eq!(sa_status.connected_private_peer_count, 1);

        // LIVE SENTRY ROTATION: swap Sentry A -> Sentry B without restart!
        let diff = val_client
            .admin_update_sentries(vec![sentry_b_addr])
            .await
            .expect("live rotation to Sentry B");
        assert_eq!(diff.removed, vec![sentry_a_id]);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].0, sentry_b_id);

        let mut connected_b = false;
        for _ in 0..40 {
            let st = val_client
                .admin_sentry_status()
                .await
                .expect("status after rotate");
            if st.connected_sentries == vec![sentry_b_id.to_string()] {
                connected_b = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connected_b, "validator should fail over live to Sentry B");
        let sb_status = sb_client
            .admin_sentry_status()
            .await
            .expect("sentry B status");
        assert_eq!(sb_status.connected_private_peer_count, 1);

        h_val.abort();
        h_sa.abort();
        h_sb.abort();
        h_att.abort();
    }

    #[test]
    fn sentry_strict_private_network_refuses_public_ip_for_private_validator() {
        let validator = random_peer();
        let public_peer = random_peer();
        let cfg = SentryConfig {
            role: "sentry".to_string(),
            private_peers: vec![validator.to_string()],
            strict_private_network: Some(true),
            ..Default::default()
        };
        let policy = SentryPolicy::from_config(&cfg).expect("valid strict sentry");
        assert!(policy
            .check_connection(&public_peer, &ma("/ip4/198.51.100.7/tcp/30333"))
            .is_ok());
        assert!(policy
            .check_connection(&validator, &ma("/ip4/10.10.0.5/tcp/30333"))
            .is_ok());
        assert_eq!(
            policy.check_connection(&validator, &ma("/ip4/203.0.113.9/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
    }

    #[test]
    fn dual_stack_ipv4_mapped_ipv6_obeys_private_and_cidr_policy() {
        let sentry_a = random_peer();
        let cfg = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}")],
            allowed_private_cidrs: vec!["10.10.0.0/16".to_string()],
            ..Default::default()
        };
        let policy = SentryPolicy::from_config(&cfg).expect("valid policy");
        assert!(policy
            .check_connection(&sentry_a, &ma("/ip6/::ffff:10.10.0.11/tcp/30333"))
            .is_ok());
        assert_eq!(
            policy.check_connection(&sentry_a, &ma("/ip6/::ffff:203.0.113.11/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
        let strict = SentryPolicy::from_config(&SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![format!("/ip4/100.64.1.2/tcp/30333/p2p/{sentry_a}")],
            ..Default::default()
        })
        .expect("strict policy");
        assert!(strict
            .check_connection(&sentry_a, &ma("/ip6/::ffff:100.64.1.2/tcp/30333"))
            .is_ok());
        assert_eq!(
            strict.check_connection(&sentry_a, &ma("/ip6/::ffff:198.51.100.2/tcp/30333")),
            Err(ConnectionRefusal::DisallowedAddress)
        );
    }

    #[test]
    fn live_sentry_rotation_redials_same_peer_id_on_new_ip_and_caps_count() {
        let sentry_a = random_peer();
        let cfg = SentryConfig {
            role: "validator".to_string(),
            sentry_peers: vec![format!("/ip4/10.10.0.11/tcp/30333/p2p/{sentry_a}")],
            ..Default::default()
        };
        let mut policy = SentryPolicy::from_config(&cfg).expect("init");

        let new_addr = format!("/ip4/10.20.0.11/tcp/30333/p2p/{sentry_a}");
        let diff = policy
            .update_sentries(std::slice::from_ref(&new_addr))
            .expect("same-peer IP rotation");
        assert!(diff.removed.is_empty());
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].0, sentry_a);
        assert_eq!(diff.added[0].1, ma(&new_addr));

        let oversized: Vec<String> = (0..=MAX_SENTRY_PEERS)
            .map(|i| {
                format!(
                    "/ip4/10.10.0.{}/tcp/30333/p2p/{}",
                    (i % 250) + 1,
                    random_peer()
                )
            })
            .collect();
        assert!(policy.update_sentries(&oversized).is_err());
        assert_eq!(policy.sentry_addrs().len(), 1);
    }
}
