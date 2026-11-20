use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;
pub const INVALID_BLOCK_PENALTY: i32 = -10;
pub const INVALID_TX_PENALTY: i32 = -5;
pub const OVERSIZED_MESSAGE_PENALTY: i32 = -3;
pub const RATE_LIMIT_PENALTY: i32 = -3;
/// A request this node sent came back unanswered. Below the ban threshold by
/// design: the ask was this node's own choice, so an unanswerable one costs
/// the peer its place in the sync order, not an hour of silence.
const UNANSWERED_REQUEST_PENALTY: i32 = -5;
/// Unanswered sync requests in a row after which a peer is set aside as a
/// sync source for a while. It is not banned for one run: see
/// `report_unanswered_request`.
const MAX_UNANSWERED_SYNC_STRIKES: u32 = 4;
/// Rest runs in a row, each a whole run of [`MAX_UNANSWERED_SYNC_STRIKES`]
/// requests left unanswered, after which the peer is banned. A rest keeps
/// the connection, so on its own it never gives the inbound slot back.
const MAX_SYNC_REST_RUNS: u32 = 3;
/// How long a peer is set aside as a sync source the first time it reaches
/// [`MAX_UNANSWERED_SYNC_STRIKES`]. Every further run of strikes doubles the
/// rest, up to one ban-length; delivered sync data clears it.
const SYNC_REST_BASE: Duration = Duration::from_secs(60);
/// A batch that does not join this chain: a fork signal, priced like an
/// unanswered request and, like it, floored above the ban threshold.
const UNJOINED_BLOCK_PENALTY: i32 = -5;
pub const SLOW_SYNC_PENALTY: i32 = -5;
pub const INVALID_HANDSHAKE_PENALTY: i32 = -20;
pub const GOOD_BEHAVIOR_REWARD: i32 = 1;
pub const BAN_THRESHOLD: i32 = -100;
pub const BAN_DURATION: Duration = Duration::from_secs(3600);
/// How long an unbanned negative-score record survives without activity.
///
/// One ban-length. A misbehaving id keeps refreshing `last_seen` while it
/// keeps misbehaving, so its score stays; an id that goes quiet for a whole
/// ban-length is reclaimed by `prune_spent_records`, so ids an attacker
/// mints for one burst of malformed handshakes cannot fill the tracked
/// table forever and refuse every peer the node has never seen.
const NEGATIVE_RECORD_TTL: Duration = BAN_DURATION;
/// After a prune that reclaimed nothing, the table is not scanned again for
/// this long.
const EMPTY_PRUNE_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_SCORE: i32 = 100;
pub const MIN_SCORE: i32 = BAN_THRESHOLD;
pub const MAX_MSG_BURST: f64 = 20.0;
pub const MSG_REFILL_RATE: f64 = 5.0;
#[derive(Debug, Clone)]
pub struct PeerScore {
    pub score: i32,
    pub banned_until: Option<Instant>,
    /// Absolute ban expiry (unix seconds). Survives restart; `banned_until`
    /// Is recomputed from this on reload.
    pub ban_expires_unix: Option<u64>,
    pub invalid_blocks: u32,
    pub invalid_txs: u32,
    pub valid_contributions: u32,
    pub last_seen: Option<Instant>,
    /// Timestamp of the latest verified protocol contribution accepted from
    /// this peer. Unlike `last_seen`, penalty and rate-limit paths never
    /// advance it, so non-banning faults cannot extend an idle inbound slot.
    pub last_valid_at: Option<Instant>,
    pub rate_tokens: f64,
    pub rate_last_refill: Instant,
    /// Last refill of the vote and blob buckets. Separate from
    /// `rate_last_refill`, which every inbound message resets.
    pub aux_last_refill: Instant,
    pub vote_tokens: f64,
    pub blob_tokens: f64,
    pub agg_frame_tokens: f64,
    pub handshaked: bool,
    pub unanswered_sync_strikes: u32,
    /// Until when this peer is not asked for sync data. Only the choice of
    /// a sync source reads it: the peer stays connected, and its blocks and
    /// votes are taken as before.
    pub sync_rest_until: Option<Instant>,
    /// How many times in a row the peer was set aside without delivering
    /// sync data in between; the next rest is that much longer.
    pub sync_rests: u32,
}
impl Default for PeerScore {
    fn default() -> Self {
        Self {
            score: 0,
            banned_until: None,
            ban_expires_unix: None,
            invalid_blocks: 0,
            invalid_txs: 0,
            valid_contributions: 0,
            last_seen: None,
            last_valid_at: None,
            rate_tokens: MAX_MSG_BURST,
            rate_last_refill: Instant::now(),
            aux_last_refill: Instant::now(),
            vote_tokens: 10.0,
            blob_tokens: 5.0,
            agg_frame_tokens: 10.0,
            handshaked: false,
            unanswered_sync_strikes: 0,
            sync_rest_until: None,
            sync_rests: 0,
        }
    }
}
impl PeerScore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }
    /// Refill the vote and blob buckets. The general bucket is refilled by
    /// `consume_token_with_rate`, so its clock is not shared with these two.
    pub fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.aux_last_refill).as_secs_f64();

        self.vote_tokens = (self.vote_tokens + elapsed * 2.0).min(20.0);

        self.blob_tokens = (self.blob_tokens + elapsed * 0.5).min(10.0);

        self.agg_frame_tokens = (self.agg_frame_tokens + elapsed * 2.0).min(20.0);

        self.aux_last_refill = now;
    }
    pub fn consume_token(&mut self) -> bool {
        self.consume_token_with_rate(MSG_REFILL_RATE)
    }

    /// Refill using an explicit tokens/sec rate (network profile).
    pub fn consume_token_with_rate(&mut self, refill_rate: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.rate_last_refill).as_secs_f64();
        self.rate_tokens = (self.rate_tokens + elapsed * refill_rate).min(MAX_MSG_BURST);
        self.rate_last_refill = now;
        if self.rate_tokens >= 1.0 {
            self.rate_tokens -= 1.0;
            true
        } else {
            false
        }
    }
    #[must_use]
    pub fn ban_remaining(&self) -> Option<Duration> {
        self.banned_until.and_then(|until| {
            let now = Instant::now();
            if now < until {
                Some(until - now)
            } else {
                None
            }
        })
    }
}
/// The bucket a peer's address is counted in for eclipse protection.
///
/// IPv4 peers share a `/24`. IPv6 peers share a `/64`, the smallest prefix a
/// single subscriber is normally delegated, so one host cannot buy extra
/// admission slots by walking its own `/64`. The family is a leading tag byte
/// so an IPv4 `/24` and an IPv6 `/64` that happen to share their first bytes
/// never collapse into one bucket.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) *is* the IPv4 address: it is
/// normalised back to the `/24`. Before this type the mapped form was bucketed
/// as a bare IPv6 address and every IPv6 peer was unbucketed altogether, so a
/// dual-stack listener handed one host the whole peer table: the bound the
/// profile sets was enforced on one of the two families and on neither mapped
/// address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct SubnetKey([u8; 16]);

impl SubnetKey {
    /// One bounded bucket for relay/circuit and other addresses with no IP.
    /// Treating an unbucketed address as unlimited would bypass eclipse limits.
    const UNADDRESSED: Self = Self([0u8; 16]);

    /// Tag for an IPv4 `/24` bucket.
    const FAMILY_V4: u8 = 4;
    /// Tag for an IPv6 `/64` bucket.
    const FAMILY_V6: u8 = 6;

    /// The `/24` an IPv4 address belongs to, keyed by its first three octets.
    #[must_use]
    fn ipv4([a, b, c]: [u8; 3]) -> Self {
        Self([Self::FAMILY_V4, a, b, c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// The `/64` an IPv6 address belongs to, keyed by its first eight octets.
    #[must_use]
    fn ipv6([p0, p1, p2, p3, p4, p5, p6, p7]: [u8; 8]) -> Self {
        Self([
            Self::FAMILY_V6,
            p0,
            p1,
            p2,
            p3,
            p4,
            p5,
            p6,
            p7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
    }

    /// The bucket of an IP address, with the mapped v4 form folded into v4.
    #[must_use]
    pub fn from_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                Self::ipv4([a, b, c])
            }
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => {
                    let [a, b, c, _] = v4.octets();
                    Self::ipv4([a, b, c])
                }
                None => {
                    let [p0, p1, p2, p3, p4, p5, p6, p7, ..] = v6.octets();
                    Self::ipv6([p0, p1, p2, p3, p4, p5, p6, p7])
                }
            },
        }
    }
}

impl From<[u8; 3]> for SubnetKey {
    fn from(octets: [u8; 3]) -> Self {
        Self::ipv4(octets)
    }
}

impl From<std::net::IpAddr> for SubnetKey {
    fn from(ip: std::net::IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

pub struct PeerManager {
    peers: HashMap<PeerId, PeerScore>,
    /// Tokens refilled per second for general P2P messages.
    /// Derived from `SecurityConfig.peer_rate_limit_per_minute` when applied.
    pub(crate) msg_refill_rate: f64,
    /// Soft ceiling on tracked peer score entries (memory `DoS` guard).
    pub(crate) max_tracked_peers: usize,
    /// H5.1 eclipse protection: max concurrent connections per subnet bucket
    /// (IPv4 `/24`, IPv6 `/64`).
    pub(crate) max_peers_per_subnet: usize,
    /// Live connection count per subnet bucket.
    subnet_counts: HashMap<SubnetKey, usize>,
    /// Peer → subnet mapping for disconnect accounting.
    peer_subnets: HashMap<PeerId, SubnetKey>,
    /// Live peer set. Libp2p can emit multiple connection events for one peer;
    /// This set makes `peer_count` and per-subnet accounting idempotent.
    connected_peers: HashSet<PeerId>,
    /// Operator-configured sentry/validator shield peers exempt from public
    /// `/24` subnet caps, public `max_peers` eviction, multiplexed rate-limit
    /// drops, and score banning.
    protected_peers: HashSet<PeerId>,
    /// H5.2 outbound diversity: max outbound connections per subnet bucket.
    pub(crate) max_outbound_per_subnet: usize,
    /// Outbound connection count per subnet bucket.
    outbound_subnet_counts: HashMap<SubnetKey, usize>,
    /// Outbound peer → subnet mapping.
    outbound_peer_subnets: HashMap<PeerId, SubnetKey>,
    /// When the last full-table prune found nothing to reclaim. While the
    /// table stays full of unprunable records, scanning it again on every
    /// message from an unknown peer is a CPU amplifier.
    last_empty_prune: Option<Instant>,
}
impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    /// Default burst refill (~5 msg/s) with 10k tracked-peer ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            msg_refill_rate: MSG_REFILL_RATE,
            max_tracked_peers: 10_000,
            max_peers_per_subnet: 4,
            subnet_counts: HashMap::new(),
            peer_subnets: HashMap::new(),
            connected_peers: HashSet::new(),
            protected_peers: HashSet::new(),
            max_outbound_per_subnet: 0,
            outbound_subnet_counts: HashMap::new(),
            outbound_peer_subnets: HashMap::new(),
            last_empty_prune: None,
        }
    }

    /// Apply network security profile to P2P rate limiting.
    /// `peer_rate_limit_per_minute` becomes tokens/second = limit/60.
    pub fn apply_security_config(&mut self, security: crate::core::chain_config::SecurityConfig) {
        let per_min = security.peer_rate_limit_per_minute.max(1);
        self.msg_refill_rate = (per_min as f64) / 60.0;
        self.max_peers_per_subnet = security.max_peers_per_subnet.max(1);
        self.max_outbound_per_subnet = security.max_outbound_per_subnet;
        // Keep a hard memory ceiling independent of max_peers (connected).
        self.max_tracked_peers = 10_000;
    }

    #[must_use]
    pub fn msg_refill_rate(&self) -> f64 {
        self.msg_refill_rate
    }

    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected_peers.iter().copied().collect()
    }

    #[must_use]
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.contains(peer_id)
    }

    /// Install the set of operator-configured sentry/validator shield peers.
    /// Any prior persisted or transient ban on a shield peer is cleared immediately.
    pub fn set_protected_peers<I: IntoIterator<Item = PeerId>>(&mut self, peers: I) {
        self.protected_peers = peers.into_iter().collect();
        let protected: Vec<PeerId> = self.protected_peers.iter().copied().collect();
        for peer_id in protected {
            self.unban_peer(&peer_id);
        }
    }

    /// Count of live connected peers excluding reserved sentry-shield links.
    #[must_use]
    pub fn public_connected_count(&self) -> usize {
        self.connected_peers
            .iter()
            .filter(|peer| !self.protected_peers.contains(peer))
            .count()
    }

    #[must_use]
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    #[must_use]
    pub fn max_tracked_peers(&self) -> usize {
        self.max_tracked_peers
    }

    /// Maximum admitted connections sharing the same IPv4 /24.
    #[must_use]
    pub fn max_peers_per_subnet(&self) -> usize {
        self.max_peers_per_subnet
    }

    pub fn set_max_peers_per_subnet(&mut self, n: usize) {
        self.max_peers_per_subnet = n.max(1);
    }

    /// Outbound subnet diversity bound (0 = no limit).
    #[must_use]
    pub fn max_outbound_per_subnet(&self) -> usize {
        self.max_outbound_per_subnet
    }

    /// Returns false if an outbound connection to `subnet` would
    /// Exceed the diversity bound. 0 = unlimited.
    ///
    /// `None` means the address carried no IP we could bucket (a relay circuit
    /// multiaddr, for instance). All such peers share one bounded bucket.
    pub fn can_admit_outbound_subnet<K: Into<SubnetKey>>(&self, subnet: Option<K>) -> bool {
        if self.max_outbound_per_subnet == 0 {
            return true;
        }
        let key = subnet.map(Into::into).unwrap_or(SubnetKey::UNADDRESSED);
        self.outbound_subnet_counts.get(&key).copied().unwrap_or(0) < self.max_outbound_per_subnet
    }

    /// Record an outbound connection. Returns false if the peer is
    /// Already tracked as outbound or the subnet bound is exceeded.
    pub fn note_outbound_connected<K: Into<SubnetKey>>(
        &mut self,
        peer_id: PeerId,
        subnet: Option<K>,
    ) -> bool {
        if self.protected_peers.contains(&peer_id) {
            return true;
        }
        let key = subnet.map(Into::into).unwrap_or(SubnetKey::UNADDRESSED);
        if !self.can_admit_outbound_subnet(Some(key)) {
            return false;
        }
        if self.outbound_peer_subnets.contains_key(&peer_id) {
            return false;
        }
        *self.outbound_subnet_counts.entry(key).or_insert(0) += 1;
        self.outbound_peer_subnets.insert(peer_id, key);
        true
    }

    /// Drop outbound accounting when a peer disconnects.
    pub fn note_outbound_disconnected(&mut self, peer_id: &PeerId) -> bool {
        if let Some(key) = self.outbound_peer_subnets.remove(peer_id) {
            if let Some(c) = self.outbound_subnet_counts.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.outbound_subnet_counts.remove(&key);
                }
            }
            true
        } else {
            false
        }
    }

    /// Returns false if admitting `subnet` would exceed the eclipse bound.
    pub fn can_admit_subnet<K: Into<SubnetKey>>(&self, subnet: Option<K>) -> bool {
        let key = subnet.map(Into::into).unwrap_or(SubnetKey::UNADDRESSED);
        self.subnet_counts.get(&key).copied().unwrap_or(0) < self.max_peers_per_subnet
    }

    /// Record a live connection under an optional subnet bucket.
    ///
    /// Returns `true` only for the first live connection for `peer_id`.
    /// Libp2p may emit duplicate connection events for the same peer/address;
    /// Counting those duplicates was causing `peer_count` drift and subnet
    /// overcount.
    pub fn note_connected<K: Into<SubnetKey>>(
        &mut self,
        peer_id: PeerId,
        subnet: Option<K>,
    ) -> bool {
        if !self.connected_peers.insert(peer_id) {
            return false;
        }
        if self.protected_peers.contains(&peer_id) {
            return true;
        }
        let key = subnet.map(Into::into).unwrap_or(SubnetKey::UNADDRESSED);
        *self.subnet_counts.entry(key).or_insert(0) += 1;
        self.peer_subnets.insert(peer_id, key);
        true
    }

    /// Drop subnet accounting when a peer disconnects.
    ///
    /// Returns `true` if this call removed a previously live peer. Duplicate
    /// Disconnect events are ignored to prevent `AtomicUsize` underflow.
    pub fn note_disconnected(&mut self, peer_id: &PeerId) -> bool {
        if !self.connected_peers.remove(peer_id) {
            return false;
        }
        if let Some(key) = self.peer_subnets.remove(peer_id) {
            if let Some(c) = self.subnet_counts.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.subnet_counts.remove(&key);
                }
            }
        }
        if self.peers.len() > self.max_tracked_peers {
            let _ = self.prune_spent_records();
            while self.peers.len() > self.max_tracked_peers && self.evict_stalest_penalty() {}
        }
        true
    }

    pub fn subnet_connection_count<K: Into<SubnetKey>>(&self, subnet: K) -> usize {
        self.subnet_counts.get(&subnet.into()).copied().unwrap_or(0)
    }
    /// Score entry for a peer, creating one if the map has room.
    ///
    /// Returns `None` when the peer is new and the map is at
    /// `max_tracked_peers`. The bound lives here rather than at the call sites
    /// because there are thirteen of them and it was written at one.
    ///
    /// What the single check protected was `check_rate_limit`. The other
    /// twelve entry points, among them `report_invalid_block`,
    /// `report_invalid_handshake`, `check_vote_rate_limit` and
    /// `check_blob_rate_limit`, all inserted an entry for any `PeerId` handed
    /// to them. A `PeerId` is a public key hash, so an attacker mints them for
    /// free, and reaching those paths costs one malformed message each: the
    /// cheapest of them is the invalid-handshake path, which by construction
    /// runs before a peer has proved anything at all.
    ///
    /// The guarded path therefore capped the map at ten thousand entries while
    /// twelve unguarded ones grew it without limit. Measured with a canary at
    /// `max_tracked_peers = 8`: sixty-four distinct peers through
    /// `report_invalid_handshake` left sixty-four entries.
    ///
    /// Refusal rather than eviction is deliberate. Evicting to make room would
    /// let an attacker flush the entry holding a real peer's ban, which turns
    /// a memory bound into a ban-clearing primitive. A peer already tracked is
    /// always found, so refusing only ever costs a new entry, never an
    /// accumulated penalty.
    fn get_or_create(&mut self, peer_id: &PeerId) -> Option<&mut PeerScore> {
        let shield_protected = self.protected_peers.contains(peer_id);
        if !shield_protected
            && !self.peers.contains_key(peer_id)
            && self.peers.len() >= self.max_tracked_peers
        {
            let recently_empty = self
                .last_empty_prune
                .is_some_and(|t| t.elapsed() < EMPTY_PRUNE_BACKOFF);
            if !recently_empty {
                if self.prune_spent_records() == 0 {
                    self.last_empty_prune = Some(Instant::now());
                } else {
                    self.last_empty_prune = None;
                }
            }
            if self.peers.len() >= self.max_tracked_peers {
                let is_connected = self.connected_peers.contains(peer_id);
                let reclaimed = is_connected && self.evict_stalest_penalty();
                let within_connected_headroom =
                    is_connected && self.peers.len() < self.max_tracked_peers.saturating_add(1_024);
                if !reclaimed && !within_connected_headroom {
                    warn!(
                        "Peer score table full ({}), refusing a record for {}",
                        self.max_tracked_peers, peer_id
                    );
                    return None;
                }
            }
        }
        Some(self.peers.entry(*peer_id).or_default())
    }

    /// Make room for a connected peer by dropping the least recently seen
    /// unbanned, unconnected record. Running bans are never evicted here, so
    /// admitting a connected peer can never clear an active ban; if every
    /// tracked slot holds a live ban, connected peers use bounded session
    /// headroom instead.
    fn evict_stalest_penalty(&mut self) -> bool {
        let connected = &self.connected_peers;
        let protected = &self.protected_peers;
        let victim = self
            .peers
            .iter()
            .filter(|(id, s)| {
                !s.is_banned() && !connected.contains(*id) && !protected.contains(*id)
            })
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(id, _)| *id);
        match victim {
            Some(id) => self.peers.remove(&id).is_some(),
            None => false,
        }
    }

    /// Reclaim records that carry nothing worth keeping.
    ///
    /// A record is spent when its ban, if it ever had one, has expired, no
    /// penalty is left on the score, and the peer is not connected. Without
    /// this the ceiling is a one-way door: a peer id is a public key hash, so
    /// an attacker mints ten thousand of them for free, fills the table once,
    /// and every peer the node has never seen is refused for the rest of its
    /// uptime.
    ///
    /// The predicate used to require `ban_expires_unix` to be set as well, so
    /// a record that never carried a ban (one message through
    /// `check_rate_limit` is enough to create one at score 0) could never be
    /// reclaimed, and `cleanup_expired_bans` clears the field before this
    /// runs, so a served ban could not be either. The table filled once and
    /// stayed full.
    ///
    /// What makes this safe against being turned into a ban-clearing
    /// primitive is what it refuses to touch: a record whose ban is still
    /// running is kept, and a penalty-bearing record is kept while it is
    /// fresh. The entries an attacker mints through
    /// `report_invalid_handshake` and friends are negative-scored the moment
    /// they exist; a fresh one stays, but an unbanned negative record whose
    /// `last_seen` is older than `NEGATIVE_RECORD_TTL` is reclaimed. The
    /// earlier rule kept every negative record forever, so minted garbage
    /// filled the ceiling once and every unseen peer was refused for the
    /// rest of the node's uptime - the denial of service this very bound
    /// exists to prevent. The trade is deliberate: a penalised id that stays
    /// quiet for a whole ban-length earns a clean record; one that keeps
    /// misbehaving refreshes `last_seen` and keeps its score, and any id
    /// whose misbehaviour reached the ban threshold carries a ban, which
    /// this predicate never reclaims. A connected peer is kept whatever its
    /// score, so a live session does not lose its handshake to a table full
    /// of strangers.
    pub fn prune_spent_records(&mut self) -> usize {
        self.cleanup_expired_bans();
        let before = self.peers.len();
        let connected = &self.connected_peers;
        let protected = &self.protected_peers;
        self.peers.retain(|id, s| {
            s.is_banned()
                || connected.contains(id)
                || protected.contains(id)
                || (s.score < 0 && Self::negative_record_is_fresh(s))
        });
        before - self.peers.len()
    }

    /// An unbanned negative record stays while its misbehaviour is recent.
    /// A record with no `last_seen` at all has no observed activity worth
    /// protecting and is treated as stale.
    fn negative_record_is_fresh(s: &PeerScore) -> bool {
        s.last_seen
            .is_some_and(|seen| seen.elapsed() < NEGATIVE_RECORD_TTL)
    }

    /// Score entry for a peer whose entry is known to exist, or a refusal.
    ///
    /// Penalty paths use this so that hitting the ceiling reads as "this peer
    /// is not tracked" rather than silently skipping the penalty.
    pub fn check_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        self.check_rate_limit_from(peer_id, true)
    }

    /// Check per-peer general message rate budget. When `authored_by_peer` is
    /// `false` (a gossipsub mesh relayer forwarding another peer's message),
    /// exhaustion still drops the excess traffic and demotes the peer in
    /// selection order, but floors above `BAN_THRESHOLD` so a transaction or
    /// vote burst originated by a third party cannot get honest mesh relayers
    /// banned and partition finality quorum.
    pub(crate) fn check_rate_limit_from(
        &mut self,
        peer_id: &PeerId,
        authored_by_peer: bool,
    ) -> bool {
        if self.protected_peers.contains(peer_id) {
            if let Some(score) = self.get_or_create(peer_id) {
                score.last_seen = Some(Instant::now());
            }
            return true;
        }
        let refill = self.msg_refill_rate;
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        if !score.consume_token_with_rate(refill) {
            let floor = if authored_by_peer {
                MIN_SCORE
            } else {
                MIN_SCORE.saturating_add(1)
            };
            score.score = score.score.saturating_add(RATE_LIMIT_PENALTY).max(floor);
            score.last_seen = Some(Instant::now());
            let spent = authored_by_peer && score.score <= BAN_THRESHOLD;
            if spent {
                self.ban_peer(peer_id);
            }
            return false;
        }
        true
    }

    pub fn check_vote_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        self.check_vote_rate_limit_from(peer_id, true)
    }

    /// Check per-peer vote rate budget. When `authored_by_peer` is `false`
    /// (for example a gossipsub relayer forwarding another validator's vote),
    /// exhaustion still drops the excess traffic and demotes the peer in
    /// selection order, but floors above `BAN_THRESHOLD` so a flooding third
    /// party cannot get honest mesh relayers banned.
    pub(crate) fn check_vote_rate_limit_from(
        &mut self,
        peer_id: &PeerId,
        authored_by_peer: bool,
    ) -> bool {
        if self.protected_peers.contains(peer_id) {
            if let Some(score) = self.get_or_create(peer_id) {
                score.last_seen = Some(Instant::now());
            }
            return true;
        }
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        score.refill_tokens();
        if score.vote_tokens >= 1.0 {
            score.vote_tokens -= 1.0;
            true
        } else {
            let floor = if authored_by_peer {
                MIN_SCORE
            } else {
                MIN_SCORE.saturating_add(1)
            };
            score.score = (score.score - 1).max(floor);
            score.last_seen = Some(Instant::now());
            let spent = authored_by_peer && score.score <= BAN_THRESHOLD;
            if spent {
                self.ban_peer(peer_id);
            }
            false
        }
    }

    pub fn check_blob_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        self.check_blob_rate_limit_from(peer_id, true)
    }

    /// Check per-peer QC/fault-proof blob rate budget. Relayed frames and
    /// `/sync` pull saturation (`authored_by_peer == false`) enforce the token
    /// bucket and demote score without auto-banning honest relayers/fetchers.
    pub(crate) fn check_blob_rate_limit_from(
        &mut self,
        peer_id: &PeerId,
        authored_by_peer: bool,
    ) -> bool {
        if self.protected_peers.contains(peer_id) {
            if let Some(score) = self.get_or_create(peer_id) {
                score.last_seen = Some(Instant::now());
            }
            return true;
        }
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        score.refill_tokens();
        if score.blob_tokens >= 1.0 {
            score.blob_tokens -= 1.0;
            true
        } else {
            let floor = if authored_by_peer {
                MIN_SCORE
            } else {
                MIN_SCORE.saturating_add(1)
            };
            score.score = (score.score - 5).max(floor);
            score.last_seen = Some(Instant::now());
            let spent = authored_by_peer && score.score <= BAN_THRESHOLD;
            if spent {
                self.ban_peer(peer_id);
            }
            false
        }
    }

    #[cfg(test)]
    pub(crate) fn charge_agg_frame(&mut self, peer_id: &PeerId, objects: usize) -> bool {
        self.charge_agg_frame_from(peer_id, true, objects)
    }

    /// Charge a peer's aggregation-frame budget proportionally to the objects
    /// inside the frame (each object costs a native signature check on the chain
    /// actor). Relayed frames (`authored_by_peer == false`) enforce the token
    /// bucket and demote score without auto-banning honest relayers.
    pub(crate) fn charge_agg_frame_from(
        &mut self,
        peer_id: &PeerId,
        authored_by_peer: bool,
        objects: usize,
    ) -> bool {
        if self.protected_peers.contains(peer_id) {
            if let Some(score) = self.get_or_create(peer_id) {
                score.last_seen = Some(Instant::now());
            }
            return true;
        }
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        score.refill_tokens();
        let capped_units = u32::try_from(objects.max(1)).unwrap_or(u32::MAX);
        let cost = (f64::from(capped_units) / 16.0).max(1.0);
        // Admit when accrued tokens cover `cost`, or allow a single large frame
        // when the peer holds at least its fresh 10-token burst while recording
        // the full unclamped cooldown debt (bounded to 128s at 2 tokens/s).
        if score.agg_frame_tokens >= cost || score.agg_frame_tokens >= 10.0 {
            score.agg_frame_tokens = (score.agg_frame_tokens - cost).max(-256.0);
            true
        } else {
            let floor = if authored_by_peer {
                MIN_SCORE
            } else {
                MIN_SCORE.saturating_add(1)
            };
            score.score = (score.score - 5).max(floor);
            score.last_seen = Some(Instant::now());
            let spent = authored_by_peer && score.score <= BAN_THRESHOLD;
            if spent {
                self.ban_peer(peer_id);
            }
            false
        }
    }
    pub fn report_invalid_block(&mut self, peer_id: &PeerId) {
        let protected = self.protected_peers.contains(peer_id);
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.invalid_blocks += 1;
        let floor = if protected { 0 } else { MIN_SCORE };
        score.score = (score.score + INVALID_BLOCK_PENALTY).max(floor);
        score.last_seen = Some(Instant::now());
        if !protected && score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_invalid_tx(&mut self, peer_id: &PeerId) {
        let protected = self.protected_peers.contains(peer_id);
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.invalid_txs += 1;
        let floor = if protected { 0 } else { MIN_SCORE };
        score.score = (score.score + INVALID_TX_PENALTY).max(floor);
        score.last_seen = Some(Instant::now());
        if !protected && score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_oversized_message(&mut self, peer_id: &PeerId) {
        let protected = self.protected_peers.contains(peer_id);
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        let floor = if protected { 0 } else { MIN_SCORE };
        score.score = (score.score + OVERSIZED_MESSAGE_PENALTY).max(floor);
        score.last_seen = Some(Instant::now());
        if !protected && score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_bad_behavior(&mut self, peer_id: &PeerId) {
        let protected = self.protected_peers.contains(peer_id);
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        let floor = if protected { 0 } else { MIN_SCORE };
        score.score = (score.score - 10).max(floor);
        score.last_seen = Some(Instant::now());
        if !protected && score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_good_behavior(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        let now = Instant::now();
        score.valid_contributions += 1;
        score.score = (score.score + GOOD_BEHAVIOR_REWARD).min(MAX_SCORE);
        score.last_seen = Some(now);
        score.last_valid_at = Some(now);
    }
    /// Reset consecutive unanswered-sync strikes only after the peer actually
    /// delivers valid sync data that advances or feeds our chain.
    pub fn report_sync_success(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        let now = Instant::now();
        score.valid_contributions += 1;
        score.unanswered_sync_strikes = 0;
        score.sync_rest_until = None;
        score.sync_rests = 0;
        score.score = (score.score + GOOD_BEHAVIOR_REWARD).min(MAX_SCORE);
        score.last_seen = Some(now);
        score.last_valid_at = Some(now);
    }
    pub fn ban_peer(&mut self, peer_id: &PeerId) {
        if self.protected_peers.contains(peer_id) {
            warn!("Refusing to ban protected sentry-shield peer {}", peer_id);
            return;
        }
        // A ban that cannot be recorded is the one refusal that must not pass
        // quietly. Every other caller of `get_or_create` is adjusting a score
        // that only matters while the peer is tracked; this one is the record
        // that keeps a peer out. Reaching the ceiling here means the map is
        // full of peers an attacker minted, which is the state the operator
        // has to know about, so it is logged at warn rather than dropped.
        //
        // The already-banned case is unaffected: a peer with an entry is
        // always found, and only a peer with no entry at all can be refused.
        let ceiling = self.max_tracked_peers;
        let tracked = self.peers.len();
        let Some(score) = self.get_or_create(peer_id) else {
            warn!(
                "Cannot ban peer {}: score map full at {}/{} entries, ban not recorded",
                peer_id, tracked, ceiling
            );
            return;
        };
        score.banned_until = Some(Instant::now() + BAN_DURATION);
        score.ban_expires_unix = Some(unix_now_secs().saturating_add(BAN_DURATION.as_secs()));
        warn!("Peer {} banned for {:?}", peer_id, BAN_DURATION);
    }
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.peers.get(peer_id).is_some_and(PeerScore::is_banned)
    }
    #[must_use]
    pub fn get_score(&self, peer_id: &PeerId) -> i32 {
        self.peers.get(peer_id).map_or(0, |s| s.score)
    }
    #[must_use]
    pub fn is_handshaked(&self, peer_id: &PeerId) -> bool {
        self.peers.get(peer_id).is_some_and(|s| s.handshaked)
    }
    pub fn set_handshaked(&mut self, peer_id: &PeerId, status: bool) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.handshaked = status;
    }
    #[must_use]
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<&PeerScore> {
        self.peers.get(peer_id)
    }
    /// Test-only: set ban expiry for a peer (simulates ban TTL expiry).
    #[cfg(test)]
    pub fn set_ban_expiry_for_test(&mut self, peer_id: &PeerId, expiry: Option<u64>) {
        if let Some(score) = self.peers.get_mut(peer_id) {
            score.ban_expires_unix = expiry;
            // Also clear banned_until when expiry is None or 0 (expired)
            if expiry.is_none() || expiry == Some(0) {
                score.banned_until = None;
            }
        }
    }
    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        if let Some(score) = self.peers.get_mut(peer_id) {
            score.banned_until = None;
            score.ban_expires_unix = None;
            score.unanswered_sync_strikes = 0;
            score.score = 0;
        }
    }
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        let now_unix = unix_now_secs();
        for score in self.peers.values_mut() {
            let expired_instant = score.banned_until.is_some_and(|until| now >= until);
            let expired_unix = score.ban_expires_unix.is_some_and(|exp| now_unix >= exp);
            if expired_instant || expired_unix {
                score.banned_until = None;
                score.ban_expires_unix = None;
                score.unanswered_sync_strikes = 0;
                score.score = 0;
            }
        }
    }
    #[must_use]
    pub fn get_banned_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, score)| score.is_banned())
            .map(|(id, _)| *id)
            .collect()
    }
    /// A sync round with this peer ran into its timeout.
    ///
    /// Slowness is not an offence. The node that waited may be the slow one
    /// (a loaded host, a debug build, a cold disk), and the peer it waited
    /// for is one of the validators whose votes it needs. The score moves,
    /// so a faster peer is asked first, and stops one point above the ban
    /// threshold.
    pub fn report_slow_sync(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = score
            .score
            .saturating_add(SLOW_SYNC_PENALTY)
            .max(MIN_SCORE.saturating_add(1));
        score.last_seen = Some(Instant::now());
    }
    /// A request this node sent came back unanswered.
    ///
    /// Asking a peer for a header batch or a block range is this node's own
    /// decision, and the answer can fail for reasons that say nothing about
    /// the peer: a connection that churned mid-flight, a peer busy importing
    /// the blocks it already has, a request the transport dropped, or this
    /// node itself being too slow to read the answer in time. The score
    /// moves - a peer that never answers sinks in `get_best_peers` - and
    /// stops one point above the ban threshold.
    ///
    /// A peer that leaves `MAX_UNANSWERED_SYNC_STRIKES` requests in a row
    /// unanswered is set aside as a sync source ([`Self::is_sync_resting`]):
    /// it is not asked again for a while, so it cannot hold the one sync
    /// round of this node by staying silent. It is not banned. A ban is an
    /// hour in which the peer's blocks and votes are refused too, and it is
    /// written to disk: a validator that fell behind on a busy host banned
    /// the peers it was syncing from, restarted, read the bans back and
    /// stayed alone (testnet rehearsal, validator loss and rejoin). On a
    /// mesh of a few validators one such ban is also one vote less in every
    /// finality round. Refusals that prove malice keep their own paths: an
    /// invalid block, a forged vote, an oversized message.
    pub fn report_unanswered_request(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.unanswered_sync_strikes = score.unanswered_sync_strikes.saturating_add(1);
        score.last_seen = Some(Instant::now());
        score.score = score
            .score
            .saturating_add(UNANSWERED_REQUEST_PENALTY)
            .max(MIN_SCORE.saturating_add(1));
        if score.unanswered_sync_strikes >= MAX_UNANSWERED_SYNC_STRIKES {
            score.unanswered_sync_strikes = 0;
            score.sync_rests = score.sync_rests.saturating_add(1);
            // 1, 2, 4, ... times the base, capped at one ban-length.
            let doublings = score.sync_rests.saturating_sub(1).min(16);
            let rest = SYNC_REST_BASE
                .saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
                .min(BAN_DURATION);
            score.sync_rest_until = Some(Instant::now() + rest);
            // A rest only reorders the asks: the peer keeps the connection,
            // and that connection keeps an inbound slot a peer that serves
            // data could hold instead. A peer that comes back from a rest
            // and leaves a whole run of requests unanswered again is not an
            // unlucky wait, and the rests stop being an answer for it. Any
            // delivered sync data clears `sync_rests`, so a validator that
            // is only slow never reaches the cap.
            let refused_across_rests = score.sync_rests >= MAX_SYNC_REST_RUNS;
            warn!(
                "Peer {} left {} sync requests in a row unanswered: not asked for sync data for {:?}",
                peer_id, MAX_UNANSWERED_SYNC_STRIKES, rest
            );
            if refused_across_rests {
                warn!(
                    "Peer {} refused sync data across {} rests: banned to free its slot",
                    peer_id, MAX_SYNC_REST_RUNS
                );
                self.ban_peer(peer_id);
            }
        }
    }
    /// Whether the peer is set aside as a sync source right now.
    #[must_use]
    pub fn is_sync_resting(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .and_then(|score| score.sync_rest_until)
            .is_some_and(|until| Instant::now() < until)
    }
    /// A block or a sync batch that does not continue this chain.
    ///
    /// `validate_and_add_block` answers `Previous hash mismatch` for two
    /// situations that look alike on the wire and are not alike at all: our
    /// own tip moved between the request and the answer (another arm of the
    /// node imported a block first), or the peer is serving a fork that does
    /// not contain our tip. Neither is a malformed block, and neither is proof
    /// that the sender forged anything: on a mesh where a slot can have more
    /// than one elected leader, a peer sitting on the winning branch is
    /// expected to answer with a suffix that does not join the losing one.
    /// Charging it as an invalid block let a four-validator devnet ban its own
    /// validators over an ordinary fork and then fail to reach finality.
    ///
    /// The score still moves: a peer that answers every round with a batch
    /// that cannot be joined sinks in `get_best_peers`, so the re-walk this
    /// node performs asks someone else next time. The floor is one point above
    /// [`BAN_THRESHOLD`], so this path can demote a peer but never silence it.
    /// Refusals that do prove malice keep their own paths: a block whose own
    /// hash does not match its contents, a forged vote, an oversized message.
    pub fn report_unjoined_block(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = score
            .score
            .saturating_add(UNJOINED_BLOCK_PENALTY)
            .max(MIN_SCORE.saturating_add(1));
        score.last_seen = Some(Instant::now());
    }
    pub fn report_invalid_handshake(&mut self, peer_id: &PeerId) {
        let protected = self.protected_peers.contains(peer_id);
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        let floor = if protected { 0 } else { MIN_SCORE };
        score.score = (score.score + INVALID_HANDSHAKE_PENALTY).max(floor);
        score.last_seen = Some(Instant::now());
        if !protected && score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    #[must_use]
    pub fn get_best_peers(&self, n: usize) -> Vec<PeerId> {
        let mut scored: Vec<_> = self.peers.iter().filter(|(_, s)| !s.is_banned()).collect();
        scored.sort_by_key(|x| std::cmp::Reverse(x.1.score));
        scored.into_iter().take(n).map(|(id, _)| *id).collect()
    }

    /// Snapshot of still-active bans with absolute expiry (unix seconds).
    /// Remaining duration is reconstructed on reload.
    #[must_use]
    pub fn get_persisted_banned_peers(&self) -> Vec<PersistedBan> {
        let now = Instant::now();
        let now_unix = unix_now_secs();
        self.peers
            .iter()
            .filter_map(|(id, s)| {
                if s.banned_until.is_none_or(|until| now >= until) {
                    return None;
                }
                let expires_unix = s.ban_expires_unix.unwrap_or_else(|| {
                    // Fallback for in-memory bans set before unix field existed.
                    let remaining = s.ban_remaining().unwrap_or(BAN_DURATION);
                    now_unix.saturating_add(remaining.as_secs())
                });
                if expires_unix <= now_unix {
                    return None;
                }
                Some(PersistedBan {
                    peer_id: id.to_base58(),
                    expires_unix,
                })
            })
            .collect()
    }

    /// Restore bans from durable storage using absolute expiry timestamps.
    /// Remaining duration = `expires_unix - now` (never restarts a full ban window).
    pub fn reload_banned_peers(&mut self, bans: &[PersistedBan]) {
        let now_unix = unix_now_secs();
        for ban in bans {
            if ban.expires_unix <= now_unix {
                continue; // already expired
            }
            let Ok(pid) = ban.peer_id.parse::<PeerId>() else {
                continue;
            };
            if self.protected_peers.contains(&pid) {
                continue;
            }
            let remaining = Duration::from_secs(ban.expires_unix - now_unix);
            // The table ceiling applies to a reload too: a long ban file must not grow it.
            let Some(entry) = self.get_or_create(&pid) else {
                continue;
            };
            entry.banned_until = Some(Instant::now() + remaining);
            entry.ban_expires_unix = Some(ban.expires_unix);
            entry.score = BAN_THRESHOLD;
        }
    }

    /// Legacy helper: reload peer IDs with a *full* ban window (pre- format).
    pub fn reload_banned_peers_legacy(&mut self, peer_ids: &[String]) {
        let bans: Vec<PersistedBan> = peer_ids
            .iter()
            .map(|peer_id| PersistedBan {
                peer_id: peer_id.clone(),
                expires_unix: unix_now_secs().saturating_add(BAN_DURATION.as_secs()),
            })
            .collect();
        self.reload_banned_peers(&bans);
    }
}

/// Durable ban record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedBan {
    pub peer_id: String,
    /// Unix timestamp (seconds) when the ban expires.
    pub expires_unix: u64,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_peer_id() -> PeerId {
        PeerId::random()
    }
    #[test]
    fn vote_bucket_refills_although_general_bucket_is_touched() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        for _ in 0..10 {
            assert!(manager.check_rate_limit(&peer));
            assert!(manager.check_vote_rate_limit(&peer));
        }
        // Ten seconds pass; the general bucket is consumed on every message.
        let Some(back) = Instant::now().checked_sub(Duration::from_secs(10)) else {
            return;
        };
        if let Some(s) = manager.peers.get_mut(&peer) {
            s.aux_last_refill = back;
            s.rate_last_refill = back;
        }
        assert!(manager.check_rate_limit(&peer));
        assert!(manager.check_vote_rate_limit(&peer));
        assert!(manager.check_vote_rate_limit(&peer));
    }
    #[test]
    fn test_new_peer_has_zero_score() {
        let manager = PeerManager::new();
        let peer = test_peer_id();
        assert_eq!(manager.get_score(&peer), 0);
    }
    #[test]
    fn test_invalid_block_penalty() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        manager.report_invalid_block(&peer);
        assert_eq!(manager.get_score(&peer), INVALID_BLOCK_PENALTY);
    }
    #[test]
    fn test_good_behavior_reward() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        manager.report_good_behavior(&peer);
        assert_eq!(manager.get_score(&peer), GOOD_BEHAVIOR_REWARD);
    }
    #[test]
    fn test_peer_gets_banned() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        for _ in 0..11 {
            manager.report_invalid_block(&peer);
        }
        assert!(manager.is_banned(&peer));
        assert!(manager.get_score(&peer) <= BAN_THRESHOLD);
    }
    /// A block that does not join this chain demotes the sender but never bans.
    ///
    /// This is the devnet failure in one test. A block or a sync answer refused
    /// with `Previous hash mismatch` is what a peer on another branch of the
    /// same slot says, and the receiving node used to charge it as an invalid
    /// block:
    /// ten such answers (a minute of ordinary fork traffic) banned a validator
    /// for an hour, and the mesh lost the very node whose block it needed. The
    /// peer is still demoted, because it must sink below a peer that answers
    /// usefully, and the score must stop one point above the ban threshold
    /// however long the fork lasts. Both callers (the gossip block arm and the
    /// sync `Blocks` arm) use this one report.
    #[test]
    fn unjoined_blocks_demote_but_never_ban() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        let useful = test_peer_id();
        manager.report_good_behavior(&useful);
        for _ in 0..64 {
            manager.report_unjoined_block(&peer);
        }
        assert!(
            !manager.is_banned(&peer),
            "a fork answer must not ban a peer"
        );
        let score = manager.get_score(&peer);
        assert_eq!(
            score,
            MIN_SCORE + 1,
            "the stale-batch score must floor one point above the ban threshold"
        );
        assert!(score < manager.get_score(&useful));
        assert_eq!(
            manager.get_best_peers(2).last().copied(),
            Some(peer),
            "a peer that keeps answering with an unjoinable batch must be asked last"
        );
    }

    /// The canary for the test above: the same number of *invalid block*
    /// reports still bans, so the floor is a property of this one path and not
    /// of the score arithmetic in general.
    #[test]
    fn unjoined_block_floor_is_load_bearing() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        for _ in 0..64 {
            manager.report_invalid_block(&peer);
        }
        assert!(manager.is_banned(&peer));
    }

    #[test]
    fn test_unban_peer() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        manager.ban_peer(&peer);
        assert!(manager.is_banned(&peer));
        manager.unban_peer(&peer);
        assert!(!manager.is_banned(&peer));
        assert_eq!(manager.get_score(&peer), 0);
    }
    #[test]
    fn test_score_capped_at_max() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        for _ in 0..200 {
            manager.report_good_behavior(&peer);
        }
        assert_eq!(manager.get_score(&peer), MAX_SCORE);
    }

    /// Reload uses absolute expiry, not a fresh full `BAN_DURATION`.
    #[test]
    fn ban_reload_preserves_remaining() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        // Simulate a ban that expires in 60s (not a full hour).
        let expires = unix_now_secs() + 60;
        manager.reload_banned_peers(&[PersistedBan {
            peer_id: peer.to_base58(),
            expires_unix: expires,
        }]);
        assert!(manager.is_banned(&peer));
        let remaining = manager
            .get_peer_info(&peer)
            .and_then(super::PeerScore::ban_remaining)
            .expect("remaining ban");
        // Allow a few seconds of slack for test runtime.
        assert!(
            remaining.as_secs() <= 60 && remaining.as_secs() >= 55,
            "remaining should be ~60s, got {remaining:?}"
        );
        // Persisted snapshot must carry the same absolute expiry.
        let persisted = manager.get_persisted_banned_peers();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].expires_unix, expires);
    }

    /// Already-expired absolute timestamps are not re-banned.
    #[test]
    fn expired_ban_not_reloaded() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        manager.reload_banned_peers(&[PersistedBan {
            peer_id: peer.to_base58(),
            expires_unix: unix_now_secs().saturating_sub(10),
        }]);
        assert!(!manager.is_banned(&peer));
        assert!(manager.get_persisted_banned_peers().is_empty());
    }

    /// `SecurityConfig.peer_rate_limit_per_minute` wires into refill rate.
    #[test]
    fn peer_rate_limit_security_profile() {
        use crate::core::chain_config::Network;

        let mut manager = PeerManager::new();
        let mainnet = Network::Mainnet.security_config();
        manager.apply_security_config(mainnet);
        // 120/min => 2.0 tokens/sec
        assert!((manager.msg_refill_rate() - 2.0).abs() < f64::EPSILON);
        assert_eq!(mainnet.max_peers, 100);
        assert_eq!(manager.max_peers_per_subnet(), 4);
        assert_eq!(mainnet.rpc_rate_limit_per_minute, 300);
        assert!(mainnet.rpc_auth_required);
        assert!(!mainnet.mdns_enabled);

        let mut dev = PeerManager::new();
        dev.apply_security_config(Network::Devnet.security_config());
        // 1000/min => ~16.666 tokens/sec
        assert!((dev.msg_refill_rate() - (1000.0 / 60.0)).abs() < 1e-9);
        assert_eq!(dev.max_peers_per_subnet(), 8);
    }

    /// Tracked peer map has a hard ceiling (memory `DoS` guard).
    ///
    /// The ceiling is on the map size, not on admissions: a new peer is
    /// admitted by reclaiming a spent record, and refused when every record
    /// is unspent. Either way the map never exceeds the ceiling.
    #[test]
    fn peer_manager_tracked_peer_ceiling() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 8;

        // Fill with 8 penalised peers: unspent records nothing may reclaim.
        for i in 0..8u8 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer = keypair.public().to_peer_id();
            manager.report_invalid_tx(&peer);
            assert!(
                manager.get_score(&peer) < 0,
                "penalised peers must be tracked (i={i})"
            );
        }
        assert_eq!(manager.tracked_peer_count(), 8);

        let overflow = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(
            !manager.check_rate_limit(&overflow),
            "9th distinct peer must be rejected while every record is unspent"
        );
        assert_eq!(manager.tracked_peer_count(), 8);

        // Spent records are reclaimed for the newcomer; the ceiling holds.
        let mut spent = PeerManager::new();
        spent.max_tracked_peers = 8;
        for _ in 0..8 {
            assert!(spent.check_rate_limit(&test_peer_id()));
        }
        assert!(spent.check_rate_limit(&overflow));
        assert!(
            spent.tracked_peer_count() <= 8,
            "the ceiling is never exceeded"
        );
        assert!(spent.peers.contains_key(&overflow));
    }

    /// A full table of unprunable records is scanned once, not on
    /// every message from an unknown peer; the back-off lifts when a scan can
    /// succeed again.
    #[test]
    fn a_full_unprunable_table_is_not_rescanned_on_every_message() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;
        for _ in 0..4 {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            manager.report_invalid_tx(&peer);
        }
        let stranger = test_peer_id();
        assert!(!manager.check_rate_limit(&stranger));
        assert!(
            manager.last_empty_prune.is_some(),
            "the empty scan is remembered"
        );
        assert!(!manager.check_rate_limit(&stranger));
        assert_eq!(manager.tracked_peer_count(), 4);
    }

    /// Burst exhaustion then rejection (token bucket).
    #[test]
    fn peer_rate_limit_burst_exhaustion() {
        let mut manager = PeerManager::new();
        // Near-zero refill so burst cannot recover mid-test.
        manager.msg_refill_rate = 0.0;
        let peer = test_peer_id();

        let mut allowed = 0u32;
        for _ in 0..50 {
            if manager.check_rate_limit(&peer) {
                allowed += 1;
            }
        }
        // Default burst is MAX_MSG_BURST = 20.
        assert_eq!(allowed, MAX_MSG_BURST as u32);
        assert!(!manager.check_rate_limit(&peer));
    }

    /// Rate-limit exhaustion uses its own penalty category,
    /// Not the oversized-message category. Magnitude stays calibrated equal to
    /// The old value; the separation prevents audit/telemetry misclassification.
    #[test]
    fn rate_limit_exhaustion_uses_dedicated_penalty() {
        let mut manager = PeerManager::new();
        manager.msg_refill_rate = 0.0;
        let peer = test_peer_id();
        for _ in 0..MAX_MSG_BURST as u32 {
            assert!(manager.check_rate_limit(&peer));
        }
        let before = manager.get_score(&peer);
        assert!(!manager.check_rate_limit(&peer));
        assert_eq!(manager.get_score(&peer), before + RATE_LIMIT_PENALTY);
        assert_eq!(RATE_LIMIT_PENALTY, OVERSIZED_MESSAGE_PENALTY);
    }

    #[test]
    fn repeated_rate_limit_exhaustion_bans_peer() {
        let mut manager = PeerManager::new();
        manager.msg_refill_rate = 0.0;
        let peer = test_peer_id();
        for _ in 0..MAX_MSG_BURST as u32 {
            assert!(manager.check_rate_limit(&peer));
        }
        for _ in 0..40 {
            let _ = manager.check_rate_limit(&peer);
        }
        assert!(manager.is_banned(&peer));
        assert!(manager.get_score(&peer) <= BAN_THRESHOLD);
        assert!(manager
            .get_peer_info(&peer)
            .and_then(|score| score.ban_expires_unix)
            .is_some());
    }

    #[test]
    fn relayed_rate_limit_exhaustion_throttles_without_banning_relayer() {
        let mut manager = PeerManager::new();
        manager.msg_refill_rate = 0.0;
        let relayer = test_peer_id();
        for _ in 0..MAX_MSG_BURST as u32 {
            assert!(manager.check_rate_limit_from(&relayer, false));
        }
        for _ in 0..100 {
            assert!(!manager.check_rate_limit_from(&relayer, false));
        }
        assert!(
            !manager.is_banned(&relayer),
            "honest gossipsub relayer must be throttled, never auto-banned, on third-party bursts"
        );
        assert_eq!(manager.get_score(&relayer), MIN_SCORE.saturating_add(1));
    }

    /// Eclipse protection - /24 subnet connection bound.
    #[test]
    fn eclipse_subnet_bound_rejects_fifth_peer() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);
        let subnet: [u8; 3] = [10, 0, 0];
        for _ in 0..4 {
            assert!(pm.can_admit_subnet(Some(subnet)));
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            pm.note_connected(peer, Some(subnet));
        }
        assert_eq!(pm.subnet_connection_count(subnet), 4);
        assert!(
            !pm.can_admit_subnet(Some(subnet)),
            "5th peer on same /24 must be rejected"
        );
        // Different subnet still ok
        assert!(pm.can_admit_subnet(Some([10u8, 0, 1])));
    }

    #[test]
    fn eclipse_disconnect_frees_subnet_slot() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(1);
        let subnet: [u8; 3] = [192, 168, 1];
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_connected(peer, Some(subnet)));
        assert!(!pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_disconnected(&peer));
        assert!(pm.can_admit_subnet(Some(subnet)));
    }

    /// The bound used to cover IPv4 only: an IPv6 peer was `None`, and `None`
    /// is admitted without a bound. A host with a `/64` then had as many
    /// admission slots as it had addresses.
    ///
    /// Canary: restore the IPv4-only key and `ipv6` is unbucketed, so the
    /// second peer is admitted.
    #[test]
    fn eclipse_bound_covers_ipv6_peers() {
        use std::net::{IpAddr, Ipv6Addr};
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(1);
        let first = SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1)));
        let same_site = SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 1, 2, 0xffff, 0, 0, 2,
        )));
        let other_site =
            SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1)));
        assert_eq!(first, same_site, "one /64 is one bucket");
        assert_ne!(first, other_site, "a different /64 is a different bucket");
        assert!(pm.can_admit_subnet(Some(first)));
        assert!(pm.note_connected(test_peer_id(), Some(first)));
        assert!(
            !pm.can_admit_subnet(Some(same_site)),
            "a second peer from the same IPv6 /64 must be refused"
        );
        assert!(
            pm.can_admit_subnet(Some(other_site)),
            "a peer from another /64 must still be admitted"
        );
        assert_eq!(pm.subnet_connection_count(first), 1);
    }

    /// The mapped form of an IPv4 address shares the IPv4 `/24` budget, so a
    /// dual-stack host cannot count the same peer twice.
    #[test]
    fn ipv4_mapped_address_shares_the_ipv4_budget() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(1);
        let plain = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
        let mapped = SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xc633, 0x6404,
        )));
        assert_eq!(plain, mapped, "::ffff:198.51.100.4 is 198.51.100.0/24");
        assert!(pm.note_connected(test_peer_id(), Some(plain)));
        assert!(!pm.can_admit_subnet(Some(mapped)));
    }

    /// The family tag keeps an IPv4 `/24` and an IPv6 `/64` that share their
    /// leading bytes in separate buckets.
    #[test]
    fn subnet_keys_do_not_collapse_across_families() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let v4 = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(4, 0, 0, 1)));
        let v6 = SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::new(0x0400, 0, 0, 0, 0, 0, 0, 1)));
        assert_ne!(v4, v6);
    }

    #[test]
    fn unaddressed_peers_cannot_bypass_the_eclipse_bound() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(1);
        let first = test_peer_id();
        assert!(pm.can_admit_subnet(None::<SubnetKey>));
        assert!(pm.note_connected(first, None::<SubnetKey>));
        assert!(!pm.can_admit_subnet(None::<SubnetKey>));
        assert!(pm.note_disconnected(&first));
        assert!(pm.can_admit_subnet(None::<SubnetKey>));

        pm.max_outbound_per_subnet = 1;
        let outbound = test_peer_id();
        assert!(pm.note_outbound_connected(outbound, None::<SubnetKey>));
        assert!(!pm.can_admit_outbound_subnet(None::<SubnetKey>));
        assert!(pm.note_outbound_disconnected(&outbound));
        assert!(pm.can_admit_outbound_subnet(None::<SubnetKey>));
    }

    /// H5.1 follow-up: duplicate libp2p connection events for one peer are
    /// Idempotent, and duplicate disconnects do not underflow accounting.
    #[test]
    fn eclipse_peer_accounting_is_idempotent() {
        let mut pm = PeerManager::new();
        let subnet: [u8; 3] = [172, 18, 0];
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();

        assert!(pm.note_connected(peer, Some(subnet)));
        assert!(!pm.note_connected(peer, Some(subnet)));
        assert_eq!(pm.subnet_connection_count(subnet), 1);

        assert!(pm.note_disconnected(&peer));
        assert!(!pm.note_disconnected(&peer));
        assert_eq!(pm.subnet_connection_count(subnet), 0);
    }

    /// Chaos: network partition isolates peer groups by subnet.
    /// Two groups on different /24 subnets cannot communicate through the
    /// `PeerManager`'s subnet-bound admission.
    #[test]
    fn chaos_network_partition_isolates_groups() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);

        let subnet_a: [u8; 3] = [10, 0, 0];
        let subnet_b: [u8; 3] = [10, 0, 1];

        // Fill subnet A
        for _ in 0..4 {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            assert!(pm.note_connected(peer, Some(subnet_a)));
        }
        // Subnet A is full - partition enforced
        assert!(!pm.can_admit_subnet(Some(subnet_a)));
        // Subnet B is still available - groups are isolated
        assert!(pm.can_admit_subnet(Some(subnet_b)));
    }

    /// Chaos: byzantine peer sending invalid messages is rejected.
    #[test]
    fn chaos_byzantine_block_rejected() {
        let mut pm = PeerManager::new();
        pm.msg_refill_rate = 0.0;
        let peer = test_peer_id();
        pm.note_connected(peer, None::<SubnetKey>);

        // Byzantine: peer sends oversized message repeatedly
        // First MAX_MSG_BURST calls consume all tokens (no penalty)
        for _ in 0..MAX_MSG_BURST as u32 {
            let _ = pm.check_rate_limit(&peer);
        }
        // Additional calls trigger rate-limit penalties
        for _ in 0..40 {
            let _ = pm.check_rate_limit(&peer);
        }
        // Peer should be banned after enough violations
        assert!(pm.is_banned(&peer), "byzantine peer must be banned");
    }

    /// Chaos: eclipse single-peer isolation - a peer that can only
    /// Connect to one subnet is isolated from the broader network.
    #[test]
    fn chaos_eclipse_single_peer_isolation() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);

        let subnet: [u8; 3] = [192, 168, 1];
        // Fill the subnet completely
        for _ in 0..4 {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            assert!(pm.note_connected(peer, Some(subnet)));
        }
        // New peer on same subnet is rejected - eclipse isolation
        assert!(!pm.can_admit_subnet(Some(subnet)));
        // New peer on different subnet is accepted
        assert!(pm.can_admit_subnet(Some([192u8, 168, 2])));
    }

    /// Chaos: sybil attack from same /24 subnet is rejected.
    #[test]
    fn chaos_sybil_subnet_bound_rejects_excess() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);

        let subnet: [u8; 3] = [172, 16, 0];
        // Sybil: 4 peers from same subnet
        for _ in 0..4 {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            assert!(pm.note_connected(peer, Some(subnet)));
        }
        // 5th peer from same subnet rejected
        assert_eq!(pm.subnet_connection_count(subnet), 4);
        assert!(!pm.can_admit_subnet(Some(subnet)));
    }

    /// Chaos: ban TTL allows reconnect after expiry.
    #[test]
    fn chaos_ban_ttl_allows_reconnect_after_expiry() {
        let mut pm = PeerManager::new();
        pm.msg_refill_rate = 0.0;
        let peer = test_peer_id();

        // Ban the peer
        for _ in 0..MAX_MSG_BURST as u32 {
            let _ = pm.check_rate_limit(&peer);
        }
        for _ in 0..40 {
            let _ = pm.check_rate_limit(&peer);
        }
        assert!(pm.is_banned(&peer));

        // Simulate ban expiry by setting ban_expires_unix to past
        pm.set_ban_expiry_for_test(&peer, Some(0));
        assert!(!pm.is_banned(&peer));
    }

    /// Chaos: reputation fuzz decay - peer score decreases
    /// With repeated violations.
    #[test]
    fn chaos_reputation_fuzz_decay() {
        let mut pm = PeerManager::new();
        pm.msg_refill_rate = 0.0;
        let peer = test_peer_id();
        pm.note_connected(peer, None::<SubnetKey>);

        let initial_score = pm.get_score(&peer);
        // Repeated violations
        for _ in 0..100 {
            let _ = pm.check_rate_limit(&peer);
        }
        let final_score = pm.get_score(&peer);
        assert!(
            final_score < initial_score,
            "score must decay: initial={initial_score}, final={final_score}"
        );
        assert!(
            final_score <= BAN_THRESHOLD,
            "score must reach ban threshold after 100 violations"
        );
    }

    /// Reputation invariant: score must stay within
    /// `[MIN_SCORE, MAX_SCORE]` under any penalty sequence. The
    /// Invalid-block / invalid-tx / oversized-message penalty paths clamp to
    /// `MIN_SCORE` (like `report_bad_behavior`) so `get_score` never
    /// Undershoots. Without the clamp these paths could return e.g. -105.
    #[test]
    fn reputation_score_clamped_under_repeated_penalties() {
        let mut pm = PeerManager::new();

        let pb = test_peer_id();
        for _ in 0..50 {
            pm.report_invalid_block(&pb);
        }
        assert!(
            (MIN_SCORE..=MAX_SCORE).contains(&pm.get_score(&pb)),
            "invalid-block penalty must clamp to MIN_SCORE, got {}",
            pm.get_score(&pb)
        );

        let pt = test_peer_id();
        for _ in 0..50 {
            pm.report_invalid_tx(&pt);
        }
        assert!(
            (MIN_SCORE..=MAX_SCORE).contains(&pm.get_score(&pt)),
            "invalid-tx penalty must clamp to MIN_SCORE, got {}",
            pm.get_score(&pt)
        );

        let po = test_peer_id();
        for _ in 0..50 {
            pm.report_oversized_message(&po);
        }
        assert!(
            (MIN_SCORE..=MAX_SCORE).contains(&pm.get_score(&po)),
            "oversized-message penalty must clamp to MIN_SCORE, got {}",
            pm.get_score(&po)
        );
    }
    /// Outbound subnet diversity rejects excess connections.
    #[test]
    fn outbound_subnet_diversity_rejects_excess() {
        let mut pm = PeerManager::new();
        pm.max_outbound_per_subnet = 2;
        let subnet: [u8; 3] = [10u8, 0, 1];
        // First 2 outbound from same subnet: OK.
        let p1 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let p2 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let p3 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(pm.note_outbound_connected(p1, Some(subnet)));
        assert!(pm.note_outbound_connected(p2, Some(subnet)));
        // 3rd outbound from same subnet: REJECT.
        assert!(!pm.note_outbound_connected(p3, Some(subnet)));
        // Disconnect p1 → slot freed → p3 OK.
        assert!(pm.note_outbound_disconnected(&p1));
        assert!(pm.note_outbound_connected(p3, Some(subnet)));
        // Max_outbound_per_subnet = 0 → unlimited.
        pm.max_outbound_per_subnet = 0;
        let p4 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(pm.can_admit_outbound_subnet(Some(subnet)));
        // Max_outbound_per_subnet = 0 means unlimited, so the fourth peer in the
        // Same subnet must actually be admitted, not merely reported admissible.
        assert!(pm.note_outbound_connected(p4, Some(subnet)));
    }

    /// Every entry point that creates a score respects `max_tracked_peers`.
    ///
    /// The ceiling used to be written at one of thirteen call sites. The
    /// twelve others, reachable with one malformed message each, grew the map
    /// without limit. This walks every public method that can create an entry
    /// and asserts the map never exceeds the ceiling.
    #[test]
    fn h5_score_map_ceiling_holds_on_every_entry_point() {
        let ceiling = 8usize;

        // Each closure drives one entry point with a fresh peer.
        type Drive = (&'static str, fn(&mut PeerManager, &PeerId));
        let paths: &[Drive] = &[
            ("check_rate_limit", |m, p| {
                let _ = m.check_rate_limit(p);
            }),
            ("check_vote_rate_limit", |m, p| {
                let _ = m.check_vote_rate_limit(p);
            }),
            ("check_blob_rate_limit", |m, p| {
                let _ = m.check_blob_rate_limit(p);
            }),
            ("report_invalid_block", |m, p| m.report_invalid_block(p)),
            ("report_invalid_tx", |m, p| m.report_invalid_tx(p)),
            ("report_oversized_message", |m, p| {
                m.report_oversized_message(p)
            }),
            ("report_bad_behavior", |m, p| m.report_bad_behavior(p)),
            ("report_good_behavior", |m, p| m.report_good_behavior(p)),
            ("report_unanswered_request", |m, p| {
                m.report_unanswered_request(p)
            }),
            ("report_unjoined_block", |m, p| m.report_unjoined_block(p)),
            ("report_slow_sync", |m, p| m.report_slow_sync(p)),
            ("report_invalid_handshake", |m, p| {
                m.report_invalid_handshake(p)
            }),
            ("ban_peer", |m, p| m.ban_peer(p)),
            ("set_handshaked", |m, p| m.set_handshaked(p, true)),
        ];

        for (name, drive) in paths {
            let mut manager = PeerManager::new();
            manager.max_tracked_peers = ceiling;
            for _ in 0..(ceiling * 8) {
                let peer = test_peer_id();
                drive(&mut manager, &peer);
            }
            assert!(
                manager.peers.len() <= ceiling,
                "{name} grew the score map to {} entries, ceiling is {ceiling}",
                manager.peers.len()
            );
        }
    }

    /// The canary for the test above: with the ceiling removed, an unguarded
    /// path must actually overflow. A bound that holds because nothing pushes
    /// on it proves nothing.
    #[test]
    fn h5_score_map_ceiling_is_load_bearing() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = usize::MAX;
        for _ in 0..64 {
            manager.report_invalid_handshake(&test_peer_id());
        }
        assert_eq!(
            manager.peers.len(),
            64,
            "without a ceiling the map must grow once per peer, or the test above is vacuous"
        );
    }

    /// Refusing at the ceiling must not evict an existing entry.
    ///
    /// Eviction would let an attacker flush a real peer's ban by minting
    /// peer ids, turning a memory bound into a ban-clearing primitive.
    #[test]
    fn h5_ceiling_refuses_rather_than_evicting_a_ban() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;

        let victim = test_peer_id();
        manager.ban_peer(&victim);
        assert!(manager.is_banned(&victim), "victim must start banned");

        // Fill the map and keep pushing well past the ceiling.
        for _ in 0..256 {
            manager.report_invalid_handshake(&test_peer_id());
        }

        assert!(
            manager.is_banned(&victim),
            "a ban was evicted to make room, which is a ban-clearing primitive"
        );
        assert!(manager.peers.len() <= 4);
    }

    /// The ceiling is a memory bound, not a life sentence.
    ///
    /// A record whose ban has expired and on which no penalty is left must be
    /// reclaimable. Without that, ten thousand minted peer ids - and a peer id
    /// is a public key hash, free to invent - fill the table once, after which
    /// `check_rate_limit` refuses every peer the node has never seen, for the
    /// rest of its uptime. Nothing short of a restart recovers it.
    #[test]
    fn h5_the_score_map_recovers_after_bans_expire() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 3;

        let stale: Vec<_> = (0..3)
            .map(|_| {
                let p = test_peer_id();
                manager.ban_peer(&p);
                p
            })
            .collect();
        assert_eq!(manager.tracked_peer_count(), 3, "table must be full");
        assert_eq!(manager.get_score(&stale[0]), 0);

        // The bans run out and no penalty is left on any of the records.
        // `checked_sub` stands in for an expired deadline: when the runner
        // has not been up long enough to represent "one second ago", an
        // absent deadline reads exactly like an expired one.
        let past = Instant::now().checked_sub(Duration::from_secs(1));
        for p in &stale {
            let entry = manager.peers.get_mut(p).expect("record");
            entry.banned_until = past;
            entry.ban_expires_unix = Some(0);
            entry.score = 0;
        }
        assert!(!manager.is_banned(&stale[0]), "the ban must have expired");

        let fresh = test_peer_id();
        assert!(
            manager.check_rate_limit(&fresh),
            "expired, penalty-free records were never reclaimed: a full table refuses every new peer for the rest of the uptime"
        );
    }

    /// A table filled by records that never carried a ban is reclaimed too:
    /// one rate-limited message per minted id used to leave a score-0 record
    /// that no predicate could drop, and the node refused every new peer for
    /// the rest of its uptime.
    #[test]
    fn h5_never_banned_score_zero_records_are_reclaimed() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 3;
        for _ in 0..3 {
            assert!(manager.check_rate_limit(&test_peer_id()));
        }
        assert_eq!(manager.tracked_peer_count(), 3, "table must be full");

        let fresh = test_peer_id();
        assert!(
            manager.check_rate_limit(&fresh),
            "score-0 records without a ban must be reclaimable"
        );
        assert!(manager.peers.contains_key(&fresh));
    }

    /// A connected peer keeps its record through a reclaim, whatever its
    /// score: a live session must not lose its handshake to strangers.
    #[test]
    fn h5_reclaim_keeps_connected_peers() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 2;
        let live = test_peer_id();
        assert!(manager.note_connected(live, None::<SubnetKey>));
        manager.set_handshaked(&live, true);
        assert!(manager.check_rate_limit(&test_peer_id()));
        assert_eq!(manager.tracked_peer_count(), 2);

        assert!(manager.check_rate_limit(&test_peer_id()));
        assert!(
            manager.is_handshaked(&live),
            "the connected peer's record was reclaimed"
        );
    }

    /// Reclaiming spent records must not become a way to clear a live ban.
    ///
    /// The two records an attacker would most like gone are exactly the two
    /// the reclaim leaves alone: a running ban, and a penalty still on the
    /// score. Minted peer ids always land in the second class, because they
    /// arrive through a `report_*` path.
    #[test]
    fn h5_reclaim_never_touches_a_running_ban_or_a_live_penalty() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 2;

        let banned = test_peer_id();
        manager.ban_peer(&banned);
        let penalised = test_peer_id();
        manager.report_invalid_block(&penalised);
        assert!(manager.is_banned(&banned));
        assert!(manager.get_score(&penalised) < 0);

        // The table is full; force the reclaim the same way a new peer would.
        assert_eq!(manager.prune_spent_records(), 0, "nothing is spent yet");
        assert!(manager.is_banned(&banned), "a running ban was reclaimed");
        assert!(
            manager.get_score(&penalised) < 0,
            "a live penalty was reclaimed"
        );

        let fresh = test_peer_id();
        assert!(
            !manager.check_rate_limit(&fresh),
            "a full table of unspent records still refuses new entries"
        );
        assert!(manager.is_banned(&banned), "refusal must not evict a ban");
    }

    /// A peer already tracked keeps working after the map fills.
    #[test]
    fn h5_tracked_peer_still_scored_when_map_is_full() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;

        let known = test_peer_id();
        manager.report_invalid_tx(&known);
        let before = manager.get_score(&known);

        for _ in 0..64 {
            manager.report_invalid_handshake(&test_peer_id());
        }

        manager.report_invalid_tx(&known);
        assert_eq!(
            manager.get_score(&known),
            before + INVALID_TX_PENALTY,
            "an already-tracked peer must keep accruing penalties when the map is full"
        );
    }

    /// Minted garbage must not fill the ceiling forever.
    ///
    /// An attacker mints peer ids for free and each malformed handshake
    /// leaves an unbanned negative record. The old predicate kept every
    /// negative record for the rest of the node's uptime, so one burst
    /// filled `max_tracked_peers` and every peer the node had never seen
    /// was refused - the denial of service the bound exists to prevent.
    /// Stale unbanned negative records expire by `last_seen`; bans and
    /// fresh penalties do not.
    #[test]
    fn stale_unbanned_negative_records_are_reclaimed() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;

        // Fill the table with minted ids whose misbehaviour is a whole
        // ban-length in the past.
        for _ in 0..4 {
            let id = test_peer_id();
            manager.report_invalid_handshake(&id);
            manager.peers.get_mut(&id).unwrap().last_seen =
                Instant::now().checked_sub(NEGATIVE_RECORD_TTL + Duration::from_secs(1));
        }
        assert_eq!(manager.peers.len(), manager.max_tracked_peers);

        // The stale garbage goes; nothing else exists yet.
        assert_eq!(
            manager.prune_spent_records(),
            4,
            "the stale minted records are reclaimed"
        );

        // A fresh negative record and a running ban survive the reclaim.
        let fresh = test_peer_id();
        manager.report_invalid_handshake(&fresh);
        let banned = test_peer_id();
        manager.ban_peer(&banned);
        assert_eq!(manager.prune_spent_records(), 0, "fresh records stay");
        assert!(
            manager.get_score(&fresh) < 0,
            "a fresh penalty survives the reclaim"
        );
        assert!(
            manager.is_banned(&banned),
            "a running ban survives the reclaim"
        );

        // Fill to the ceiling again with stale garbage, then show the
        // reclaim path inside `get_or_create` admits an unseen peer.
        while manager.peers.len() < manager.max_tracked_peers {
            let id = test_peer_id();
            manager.report_invalid_handshake(&id);
            manager.peers.get_mut(&id).unwrap().last_seen =
                Instant::now().checked_sub(NEGATIVE_RECORD_TTL + Duration::from_secs(1));
        }
        let newcomer = test_peer_id();
        assert!(
            manager.check_rate_limit(&newcomer),
            "the table admits a new peer once the stale garbage is reclaimed"
        );
    }

    /// A connected peer must be able to handshake when the table is full of
    /// fresh penalty records minted by short-lived ids.
    #[test]
    fn connected_peer_handshakes_when_table_is_full_of_fresh_penalties() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;
        let banned = test_peer_id();
        manager.ban_peer(&banned);
        for _ in 0..3 {
            manager.report_invalid_handshake(&test_peer_id());
        }
        assert_eq!(manager.tracked_peer_count(), 4);

        let honest = test_peer_id();
        assert!(manager.note_connected(honest, None::<SubnetKey>));
        manager.set_handshaked(&honest, true);
        assert!(manager.is_handshaked(&honest));
        assert!(manager.is_banned(&banned), "a running ban must survive");
    }

    #[test]
    fn reloading_a_long_ban_list_respects_the_table_ceiling() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;
        let expires_unix = unix_now_secs() + 600;
        let bans: Vec<PersistedBan> = (0..16)
            .map(|_| PersistedBan {
                peer_id: PeerId::random().to_base58(),
                expires_unix,
            })
            .collect();
        manager.reload_banned_peers(&bans);
        assert!(manager.peers.len() <= 4);
        assert!(manager.get_banned_peers().len() <= 4);
    }

    #[test]
    fn connected_peer_handshakes_when_table_is_saturated_with_running_bans() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 4;
        let now = unix_now_secs();
        let soonest_peer = test_peer_id();
        let mut others = Vec::new();
        for _ in 0..3 {
            let p = test_peer_id();
            others.push(p);
        }
        let bans = vec![
            PersistedBan {
                peer_id: soonest_peer.to_base58(),
                expires_unix: now + 60,
            },
            PersistedBan {
                peer_id: others[0].to_base58(),
                expires_unix: now + 300,
            },
            PersistedBan {
                peer_id: others[1].to_base58(),
                expires_unix: now + 600,
            },
            PersistedBan {
                peer_id: others[2].to_base58(),
                expires_unix: now + 900,
            },
        ];
        manager.reload_banned_peers(&bans);
        assert_eq!(manager.tracked_peer_count(), 4);

        let honest = test_peer_id();
        assert!(manager.note_connected(honest, None::<SubnetKey>));
        assert!(
            manager.check_rate_limit(&honest),
            "connected peer must still be admitted when every unconnected slot holds a ban"
        );
        manager.set_handshaked(&honest, true);
        assert!(manager.is_handshaked(&honest));
        assert!(
            manager.is_banned(&soonest_peer),
            "admitting a connected peer must never evict a live ban"
        );
        for kept in &others {
            assert!(manager.is_banned(kept), "longer-lived bans remain enforced");
        }
        assert!(manager.note_disconnected(&honest));
        assert_eq!(
            manager.tracked_peer_count(),
            4,
            "disconnecting sheds session headroom back to max_tracked_peers while keeping all bans"
        );
    }

    #[test]
    fn duplicate_connection_event_for_admitted_peer_is_not_rejected_at_subnet_cap() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);
        let subnet: [u8; 3] = [127, 0, 0];
        let mut admitted = Vec::new();
        for _ in 0..4 {
            let p = test_peer_id();
            assert!(pm.is_connected(&p) || pm.can_admit_subnet(Some(subnet)));
            assert!(pm.note_connected(p, Some(subnet)));
            admitted.push(p);
        }
        // A 5th distinct peer on the same /24 is still refused.
        let stranger = test_peer_id();
        assert!(!(pm.is_connected(&stranger) || pm.can_admit_subnet(Some(subnet))));
        // A simultaneous reverse-dial or second transport for an already-admitted peer
        // stays admitted without incrementing the /24 count.
        assert!(pm.is_connected(&admitted[0]) || pm.can_admit_subnet(Some(subnet)));
        assert!(!pm.note_connected(admitted[0], Some(subnet)));
        assert_eq!(pm.subnet_connection_count(subnet), 4);
    }

    #[test]
    fn simultaneous_dial_to_same_peer_is_recognized_as_already_connected() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        let lo: [u8; 3] = [127, 0, 0];
        assert!(!manager.is_connected(&peer));
        assert!(manager.note_connected(peer, Some(lo)));
        assert!(manager.is_connected(&peer));
        assert!(!manager.note_connected(peer, Some(lo)));
        assert!(manager.is_connected(&peer));
        assert!(manager.note_disconnected(&peer));
        assert!(!manager.is_connected(&peer));
    }

    #[test]
    fn ipv6_slash64_and_ipv4_mapped_share_eclipse_ceiling() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(2);
        let v6_a: libp2p::Multiaddr = "/ip6/2001:db8:cafe:1::1/tcp/30333".parse().unwrap();
        let v6_b: libp2p::Multiaddr = "/ip6/2001:db8:cafe:1:ffff::9/tcp/30333".parse().unwrap();
        let v6_other: libp2p::Multiaddr = "/ip6/2001:db8:beef:1::1/tcp/30333".parse().unwrap();
        let key_a = crate::network::node::subnet_bucket(&v6_a);
        let key_b = crate::network::node::subnet_bucket(&v6_b);
        assert_eq!(key_a, key_b, "two hosts inside the same /64 share one key");
        assert!(pm.note_connected(test_peer_id(), key_a));
        assert!(pm.note_connected(test_peer_id(), key_b));
        assert!(
            !pm.can_admit_subnet(key_a),
            "third IPv6 peer from the same /64 must be rejected"
        );
        assert!(
            pm.can_admit_subnet(crate::network::node::subnet_bucket(&v6_other)),
            "distinct IPv6 /64 remains admissible"
        );

        let v4: libp2p::Multiaddr = "/ip4/203.0.113.7/tcp/30333".parse().unwrap();
        let v4_mapped: libp2p::Multiaddr = "/ip6/::ffff:203.0.113.99/tcp/30333".parse().unwrap();
        assert_eq!(
            crate::network::node::subnet_bucket(&v4),
            crate::network::node::subnet_bucket(&v4_mapped),
            "IPv4-mapped IPv6 must share the IPv4 /24 bucket"
        );
        let v6_lo: libp2p::Multiaddr = "/ip6/::1/tcp/30333".parse().unwrap();
        assert_eq!(crate::network::node::subnet_bucket(&v6_lo), None);
    }

    #[test]
    fn relayed_vote_and_blob_rate_exhaustion_demotes_without_banning_relayer() {
        let mut pm = PeerManager::new();
        let relay = test_peer_id();
        let flooder = test_peer_id();

        for _ in 0..300 {
            let _ = pm.check_vote_rate_limit_from(&relay, false);
            let _ = pm.check_blob_rate_limit_from(&relay, false);
        }
        assert!(
            !pm.is_banned(&relay),
            "honest relayer must not be auto-banned when forwarding flooded votes/blobs"
        );
        assert_eq!(pm.get_score(&relay), MIN_SCORE + 1);

        for _ in 0..300 {
            let _ = pm.check_vote_rate_limit_from(&flooder, true);
        }
        assert!(
            pm.is_banned(&flooder),
            "direct author flooding vote bucket must still be banned"
        );
    }

    #[test]
    fn unanswered_sync_requests_set_a_peer_aside_and_never_ban_it() {
        let mut pm = PeerManager::new();
        let quiet = test_peer_id();
        let flaky = test_peer_id();
        let staller = test_peer_id();

        // Below the run of strikes nothing happens but the score.
        pm.report_unanswered_request(&quiet);
        pm.report_unanswered_request(&quiet);
        assert!(!pm.is_sync_resting(&quiet));
        // Good behaviour that is not sync data (a handshake, gossip) does
        // not clear the strikes.
        pm.report_good_behavior(&quiet);
        pm.report_unanswered_request(&quiet);
        pm.report_unanswered_request(&quiet);
        assert!(
            pm.is_sync_resting(&quiet),
            "a run of unanswered sync requests sets the peer aside as a sync source"
        );
        assert!(
            !pm.is_banned(&quiet),
            "a peer that did not answer is not banned: its blocks and votes are still wanted"
        );

        // Delivered sync data resets the run.
        pm.report_unanswered_request(&flaky);
        pm.report_unanswered_request(&flaky);
        pm.report_sync_success(&flaky);
        pm.report_unanswered_request(&flaky);
        pm.report_unanswered_request(&flaky);
        assert!(!pm.is_sync_resting(&flaky));

        // A peer that keeps leaving whole runs unanswered across rests is
        // refusing sync data and eventually loses its connection slot via ban;
        // delivered sync data resets the rest streak before the cap.
        let mut rests = Vec::new();
        for run in 0..MAX_SYNC_REST_RUNS {
            for _ in 0..MAX_UNANSWERED_SYNC_STRIKES {
                pm.report_unanswered_request(&staller);
                pm.report_slow_sync(&staller);
            }
            let until = pm
                .get_peer_info(&staller)
                .and_then(|score| score.sync_rest_until)
                .expect("resting");
            rests.push(until.saturating_duration_since(Instant::now()));
            if run + 1 < MAX_SYNC_REST_RUNS {
                assert!(!pm.is_banned(&staller));
            }
        }
        assert!(
            pm.is_banned(&staller),
            "refusing sync across MAX_SYNC_REST_RUNS must ban to free the inbound slot"
        );
        assert!(pm.get_score(&staller) > BAN_THRESHOLD);
        assert!(rests
            .windows(2)
            .all(|pair| pair[0] <= pair[1] + Duration::from_secs(1)));
        assert!(rests[1] > rests[0] + SYNC_REST_BASE / 2);
        assert!(rests.last().copied().unwrap() <= BAN_DURATION);
        assert!(!pm.get_persisted_banned_peers().is_empty());

        // Sync data from a peer before the cap clears the rest and streak.
        let recovering = test_peer_id();
        for _ in 0..(MAX_SYNC_REST_RUNS - 1) {
            for _ in 0..MAX_UNANSWERED_SYNC_STRIKES {
                pm.report_unanswered_request(&recovering);
            }
        }
        assert!(!pm.is_banned(&recovering));
        pm.report_sync_success(&recovering);
        assert!(!pm.is_sync_resting(&recovering));
        assert_eq!(
            pm.get_peer_info(&recovering).map(|score| score.sync_rests),
            Some(0)
        );
    }

    #[test]
    fn agg_frame_budget_charges_proportional_to_object_count() {
        let mut pm = PeerManager::new();
        let flooder = test_peer_id();
        // A 160-object frame costs max budget (10 tokens) and fits once.
        assert!(pm.charge_agg_frame(&flooder, 160));
        // A second immediate large frame exceeds the refilled budget and fails.
        assert!(!pm.charge_agg_frame(&flooder, 160));
    }

    #[test]
    fn agg_frame_budget_does_not_discount_frames_above_160_verification_units() {
        let mut pm = PeerManager::new();
        let flooder = test_peer_id();
        // 640 verification units (e.g. 320 claims + 320 segment attestations)
        // represent 40 tokens of ML-DSA-87 work at 16 units/token (20s at 2/s).
        assert!(pm.charge_agg_frame(&flooder, 640));
        // Simulate 6 seconds of refill (+12 tokens). With a 10-token clamp this
        // would already admit another 160-unit frame; without clamping, 30 tokens
        // of debt dropped to -18, so another frame must still be rejected.
        if let Some(score) = pm.peers.get_mut(&flooder) {
            score.aux_last_refill = Instant::now()
                .checked_sub(Duration::from_secs(6))
                .expect("6s back");
        }
        assert!(
            !pm.charge_agg_frame(&flooder, 160),
            "oversized frame must pay full proportional verification cooldown"
        );
        // After 25 seconds (+50 tokens from -30 -> capped at 20), budget recovers.
        if let Some(score) = pm.peers.get_mut(&flooder) {
            score.aux_last_refill = Instant::now()
                .checked_sub(Duration::from_secs(25))
                .expect("25s back");
        }
        assert!(pm.charge_agg_frame(&flooder, 160));
    }

    #[test]
    fn protected_sentry_shield_peers_resist_banning_subnet_caps_and_relay_floods() {
        let mut pm = PeerManager::new();
        pm.max_tracked_peers = 4;
        pm.set_max_peers_per_subnet(2);

        let sentry_a = test_peer_id();
        let sentry_b = test_peer_id();
        let sentry_c = test_peer_id();
        let public_a = test_peer_id();
        let public_b = test_peer_id();
        let public_c = test_peer_id();
        let subnet = [10u8, 42, 0];

        // Even if a shield peer was banned prior to shield installation or in a
        // persisted ban file, `set_protected_peers` and `reload_banned_peers`
        // keep it unbanned.
        pm.ban_peer(&sentry_a);
        assert!(pm.is_banned(&sentry_a));
        pm.set_protected_peers([sentry_a, sentry_b, sentry_c]);
        assert!(!pm.is_banned(&sentry_a));

        pm.reload_banned_peers(&[PersistedBan {
            peer_id: sentry_a.to_base58(),
            expires_unix: unix_now_secs() + 3600,
        }]);
        assert!(!pm.is_banned(&sentry_a));

        // Relayed invalid transactions/blocks or direct ban attempts must never
        // ban a configured sentry/validator shield peer or drive its score negative.
        for _ in 0..20 {
            pm.report_invalid_tx(&sentry_a);
            pm.report_invalid_block(&sentry_a);
            pm.report_oversized_message(&sentry_a);
            pm.report_bad_behavior(&sentry_a);
        }
        pm.ban_peer(&sentry_a);
        assert!(!pm.is_banned(&sentry_a));
        assert!(pm.get_score(&sentry_a) >= 0);

        // Multiplexed consensus traffic (100+ votes/messages/agg frames) over a
        // sentry link must never be dropped by single-peer rate limits.
        for _ in 0..250 {
            assert!(pm.check_rate_limit_from(&sentry_a, false));
            assert!(pm.check_vote_rate_limit_from(&sentry_a, false));
            assert!(pm.check_blob_rate_limit_from(&sentry_a, false));
            assert!(pm.charge_agg_frame_from(&sentry_a, false, 160));
        }

        // Three sentries in the same /24 subnet connect without consuming any
        // of the 2 public /24 subnet slots or `public_connected_count`.
        assert!(pm.note_connected(sentry_a, Some(subnet)));
        assert!(pm.note_connected(sentry_b, Some(subnet)));
        assert!(pm.note_connected(sentry_c, Some(subnet)));
        assert_eq!(pm.public_connected_count(), 0);
        assert_eq!(pm.subnet_connection_count(subnet), 0);

        // Two public peers in that same /24 still fit, and the third public peer hits the /24 cap.
        assert!(pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_connected(public_a, Some(subnet)));
        assert!(pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_connected(public_b, Some(subnet)));
        assert!(!pm.can_admit_subnet(Some(subnet)));
        assert!(!pm.is_connected(&public_c));
        assert_eq!(pm.public_connected_count(), 2);

        // Even when the tracked score map is full, an unseen protected peer is
        // still tracked and marked handshaked cleanly.
        pm.set_handshaked(&sentry_c, true);
        assert!(pm.is_handshaked(&sentry_c));
    }
}
