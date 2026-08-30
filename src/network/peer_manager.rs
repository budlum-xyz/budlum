use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;
pub const INVALID_BLOCK_PENALTY: i32 = -10;
pub const INVALID_TX_PENALTY: i32 = -5;
pub const OVERSIZED_MESSAGE_PENALTY: i32 = -3;
pub const RATE_LIMIT_PENALTY: i32 = -3;
pub const TIMEOUT_PENALTY: i32 = -15;
pub const SLOW_SYNC_PENALTY: i32 = -5;
pub const INVALID_HANDSHAKE_PENALTY: i32 = -20;
pub const GOOD_BEHAVIOR_REWARD: i32 = 1;
pub const BAN_THRESHOLD: i32 = -100;
pub const BAN_DURATION: Duration = Duration::from_secs(3600);
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
    pub rate_tokens: f64,
    pub rate_last_refill: Instant,
    pub vote_tokens: f64,
    pub blob_tokens: f64,
    pub handshaked: bool,
}
impl Default for PeerScore {
    fn default() -> Self {
        PeerScore {
            score: 0,
            banned_until: None,
            ban_expires_unix: None,
            invalid_blocks: 0,
            invalid_txs: 0,
            valid_contributions: 0,
            last_seen: None,
            rate_tokens: MAX_MSG_BURST,
            rate_last_refill: Instant::now(),
            vote_tokens: 10.0,
            blob_tokens: 5.0,
            handshaked: false,
        }
    }
}
impl PeerScore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }
    pub fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.rate_last_refill).as_secs_f64();

        self.rate_tokens = (self.rate_tokens + elapsed * MSG_REFILL_RATE).min(MAX_MSG_BURST);

        self.vote_tokens = (self.vote_tokens + elapsed * 2.0).min(20.0);

        self.blob_tokens = (self.blob_tokens + elapsed * 0.5).min(10.0);

        self.rate_last_refill = now;
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
pub struct PeerManager {
    peers: HashMap<PeerId, PeerScore>,
    /// Tokens refilled per second for general P2P messages.
    /// Derived from `SecurityConfig.peer_rate_limit_per_minute` when applied.
    pub(crate) msg_refill_rate: f64,
    /// Soft ceiling on tracked peer score entries (memory DoS guard).
    pub(crate) max_tracked_peers: usize,
    /// H5.1 eclipse protection: max concurrent connections per IPv4 /24.
    pub(crate) max_peers_per_subnet: usize,
    /// Live connection count per IPv4 /24 key (first 3 octets).
    subnet_counts: HashMap<[u8; 3], usize>,
    /// Peer → subnet mapping for disconnect accounting.
    peer_subnets: HashMap<PeerId, [u8; 3]>,
    /// Live peer set. Libp2p can emit multiple connection events for one peer;
    /// This set makes peer_count and /24 accounting idempotent.
    connected_peers: HashSet<PeerId>,
    /// H5.2 outbound diversity: max outbound connections per IPv4 /24.
    pub(crate) max_outbound_per_subnet: usize,
    /// Outbound connection count per IPv4 /24.
    outbound_subnet_counts: HashMap<[u8; 3], usize>,
    /// Outbound peer → subnet mapping.
    outbound_peer_subnets: HashMap<PeerId, [u8; 3]>,
}
impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    /// Default burst refill (~5 msg/s) with 10k tracked-peer ceiling.
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
            msg_refill_rate: MSG_REFILL_RATE,
            max_tracked_peers: 10_000,
            max_peers_per_subnet: 4,
            subnet_counts: HashMap::new(),
            peer_subnets: HashMap::new(),
            connected_peers: HashSet::new(),
            max_outbound_per_subnet: 0,
            outbound_subnet_counts: HashMap::new(),
            outbound_peer_subnets: HashMap::new(),
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

    pub fn msg_refill_rate(&self) -> f64 {
        self.msg_refill_rate
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected_peers.iter().copied().collect()
    }

    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn max_tracked_peers(&self) -> usize {
        self.max_tracked_peers
    }

    /// Maximum admitted connections sharing the same IPv4 /24.
    pub fn max_peers_per_subnet(&self) -> usize {
        self.max_peers_per_subnet
    }

    pub fn set_max_peers_per_subnet(&mut self, n: usize) {
        self.max_peers_per_subnet = n.max(1);
    }

    /// Outbound subnet diversity bound (0 = no limit).
    pub fn max_outbound_per_subnet(&self) -> usize {
        self.max_outbound_per_subnet
    }

    /// Returns false if an outbound connection to `subnet` would
    /// Exceed the diversity bound. 0 = unlimited.
    pub fn can_admit_outbound_subnet(&self, subnet: Option<[u8; 3]>) -> bool {
        if self.max_outbound_per_subnet == 0 {
            return true;
        }
        let Some(key) = subnet else {
            return true;
        };
        self.outbound_subnet_counts.get(&key).copied().unwrap_or(0) < self.max_outbound_per_subnet
    }

    /// Record an outbound connection. Returns false if the peer is
    /// Already tracked as outbound or the subnet bound is exceeded.
    pub fn note_outbound_connected(&mut self, peer_id: PeerId, subnet: Option<[u8; 3]>) -> bool {
        if !self.can_admit_outbound_subnet(subnet) {
            return false;
        }
        if self.outbound_peer_subnets.contains_key(&peer_id) {
            return false;
        }
        if let Some(key) = subnet {
            *self.outbound_subnet_counts.entry(key).or_insert(0) += 1;
            self.outbound_peer_subnets.insert(peer_id, key);
        }
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
    pub fn can_admit_subnet(&self, subnet: Option<[u8; 3]>) -> bool {
        let Some(key) = subnet else {
            return true; // non-IPv4 (relay/circuit) - bound by max_peers only
        };
        self.subnet_counts.get(&key).copied().unwrap_or(0) < self.max_peers_per_subnet
    }

    /// Record a live connection under an optional /24 key.
    ///
    /// Returns `true` only for the first live connection for `peer_id`.
    /// Libp2p may emit duplicate connection events for the same peer/address;
    /// Counting those duplicates was causing peer_count drift and /24 overcount.
    pub fn note_connected(&mut self, peer_id: PeerId, subnet: Option<[u8; 3]>) -> bool {
        if !self.connected_peers.insert(peer_id) {
            return false;
        }
        if let Some(key) = subnet {
            *self.subnet_counts.entry(key).or_insert(0) += 1;
            self.peer_subnets.insert(peer_id, key);
        }
        true
    }

    /// Drop subnet accounting when a peer disconnects.
    ///
    /// Returns `true` if this call removed a previously live peer. Duplicate
    /// Disconnect events are ignored to prevent AtomicUsize underflow.
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
        true
    }

    pub fn subnet_connection_count(&self, subnet: [u8; 3]) -> usize {
        self.subnet_counts.get(&subnet).copied().unwrap_or(0)
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
        if !self.peers.contains_key(peer_id) && self.peers.len() >= self.max_tracked_peers {
            self.prune_spent_records();
            if self.peers.len() >= self.max_tracked_peers {
                return None;
            }
        }
        Some(self.peers.entry(*peer_id).or_default())
    }

    /// Reclaim records that carry nothing worth keeping.
    ///
    /// A record is spent when its ban, if it ever had one, has expired, and no
    /// penalty is left on the score. Without this the ceiling is a one-way
    /// door: a peer id is a public key hash, so an attacker mints ten thousand
    /// of them for free, fills the table once, and every peer the node has
    /// never seen is refused for the rest of its uptime.
    ///
    /// What makes this safe against being turned into a ban-clearing
    /// primitive is what it refuses to touch: a record whose ban is still
    /// running is kept, and a record still carrying a penalty is kept. The
    /// entries an attacker mints arrive through `report_invalid_handshake` and
    /// friends, so they are negative-scored the moment they exist and stay.
    /// Only a peer that has served its time and owes nothing can be dropped,
    /// and dropping that one costs nothing the node still needs.
    pub fn prune_spent_records(&mut self) -> usize {
        let before = self.peers.len();
        self.peers.retain(|_, s| {
            if s.is_banned() {
                return true;
            }
            !(s.ban_expires_unix.is_some() && s.score >= 0)
        });
        before - self.peers.len()
    }

    /// Score entry for a peer whose entry is known to exist, or a refusal.
    ///
    /// Penalty paths use this so that hitting the ceiling reads as "this peer
    /// is not tracked" rather than silently skipping the penalty.
    pub fn check_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        let refill = self.msg_refill_rate;
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        if !score.consume_token_with_rate(refill) {
            score.score = (score.score + RATE_LIMIT_PENALTY).max(MIN_SCORE);
            if score.score <= BAN_THRESHOLD {
                let until = Instant::now() + BAN_DURATION;
                score.banned_until = Some(until);
                score.ban_expires_unix =
                    Some(unix_now_secs().saturating_add(BAN_DURATION.as_secs()));
            }
            return false;
        }
        true
    }

    pub fn check_vote_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        score.refill_tokens();
        if score.vote_tokens >= 1.0 {
            score.vote_tokens -= 1.0;
            true
        } else {
            score.score = (score.score - 1).max(MIN_SCORE);
            false
        }
    }

    pub fn check_blob_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        let Some(score) = self.get_or_create(peer_id) else {
            return false;
        };
        score.refill_tokens();
        if score.blob_tokens >= 1.0 {
            score.blob_tokens -= 1.0;
            true
        } else {
            score.score = (score.score - 5).max(MIN_SCORE);
            false
        }
    }
    pub fn report_invalid_block(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.invalid_blocks += 1;
        score.score = (score.score + INVALID_BLOCK_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_invalid_tx(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.invalid_txs += 1;
        score.score = (score.score + INVALID_TX_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_oversized_message(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = (score.score + OVERSIZED_MESSAGE_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_bad_behavior(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = (score.score - 10).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_good_behavior(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.valid_contributions += 1;
        score.score = (score.score + GOOD_BEHAVIOR_REWARD).min(MAX_SCORE);
        score.last_seen = Some(Instant::now());
    }
    pub fn ban_peer(&mut self, peer_id: &PeerId) {
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
        self.peers
            .get(peer_id)
            .map(|s| s.is_banned())
            .unwrap_or(false)
    }
    pub fn get_score(&self, peer_id: &PeerId) -> i32 {
        self.peers.get(peer_id).map_or(0, |s| s.score)
    }
    pub fn is_handshaked(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .map(|s| s.handshaked)
            .unwrap_or(false)
    }
    pub fn set_handshaked(&mut self, peer_id: &PeerId, status: bool) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.handshaked = status;
    }
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
                score.score = 0;
            }
        }
    }
    pub fn get_banned_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, score)| score.is_banned())
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn report_timeout(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = (score.score + TIMEOUT_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_slow_sync(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = (score.score + SLOW_SYNC_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_invalid_handshake(&mut self, peer_id: &PeerId) {
        let Some(score) = self.get_or_create(peer_id) else {
            return;
        };
        score.score = (score.score + INVALID_HANDSHAKE_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn get_best_peers(&self, n: usize) -> Vec<PeerId> {
        let mut scored: Vec<_> = self.peers.iter().filter(|(_, s)| !s.is_banned()).collect();
        scored.sort_by_key(|x| std::cmp::Reverse(x.1.score));
        scored.into_iter().take(n).map(|(id, _)| *id).collect()
    }

    /// Snapshot of still-active bans with absolute expiry (unix seconds).
    /// Remaining duration is reconstructed on reload.
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
            let remaining = Duration::from_secs(ban.expires_unix - now_unix);
            let entry = self.peers.entry(pid).or_default();
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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_peer_id() -> PeerId {
        PeerId::random()
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

    /// Reload uses absolute expiry, not a fresh full BAN_DURATION.
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
            .and_then(|s| s.ban_remaining())
            .expect("remaining ban");
        // Allow a few seconds of slack for test runtime.
        assert!(
            remaining.as_secs() <= 60 && remaining.as_secs() >= 55,
            "remaining should be ~60s, got {:?}",
            remaining
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

    /// SecurityConfig.peer_rate_limit_per_minute wires into refill rate.
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

    /// Tracked peer map has a hard ceiling (memory DoS guard).
    #[test]
    fn peer_manager_tracked_peer_ceiling() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 8;

        // Fill with 8 synthetic peers via check_rate_limit.
        for i in 0..8u8 {
            // PeerId from random-ish bytes - use libp2p Keypair for uniqueness.
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer = keypair.public().to_peer_id();
            assert!(
                manager.check_rate_limit(&peer),
                "first 8 peers must be admitted (i={i})"
            );
        }
        assert_eq!(manager.tracked_peer_count(), 8);

        let overflow = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(
            !manager.check_rate_limit(&overflow),
            "9th distinct peer must be rejected at ceiling"
        );
        assert_eq!(manager.tracked_peer_count(), 8);
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

    /// Eclipse protection - /24 subnet connection bound.
    #[test]
    fn eclipse_subnet_bound_rejects_fifth_peer() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);
        let subnet = [10, 0, 0];
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
        assert!(pm.can_admit_subnet(Some([10, 0, 1])));
    }

    #[test]
    fn eclipse_disconnect_frees_subnet_slot() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(1);
        let subnet = [192, 168, 1];
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_connected(peer, Some(subnet)));
        assert!(!pm.can_admit_subnet(Some(subnet)));
        assert!(pm.note_disconnected(&peer));
        assert!(pm.can_admit_subnet(Some(subnet)));
    }

    /// H5.1 follow-up: duplicate libp2p connection events for one peer are
    /// Idempotent, and duplicate disconnects do not underflow accounting.
    #[test]
    fn eclipse_peer_accounting_is_idempotent() {
        let mut pm = PeerManager::new();
        let subnet = [172, 18, 0];
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
    /// PeerManager's subnet-bound admission.
    #[test]
    fn chaos_network_partition_isolates_groups() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);

        let subnet_a = [10, 0, 0];
        let subnet_b = [10, 0, 1];

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
        pm.note_connected(peer, None);

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

        let subnet = [192, 168, 1];
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
        assert!(pm.can_admit_subnet(Some([192, 168, 2])));
    }

    /// Chaos: sybil attack from same /24 subnet is rejected.
    #[test]
    fn chaos_sybil_subnet_bound_rejects_excess() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(4);

        let subnet = [172, 16, 0];
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
        pm.note_connected(peer, None);

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

    /// Reputation invariant (§3.4): score must stay within
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
        let subnet = [10u8, 0, 1];
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
            ("report_timeout", |m, p| m.report_timeout(p)),
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
        let past = Instant::now() - Duration::from_secs(1);
        for p in &stale {
            let entry = manager.peers.get_mut(p).expect("record");
            entry.banned_until = Some(past);
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
}
