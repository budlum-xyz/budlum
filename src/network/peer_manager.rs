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
    /// is recomputed from this on reload (Phase 0.334 / A4).
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

    /// Refill using an explicit tokens/sec rate (Phase 3 §3.4 network profile).
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
    /// this set makes peer_count and /24 accounting idempotent.
    connected_peers: HashSet<PeerId>,
}
impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    /// Default burst refill (~5 msg/s) with 10k tracked-peer ceiling (Phase 3 §3.4).
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
            msg_refill_rate: MSG_REFILL_RATE,
            max_tracked_peers: 10_000,
            max_peers_per_subnet: 4,
            subnet_counts: HashMap::new(),
            peer_subnets: HashMap::new(),
            connected_peers: HashSet::new(),
        }
    }

    /// Phase 3 §3.4: apply network security profile to P2P rate limiting.
    /// `peer_rate_limit_per_minute` becomes tokens/second = limit/60.
    pub fn apply_security_config(&mut self, security: crate::core::chain_config::SecurityConfig) {
        let per_min = security.peer_rate_limit_per_minute.max(1);
        self.msg_refill_rate = (per_min as f64) / 60.0;
        self.max_peers_per_subnet = security.max_peers_per_subnet.max(1);
        // Keep a hard memory ceiling independent of max_peers (connected).
        self.max_tracked_peers = 10_000;
    }

    pub fn msg_refill_rate(&self) -> f64 {
        self.msg_refill_rate
    }

    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn max_tracked_peers(&self) -> usize {
        self.max_tracked_peers
    }

    /// H5.1: maximum admitted connections sharing the same IPv4 /24.
    pub fn max_peers_per_subnet(&self) -> usize {
        self.max_peers_per_subnet
    }

    pub fn set_max_peers_per_subnet(&mut self, n: usize) {
        self.max_peers_per_subnet = n.max(1);
    }

    /// Returns false if admitting `subnet` would exceed the eclipse bound.
    pub fn can_admit_subnet(&self, subnet: Option<[u8; 3]>) -> bool {
        let Some(key) = subnet else {
            return true; // non-IPv4 (relay/circuit) — bound by max_peers only
        };
        self.subnet_counts.get(&key).copied().unwrap_or(0) < self.max_peers_per_subnet
    }

    /// Record a live connection under an optional /24 key.
    ///
    /// Returns `true` only for the first live connection for `peer_id`.
    /// Libp2p may emit duplicate connection events for the same peer/address;
    /// counting those duplicates was causing peer_count drift and /24 overcount.
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
    /// disconnect events are ignored to prevent AtomicUsize underflow.
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
    fn get_or_create(&mut self, peer_id: &PeerId) -> &mut PeerScore {
        self.peers.entry(*peer_id).or_default()
    }
    pub fn check_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        // Phase 3 §3.4: refuse to grow the score map without bound (memory DoS).
        if !self.peers.contains_key(peer_id) && self.peers.len() >= self.max_tracked_peers {
            return false;
        }
        let refill = self.msg_refill_rate;
        let score = self.get_or_create(peer_id);
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
        let score = self.get_or_create(peer_id);
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
        let score = self.get_or_create(peer_id);
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
        let score = self.get_or_create(peer_id);
        score.invalid_blocks += 1;
        score.score += INVALID_BLOCK_PENALTY;
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_invalid_tx(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
        score.invalid_txs += 1;
        score.score += INVALID_TX_PENALTY;
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_oversized_message(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
        score.score += OVERSIZED_MESSAGE_PENALTY;
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_bad_behavior(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
        score.score = (score.score - 10).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_good_behavior(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
        score.valid_contributions += 1;
        score.score = (score.score + GOOD_BEHAVIOR_REWARD).min(MAX_SCORE);
        score.last_seen = Some(Instant::now());
    }
    pub fn ban_peer(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
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
        let score = self.get_or_create(peer_id);
        score.handshaked = status;
    }
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<&PeerScore> {
        self.peers.get(peer_id)
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
        let score = self.get_or_create(peer_id);
        score.score = (score.score + TIMEOUT_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_slow_sync(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
        score.score = (score.score + SLOW_SYNC_PENALTY).max(MIN_SCORE);
        score.last_seen = Some(Instant::now());
        if score.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }
    pub fn report_invalid_handshake(&mut self, peer_id: &PeerId) {
        let score = self.get_or_create(peer_id);
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
    /// Phase 0.334 / A4: remaining duration is reconstructed on reload.
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

    /// Legacy helper: reload peer IDs with a *full* ban window (pre-Phase 0.334 format).
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

/// Durable ban record (Phase 0.334 / A4).
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

    /// Phase 0.334 / A4: reload uses absolute expiry, not a fresh full BAN_DURATION.
    #[test]
    fn tur117_ban_reload_preserves_remaining() {
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

    /// Phase 0.334 / A4: already-expired absolute timestamps are not re-banned.
    #[test]
    fn tur117_expired_ban_not_reloaded() {
        let mut manager = PeerManager::new();
        let peer = test_peer_id();
        manager.reload_banned_peers(&[PersistedBan {
            peer_id: peer.to_base58(),
            expires_unix: unix_now_secs().saturating_sub(10),
        }]);
        assert!(!manager.is_banned(&peer));
        assert!(manager.get_persisted_banned_peers().is_empty());
    }

    /// Phase 3 §3.4: SecurityConfig.peer_rate_limit_per_minute wires into refill rate.
    #[test]
    fn phase3_peer_rate_limit_security_profile() {
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

    /// Phase 3 §3.4: tracked peer map has a hard ceiling (memory DoS guard).
    #[test]
    fn phase3_peer_manager_tracked_peer_ceiling() {
        let mut manager = PeerManager::new();
        manager.max_tracked_peers = 8;

        // Fill with 8 synthetic peers via check_rate_limit.
        for i in 0..8u8 {
            // PeerId from random-ish bytes — use libp2p Keypair for uniqueness.
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

    /// Phase 3 §3.4: burst exhaustion then rejection (token bucket).
    #[test]
    fn phase3_peer_rate_limit_burst_exhaustion() {
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

    /// Phase 11.12 / H5.4: rate-limit exhaustion uses its own penalty category,
    /// not the oversized-message category. Magnitude stays calibrated equal to
    /// the old value; the separation prevents audit/telemetry misclassification.
    #[test]
    fn phase11_12_rate_limit_exhaustion_uses_dedicated_penalty() {
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
    fn phase11_12_repeated_rate_limit_exhaustion_bans_peer() {
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

    /// H5.1: eclipse protection — /24 subnet connection bound.
    #[test]
    fn h5_eclipse_subnet_bound_rejects_fifth_peer() {
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
    fn h5_eclipse_disconnect_frees_subnet_slot() {
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
    /// idempotent, and duplicate disconnects do not underflow accounting.
    #[test]
    fn h5_eclipse_peer_accounting_is_idempotent() {
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

    /// Phase 11.12 chaos: network partition isolates peer groups by subnet.
    /// Two groups on different /24 subnets cannot communicate through the
    /// PeerManager's subnet-bound admission.
    #[test]
    fn phase11_12_chaos_network_partition_isolates_groups() {
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
        // Subnet A is full — partition enforced
        assert!(!pm.can_admit_subnet(Some(subnet_a)));
        // Subnet B is still available — groups are isolated
        assert!(pm.can_admit_subnet(Some(subnet_b)));
    }

    /// Phase 11.12 chaos: byzantine peer sending invalid messages is rejected.
    #[test]
    fn phase11_12_chaos_byzantine_block_rejected() {
        let mut pm = PeerManager::new();
        let peer = test_peer_id();
        pm.note_connected(peer, None);

        // Byzantine: peer sends oversized message repeatedly
        for _ in 0..MAX_MSG_BURST as u32 {
            let _ = pm.check_rate_limit(&peer);
        }
        // Peer should be penalized
        assert!(pm.get_score(&peer) < 0);
    }

    /// Phase 11.12 chaos: eclipse single-peer isolation — a peer that can only
    /// connect to one subnet is isolated from the broader network.
    #[test]
    fn phase11_12_chaos_eclipse_single_peer_isolation() {
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
        // New peer on same subnet is rejected — eclipse isolation
        assert!(!pm.can_admit_subnet(Some(subnet)));
        // New peer on different subnet is accepted
        assert!(pm.can_admit_subnet(Some([192, 168, 2])));
    }

    /// Phase 11.12 chaos: sybil attack from same /24 subnet is rejected.
    #[test]
    fn phase11_12_chaos_sybil_subnet_bound_rejects_excess() {
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

    /// Phase 11.12 chaos: ban TTL allows reconnect after expiry.
    #[test]
    fn phase11_12_chaos_ban_ttl_allows_reconnect_after_expiry() {
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
        if let Some(info) = pm.get_peer_info(&peer) {
            info.ban_expires_unix = Some(0); // expired
        }
        assert!(!pm.is_banned(&peer));
    }

    /// Phase 11.12 chaos: reputation fuzz decay — peer score decreases
    /// with repeated violations.
    #[test]
    fn phase11_12_chaos_reputation_fuzz_decay() {
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
}
