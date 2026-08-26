//! Gossip Message Deduplication & Peer Scoring.
//!
//! Prevents processing the same gossip message twice (reduces CPU/IO waste)
//! And tracks per-peer message quality for scoring.
//!
//! ## Deduplication
//! Uses a bounded LRU-like ring buffer of recently seen message hashes.
//! Messages older than `dedup_window` entries are evicted automatically.
//! This prevents both accidental duplicates and deliberate replay attacks.
//!
//! ## Peer Scoring
//! Each peer gets a score based on:
//! - Valid messages delivered (+1 per valid message)
//! - Duplicate messages sent (-0.5 per duplicate)
//! - Invalid messages sent (-5 per invalid)
//! - Timely messages (+0.5 for messages within propagation window)
//!
//! Peers below `MIN_SCORE` are candidates for disconnection.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default deduplication window size (number of recent message hashes to keep).
pub const DEFAULT_DEDUP_WINDOW: usize = 10_000;

/// Maximum number of peers whose scores are retained.
///
/// # Why the score table needs a ceiling
///
/// The dedup window is bounded and the score table was not. A `PeerId` is a
/// public key, so producing a fresh one costs a key generation and nothing
/// else; a peer that connects, sends one message and disconnects leaves a
/// `PeerScore` behind, and the map had no path that ever removed it.
/// `remove_peer` existed and was called from nowhere, which is why the tree's
/// idle-code baseline lists it: the eviction was written and never wired.
///
/// The ceiling is set well above `node::MAX_PEERS` because the table is
/// deliberately allowed to outlive a connection. A peer that misbehaves,
/// disconnects and reconnects must not arrive with a clean score, or
/// disconnecting becomes the cheapest way to launder a ban. So the record
/// survives the connection and is dropped only under pressure, oldest close
/// first.
const MAX_SCORED_PEERS: usize = 4_096;

/// Minimum peer score before disconnection candidate.
pub const MIN_PEER_SCORE: f64 = -10.0;

/// Maximum peer score (cap to prevent unbounded growth).
pub const MAX_PEER_SCORE: f64 = 100.0;

/// Score increment for a valid message.
pub const SCORE_VALID_MESSAGE: f64 = 1.0;

/// Score decrement for a duplicate message.
pub const SCORE_DUPLICATE: f64 = -0.5;

/// Score decrement for an invalid message.
pub const SCORE_INVALID: f64 = -5.0;

/// Score increment for a timely message (within propagation window).
pub const SCORE_TIMELY: f64 = 0.5;

/// Propagation window in milliseconds - messages within this window
/// Are considered "timely" and earn bonus score.
pub const PROPAGATION_WINDOW_MS: u128 = 5_000; // 5 seconds

/// Maximum number of duplicate messages a single peer may send before it is
/// Flagged for automatic banning. The gossip-flood finding explicitly requires
/// That peers producing an excessive message rate be auto-banned, not merely
/// Scored. This is the duplicate-flood half of that threshold; the score half
/// Is `MIN_PEER_SCORE`.
pub const MAX_DUPLICATE_COUNT: u64 = 1_000;

/// Result of a deduplication check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupResult {
    /// Message is new - should be processed.
    New,
    /// Message was already seen - should be skipped.
    Duplicate,
}

/// Per-peer scoring information.
#[derive(Debug, Clone)]
pub struct PeerScore {
    pub score: f64,
    pub valid_count: u64,
    pub duplicate_count: u64,
    pub invalid_count: u64,
    pub timely_count: u64,
    pub last_message_at: u64, // timestamp in ms
}

impl PeerScore {
    pub fn new() -> Self {
        Self {
            score: 0.0,
            valid_count: 0,
            duplicate_count: 0,
            invalid_count: 0,
            timely_count: 0,
            last_message_at: 0,
        }
    }

    pub fn is_below_threshold(&self) -> bool {
        self.score < MIN_PEER_SCORE
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::new()
    }
}

/// Gossip deduplication and peer scoring engine.
pub struct GossipDedup {
    /// Set of recently seen message hashes for O(1) membership tests.
    ///
    /// Previously this was a `VecDeque` queried with `contains`, which is an
    /// O(n) linear scan (up to `window_size` = 10_000 entries) on *every*
    /// Incoming gossip message - itself a CPU-DoS vector under high load.
    /// Membership is now a `HashSet` lookup.
    seen_set: HashSet<[u8; 32]>,
    /// Insertion-order ring buffer used purely for LRU eviction so `seen_set`
    /// Stays bounded at `window_size` entries.
    seen_order: VecDeque<[u8; 32]>,
    /// Maximum number of entries in the dedup window.
    window_size: usize,
    /// Per-peer scores.
    ///
    /// Bounded by [`MAX_SCORED_PEERS`]. See that constant for why the bound
    /// exists and why a disconnect alone does not drop an entry.
    peer_scores: HashMap<libp2p::PeerId, PeerScore>,
    /// Peers whose connection has closed, in the order they closed.
    ///
    /// A disconnected peer's score is kept - dropping it would let a
    /// misbehaving peer clear its record by reconnecting - but it is the first
    /// thing evicted when the table is full. Held separately from
    /// `peer_scores` so the eviction order does not depend on hash iteration
    /// order, which differs between processes.
    disconnected_order: VecDeque<libp2p::PeerId>,
    /// Total messages processed (for metrics).
    total_processed: u64,
    /// Total duplicates rejected (for metrics).
    total_duplicates: u64,
}

impl GossipDedup {
    pub fn new(window_size: usize) -> Self {
        Self {
            seen_set: HashSet::with_capacity(window_size),
            seen_order: VecDeque::with_capacity(window_size),
            window_size,
            peer_scores: HashMap::new(),
            disconnected_order: VecDeque::new(),
            total_processed: 0,
            total_duplicates: 0,
        }
    }

    /// Check if a message has been seen before and record it.
    ///
    /// Returns `DedupResult::New` if the message is fresh (should be processed),
    /// Or `DedupResult::Duplicate` if it was already seen (should be skipped).
    pub fn check_and_record(&mut self, message_bytes: &[u8], peer: &libp2p::PeerId) -> DedupResult {
        let hash = hash_message(message_bytes);

        if self.seen_set.contains(&hash) {
            // Duplicate - record on peer score
            self.total_duplicates += 1;
            let score = self.peer_scores.entry(*peer).or_default();
            score.score += SCORE_DUPLICATE;
            score.duplicate_count += 1;
            score.score = score.score.clamp(-100.0, MAX_PEER_SCORE);
            self.enforce_score_ceiling();
            return DedupResult::Duplicate;
        }

        // New message - add to seen set (bounded by LRU eviction)
        if self.seen_order.len() >= self.window_size {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        self.seen_set.insert(hash);
        self.seen_order.push_back(hash);
        self.total_processed += 1;

        DedupResult::New
    }

    /// Record a valid message from a peer (called after successful processing).
    pub fn record_valid(&mut self, peer: &libp2p::PeerId, timestamp_ms: u64) {
        let score = self.peer_scores.entry(*peer).or_default();
        score.score += SCORE_VALID_MESSAGE;
        score.valid_count += 1;

        // Timely bonus
        if score.last_message_at > 0 {
            let gap = timestamp_ms.saturating_sub(score.last_message_at);
            if gap <= PROPAGATION_WINDOW_MS as u64 {
                score.score += SCORE_TIMELY;
                score.timely_count += 1;
            }
        }
        score.last_message_at = timestamp_ms;
        score.score = score.score.clamp(-100.0, MAX_PEER_SCORE);
        self.enforce_score_ceiling();
    }

    /// Record an invalid message from a peer.
    pub fn record_invalid(&mut self, peer: &libp2p::PeerId) {
        let score = self.peer_scores.entry(*peer).or_default();
        score.score += SCORE_INVALID;
        score.invalid_count += 1;
        score.score = score.score.clamp(-100.0, MAX_PEER_SCORE);
        self.enforce_score_ceiling();
    }

    /// Get the score for a peer.
    pub fn peer_score(&self, peer: &libp2p::PeerId) -> f64 {
        self.peer_scores.get(peer).map(|s| s.score).unwrap_or(0.0)
    }

    /// Get all peers below the minimum score threshold.
    pub fn peers_below_threshold(&self) -> Vec<libp2p::PeerId> {
        self.peer_scores
            .iter()
            .filter(|(_, s)| s.is_below_threshold())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get detailed score info for a peer.
    pub fn get_peer_score(&self, peer: &libp2p::PeerId) -> Option<&PeerScore> {
        self.peer_scores.get(peer)
    }

    /// Returns `true` if the peer must be auto-banned: its score has dropped to
    /// Or below `MIN_PEER_SCORE` **or** it has sent more than
    /// `MAX_DUPLICATE_COUNT` duplicate messages (a replay/duplicate flood).
    ///
    /// Per the gossip-flood finding, peers producing an excessive message rate
    /// Must be auto-banned, not merely scored. This engine only *decides* the
    /// Ban; the caller (swarm / peer-manager) is responsible for enforcing the
    /// Disconnect so the DoS primitive stays self-contained and testable.
    pub fn peer_should_be_banned(&self, peer: &libp2p::PeerId) -> bool {
        match self.peer_scores.get(peer) {
            Some(s) => s.score <= MIN_PEER_SCORE || s.duplicate_count >= MAX_DUPLICATE_COUNT,
            None => false,
        }
    }

    /// Remove a peer's score outright.
    ///
    /// Used when the record must genuinely go - a clear, or a peer that was
    /// never scored. On an ordinary disconnect call
    /// [`Self::note_peer_disconnected`] instead, which keeps the record and
    /// only marks it evictable.
    pub fn remove_peer(&mut self, peer: &libp2p::PeerId) {
        self.peer_scores.remove(peer);
        self.disconnected_order.retain(|p| p != peer);
    }

    /// Mark a peer as disconnected.
    ///
    /// The score is deliberately **not** deleted. Deleting it on disconnect
    /// would make reconnecting the cheapest way to clear a bad record: a peer
    /// one message away from the ban threshold drops the connection, comes
    /// back at zero, and repeats. The entry instead joins the eviction queue,
    /// so it survives until the table is under pressure.
    ///
    /// Idempotent: a peer that closes several connections is queued once.
    pub fn note_peer_disconnected(&mut self, peer: &libp2p::PeerId) {
        if !self.peer_scores.contains_key(peer) {
            return;
        }
        if !self.disconnected_order.iter().any(|p| p == peer) {
            self.disconnected_order.push_back(*peer);
        }
    }

    /// Note that a peer connected, so its record is no longer evictable.
    pub fn note_peer_connected(&mut self, peer: &libp2p::PeerId) {
        self.disconnected_order.retain(|p| p != peer);
    }

    /// How many peers currently hold a score.
    #[must_use]
    pub fn scored_peer_count(&self) -> usize {
        self.peer_scores.len()
    }

    /// Mean gossip score across scored peers, rounded toward zero as `i64`.
    ///
    /// Returns 0 when the table is empty so a cold node does not look like a
    /// mass ban. Used by the `peer_connection_quality` gauge.
    #[must_use]
    pub fn mean_peer_score_i64(&self) -> i64 {
        if self.peer_scores.is_empty() {
            return 0;
        }
        let sum: f64 = self.peer_scores.values().map(|s| s.score).sum();
        let mean = sum / self.peer_scores.len() as f64;
        if mean >= i64::MAX as f64 {
            i64::MAX
        } else if mean <= i64::MIN as f64 {
            i64::MIN
        } else {
            mean as i64
        }
    }

    /// Drop records until the table is within [`MAX_SCORED_PEERS`].
    ///
    /// Disconnected peers go first, oldest close first. Only if that is not
    /// enough - every scored peer is currently connected, which means the
    /// ceiling is below the connection limit and is misconfigured - does it
    /// touch a connected peer, and then it takes the **highest** score, because
    /// the record worth keeping is the one that would ban somebody.
    fn enforce_score_ceiling(&mut self) {
        while self.peer_scores.len() > MAX_SCORED_PEERS {
            if let Some(peer) = self.disconnected_order.pop_front() {
                self.peer_scores.remove(&peer);
                continue;
            }
            let Some(victim) = self
                .peer_scores
                .iter()
                .max_by(|a, b| {
                    a.1.score
                        .partial_cmp(&b.1.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.0.cmp(b.0))
                })
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.peer_scores.remove(&victim);
        }
    }

    /// Total messages processed.
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }

    /// Total duplicates rejected.
    pub fn total_duplicates(&self) -> u64 {
        self.total_duplicates
    }

    /// Current dedup window utilization.
    pub fn window_utilization(&self) -> f64 {
        self.seen_order.len() as f64 / self.window_size as f64
    }

    /// Clear all state (e.g. on restart).
    pub fn clear(&mut self) {
        self.seen_set.clear();
        self.seen_order.clear();
        self.peer_scores.clear();
        self.disconnected_order.clear();
        self.total_processed = 0;
        self.total_duplicates = 0;
    }
}

impl Default for GossipDedup {
    fn default() -> Self {
        Self::new(DEFAULT_DEDUP_WINDOW)
    }
}

fn hash_message(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_GOSSIP_MSG_V1");
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct peer id per message must not grow the score table without
    /// bound.
    ///
    /// A `PeerId` is a public key, so the attacker's cost per entry is one key
    /// generation. Before the ceiling the table had no eviction path at all:
    /// `remove_peer` was written and called from nowhere, which is why the
    /// idle-code baseline lists it.
    #[test]
    fn peer_id_churn_cannot_grow_the_score_table_without_bound() {
        let mut dedup = GossipDedup::new(64);
        for n in 0..(MAX_SCORED_PEERS + 500) {
            let peer = libp2p::PeerId::random();
            dedup.record_invalid(&peer);
            // Every one of them then goes away, as a churning attacker's would.
            dedup.note_peer_disconnected(&peer);
            assert!(
                dedup.scored_peer_count() <= MAX_SCORED_PEERS,
                "the table reached {} entries after {n} peers",
                dedup.scored_peer_count()
            );
        }
        assert!(dedup.scored_peer_count() <= MAX_SCORED_PEERS);
    }

    /// Disconnecting does not clear a bad record.
    ///
    /// This is the half that makes the eviction safe. If a disconnect deleted
    /// the score, a peer one message from the ban threshold would reconnect at
    /// zero, and dropping the connection would be the cheapest ban laundry
    /// available.
    #[test]
    fn a_disconnect_does_not_launder_a_bad_score() {
        let mut dedup = GossipDedup::new(64);
        let peer = libp2p::PeerId::random();
        for _ in 0..5 {
            dedup.record_invalid(&peer);
        }
        let before = dedup.peer_score(&peer);
        assert!(before < 0.0, "the setup did not produce a bad score");

        dedup.note_peer_disconnected(&peer);
        assert_eq!(
            dedup.peer_score(&peer),
            before,
            "the score was cleared by a disconnect"
        );
        assert!(dedup.peer_should_be_banned(&peer) || before > MIN_PEER_SCORE);
    }

    /// A connected peer is not evicted while a disconnected record is
    /// available.
    ///
    /// The resident is given a HIGH score on purpose. The fallback path -
    /// the one that runs when the eviction queue is empty - drops the highest
    /// score first, so a resident scored like the churn would survive by the
    /// id tie-break and the test would pass without the queue existing at all.
    /// That is what the first version of this test did: deleting the queue
    /// left it green. Scoring the resident above the churn makes it the
    /// fallback's first victim, so only the queue can save it.
    #[test]
    fn eviction_prefers_disconnected_peers() {
        let mut dedup = GossipDedup::new(64);
        let resident = libp2p::PeerId::random();
        for _ in 0..20 {
            dedup.record_valid(&resident, 0);
        }
        dedup.note_peer_connected(&resident);
        assert!(
            dedup.peer_score(&resident) > 0.0,
            "the resident must outscore the churn for this test to mean anything"
        );

        for _ in 0..(MAX_SCORED_PEERS + 10) {
            let churn = libp2p::PeerId::random();
            dedup.record_invalid(&churn);
            dedup.note_peer_disconnected(&churn);
        }

        assert!(
            dedup.get_peer_score(&resident).is_some(),
            "the connected peer was evicted while disconnected records remained"
        );
    }

    /// Reconnecting takes a record back out of the eviction queue.
    #[test]
    fn reconnecting_protects_the_record_again() {
        let mut dedup = GossipDedup::new(64);
        let peer = libp2p::PeerId::random();
        dedup.record_invalid(&peer);
        dedup.note_peer_disconnected(&peer);
        dedup.note_peer_connected(&peer);

        for _ in 0..(MAX_SCORED_PEERS + 10) {
            let churn = libp2p::PeerId::random();
            dedup.record_invalid(&churn);
            dedup.note_peer_disconnected(&churn);
        }
        assert!(
            dedup.get_peer_score(&peer).is_some(),
            "a reconnected peer stayed in the eviction queue"
        );
    }

    /// Marking an unknown peer disconnected does not create a record.
    #[test]
    fn a_never_scored_peer_is_not_queued() {
        let mut dedup = GossipDedup::new(64);
        dedup.note_peer_disconnected(&libp2p::PeerId::random());
        assert_eq!(dedup.scored_peer_count(), 0);
    }

    /// `clear` empties the eviction queue too.
    ///
    /// A queue holding ids whose scores are gone would evict nothing on the
    /// next pass and let the table run past its ceiling.
    #[test]
    fn clear_empties_the_eviction_queue() {
        let mut dedup = GossipDedup::new(64);
        let peer = libp2p::PeerId::random();
        dedup.record_invalid(&peer);
        dedup.note_peer_disconnected(&peer);
        dedup.clear();
        assert_eq!(dedup.scored_peer_count(), 0);

        for _ in 0..(MAX_SCORED_PEERS + 5) {
            let churn = libp2p::PeerId::random();
            dedup.record_invalid(&churn);
            dedup.note_peer_disconnected(&churn);
        }
        assert!(dedup.scored_peer_count() <= MAX_SCORED_PEERS);
    }

    fn peer(_b: u8) -> libp2p::PeerId {
        let key = libp2p::identity::Keypair::generate_ed25519();
        key.public().to_peer_id()
    }

    #[test]
    fn first_message_is_new() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);
        assert_eq!(dedup.check_and_record(b"hello", &p), DedupResult::New);
    }

    #[test]
    fn duplicate_message_detected() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);
        assert_eq!(dedup.check_and_record(b"hello", &p), DedupResult::New);
        assert_eq!(dedup.check_and_record(b"hello", &p), DedupResult::Duplicate);
    }

    #[test]
    fn different_messages_are_not_duplicates() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);
        assert_eq!(dedup.check_and_record(b"hello", &p), DedupResult::New);
        assert_eq!(dedup.check_and_record(b"world", &p), DedupResult::New);
    }

    #[test]
    fn window_eviction_allows_reprocessing() {
        let mut dedup = GossipDedup::new(3);
        let p = peer(1);

        dedup.check_and_record(b"a", &p);
        dedup.check_and_record(b"b", &p);
        dedup.check_and_record(b"c", &p);
        // Window full. Next insert evicts "a".
        dedup.check_and_record(b"d", &p);

        // "a" was evicted, so it's "new" again.
        assert_eq!(dedup.check_and_record(b"a", &p), DedupResult::New);
    }

    #[test]
    fn duplicate_increments_peer_duplicate_count() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        dedup.check_and_record(b"hello", &p);
        dedup.check_and_record(b"hello", &p); // duplicate
        dedup.check_and_record(b"hello", &p); // duplicate

        let score = dedup.get_peer_score(&p).unwrap();
        assert_eq!(score.duplicate_count, 2);
        assert!(score.score < 0.0); // negative from duplicates
    }

    #[test]
    fn valid_message_improves_score() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        dedup.check_and_record(b"hello", &p);
        dedup.record_valid(&p, 1000);
        dedup.check_and_record(b"world", &p);
        dedup.record_valid(&p, 2000);

        assert!(dedup.peer_score(&p) > 0.0);
    }

    #[test]
    fn invalid_message_degrades_score() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        dedup.record_invalid(&p);
        dedup.record_invalid(&p);
        dedup.record_invalid(&p);

        assert!(dedup.peer_score(&p) < 0.0);
    }

    #[test]
    fn peers_below_threshold_detected() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        // Push score below threshold
        for _ in 0..25 {
            dedup.record_invalid(&p);
        }

        let bad_peers = dedup.peers_below_threshold();
        assert!(bad_peers.contains(&p));
    }

    #[test]
    fn timely_message_gets_bonus() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        dedup.check_and_record(b"a", &p);
        dedup.record_valid(&p, 1000);

        dedup.check_and_record(b"b", &p);
        dedup.record_valid(&p, 2000); // within 5s window

        let score = dedup.get_peer_score(&p).unwrap();
        assert_eq!(score.timely_count, 1);
        assert!(score.score > 2.0); // 2 valid + 1 timely bonus
    }

    #[test]
    fn total_counts_are_correct() {
        let mut dedup = GossipDedup::new(100);
        let p = peer(1);

        dedup.check_and_record(b"a", &p);
        dedup.check_and_record(b"b", &p);
        dedup.check_and_record(b"a", &p); // dup
        dedup.check_and_record(b"c", &p);

        assert_eq!(dedup.total_processed(), 3); // 3 new
        assert_eq!(dedup.total_duplicates(), 1); // 1 dup
    }

    #[test]
    fn window_utilization() {
        let mut dedup = GossipDedup::new(10);
        let p = peer(1);

        for i in 0..5u8 {
            dedup.check_and_record(&[i], &p);
        }

        assert!((dedup.window_utilization() - 0.5).abs() < 0.01);
    }

    #[test]
    fn excessive_duplicate_flood_flags_peer_for_ban() {
        let mut dedup = GossipDedup::new(10_000);
        let p = peer(1);
        // First insert is "New"; every subsequent identical message is a
        // Duplicate. Exceed MAX_DUPLICATE_COUNT so the peer is auto-banned.
        for _ in 0..=MAX_DUPLICATE_COUNT {
            dedup.check_and_record(b"spam", &p);
        }
        assert!(
            dedup.peer_should_be_banned(&p),
            "peer flooding duplicates must be auto-banned"
        );
    }

    #[test]
    fn healthy_peer_is_not_banned() {
        let mut dedup = GossipDedup::new(10_000);
        let p = peer(1);
        for i in 0..50u8 {
            dedup.check_and_record(&[i], &p);
        }
        assert!(!dedup.peer_should_be_banned(&p));
    }

    #[test]
    fn membership_is_unique_after_eviction_reinsert() {
        // Regression for the O(1) HashSet-backed membership: re-inserting an
        // Evicted hash must be detected as "New" exactly once, and a hash still
        // Inside the window must always be "Duplicate".
        let mut dedup = GossipDedup::new(2);
        let p = peer(1);
        assert_eq!(dedup.check_and_record(b"a", &p), DedupResult::New);
        assert_eq!(dedup.check_and_record(b"b", &p), DedupResult::New);
        // Window full (a, b). Insert "c" -> evicts the oldest entry, "a".
        assert_eq!(dedup.check_and_record(b"c", &p), DedupResult::New);
        // Window is now (b, c). "a" was evicted -> New again, and inserting it
        // Evicts the next-oldest entry, "b". window becomes (c, a).
        assert_eq!(dedup.check_and_record(b"a", &p), DedupResult::New);
        // Still inside the window -> Duplicate, and a duplicate never evicts.
        assert_eq!(dedup.check_and_record(b"c", &p), DedupResult::Duplicate);
        assert_eq!(dedup.check_and_record(b"a", &p), DedupResult::Duplicate);
        // "b" was evicted by the "a" re-insert above -> New again.
        assert_eq!(dedup.check_and_record(b"b", &p), DedupResult::New);
    }
}
