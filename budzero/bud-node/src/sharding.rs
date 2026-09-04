//! B.U.D. Active Sharding - determines shard responsibility.
//!
//! Implements the sharding logic from Vision §7: nodes are responsible
//! For a subset of the global storage state based on the distance between
//! Their `PeerId` and the `ContentId` (CID) of the shard.
//!
//! # Responsibility Rule
//!
//! A node is a "responsible host" for a shard if:
//! 1. The shard is assigned to them via an on-chain `StorageDeal`.
//! 2. The node's `PeerId` is among the K-closest peers to the CID in the DHT.
//!
//! Reached from node startup: `src/network/node.rs` builds a `ShardManager`
//! at line 446 when a sharding config is present, and `src/main.rs` supplies
//! `ShardingConfig::mobile_default()` for the mobile profile.
//!
//! It carried a marker saying no node builds one, which stopped being true
//! when that call site landed and nothing removed it. A stale marker is worse
//! than none: it tells the next reader not to look.

use crate::store::ContentId;
use libp2p::kad::{KBucketDistance, KBucketKey, RecordKey, U256};
use libp2p::PeerId;

/// Sharding configuration.
#[derive(Debug, Clone)]
pub struct ShardingConfig {
    /// Number of replicas required per shard (default: 3).
    pub replication_factor: usize,
    /// Maximum distance (XOR) allowed for opportunistic caching.
    pub max_xor_distance: u128,
    /// Whether sharding responsibility is strictly enforced.
    /// (User Decision 5: mandatory_sharding).
    pub mandatory: bool,
    /// Mobile mode: Lighter sharding, battery-aware.
    pub mobile_mode: bool,
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            max_xor_distance: u128::MAX / 1000, // 0.1% of the keyspace
            mandatory: true,
            mobile_mode: false,
        }
    }
}

impl ShardingConfig {
    pub fn mobile_default() -> Self {
        Self {
            replication_factor: 2,                 // Balance energy and availability
            max_xor_distance: u128::MAX / 100_000, // 0.001% of the keyspace
            mandatory: true,
            mobile_mode: true,
        }
    }
}

/// Evaluates shard responsibility and routing.
pub struct ShardManager {
    local_peer_id: PeerId,
    config: ShardingConfig,
}

impl ShardManager {
    /// Create a new shard manager for the local node.
    pub fn new(local_peer_id: PeerId, config: ShardingConfig) -> Self {
        Self {
            local_peer_id,
            config,
        }
    }

    /// Check if this node should proactively fetch and store a CID.
    ///
    /// This is used for "Active Sharding" (Vision §7.2): nodes don't
    /// Just wait for deals; they help maintain the network's health by
    /// Caching CIDs that are "close" to them in the XOR keyspace.
    pub fn should_cache(&self, cid: &ContentId) -> bool {
        if self.config.mobile_mode && !self.is_resource_buffer_sufficient() {
            return false; // Skip caching on mobile if low on battery/budget
        }
        // The threshold is a `u128`, the distance is 256 bits wide. A
        // distance with any of its upper 128 bits set is farther than every
        // threshold this type can express, so it is never "close". Truncating
        // to the low half first (`low_u128`) used to let such a distance pass
        // whenever its low half happened to be small, including as an exact
        // match under a zero threshold.
        self.xor_distance(cid).0 <= U256::from(self.config.max_xor_distance)
    }

    /// Resource budget check for mobile devices (Mock/Placeholder).
    /// In a real mobile app, this would check battery level and Wi-Fi status.
    pub fn is_resource_buffer_sufficient(&self) -> bool {
        // Placeholder: Always true in simulation,
        // Would be linked to OS-level battery/metered connection API.
        true
    }

    /// Calculate the XOR distance between the local PeerId and a CID, in
    /// Kademlia's own key space.
    ///
    /// The DHT places both sides through `kbucket::Key`: `SHA-256(peer_id
    /// bytes)` for the peer and `SHA-256(record key)` for the CID, where the
    /// record key is the raw CID (`ContentDiscovery::cid_to_key`). The CID
    /// used to enter the XOR unhashed, so `should_cache` was measuring in a
    /// space the DHT does not use, and "close" here was not "close" there.
    /// The full 256-bit distance is returned; `should_cache` compares all
    /// of it against the threshold.
    pub fn xor_distance(&self, cid: &ContentId) -> KBucketDistance {
        let peer = KBucketKey::from(self.local_peer_id);
        let key = KBucketKey::new(RecordKey::new(&cid.0));
        peer.distance(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn random_peer_id() -> PeerId {
        let keypair = identity::Keypair::generate_ed25519();
        keypair.public().to_peer_id()
    }

    #[test]
    fn test_xor_distance_is_deterministic() {
        let peer = random_peer_id();
        let manager = ShardManager::new(peer, ShardingConfig::default());
        let cid = ContentId([0x42; 32]);

        let d1 = manager.xor_distance(&cid);
        let d2 = manager.xor_distance(&cid);
        assert_eq!(d1, d2);
    }

    /// The distance is the one Kademlia computes between the peer's bucket
    /// key and the record key of the CID, not an XOR against raw CID bytes.
    #[test]
    fn xor_distance_matches_the_dht_key_space() {
        let peer = random_peer_id();
        let manager = ShardManager::new(peer, ShardingConfig::default());
        let cid = ContentId([0x42; 32]);
        let expected = KBucketKey::from(peer).distance(&KBucketKey::new(RecordKey::new(&cid.0)));
        assert_eq!(manager.xor_distance(&cid), expected);

        // The raw-byte XOR the code used to compute is a different number.
        use sha2::{Digest, Sha256};
        let peer_hash = Sha256::digest(peer.to_bytes());
        let mut raw = [0u8; 32];
        for i in 0..32 {
            raw[i] = peer_hash[i] ^ cid.0[i];
        }
        assert_ne!(manager.xor_distance(&cid).0, U256::from_big_endian(&raw));
    }

    /// The threshold is compared against the whole 256-bit distance. With
    /// the widest threshold a `u128` can hold, only a CID whose distance has
    /// no upper bit set is close; that is one CID in 2^128. Truncating to
    /// the low half used to make this threshold admit every CID.
    #[test]
    fn the_widest_u128_threshold_does_not_admit_every_cid() {
        let peer = random_peer_id();
        let manager = ShardManager::new(
            peer,
            ShardingConfig {
                max_xor_distance: u128::MAX,
                ..Default::default()
            },
        );
        let admitted = (0u8..32)
            .filter(|i| manager.should_cache(&ContentId([*i; 32])))
            .count();
        assert_eq!(
            admitted, 0,
            "a 256-bit distance above u128::MAX was called close"
        );
        // The full distance really does carry upper bits for these CIDs.
        assert!(manager.xor_distance(&ContentId([7u8; 32])).0 > U256::from(u128::MAX));
    }

    #[test]
    fn test_should_cache_respects_threshold() {
        let peer = random_peer_id();
        let config = ShardingConfig {
            max_xor_distance: 0, // Only exact match
            ..Default::default()
        };

        let manager = ShardManager::new(peer, config);
        let cid = ContentId([0xEE; 32]);

        // Very unlikely to be 0
        assert!(!manager.should_cache(&cid));
    }
}
