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
    /// Maximum distance (XOR) allowed for opportunistic caching, in the
    /// DHT's own 256-bit key space: a CID is cached when the Kademlia
    /// distance between the node's bucket key and the CID's record key is at
    /// or below this value. The field used to be a `u128` compared against
    /// that 256-bit distance, which is below `2^128` for one CID in `2^128`,
    /// so no threshold the type could hold admitted anything and active
    /// sharding cached nothing.
    pub max_xor_distance: U256,
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
            max_xor_distance: U256::MAX / 1000u64, // 0.1% of the key space
            mandatory: true,
            mobile_mode: false,
        }
    }
}

impl ShardingConfig {
    pub fn mobile_default() -> Self {
        Self {
            replication_factor: 2,                    // Balance energy and availability
            max_xor_distance: U256::MAX / 100_000u64, // 0.001% of the key space
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
        // Threshold and distance live in the same 256-bit key space, so the
        // whole distance is compared. Truncating the distance to its low half
        // first (`low_u128`) used to let a far CID pass whenever that half
        // happened to be small, including as an exact match under a zero
        // threshold.
        self.xor_distance(cid).0 <= self.config.max_xor_distance
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

    fn fixed_peer_id() -> PeerId {
        identity::Keypair::ed25519_from_bytes([7u8; 32])
            .expect("32 secret bytes")
            .public()
            .to_peer_id()
    }

    fn cids(n: u32) -> impl Iterator<Item = ContentId> {
        (0..n).map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            ContentId(bytes)
        })
    }

    /// The threshold is a share of the 256-bit key space and admits that
    /// share of CIDs: an eighth of the space takes in about an eighth of
    /// 2048 CIDs (256 expected, the bounds are more than ten standard
    /// deviations wide), and the default tenth of a percent takes in a
    /// handful. The old `u128` threshold, however wide, admitted none of
    /// them: the distance has upper bits for every CID here.
    #[test]
    fn the_threshold_admits_its_share_of_the_key_space() {
        let peer = fixed_peer_id();
        let eighth = ShardManager::new(
            peer,
            ShardingConfig {
                max_xor_distance: U256::MAX / 8u64,
                ..Default::default()
            },
        );
        let admitted = cids(2048).filter(|c| eighth.should_cache(c)).count();
        assert!(
            (100..=410).contains(&admitted),
            "an eighth of the key space admitted {admitted} of 2048 CIDs"
        );
        let default = ShardManager::new(peer, ShardingConfig::default());
        let admitted = cids(2048).filter(|c| default.should_cache(c)).count();
        assert!(
            admitted <= 20,
            "a tenth of a percent of the key space admitted {admitted} of 2048 CIDs"
        );
        assert!(cids(2048).all(|c| default.xor_distance(&c).0 > U256::from(u128::MAX)));
    }

    /// The whole key space as the threshold is every CID; nothing else in
    /// the comparison can refuse one.
    #[test]
    fn the_widest_threshold_admits_every_cid() {
        let manager = ShardManager::new(
            fixed_peer_id(),
            ShardingConfig {
                max_xor_distance: U256::MAX,
                ..Default::default()
            },
        );
        assert!(cids(256).all(|c| manager.should_cache(&c)));
    }

    #[test]
    fn test_should_cache_respects_threshold() {
        let peer = random_peer_id();
        let config = ShardingConfig {
            max_xor_distance: U256::zero(), // Only exact match
            ..Default::default()
        };

        let manager = ShardManager::new(peer, config);
        let cid = ContentId([0xEE; 32]);

        // Very unlikely to be 0
        assert!(!manager.should_cache(&cid));
    }
}
