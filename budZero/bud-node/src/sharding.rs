//! B.U.D. Active Sharding — determines shard responsibility.
//!
//! Implements the sharding logic from Vision §7: nodes are responsible
//! for a subset of the global storage state based on the distance between
//! their `PeerId` and the `ContentId` (CID) of the shard.
//!
//! # Responsibility Rule
//!
//! A node is a "responsible host" for a shard if:
//! 1. The shard is assigned to them via an on-chain `StorageDeal`.
//! 2. The node's `PeerId` is among the K-closest peers to the CID in the DHT.

use crate::store::ContentId;
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
    /// Mobile mode (ADIM 5 §5.2): Lighter sharding, battery-aware.
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
    /// just wait for deals; they help maintain the network's health by
    /// caching CIDs that are "close" to them in the XOR keyspace.
    pub fn should_cache(&self, cid: &ContentId) -> bool {
        if self.config.mobile_mode && !self.is_resource_buffer_sufficient() {
            return false; // Skip caching on mobile if low on battery/budget
        }
        let distance = self.xor_distance(cid);
        distance <= self.config.max_xor_distance
    }

    /// Resource budget check for mobile devices (Mock/Placeholder).
    /// In a real mobile app, this would check battery level and Wi-Fi status.
    pub fn is_resource_buffer_sufficient(&self) -> bool {
        // Placeholder: Always true in simulation,
        // would be linked to OS-level battery/metered connection API.
        true
    }

    /// Calculate the XOR distance between the local PeerId and a CID.
    ///
    /// Both PeerId and ContentId (V1) are based on SHA-256 (32 bytes).
    pub fn xor_distance(&self, cid: &ContentId) -> u128 {
        let peer_bytes = self.local_peer_id.to_bytes();
        // Take the last 16 bytes for a u128 distance metric.
        // PeerId bytes vary in length, so we hash it to get a fixed 32 bytes.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&peer_bytes);
        let peer_hash = hasher.finalize();

        let mut dist_bytes = [0u8; 16];
        for i in 0..16 {
            dist_bytes[i] = peer_hash[i + 16] ^ cid.0[i + 16];
        }
        u128::from_be_bytes(dist_bytes)
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
