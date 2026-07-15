//! B.U.D. Content Discovery — Kademlia DHT-based CID → peer mapping.
//!
//! Uses libp2p's Kademlia DHT to announce which content chunks a node
//! holds ("provider records") and to discover which peers hold a given
//! CID ("provider queries").
//!
//! # How It Works
//!
//! 1. **Provider announcement:** When a chunk is stored locally, the
//!    node calls `announce_content(cid)` to register itself as a
//!    provider in the DHT.
//! 2. **Provider query:** When a chunk is needed, the node calls
//!    `find_providers(cid)` to discover peers that have announced it.
//! 3. **Bitswap exchange:** Once providers are found, the Bitswap
//!    protocol is used to fetch the actual data.
//!
//! # DHT Key Mapping
//!
//! `ContentId` (32 bytes) is used directly as the Kademlia key.
//! The Kademlia `RecordKey` is constructed from the raw bytes.

use crate::store::ContentId;
use libp2p::kad::RecordKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Configuration for the content discovery layer.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to re-announce stored content to the DHT.
    /// Kademlia provider records expire after 24h by default;
    /// re-announcing every 12h keeps them fresh.
    pub reannounce_interval: Duration,
    /// Maximum number of providers to track per CID.
    pub max_providers_per_cid: usize,
    /// Maximum number of CIDs to track in the local cache.
    pub max_cached_cids: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            reannounce_interval: Duration::from_secs(12 * 60 * 60), // 12 hours
            max_providers_per_cid: 20,
            max_cached_cids: 50_000,
        }
    }
}

/// A discovered provider for a given CID.
#[derive(Debug, Clone)]
pub struct Provider {
    /// The peer ID of the provider.
    pub peer_id: PeerId,
    /// When this provider was discovered.
    pub discovered_at: Instant,
    /// Whether we've successfully fetched from this peer.
    pub verified: bool,
}

/// Local cache of content discovery results.
///
/// Tracks which peers have announced which CIDs. This cache is
/// populated by DHT provider queries and can also be manually
/// updated when peers respond to Bitswap requests.
struct DiscoveryCache {
    /// CID → set of known providers.
    providers: BTreeMap<ContentId, BTreeSet<PeerId>>,
    /// CID → last announcement time (for re-announcement scheduling).
    last_announced: BTreeMap<ContentId, Instant>,
    /// Configuration.
    config: DiscoveryConfig,
}

/// Content discovery layer — bridges the Kademlia DHT with the
/// Bitswap protocol.
///
/// This struct manages the local cache of provider records and
/// provides methods for announcing content and finding providers.
/// The actual DHT operations are performed by the libp2p swarm
/// (which holds the `kad::Behaviour`); this struct coordinates
/// between the swarm and the content store.
pub struct ContentDiscovery {
    cache: Arc<RwLock<DiscoveryCache>>,
}

impl ContentDiscovery {
    /// Create a new discovery layer with the given configuration.
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            cache: Arc::new(RwLock::new(DiscoveryCache {
                providers: BTreeMap::new(),
                last_announced: BTreeMap::new(),
                config,
            })),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Convert a `ContentId` to a Kademlia `RecordKey`.
    pub fn cid_to_key(cid: &ContentId) -> RecordKey {
        RecordKey::new(&cid.0)
    }

    /// Convert a Kademlia `RecordKey` back to a `ContentId`.
    /// Returns `None` if the key is not 32 bytes.
    pub fn key_to_cid(key: &RecordKey) -> Option<ContentId> {
        let bytes = key.as_ref();
        if bytes.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        Some(ContentId(id))
    }

    /// Record that a local CID should be announced to the DHT.
    /// Returns `true` if the CID needs to be (re-)announced (i.e.,
    /// it's new or the re-announce interval has elapsed).
    pub fn should_announce(&self, cid: &ContentId) -> bool {
        let cache = self.cache.read().unwrap();
        match cache.last_announced.get(cid) {
            None => true,
            Some(last) => last.elapsed() >= cache.config.reannounce_interval,
        }
    }

    /// Mark a CID as announced to the DHT.
    pub fn mark_announced(&self, cid: &ContentId) {
        let mut cache = self.cache.write().unwrap();

        // Evict oldest if at capacity.
        if cache.last_announced.len() >= cache.config.max_cached_cids
            && !cache.last_announced.contains_key(cid)
        {
            if let Some(oldest) = cache
                .last_announced
                .iter()
                .min_by_key(|(_, v)| *v)
                .map(|(k, _)| *k)
            {
                cache.last_announced.remove(&oldest);
                cache.providers.remove(&oldest);
            }
        }

        cache.last_announced.insert(*cid, Instant::now());
    }

    /// Record a discovered provider for a CID.
    pub fn add_provider(&self, cid: &ContentId, peer_id: PeerId) {
        let mut cache = self.cache.write().unwrap();
        let max = cache.config.max_providers_per_cid;
        let providers = cache.providers.entry(*cid).or_default();
        if providers.len() < max {
            providers.insert(peer_id);
        }
    }

    /// Get all known providers for a CID.
    pub fn get_providers(&self, cid: &ContentId) -> Vec<PeerId> {
        let cache = self.cache.read().unwrap();
        cache
            .providers
            .get(cid)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all CIDs that need re-announcement.
    pub fn cids_needing_reannouncement(&self) -> Vec<ContentId> {
        let cache = self.cache.read().unwrap();
        let interval = cache.config.reannounce_interval;
        cache
            .last_announced
            .iter()
            .filter(|(_, last)| last.elapsed() >= interval)
            .map(|(cid, _)| *cid)
            .collect()
    }

    /// Total number of cached CIDs.
    pub fn cached_cid_count(&self) -> usize {
        self.cache.read().unwrap().last_announced.len()
    }

    /// Total number of cached provider records.
    pub fn cached_provider_count(&self) -> usize {
        self.cache
            .read()
            .unwrap()
            .providers
            .values()
            .map(|set| set.len())
            .sum()
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
    fn cid_to_key_roundtrip() {
        let cid = ContentId::of(b"test content for DHT");
        let key = ContentDiscovery::cid_to_key(&cid);
        let recovered = ContentDiscovery::key_to_cid(&key);
        assert_eq!(recovered, Some(cid));
    }

    #[test]
    fn key_to_cid_rejects_wrong_length() {
        let key = RecordKey::new(&[1u8; 16]); // 16 bytes, not 32
        assert!(ContentDiscovery::key_to_cid(&key).is_none());
    }

    #[test]
    fn should_announce_new_cid() {
        let disc = ContentDiscovery::with_defaults();
        let cid = ContentId::of(b"new content");
        assert!(disc.should_announce(&cid));
    }

    #[test]
    fn should_not_announce_recently_announced() {
        let disc = ContentDiscovery::with_defaults();
        let cid = ContentId::of(b"recent content");
        disc.mark_announced(&cid);
        assert!(!disc.should_announce(&cid));
    }

    #[test]
    fn add_and_get_providers() {
        let disc = ContentDiscovery::with_defaults();
        let cid = ContentId::of(b"popular content");
        let peer1 = random_peer_id();
        let peer2 = random_peer_id();

        disc.add_provider(&cid, peer1);
        disc.add_provider(&cid, peer2);

        let providers = disc.get_providers(&cid);
        assert_eq!(providers.len(), 2);
        assert!(providers.contains(&peer1));
        assert!(providers.contains(&peer2));
    }

    #[test]
    fn get_providers_empty_for_unknown_cid() {
        let disc = ContentDiscovery::with_defaults();
        let cid = ContentId::of(b"unknown content");
        assert!(disc.get_providers(&cid).is_empty());
    }

    #[test]
    fn cids_needing_reannouncement_empty_initially() {
        let disc = ContentDiscovery::with_defaults();
        assert!(disc.cids_needing_reannouncement().is_empty());
    }

    #[test]
    fn cids_needing_reannouncement_after_interval() {
        let config = DiscoveryConfig {
            reannounce_interval: Duration::from_millis(1), // 1ms for testing
            max_providers_per_cid: 10,
            max_cached_cids: 100,
        };
        let disc = ContentDiscovery::new(config);
        let cid = ContentId::of(b"stale announcement");

        disc.mark_announced(&cid);
        std::thread::sleep(Duration::from_millis(5));

        let stale = disc.cids_needing_reannouncement();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], cid);
    }

    #[test]
    fn eviction_at_capacity() {
        let config = DiscoveryConfig {
            reannounce_interval: Duration::from_secs(3600),
            max_providers_per_cid: 10,
            max_cached_cids: 3,
        };
        let disc = ContentDiscovery::new(config);

        for i in 0..4 {
            let cid = ContentId::of(&format!("chunk {}", i).into_bytes());
            disc.mark_announced(&cid);
        }

        // Only 3 CIDs should remain.
        assert_eq!(disc.cached_cid_count(), 3);
    }
}
