use crate::core::address::Address;
use crate::cross_domain::message::MessageId;
use crate::domain::types::DomainId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of processed message IDs
/// Retained in the replay store. Beyond this limit, the oldest entries
/// Are pruned to prevent unbounded memory growth (OOM liveness failure).
/// 65536 entries × 32 bytes ≈ 2 MiB - sufficient for weeks of bridge traffic.
pub const MAX_PROCESSED_MESSAGES: usize = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayNonceStore {
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    processed_messages: BTreeSet<MessageId>,
    /// Block height at which each message was processed.
    /// Used for safe height-based pruning that only removes entries after
    /// FINALITY_PRUNE_DEPTH blocks - ensuring replay protection covers the
    /// Finality window. Messages younger than the depth are never pruned.
    ///
    /// Persisted with the rest of the store. It used to be `#[serde(skip)]`,
    /// which meant a restarted node reloaded every processed id with no
    /// height next to it; `prune_processed_safe` filters on the heights, so
    /// nothing was ever old enough to prune and the bound this map exists
    /// for was gone after the first restart. Replay protection did not
    /// suffer (the ids were kept); the memory bound did.
    processed_at_height: BTreeMap<MessageId, u64>,
}

/// On-disk shape of the store before `processed_at_height` was persisted.
///
/// Bincode is positional, so a record written by the older build ends after
/// `processed_messages`; serde defaults alone cannot recover it. A store
/// loaded through this shape has every id and no heights, exactly what the
/// older build held in memory after a restart, so nothing it could prune
/// before becomes prunable now, and nothing it refused becomes accepted.
#[derive(Deserialize)]
pub struct LegacyReplayNonceStoreV1 {
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    processed_messages: BTreeSet<MessageId>,
}

impl From<LegacyReplayNonceStoreV1> for ReplayNonceStore {
    fn from(legacy: LegacyReplayNonceStoreV1) -> Self {
        Self {
            outbound_nonces: legacy.outbound_nonces,
            processed_messages: legacy.processed_messages,
            processed_at_height: BTreeMap::new(),
        }
    }
}

impl ReplayNonceStore {
    pub fn new() -> Self {
        Self {
            outbound_nonces: BTreeMap::new(),
            processed_messages: BTreeSet::new(),
            processed_at_height: BTreeMap::new(),
        }
    }

    pub fn next_nonce(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        sender: Address,
    ) -> u64 {
        let key = (source_domain, target_domain, sender);
        let nonce = self.outbound_nonces.get(&key).copied().unwrap_or(0);
        self.outbound_nonces.insert(key, nonce.saturating_add(1));
        nonce
    }

    /// Mark processed with block height for safe pruning.
    /// The height is recorded so that pruning only removes entries that are
    /// Deeper than FINALITY_PRUNE_DEPTH blocks, preventing replay within
    /// The finality window.
    pub fn mark_processed_at(
        &mut self,
        message_id: MessageId,
        current_height: u64,
    ) -> Result<(), String> {
        if !self.processed_messages.insert(message_id) {
            return Err("Cross-domain message was already processed".into());
        }
        self.processed_at_height.insert(message_id, current_height);
        // Safe prune: only remove entries older than finality depth
        self.prune_processed_safe(current_height);
        Ok(())
    }

    /// Fix (legacy - kept for backward compat): Unconditional count-based prune.
    /// WARNING: This can create a replay window for pruned messages.
    /// Prefer prune_processed_safe which respects finality depth.
    pub fn prune_processed(&mut self) {
        while self.processed_messages.len() > MAX_PROCESSED_MESSAGES {
            if let Some(oldest) = self.processed_messages.iter().next().copied() {
                self.processed_messages.remove(&oldest);
                self.processed_at_height.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Height-aware pruning that only removes
    /// Messages processed at least FINALITY_PRUNE_DEPTH blocks ago.
    /// This prevents replay attacks within the finality window while
    /// Still bounding memory usage for long-running nodes.
    pub fn prune_processed_safe(&mut self, current_height: u64) {
        /// Minimum blocks before a processed message can be pruned.
        /// Must be >= the maximum reorg depth for the chain's consensus.
        const FINALITY_PRUNE_DEPTH: u64 = 1000;

        // Hard cap: even with height awareness, bound the set size
        if self.processed_messages.len() <= MAX_PROCESSED_MESSAGES {
            return;
        }
        // Only prune entries that are safely finalized
        let cutoff = current_height.saturating_sub(FINALITY_PRUNE_DEPTH);
        let to_remove: Vec<MessageId> = self
            .processed_at_height
            .iter()
            .filter(|(_, h)| **h < cutoff)
            .map(|(id, _)| *id)
            .collect();
        for id in &to_remove {
            self.processed_messages.remove(id);
            self.processed_at_height.remove(id);
        }
    }

    /// Returns the number of processed messages currently stored.
    pub fn processed_count(&self) -> usize {
        self.processed_messages.len()
    }

    pub fn is_processed(&self, message_id: &MessageId) -> bool {
        self.processed_messages.contains(message_id)
    }

    pub fn root(&self) -> [u8; 32] {
        let mut leaves = Vec::new();

        for ((source, target, sender), nonce) in &self.outbound_nonces {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_NONCE_LEAF_V1",
                &source.to_le_bytes(),
                &target.to_le_bytes(),
                sender.as_bytes(),
                &nonce.to_le_bytes(),
            ]));
        }

        for message_id in &self.processed_messages {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_PROCESSED_MESSAGE_LEAF_V1",
                message_id,
            ]));
        }

        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b3_prune_limits_processed_messages() {
        let mut store = ReplayNonceStore::new();
        // Insert MAX + 10 messages
        for i in 0..(MAX_PROCESSED_MESSAGES + 10) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 0).unwrap();
        }
        // Marking at height zero never triggers the height-aware prune
        // (V4-13), so the set is allowed to grow here; this verifies the
        // legacy prune_processed still caps correctly.
        store.prune_processed();
        assert!(
            store.processed_count() <= MAX_PROCESSED_MESSAGES,
            "prune should keep count at or below MAX"
        );
    }

    #[test]
    fn replay_protection_still_works_after_prune() {
        let mut store = ReplayNonceStore::new();
        let id = [42u8; 32];
        store.mark_processed_at(id, 0).unwrap();
        assert!(store.is_processed(&id));
        assert!(store.mark_processed_at(id, 0).is_err()); // duplicate rejected
    }
}

#[cfg(test)]
mod audit_replay_regression {
    use super::*;

    #[test]
    fn replay_store_rejects_duplicate_and_tracks_count() {
        let mut s = ReplayNonceStore::new();
        let id = [7u8; 32];
        assert!(s.mark_processed_at(id, 0).is_ok());
        assert!(s.is_processed(&id));
        assert_eq!(s.processed_count(), 1);
        assert!(s.mark_processed_at(id, 0).is_err());
        let _ = s.root();
    }

    #[test]
    fn replay_store_distinct_ids_independent() {
        let mut s = ReplayNonceStore::new();
        s.mark_processed_at([1u8; 32], 0).unwrap();
        s.mark_processed_at([2u8; 32], 0).unwrap();
        assert_eq!(s.processed_count(), 2);
        assert!(s.is_processed(&[1u8; 32]));
        assert!(s.is_processed(&[2u8; 32]));
        assert!(!s.is_processed(&[3u8; 32]));
    }
}

#[cfg(test)]
mod v4_prune_tests {
    use super::*;

    /// A store written by the older build still loads.
    ///
    /// The older row ends after `processed_messages`. Encoding that shape and
    /// decoding it through `LegacyReplayNonceStoreV1` must give back every id
    /// with no heights, which is what the older build itself held after a
    /// restart. Decoding it as the current shape must fail, which is what
    /// makes the fallback in `storage/db.rs` reachable rather than dead.
    #[test]
    fn legacy_store_rows_still_load() {
        #[derive(serde::Serialize)]
        struct OldRow {
            outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
            processed_messages: BTreeSet<MessageId>,
        }
        let mut old = OldRow {
            outbound_nonces: BTreeMap::new(),
            processed_messages: BTreeSet::new(),
        };
        old.outbound_nonces
            .insert((1, 2, Address::from([9u8; 32])), 7);
        old.processed_messages.insert([3u8; 32]);
        let bytes = bincode::serialize(&old).expect("old row serializes");

        assert!(
            bincode::deserialize::<ReplayNonceStore>(&bytes).is_err(),
            "the current shape must not silently accept the shorter row"
        );
        let legacy: LegacyReplayNonceStoreV1 =
            bincode::deserialize(&bytes).expect("the legacy shape decodes the old row");
        let mut store = ReplayNonceStore::from(legacy);
        assert!(store.is_processed(&[3u8; 32]));
        assert_eq!(store.processed_count(), 1);
        assert_eq!(store.next_nonce(1, 2, Address::from([9u8; 32])), 7);
        assert!(store.mark_processed_at([3u8; 32], 5).is_err());
    }

    /// The heights survive a round trip through the store's own encoding.
    ///
    /// `processed_at_height` was marked `#[serde(skip)]`, so a node that
    /// restarted (or restored from a snapshot) loaded every processed
    /// message id with no height next to it. `prune_processed_safe` filters
    /// on those heights, so on such a node nothing was ever old enough to
    /// prune, and the set the bound was written for grew without bound for
    /// the rest of the node's uptime. Replay protection was not weakened
    /// (the ids were still there); the memory bound was gone.
    ///
    /// The store is persisted with bincode (`storage/db.rs`) and hashed into
    /// the snapshot digest, so the round trip is asserted on bincode.
    #[test]
    fn processed_heights_survive_the_persisted_encoding() {
        let mut store = ReplayNonceStore::new();
        for i in 0..(MAX_PROCESSED_MESSAGES + 50) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 10).unwrap();
        }
        let bytes = bincode::serialize(&store).expect("the store serializes");
        let mut reloaded: ReplayNonceStore =
            bincode::deserialize(&bytes).expect("the store deserializes");
        assert_eq!(reloaded.processed_count(), MAX_PROCESSED_MESSAGES + 50);
        reloaded.prune_processed_safe(2000);
        assert!(
            reloaded.processed_count() <= MAX_PROCESSED_MESSAGES,
            "a reloaded store must still be able to prune entries past the finality depth, \
             got {} entries",
            reloaded.processed_count()
        );
        // Replay protection is unchanged by the reload.
        let mut recent = [0xEEu8; 32];
        recent[0] = 1;
        assert!(reloaded.mark_processed_at(recent, 2000).is_ok());
        assert!(reloaded.mark_processed_at(recent, 2001).is_err());
    }

    #[test]
    fn v4_13_height_aware_prune_preserves_recent_messages() {
        let mut store = ReplayNonceStore::new();
        // Process messages at various heights
        for i in 0..100u64 {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&i.to_le_bytes());
            store.mark_processed_at(id, i * 20).unwrap(); // spread across heights
        }
        assert_eq!(store.processed_count(), 100);
        // Prune at height 500 - only messages before height 500-1000=0 can be pruned
        // Since we have 100 entries (< MAX_PROCESSED_MESSAGES=65536), no pruning occurs
        store.prune_processed_safe(500);
        assert_eq!(
            store.processed_count(),
            100,
            "all messages within finality depth should be kept"
        );
    }

    #[test]
    fn v4_13_prune_removes_old_messages_beyond_finality() {
        let mut store = ReplayNonceStore::new();
        // Simulate more than MAX messages, all at old heights
        for i in 0..(MAX_PROCESSED_MESSAGES + 50) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 10).unwrap(); // all at height 10
        }
        // Prune at height 2000 (well beyond FINALITY_PRUNE_DEPTH=1000)
        store.prune_processed_safe(2000);
        assert!(
            store.processed_count() <= MAX_PROCESSED_MESSAGES,
            "old messages beyond finality should be pruned"
        );
    }

    #[test]
    fn v4_13_recent_messages_never_pruned() {
        let mut store = ReplayNonceStore::new();
        // Fill past MAX with recent messages
        for i in 0..(MAX_PROCESSED_MESSAGES + 100) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 999).unwrap(); // all at height 999
        }
        // Prune at height 1000 - cutoff = 1000-1000=0, nothing is below 0
        store.prune_processed_safe(1000);
        // All messages are at height 999, cutoff is 0, so none are pruned
        assert_eq!(
            store.processed_count(),
            MAX_PROCESSED_MESSAGES + 100,
            "recent messages must NOT be pruned even if over cap"
        );
    }
}
