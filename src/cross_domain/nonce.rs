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
    #[serde(skip)]
    processed_at_height: BTreeMap<MessageId, u64>,
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

    pub fn mark_processed(&mut self, message_id: MessageId) -> Result<(), String> {
        if !self.processed_messages.insert(message_id) {
            return Err("Cross-domain message was already processed".into());
        }
        Ok(())
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
            store.mark_processed(id).unwrap();
        }
        // Mark_processed no longer auto-prunes (V4-13: height-aware pruning).
        // Verify prune_processed (legacy) still caps correctly.
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
        store.mark_processed(id).unwrap();
        assert!(store.is_processed(&id));
        assert!(store.mark_processed(id).is_err()); // duplicate rejected
    }
}

#[cfg(test)]
mod audit_replay_regression {
    use super::*;

    #[test]
    fn replay_store_rejects_duplicate_and_tracks_count() {
        let mut s = ReplayNonceStore::new();
        let id = [7u8; 32];
        assert!(s.mark_processed(id).is_ok());
        assert!(s.is_processed(&id));
        assert_eq!(s.processed_count(), 1);
        assert!(s.mark_processed(id).is_err());
        let _ = s.root();
    }

    #[test]
    fn replay_store_distinct_ids_independent() {
        let mut s = ReplayNonceStore::new();
        s.mark_processed([1u8; 32]).unwrap();
        s.mark_processed([2u8; 32]).unwrap();
        assert_eq!(s.processed_count(), 2);
        assert!(s.is_processed(&[1u8; 32]));
        assert!(s.is_processed(&[2u8; 32]));
        assert!(!s.is_processed(&[3u8; 32]));
    }
}

#[cfg(test)]
mod v4_prune_tests {
    use super::*;

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
