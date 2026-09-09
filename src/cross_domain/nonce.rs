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

/// Minimum blocks before a processed message can be pruned.
/// Must be >= the maximum reorg depth for the chain's consensus. The bridge
/// derives its settled-row retention from this depth, so the two horizons
/// cannot drift apart by an edit to one of them.
pub const FINALITY_PRUNE_DEPTH: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayNonceStore {
    #[serde(with = "crate::core::map_keys")]
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    processed_messages: BTreeSet<MessageId>,
    /// Block height at which each message was processed.
    /// Used for safe height-based pruning that only removes entries after
    /// FINALITY_PRUNE_DEPTH blocks - ensuring replay protection covers the
    /// Finality window. Rows younger than the depth leave only when the
    /// store is over MAX_PROCESSED_MESSAGES and the finality band has
    /// nothing older to release; the eviction order is oldest first, so the
    /// replay window a bound can open is measured in the oldest rows the
    /// store still held.
    ///
    /// Persisted with the rest of the store. It used to be `#[serde(skip)]`,
    /// which meant a restarted node reloaded every processed id with no
    /// height next to it; `prune_processed_safe` filters on the heights, so
    /// nothing was ever old enough to prune and the bound this map exists
    /// for was gone after the first restart. Replay protection did not
    /// suffer (the ids were kept); the memory bound did.
    #[serde(with = "crate::core::map_keys")]
    processed_at_height: BTreeMap<MessageId, u64>,
}

/// There is no reader for the store shape that ended after
/// `processed_messages`.
///
/// One existed (`LegacyReplayNonceStoreV1`): it decoded the shorter row and
/// filled `processed_at_height` with nothing. `root()` hashes every height
/// entry, `BridgeState::replay_root` hands that root to `build_global_header`
/// as `replay_nonce_root`, so a node that loaded the shorter row committed a
/// different global header than a peer holding the same ids with their
/// heights. No network has launched, so no such row exists to be loyal to;
/// the loader in `storage/db.rs` refuses a row the current shape does not
/// decode, and says why, instead of quietly diverging.
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

    /// Legacy count-based prune, kept for the paths that have no height in
    /// hand. The eviction order is the shared oldest-first order; the
    /// previous version removed the smallest message id, which is an
    /// ordering on the id bytes with no relation to age: a fresh message
    /// whose id happened to sort below every old one left first, so the
    /// cap spent replay protection on the newest rows and kept stale ones.
    ///
    /// WARNING: A count-based prune does not respect the finality window.
    /// Prefer prune_processed_safe which releases finalized rows first.
    pub fn prune_processed(&mut self) {
        self.enforce_cap_oldest_first();
    }

    /// Evict rows until the set is at most MAX_PROCESSED_MESSAGES, oldest
    /// processed height first, smallest id on equal heights.
    ///
    /// Deterministic on both keys, so nodes that prune at the same height
    /// evict the same rows and the committed root stays reproducible.
    fn enforce_cap_oldest_first(&mut self) {
        let excess = match self
            .processed_messages
            .len()
            .checked_sub(MAX_PROCESSED_MESSAGES)
        {
            Some(excess) if excess > 0 => excess,
            _ => return,
        };
        let mut by_age: Vec<(u64, MessageId)> = self
            .processed_at_height
            .iter()
            .map(|(id, height)| (*height, *id))
            .collect();
        by_age.sort_unstable();
        for (_, id) in by_age.into_iter().take(excess) {
            self.processed_messages.remove(&id);
            self.processed_at_height.remove(&id);
        }
    }

    /// Height-aware pruning: release finalized rows first, then hold the
    /// cap even when the whole set is younger than the finality depth.
    ///
    /// The old header called MAX_PROCESSED_MESSAGES a hard cap while the
    /// body only removed rows below the finality cutoff. A set filled with
    /// messages newer than the cutoff never shrank: the cap existed in the
    /// comment and nowhere else, and the test suite pinned that growth as
    /// a property. An unbounded set is a liveness failure the node cannot
    /// recover from; a bounded set that evicts oldest-first opens the
    /// smallest replay window a bound can open, and only when the
    /// finalized band had nothing left to give.
    pub fn prune_processed_safe(&mut self, current_height: u64) {
        if self.processed_messages.len() <= MAX_PROCESSED_MESSAGES {
            return;
        }
        // Finalized first: removing these opens no replay window at all.
        let cutoff = current_height.saturating_sub(FINALITY_PRUNE_DEPTH);
        let finalized: Vec<MessageId> = self
            .processed_at_height
            .iter()
            .filter(|(_, height)| **height < cutoff)
            .map(|(id, _)| *id)
            .collect();
        for id in &finalized {
            self.processed_messages.remove(id);
            self.processed_at_height.remove(id);
        }
        // Whatever the finality band could not release, the cap must.
        self.enforce_cap_oldest_first();
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

        // State-root V2 migration: heights were added to persisted replay
        // state after the original processed-message leaf was defined. Keep
        // that membership leaf and commit the height map separately so a
        // height-only state difference cannot produce the same root.
        for (message_id, processed_at_height) in &self.processed_at_height {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_PROCESSED_HEIGHT_LEAF_V1",
                message_id,
                &processed_at_height.to_le_bytes(),
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
        // Marking at height zero releases nothing through the finality band
        // (V4-13); the cap holds anyway, through oldest-first eviction, and
        // the legacy entry point agrees: there is nothing left to remove.
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

    #[test]
    fn processed_height_changes_the_replay_root() {
        let id = [42u8; 32];
        let mut first = ReplayNonceStore::new();
        first.mark_processed_at(id, 7).unwrap();
        let mut second = first.clone();
        second.processed_at_height.insert(id, 8);

        assert_ne!(first.root(), second.root());
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

    /// The row shape that ended after `processed_messages` is refused.
    ///
    /// It used to be decoded through a legacy shape that left every height
    /// empty, which put a different `replay_nonce_root` into this node's
    /// global header than its peers computed. A shorter row now fails to
    /// decode, and the loader reports it, instead of loading a store whose
    /// committed root nobody else can reproduce.
    #[test]
    fn a_row_without_heights_is_refused() {
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
        // The cap held during insertion itself (oldest-first eviction), so
        // the row that round-trips is exactly at the cap, heights included.
        assert_eq!(store.processed_count(), MAX_PROCESSED_MESSAGES);
        let bytes = bincode::serialize(&store).expect("the store serializes");
        let mut reloaded: ReplayNonceStore =
            bincode::deserialize(&bytes).expect("the store deserializes");
        assert_eq!(reloaded.processed_count(), MAX_PROCESSED_MESSAGES);
        // Every reloaded row was processed at height 10, so at height 2000
        // the whole set is finalized and the reloaded store must be able to
        // release it: the heights survived the encoding, not just the ids.
        reloaded.prune_processed_safe(2000);
        assert_eq!(
            reloaded.processed_count(),
            0,
            "a reloaded store must still be able to prune entries past the finality depth"
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
        // Simulate more than MAX messages, all at old heights. Insertion
        // holds the cap through oldest-first eviction, so the set settles
        // at MAX with the newest rows.
        for i in 0..(MAX_PROCESSED_MESSAGES + 50) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 10).unwrap(); // all at height 10
        }
        assert_eq!(store.processed_count(), MAX_PROCESSED_MESSAGES);
        // Prune at height 2000 (well beyond FINALITY_PRUNE_DEPTH=1000):
        // every remaining row is finalized and the finality band alone
        // empties the set; the cap never has to evict in-window rows here.
        store.prune_processed_safe(2000);
        assert_eq!(
            store.processed_count(),
            0,
            "old messages beyond finality should be pruned"
        );
    }

    /// The reversed pin: this test used to assert that a set filled with
    /// messages younger than the finality depth grew past the cap and kept
    /// every row, which is the unbounded-growth finding stated as a
    /// property. The cap is real now: the finality band has nothing to
    /// release at these heights, so the oldest rows leave, in (height, id)
    /// order, and the store settles at the cap with the newest rows.
    #[test]
    fn over_cap_recent_rows_are_evicted_oldest_first() {
        let mut store = ReplayNonceStore::new();
        // Fill past MAX with recent messages
        for i in 0..(MAX_PROCESSED_MESSAGES + 100) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.mark_processed_at(id, 999).unwrap(); // all at height 999
        }
        // Prune at height 1000 - cutoff = 1000-1000=0, nothing is below 0
        store.prune_processed_safe(1000);
        assert_eq!(
            store.processed_count(),
            MAX_PROCESSED_MESSAGES,
            "the cap must hold even when every row is inside the finality window"
        );
        // All heights are equal, so the eviction order falls to the id:
        // the smallest ids left first, the newest hundred survived.
        for i in 0..100u64 {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&i.to_le_bytes());
            assert!(
                !store.is_processed(&id),
                "id {i} is among the oldest rows and must have been evicted"
            );
        }
        for i in (MAX_PROCESSED_MESSAGES as u64 + 50)..(MAX_PROCESSED_MESSAGES as u64 + 100) {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&i.to_le_bytes());
            assert!(store.is_processed(&id), "id {i} is among the newest rows");
        }
    }
}
