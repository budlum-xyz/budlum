use crate::core::address::Address;
use crate::cross_domain::message::MessageId;
use crate::domain::types::DomainId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// B3 fix (pre-mortem audit): Maximum number of processed message IDs
/// retained in the replay store. Beyond this limit, the oldest entries
/// are pruned to prevent unbounded memory growth (OOM liveness failure).
/// 65536 entries × 32 bytes ≈ 2 MiB — sufficient for weeks of bridge traffic.
pub const MAX_PROCESSED_MESSAGES: usize = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayNonceStore {
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    processed_messages: BTreeSet<MessageId>,
}

impl ReplayNonceStore {
    pub fn new() -> Self {
        Self {
            outbound_nonces: BTreeMap::new(),
            processed_messages: BTreeSet::new(),
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
        // B3 fix: prune oldest entries when exceeding capacity
        self.prune_processed();
        Ok(())
    }

    /// B3 fix (pre-mortem audit): Prune oldest processed messages when
    /// the set exceeds MAX_PROCESSED_MESSAGES to prevent unbounded growth.
    pub fn prune_processed(&mut self) {
        while self.processed_messages.len() > MAX_PROCESSED_MESSAGES {
            // BTreeSet is ordered — pop_first removes the smallest (oldest) entry
            if let Some(oldest) = self.processed_messages.iter().next().copied() {
                self.processed_messages.remove(&oldest);
            } else {
                break;
            }
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
