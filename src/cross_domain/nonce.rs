use crate::core::address::Address;
use crate::domain::types::DomainId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum blocks before a settled bridge row can be dropped.
/// Must be >= the maximum reorg depth for the chain's consensus. The bridge
/// derives its settled-row retention from this depth, so the two horizons
/// cannot drift apart by an edit to one of them.
pub const FINALITY_PRUNE_DEPTH: u64 = 1000;

/// Replay protection for cross-domain messages, held as one high-water mark
/// per (source, target, sender) direction.
///
/// The store used to remember every processed message id in a set (plus a
/// height per id). Replay memory was therefore proportional to traffic, and
/// the interim fix bounded it with a cap that evicted the oldest rows - a
/// bound that paid for itself by opening a replay window measured in
/// whatever the eviction horizon was.
///
/// The high-water mark removes the trade-off instead of negotiating it.
/// Message nonces are assigned sequentially per direction and sender by
/// [`ReplayNonceStore::next_nonce`], so "this direction already processed
/// nonce `n`" is exactly "the high water is at or past `n`". One row per
/// bridging sender bounds the memory by the number of distinct senders, no
/// eviction ever runs, and a processed nonce stays refused for the life of
/// the store because the mark only moves forward.
///
/// Gap semantics: accepting nonce `n` advances the mark past every
/// unprocessed `n' < n`, and a delayed pre-gap message is then refused. Its
/// transfer stays `Locked` and the expiry sweep refunds the owner, so the
/// sender loses nothing; the strict alternative - accepting only
/// `high_water + 1` - would let one abandoned lock wedge every later mint
/// of the same sender forever.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayNonceStore {
    #[serde(with = "crate::core::map_keys")]
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    /// The highest processed message nonce per direction and sender, with
    /// the block height at which the mark was last advanced. The height is
    /// committed in [`ReplayNonceStore::root`], so two nodes that process
    /// the same message at different heights carry different roots - the
    /// mark moves inside block execution, and until it does the height is
    /// part of the honest record.
    #[serde(with = "crate::core::map_keys")]
    processed_high_water: BTreeMap<(DomainId, DomainId, Address), (u64, u64)>,
}

/// There is no reader for the store shape that ended after
/// `processed_messages` + `processed_at_height`, and none for the shorter
/// per-message row before it.
///
/// One existed (`LegacyReplayNonceStoreV1`): it decoded the shorter row and
/// filled the heights with nothing. `root()` committed those heights, so a
/// node that loaded the shorter row committed a different global header
/// than a peer holding the same ids with their heights. No network has
/// launched, so no such row exists to be loyal to; the loader in
/// `storage/db.rs` refuses a row the current shape does not decode, and
/// says why, instead of quietly diverging.
impl ReplayNonceStore {
    pub fn new() -> Self {
        Self {
            outbound_nonces: BTreeMap::new(),
            processed_high_water: BTreeMap::new(),
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

    /// Has this direction already processed `nonce` for `sender`?
    pub fn is_processed(
        &self,
        source_domain: DomainId,
        target_domain: DomainId,
        sender: &Address,
        nonce: u64,
    ) -> bool {
        self.processed_high_water
            .get(&(source_domain, target_domain, *sender))
            .is_some_and(|(high_water, _)| nonce <= *high_water)
    }

    /// Advance the per-direction high-water mark to `nonce`.
    ///
    /// Refuses any nonce at or below the current mark: an exact repeat is a
    /// replay, and a nonce the mark already passed is spent (see the gap
    /// semantics on the struct). The height is recorded next to the mark and
    /// committed in [`ReplayNonceStore::root`].
    pub fn mark_processed_at(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        sender: &Address,
        nonce: u64,
        current_height: u64,
    ) -> Result<(), String> {
        let key = (source_domain, target_domain, *sender);
        if let Some((high_water, _)) = self.processed_high_water.get(&key) {
            if nonce <= *high_water {
                return Err("Cross-domain message was already processed".into());
            }
        }
        self.processed_high_water
            .insert(key, (nonce, current_height));
        Ok(())
    }

    /// Number of distinct (direction, sender) rows the replay memory holds.
    /// Bounded by the number of distinct bridging senders, never by traffic.
    pub fn processed_count(&self) -> usize {
        self.processed_high_water.len()
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

        for ((source, target, sender), (high_water, height)) in &self.processed_high_water {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_PROCESSED_HIGH_WATER_LEAF_V1",
                &source.to_le_bytes(),
                &target.to_le_bytes(),
                sender.as_bytes(),
                &high_water.to_le_bytes(),
                &height.to_le_bytes(),
            ]));
        }

        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn the_first_nonce_zero_is_accepted_then_refused_as_a_replay() {
        let mut store = ReplayNonceStore::new();
        let s = sender(7);
        assert!(!store.is_processed(1, 2, &s, 0));
        assert!(store.mark_processed_at(1, 2, &s, 0, 1).is_ok());
        assert!(store.is_processed(1, 2, &s, 0));
        assert_eq!(
            store.mark_processed_at(1, 2, &s, 0, 2),
            Err("Cross-domain message was already processed".to_string())
        );
    }

    #[test]
    fn any_nonce_at_or_below_the_high_water_is_refused() {
        let mut store = ReplayNonceStore::new();
        let s = sender(7);
        store.mark_processed_at(1, 2, &s, 3, 10).unwrap();
        for spent in [0u64, 1, 2, 3] {
            assert!(store.mark_processed_at(1, 2, &s, spent, 11).is_err());
            assert!(store.is_processed(1, 2, &s, spent));
        }
        assert!(store.mark_processed_at(1, 2, &s, 4, 12).is_ok());
    }

    #[test]
    fn a_gap_advances_the_high_water_past_the_missing_nonces() {
        let mut store = ReplayNonceStore::new();
        let s = sender(7);
        assert!(store.mark_processed_at(1, 2, &s, 5, 100).is_ok());
        assert!(
            store.mark_processed_at(1, 2, &s, 4, 101).is_err(),
            "a nonce the high water already passed is spent, replay or not"
        );
        assert!(
            !store.is_processed(1, 2, &s, 6),
            "a nonce above the high water is still new"
        );
    }

    #[test]
    fn senders_and_directions_are_independent() {
        let mut store = ReplayNonceStore::new();
        let a = sender(1);
        let b = sender(2);
        store.mark_processed_at(1, 2, &a, 0, 1).unwrap();
        // Same nonce, different sender: an independent row.
        assert!(store.mark_processed_at(1, 2, &b, 0, 1).is_ok());
        // Same sender, different direction: an independent row.
        assert!(store.mark_processed_at(1, 3, &a, 0, 1).is_ok());
        assert!(store.mark_processed_at(2, 1, &a, 0, 1).is_ok());
        assert_eq!(store.processed_count(), 4);
        assert!(store.is_processed(1, 2, &a, 0));
        assert!(!store.is_processed(1, 2, &a, 1));
    }

    #[test]
    fn the_row_count_is_bounded_by_distinct_senders() {
        let mut store = ReplayNonceStore::new();
        let s = sender(7);
        for nonce in 0..50u64 {
            assert!(store.mark_processed_at(1, 2, &s, nonce, 10 + nonce).is_ok());
        }
        assert_eq!(
            store.processed_count(),
            1,
            "one sender is one row, whatever the traffic"
        );
        assert!(store.mark_processed_at(1, 2, &sender(8), 0, 60).is_ok());
        assert_eq!(store.processed_count(), 2);
    }

    #[test]
    fn heights_stay_committed_in_the_replay_root() {
        let s = sender(7);
        let mut first = ReplayNonceStore::new();
        first.mark_processed_at(1, 2, &s, 3, 7).unwrap();
        let mut second = ReplayNonceStore::new();
        second.mark_processed_at(1, 2, &s, 3, 8).unwrap();
        assert_ne!(
            first.root(),
            second.root(),
            "the same mark advanced at different heights must not share a root"
        );
        let mut third = ReplayNonceStore::new();
        third.mark_processed_at(1, 2, &s, 3, 7).unwrap();
        assert_eq!(first.root(), third.root());
    }

    #[test]
    fn the_high_water_survives_the_persisted_encoding() {
        let mut store = ReplayNonceStore::new();
        let s = sender(7);
        store.mark_processed_at(1, 2, &s, 3, 123).unwrap();
        let _ = store.next_nonce(1, 2, s);
        let bytes = bincode::serialize(&store).expect("the store serializes");
        let reloaded: ReplayNonceStore =
            bincode::deserialize(&bytes).expect("the store deserializes");
        assert!(reloaded.is_processed(1, 2, &s, 3));
        assert!(!reloaded.is_processed(1, 2, &s, 4));
        assert_eq!(reloaded.processed_count(), 1);
        assert_eq!(
            reloaded.root(),
            store.root(),
            "the reloaded store must reproduce the committed root bit for bit"
        );
    }

    /// The row shape that remembered every processed message id (with or
    /// without its heights) is refused.
    ///
    /// A per-message row decoded through a legacy shape put a different
    /// `replay_nonce_root` into this node's global header than its peers
    /// computed. A shorter row now fails to decode, and the loader reports
    /// it, instead of loading a store whose committed root nobody else can
    /// reproduce.
    #[test]
    fn a_row_from_the_per_message_shape_is_refused() {
        use crate::cross_domain::message::MessageId;
        use std::collections::BTreeSet;

        #[derive(serde::Serialize)]
        struct PerMessageRow {
            #[serde(with = "crate::core::map_keys")]
            outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
            processed_messages: BTreeSet<MessageId>,
        }

        let mut old = PerMessageRow {
            outbound_nonces: BTreeMap::new(),
            processed_messages: BTreeSet::new(),
        };
        old.outbound_nonces
            .insert((1, 2, Address::from([9u8; 32])), 7);
        old.processed_messages.insert([3u8; 32]);
        let bytes = bincode::serialize(&old).expect("old row serializes");

        assert!(
            bincode::deserialize::<ReplayNonceStore>(&bytes).is_err(),
            "the current shape must not silently accept the per-message row"
        );
    }
}
