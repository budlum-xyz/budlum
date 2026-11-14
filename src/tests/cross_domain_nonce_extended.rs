//! Extended cross-domain nonce store tests: finality prune depth, root
//! commitment, and edge cases.

use crate::core::address::Address;
use crate::cross_domain::nonce::{ReplayNonceStore, FINALITY_PRUNE_DEPTH, MAX_NONCE_GAP};

fn sender(byte: u8) -> Address {
    Address::from([byte; 32])
}

#[test]
fn finality_prune_depth_is_at_least_100() {
    const {
        assert!(
            FINALITY_PRUNE_DEPTH >= 100,
            "the prune depth is too shallow for safe finality"
        );
    }
}

#[test]
fn max_nonce_gap_is_65536() {
    assert_eq!(MAX_NONCE_GAP, 65_536);
}

#[test]
fn nonce_store_root_is_deterministic() {
    let mut s1 = ReplayNonceStore::new();
    let mut s2 = ReplayNonceStore::new();
    let addr = sender(7);
    s1.mark_processed_at(1, 2, &addr, 5, 100).unwrap();
    s2.mark_processed_at(1, 2, &addr, 5, 100).unwrap();
    assert_eq!(s1.root(), s2.root());
}

#[test]
fn nonce_store_root_changes_with_height() {
    let addr = sender(7);
    let mut s1 = ReplayNonceStore::new();
    s1.mark_processed_at(1, 2, &addr, 5, 100).unwrap();
    let mut s2 = ReplayNonceStore::new();
    s2.mark_processed_at(1, 2, &addr, 5, 200).unwrap();
    assert_ne!(s1.root(), s2.root());
}

#[test]
fn nonce_store_processed_count_matches_senders() {
    let mut store = ReplayNonceStore::new();
    for i in 0u8..10 {
        let s = sender(i);
        store.mark_processed_at(1, 2, &s, 0, 1).unwrap();
    }
    assert_eq!(store.processed_count(), 10);
}

#[test]
fn next_nonce_increments() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert_eq!(store.next_nonce(1, 2, s), 0);
    assert_eq!(store.next_nonce(1, 2, s), 1);
    assert_eq!(store.next_nonce(1, 2, s), 2);
}

#[test]
fn next_nonce_is_per_direction() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert_eq!(store.next_nonce(1, 2, s), 0);
    assert_eq!(store.next_nonce(2, 1, s), 0);
    assert_eq!(store.next_nonce(1, 2, s), 1);
}

#[test]
fn u64_max_nonce_is_refused() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert!(store.mark_processed_at(1, 2, &s, u64::MAX, 1).is_err());
}

#[test]
fn nonce_store_serde_round_trip() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    store.mark_processed_at(1, 2, &s, 3, 100).unwrap();
    let _ = store.next_nonce(1, 2, s);
    let bytes = bincode::serialize(&store).unwrap();
    let reloaded: ReplayNonceStore = bincode::deserialize(&bytes).unwrap();
    assert_eq!(store.root(), reloaded.root());
    assert_eq!(reloaded.processed_count(), 1);
}
