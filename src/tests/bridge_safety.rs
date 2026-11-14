//! Bridge safety tests: verify the lock-mint-burn-unlock cycle, replay
//! protection, and domain separation.

use crate::core::address::Address;
use crate::cross_domain::nonce::{ReplayNonceStore, MAX_NONCE_GAP};

fn sender(byte: u8) -> Address {
    Address::from([byte; 32])
}

/// ReplayNonceStore rejects duplicate nonces.
#[test]
fn replay_nonce_store_rejects_duplicate() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert!(store.mark_processed_at(1, 2, &s, 0, 1).is_ok());
    assert!(
        store.mark_processed_at(1, 2, &s, 0, 2).is_err(),
        "second use should be rejected"
    );
}

/// ReplayNonceStore accepts sequential nonces.
#[test]
fn replay_nonce_store_accepts_sequential() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert!(store.mark_processed_at(1, 2, &s, 0, 1).is_ok());
    assert!(store.mark_processed_at(1, 2, &s, 1, 2).is_ok());
    assert!(store.mark_processed_at(1, 2, &s, 2, 3).is_ok());
}

/// Zero nonce is a valid nonce (not special-cased).
#[test]
fn zero_nonce_is_valid() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert!(store.mark_processed_at(1, 2, &s, 0, 1).is_ok());
    assert!(store.mark_processed_at(1, 2, &s, 0, 2).is_err());
}

/// ReplayNonceStore handles many sequential nonces.
#[test]
fn replay_nonce_store_handles_many() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    for i in 0u64..1_000 {
        assert!(store.mark_processed_at(1, 2, &s, i, i + 1).is_ok());
    }
    assert!(store.is_processed(1, 2, &s, 0));
    assert!(store.is_processed(1, 2, &s, 999));
    assert!(!store.is_processed(1, 2, &s, 1000));
}

/// A gap beyond MAX_NONCE_GAP is refused.
#[test]
fn nonce_gap_ceiling_enforced() {
    let mut store = ReplayNonceStore::new();
    let s = sender(7);
    assert!(store.mark_processed_at(1, 2, &s, 0, 1).is_ok());
    assert!(
        store
            .mark_processed_at(1, 2, &s, MAX_NONCE_GAP + 1, 2)
            .is_err(),
        "gap beyond MAX_NONCE_GAP must be refused"
    );
}

/// Different senders are independent.
#[test]
fn different_senders_independent() {
    let mut store = ReplayNonceStore::new();
    let a = sender(1);
    let b = sender(2);
    assert!(store.mark_processed_at(1, 2, &a, 0, 1).is_ok());
    assert!(store.mark_processed_at(1, 2, &b, 0, 1).is_ok());
    assert_eq!(store.processed_count(), 2);
}
