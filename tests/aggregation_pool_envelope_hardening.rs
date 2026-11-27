//! Regression tests for aggregation Envelope zero-scheme Signature refusal and
//! ObjectPool seen-set eviction consistency.

use std::collections::BTreeMap;

use budlum_core::aggregation::envelope::{Envelope, ObjectKind};
use budlum_core::aggregation::params::AggParams;
use budlum_core::aggregation::pool::{Admission, ObjectPool, Rejection, TxFacts, TxLookup};
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use budlum_core::domain::types::Hash32;

struct MapTxs(BTreeMap<Hash32, TxFacts>);

impl TxLookup for MapTxs {
    fn tx_facts(&self, tx_hash: &Hash32) -> Option<TxFacts> {
        self.0.get(tx_hash).copied()
    }
}

#[test]
fn signature_envelope_with_zero_scheme_is_refused_on_decode() {
    let bad = Envelope {
        kind: ObjectKind::Signature,
        scheme: SchemeId(0),
        payload: vec![0xAA; 16],
        tx_hash: [0x11; 32],
        domain: 1,
    };
    let wire = bad.encode();
    assert!(
        Envelope::decode(&wire, 1024).is_err(),
        "ObjectKind::Signature carrying SchemeId(0) must be refused on decode"
    );
}

#[test]
fn unverified_waiting_spam_cannot_consume_entire_ready_pool_budget() {
    let mut params = AggParams::default();
    params.pool_max_bytes = 2_000;
    let mut pool = ObjectPool::new(params, 1);
    let txs = MapTxs(BTreeMap::new());
    let reg = SchemeStatusRegistry::genesis();

    // Flood unknown-tx unverified Waiting envelopes of ~450 bytes each.
    // Unverified Waiting items must be capped to at most 25% of pool_max_bytes (500B),
    // never allowed to fill 100% of pool_max_bytes!
    let mut accepted_waiting = 0usize;
    for i in 1..=10u8 {
        let env = Envelope {
            kind: ObjectKind::StarkProof,
            scheme: SchemeId(0),
            payload: vec![i; 400],
            tx_hash: [i; 32],
            domain: 1,
        };
        if matches!(pool.admit(env, &txs, &reg), Ok(Admission::Waiting(_))) {
            accepted_waiting += 1;
        }
    }
    let _ = (WalletKeyPair::from_seed, Rejection::PoolFull);
    assert!(
        pool.bytes() <= 500 && accepted_waiting <= 1,
        "unverified Waiting objects consumed {} bytes (> 25% of 2000B pool_max_bytes)",
        pool.bytes()
    );
}
