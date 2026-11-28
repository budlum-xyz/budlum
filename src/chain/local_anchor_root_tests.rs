//! The seam between "this node holds no anchor leaves" and "this node's
//! leaves were refused".
//!
//! `local_anchor_root` used to answer both with `None`: it folded the
//! aggregation's `Result` into an `Option` with `.ok()`. A zero leaf digest or
//! a root that derived to zero therefore reached the state-recovery tick
//! dressed as an absent window, and the tick moved on as if this node held no
//! commitment for that height. These tests hold the two answers apart.

use super::aggregate_local_anchor_root;
use crate::settlement::AnchorError;

/// A leaf that aggregates to something other than zero.
fn leaf(seed: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[0] = seed;
    out[31] = seed.wrapping_mul(7).wrapping_add(3);
    out
}

#[test]
fn an_empty_window_is_an_absence_and_not_an_error() {
    // Nothing to aggregate is a real state: this node has no headers inside
    // the window. It stays `None` so a caller can tell it from a refusal
    // without reading a log line.
    assert_eq!(aggregate_local_anchor_root(&[]), Ok(None));
}

#[test]
fn a_window_of_zero_leaves_is_refused_instead_of_read_as_absent() {
    // The old `.ok()` turned this into `None`, which is indistinguishable
    // from the empty window above. It must surface as the encoding failure
    // it is.
    let digests = [leaf(1), [0_u8; 32], leaf(2)];
    assert_eq!(
        aggregate_local_anchor_root(&digests),
        Err(AnchorError::ZeroDigest {
            field: "leaf digest"
        })
    );
}

#[test]
fn a_sound_window_still_aggregates_to_the_signed_root() {
    // The seam must not change what a healthy window produces: the value the
    // caller gets is the one the anchor signs over.
    let digests = [leaf(3), leaf(4), leaf(5)];
    let expected = crate::settlement::aggregate_finality_roots(&digests);
    assert_eq!(aggregate_local_anchor_root(&digests), expected.map(Some));
    let aggregated = aggregate_local_anchor_root(&digests).unwrap_or(None);
    assert!(
        aggregated.is_some_and(|root| root != [0_u8; 32]),
        "a sound window aggregates to a non-zero root"
    );
}
