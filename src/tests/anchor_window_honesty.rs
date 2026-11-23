//! `local_anchor_root` must not fold two different answers into one `None`.
//!
//! `aggregate_finality_roots` returns `Err` for two unrelated reasons:
//!
//! * `EmptyAggregation` - the window has no global headers yet. "This node has
//!   not reached a checkpoint" is a fact about where the chain is, and callers
//!   that treat it as "nothing to anchor" are right.
//! * `ZeroDigest` - the window exists but a leaf (or the resulting root) is all
//!   zeros. That is not a fact about the chain; it is a fault in what this node
//!   is about to sign. Folding it into `None` lets a node that cannot form a
//!   sound anchor look exactly like a node that has nothing to anchor.
//!
//! The distinction has to survive the `Option` at the call site, so it is pinned
//! here: `Option` for "not yet", `Result` for "cannot".

use crate::chain::blockchain::AnchorWindowOutcome;

/// An anchor window that has not been reached is not an error.
#[test]
fn a_window_with_no_leaves_is_empty_not_a_fault() {
    let outcome = AnchorWindowOutcome::from_leaves(&[]);
    assert_eq!(outcome, AnchorWindowOutcome::NotYet);
    assert!(
        !matches!(outcome, AnchorWindowOutcome::Fault(_)),
        "an unreached window must not read as a fault on this node"
    );
}

/// A zero digest in the window is a fault and must not read as "not yet".
#[test]
fn a_zero_leaf_is_a_fault_and_not_an_empty_window() {
    let leaves = [[0u8; 32]];
    let outcome = AnchorWindowOutcome::from_leaves(&leaves);
    assert!(
        matches!(outcome, AnchorWindowOutcome::Fault(_)),
        "a zero leaf must not fold into the same value an unreached window yields"
    );
    assert_ne!(
        outcome,
        AnchorWindowOutcome::NotYet,
        "the two answers above differ and the type has to keep them apart"
    );
}

/// A sound window produces the root the settlement fold produces.
#[test]
fn a_sound_window_yields_the_settlement_root() {
    let leaves = [[7u8; 32], [9u8; 32]];
    let expected = crate::settlement::aggregate_finality_roots(&leaves)
        .expect("a window of non-zero leaves aggregates");
    assert_eq!(
        AnchorWindowOutcome::from_leaves(&leaves),
        AnchorWindowOutcome::Root(expected)
    );
}

/// The fault case carries enough to say which field was zero.
#[test]
fn the_fault_names_the_field_it_found_zero() {
    let outcome = AnchorWindowOutcome::from_leaves(&[[0u8; 32]]);
    match outcome {
        AnchorWindowOutcome::Fault(reason) => {
            assert!(
                reason.contains("leaf digest") || reason.contains("aggregate_root"),
                "the fault must name the field, got {reason:?}"
            );
        }
        other => panic!("expected a fault, got {other:?}"),
    }
}
