//! Fail-closed behaviours of the proof verifier.
//!
//! An adversary controls the proof bytes handed to `verify`. A verifier that
//! panics on a structurally odd proof is a denial of service and violates the
//! no-panic rule: rejection must be a value, never an abort.

use budlum_nipopow::{hash_block, ChainBuilder, Hash32, NipopowProof};

fn anchor() -> Hash32 {
    [7u8; 32]
}

#[test]
fn an_empty_prefix_is_rejected_not_panicked() {
    let mut b = ChainBuilder::new(anchor());
    b.push(1);
    b.push(1);
    let suffix = b.headers().to_vec();
    let proof = NipopowProof {
        prefix: Vec::new(),
        suffix,
        anchor: anchor(),
    };
    // Must return false; before the guard landed this panicked with an index
    // out of bounds on prefix[0].
    assert!(!proof.verify(1, 8));
}

#[test]
fn an_empty_prefix_and_empty_suffix_is_rejected() {
    let proof = NipopowProof {
        prefix: Vec::new(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(!proof.verify(1, 8));
}

#[test]
fn a_prefix_only_proof_must_connect_to_the_anchor() {
    let mut b = ChainBuilder::new(anchor());
    b.push(1);
    b.push(2);
    b.push(1);
    let proof = NipopowProof {
        prefix: b.headers().to_vec(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(proof.verify(2, 8));
    let foreign = NipopowProof {
        prefix: b.headers().to_vec(),
        suffix: Vec::new(),
        anchor: [9u8; 32],
    };
    assert!(!foreign.verify(2, 8));
}

#[test]
fn goodness_bound_is_exact() {
    let mut b = ChainBuilder::new(anchor());
    for _ in 0..4 {
        b.push(1);
    }
    let proof = NipopowProof {
        prefix: b.headers().to_vec(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(proof.verify(4, 8));
    assert!(!proof.verify(5, 8));
}

#[test]
fn hash_block_binds_every_field() {
    let parent = [1u8; 32];
    let base = hash_block(&parent, 7, 99, 2);
    assert_ne!(base, hash_block(&parent, 8, 99, 2));
    assert_ne!(base, hash_block(&parent, 7, 100, 2));
    assert_ne!(base, hash_block(&parent, 7, 99, 3));
    assert_ne!(base, hash_block(&[2u8; 32], 7, 99, 2));
}
