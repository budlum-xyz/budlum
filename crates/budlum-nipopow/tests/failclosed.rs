//! Fail-closed behaviours of the proof verifier.
//!
//! An adversary controls the proof bytes handed to `verify`. A verifier that
//! panics on a structurally odd proof is a denial of service and violates the
//! no-panic rule: rejection must be a value, never an abort.

use budlum_nipopow::{
    hash_block, ChainBuilder, Hash32, NipopowProof, SecurityParams, TrustedAnchor,
};

fn anchor() -> Hash32 {
    [7u8; 32]
}

fn params(m: usize) -> SecurityParams {
    match SecurityParams::new(m, 2, 8) {
        Some(params) => params,
        None => panic!("the fixture parameters are valid"),
    }
}

#[test]
fn an_empty_prefix_is_rejected_not_panicked() {
    let mut builder = ChainBuilder::new(anchor());
    builder.push(2);
    builder.push(2);
    let proof = NipopowProof {
        prefix: Vec::new(),
        suffix: builder.headers().to_vec(),
        anchor: anchor(),
    };
    assert!(!proof.verify(&TrustedAnchor::genesis(anchor()), &params(1)));
}

#[test]
fn an_empty_prefix_and_empty_suffix_is_rejected() {
    let proof = NipopowProof {
        prefix: Vec::new(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(!proof.verify(&TrustedAnchor::genesis(anchor()), &params(1)));
}

#[test]
fn a_prefix_only_proof_must_connect_to_the_anchor() {
    let mut builder = ChainBuilder::new(anchor());
    builder.push(2);
    builder.push(2);
    let proof = NipopowProof {
        prefix: builder.headers().to_vec(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(proof.verify(&TrustedAnchor::genesis(anchor()), &params(2)));
    assert!(!proof.verify(&TrustedAnchor::genesis([9u8; 32]), &params(2)));
}

#[test]
fn goodness_bound_is_exact() {
    let mut builder = ChainBuilder::new(anchor());
    for _ in 0..4 {
        builder.push(2);
    }
    let proof = NipopowProof {
        prefix: builder.headers().to_vec(),
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(proof.verify(&TrustedAnchor::genesis(anchor()), &params(4)));
    assert!(!proof.verify(&TrustedAnchor::genesis(anchor()), &params(5)));
}

#[test]
fn hash_block_binds_every_field() {
    let parent = [1u8; 32];
    let base = hash_block(&parent, 7, 99, 2, &[[4u8; 32], [5u8; 32]]);
    assert_ne!(base, hash_block(&parent, 8, 99, 2, &[[4u8; 32], [5u8; 32]]));
    assert_ne!(
        base,
        hash_block(&parent, 7, 100, 2, &[[4u8; 32], [5u8; 32]])
    );
    assert_ne!(base, hash_block(&parent, 7, 99, 3, &[[4u8; 32], [5u8; 32]]));
    assert_ne!(
        base,
        hash_block(&[2u8; 32], 7, 99, 2, &[[4u8; 32], [5u8; 32]])
    );
    assert_ne!(base, hash_block(&parent, 7, 99, 2, &[[4u8; 32], [6u8; 32]]));
}
