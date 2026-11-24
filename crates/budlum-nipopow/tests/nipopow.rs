//! End-to-end verification tests for the NIPoPoW succinct PoW finality adapter.
//!
//! These tests describe the verifier's contract from the outside: an honest
//! proof of a chain built by the crate verifies, and each field an adversary
//! controls breaks verification when it is rewritten.

use budlum_nipopow::{
    leading_zero_bits, ChainBuilder, Hash32, NipopowProof, PowHeader, SecurityParams, TrustedAnchor,
};

fn anchor() -> Hash32 {
    [0xaa; 32]
}

/// Parameters for the fixture chains below: m superblocks at level two or
/// above, and no header above level four.
fn params(m: usize) -> SecurityParams {
    match SecurityParams::new(m, 2, 4) {
        Some(params) => params,
        None => panic!("the fixture parameters are valid"),
    }
}

/// Build a deterministic chain with a mix of PoW difficulty levels so the
/// interlink structure (and thus the succinct proof) is exercised.
fn build_chain(n: usize) -> ChainBuilder {
    let mut builder = ChainBuilder::new(anchor());
    for i in 0..n {
        let level = if i % 3 == 0 || i % 7 == 0 { 2 } else { 1 };
        builder.push(level);
    }
    builder
}

#[test]
fn leading_zero_bits_counts_from_msb() {
    let mut h = [0u8; 32];
    h[0] = 0x7f; // 0b0111_1111: the MSB is zero, so exactly one.
    assert_eq!(leading_zero_bits(&h), 1);
    let mut z = [0u8; 32];
    z[0] = 0x80; // 0b1000_0000: no leading zero bit.
    assert_eq!(leading_zero_bits(&z), 0);
    let mut z2 = [0u8; 32];
    z2[1] = 0x01; // eight zero bits, then seven more.
    assert_eq!(leading_zero_bits(&z2), 15);
}

#[test]
fn honest_proof_verifies() {
    let builder = build_chain(40);
    let proof = builder.build_proof(6);
    assert!(
        proof.verify(&builder.trusted_anchor(), &params(6)),
        "an honest proof must verify against its own anchor"
    );
}

#[test]
fn tampered_pow_is_rejected() {
    let builder = build_chain(40);
    let mut proof = builder.build_proof(6);
    proof.prefix[0].id[0] ^= 0x01;
    assert!(!proof.verify(&builder.trusted_anchor(), &params(6)));
}

#[test]
fn broken_interlink_is_rejected() {
    let builder = build_chain(40);
    let mut proof = builder.build_proof(6);
    assert!(proof.suffix.len() > 1, "the fixture must carry a descent");
    if let Some(first) = proof.suffix.first_mut() {
        for pointer in first.interlink.iter_mut() {
            *pointer = [0x99; 32];
        }
    }
    assert!(!proof.verify(&builder.trusted_anchor(), &params(6)));
}

#[test]
fn disconnected_proof_is_rejected() {
    let builder = build_chain(40);
    let mut proof = builder.build_proof(6);
    proof.suffix.clear();
    assert!(!proof.verify(&builder.trusted_anchor(), &params(6)));
}

#[test]
fn insufficient_goodness_is_rejected() {
    let builder = build_chain(40);
    let proof = builder.build_proof(6);
    assert!(!proof.verify(&builder.trusted_anchor(), &params(1000)));
}

#[test]
fn wrong_anchor_is_rejected() {
    let builder = build_chain(40);
    let proof = builder.build_proof(6);
    assert!(proof.verify(&builder.trusted_anchor(), &params(6)));
    let foreign = TrustedAnchor::genesis([0x77; 32]);
    assert!(!proof.verify(&foreign, &params(6)));
}

#[test]
fn an_anchor_at_the_wrong_height_is_rejected() {
    let builder = build_chain(40);
    let proof = builder.build_proof(6);
    let mut trusted = builder.trusted_anchor();
    trusted.height = 1;
    assert!(
        !proof.verify(&trusted, &params(6)),
        "the anchor's height is part of the claim, not decoration"
    );
}

#[test]
fn prefix_must_be_contiguous_and_connected() {
    let builder = build_chain(40);
    let mut proof: NipopowProof = builder.build_proof(6);
    if proof.prefix.len() >= 2 {
        let mut header: PowHeader = proof.prefix[1].clone();
        header.parent = [0x55; 32];
        proof.prefix[1] = header;
    }
    assert!(!proof.verify(&builder.trusted_anchor(), &params(6)));
}
