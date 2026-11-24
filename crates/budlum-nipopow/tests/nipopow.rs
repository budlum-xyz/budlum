//! End-to-end verification tests for the NIPoPoW succinct PoW finality adapter.
//! These tests are written BEFORE the implementation exists (red-green TDD):
//! the crate API they import does not compile until `src/lib.rs` lands, which
//! is the "breaking test" that must precede every new behavior.

use budlum_nipopow::{ChainBuilder, Hash32, PowHeader, leading_zero_bits};

fn anchor() -> Hash32 {
    [0xaa; 32]
}

/// Build a deterministic chain with a mix of PoW difficulty levels so the
/// interlink structure (and thus the succinct proof) is exercised.
fn build_chain(n: usize) -> ChainBuilder {
    let mut b = ChainBuilder::new(anchor());
    for i in 0..n {
        let level = if i % 7 == 0 { 3 } else if i % 3 == 0 { 2 } else { 1 };
        b.push(level);
    }
    b
}

#[test]
fn leading_zero_bits_counts_from_msb() {
    let mut h = [0u8; 32];
    // 0b0111_1111 -> MSB is 0, so 1 leading zero bit.
    h[0] = 0x7f;
    assert_eq!(leading_zero_bits(&h), 1);
    let mut z = [0u8; 32];
    z[0] = 0x80; // 0b1000_0000 -> MSB is 1, 0 leading zero bits.
    assert_eq!(leading_zero_bits(&z), 0);
    let mut z2 = [0u8; 32];
    z2[0] = 0x00;
    z2[1] = 0x01; // first byte all zero (8 bits), second 0b0000_0001 -> 7 more.
    assert_eq!(leading_zero_bits(&z2), 15);
}

#[test]
fn honest_proof_verifies() {
    let b = build_chain(40);
    let proof = b.build_proof(6);
    // The proof must verify against the same security parameter and max level.
    assert!(proof.verify(6, 3), "honest NIPoPoW proof must verify");
}

#[test]
fn tampered_pow_is_rejected() {
    let b = build_chain(40);
    let mut proof = b.build_proof(6);
    // Flip a bit in a header id: the recomputed digest no longer matches, so the
    // proof-of-work is invalid. Fail-closed must reject.
    proof.prefix[0].id[0] ^= 0x01;
    assert!(!proof.verify(6, 3), "tampered PoW must be rejected");
}

#[test]
fn broken_interlink_is_rejected() {
    let b = build_chain(40);
    let mut proof = b.build_proof(6);
    // The step from suffix[0] down to suffix[1] is an interlink jump (not a
    // contiguous parent link). Corrupt every interlink pointer of suffix[0] so
    // that descent can no longer be validated; it must fail closed.
    assert!(proof.suffix.len() > 1, "suffix must contain an interlink step");
    if let Some(first) = proof.suffix.first_mut() {
        for p in first.interlink.iter_mut() {
            *p = [0x99; 32];
        }
    }
    assert!(!proof.verify(6, 3), "broken interlink must be rejected");
}

#[test]
fn disconnected_proof_is_rejected() {
    let b = build_chain(40);
    let mut proof = b.build_proof(6);
    // Drop the suffix entirely: the prefix can no longer descend to the anchor.
    proof.suffix.clear();
    assert!(!proof.verify(6, 3), "disconnected proof must be rejected");
}

#[test]
fn insufficient_goodness_is_rejected() {
    let b = build_chain(40);
    // Require far more level-1 blocks than the chain contains: the adversary
    // (or a buggy prover) cannot satisfy the goodness bound, so verify fails.
    let proof = b.build_proof(6);
    assert!(
        !proof.verify(1000, 3),
        "proof failing the goodness bound must be rejected"
    );
}

#[test]
fn wrong_anchor_is_rejected() {
    let b = build_chain(40);
    let honest = b.build_proof(6);
    assert!(honest.verify(6, 3));

    // The proof must bind to the trusted checkpoint. An adversary that replays a
    // valid proof under a different anchor cannot make the descent reach it, so
    // verification must fail closed.
    let mut forged = honest.clone();
    forged.anchor = [0x77; 32];
    assert!(
        !forged.verify(6, 3),
        "proof bound to the wrong anchor must be rejected"
    );
}

#[test]
fn prefix_must_be_contiguous_and_connected() {
    let b = build_chain(40);
    let mut proof = b.build_proof(6);
    // Break contiguity: replace a prefix header with a copy whose parent no
    // longer links to the previous header.
    if proof.prefix.len() >= 2 {
        let mut hdr: PowHeader = proof.prefix[1].clone();
        hdr.parent = [0x55; 32];
        proof.prefix[1] = hdr;
    }
    assert!(!proof.verify(6, 3), "non-contiguous prefix must be rejected");
}
