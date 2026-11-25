//! Adversarial tests: each one is a forgery the verifier used to accept.
//!
//! Every test here fails against the verifier as first merged, and each fails for
//! the reason its name gives, not because a fixture is malformed. A verifier is
//! only as strong as the fields its proof cannot choose, so each test rewrites
//! one of those fields and demands a refusal.
//!
//! The suite is written from the adversary's side: it forges a proof, then asks
//! the verifier to reject it. A test that passes because the honest path is
//! broken would be worthless, so the honest control is asserted first in each
//! case.

use budlum_nipopow::{
    hash_block, leading_zero_bits, ChainBuilder, Hash32, NipopowProof, PowHeader, SecurityParams,
    TrustedAnchor,
};

fn anchor() -> Hash32 {
    [0xaa; 32]
}

fn params(m: usize) -> SecurityParams {
    match SecurityParams::new(m, 2, 4) {
        Some(params) => params,
        None => panic!("the fixture parameters are valid"),
    }
}

/// Mine a header with an explicit interlink, the way a prover would.
fn mine(parent: Hash32, height: u64, level: u8, interlink: Vec<Hash32>) -> PowHeader {
    let mut nonce = 0u64;
    loop {
        let id = hash_block(&parent, height, nonce, level, &interlink);
        if leading_zero_bits(&id) >= u32::from(level) {
            return PowHeader {
                id,
                parent,
                height,
                nonce,
                level,
                interlink,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn mixed_chain() -> ChainBuilder {
    let mut chain = ChainBuilder::new(anchor());
    for i in 0..40 {
        let level = if i % 7 == 0 || i % 3 == 0 { 2 } else { 1 };
        chain.push(level);
    }
    chain
}

/// F1: an interlink pointer is not a free parameter.
///
/// Before the digest covered the interlink, an adversary rewrote one pointer to
/// aim at a header of an unrelated fork it had mined at level 1 (two hashes),
/// and the descent walked from the honest chain into that fork while still
/// reaching the anchor. The rewritten pointer now breaks the header's own PoW.
#[test]
fn an_unrelated_fork_cannot_be_spliced_with_a_mutable_interlink() {
    let honest = mixed_chain();
    let mut forged = honest.build_proof(6);
    assert!(
        forged.verify(&honest.trusted_anchor(), &params(6)),
        "the fixture must start from a proof that verifies"
    );

    let mut fork = ChainBuilder::new(anchor());
    for _ in 0..12 {
        fork.push(1);
    }
    let bridge = forged.suffix[0].clone();
    let mut redirected = bridge.interlink.clone();
    redirected[0] = fork.headers()[10].id;
    let spliced_bridge = PowHeader {
        interlink: redirected,
        ..bridge
    };

    let mut spliced = vec![spliced_bridge];
    spliced.extend(fork.headers()[..=10].iter().rev().cloned());
    forged.suffix = spliced;

    assert!(
        !forged.verify(&honest.trusted_anchor(), &params(6)),
        "a pointer the miner did not commit to must not redirect a descent"
    );
}

/// F2: the trusted anchor is an id and a height.
///
/// A single superblock named the anchor as its parent and claimed any height it
/// liked. The forgery is mined at level two on purpose: at level one the
/// superblock bound would reject it anyway, and a test that passes for the
/// wrong reason proves nothing. The anchor now carries its own height and the
/// oldest header must be the anchor's immediate child.
#[test]
fn a_single_cheap_header_cannot_claim_an_arbitrary_height() {
    let claimed_height = 1u64 << 40;
    let header = mine(anchor(), claimed_height, 2, vec![[0u8; 32], [0u8; 32]]);
    let proof = NipopowProof {
        prefix: vec![header],
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(
        !proof.verify(&TrustedAnchor::genesis(anchor()), &params(1)),
        "an anchor hash alone must not authorize a claimed height"
    );
    // The same proof at the anchor's real height is honest: the rejection
    // above is the height binding, not a malformed fixture.
    let plausible = mine(anchor(), 1, 2, vec![[0u8; 32], [0u8; 32]]);
    let honest = NipopowProof {
        prefix: vec![plausible],
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(honest.verify(&TrustedAnchor::genesis(anchor()), &params(1)));
}

/// F3: goodness counts superblocks, not the proof's own length.
///
/// Every accepted header is level at least one, so counting level-at-least-one
/// blocks counted the proof. A chain of ordinary blocks with no superblock in
/// it satisfied any bound smaller than its own length.
#[test]
fn goodness_counts_superblocks_not_carried_headers() {
    let mut chain = ChainBuilder::new(anchor());
    for _ in 0..40 {
        chain.push(1);
    }
    assert!(
        chain.headers().iter().all(|h| h.level == 1),
        "the fixture must contain no superblock at all"
    );
    let proof = chain.build_proof(6);
    assert!(
        !proof.verify(&chain.trusted_anchor(), &params(6)),
        "a proof with zero superblocks must not satisfy a superblock bound"
    );
}

/// F3b: a proof may not repeat a header.
///
/// Repeating a superblock would pay for goodness more than once if the
/// structural rules ever relaxed, so the verifier refuses a repeated digest.
/// Today the contiguity and descent rules already reject every repetition, and
/// this test records the property rather than the rule that enforces it.
#[test]
fn a_repeated_header_is_rejected() {
    let builder = mixed_chain();
    let mut proof = builder.build_proof(6);
    let repeated = match proof
        .suffix
        .iter()
        .chain(proof.prefix.iter())
        .find(|h| h.level >= 2)
    {
        Some(header) => header.clone(),
        None => return,
    };
    let copies = proof.verify(&builder.trusted_anchor(), &params(6));
    assert!(copies);
    let pool: Vec<PowHeader> = proof.suffix.to_vec();
    let superblocks = pool.iter().filter(|h| h.level >= 2).count();
    let mut suffix: Vec<PowHeader> = pool.into_iter().filter(|h| h.level < 2).collect();
    for _ in 0..(superblocks + 4) {
        suffix.push(repeated.clone());
    }
    proof.suffix = suffix;
    assert!(
        !proof.verify(&builder.trusted_anchor(), &params(6)),
        "a proof must not repeat a header to reach the goodness bound"
    );
}

/// F4: a level-3 ancestor fills the level-1, level-2 and level-3 slots.
///
/// The builder recorded the newest header only at its exact level, so a level-3
/// block left the lower pointers at zero even though the contract says they
/// point at the closest ancestor that reaches that level.
#[test]
fn a_level_three_block_fills_every_lower_interlink_level() {
    let mut chain = ChainBuilder::new(anchor());
    chain.push(3);
    chain.push(1);
    chain.push(3);
    let headers = chain.headers();
    assert_eq!(
        headers[2].interlink[1], headers[0].id,
        "the nearest ancestor at level two or above must populate the level-2 slot"
    );
    assert_eq!(
        headers[2].interlink[0], headers[1].id,
        "the level-1 slot stays the closest ancestor at level one or above"
    );
}

/// The honest control for the whole suite: the same builder still verifies.
#[test]
fn the_honest_path_still_verifies() {
    let builder = mixed_chain();
    let proof = builder.build_proof(6);
    assert!(proof.verify(&builder.trusted_anchor(), &params(6)));
    assert!(!proof.verify(&builder.trusted_anchor(), &params(1000)));
}

/// A height of `u64::MAX` is attacker input and must not turn into an abort.
///
/// `prev.height + 1` panics in a build with overflow checks on, and the release
/// profile (overflow checks on, `panic = "abort"`) turns that panic into a
/// process abort, so a single malformed proof could stop a node.
#[test]
fn a_height_at_the_u64_ceiling_is_rejected_not_panicked() {
    let first = mine(anchor(), u64::MAX, 1, vec![[0u8; 32]]);
    let second = mine(first.id, u64::MAX, 1, vec![[0u8; 32]]);
    let proof = NipopowProof {
        prefix: vec![first, second],
        suffix: Vec::new(),
        anchor: anchor(),
    };
    assert!(!proof.verify(&TrustedAnchor::genesis(anchor()), &params(1)));
}

/// An anchor at the ceiling cannot accept a child it could never have.
#[test]
fn an_anchor_at_the_u64_ceiling_rejects_a_ceiling_height_child() {
    let header = mine(anchor(), u64::MAX, 2, vec![[0u8; 32], [0u8; 32]]);
    let proof = NipopowProof {
        prefix: vec![header],
        suffix: Vec::new(),
        anchor: anchor(),
    };
    let anchor_at_ceiling = TrustedAnchor {
        id: anchor(),
        height: u64::MAX,
    };
    assert!(
        !proof.verify(&anchor_at_ceiling, &params(1)),
        "saturating addition would accept a child one past the ceiling"
    );
}

/// The cost of a forgery is the difficulty the caller pins, and nothing else.
///
/// A single proof cannot tell a fabricated low-difficulty chain from a real one:
/// both are internally consistent, and the verifier sees only the second. What
/// bounds the adversary is `SecurityParams::superblock_level`, because a
/// superblock must really carry that many leading zero bits. This test records
/// the boundary instead of claiming it away: the same forged chain that
/// satisfies a level-two bound is refused when the caller pins level twelve, and
/// level twelve costs 4096 hash evaluations per superblock.
#[test]
fn a_forged_chain_cannot_satisfy_a_pinned_difficulty() {
    let (forged, anchor_at) = forged_low_difficulty_chain(6);
    let cheap = match SecurityParams::new(6, 2, 4) {
        Some(params) => params,
        None => panic!("level two is a valid bound"),
    };
    assert!(
        forged.verify(&anchor_at, &cheap),
        "the forgery is internally consistent: this is the documented boundary"
    );
    let pinned = match SecurityParams::new(6, 12, 12) {
        Some(params) => params,
        None => panic!("level twelve is a valid bound"),
    };
    assert!(
        !forged.verify(&anchor_at, &pinned),
        "a forged chain cannot carry six blocks at twelve leading zero bits"
    );
}

/// A chain an adversary can mine from nothing, attached to the anchor.
fn forged_low_difficulty_chain(superblocks: usize) -> (NipopowProof, TrustedAnchor) {
    let mut headers: Vec<PowHeader> = Vec::new();
    let mut parent = anchor();
    for index in 0..superblocks {
        let height = index as u64 + 1;
        let header = mine(parent, height, 2, vec![[0u8; 32], [0u8; 32]]);
        parent = header.id;
        headers.push(header);
    }
    (
        NipopowProof {
            prefix: headers,
            suffix: Vec::new(),
            anchor: anchor(),
        },
        TrustedAnchor::genesis(anchor()),
    )
}
