//! The test suite of the aggregation layer.
//!
//! Three kinds of test live here, and the third is the one that keeps the other
//! two honest:
//!
//! 1. **Properties.** A digest or a fold that holds for one input and not
//!    another is not a property. Every `*_covers_*` and `*_binds_*` test walks
//!    every field of its structure.
//! 2. **The negative matrix of directive section 11.** Each refusal names the
//!    rule it enforces, so a future backend that drops a check fails a test that
//!    says which check it dropped.
//! 3. **Source gates.** Two properties cannot be stated as behaviour at all:
//!    "the production profile does not contain the reference backend" and "no
//!    production path panics". Both are read out of the source text here, the
//!    same way `xtask/gates` reads the tree, because the alternative is a
//!    promise in a document.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::backend::{
    claim_from_envelope, combine, pool_item, verify_frame, verify_frame_hash, AggBackend,
    NativeBackend, ObjectVerifier, StructuralVerifier, TickCtx, BLOCK_RULES_NOT_IN_THIS_LAYER,
};
use super::digest::{
    adapter_binding, agg_merge_program_hash, agg_tick_program_hash, auth_ok, claim_digest,
    claims_root, claims_root_of, finality_claim, fold_shape, frame_hash, master_pi, merge_pi,
    object_id, params_hash, tick_pi, ALL_TAGS,
};
use super::pool::AggPool;
use super::types::{
    Address, AggError, AggMode, AggParams, Claim, ClaimFrame, DomainId, Envelope, Ext, Hash,
    ObjectKind, PoolItem, SchemeDef, SchemeId, SchemeRegistry, Segment,
};

const D1: DomainId = 1;
const D2: DomainId = 2;
const SCHEME_OK: SchemeId = 0x0101;

fn params_on() -> AggParams {
    AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    }
}

fn ctx(domain: DomainId) -> TickCtx {
    TickCtx {
        domain,
        aggregator: Address([0x77; 32]),
        params: params_on(),
    }
}

fn verifier() -> TestVerifier {
    TestVerifier
}

/// A verifier that refuses a signature whose last payload byte is `0xFF` and
/// accepts everything else structurally. It is deliberately stupid: what is
/// under test is the frame machinery, not a signature scheme.
struct TestVerifier;

impl ObjectVerifier for TestVerifier {
    fn verify(&self, envelope: &Envelope, claim: &Claim) -> Result<(), AggError> {
        let derived = claim_from_envelope(envelope)?;
        if derived != *claim {
            return Err(AggError::ClaimMismatch);
        }
        if envelope.kind == ObjectKind::Signature && envelope.payload.last() == Some(&0xFF) {
            return Err(AggError::VerifierRefused("bad signature"));
        }
        Ok(())
    }
}

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sig_payload(signer: u8, msg: u8, tail: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&fill(signer));
    out.extend_from_slice(&fill(msg));
    out.push(tail);
    out
}

fn sig_env(scheme: SchemeId, signer: u8, msg: u8, tail: u8, domain: DomainId) -> Envelope {
    Envelope {
        kind: ObjectKind::Signature,
        scheme,
        payload: sig_payload(signer, msg, tail),
        tx_hash: fill(0xAA),
        domain,
    }
}

fn sig_item(signer: u8, msg: u8, domain: DomainId) -> PoolItem {
    pool_item(sig_env(SCHEME_OK, signer, msg, 0x01, domain)).expect("well-formed signature")
}

fn stark_payload(program: u8, input: u8, output: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(97);
    out.extend_from_slice(&fill(program));
    out.extend_from_slice(&fill(input));
    out.extend_from_slice(&fill(output));
    out.push(0x01);
    out
}

fn stark_env(program: u8, input: u8, output: u8, domain: DomainId) -> Envelope {
    Envelope {
        kind: ObjectKind::StarkProof,
        scheme: 0x1001,
        payload: stark_payload(program, input, output),
        tx_hash: fill(0xBB),
        domain,
    }
}

fn pcs_env(poly: u8, point: [u64; 4], value: [u64; 4], domain: DomainId) -> Envelope {
    let mut payload = Vec::with_capacity(97);
    payload.extend_from_slice(&fill(poly));
    payload.extend_from_slice(&Ext(point).canonical_bytes());
    payload.extend_from_slice(&Ext(value).canonical_bytes());
    payload.push(0x01);
    Envelope {
        kind: ObjectKind::PcsOpening,
        scheme: 0x2001,
        payload,
        tx_hash: fill(0xCC),
        domain,
    }
}

fn backend() -> NativeBackend<TestVerifier> {
    NativeBackend::new(verifier(), SchemeRegistry::budlum_reference())
}

fn claim_sig(signer: u8, msg: u8, domain: DomainId) -> Claim {
    claim_from_envelope(&sig_env(SCHEME_OK, signer, msg, 0x01, domain)).expect("derives")
}

/// Two distinct, valid frames for the same domain, each one segment.
fn two_frames() -> (ClaimFrame, ClaimFrame) {
    let a = backend()
        .prove_tick(
            &ctx(D1),
            &[sig_item(0x01, 0x01, D1), sig_item(0x02, 0x02, D1)],
        )
        .expect("frame a");
    let b = backend()
        .prove_tick(
            &ctx(D1),
            &[sig_item(0x03, 0x03, D1), sig_item(0x04, 0x04, D1)],
        )
        .expect("frame b");
    (a, b)
}

// ---------------------------------------------------------------- tags ----

#[test]
fn all_tags_are_distinct() {
    let mut seen: Vec<&str> = ALL_TAGS.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), ALL_TAGS.len(), "two tags are the same string");
}

#[test]
fn all_tags_are_prefix_free() {
    for a in ALL_TAGS {
        for b in ALL_TAGS {
            if a != b {
                assert!(!a.starts_with(b), "{a} starts with {b}");
            }
        }
    }
}

#[test]
fn tags_are_registered_in_the_domain_tag_inventory() {
    // The `domain-tags` gate refuses a `BDLM_*` literal used but unlisted. This
    // test proves the same fact for the twelve tags this module introduces, so
    // the slice cannot be merged with a tag that only exists here.
    let inventory = include_str!("../crypto/domain_tags.rs");
    for tag in ALL_TAGS {
        assert!(
            inventory.contains(&format!("\"{tag}\"")),
            "{tag} is used by the aggregation layer but is not in src/crypto/domain_tags.rs"
        );
    }
}

#[test]
fn program_hashes_are_name_derived_and_distinct() {
    assert_eq!(agg_tick_program_hash(), agg_tick_program_hash());
    assert_ne!(agg_tick_program_hash(), agg_merge_program_hash());
    assert_eq!(auth_ok(), auth_ok());
    assert_ne!(auth_ok(), agg_tick_program_hash());
}

// -------------------------------------------------------------- digests ----

#[test]
fn claim_digest_is_domain_separated() {
    let one = claim_sig(0x01, 0x02, D1);
    let two = claim_sig(0x01, 0x02, D2);
    assert_ne!(claim_digest(D1, &one), claim_digest(D2, &two));
}

#[test]
fn claim_digest_covers_every_sig_field() {
    let base = claim_sig(0x01, 0x02, D1);
    let other_scheme = Claim::Sig {
        scheme: 0x0201,
        signer: Address(fill(0x01)),
        msg_hash: fill(0x02),
    };
    let other_signer = claim_sig(0x09, 0x02, D1);
    let other_msg = claim_sig(0x01, 0x09, D1);
    let base_digest = claim_digest(D1, &base);
    assert_ne!(base_digest, claim_digest(D1, &other_scheme));
    assert_ne!(base_digest, claim_digest(D1, &other_signer));
    assert_ne!(base_digest, claim_digest(D1, &other_msg));
}

#[test]
fn claim_digest_covers_every_prog_field() {
    let claim = claim_from_envelope(&stark_env(0x01, 0x02, 0x03, D1)).expect("derives");
    let base = claim_digest(D1, &claim);
    for other in [
        claim_from_envelope(&stark_env(0x09, 0x02, 0x03, D1)).unwrap(),
        claim_from_envelope(&stark_env(0x01, 0x09, 0x03, D1)).unwrap(),
        claim_from_envelope(&stark_env(0x01, 0x02, 0x09, D1)).unwrap(),
    ] {
        assert_ne!(base, claim_digest(D1, &other));
    }
}

#[test]
fn claim_digest_covers_every_poly_field() {
    let claim =
        claim_from_envelope(&pcs_env(0x01, [1, 2, 3, 4], [5, 6, 7, 8], D1)).expect("derives");
    let base = claim_digest(D1, &claim);
    for other in [
        claim_from_envelope(&pcs_env(0x09, [1, 2, 3, 4], [5, 6, 7, 8], D1)).unwrap(),
        claim_from_envelope(&pcs_env(0x01, [9, 2, 3, 4], [5, 6, 7, 8], D1)).unwrap(),
        claim_from_envelope(&pcs_env(0x01, [1, 2, 3, 4], [9, 6, 7, 8], D1)).unwrap(),
    ] {
        assert_ne!(base, claim_digest(D1, &other));
    }
}

#[test]
fn claim_digest_distinguishes_variants_with_the_same_bytes() {
    // A `Sig` and a `Prog` that name the same three 32-byte values must not
    // collide: the variant tag is part of the preimage.
    let sig = Claim::Sig {
        scheme: 0x0101,
        signer: Address(fill(0x01)),
        msg_hash: fill(0x02),
    };
    let prog = Claim::Prog {
        program_hash: fill(0x01),
        input_hash: fill(0x02),
        output_hash: fill(0x03),
    };
    assert_ne!(claim_digest(D1, &sig), claim_digest(D1, &prog));
}

#[test]
fn claims_root_rejects_empty() {
    assert_eq!(claims_root(&[]), Err(AggError::Empty));
    assert_eq!(claims_root_of(D1, &[]), Err(AggError::Empty));
}

#[test]
fn claims_root_is_order_sensitive() {
    let a = claim_digest(D1, &claim_sig(0x01, 0x01, D1));
    let b = claim_digest(D1, &claim_sig(0x02, 0x02, D1));
    assert_ne!(claims_root(&[a, b]).unwrap(), claims_root(&[b, a]).unwrap());
}

#[test]
fn claims_root_single_leaf_is_the_leaf_hash() {
    let a = claim_digest(D1, &claim_sig(0x01, 0x01, D1));
    let root = claims_root(&[a]).unwrap();
    assert_ne!(
        root, a,
        "the leaf hash must be domain separated from the digest"
    );
    assert_eq!(root, claims_root(&[a]).unwrap());
}

#[test]
fn claims_root_promotes_an_odd_leaf_instead_of_duplicating_it() {
    // The duplicate-leaf shape is the CVE-2012-2459 class: a tree over [a,b,c]
    // must not collide with a tree over [a,b,c,c].
    let a = claim_digest(D1, &claim_sig(0x01, 0x01, D1));
    let b = claim_digest(D1, &claim_sig(0x02, 0x02, D1));
    let c = claim_digest(D1, &claim_sig(0x03, 0x03, D1));
    let three = claims_root(&[a, b, c]).unwrap();
    let four_with_duplicate = claims_root(&[a, b, c, c]).unwrap();
    assert_ne!(three, four_with_duplicate);
}

#[test]
fn tick_pi_binds_every_field() {
    let segment = Segment {
        claims_root: fill(0x01),
        count: 2,
        aggregator: Address(fill(0x02)),
    };
    let base = tick_pi(D1, &segment);
    let other_root = Segment {
        claims_root: fill(0x09),
        ..segment
    };
    let other_count = Segment {
        count: 3,
        ..segment
    };
    let other_aggregator = Segment {
        aggregator: Address(fill(0x09)),
        ..segment
    };
    assert_ne!(base, tick_pi(D1, &other_root));
    assert_ne!(base, tick_pi(D1, &other_count));
    assert_ne!(base, tick_pi(D1, &other_aggregator));
    assert_ne!(base, tick_pi(D2, &segment));
}

#[test]
fn object_id_is_deterministic_and_binds_every_field() {
    let envelope = sig_env(SCHEME_OK, 0x01, 0x02, 0x01, D1);
    assert_eq!(object_id(&envelope), object_id(&envelope.clone()));
    let mut other = envelope.clone();
    other.domain = D2;
    assert_ne!(object_id(&envelope), object_id(&other));
    let mut other = envelope.clone();
    other.tx_hash = fill(0x09);
    assert_ne!(object_id(&envelope), object_id(&other));
    let mut other = envelope.clone();
    other.scheme = 0x0201;
    assert_ne!(object_id(&envelope), object_id(&other));
    let mut other = envelope.clone();
    other.payload.push(0x00);
    assert_ne!(object_id(&envelope), object_id(&other));
}

#[test]
fn envelope_encoding_is_length_prefixed() {
    // A payload of "ab" and a payload of "a" followed by a different tx hash
    // must not produce the same preimage: the length prefix is what stops the
    // boundary from moving.
    let mut one = sig_env(SCHEME_OK, 0x01, 0x02, 0x01, D1);
    one.payload = vec![0xAB, 0xCD];
    let mut two = sig_env(SCHEME_OK, 0x01, 0x02, 0x01, D1);
    two.payload = vec![0xAB];
    assert_ne!(object_id(&one), object_id(&two));
}

#[test]
fn adapter_binding_and_finality_claim_are_bound() {
    let one = adapter_binding("pow-header-chain-v1", "v1");
    let two = adapter_binding("pow-header-chain-v1", "v2");
    assert_ne!(one, two);
    assert_ne!(
        finality_claim(one, &fill(0x01)),
        finality_claim(two, &fill(0x01))
    );
    assert_ne!(
        finality_claim(one, &fill(0x01)),
        finality_claim(one, &fill(0x02))
    );
}

#[test]
fn params_hash_changes_with_every_consensus_field() {
    let base = params_hash(&params_on());
    let mut other = params_on();
    other.max_claims_per_block += 1;
    assert_ne!(base, params_hash(&other));
    let mut other = params_on();
    other.max_proof_bytes += 1;
    assert_ne!(base, params_hash(&other));
    let mut other = params_on();
    other.claim_fee_per_byte += 1;
    assert_ne!(base, params_hash(&other));
    let mut other = params_on();
    other.agg_share_bps += 1;
    assert_ne!(base, params_hash(&other));
    // A node parameter outside the consensus set must not move the digest.
    let mut other = params_on();
    other.tick_ms += 1;
    assert_eq!(base, params_hash(&other));
}

// ----------------------------------------------------------- fold_shape ----

fn segment(root: u8, count: u32) -> Segment {
    Segment {
        claims_root: fill(root),
        count,
        aggregator: Address(fill(0x77)),
    }
}

#[test]
fn fold_shape_accepts_a_single_tick() {
    let one = segment(0x01, 1);
    assert_eq!(fold_shape(D1, &[one], &[0]).unwrap(), tick_pi(D1, &one));
}

#[test]
fn fold_shape_accepts_a_balanced_tree() {
    let (a, b, c, d) = (
        segment(0x01, 1),
        segment(0x02, 1),
        segment(0x03, 1),
        segment(0x04, 1),
    );
    let got = fold_shape(D1, &[a, b, c, d], &[0, 0, 1, 0, 0, 1, 1]).unwrap();
    let expected = merge_pi(
        merge_pi(tick_pi(D1, &a), tick_pi(D1, &b)),
        merge_pi(tick_pi(D1, &c), tick_pi(D1, &d)),
    );
    assert_eq!(got, expected);
}

#[test]
fn fold_shape_accepts_an_unbalanced_tree() {
    let (a, b, c) = (segment(0x01, 1), segment(0x02, 1), segment(0x03, 1));
    let got = fold_shape(D1, &[a, b, c], &[0, 0, 1, 0, 1]).unwrap();
    let expected = merge_pi(merge_pi(tick_pi(D1, &a), tick_pi(D1, &b)), tick_pi(D1, &c));
    assert_eq!(got, expected);
}

#[test]
fn fold_shape_rejects_an_unconsumed_segment() {
    let (a, b) = (segment(0x01, 1), segment(0x02, 1));
    assert_eq!(fold_shape(D1, &[a, b], &[0]), Err(AggError::BadShape));
}

#[test]
fn fold_shape_rejects_a_missing_segment() {
    let a = segment(0x01, 1);
    assert_eq!(fold_shape(D1, &[a], &[0, 0, 1]), Err(AggError::BadShape));
}

#[test]
fn fold_shape_rejects_merge_underflow() {
    assert_eq!(fold_shape(D1, &[], &[1]), Err(AggError::BadShape));
    let a = segment(0x01, 1);
    assert_eq!(fold_shape(D1, &[a], &[0, 1]), Err(AggError::BadShape));
}

#[test]
fn fold_shape_rejects_an_unknown_operator() {
    let a = segment(0x01, 1);
    assert_eq!(fold_shape(D1, &[a], &[2]), Err(AggError::BadShape));
    assert_eq!(fold_shape(D1, &[a], &[0, 0xFF]), Err(AggError::BadShape));
}

#[test]
fn fold_shape_rejects_an_empty_shape() {
    assert_eq!(fold_shape(D1, &[], &[]), Err(AggError::Empty));
}

#[test]
fn fold_shape_is_deterministic_and_binds_the_domain() {
    let (a, b) = (segment(0x01, 1), segment(0x02, 1));
    let one = fold_shape(D1, &[a, b], &[0, 0, 1]).unwrap();
    let two = fold_shape(D1, &[a, b], &[0, 0, 1]).unwrap();
    assert_eq!(one, two);
    assert_ne!(one, fold_shape(D2, &[a, b], &[0, 0, 1]).unwrap());
}

// -------------------------------------------------------- claim derivation --

#[test]
fn claim_derivation_refuses_a_truncated_payload() {
    for envelope in [
        Envelope {
            kind: ObjectKind::Signature,
            scheme: SCHEME_OK,
            payload: vec![0u8; 32],
            tx_hash: fill(0xAA),
            domain: D1,
        },
        Envelope {
            kind: ObjectKind::StarkProof,
            scheme: 0x1001,
            payload: vec![0u8; 64],
            tx_hash: fill(0xAA),
            domain: D1,
        },
        Envelope {
            kind: ObjectKind::PcsOpening,
            scheme: 0x2001,
            payload: vec![0u8; 95],
            tx_hash: fill(0xAA),
            domain: D1,
        },
    ] {
        assert_eq!(
            claim_from_envelope(&envelope),
            Err(AggError::MalformedObject)
        );
    }
}

#[test]
fn claim_derivation_refuses_an_empty_tail() {
    let envelope = Envelope {
        kind: ObjectKind::Signature,
        scheme: SCHEME_OK,
        payload: vec![0u8; 64],
        tx_hash: fill(0xAA),
        domain: D1,
    };
    assert_eq!(
        claim_from_envelope(&envelope),
        Err(AggError::MalformedObject)
    );
}

#[test]
fn claim_derivation_is_the_only_constructor_the_backend_accepts() {
    let mut item = sig_item(0x01, 0x01, D1);
    item.claim = claim_sig(0x09, 0x09, D1);
    let refused = backend().prove_tick(&ctx(D1), &[item]);
    assert_eq!(refused, Err(AggError::ClaimMismatch));
}

// ------------------------------------------------------------ prove_tick ----

#[test]
fn prove_tick_is_order_independent() {
    let one = backend()
        .prove_tick(
            &ctx(D1),
            &[
                sig_item(0x01, 0x01, D1),
                sig_item(0x02, 0x02, D1),
                sig_item(0x03, 0x03, D1),
            ],
        )
        .expect("frame");
    let two = backend()
        .prove_tick(
            &ctx(D1),
            &[
                sig_item(0x03, 0x03, D1),
                sig_item(0x01, 0x01, D1),
                sig_item(0x02, 0x02, D1),
            ],
        )
        .expect("frame");
    assert_eq!(one.claims, two.claims);
    assert_eq!(one.segments, two.segments);
    assert_eq!(one.shape, vec![0u8]);
}

#[test]
fn prove_tick_orders_claims_by_digest() {
    let frame = backend()
        .prove_tick(
            &ctx(D1),
            &[
                sig_item(0x0F, 0x0F, D1),
                sig_item(0x01, 0x01, D1),
                sig_item(0x08, 0x08, D1),
            ],
        )
        .expect("frame");
    let digests: Vec<Hash> = frame.claims.iter().map(|c| claim_digest(D1, c)).collect();
    let mut sorted = digests.clone();
    sorted.sort_unstable();
    assert_eq!(digests, sorted);
}

#[test]
fn prove_tick_refuses_a_foreign_domain_envelope() {
    let item = sig_item(0x01, 0x01, D2);
    assert_eq!(
        backend().prove_tick(&ctx(D1), &[item]),
        Err(AggError::WrongDomain {
            envelope: D2,
            expected: D1
        })
    );
}

#[test]
fn prove_tick_refuses_an_unregistered_signature_scheme() {
    let item = pool_item(sig_env(0x0999, 0x01, 0x01, 0x01, D1)).expect("derives");
    assert_eq!(
        backend().prove_tick(&ctx(D1), &[item]),
        Err(AggError::UnknownScheme(0x0999))
    );
}

#[test]
fn prove_tick_refuses_an_oversize_object() {
    let mut item = sig_item(0x01, 0x01, D1);
    item.envelope.payload = vec![0u8; 6_145];
    assert!(matches!(
        backend().prove_tick(&ctx(D1), &[item]),
        Err(AggError::ObjectTooLarge { .. })
    ));
}

#[test]
fn prove_tick_refuses_when_off() {
    let off = TickCtx {
        domain: D1,
        aggregator: Address::zero(),
        params: AggParams::default(),
    };
    assert_eq!(
        backend().prove_tick(&off, &[sig_item(0x01, 0x01, D1)]),
        Err(AggError::Disabled)
    );
}

#[test]
fn prove_tick_refuses_more_objects_than_a_tick_holds() {
    let mut params = params_on();
    params.tick_max_objects = 1;
    let tick = TickCtx {
        domain: D1,
        aggregator: Address::zero(),
        params,
    };
    assert_eq!(
        backend().prove_tick(&tick, &[sig_item(0x01, 0x01, D1), sig_item(0x02, 0x02, D1)]),
        Err(AggError::TooManyObjects { have: 2, max: 1 })
    );
}

#[test]
fn prove_tick_refuses_an_empty_tick() {
    assert_eq!(backend().prove_tick(&ctx(D1), &[]), Err(AggError::Empty));
}

#[test]
fn verifier_refusal_propagates_and_no_frame_is_built() {
    let bad = pool_item(sig_env(SCHEME_OK, 0x01, 0x01, 0xFF, D1)).expect("derives");
    assert!(matches!(
        backend().prove_tick(&ctx(D1), &[bad]),
        Err(AggError::VerifierRefused("bad signature"))
    ));
}

#[test]
fn structural_verifier_accepts_structure_and_says_nothing_about_crypto() {
    // The reference verifier is structural only; this test pins that it is
    // still wired through the same trait the production verifier will be.
    let envelope = sig_env(SCHEME_OK, 0x01, 0x01, 0xFF, D1);
    let claim = claim_from_envelope(&envelope).expect("derives");
    assert!(StructuralVerifier.verify(&envelope, &claim).is_ok());
}

// --------------------------------------------------------------- verify ----

#[test]
fn verify_accepts_a_well_formed_frame() {
    let frame = backend()
        .prove_tick(
            &ctx(D1),
            &[sig_item(0x01, 0x01, D1), sig_item(0x02, 0x02, D1)],
        )
        .expect("frame");
    assert!(backend().verify(&frame, &ctx(D1)).is_ok());
    assert!(verify_frame(&frame, &ctx(D1)).is_ok());
}

#[test]
fn verify_rejects_empty_claims() {
    let frame = ClaimFrame {
        segments: vec![segment(0x01, 0)],
        shape: vec![0],
        claims: vec![],
        proof: vec![0x01],
    };
    assert_eq!(verify_frame(&frame, &ctx(D1)), Err(AggError::Empty));
}

#[test]
fn verify_rejects_a_duplicate_claim() {
    let claim = claim_sig(0x01, 0x01, D1);
    let root = claims_root_of(D1, &[claim, claim]).expect("root");
    let frame = ClaimFrame {
        segments: vec![Segment {
            claims_root: root,
            count: 2,
            aggregator: Address(fill(0x77)),
        }],
        shape: vec![0],
        claims: vec![claim, claim],
        proof: vec![0x01],
    };
    assert_eq!(
        verify_frame(&frame, &ctx(D1)),
        Err(AggError::DuplicateClaim)
    );
}

#[test]
fn verify_rejects_a_count_that_does_not_partition_the_claims() {
    let one = claim_sig(0x01, 0x01, D1);
    let two = claim_sig(0x02, 0x02, D1);
    let root = claims_root_of(D1, &[one, two]).expect("root");
    let frame = ClaimFrame {
        segments: vec![Segment {
            claims_root: root,
            count: 1,
            aggregator: Address(fill(0x77)),
        }],
        shape: vec![0],
        claims: vec![one, two],
        proof: vec![0x01],
    };
    assert_eq!(
        verify_frame(&frame, &ctx(D1)),
        Err(AggError::CountMismatch {
            declared: 1,
            actual: 2
        })
    );
}

#[test]
fn verify_rejects_a_tampered_segment_root() {
    let mut frame = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x01, 0x01, D1)])
        .expect("frame");
    frame.segments[0].claims_root = fill(0xEE);
    assert_eq!(
        verify_frame(&frame, &ctx(D1)),
        Err(AggError::RootMismatch { index: 0 })
    );
}

#[test]
fn verify_rejects_a_tampered_count_that_stays_consistent() {
    // Two claims, one segment, count says 2, but the root is of the first only:
    // rule 3 catches it even though rule 2 passes.
    let one = claim_sig(0x01, 0x01, D1);
    let two = claim_sig(0x02, 0x02, D1);
    let frame = ClaimFrame {
        segments: vec![Segment {
            claims_root: claims_root_of(D1, &[one]).expect("root"),
            count: 2,
            aggregator: Address(fill(0x77)),
        }],
        shape: vec![0],
        claims: vec![one, two],
        proof: vec![0x01],
    };
    assert_eq!(
        verify_frame(&frame, &ctx(D1)),
        Err(AggError::RootMismatch { index: 0 })
    );
}

#[test]
fn verify_rejects_swapped_segments() {
    let (mut a, b) = two_frames();
    let merged = combine(&backend(), &a, &b).expect("merge");
    a = merged;
    a.segments.swap(0, 1);
    assert_eq!(
        verify_frame(&a, &ctx(D1)),
        Err(AggError::RootMismatch { index: 0 })
    );
}

#[test]
fn verify_rejects_a_frame_from_another_domain() {
    let frame = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x01, 0x01, D1)])
        .expect("frame");
    // Same bytes, different domain context: the claim digests move, so rule 3
    // refuses. This is the cross-domain replay boundary.
    assert_eq!(
        verify_frame(&frame, &ctx(D2)),
        Err(AggError::RootMismatch { index: 0 })
    );
}

#[test]
fn verify_rejects_more_claims_than_the_cap() {
    let mut params = params_on();
    params.max_claims_per_block = 2;
    let tick = TickCtx {
        domain: D1,
        aggregator: Address(fill(0x77)),
        params,
    };
    let frame = backend()
        .prove_tick(
            &ctx(D1),
            &[
                sig_item(0x01, 0x01, D1),
                sig_item(0x02, 0x02, D1),
                sig_item(0x03, 0x03, D1),
            ],
        )
        .expect("frame");
    assert_eq!(
        verify_frame(&frame, &tick),
        Err(AggError::TooManyClaims { have: 3, max: 2 })
    );
}

#[test]
fn verify_rejects_an_oversize_proof() {
    let mut params = params_on();
    params.max_proof_bytes = 4;
    let tick = TickCtx {
        domain: D1,
        aggregator: Address(fill(0x77)),
        params,
    };
    let frame = ClaimFrame {
        segments: vec![Segment {
            claims_root: claims_root_of(D1, &[claim_sig(0x01, 0x01, D1)]).expect("root"),
            count: 1,
            aggregator: Address(fill(0x77)),
        }],
        shape: vec![0],
        claims: vec![claim_sig(0x01, 0x01, D1)],
        proof: vec![0x01; 5],
    };
    assert!(matches!(
        verify_frame(&frame, &tick),
        Err(AggError::ProofTooLarge { have: 5, max: 4 })
    ));
}

#[test]
fn verify_rejects_a_bad_shape() {
    let frame = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x01, 0x01, D1)])
        .expect("frame");
    let mut broken = frame.clone();
    broken.shape = vec![0, 0, 1];
    assert_eq!(verify_frame(&broken, &ctx(D1)), Err(AggError::BadShape));
}

#[test]
fn frame_hash_binds_master_pi_params_and_proof() {
    let frame = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x01, 0x01, D1)])
        .expect("frame");
    let master = master_pi(D1, &frame).expect("master");
    let base = frame_hash(master, &params_on(), &frame.proof);
    assert_ne!(base, frame_hash(fill(0xEE), &params_on(), &frame.proof));
    let mut other = params_on();
    other.max_claims_per_block += 1;
    assert_ne!(base, frame_hash(master, &other, &frame.proof));
    assert_ne!(base, frame_hash(master, &params_on(), b"another proof"));
}

#[test]
fn verify_frame_hash_accepts_the_right_hash_and_refuses_another() {
    let frame = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x01, 0x01, D1)])
        .expect("frame");
    let master = master_pi(D1, &frame).expect("master");
    let right = frame_hash(master, &params_on(), &frame.proof);
    assert!(verify_frame_hash(&frame, right, &ctx(D1)).is_ok());
    assert_eq!(
        verify_frame_hash(&frame, fill(0xEE), &ctx(D1)),
        Err(AggError::FrameHashMismatch)
    );
}

// --------------------------------------------------------------- combine ----

#[test]
fn combine_concatenates_and_pushes_one_merge() {
    let (a, b) = two_frames();
    let merged = combine(&backend(), &a, &b).expect("merge");
    assert_eq!(merged.segments.len(), 2);
    assert_eq!(merged.shape, vec![0, 0, 1]);
    assert_eq!(merged.claims.len(), a.claims.len() + b.claims.len());
    assert_eq!(merged.proof.len(), 32);
}

#[test]
fn combined_public_input_is_the_merge_of_the_public_inputs() {
    let (a, b) = two_frames();
    let merged = combine(&backend(), &a, &b).expect("merge");
    let expected = merge_pi(master_pi(D1, &a).unwrap(), master_pi(D1, &b).unwrap());
    assert_eq!(master_pi(D1, &merged).unwrap(), expected);
}

#[test]
fn a_three_way_merge_verifies() {
    let (a, b) = two_frames();
    let c = backend()
        .prove_tick(&ctx(D1), &[sig_item(0x05, 0x05, D1)])
        .expect("frame c");
    let ab = combine(&backend(), &a, &b).expect("ab");
    let abc = combine(&backend(), &ab, &c).expect("abc");
    assert!(verify_frame(&abc, &ctx(D1)).is_ok());
    assert_eq!(abc.shape, vec![0, 0, 1, 0, 1]);
}

#[test]
fn combine_refuses_an_empty_side() {
    let (a, _) = two_frames();
    let empty = ClaimFrame {
        segments: vec![],
        shape: vec![],
        claims: vec![],
        proof: vec![],
    };
    assert_eq!(combine(&backend(), &a, &empty), Err(AggError::Empty));
}

// ------------------------------------------------------------------ pool ----

fn small_pool(params: AggParams) -> AggPool {
    AggPool::new(params, SchemeRegistry::budlum_reference())
}

fn sized_sig_item(signer: u8, payload_len: usize, domain: DomainId) -> PoolItem {
    let mut envelope = sig_env(SCHEME_OK, signer, signer, 0x01, domain);
    envelope.payload = vec![0x01; payload_len];
    let mut payload = sig_payload(signer, signer, 0x01);
    payload.resize(payload_len, 0x01);
    envelope.payload = payload;
    pool_item(envelope).expect("derives")
}

#[test]
fn pool_refuses_a_duplicate_object() {
    let mut pool = small_pool(params_on());
    let item = sig_item(0x01, 0x01, D1);
    pool.admit(item.clone(), Address(fill(0x01)), 1, 0, true, &verifier())
        .expect("first admit");
    assert!(matches!(
        pool.admit(item, Address(fill(0x01)), 1, 0, true, &verifier()),
        Err(AggError::DuplicateObject(_))
    ));
}

#[test]
fn pool_keeps_a_duplicate_refused_after_eviction() {
    // An object evicted for room is not new a tick later: the id stays in the
    // seen set, so re-sending it is refused rather than paid twice.
    let mut params = params_on();
    params.pool_max_bytes = 200;
    let mut pool = small_pool(params);
    let small = sized_sig_item(0x01, 70, D1);
    pool.admit(small.clone(), Address(fill(0x01)), 1, 0, true, &verifier())
        .expect("admit small");
    let big = sized_sig_item(0x02, 150, D1);
    pool.admit(big, Address(fill(0x02)), 10_000, 0, true, &verifier())
        .expect("admit big evicts small");
    assert_eq!(pool.len(), 1, "the small object was evicted for room");
    assert!(matches!(
        pool.admit(small, Address(fill(0x01)), 1, 1, true, &verifier()),
        Err(AggError::DuplicateObject(_))
    ));
    // The id is still in the seen set even though the payload is gone, which is
    // the point: eviction is not a forget.
}

#[test]
fn pool_enforces_the_sender_tick_limit() {
    let mut params = params_on();
    params.sender_tick_limit = 2;
    let mut pool = small_pool(params);
    let sender = Address(fill(0x01));
    for n in 0..2u8 {
        pool.admit(
            sig_item(0x10 + n, 0x10 + n, D1),
            sender,
            1,
            0,
            true,
            &verifier(),
        )
        .expect("under the limit");
    }
    assert_eq!(
        pool.admit(sig_item(0x20, 0x20, D1), sender, 1, 0, true, &verifier()),
        Err(AggError::SenderLimit { sender })
    );
    // A different tick is a different allowance.
    pool.admit(sig_item(0x30, 0x30, D1), sender, 1, 1, true, &verifier())
        .expect("next tick");
}

#[test]
fn pool_refuses_a_cheap_object_when_it_is_the_cheapest() {
    let mut params = params_on();
    params.pool_max_bytes = 220;
    let mut pool = small_pool(params);
    pool.admit(
        sized_sig_item(0x01, 70, D1),
        Address(fill(0x01)),
        5_000,
        0,
        true,
        &verifier(),
    )
    .expect("first");
    pool.admit(
        sized_sig_item(0x02, 70, D1),
        Address(fill(0x02)),
        5_000,
        0,
        true,
        &verifier(),
    )
    .expect("second");
    assert_eq!(
        pool.admit(
            sized_sig_item(0x03, 200, D1),
            Address(fill(0x03)),
            0,
            0,
            true,
            &verifier()
        ),
        Err(AggError::PoolFull)
    );
}

#[test]
fn pool_takes_the_highest_fee_first() {
    let mut pool = small_pool(params_on());
    pool.admit(
        sig_item(0x01, 0x01, D1),
        Address(fill(0x01)),
        1,
        0,
        true,
        &verifier(),
    )
    .expect("cheap");
    pool.admit(
        sig_item(0x02, 0x02, D1),
        Address(fill(0x02)),
        900,
        0,
        true,
        &verifier(),
    )
    .expect("rich");
    let taken = pool.take_tick(0, 8).expect("a tick");
    assert_eq!(taken.len(), 2);
    assert_eq!(
        claim_from_envelope(&taken[0].envelope).unwrap(),
        claim_sig(0x02, 0x02, D1)
    );
    // Taking again finds nothing new.
    assert_eq!(pool.take_tick(1, 8), Err(AggError::Empty));
}

#[test]
fn pool_expires_orphans_after_two_ticks_and_keeps_known_transactions() {
    let mut pool = small_pool(params_on());
    pool.admit(
        sig_item(0x01, 0x01, D1),
        Address(fill(0x01)),
        1,
        0,
        false,
        &verifier(),
    )
    .expect("orphan");
    pool.admit(
        sig_item(0x02, 0x02, D1),
        Address(fill(0x02)),
        1,
        0,
        true,
        &verifier(),
    )
    .expect("known");
    assert_eq!(pool.expire_orphans(2), 0, "two ticks is the grace period");
    assert_eq!(pool.expire_orphans(3), 1, "the orphan is dropped");
    assert_eq!(pool.len(), 1, "the known transaction stays");
}

#[test]
fn pool_release_proven_drops_payloads_and_bytes() {
    let mut pool = small_pool(params_on());
    let id = pool
        .admit(
            sig_item(0x01, 0x01, D1),
            Address(fill(0x01)),
            1,
            0,
            true,
            &verifier(),
        )
        .expect("admit");
    let before = pool.bytes();
    assert!(before > 0);
    let released = pool.release_proven(&[id]);
    assert_eq!(released, before);
    assert_eq!(pool.bytes(), 0);
    assert_eq!(pool.len(), 1, "the claim is kept until the block is final");
}

#[test]
fn pool_refuses_an_object_over_its_scheme_ceiling_before_it_is_verified() {
    let mut pool = small_pool(params_on());
    let mut item = sig_item(0x01, 0x01, D1);
    item.envelope.payload = vec![0u8; 6_145];
    assert!(matches!(
        pool.admit(item, Address(fill(0x01)), 1, 0, true, &verifier()),
        Err(AggError::ObjectTooLarge { .. })
    ));
    assert_eq!(pool.len(), 0);
}

#[test]
fn scheme_registry_refuses_a_duplicate_id_and_an_unknown_lookup() {
    let mut registry = SchemeRegistry::empty();
    registry
        .insert(SchemeDef {
            id: 7,
            name: "a",
            max_object_bytes: 10,
        })
        .expect("first");
    assert_eq!(
        registry.insert(SchemeDef {
            id: 7,
            name: "b",
            max_object_bytes: 20
        }),
        Err(AggError::DuplicateScheme(7))
    );
    assert!(registry.get(8).is_none());
    assert!(SchemeRegistry::empty().get(7).is_none());
}

// ----------------------------------------------------------- type shape ----

#[test]
fn address_is_a_32_byte_transparent_wrapper() {
    // The swap from this type to `crate::core::address::Address` is a `use`
    // change only if the layout is the same: this pins it.
    assert_eq!(std::mem::size_of::<Address>(), 32);
    assert_eq!(std::mem::align_of::<Address>(), 1);
    assert_eq!(Address::zero().0, [0u8; 32]);
    assert_eq!(*Address(fill(0x05)).as_bytes(), fill(0x05));
}

#[test]
fn ext_encoding_is_fixed_width_little_endian() {
    let value = Ext([1, 2, 3, 4]);
    let bytes = value.canonical_bytes();
    assert_eq!(&bytes[..8], &1u64.to_le_bytes());
    assert_eq!(&bytes[24..], &4u64.to_le_bytes());
    assert_eq!(Ext([1, 2, 3, 4]).canonical_bytes(), bytes);
}

#[test]
fn object_kind_tags_round_trip_and_refuse_the_unknown() {
    for kind in [
        ObjectKind::Signature,
        ObjectKind::StarkProof,
        ObjectKind::PcsOpening,
    ] {
        assert_eq!(ObjectKind::from_tag(kind.tag()), Some(kind));
    }
    assert_eq!(ObjectKind::from_tag(3), None);
    assert_eq!(ObjectKind::from_tag(0xFF), None);
}

#[test]
fn block_rules_not_in_this_layer_are_named() {
    // The three rules that need the block's transaction set are listed as data
    // with the reason each one is out of scope here, so a reader checks a list
    // instead of a sentence.
    assert_eq!(BLOCK_RULES_NOT_IN_THIS_LAYER.len(), 3);
    for (rule, reason) in BLOCK_RULES_NOT_IN_THIS_LAYER {
        assert!(rule.starts_with("rule-"));
        assert!(reason.contains("transaction set"));
    }
}

// --------------------------------------------------------- source gates ----

fn production_source(file: &str) -> &'static str {
    match file {
        "types" => include_str!("types.rs"),
        "digest" => include_str!("digest.rs"),
        "backend" => include_str!("backend.rs"),
        "pool" => include_str!("pool.rs"),
        "mod" => include_str!("mod.rs"),
        other => panic!("unknown source file {other}"),
    }
}

#[test]
fn production_sources_have_no_unwrap_expect_or_panic() {
    for file in ["types", "digest", "backend", "pool", "mod"] {
        let source = production_source(file);
        for needle in [
            ".unwrap(",
            ".expect(",
            "panic!(",
            "unreachable!(",
            "todo!(",
            "unimplemented!(",
        ] {
            assert!(
                !source.contains(needle),
                "{file}.rs contains {needle}, which the workspace refuses in production paths"
            );
        }
    }
}

#[test]
fn the_reference_backend_is_gated_out_of_the_production_profile() {
    let source = production_source("backend");
    // Every item that performs no cryptography must sit behind the native gate.
    for marker in ["pub struct StructuralVerifier", "pub struct NativeBackend"] {
        let at = source.find(marker).expect("marker is present");
        let before = &source[..at];
        let gate = before.rfind("#[cfg(").expect("a cfg precedes it");
        let cfg = &before[gate..];
        assert!(
            cfg.contains("feature = \"native-agg-backend\""),
            "{marker} is not behind the native-agg-backend gate"
        );
    }
    // And the default feature set must not turn the gate on.
    let cargo = include_str!("../../Cargo.toml");
    let default_line = cargo
        .lines()
        .find(|line| line.trim_start().starts_with("default = ["))
        .expect("the crate declares a default feature set");
    assert!(
        !default_line.contains("native-agg-backend"),
        "native-agg-backend must not be a default feature"
    );
}

#[test]
fn every_error_variant_is_a_refusal() {
    // Exhaustive match: adding a variant breaks this test, which is the reminder
    // that a new variant has to be a refusal and not an "accepted with a caveat"
    // path. No variant carries a success payload.
    fn is_refusal(error: &AggError) -> bool {
        match error {
            AggError::Empty
            | AggError::BadShape
            | AggError::CountMismatch { .. }
            | AggError::RootMismatch { .. }
            | AggError::DuplicateClaim
            | AggError::TooManyClaims { .. }
            | AggError::ProofTooLarge { .. }
            | AggError::ObjectTooLarge { .. }
            | AggError::UnknownScheme(_)
            | AggError::ClaimMismatch
            | AggError::MalformedObject
            | AggError::WrongDomain { .. }
            | AggError::DuplicateObject(_)
            | AggError::SenderLimit { .. }
            | AggError::PoolFull
            | AggError::FrameHashMismatch
            | AggError::DuplicateScheme(_)
            | AggError::ParamsMismatch
            | AggError::VerifierRefused(_)
            | AggError::Disabled
            | AggError::TooManyObjects { .. } => true,
        }
    }
    let samples = [
        AggError::Empty,
        AggError::BadShape,
        AggError::DuplicateClaim,
        AggError::MalformedObject,
        AggError::PoolFull,
        AggError::Disabled,
    ];
    for sample in &samples {
        assert!(is_refusal(sample));
    }
}
