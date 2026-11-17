//! Tests of the claim layer core. Known answers come from
//! an independent Keccak-256 written in Python, not from this crate.

use crate::aggregation::claim::{Claim, ClaimError, Ext, GOLDILOCKS_MODULUS};
use crate::aggregation::envelope::{Envelope, EnvelopeError, ObjectKind};
use crate::aggregation::frame::{
    fold_shape, frame_hash, merge_pi, tick_pi, AggProgram, ClaimFrame, FrameError, FrameLimits,
    Segment, SegmentAttestation, SHAPE_MERGE, SHAPE_TICK,
};
use crate::aggregation::hash::{
    auth_ok, TAG_AGG_MERGE, TAG_AGG_TICK, TAG_CLAIM, TAG_CLAIM_ROOT, TAG_FRAME, TAG_OBJECT,
};
use crate::aggregation::merkle::{claims_root, MerkleError};
use crate::aggregation::params::{AggMode, AggParams};
use crate::core::address::Address;
use crate::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;

const DOMAIN: u32 = 7;

/// Every tag of the aggregation layer.
const TAGS: [&[u8]; 8] = [
    TAG_CLAIM,
    TAG_CLAIM_ROOT,
    TAG_AGG_TICK,
    TAG_AGG_MERGE,
    b"BDLM_AGG_SEGMENT_AUTH_V1",
    TAG_OBJECT,
    TAG_FRAME,
    b"BDLM_AUTH_OK_V1",
];

fn hex32(s: &str) -> Hash32 {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn sig_claim() -> Claim {
    Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: Address::from([0x11; 32]),
        msg_hash: [0x22; 32],
    }
}

fn prog_claim() -> Claim {
    Claim::Prog {
        program_hash: [0x31; 32],
        input_hash: [0x32; 32],
        output_hash: [0x33; 32],
    }
}

fn poly_claim() -> Claim {
    Claim::Poly {
        poly_hash: [0x41; 32],
        point: Ext::new([1, 2, 3]).expect("canonical"),
        value: Ext::new([4, 5, GOLDILOCKS_MODULUS - 1]).expect("canonical"),
    }
}

/// `n` distinct signature claims.
fn claims(n: u8, salt: u8) -> Vec<Claim> {
    (0..n)
        .map(|i| Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: Address::from([salt; 32]),
            msg_hash: [i; 32],
        })
        .collect()
}

fn limits() -> FrameLimits {
    FrameLimits::from(&AggParams::default())
}

fn tick_frame(n: u8, salt: u8) -> ClaimFrame {
    ClaimFrame::tick(DOMAIN, &[salt; 32], claims(n, salt), vec![salt; 16]).expect("tick frame")
}

// ---- tags -----------------------------------------------------------------

#[test]
fn every_aggregation_tag_is_distinct_and_none_prefixes_another() {
    for (i, a) in TAGS.iter().enumerate() {
        assert!(a.starts_with(b"BDLM_"));
        for (j, b) in TAGS.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert!(!b.starts_with(a), "{a:?} is a prefix of {b:?}");
            }
        }
    }
}

/// Section 11, tag test, against the whole inventory: an aggregation tag is
/// listed, and neither it nor any other listed tag is a prefix of the other.
#[test]
fn no_aggregation_tag_shares_a_prefix_with_any_tag_of_the_inventory() {
    use crate::crypto::domain_tags::DOMAIN_TAGS;
    for tag in TAGS {
        let tag = std::str::from_utf8(tag).expect("ascii");
        assert!(DOMAIN_TAGS.contains(&tag), "{tag} is not in the inventory");
        for other in DOMAIN_TAGS {
            if *other != tag {
                assert!(
                    !other.starts_with(tag) && !tag.starts_with(other),
                    "{tag} and {other} share a prefix"
                );
            }
        }
    }
}

#[test]
fn auth_ok_is_the_hash_of_its_tag() {
    assert_eq!(
        auth_ok(),
        hex32("406ebd6719604c883cd619434babae16606de287165fd6eb390b08158db2cabe")
    );
}

/// The aggregation scheme registry repeats nothing by hand that the scheme
/// table of the chain already fixes.
#[test]
fn every_aggregation_scheme_matches_the_scheme_table() {
    for scheme in crate::aggregation::schemes::AGG_SCHEMES {
        let info = scheme.id.info().expect("listed in the scheme table");
        assert_eq!(scheme.name, info.canonical);
        assert_eq!(Some(scheme.public_key_bytes), info.public_key_len);
        assert_eq!(Some(scheme.signature_bytes), info.signature_len);
    }
}

// ---- claims ---------------------------------------------------------------

#[test]
fn claim_digests_match_the_independent_vectors() {
    assert_eq!(
        sig_claim().digest(DOMAIN),
        hex32("7f72e9e2ccd94919bf4d6095c2982a5f0da90ab87e1189fb5963d16aafa234b4")
    );
    assert_eq!(
        prog_claim().digest(DOMAIN),
        hex32("f7c21a21c97dd90feebd61a28f0bb8f359b23cd30f461823cac81ec314b8e90c")
    );
    assert_eq!(
        poly_claim().digest(DOMAIN),
        hex32("5a7d5bac133751b8c6a378a3742436934271bd2110c9f622e172a8f6c435dca2")
    );
}

#[test]
fn a_claim_of_another_domain_has_another_digest() {
    assert_eq!(
        sig_claim().digest(8),
        hex32("bbac1a64ab3686354b0f61d12584b5cc7871970e8e9dde48cf32de82a789cef5")
    );
    assert_ne!(sig_claim().digest(DOMAIN), sig_claim().digest(8));
}

#[test]
fn a_claim_is_between_64_and_97_bytes() {
    assert_eq!(sig_claim().encode().len(), 67);
    assert_eq!(prog_claim().encode().len(), 97);
    assert_eq!(poly_claim().encode().len(), 81);
    for c in [sig_claim(), prog_claim(), poly_claim()] {
        assert_eq!(c.encode().len(), c.encoded_len());
    }
}

#[test]
fn a_claim_round_trips_and_reports_what_it_consumed() {
    for c in [sig_claim(), prog_claim(), poly_claim()] {
        let mut bytes = c.encode();
        let len = bytes.len();
        bytes.extend_from_slice(&[0xEE, 0xEE]);
        assert_eq!(Claim::decode(&bytes), Ok((c, len)));
    }
}

#[test]
fn a_truncated_or_unknown_claim_is_refused() {
    for c in [sig_claim(), prog_claim(), poly_claim()] {
        let bytes = c.encode();
        for cut in 0..bytes.len() {
            assert_eq!(
                Claim::decode(&bytes[..cut]),
                Err(ClaimError::Truncated),
                "cut at {cut}"
            );
        }
    }
    assert_eq!(Claim::decode(&[0x00; 100]), Err(ClaimError::UnknownKind(0)));
    assert_eq!(Claim::decode(&[0x04; 100]), Err(ClaimError::UnknownKind(4)));
}

#[test]
fn a_field_element_outside_the_field_is_refused() {
    assert_eq!(
        Ext::new([0, 0, GOLDILOCKS_MODULUS]),
        Err(ClaimError::NonCanonicalFieldElement)
    );
    assert_eq!(
        Ext::new([u64::MAX, 0, 0]),
        Err(ClaimError::NonCanonicalFieldElement)
    );
    // The same value written unreduced must not decode: one claim, one encoding.
    let mut bytes = poly_claim().encode();
    let at = 1 + 32;
    bytes[at..at + 8].copy_from_slice(&GOLDILOCKS_MODULUS.wrapping_add(1).to_le_bytes());
    assert_eq!(
        Claim::decode(&bytes),
        Err(ClaimError::NonCanonicalFieldElement)
    );
}

// ---- merkle ---------------------------------------------------------------

#[test]
fn claim_roots_match_the_independent_vectors() {
    let d = [
        sig_claim().digest(DOMAIN),
        prog_claim().digest(DOMAIN),
        poly_claim().digest(DOMAIN),
    ];
    assert_eq!(
        claims_root(&d[..1]),
        Ok(hex32(
            "5ff2f909b910bca532ca1ec1bad14c238f73d71f5e767470f7a5c7bfb9e7365f"
        ))
    );
    assert_eq!(
        claims_root(&d[..2]),
        Ok(hex32(
            "31cf20ab600c0b5f35f9697c8c5fa0ffec319451e146a7c35109e85fee5c4baf"
        ))
    );
    assert_eq!(
        claims_root(&d),
        Ok(hex32(
            "d1a7cc867d85f65bdd0e068534c45467989dcd3766b674dde34f84678e59f911"
        ))
    );
    let five: Vec<Hash32> = (1..=5u8).map(|i| [i; 32]).collect();
    assert_eq!(
        claims_root(&five),
        Ok(hex32(
            "9e94f7570a7e40525b50672bbc4c4d30a1a34cd37a61a57a40a5989255e2778f"
        ))
    );
}

#[test]
fn an_empty_claim_list_has_no_root() {
    assert_eq!(claims_root(&[]), Err(MerkleError::Empty));
}

#[test]
fn a_single_leaf_root_is_not_the_digest_itself() {
    let d = sig_claim().digest(DOMAIN);
    assert_ne!(claims_root(&[d]), Ok(d));
}

#[test]
fn the_root_depends_on_the_order_of_the_leaves() {
    let a = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let b = [[2u8; 32], [1u8; 32], [3u8; 32]];
    assert_ne!(claims_root(&a), claims_root(&b));
}

// ---- public inputs and fold_shape ------------------------------------------

fn seg(root: Hash32, count: u32, aggregator: u8) -> Segment {
    Segment {
        claims_root: root,
        count,
        aggregator: Address::from([aggregator; 32]),
        attestation: SegmentAttestation {
            public_key: Box::new([0u8; ML_DSA_87_PUBLIC_KEY_LEN]),
            signature: Box::new([0u8; ML_DSA_87_SIGNATURE_LEN]),
        },
    }
}

fn two_segments() -> [Segment; 2] {
    let d = [
        sig_claim().digest(DOMAIN),
        prog_claim().digest(DOMAIN),
        poly_claim().digest(DOMAIN),
    ];
    [
        seg(claims_root(&d[..2]).expect("root"), 2, 0x55),
        seg(claims_root(&d[2..]).expect("root"), 1, 0x66),
    ]
}

#[test]
fn public_inputs_match_the_independent_vectors() {
    let segs = two_segments();
    let t1 = hex32("a7ff39884777190f3ba67a61fb4b1f703eeca2649658e329508d1994267d7860");
    let t2 = hex32("c1446ce3444562a789928221ee22234c74c40f494fc58ea4cee83cb294666067");
    let m = hex32("acd3591da554c4cb1340df13a1ecfde900b37da688bb064eef5ff024e593e0b2");
    assert_eq!(tick_pi(DOMAIN, &segs[0]), t1);
    assert_eq!(tick_pi(DOMAIN, &segs[1]), t2);
    assert_eq!(merge_pi(&t1, &t2), m);
    assert_eq!(
        frame_hash(&m, &segs, b"proof-bytes"),
        hex32("622f232493130b4e65244d3d2f92d408a067dc4b23c5aa555fbdc07b1265346b")
    );
}

#[test]
fn fold_shape_folds_one_segment_and_a_merge() {
    let segs = two_segments();
    assert_eq!(
        fold_shape(DOMAIN, &segs[..1], &[SHAPE_TICK]),
        Ok(tick_pi(DOMAIN, &segs[0]))
    );
    assert_eq!(
        fold_shape(DOMAIN, &segs, &[SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE]),
        Ok(hex32(
            "acd3591da554c4cb1340df13a1ecfde900b37da688bb064eef5ff024e593e0b2"
        ))
    );
}

#[test]
fn fold_shape_refuses_every_malformed_shape() {
    let segs = two_segments();
    let bad: [&[u8]; 9] = [
        &[],                                                 // nothing on the stack
        &[SHAPE_MERGE],                                      // merge with an empty stack
        &[SHAPE_TICK, SHAPE_MERGE],                          // merge with one entry
        &[SHAPE_TICK],                                       // a segment is not consumed
        &[SHAPE_TICK, SHAPE_TICK],                           // two entries stay
        &[SHAPE_TICK, SHAPE_TICK, SHAPE_TICK],               // more ticks than segments
        &[SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE, SHAPE_MERGE], // one merge too many
        &[SHAPE_TICK, SHAPE_TICK, 2],                        // unknown op
        &[SHAPE_TICK, SHAPE_MERGE, SHAPE_TICK],              // merge before its operands
    ];
    for shape in bad {
        assert_eq!(
            fold_shape(DOMAIN, &segs, shape),
            Err(FrameError::BadShape),
            "{shape:?}"
        );
    }
    assert_eq!(fold_shape(DOMAIN, &[], &[]), Err(FrameError::BadShape));
}

#[test]
fn the_public_input_binds_domain_count_root_and_aggregator() {
    let [s, _] = two_segments();
    let base = tick_pi(DOMAIN, &s);
    assert_ne!(tick_pi(DOMAIN + 1, &s), base);
    assert_ne!(
        tick_pi(DOMAIN, &seg(s.claims_root, s.count + 1, 0x55)),
        base
    );
    assert_ne!(tick_pi(DOMAIN, &seg([0xAB; 32], s.count, 0x55)), base);
    assert_ne!(tick_pi(DOMAIN, &seg(s.claims_root, s.count, 0x56)), base);
}

#[test]
fn merge_is_not_commutative() {
    let (a, b) = ([1u8; 32], [2u8; 32]);
    assert_ne!(merge_pi(&a, &b), merge_pi(&b, &a));
}

// ---- frames ---------------------------------------------------------------

#[test]
fn a_tick_frame_sorts_its_claims_and_passes_the_structure_rules() {
    let frame = tick_frame(5, 0x10);
    let digests: Vec<Hash32> = frame.claims.iter().map(|c| c.digest(DOMAIN)).collect();
    let mut sorted = digests.clone();
    sorted.sort_unstable();
    assert_eq!(digests, sorted);
    let facts = frame.check_structure(DOMAIN, &limits()).expect("valid");
    assert_eq!(facts.program, AggProgram::Tick);
    assert_eq!(facts.claim_digests, digests);
    assert_eq!(facts.master_pi, tick_pi(DOMAIN, &frame.segments[0]));
    assert_eq!(frame.shape, vec![SHAPE_TICK]);
}

#[test]
fn combine_follows_the_directive_and_folds_to_the_merge_input() {
    let (left, right) = (tick_frame(3, 0x10), tick_frame(2, 0x20));
    let pair = ClaimFrame::combine(&left, &right, vec![0xCC; 8]).expect("combine");
    assert_eq!(
        pair.segments,
        [left.segments.clone(), right.segments.clone()].concat()
    );
    assert_eq!(pair.shape, vec![SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE]);
    assert_eq!(
        pair.claims,
        [left.claims.clone(), right.claims.clone()].concat()
    );
    let facts = pair.check_structure(DOMAIN, &limits()).expect("valid");
    assert_eq!(facts.program, AggProgram::Merge);
    let pi = |frame: &ClaimFrame| {
        frame
            .check_structure(DOMAIN, &limits())
            .expect("valid")
            .master_pi
    };
    assert_eq!(facts.master_pi, merge_pi(&pi(&left), &pi(&right)));
    // A third frame on top: ((left right) third).
    let third = tick_frame(1, 0x30);
    let triple = ClaimFrame::combine(&pair, &third, vec![]).expect("combine");
    assert_eq!(
        triple.shape,
        vec![SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE, SHAPE_TICK, SHAPE_MERGE]
    );
    assert_eq!(pi(&triple), merge_pi(&facts.master_pi, &pi(&third)));
}

#[test]
fn combine_refuses_frames_that_share_a_claim() {
    let a = tick_frame(3, 0x10);
    let b = tick_frame(2, 0x10); // the same signer and messages 0 and 1
    assert_eq!(
        ClaimFrame::combine(&a, &b, vec![]),
        Err(FrameError::DuplicateClaim)
    );
}

#[test]
fn a_tick_frame_needs_claims_and_refuses_a_repeat() {
    assert_eq!(
        ClaimFrame::tick(DOMAIN, &[1; 32], vec![], vec![]),
        Err(FrameError::EmptySegment)
    );
    let mut twice = claims(2, 1);
    twice.push(twice[0].clone());
    assert_eq!(
        ClaimFrame::tick(DOMAIN, &[1; 32], twice, vec![]),
        Err(FrameError::DuplicateClaim)
    );
}

fn merged_pair() -> (ClaimFrame, ClaimFrame, ClaimFrame, Hash32) {
    let (left, right) = (tick_frame(3, 0x10), tick_frame(2, 0x20));
    let good = ClaimFrame::combine(&left, &right, vec![0xCC; 8]).expect("combine");
    let good_pi = good
        .check_structure(DOMAIN, &limits())
        .expect("valid")
        .master_pi;
    (left, right, good, good_pi)
}

/// Section 11, negative tests on the frame alone: claims, counts and roots.
/// Each mutation of a valid two-segment frame must fail a structure rule.
#[test]
fn every_mutation_of_claims_counts_and_roots_is_caught() {
    let (_, _, good, _) = merged_pair();

    // Duplicate claim (rule 1). The count is raised with it, so only the
    // duplicate rule can catch it.
    let mut m = good.clone();
    m.claims.push(m.claims[0].clone());
    m.segments[1].count += 1;
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::DuplicateClaim)
    );

    // Reordered claims inside a segment (rule 3).
    let mut m = good.clone();
    m.claims.swap(0, 1);
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::ClaimsRootMismatch(0))
    );

    // A claim moved across the segment border keeps the total but breaks both roots.
    let mut m = good.clone();
    m.claims.swap(2, 3);
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::ClaimsRootMismatch(0))
    );

    // Changed count (rule 2), up and down.
    for delta in [1i64, -1] {
        let mut m = good.clone();
        m.segments[0].count = u32::try_from(i64::from(m.segments[0].count) + delta).expect("count");
        assert_eq!(
            m.check_structure(DOMAIN, &limits()),
            Err(FrameError::CountMismatch)
        );
    }
    // Counts that still sum up but move the border (rule 3).
    let mut m = good.clone();
    m.segments[0].count -= 1;
    m.segments[1].count += 1;
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::ClaimsRootMismatch(0))
    );
    // A count of zero.
    let mut m = good.clone();
    m.segments[0].count = 0;
    m.segments[1].count = 5;
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::EmptySegment)
    );

    // Changed claims_root (rule 3).
    let mut m = good;
    m.segments[1].claims_root[0] ^= 1;
    assert_eq!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::ClaimsRootMismatch(1))
    );
}

/// Section 11, negative tests on the frame alone: aggregator, shape, segment
/// order, domain and limits. A mutation must fail a structure rule or move
/// the public input the proof is checked against.
#[test]
fn every_mutation_of_aggregator_shape_order_domain_and_limits_is_caught() {
    let (left, right, good, good_pi) = merged_pair();

    // Changed aggregator: the structure holds, the public input moves, so the
    // proof made for the honest frame no longer matches (rule 5).
    let mut m = good.clone();
    m.segments[0].aggregator = Address::from([0x99; 32]);
    let moved = m
        .check_structure(DOMAIN, &limits())
        .expect("structure holds");
    assert_ne!(moved.master_pi, good_pi);

    // Changed shape (rule 4).
    for shape in [
        vec![SHAPE_TICK, SHAPE_TICK],
        vec![SHAPE_TICK, SHAPE_MERGE, SHAPE_TICK],
        vec![],
    ] {
        let mut m = good.clone();
        m.shape = shape;
        assert_eq!(
            m.check_structure(DOMAIN, &limits()),
            Err(FrameError::BadShape)
        );
    }

    // Swapped segments: with the claims left in place the roots break (rule 3);
    // with the claims swapped too the frame is well formed but has another
    // public input (rule 5).
    let mut m = good.clone();
    m.segments.swap(0, 1);
    assert!(matches!(
        m.check_structure(DOMAIN, &limits()),
        Err(FrameError::ClaimsRootMismatch(_))
    ));
    let swapped = ClaimFrame::combine(&right, &left, vec![0xCC; 8]).expect("combine");
    assert_ne!(
        swapped
            .check_structure(DOMAIN, &limits())
            .expect("valid")
            .master_pi,
        good_pi
    );

    // The claims of another domain: the same frame read under another domain
    // has other digests, so the roots break (rule 3).
    assert_eq!(
        good.check_structure(DOMAIN + 1, &limits()),
        Err(FrameError::ClaimsRootMismatch(0))
    );

    // Limits (rule 9).
    let tight = FrameLimits {
        max_claims: 4,
        max_proof_bytes: 1024,
    };
    assert_eq!(
        good.check_structure(DOMAIN, &tight),
        Err(FrameError::TooManyClaims(5))
    );
    let tight = FrameLimits {
        max_claims: 8192,
        max_proof_bytes: 7,
    };
    assert_eq!(
        good.check_structure(DOMAIN, &tight),
        Err(FrameError::ProofTooLarge(8))
    );
}

#[test]
fn the_frame_hash_binds_the_public_input_attestations_and_the_proof() {
    let frame = tick_frame(2, 0x10);
    let pi = frame
        .check_structure(DOMAIN, &limits())
        .expect("valid")
        .master_pi;
    assert_eq!(
        frame.hash(DOMAIN),
        Ok(frame_hash(&pi, &frame.segments, &frame.proof))
    );
    let mut other = frame.clone();
    other.proof.push(0);
    assert_ne!(other.hash(DOMAIN), frame.hash(DOMAIN));
    let mut tampered = frame.clone();
    tampered.segments[0].attestation.signature[0] ^= 1;
    assert_ne!(tampered.hash(DOMAIN), frame.hash(DOMAIN));
}

#[test]
fn a_frame_round_trips_through_its_encoding() {
    let (a, b) = (tick_frame(3, 0x10), tick_frame(2, 0x20));
    let mut mixed = ClaimFrame::combine(&a, &b, vec![0xCC; 8]).expect("combine");
    mixed.claims.push(prog_claim());
    mixed.claims.push(poly_claim());
    for frame in [a, b, mixed] {
        let bytes = frame.encode();
        assert_eq!(ClaimFrame::decode(&bytes, &limits()), Ok(frame));
    }
}

#[test]
fn a_malformed_frame_encoding_is_refused_without_reading_past_its_limits() {
    let frame = tick_frame(3, 0x10);
    let bytes = frame.encode();
    for cut in 0..bytes.len() {
        assert!(
            ClaimFrame::decode(&bytes[..cut], &limits()).is_err(),
            "cut at {cut}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ClaimFrame::decode(&trailing, &limits()),
        Err(FrameError::TrailingBytes)
    );

    // A count far above the limit is refused before anything is allocated for it.
    let mut huge = Vec::new();
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ClaimFrame::decode(&huge, &limits()),
        Err(FrameError::TooManyClaims(
            usize::try_from(u32::MAX).expect("64-bit")
        ))
    );

    let tight = FrameLimits {
        max_claims: 8192,
        max_proof_bytes: 15,
    };
    assert_eq!(
        ClaimFrame::decode(&bytes, &tight),
        Err(FrameError::ProofTooLarge(16))
    );
    let tight = FrameLimits {
        max_claims: 2,
        max_proof_bytes: 1024,
    };
    assert_eq!(
        ClaimFrame::decode(&bytes, &tight),
        Err(FrameError::TooManyClaims(3))
    );
}

// ---- envelopes --------------------------------------------------------------

fn envelope() -> Envelope {
    Envelope {
        kind: ObjectKind::Signature,
        scheme: SchemeId::ML_DSA_87,
        payload: b"payload-bytes".to_vec(),
        tx_hash: [0x77; 32],
        domain: DOMAIN,
    }
}

#[test]
fn the_envelope_encoding_and_object_id_match_the_independent_vectors() {
    let e = envelope();
    let hex = e.encode().iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    assert_eq!(
        hex,
        "0001037777777777777777777777777777777777777777777777777777777777777777000000070000000d7061796c6f61642d6279746573"
    );
    assert_eq!(
        e.object_id(),
        hex32("acb30b3e71c3c253efd3ee646631a4c7a0e4e186f79fe7950020290a4e7e1b62")
    );
}

#[test]
fn an_envelope_round_trips_and_malformed_bytes_are_refused() {
    let e = envelope();
    let bytes = e.encode();
    assert_eq!(Envelope::decode(&bytes, 1024), Ok(e.clone()));
    for cut in 0..bytes.len() {
        assert!(
            Envelope::decode(&bytes[..cut], 1024).is_err(),
            "cut at {cut}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Envelope::decode(&trailing, 1024),
        Err(EnvelopeError::TrailingBytes)
    );
    assert_eq!(
        Envelope::decode(&bytes, 12),
        Err(EnvelopeError::PayloadTooLarge(13))
    );
    let mut unknown = bytes;
    unknown[0] = 3;
    assert_eq!(
        Envelope::decode(&unknown, 1024),
        Err(EnvelopeError::UnknownKind(3))
    );
    // A proof or opening names no scheme: a non-zero scheme there is a second
    // encoding of the same object and is refused.
    let mut stark = e;
    stark.kind = ObjectKind::StarkProof;
    assert_eq!(
        Envelope::decode(&stark.encode(), 1024),
        Err(EnvelopeError::SchemeOnNonSignature)
    );
    stark.scheme = SchemeId(0);
    assert_eq!(Envelope::decode(&stark.encode(), 1024), Ok(stark));
}

// ---- parameters -------------------------------------------------------------

#[test]
fn the_default_parameters_are_the_directive_values_and_the_mode_is_off() {
    let p = AggParams::default();
    assert_eq!(p.mode, AggMode::Off);
    assert_eq!(
        (p.tick_ms, p.tick_max_objects, p.sender_tick_limit),
        (1000, 256, 8)
    );
    assert_eq!((p.max_claims_per_block, p.max_proof_bytes), (8192, 262_144));
    assert_eq!(
        (
            p.max_stark_object_bytes,
            p.max_pcs_object_bytes,
            p.pool_max_bytes
        ),
        (262_144, 131_072, 268_435_456)
    );
    assert_eq!(
        (
            p.claim_fee_per_byte,
            p.agg_share_bps,
            p.proof_retention_blocks
        ),
        (64, 5000, 100_000)
    );
    assert_eq!(
        limits(),
        FrameLimits {
            max_claims: 8192,
            max_proof_bytes: 262_144
        }
    );
}

// ---- properties -------------------------------------------------------------

mod properties {
    use super::*;
    use proptest::prelude::*;

    /// A random binary tree over `n` leaves as a postfix shape, with the
    /// public input computed by plain recursion next to it.
    fn tree(
        segs: &[Segment],
        lo: usize,
        hi: usize,
        cuts: &[usize],
        depth: usize,
        shape: &mut Vec<u8>,
    ) -> Hash32 {
        if hi - lo == 1 {
            shape.push(SHAPE_TICK);
            return tick_pi(DOMAIN, &segs[lo]);
        }
        let pick = cuts.get(depth).copied().unwrap_or(0);
        let mid = lo + 1 + pick % (hi - lo - 1);
        let left = tree(segs, lo, mid, cuts, depth + 1, shape);
        let right = tree(segs, mid, hi, cuts, depth + 2, shape);
        shape.push(SHAPE_MERGE);
        merge_pi(&left, &right)
    }

    proptest! {
        #[test]
        fn fold_shape_equals_the_recursive_definition(n in 1usize..24, cuts in prop::collection::vec(0usize..64, 64)) {
            let segs: Vec<Segment> = (0..n).map(|i| seg([u8::try_from(i).expect("small"); 32], 1, 0x55)).collect();
            let mut shape = Vec::new();
            let expected = tree(&segs, 0, n, &cuts, 0, &mut shape);
            prop_assert_eq!(shape.len(), 2 * n - 1);
            prop_assert_eq!(fold_shape(DOMAIN, &segs, &shape), Ok(expected));
        }

        #[test]
        fn fold_shape_never_panics_and_accepts_only_full_trees(n in 0usize..6, shape in prop::collection::vec(0u8..3, 0..16)) {
            let segs: Vec<Segment> = (0..n).map(|i| seg([u8::try_from(i).expect("small"); 32], 1, 0x55)).collect();
            if fold_shape(DOMAIN, &segs, &shape).is_ok() {
                prop_assert!(n >= 1);
                prop_assert_eq!(shape.len(), 2 * n - 1);
                let merges: usize = shape.iter().map(|op| usize::from(*op)).sum();
                prop_assert_eq!(merges + 1, n);
            }
        }

        #[test]
        fn changing_any_leaf_changes_the_root(leaves in prop::collection::vec(any::<[u8; 32]>(), 1..40), at in any::<prop::sample::Index>(), bit in 0usize..256) {
            let root = claims_root(&leaves).expect("non-empty");
            let mut other = leaves;
            let i = at.index(other.len());
            other[i][bit / 8] ^= 1 << (bit % 8);
            prop_assert_ne!(claims_root(&other).expect("non-empty"), root);
        }

        #[test]
        fn appending_a_leaf_changes_the_root(leaves in prop::collection::vec(any::<[u8; 32]>(), 1..40), extra in any::<[u8; 32]>()) {
            let root = claims_root(&leaves).expect("non-empty");
            let mut longer = leaves;
            longer.push(extra);
            prop_assert_ne!(claims_root(&longer).expect("non-empty"), root);
        }

        #[test]
        fn combine_keeps_every_claim_and_stays_valid(sizes in prop::collection::vec(1u8..6, 2..7)) {
            let frames: Vec<ClaimFrame> = sizes.iter().enumerate()
                .map(|(i, n)| tick_frame(*n, u8::try_from(i + 1).expect("small")))
                .collect();
            let total: usize = frames.iter().map(|f| f.claims.len()).sum();
            let mut acc = frames[0].clone();
            for next in &frames[1..] {
                acc = ClaimFrame::combine(&acc, next, vec![]).expect("disjoint");
            }
            let facts = acc.check_structure(DOMAIN, &limits()).expect("valid");
            prop_assert_eq!(acc.claims.len(), total);
            prop_assert_eq!(facts.claim_digests.len(), total);
            prop_assert_eq!(acc.segments.len(), frames.len());
            prop_assert_eq!(ClaimFrame::decode(&acc.encode(), &limits()), Ok(acc));
        }

        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = ClaimFrame::decode(&bytes, &limits());
            let _ = Envelope::decode(&bytes, 4096);
            let _ = Claim::decode(&bytes);
        }

        #[test]
        fn a_decoded_frame_encodes_to_the_same_bytes(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            if let Ok(frame) = ClaimFrame::decode(&bytes, &limits()) {
                prop_assert_eq!(&frame.encode(), &bytes);
            }
            if let Ok(env) = Envelope::decode(&bytes, 4096) {
                prop_assert_eq!(&env.encode(), &bytes);
            }
        }
    }
}
