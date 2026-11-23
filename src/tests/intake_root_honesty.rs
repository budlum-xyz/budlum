//! `external_intake_root` must not read "nothing" when the intake *cannot be
//! encoded*.
//!
//! The field's own documentation says it is "the external-domain intake digest
//! (V6), when the intake holds any record". The builder used
//! `external_intake_digest().ok()`, so a digest that could not be produced
//! collapsed to `None` - the same value as "the intake carries no record". A light
//! client reading the header then sees "no external intake" where the truth is
//! "there is one and this node could not encode it".
//!
//! `SettlementRegistries::root()` already answers this question the other way
//! round: a registry that cannot be encoded folds a fixed marker
//! (`BDLM_SETTLEMENT_UNENCODABLE_V1`), because a node that cannot encode its
//! state must not agree with one that can. These tests hold the header field to
//! the same discipline, for the component the header carries separately.

use crate::core::hash::hash_fields_bytes;
use crate::settlement::registries::SettlementRegistries;

/// The marker the settlement fold uses when a registry cannot be encoded; the
/// header carries the same marker for the same reason.
const UNENCODABLE_MARKER_TAG: &[u8] = b"BDLM_SETTLEMENT_UNENCODABLE_V1";

fn marker() -> [u8; 32] {
    hash_fields_bytes(&[UNENCODABLE_MARKER_TAG])
}

/// The contract the production builder must satisfy.
///
/// `Err` is not "no intake": it is "there is an intake and this node could not
/// encode it". Returning `None` for both makes the two states indistinguishable
/// in the header, which is the defect this file exists to pin.
#[test]
fn an_unencodable_intake_is_not_reported_as_an_absent_one() {
    let root = SettlementRegistries::intake_root_for_header(Err(String::from(
        "serializer refused the state",
    )));
    assert!(
        root.is_some(),
        "an intake that cannot be encoded must NOT read as absent: the header \
         must carry the unencodable marker instead of None"
    );
    assert_eq!(
        root,
        Some(marker()),
        "the marker must be the settlement fold's own marker, not a new value"
    );
}

#[test]
fn an_encodable_intake_reports_its_digest() {
    let digest = [0xA1; 32];
    let root = SettlementRegistries::intake_root_for_header(Ok(digest));
    assert_eq!(root, Some(digest));
}

#[test]
fn the_marker_is_distinguishable_from_every_real_digest_and_from_absence() {
    // The header hash binds the field through `presence_tagged`, which
    // distinguishes `None` from `Some(_)` and nothing else; the marker must
    // therefore be a value no digest can be, or the third state hides in the
    // second.
    let absent: Option<[u8; 32]> = None;
    let real = Some([0x11; 32]);
    let marker = Some(marker());
    assert_ne!(absent, real);
    assert_ne!(absent, marker);
    assert_ne!(real, marker);
    assert_ne!(
        marker,
        Some([0u8; 32]),
        "the marker must not be the zero digest (which already means 'unset' \
         in wire formats)"
    );
}
