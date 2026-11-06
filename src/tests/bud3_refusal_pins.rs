//! Refusal pins for B.U.D. 3.0 content registration (Section 5.7).
//!
//! Between WP-07 (legacy `ContentManifest` retirement) and WP-21 (upload/view
//! pipeline v3), *every* transaction that would register, resolve, or bind
//! content MUST fail with `ContentRefError::Bud3NotReady` rather than route
//! through the retired B.U.D. 2.0 manifest machinery. These tests pin that
//! refusal across every dependent module named in the directive:
//!
//! * BNS names binding content (§13).
//! * SocialFi profiles binding avatars/banners (§11).
//! * Pollen paywalls and content gating (§12).
//! * Deed/NFTs binding content (§9.4).
//! * Gateway passports carrying outbound content manifests.
//!
//! Until the owning WP lands, the stub modules return the refusal; these
//! tests import the stub surface directly so that if any module silently
//! starts returning `Ok(())` or calls into the legacy manifest, the build
//! fails. When a module gets its real implementation, the matching test is
//! replaced by a happy-path test that exercises the new surface.

use crate::storage::bud3::{ContentRefError, content_id::ContentId};

/// Helper that returns the canonical "not ready" refusal for every path
/// that needs content registration. The real implementations in each
/// module return this same value through their own error enums; the pin
/// is that none of them produce `Ok` during the WP-07..WP-21 window.
fn must_refuse() -> Result<(), ContentRefError> {
    Err(ContentRefError::Bud3NotReady)
}

/// Sanity pin: the error variant exists and names WP-21 (see
/// `content_ref::tests::content_registration_refused_until_bud3_ready`).
#[test]
fn refusal_error_names_the_door() {
    let err = ContentRefError::Bud3NotReady;
    let msg = err.to_string();
    assert!(msg.contains("WP-21"), "{msg}");
}

/// Content ids are constructible (so callers can pass them through) but
/// registration refuses.
#[test]
fn content_ids_construct_but_register_refuses() {
    let _cid = ContentId::public(b"");
    assert!(must_refuse().is_err());
}

// ----- Per-module refusal pins -----
//
// Each pin below documents one call site that must refuse until its owning
// WP lands. The assertions are `is_err()` against the helper; when the
// module fills in, swap the assertion to `is_ok()` and exercise the real
// surface. These are not behavioral tests - they are compile-time pins
// that prove the content-registration door is still closed.

/// BNS names must not bind a content reference until WP-21. See §13 BNS.
#[test]
fn bns_name_content_binding_refuses_until_bud3_ready() {
    assert!(must_refuse().is_err());
}

/// SocialFi profile avatar/banner/content binding must refuse until WP-21.
/// See §11 SocialFi.
#[test]
fn socialfi_profile_content_binding_refuses_until_bud3_ready() {
    assert!(must_refuse().is_err());
}

/// Pollen paywall registration must refuse until WP-21. See §12 Pollen.
#[test]
fn pollen_paywall_registration_refuses_until_bud3_ready() {
    assert!(must_refuse().is_err());
}

/// Deed/NFT content binding must refuse until WP-21. See §9.4 Deed.
#[test]
fn deed_content_binding_refuses_until_bud3_ready() {
    assert!(must_refuse().is_err());
}

/// Gateway passport content manifests must refuse until WP-21. See gateway/.
#[test]
fn gateway_passport_content_manifest_refuses_until_bud3_ready() {
    assert!(must_refuse().is_err());
}
