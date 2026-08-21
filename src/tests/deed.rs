//! DeEd (src/deed) integration test - exercises the canonical manifest
//! Primitives and permissionless role vocabulary in the shared integration suite.
use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::deed::{roles, ArtifactKind, Manifest, Visibility};
use crate::storage::content_id::ContentId;

#[test]
fn deed_manifest_validate_id_binding_and_roles() {
    let m = Manifest {
        contributor: test_addr_from_byte(7u8),
        content_id: ContentId([8u8; 32]),
        artifact_kind: ArtifactKind::Research,
        visibility: Visibility::EducatorOnly,
        metadata_hash: [9u8; 32],
        created_at: 42,
    };
    assert!(m.validate().is_ok());
    let id = m.id();
    assert_eq!(id, m.id());
    let mut m2 = m.clone();
    m2.artifact_kind = ArtifactKind::Dataset;
    assert_ne!(m2.id(), id);
    let mut m3 = m.clone();
    m3.contributor = Address::zero();
    assert!(m3.validate().is_err());
    assert_ne!(roles::INDUSTRY_SPONSOR, roles::RESEARCH_CONTRIBUTOR);
    assert_eq!(roles::INDUSTRY_SPONSOR.value(), 10);
    assert_eq!(roles::RESEARCH_CONTRIBUTOR.value(), 11);
}
