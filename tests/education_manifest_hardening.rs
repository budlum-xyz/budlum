//! Regression tests for EducationArtifact zero-commitment / kind-collision
//! guards and ProjectManifest duplicate/unbounded fixture refusals.

use budlum_core::core::address::Address;
use budlum_core::education_domain::{
    EducationArtifact, EducationArtifactKind, EducationVisibility,
};
use budlum_core::project_manifest::{ProjectManifest, ProofFixture, ProofFixtureStatus};
use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
use budlum_core::storage::bud3::content_ref::ContentRef;

#[test]
fn education_artifact_refuses_zero_commitment_and_binds_content_kind_in_id() {
    let cid_pub = ContentId {
        kind: ContentIdKind::Public,
        digest: [0x11; 32],
        len: 128,
    };
    let cid_sealed = ContentId {
        kind: ContentIdKind::Sealed,
        digest: [0x11; 32],
        len: 128,
    };
    let cref_pub = ContentRef {
        content_id: cid_pub,
        object_commitment: [0x22; 32],
        nft_id: None,
    };
    let cref_sealed = ContentRef {
        content_id: cid_sealed,
        object_commitment: [0x22; 32],
        nft_id: None,
    };

    // 1. All-zero object_commitment must fail validate().
    let zero_commit = EducationArtifact {
        contributor: Address::from([0x01; 32]),
        content_ref: cref_pub.clone(),
        object_commitment: [0u8; 32],
        artifact_kind: EducationArtifactKind::Research,
        visibility: EducationVisibility::Public,
        metadata_hash: [0x33; 32],
        created_at: 100,
    };
    assert!(
        zero_commit.validate().is_err(),
        "all-zero object_commitment in EducationArtifact must be refused"
    );

    // 2. Public vs Sealed ContentIdKind with identical digest/len must derive distinct artifact_ids!
    let art_pub = EducationArtifact {
        object_commitment: [0x22; 32],
        ..zero_commit
    };
    let art_sealed = EducationArtifact {
        content_ref: cref_sealed,
        ..art_pub.clone()
    };
    assert_ne!(
        art_pub.artifact_id(),
        art_sealed.artifact_id(),
        "Public and Sealed ContentIdKind must not collide to the same EducationArtifact ID"
    );
}

#[test]
fn project_manifest_refuses_duplicate_proof_fixture_names() {
    let mut manifest = ProjectManifest::local_standard("demo-app", [0xAB; 32]);
    manifest.proof_fixtures.push(ProofFixture {
        name: String::from("zkvm-smoke"), // duplicate of the default fixture!
        proof_hash: [0x99; 32],
        input_commitment: [0x88; 32],
        result_root: [0x77; 32],
        status: ProofFixtureStatus::Pending,
    });
    assert!(
        manifest.validate().is_err(),
        "duplicate proof_fixture names in ProjectManifest must be refused"
    );
}
