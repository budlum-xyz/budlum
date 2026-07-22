//! Developer OS / BudL SDK primitives (Task 12 / ARENA4).
//!
//! This module defines deterministic project manifests and fixture bundles for
//! local Budlum development. It does not start a network, call external APIs, or
//! depend on budlumdevnet; it is a pure data/validation layer that future CLI and
//! SDK tools can consume.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type DeveloperProjectId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DevnetTopology {
    SingleNode,
    FourNodeMesh,
    MobileSelfReplica,
}

impl DevnetTopology {
    fn tag(self) -> u8 {
        match self {
            DevnetTopology::SingleNode => 1,
            DevnetTopology::FourNodeMesh => 2,
            DevnetTopology::MobileSelfReplica => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdkFeature {
    WalletSigningV4,
    PollenGrantFlow,
    ProofFixtureRunner,
    RelayerPolicyFixture,
    MobileSelfProfile,
}

impl SdkFeature {
    fn tag(&self) -> u8 {
        match self {
            SdkFeature::WalletSigningV4 => 1,
            SdkFeature::PollenGrantFlow => 2,
            SdkFeature::ProofFixtureRunner => 3,
            SdkFeature::RelayerPolicyFixture => 4,
            SdkFeature::MobileSelfProfile => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudlPackageFixture {
    pub package_name: String,
    pub source_hash: [u8; 32],
    pub compiler_profile: String,
    pub entrypoint: String,
}

impl BudlPackageFixture {
    pub fn validate(&self) -> Result<(), DeveloperOsError> {
        validate_label("package_name", &self.package_name)?;
        validate_label("compiler_profile", &self.compiler_profile)?;
        validate_label("entrypoint", &self.entrypoint)?;
        if self.source_hash == [0u8; 32] {
            return Err(DeveloperOsError::ZeroBudlSourceHash);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        update_str(hasher, &self.package_name);
        hasher.update(self.source_hash);
        update_str(hasher, &self.compiler_profile);
        update_str(hasher, &self.entrypoint);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofFixtureStatus {
    Pending,
    Verified,
    Rejected,
}

impl ProofFixtureStatus {
    fn tag(self) -> u8 {
        match self {
            ProofFixtureStatus::Pending => 1,
            ProofFixtureStatus::Verified => 2,
            ProofFixtureStatus::Rejected => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFixture {
    pub name: String,
    pub proof_hash: [u8; 32],
    pub input_commitment: [u8; 32],
    pub result_root: [u8; 32],
    pub status: ProofFixtureStatus,
}

impl ProofFixture {
    pub fn validate(&self) -> Result<(), DeveloperOsError> {
        validate_label("proof fixture name", &self.name)?;
        if self.input_commitment == [0u8; 32] {
            return Err(DeveloperOsError::ZeroProofInputCommitment);
        }
        if self.result_root == [0u8; 32] {
            return Err(DeveloperOsError::ZeroProofResultRoot);
        }
        if self.status == ProofFixtureStatus::Verified && self.proof_hash == [0u8; 32] {
            return Err(DeveloperOsError::VerifiedProofWithoutProofHash);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        update_str(hasher, &self.name);
        hasher.update(self.proof_hash);
        hasher.update(self.input_commitment);
        hasher.update(self.result_root);
        hasher.update([self.status.tag()]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollenFixture {
    pub asset_id: [u8; 32],
    pub grant_id: [u8; 32],
    pub ai_read_requires_grant: bool,
}

impl PollenFixture {
    pub fn validate(&self) -> Result<(), DeveloperOsError> {
        if self.asset_id == [0u8; 32] {
            return Err(DeveloperOsError::ZeroPollenAssetId);
        }
        if self.grant_id == [0u8; 32] {
            return Err(DeveloperOsError::ZeroPollenGrantId);
        }
        if !self.ai_read_requires_grant {
            return Err(DeveloperOsError::AiReadGrantBypassFixture);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(self.asset_id);
        hasher.update(self.grant_id);
        hasher.update([u8::from(self.ai_read_requires_grant)]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerPolicyFixture {
    pub intent_kind: String,
    pub policy_hash: [u8; 32],
}

impl RelayerPolicyFixture {
    pub fn validate(&self) -> Result<(), DeveloperOsError> {
        validate_label("intent_kind", &self.intent_kind)?;
        if self.policy_hash == [0u8; 32] {
            return Err(DeveloperOsError::ZeroRelayerPolicyHash);
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        update_str(hasher, &self.intent_kind);
        hasher.update(self.policy_hash);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeveloperOsManifest {
    pub project_name: String,
    pub chain_id: u64,
    pub devnet_topology: DevnetTopology,
    pub budl_package: BudlPackageFixture,
    pub proof_fixtures: Vec<ProofFixture>,
    pub pollen_fixtures: Vec<PollenFixture>,
    pub relayer_policy_fixtures: Vec<RelayerPolicyFixture>,
    pub sdk_features: Vec<SdkFeature>,
    pub external_network_access: bool,
}

impl DeveloperOsManifest {
    pub fn local_standard(project_name: impl Into<String>, budl_source_hash: [u8; 32]) -> Self {
        Self {
            project_name: project_name.into(),
            chain_id: 1337,
            devnet_topology: DevnetTopology::SingleNode,
            budl_package: BudlPackageFixture {
                package_name: "budlum-app".into(),
                source_hash: budl_source_hash,
                compiler_profile: "production".into(),
                entrypoint: "main".into(),
            },
            proof_fixtures: vec![ProofFixture {
                name: "zkvm-smoke".into(),
                proof_hash: [1u8; 32],
                input_commitment: [2u8; 32],
                result_root: [3u8; 32],
                status: ProofFixtureStatus::Pending,
            }],
            pollen_fixtures: vec![PollenFixture {
                asset_id: [4u8; 32],
                grant_id: [5u8; 32],
                ai_read_requires_grant: true,
            }],
            relayer_policy_fixtures: vec![RelayerPolicyFixture {
                intent_kind: "dweb-resolve".into(),
                policy_hash: [6u8; 32],
            }],
            sdk_features: vec![
                SdkFeature::WalletSigningV4,
                SdkFeature::PollenGrantFlow,
                SdkFeature::ProofFixtureRunner,
                SdkFeature::RelayerPolicyFixture,
            ],
            external_network_access: false,
        }
    }

    pub fn validate(&self) -> Result<(), DeveloperOsError> {
        validate_label("project_name", &self.project_name)?;
        if self.chain_id == 0 {
            return Err(DeveloperOsError::ZeroChainId);
        }
        if self.external_network_access {
            return Err(DeveloperOsError::ExternalNetworkAccessNotAllowed);
        }
        self.budl_package.validate()?;
        for fixture in &self.proof_fixtures {
            fixture.validate()?;
        }
        for fixture in &self.pollen_fixtures {
            fixture.validate()?;
        }
        for fixture in &self.relayer_policy_fixtures {
            fixture.validate()?;
        }
        if self.sdk_features.is_empty() {
            return Err(DeveloperOsError::NoSdkFeatures);
        }
        Ok(())
    }

    pub fn project_id(&self) -> DeveloperProjectId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_DEVELOPER_OS_MANIFEST_V1");
        update_str(&mut hasher, &self.project_name);
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update([self.devnet_topology.tag()]);
        self.budl_package.hash_into(&mut hasher);
        for fixture in &self.proof_fixtures {
            hasher.update(b"proof_fixture");
            fixture.hash_into(&mut hasher);
        }
        for fixture in &self.pollen_fixtures {
            hasher.update(b"pollen_fixture");
            fixture.hash_into(&mut hasher);
        }
        for fixture in &self.relayer_policy_fixtures {
            hasher.update(b"relayer_fixture");
            fixture.hash_into(&mut hasher);
        }
        for feature in &self.sdk_features {
            hasher.update(b"sdk_feature");
            hasher.update([feature.tag()]);
        }
        hasher.update([u8::from(self.external_network_access)]);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeveloperOsError {
    InvalidLabel { field: &'static str, value: String },
    ZeroChainId,
    ZeroBudlSourceHash,
    ZeroProofInputCommitment,
    ZeroProofResultRoot,
    VerifiedProofWithoutProofHash,
    ZeroPollenAssetId,
    ZeroPollenGrantId,
    AiReadGrantBypassFixture,
    ZeroRelayerPolicyHash,
    ExternalNetworkAccessNotAllowed,
    NoSdkFeatures,
}

fn update_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn validate_label(field: &'static str, value: &str) -> Result<(), DeveloperOsError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(DeveloperOsError::InvalidLabel {
            field,
            value: value.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> DeveloperOsManifest {
        DeveloperOsManifest::local_standard("demo-app", [9u8; 32])
    }

    #[test]
    fn local_devnet_template_is_deterministic_and_offline() {
        let sample = manifest();
        sample.validate().unwrap();
        assert!(!sample.external_network_access);
        assert_eq!(sample.chain_id, 1337);
        assert_eq!(sample.project_id(), manifest().project_id());
    }

    #[test]
    fn project_id_changes_with_budl_source_hash() {
        let first = DeveloperOsManifest::local_standard("demo-app", [9u8; 32]);
        let second = DeveloperOsManifest::local_standard("demo-app", [10u8; 32]);
        assert_ne!(first.project_id(), second.project_id());
    }

    #[test]
    fn verified_proof_fixture_requires_nonzero_proof_hash() {
        let mut manifest = manifest();
        manifest.proof_fixtures[0].status = ProofFixtureStatus::Verified;
        manifest.proof_fixtures[0].proof_hash = [0u8; 32];
        assert_eq!(
            manifest.validate().unwrap_err(),
            DeveloperOsError::VerifiedProofWithoutProofHash
        );
    }

    #[test]
    fn pollen_fixture_cannot_model_ai_grant_bypass() {
        let mut manifest = manifest();
        manifest.pollen_fixtures[0].ai_read_requires_grant = false;
        assert_eq!(
            manifest.validate().unwrap_err(),
            DeveloperOsError::AiReadGrantBypassFixture
        );
    }

    #[test]
    fn project_name_rejects_path_traversal() {
        let mut manifest = manifest();
        manifest.project_name = "../bad".into();
        assert!(matches!(
            manifest.validate().unwrap_err(),
            DeveloperOsError::InvalidLabel { .. }
        ));
    }
}
