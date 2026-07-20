//! Sovereign Domain Kit primitives (Phase 12 / ARENA4).
//!
//! The kit helps CBDC, public-sector, enterprise PoA and consortium domains
//! describe lifecycle and compliance evidence without leaking private KYC data
//! or merging PoA rules into the permissionless core registry.

use crate::core::address::Address;
use crate::domain::{ConsensusKind, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_AUDIT_EXPORT_SPAN_BLOCKS: u64 = 1_000_000;
pub const MAX_SOVEREIGN_DOMAIN_TEMPLATES: usize = 1_024;

fn nonzero_hash(value: &Hash32) -> bool {
    *value != [0u8; 32]
}

fn validate_label(field: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && !value.contains('/')
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control());
    if valid {
        Ok(())
    } else {
        Err(format!("{field} invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereignDomainClass {
    Cbdc,
    PublicSector,
    EnterprisePoa,
    Consortium,
    Custom(String),
}

impl SovereignDomainClass {
    pub fn validate(&self) -> Result<(), String> {
        if let SovereignDomainClass::Custom(label) = self {
            validate_label("SovereignDomainClass::Custom", label)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainLifecycleState {
    Draft,
    Active,
    Frozen,
    Retired,
}

impl DomainLifecycleState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        match (self, next) {
            (Self::Draft, Self::Active | Self::Frozen | Self::Retired) => true,
            (Self::Active, Self::Frozen | Self::Retired) => true,
            (Self::Frozen, Self::Active | Self::Retired) => true,
            (Self::Retired, _) => false,
            (current, next) if current == next => true,
            _ => false,
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Draft => 1,
            Self::Active => 2,
            Self::Frozen => 3,
            Self::Retired => 4,
        }
    }
}

impl From<DomainStatus> for DomainLifecycleState {
    fn from(status: DomainStatus) -> Self {
        match status {
            DomainStatus::Active => Self::Active,
            DomainStatus::Frozen => Self::Frozen,
            DomainStatus::Retired => Self::Retired,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    pub policy_hash: Hash32,
    pub authority_set_hash: Hash32,
    pub jurisdiction_hash: Hash32,
    pub audit_commitment: Hash32,
}

impl ComplianceEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if !nonzero_hash(&self.policy_hash) {
            return Err("ComplianceEvidence policy_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.authority_set_hash) {
            return Err("ComplianceEvidence authority_set_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.jurisdiction_hash) {
            return Err("ComplianceEvidence jurisdiction_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.audit_commitment) {
            return Err("ComplianceEvidence audit_commitment cannot be zero".into());
        }
        Ok(())
    }

    /// Domain-separated root over public commitments only. No KYC/person data
    /// is carried here; private compliance data remains off-chain.
    pub fn root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_COMPLIANCE_EVIDENCE_V1");
        hasher.update(self.policy_hash);
        hasher.update(self.authority_set_hash);
        hasher.update(self.jurisdiction_hash);
        hasher.update(self.audit_commitment);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignDomainTemplate {
    pub template_id: Hash32,
    pub domain_id: DomainId,
    pub class: SovereignDomainClass,
    pub consensus_kind: ConsensusKind,
    pub operator: Address,
    pub requires_kyc: bool,
    pub compliance: ComplianceEvidence,
    pub lifecycle: DomainLifecycleState,
}

impl SovereignDomainTemplate {
    pub fn new(
        domain_id: DomainId,
        class: SovereignDomainClass,
        consensus_kind: ConsensusKind,
        operator: Address,
        requires_kyc: bool,
        compliance: ComplianceEvidence,
        lifecycle: DomainLifecycleState,
    ) -> Self {
        let mut template = Self {
            template_id: [0u8; 32],
            domain_id,
            class,
            consensus_kind,
            operator,
            requires_kyc,
            compliance,
            lifecycle,
        };
        template.template_id = template.calculate_id();
        template
    }

    pub fn calculate_id(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_DOMAIN_TEMPLATE_V1");
        hasher.update(self.domain_id.to_le_bytes());
        hasher.update(format!("{:?}", self.class).as_bytes());
        hasher.update(self.consensus_kind.as_bytes());
        hasher.update(self.operator.as_bytes());
        hasher.update([u8::from(self.requires_kyc)]);
        hasher.update(self.compliance.root());
        hasher.update([self.lifecycle.tag()]);
        hasher.finalize().into()
    }

    pub fn verify_id(&self) -> bool {
        self.template_id == self.calculate_id()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.domain_id == 0 {
            return Err("SovereignDomainTemplate domain_id must be non-zero".into());
        }
        self.class.validate()?;
        self.compliance.validate()?;
        if self.operator == Address::zero() {
            return Err("SovereignDomainTemplate operator cannot be zero".into());
        }
        if !self.verify_id() {
            return Err("SovereignDomainTemplate template_id mismatch".into());
        }
        if matches!(self.consensus_kind, ConsensusKind::PoA) && !self.requires_kyc {
            return Err("PoA sovereign domains must explicitly require KYC".into());
        }
        if !matches!(self.consensus_kind, ConsensusKind::PoA) && self.requires_kyc {
            return Err("KYC requirement must not leak into permissionless non-PoA domains".into());
        }
        if matches!(self.class, SovereignDomainClass::EnterprisePoa)
            && !matches!(self.consensus_kind, ConsensusKind::PoA)
        {
            return Err("EnterprisePoa sovereign class must use PoA consensus".into());
        }
        Ok(())
    }

    pub fn transition_to(&mut self, next: DomainLifecycleState) -> Result<(), String> {
        if !self.lifecycle.can_transition_to(&next) {
            return Err("SovereignDomainTemplate lifecycle transition invalid".into());
        }
        self.lifecycle = next;
        self.template_id = self.calculate_id();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportBundle {
    pub template_id: Hash32,
    pub from_height: u64,
    pub to_height: u64,
    pub global_header_root: Hash32,
    pub commitment_root: Hash32,
    pub compliance_root: Hash32,
}

impl AuditExportBundle {
    pub fn validate_against_template(
        &self,
        template: &SovereignDomainTemplate,
    ) -> Result<(), String> {
        template.validate()?;
        if self.template_id != template.template_id {
            return Err("AuditExportBundle template mismatch".into());
        }
        if self.from_height > self.to_height {
            return Err("AuditExportBundle height range invalid".into());
        }
        if self.to_height.saturating_sub(self.from_height) > MAX_AUDIT_EXPORT_SPAN_BLOCKS {
            return Err("AuditExportBundle height range too large".into());
        }
        if !nonzero_hash(&self.global_header_root)
            || !nonzero_hash(&self.commitment_root)
            || !nonzero_hash(&self.compliance_root)
        {
            return Err("AuditExportBundle roots cannot be zero".into());
        }
        if self.compliance_root != template.compliance.root() {
            return Err("AuditExportBundle compliance root mismatch".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SovereignDomainRegistry {
    pub templates: BTreeMap<DomainId, SovereignDomainTemplate>,
}

impl SovereignDomainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_template(&mut self, template: SovereignDomainTemplate) -> Result<(), String> {
        template.validate()?;
        if self.templates.len() >= MAX_SOVEREIGN_DOMAIN_TEMPLATES
            && !self.templates.contains_key(&template.domain_id)
        {
            return Err("SovereignDomainRegistry template limit exceeded".into());
        }
        if self.templates.contains_key(&template.domain_id) {
            return Err("SovereignDomainRegistry domain already registered".into());
        }
        self.templates.insert(template.domain_id, template);
        Ok(())
    }

    pub fn transition_lifecycle(
        &mut self,
        domain_id: DomainId,
        next: DomainLifecycleState,
    ) -> Result<(), String> {
        let template = self
            .templates
            .get_mut(&domain_id)
            .ok_or_else(|| "SovereignDomainRegistry domain not found".to_string())?;
        template.transition_to(next)
    }

    pub fn root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_DOMAIN_REGISTRY_V1");
        for (domain_id, template) in &self.templates {
            hasher.update(domain_id.to_le_bytes());
            hasher.update(template.template_id);
            hasher.update(template.compliance.root());
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn evidence() -> ComplianceEvidence {
        ComplianceEvidence {
            policy_hash: [1u8; 32],
            authority_set_hash: [2u8; 32],
            jurisdiction_hash: [3u8; 32],
            audit_commitment: [4u8; 32],
        }
    }

    #[test]
    fn poa_template_requires_kyc_and_keeps_only_hashes() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::Cbdc,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().is_ok());
        let json = serde_json::to_string(&template).unwrap();
        assert!(!json.contains("passport"));
        assert!(!json.contains("national_id"));
        assert!(!json.contains("kyc_document"));
    }

    #[test]
    fn non_poa_template_rejects_kyc_leakage() {
        let template = SovereignDomainTemplate::new(
            8,
            SovereignDomainClass::Consortium,
            ConsensusKind::PoS,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("non-PoA"));
    }

    #[test]
    fn audit_bundle_binds_template_and_compliance_root() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        let bundle = AuditExportBundle {
            template_id: template.template_id,
            from_height: 10,
            to_height: 20,
            global_header_root: [5u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(bundle.validate_against_template(&template).is_ok());
    }

    #[test]
    fn compliance_evidence_rejects_zero_hashes() {
        let mut evidence = evidence();
        evidence.policy_hash = [0u8; 32];
        assert!(evidence.validate().unwrap_err().contains("policy_hash"));
    }

    #[test]
    fn custom_class_rejects_path_like_label() {
        let template = SovereignDomainTemplate::new(
            9,
            SovereignDomainClass::Custom("../bad".into()),
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("Custom"));
    }

    #[test]
    fn enterprise_poa_class_cannot_use_permissionless_consensus() {
        let template = SovereignDomainTemplate::new(
            9,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoS,
            addr(9),
            false,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("EnterprisePoa"));
    }

    #[test]
    fn lifecycle_transition_rejects_retired_reactivation() {
        let mut template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        template.transition_to(DomainLifecycleState::Retired).unwrap();
        assert!(template
            .transition_to(DomainLifecycleState::Active)
            .unwrap_err()
            .contains("transition"));
    }

    #[test]
    fn registry_root_changes_when_lifecycle_transitions() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        let mut registry = SovereignDomainRegistry::new();
        registry.register_template(template).unwrap();
        let before = registry.root();
        registry
            .transition_lifecycle(7, DomainLifecycleState::Active)
            .unwrap();
        assert_ne!(before, registry.root());
    }

    #[test]
    fn audit_bundle_rejects_zero_roots_and_huge_ranges() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        let zero_root_bundle = AuditExportBundle {
            template_id: template.template_id,
            from_height: 10,
            to_height: 20,
            global_header_root: [0u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(zero_root_bundle
            .validate_against_template(&template)
            .unwrap_err()
            .contains("roots"));

        let huge = AuditExportBundle {
            template_id: template.template_id,
            from_height: 0,
            to_height: MAX_AUDIT_EXPORT_SPAN_BLOCKS + 1,
            global_header_root: [5u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(huge
            .validate_against_template(&template)
            .unwrap_err()
            .contains("too large"));
    }

}
