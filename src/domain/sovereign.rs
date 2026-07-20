//! Sovereign Domain Kit primitives (Phase 12 / ARENA4).
//!
//! The kit helps CBDC, public-sector, enterprise PoA and consortium domains
//! describe lifecycle and compliance evidence without leaking private KYC data
//! or merging PoA rules into the permissionless core registry.

use crate::core::address::Address;
use crate::domain::{ConsensusKind, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereignDomainClass {
    Cbdc,
    PublicSector,
    EnterprisePoa,
    Consortium,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainLifecycleState {
    Draft,
    Active,
    Frozen,
    Retired,
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
        hasher.update(format!("{:?}", self.lifecycle).as_bytes());
        hasher.finalize().into()
    }

    pub fn verify_id(&self) -> bool {
        self.template_id == self.calculate_id()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.domain_id == 0 {
            return Err("SovereignDomainTemplate domain_id must be non-zero".into());
        }
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
        if self.template_id != template.template_id {
            return Err("AuditExportBundle template mismatch".into());
        }
        if self.from_height > self.to_height {
            return Err("AuditExportBundle height range invalid".into());
        }
        if self.compliance_root != template.compliance.root() {
            return Err("AuditExportBundle compliance root mismatch".into());
        }
        Ok(())
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
}
