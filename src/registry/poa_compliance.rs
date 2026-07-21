//! Phase 11.18 — MASAK/AML compliance primitives isolated to PoA domains.
//!
//! The permissionless network must never inherit PoA-only compliance hooks. This
//! module therefore requires every state-changing operation to declare its
//! domain kind and fails closed for [`ComplianceDomainKind::Permissionless`].

use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceDomainKind {
    Permissionless,
    PoA,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScreeningStatus {
    Clear,
    Watchlist,
    Sanctioned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceAction {
    ScreeningUpdated,
    AccountFrozen,
    TravelRuleMetadataRecorded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreeningRecord {
    pub address: Address,
    pub status: ScreeningStatus,
    pub oracle_reference_hash: [u8; 32],
    pub updated_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeRecord {
    pub address: Address,
    pub reason_hash: [u8; 32],
    pub frozen_at_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TravelRuleRecord {
    pub tx_hash: [u8; 32],
    pub subject: Address,
    pub metadata_hash: [u8; 32],
    pub recorded_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceAuditEvent {
    pub action: ComplianceAction,
    pub address: Address,
    pub block: u64,
    pub evidence_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoaComplianceError {
    PermissionlessDomainForbidden,
    AdminRequired,
    ZeroEvidenceHash,
}

impl std::fmt::Display for PoaComplianceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoaComplianceError::PermissionlessDomainForbidden => {
                write!(
                    f,
                    "PoA compliance hooks are forbidden in permissionless domains"
                )
            }
            PoaComplianceError::AdminRequired => {
                write!(f, "PoA compliance admin approval required")
            }
            PoaComplianceError::ZeroEvidenceHash => {
                write!(f, "compliance evidence hash must be non-zero")
            }
        }
    }
}

impl std::error::Error for PoaComplianceError {}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PoaComplianceRegistry {
    screenings: HashMap<Address, ScreeningRecord>,
    freezes: HashMap<Address, FreezeRecord>,
    travel_rules: HashMap<[u8; 32], TravelRuleRecord>,
    audit_log: Vec<ComplianceAuditEvent>,
}

impl PoaComplianceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_poa(domain: ComplianceDomainKind) -> Result<(), PoaComplianceError> {
        match domain {
            ComplianceDomainKind::PoA => Ok(()),
            ComplianceDomainKind::Permissionless => {
                Err(PoaComplianceError::PermissionlessDomainForbidden)
            }
        }
    }

    fn ensure_non_zero(hash: [u8; 32]) -> Result<[u8; 32], PoaComplianceError> {
        if hash == [0u8; 32] {
            Err(PoaComplianceError::ZeroEvidenceHash)
        } else {
            Ok(hash)
        }
    }

    pub fn screen_address(
        &mut self,
        domain: ComplianceDomainKind,
        address: Address,
        status: ScreeningStatus,
        oracle_reference_hash: [u8; 32],
        block: u64,
    ) -> Result<(), PoaComplianceError> {
        Self::ensure_poa(domain)?;
        let evidence_hash = Self::ensure_non_zero(oracle_reference_hash)?;
        let record = ScreeningRecord {
            address,
            status,
            oracle_reference_hash: evidence_hash,
            updated_block: block,
        };
        self.screenings.insert(address, record);
        self.audit_log.push(ComplianceAuditEvent {
            action: ComplianceAction::ScreeningUpdated,
            address,
            block,
            evidence_hash,
        });
        Ok(())
    }

    pub fn freeze_suspicious(
        &mut self,
        domain: ComplianceDomainKind,
        admin_authorized: bool,
        address: Address,
        reason_hash: [u8; 32],
        block: u64,
    ) -> Result<(), PoaComplianceError> {
        Self::ensure_poa(domain)?;
        if !admin_authorized {
            return Err(PoaComplianceError::AdminRequired);
        }
        let evidence_hash = Self::ensure_non_zero(reason_hash)?;
        self.freezes.insert(
            address,
            FreezeRecord {
                address,
                reason_hash: evidence_hash,
                frozen_at_block: block,
            },
        );
        self.audit_log.push(ComplianceAuditEvent {
            action: ComplianceAction::AccountFrozen,
            address,
            block,
            evidence_hash,
        });
        Ok(())
    }

    pub fn record_travel_rule_metadata(
        &mut self,
        domain: ComplianceDomainKind,
        tx_hash: [u8; 32],
        subject: Address,
        metadata_hash: [u8; 32],
        block: u64,
    ) -> Result<(), PoaComplianceError> {
        Self::ensure_poa(domain)?;
        let tx_hash = Self::ensure_non_zero(tx_hash)?;
        let evidence_hash = Self::ensure_non_zero(metadata_hash)?;
        self.travel_rules.insert(
            tx_hash,
            TravelRuleRecord {
                tx_hash,
                subject,
                metadata_hash: evidence_hash,
                recorded_block: block,
            },
        );
        self.audit_log.push(ComplianceAuditEvent {
            action: ComplianceAction::TravelRuleMetadataRecorded,
            address: subject,
            block,
            evidence_hash,
        });
        Ok(())
    }

    pub fn screening(&self, address: &Address) -> Option<&ScreeningRecord> {
        self.screenings.get(address)
    }

    pub fn travel_rule(&self, tx_hash: &[u8; 32]) -> Option<&TravelRuleRecord> {
        self.travel_rules.get(tx_hash)
    }

    /// Permissionless domains deliberately ignore PoA freeze state.
    pub fn is_frozen(&self, domain: ComplianceDomainKind, address: &Address) -> bool {
        domain == ComplianceDomainKind::PoA && self.freezes.contains_key(address)
    }

    pub fn audit_events(&self) -> &[ComplianceAuditEvent] {
        &self.audit_log
    }

    pub fn export_audit_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.audit_log)
    }

    pub fn export_audit_csv(&self) -> String {
        let mut out = String::from("action,address,block,evidence_hash\n");
        for event in &self.audit_log {
            out.push_str(&format!(
                "{:?},{},{},{}\n",
                event.action,
                hex::encode(event.address.as_bytes()),
                event.block,
                hex::encode(event.evidence_hash)
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn phase11_18_poa_compliance_rejects_permissionless_screening() {
        let mut registry = PoaComplianceRegistry::new();
        let err = registry
            .screen_address(
                ComplianceDomainKind::Permissionless,
                addr(1),
                ScreeningStatus::Watchlist,
                hash(9),
                10,
            )
            .unwrap_err();
        assert_eq!(err, PoaComplianceError::PermissionlessDomainForbidden);
        assert!(registry.audit_events().is_empty());
    }

    #[test]
    fn phase11_18_poa_compliance_screening_updates_status() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .screen_address(
                ComplianceDomainKind::PoA,
                addr(2),
                ScreeningStatus::Clear,
                hash(1),
                10,
            )
            .unwrap();
        registry
            .screen_address(
                ComplianceDomainKind::PoA,
                addr(2),
                ScreeningStatus::Sanctioned,
                hash(2),
                11,
            )
            .unwrap();
        let record = registry.screening(&addr(2)).unwrap();
        assert_eq!(record.status, ScreeningStatus::Sanctioned);
        assert_eq!(record.updated_block, 11);
        assert_eq!(registry.audit_events().len(), 2);
    }

    #[test]
    fn phase11_18_poa_compliance_requires_admin_for_freeze() {
        let mut registry = PoaComplianceRegistry::new();
        let err = registry
            .freeze_suspicious(ComplianceDomainKind::PoA, false, addr(3), hash(3), 12)
            .unwrap_err();
        assert_eq!(err, PoaComplianceError::AdminRequired);
        assert!(!registry.is_frozen(ComplianceDomainKind::PoA, &addr(3)));
    }

    #[test]
    fn phase11_18_poa_compliance_freeze_is_poa_only() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .freeze_suspicious(ComplianceDomainKind::PoA, true, addr(4), hash(4), 13)
            .unwrap();
        assert!(registry.is_frozen(ComplianceDomainKind::PoA, &addr(4)));
        assert!(!registry.is_frozen(ComplianceDomainKind::Permissionless, &addr(4)));
    }

    #[test]
    fn phase11_18_poa_compliance_audit_log_is_append_only() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .screen_address(
                ComplianceDomainKind::PoA,
                addr(5),
                ScreeningStatus::Watchlist,
                hash(5),
                20,
            )
            .unwrap();
        registry
            .freeze_suspicious(ComplianceDomainKind::PoA, true, addr(5), hash(6), 21)
            .unwrap();
        assert_eq!(registry.audit_events().len(), 2);
        assert_eq!(
            registry.audit_events()[0].action,
            ComplianceAction::ScreeningUpdated
        );
        assert_eq!(
            registry.audit_events()[1].action,
            ComplianceAction::AccountFrozen
        );
    }

    #[test]
    fn phase11_18_poa_compliance_rejects_zero_evidence_hashes() {
        let mut registry = PoaComplianceRegistry::new();
        assert_eq!(
            registry
                .screen_address(
                    ComplianceDomainKind::PoA,
                    addr(6),
                    ScreeningStatus::Watchlist,
                    [0u8; 32],
                    30,
                )
                .unwrap_err(),
            PoaComplianceError::ZeroEvidenceHash
        );
        assert_eq!(
            registry
                .freeze_suspicious(ComplianceDomainKind::PoA, true, addr(6), [0u8; 32], 31)
                .unwrap_err(),
            PoaComplianceError::ZeroEvidenceHash
        );
    }

    #[test]
    fn phase11_18_poa_compliance_records_travel_rule_metadata_hash() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .record_travel_rule_metadata(
                ComplianceDomainKind::PoA,
                hash(9),
                addr(9),
                hash(10),
                42,
            )
            .unwrap();
        let record = registry.travel_rule(&hash(9)).unwrap();
        assert_eq!(record.subject, addr(9));
        assert_eq!(record.metadata_hash, hash(10));
        assert_eq!(record.recorded_block, 42);
        assert_eq!(
            registry.audit_events().last().unwrap().action,
            ComplianceAction::TravelRuleMetadataRecorded
        );
    }

    #[test]
    fn phase11_18_poa_compliance_rejects_permissionless_travel_rule_metadata() {
        let mut registry = PoaComplianceRegistry::new();
        let err = registry
            .record_travel_rule_metadata(
                ComplianceDomainKind::Permissionless,
                hash(9),
                addr(9),
                hash(10),
                42,
            )
            .unwrap_err();
        assert_eq!(err, PoaComplianceError::PermissionlessDomainForbidden);
        assert!(registry.travel_rule(&hash(9)).is_none());
    }

    #[test]
    fn phase11_18_poa_compliance_exports_audit_csv() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .screen_address(
                ComplianceDomainKind::PoA,
                addr(7),
                ScreeningStatus::Clear,
                hash(7),
                40,
            )
            .unwrap();
        let csv = registry.export_audit_csv();
        assert!(csv.starts_with("action,address,block,evidence_hash\n"));
        assert!(csv.contains("ScreeningUpdated"));
        assert!(csv.contains(&hex::encode(addr(7).as_bytes())));
    }

    #[test]
    fn phase11_18_poa_compliance_exports_audit_json() {
        let mut registry = PoaComplianceRegistry::new();
        registry
            .freeze_suspicious(ComplianceDomainKind::PoA, true, addr(8), hash(8), 41)
            .unwrap();
        let json = registry.export_audit_json().unwrap();
        assert!(json.contains("AccountFrozen"));
        assert!(json.contains("evidence_hash"));
    }
}
