//! Constitution Engine primitives (Task 12 / ARENA4).
//!
//! The constitution layer binds governance to user-sovereignty guardrails. DAO
//! proposals may tune bounded operational parameters, but they must not weaken
//! hard rules such as AI default-deny, no decrypt override, permissionless core
//! operation, or PoA island isolation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConstitutionParameterKey {
    /// AI may only read Pollen/B.U.D. data through an explicit owner grant.
    AiReadRequiresPollenGrant,
    /// Governance cannot grant AI read/decrypt override power.
    NoGovernanceReadOverride,
    /// Permissionless PoW/PoS/BFT core cannot gain admin/whitelist admission.
    PermissionlessCoreNoAdminWhitelist,
    /// PoA/sovereign-domain rules stay inside their own islands.
    PoaIslandIsolation,
    /// DAO/protocol state cannot custody or request user private keys.
    NoPrivateKeyCustody,
    /// Passport/Atlas public APIs expose evidence/commitments, not plaintext.
    EvidenceApisNoPlaintext,
    /// Maximum emergency halt duration, in epochs, for future halt proposals.
    MaxEmergencyHaltEpochs,
    /// Minimum voting duration for future constitution amendments.
    MinConstitutionProposalEpochs,
}

impl ConstitutionParameterKey {
    pub fn is_hard_guardrail(self) -> bool {
        matches!(
            self,
            ConstitutionParameterKey::AiReadRequiresPollenGrant
                | ConstitutionParameterKey::NoGovernanceReadOverride
                | ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist
                | ConstitutionParameterKey::PoaIslandIsolation
                | ConstitutionParameterKey::NoPrivateKeyCustody
                | ConstitutionParameterKey::EvidenceApisNoPlaintext
        )
    }

    fn tag(self) -> u8 {
        match self {
            ConstitutionParameterKey::AiReadRequiresPollenGrant => 1,
            ConstitutionParameterKey::NoGovernanceReadOverride => 2,
            ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist => 3,
            ConstitutionParameterKey::PoaIslandIsolation => 4,
            ConstitutionParameterKey::NoPrivateKeyCustody => 5,
            ConstitutionParameterKey::EvidenceApisNoPlaintext => 6,
            ConstitutionParameterKey::MaxEmergencyHaltEpochs => 7,
            ConstitutionParameterKey::MinConstitutionProposalEpochs => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstitutionValue {
    Bool(bool),
    U64(u64),
    Hash([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionParameter {
    pub key: ConstitutionParameterKey,
    pub value: ConstitutionValue,
    pub effective_epoch: u64,
    pub rationale_hash: [u8; 32],
}

impl ConstitutionParameter {
    pub fn new(
        key: ConstitutionParameterKey,
        value: ConstitutionValue,
        effective_epoch: u64,
        rationale_hash: [u8; 32],
    ) -> Self {
        Self {
            key,
            value,
            effective_epoch,
            rationale_hash,
        }
    }

    fn hard_default(key: ConstitutionParameterKey) -> Self {
        Self::new(key, ConstitutionValue::Bool(true), 0, [0u8; 32])
    }

    fn validate_value(&self) -> Result<(), String> {
        match self.key {
            ConstitutionParameterKey::AiReadRequiresPollenGrant
            | ConstitutionParameterKey::NoGovernanceReadOverride
            | ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist
            | ConstitutionParameterKey::PoaIslandIsolation
            | ConstitutionParameterKey::NoPrivateKeyCustody
            | ConstitutionParameterKey::EvidenceApisNoPlaintext => match &self.value {
                ConstitutionValue::Bool(true) => Ok(()),
                ConstitutionValue::Bool(false) => Err(format!(
                    "hard constitution guardrail {:?} cannot be disabled",
                    self.key
                )),
                _ => Err(format!(
                    "hard constitution guardrail {:?} must be Bool(true)",
                    self.key
                )),
            },
            ConstitutionParameterKey::MaxEmergencyHaltEpochs => match &self.value {
                ConstitutionValue::U64(value) if (1..=10_080).contains(value) => Ok(()),
                ConstitutionValue::U64(_) => {
                    Err("MaxEmergencyHaltEpochs must be between 1 and 10080 epochs".into())
                }
                _ => Err("MaxEmergencyHaltEpochs must be U64".into()),
            },
            ConstitutionParameterKey::MinConstitutionProposalEpochs => match &self.value {
                ConstitutionValue::U64(value) if (10..=100_000).contains(value) => Ok(()),
                ConstitutionValue::U64(_) => {
                    Err("MinConstitutionProposalEpochs must be between 10 and 100000 epochs".into())
                }
                _ => Err("MinConstitutionProposalEpochs must be U64".into()),
            },
        }
    }

    pub fn validate_update(&self) -> Result<(), String> {
        self.validate_value()?;
        if self.key.is_hard_guardrail() {
            return Err(format!(
                "hard constitution guardrail {:?} cannot be changed by governance",
                self.key
            ));
        }
        if self.rationale_hash == [0u8; 32] {
            return Err("constitution update rationale_hash cannot be zero".into());
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update([self.key.tag()]);
        match &self.value {
            ConstitutionValue::Bool(value) => {
                hasher.update([1]);
                hasher.update([u8::from(*value)]);
            }
            ConstitutionValue::U64(value) => {
                hasher.update([2]);
                hasher.update(value.to_le_bytes());
            }
            ConstitutionValue::Hash(value) => {
                hasher.update([3]);
                hasher.update(value);
            }
        }
        hasher.update(self.effective_epoch.to_le_bytes());
        hasher.update(self.rationale_hash);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionRegistry {
    pub parameters: BTreeMap<ConstitutionParameterKey, ConstitutionParameter>,
}

impl ConstitutionRegistry {
    pub fn new() -> Self {
        let mut parameters = BTreeMap::new();
        for key in [
            ConstitutionParameterKey::AiReadRequiresPollenGrant,
            ConstitutionParameterKey::NoGovernanceReadOverride,
            ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist,
            ConstitutionParameterKey::PoaIslandIsolation,
            ConstitutionParameterKey::NoPrivateKeyCustody,
            ConstitutionParameterKey::EvidenceApisNoPlaintext,
        ] {
            parameters.insert(key, ConstitutionParameter::hard_default(key));
        }
        parameters.insert(
            ConstitutionParameterKey::MaxEmergencyHaltEpochs,
            ConstitutionParameter::new(
                ConstitutionParameterKey::MaxEmergencyHaltEpochs,
                ConstitutionValue::U64(1_440),
                0,
                [0u8; 32],
            ),
        );
        parameters.insert(
            ConstitutionParameterKey::MinConstitutionProposalEpochs,
            ConstitutionParameter::new(
                ConstitutionParameterKey::MinConstitutionProposalEpochs,
                ConstitutionValue::U64(10),
                0,
                [0u8; 32],
            ),
        );
        Self { parameters }
    }

    pub fn set_parameter(&mut self, parameter: ConstitutionParameter) -> Result<(), String> {
        parameter.validate_update()?;
        self.parameters.insert(parameter.key, parameter);
        self.assert_hard_guardrails()
    }

    pub fn get(&self, key: ConstitutionParameterKey) -> Option<&ConstitutionParameter> {
        self.parameters.get(&key)
    }

    pub fn assert_hard_guardrails(&self) -> Result<(), String> {
        for key in [
            ConstitutionParameterKey::AiReadRequiresPollenGrant,
            ConstitutionParameterKey::NoGovernanceReadOverride,
            ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist,
            ConstitutionParameterKey::PoaIslandIsolation,
            ConstitutionParameterKey::NoPrivateKeyCustody,
            ConstitutionParameterKey::EvidenceApisNoPlaintext,
        ] {
            let parameter = self
                .parameters
                .get(&key)
                .ok_or_else(|| format!("missing hard constitution guardrail {:?}", key))?;
            parameter.validate_value()?;
        }
        Ok(())
    }

    pub fn has_non_default_updates(&self) -> bool {
        self != &Self::new()
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_CONSTITUTION_REGISTRY_V1");
        for parameter in self.parameters.values() {
            parameter.hash_into(&mut hasher);
        }
        hasher.finalize().into()
    }
}

impl Default for ConstitutionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rationale(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn default_constitution_keeps_hard_guardrails_active() {
        let registry = ConstitutionRegistry::new();
        registry.assert_hard_guardrails().unwrap();
        assert_eq!(
            registry
                .get(ConstitutionParameterKey::AiReadRequiresPollenGrant)
                .unwrap()
                .value
                .clone(),
            ConstitutionValue::Bool(true)
        );
        assert_eq!(
            registry
                .get(ConstitutionParameterKey::NoGovernanceReadOverride)
                .unwrap()
                .value
                .clone(),
            ConstitutionValue::Bool(true)
        );
    }

    #[test]
    fn governance_cannot_disable_ai_read_denial_guardrail() {
        let mut registry = ConstitutionRegistry::new();
        let update = ConstitutionParameter::new(
            ConstitutionParameterKey::AiReadRequiresPollenGrant,
            ConstitutionValue::Bool(false),
            10,
            rationale(1),
        );
        let err = registry.set_parameter(update).unwrap_err();
        assert!(err.contains("cannot be disabled"));
    }

    #[test]
    fn governance_cannot_mutate_permissionless_no_admin_guardrail() {
        let mut registry = ConstitutionRegistry::new();
        let update = ConstitutionParameter::new(
            ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist,
            ConstitutionValue::Bool(true),
            10,
            rationale(2),
        );
        let err = registry.set_parameter(update).unwrap_err();
        assert!(err.contains("cannot be changed by governance"));
    }

    #[test]
    fn bounded_mutable_parameter_changes_root() {
        let mut registry = ConstitutionRegistry::new();
        let before = registry.root();
        registry
            .set_parameter(ConstitutionParameter::new(
                ConstitutionParameterKey::MaxEmergencyHaltEpochs,
                ConstitutionValue::U64(720),
                42,
                rationale(3),
            ))
            .unwrap();
        assert_ne!(before, registry.root());
        assert!(registry.has_non_default_updates());
    }

    #[test]
    fn mutable_parameter_requires_rationale_hash_and_bounds() {
        let mut registry = ConstitutionRegistry::new();
        let zero_rationale = ConstitutionParameter::new(
            ConstitutionParameterKey::MaxEmergencyHaltEpochs,
            ConstitutionValue::U64(720),
            42,
            [0u8; 32],
        );
        assert!(registry
            .set_parameter(zero_rationale)
            .unwrap_err()
            .contains("rationale_hash"));

        let out_of_bounds = ConstitutionParameter::new(
            ConstitutionParameterKey::MaxEmergencyHaltEpochs,
            ConstitutionValue::U64(0),
            42,
            rationale(4),
        );
        assert!(registry
            .set_parameter(out_of_bounds)
            .unwrap_err()
            .contains("between 1 and 10080"));
    }
}
