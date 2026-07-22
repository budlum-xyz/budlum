use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{ConsensusDomain, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MIN_DOMAIN_OPERATOR_BOND: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusDomainRegistry {
    domains: BTreeMap<DomainId, ConsensusDomain>,
}

impl ConsensusDomainRegistry {
    pub fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, domain: ConsensusDomain) -> Result<(), String> {
        if self.domains.contains_key(&domain.id) {
            return Err(format!("Domain {} is already registered", domain.id));
        }
        if !domain.has_operator_bond(MIN_DOMAIN_OPERATOR_BOND) {
            return Err(format!(
                "Domain {} requires operator identity and minimum bond {}",
                domain.id, MIN_DOMAIN_OPERATOR_BOND
            ));
        }
        if domain.operator == Some(crate::core::address::Address::zero()) {
            return Err(format!("Domain {} has invalid zero operator", domain.id));
        }

        if domain.finality_adapter == crate::domain::types::POW_HEADER_CHAIN_ADAPTER {
            if domain.kind != crate::domain::types::ConsensusKind::PoW {
                return Err(format!(
                    "Domain {} uses the PoW header adapter with a non-PoW consensus kind",
                    domain.id
                ));
            }
            domain
                .pow_parameters
                .as_ref()
                .ok_or_else(|| {
                    format!(
                        "Domain {} uses the PoW header adapter without pow_parameters",
                        domain.id
                    )
                })?
                .validate(domain.min_confirmations)?;
        } else if domain.pow_parameters.is_some() {
            return Err(format!(
                "Domain {} supplies pow_parameters for incompatible adapter {}",
                domain.id, domain.finality_adapter
            ));
        }

        // Task 0.38, Görev 1 (B.U.D. Storage ConsensusDomain, vision §8.1):
        // a `StorageAttestation` domain MUST use the dedicated
        // `STORAGE_ATTESTATION_ADAPTER` finality adapter, and the
        // parameters must validate. This is the same fail-fast-at-the-edge
        // pattern as the PoW header-chain branch above.
        if let crate::domain::types::ConsensusKind::StorageAttestation(params) = &domain.kind {
            if domain.finality_adapter != crate::domain::types::STORAGE_ATTESTATION_ADAPTER {
                return Err(format!(
                    "Domain {} uses StorageAttestation with non-storage finality adapter '{}' \
                     (expected '{}')",
                    domain.id,
                    domain.finality_adapter,
                    crate::domain::types::STORAGE_ATTESTATION_ADAPTER
                ));
            }
            if domain.operator_bond < params.min_operator_bond {
                return Err(format!(
                    "Domain {} operator_bond {} below StorageAttestation min_operator_bond {}",
                    domain.id, domain.operator_bond, params.min_operator_bond
                ));
            }
            params.validate()?;
        } else if domain.finality_adapter == crate::domain::types::STORAGE_ATTESTATION_ADAPTER {
            return Err(format!(
                "Domain {} uses the storage-attestation adapter with a non-StorageAttestation \
                 consensus kind",
                domain.id
            ));
        }

        self.domains.insert(domain.id, domain);
        Ok(())
    }

    pub fn get(&self, id: DomainId) -> Option<&ConsensusDomain> {
        self.domains.get(&id)
    }

    pub fn get_mut(&mut self, id: DomainId) -> Option<&mut ConsensusDomain> {
        self.domains.get_mut(&id)
    }

    pub fn set_status(&mut self, id: DomainId, status: DomainStatus) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        domain.status = status;
        Ok(())
    }

    /// Task 11.8 lifecycle guard: use this for governance/operator-driven
    /// transitions. `set_status` remains for migration/tests, while this helper
    /// prevents accidental Active→Retired jumps and makes Retired terminal.
    pub fn transition_status_checked(
        &mut self,
        id: DomainId,
        next: DomainStatus,
    ) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        let current = domain.status;
        let allowed = matches!(
            (current, next),
            (DomainStatus::Active, DomainStatus::Frozen)
                | (DomainStatus::Frozen, DomainStatus::Active)
                | (DomainStatus::Frozen, DomainStatus::Retired)
        );
        if !allowed {
            return Err(format!(
                "Illegal domain lifecycle transition for {id}: {current:?} -> {next:?}"
            ));
        }
        domain.status = next;
        Ok(())
    }

    pub fn active_domains(&self) -> impl Iterator<Item = &ConsensusDomain> {
        self.domains
            .values()
            .filter(|domain| domain.status == DomainStatus::Active)
    }

    pub fn domains(&self) -> Vec<ConsensusDomain> {
        self.domains.values().cloned().collect()
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self.domains.values().map(domain_leaf_hash).collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

pub fn domain_leaf_hash(domain: &ConsensusDomain) -> Hash32 {
    let kind = domain.kind.as_bytes();
    let status = match domain.status {
        DomainStatus::Active => b"active".as_slice(),
        DomainStatus::Frozen => b"frozen".as_slice(),
        DomainStatus::Retired => b"retired".as_slice(),
    };
    let block_scheme = domain.block_hash_scheme.as_bytes();
    let state_scheme = domain.state_root_scheme.as_bytes();
    let tx_scheme = domain.tx_root_scheme.as_bytes();
    let operator = domain
        .operator
        .map(|address| address.as_bytes().to_vec())
        .unwrap_or_default();

    if let Some(params) = &domain.pow_parameters {
        let mut pow_parameters = Vec::with_capacity(4 + 4 + 16 + 4);
        pow_parameters.extend_from_slice(&params.min_difficulty_bits.to_le_bytes());
        pow_parameters.extend_from_slice(&params.max_difficulty_bits.to_le_bytes());
        pow_parameters.extend_from_slice(&params.min_cumulative_work.to_le_bytes());
        pow_parameters.extend_from_slice(&params.max_headers.to_le_bytes());
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V2",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &pow_parameters,
            &[domain.bridge_enabled as u8],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    } else if let crate::domain::types::ConsensusKind::StorageAttestation(storage) = &domain.kind {
        // Task 0.38, Görev 1: B.U.D. storage domains get a V3 leaf that mixes the
        // storage parameters into the leaf. Without this, two storage domains
        // with different chunk_size / challenge_interval would hash to the
        // same leaf and the registry root would no longer be a sound
        // commitment to the per-domain parameters.
        let storage_params = crate::domain::storage_params::storage_params_bytes(storage);
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V3",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &storage_params,
            &[domain.bridge_enabled as u8],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    } else {
        // Preserve the exact V1 leaf for every pre-Task 0.37 domain.
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V1",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &[domain.bridge_enabled as u8],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::plugin::default_domain;
    use crate::domain::types::ConsensusKind;

    #[test]
    fn registry_root_is_order_independent_by_domain_id() {
        let domain_a = default_domain(1, ConsensusKind::PoW, 1337, "pow", 64);
        let domain_b = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);

        let mut first = ConsensusDomainRegistry::new();
        first.register(domain_b.clone()).unwrap();
        first.register(domain_a.clone()).unwrap();

        let mut second = ConsensusDomainRegistry::new();
        second.register(domain_a).unwrap();
        second.register(domain_b).unwrap();

        assert_eq!(first.root(), second.root());
    }

    #[test]
    fn duplicate_domain_registration_is_rejected() {
        let domain = default_domain(1, ConsensusKind::PoW, 1337, "pow", 64);
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain.clone()).unwrap();
        assert!(registry.register(domain).is_err());
    }

    #[test]
    fn task11_8_domain_lifecycle_requires_freeze_before_retire() {
        let domain = default_domain(7, ConsensusKind::PoS, 1337, "pos", 0);
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain).unwrap();
        assert!(registry
            .transition_status_checked(7, DomainStatus::Retired)
            .unwrap_err()
            .contains("Illegal domain lifecycle transition"));
        registry
            .transition_status_checked(7, DomainStatus::Frozen)
            .unwrap();
        registry
            .transition_status_checked(7, DomainStatus::Retired)
            .unwrap();
    }

    #[test]
    fn task11_8_retired_domain_is_terminal() {
        let domain = default_domain(8, ConsensusKind::Bft, 1337, "bft", 0);
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain).unwrap();
        registry
            .transition_status_checked(8, DomainStatus::Frozen)
            .unwrap();
        registry
            .transition_status_checked(8, DomainStatus::Retired)
            .unwrap();
        assert!(registry
            .transition_status_checked(8, DomainStatus::Active)
            .unwrap_err()
            .contains("Illegal domain lifecycle transition"));
    }
}
