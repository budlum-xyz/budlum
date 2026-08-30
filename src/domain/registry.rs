use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{ConsensusDomain, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MIN_DOMAIN_OPERATOR_BOND: u64 = 10_000;

/// The maximum number of domains that may be kept registered.
///
/// # Why a ceiling is needed
///
/// Registration is permissionless: anyone who posts enough bond can open a domain. The bond
/// is itself a cost but **not a bound** - it is a refundable
/// deposit, not a spent fee. When the unbond period expires the operator
/// gets the money back, so for someone with enough capital the net cost of opening a domain
/// is only that the money stays locked for that period.
///
/// Every registered domain adds to the chain's **per-block** work: [`ConsensusDomainRegistry::root`]
/// computes a leaf hash for every domain and this root is recomputed in every
/// block. So the registration count directly determines the work every validator does in every
/// block, and that work is paid **by the network**, not by the domain
/// owner. Because the bond is refundable, an attacker with capital can raise that work
/// permanently and still get their money back.
///
/// Tavan bu bilesimi kirar: bagin geri alinabilirligi degismez, ama toplam
/// the load is now bounded from above by a constant. A number within `u16` width was chosen
/// (4096, not 65 536): a Merkle tree with 4096 leaves is 12 levels deep and recomputing it in
/// every block is a measurable cost; anything above that grows validator cost without
/// corresponding to any legitimate need.
///
/// # What happens when the ceiling is reached
///
/// New registrations are refused. That forces a governance decision - raising the
/// or retiring unused domains - and that decision
/// becomes visible. From a silently growing cost to a discussed decision.
///
/// Retired domains count too: as long as the leaf stands in the tree, the root
/// and the proof size count against it. To be excluded from the count a domain
/// has to be **removed** from the registry, which is a separate decision and a
/// separate path.
pub const MAX_REGISTERED_DOMAINS: usize = 4096;

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
        // The count comes after the identity check: a request arriving with an already registered id
        // must not occupy the ceiling, because it adds no new leaf.
        if self.domains.len() >= MAX_REGISTERED_DOMAINS {
            return Err(format!(
                "Domain {} rejected: registry is at its ceiling of {MAX_REGISTERED_DOMAINS} \
                 domains. Every registered domain costs every validator work in every block \
                 (the registry root is rebuilt per block), and the operator bond is refundable, \
                 so nothing else bounds that cost. Retire an unused domain or raise the ceiling \
                 through governance.",
                domain.id
            ));
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
        } else if domain.min_confirmations > 1 {
            // `min_confirmations` is a header-chain depth. Exactly one of the
            // seven finality adapters reads it - the PoW one, at
            // `observed_depth < domain.min_confirmations`. The other six never
            // look at the field, so a value above the no-op default was
            // accepted, stored, hashed into the registry, and then ignored.
            //
            // That is worse than not having the field: an operator reading
            // `"min_confirmations": 3` on a PoS domain in genesis has every
            // reason to believe three confirmations are required, and nothing
            // in the logs would ever say otherwise. Rejecting at registration
            // is the same fail-fast-at-the-edge rule the pow_parameters branch
            // above already applies.
            //
            // `1` stays allowed because it is the historical default in the
            // shipped genesis files and means the same thing as "no depth
            // requirement" for an adapter that finalises on a quorum.
            return Err(format!(
                "Domain {} sets min_confirmations={} but its adapter {} never reads it; \
                 header-chain depth only applies to {}",
                domain.id,
                domain.min_confirmations,
                domain.finality_adapter,
                crate::domain::types::POW_HEADER_CHAIN_ADAPTER
            ));
        }

        // (B.U.D. Storage ConsensusDomain, vision §8.1)
        // A `StorageAttestation` domain MUST use the dedicated
        // `STORAGE_ATTESTATION_ADAPTER` finality adapter, and the
        // Parameters must validate. This is the same fail-fast-at-the-edge
        // Pattern as the PoW header-chain branch above.
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

    /// Lifecycle guard: use this for governance/operator-driven
    /// Transitions. `set_status` remains for migration/tests, while this helper
    /// Prevents accidental Active→Retired jumps and makes Retired terminal.
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

    /// Adds a zk program to the domain allowlist.
    ///
    /// # Why this path exists
    ///
    /// `zk_program_allowlist` is read in `submit_zk_proof` and an empty list means
    /// fail-closed - the right default. But nothing touched the **insertion**
    /// side of the list: `Vec::new()` is written when the domain is created and
    /// no other code path ever reached it. So there could never be anything
    /// behind the gate; a list that is read but can never be filled gives a
    /// reader the impression that "programs are managed" while they are not.
    ///
    /// # Errors
    ///
    /// If the domain does not exist, or the program is already in the list. The second case could have been
    /// passed silently, but if "it was already there" and "it was just added" give the same answer,
    /// a governance operation cannot verify its own effect.
    pub fn allow_zk_program(&mut self, id: DomainId, program: Hash32) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        if domain.zk_program_allowlist.contains(&program) {
            return Err(format!(
                "Program {} is already on the allowlist of domain {id}",
                hex::encode(program)
            ));
        }
        domain.zk_program_allowlist.push(program);
        Ok(())
    }

    /// Removes a zk program from the allowlist.
    ///
    /// # Why revocation is mandatory
    ///
    /// An admitted program holds the right to advance the state of the domain.
    /// If a defect is later found in that program - a field the proof system
    /// does not constrain, a wrong transition rule - the only defence is to take
    /// it off the list. An allowlist with an insertion path but no removal path
    /// is a one-way door: what gets in can never be taken out, and once that
    /// program is known to be wrong the only thing left to do would be to freeze
    /// the whole domain.
    ///
    /// Revocation is **not retroactive**: proofs produced and already accepted
    /// before the removal stay valid. The history of the chain is not rewritten;
    /// what changes is what will be accepted from now on.
    ///
    /// # Errors
    ///
    /// If the domain does not exist, or the program is not on the list.
    pub fn revoke_zk_program(&mut self, id: DomainId, program: &Hash32) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        let before = domain.zk_program_allowlist.len();
        domain.zk_program_allowlist.retain(|p| p != program);
        if domain.zk_program_allowlist.len() == before {
            return Err(format!(
                "Program {} is not on the allowlist of domain {id}, so there is nothing to revoke",
                hex::encode(program)
            ));
        }
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
        // B.U.D. storage domains get a V3 leaf that mixes the
        // Storage parameters into the leaf. Without this, two storage domains
        // With different chunk_size / challenge_interval would hash to the
        // Same leaf and the registry root would no longer be a sound
        // Commitment to the per-domain parameters.
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
        // Preserve the exact V1 leaf for every pre- domain.
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
        // Uses the real PoW header-chain adapter because 64 is a genuine
        // confirmation depth, and only that adapter reads the field.
        let domain_a = default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            64,
        );
        let domain_b = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);

        let mut first = ConsensusDomainRegistry::new();
        first.register(domain_b.clone()).unwrap();
        first.register(domain_a.clone()).unwrap();

        let mut second = ConsensusDomainRegistry::new();
        second.register(domain_a).unwrap();
        second.register(domain_b).unwrap();

        assert_eq!(first.root(), second.root());
    }

    /// The registry cannot exceed its ceiling.
    ///
    /// Every registered domain adds a leaf to the registry root that is recomputed in every
    /// block; the whole network bears that work, not the domain owner. Because the operator bond is
    /// refundable the bond does not bound this growth - the ceiling is the only bound.
    #[test]
    fn the_registry_does_not_grow_past_its_ceiling() {
        let mut registry = ConsensusDomainRegistry::new();

        // Filled up to the ceiling. Every registration must succeed: the ceiling
        // dolmadan reddeden bir kapi mesru kullanimi engellerdi.
        for id in 0..MAX_REGISTERED_DOMAINS {
            let id = u32::try_from(id).expect("tavan u32'ye sigar");
            registry
                .register(default_domain(id, ConsensusKind::PoS, 1338, "pos", 0))
                .expect("every registration up to the ceiling must be accepted");
        }
        assert_eq!(registry.domains().len(), MAX_REGISTERED_DOMAINS);

        // The first registration above the ceiling is refused.
        let overflow = u32::try_from(MAX_REGISTERED_DOMAINS).expect("tavan+0 u32'ye sigar");
        let err = registry
            .register(default_domain(overflow, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("a registration above the ceiling must be refused");
        assert!(
            err.contains("ceiling"),
            "the refusal reason must state the ceiling: {err}"
        );

        // The refusal must really have kept it out of the registry - reporting a message and adding anyway
        // would leave the ceiling silent.
        assert_eq!(
            registry.domains().len(),
            MAX_REGISTERED_DOMAINS,
            "a refused registration must not enter the registry"
        );

        // A request with an already registered id is refused for duplication,
        // not for the ceiling: because it adds no new leaf
        // tavanla ilgisi yok.
        let dup = registry
            .register(default_domain(0, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("a duplicate registration must be refused");
        assert!(
            dup.contains("already registered"),
            "yinelenme, tavandan once denetlenmeli: {dup}"
        );
    }

    /// Bir program listeye alinabilir ve geri cekilebilir.
    ///
    /// Before the gate the list was only read: `submit_zk_proof` looked at it
    /// but no code wrote to it. An allowlist that is read but cannot be filled
    /// listesi, yonetiliyormus gibi gorunen ve yonetilmeyen bir kapidir.
    #[test]
    fn a_zk_program_can_be_admitted_and_withdrawn() {
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(5, ConsensusKind::PoS, 1338, "pos", 0))
            .expect("registration");

        let program = [9u8; 32];
        let other = [8u8; 32];

        // The list starts empty: the fail-closed default is preserved.
        let domain = registry.get(5).expect("alan");
        assert!(domain.zk_program_allowlist.is_empty());

        registry.allow_zk_program(5, program).expect("ekleme");
        assert_eq!(
            registry.get(5).expect("alan").zk_program_allowlist,
            vec![program]
        );

        // Adding the same program twice does not pass silently: a governance operation
        // must be able to verify its own effect.
        assert!(registry.allow_zk_program(5, program).is_err());

        // Revocation works and removes only the target.
        registry.allow_zk_program(5, other).expect("ikinci ekleme");
        registry.revoke_zk_program(5, &program).expect("geri cekme");
        assert_eq!(
            registry.get(5).expect("alan").zk_program_allowlist,
            vec![other],
            "only the targeted program must be removed"
        );

        // Revoking something not in the list is an error: a failed revocation
        // reads as success, the program is still accepted while appearing removed
        // sanilir.
        assert!(registry.revoke_zk_program(5, &program).is_err());

        // An unknown domain is refused on both paths.
        assert!(registry.allow_zk_program(404, program).is_err());
        assert!(registry.revoke_zk_program(404, &program).is_err());
    }

    #[test]
    fn duplicate_domain_registration_is_rejected() {
        let domain = default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            64,
        );
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain.clone()).unwrap();
        assert!(registry.register(domain).is_err());
    }

    #[test]
    fn domain_lifecycle_requires_freeze_before_retire() {
        let domain = default_domain(7, ConsensusKind::PoS, 45262, "pos", 0);
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
    fn retired_domain_is_terminal() {
        let domain = default_domain(8, ConsensusKind::Bft, 45262, "bft", 0);
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

    /// A field that only one adapter reads must not be silently accepted by
    /// the other six.
    ///
    /// Measured: of the seven `DomainFinalityAdapter` implementations, exactly
    /// one - `PoWHeaderChainFinalityAdapter` - reads `min_confirmations`, at
    /// `observed_depth < domain.min_confirmations`. The rest never look at it.
    /// The shipped `config/mainnet-genesis.json` nonetheless sets it on all
    /// four bootstrap domains, so an operator reading that file has every
    /// reason to think a depth requirement applies where none does.
    #[test]
    fn a_non_pow_domain_cannot_claim_a_confirmation_depth() {
        let mut registry = ConsensusDomainRegistry::new();
        let domain = default_domain(101, ConsensusKind::PoS, 45262, "pos-qc-finality", 3);
        let err = registry
            .register(domain)
            .expect_err("a depth no adapter reads must not be accepted silently");
        assert!(err.contains("never reads it"), "err: {err}");
        assert!(
            err.contains("101"),
            "the message must name the domain: {err}"
        );
    }

    #[test]
    fn the_historical_default_of_one_is_still_accepted() {
        // `1` is what the shipped genesis files carry for the non-PoW domains
        // and means the same thing as "no depth requirement" for an adapter
        // that finalises on a quorum. Rejecting it would break every existing
        // configuration for no safety gain.
        let mut registry = ConsensusDomainRegistry::new();
        for (id, kind, adapter) in [
            (111u32, ConsensusKind::PoS, "pos-qc-finality"),
            (112, ConsensusKind::Bft, "bft-quorum-commit"),
            (113, ConsensusKind::PoA, "poa-authority-quorum"),
        ] {
            registry
                .register(default_domain(id, kind, 45262, adapter, 1))
                .unwrap_or_else(|e| {
                    panic!("min_confirmations=1 must stay valid for {adapter}: {e}")
                });
        }
    }

    #[test]
    fn zero_is_still_accepted_for_a_quorum_adapter() {
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(
                121,
                ConsensusKind::Bft,
                45262,
                "bft-quorum-commit",
                0,
            ))
            .expect("zero means no depth requirement, which is honest for a quorum adapter");
    }

    #[test]
    fn a_pow_domain_may_still_require_real_depth() {
        // The check must not have closed the one case where the field works.
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(
                131,
                ConsensusKind::PoW,
                45262,
                crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
                6,
            ))
            .expect("a PoW header-chain domain is exactly where depth applies");
    }
}
