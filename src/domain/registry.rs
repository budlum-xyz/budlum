use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{ConsensusDomain, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MIN_DOMAIN_OPERATOR_BOND: u64 = 10_000;

/// Kayitli tutulabilecek en fazla domain sayisi.
///
/// # Neden bir tavan gerekiyor
///
/// Kayit izinli degil: yeterli bagi yatiran herkes domain acabilir. Bagin
/// kendisi bir maliyettir ama **sinir degildir** - geri alinabilir bir
/// mevduattir, harcanan bir ucret degil. Unbond suresi dolunca operator
/// parasini geri alir, yani yeterli sermayeli biri icin bir domain acmanin
/// net maliyeti yalnizca paranin o sure boyunca bagli kalmasidir.
///
/// Kayitli her domain zincirin **blok basina** isine ekleniyor: [`ConsensusDomainRegistry::root`]
/// her domain icin bir yaprak hash'i hesaplar ve bu kok her blokta yeniden
/// uretilir. Yani kayit sayisi dogrudan her dogrulayicinin her blokta yaptigi
/// isi belirler, ve o is domain sahibi tarafindan degil **ag tarafindan**
/// odenir. Bag geri alinabildigi icin, sermayesi olan bir saldirgan bu isi
/// kalici olarak yukseltip parasini geri alabilir.
///
/// Tavan bu bilesimi kirar: bagin geri alinabilirligi degismez, ama toplam
/// yuk artik sabit bir ustten sinirli. `u16` genisliginde bir sayi secildi
/// (65 536 degil 4096): 4096 yaprakli bir Merkle agaci 12 seviyedir ve her
/// blokta yeniden hesaplanmasi olculebilir bir maliyettir; bunun ustu, hicbir
/// mesru ihtiyacin karsiligi olmadan dogrulayici maliyetini buyutur.
///
/// # Tavan dolunca ne olur
///
/// Yeni kayit reddedilir. Bu bir yonetim kararini zorunlu kilar - tavani
/// yukseltmek ya da kullanilmayan domainleri emekliye ayirmak - ve o karar
/// gorunur olur. Sessizce buyuyen bir maliyetten, konusulan bir karara.
///
/// Emekli (`Retired`) domainler de sayilir: yaprak agacta durdugu surece kok
/// hesabina girer. Sayimin disinda tutulmalari icin kayittan **silinmeleri**
/// gerekir, ki o ayri bir karar ve ayri bir yol.
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
        // Sayim, kimlik denetiminden sonra: zaten kayitli bir id ile gelen
        // istek tavani mesgul etmemeli, cunku yeni bir yaprak eklemiyor.
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

    /// Kayit defteri tavanini asamaz.
    ///
    /// Kayitli her domain her blokta yeniden hesaplanan kayit kokune bir
    /// yaprak ekler; o isi agin tamami karsiliyor, domain sahibi degil. Operator bagi geri
    /// alinabildigi icin bag bu buyumeyi sinirlamaz - tek sinir tavan.
    #[test]
    fn the_registry_does_not_grow_past_its_ceiling() {
        let mut registry = ConsensusDomainRegistry::new();

        // Tavana kadar dolduruluyor. Her kayit basarili olmali: tavan
        // dolmadan reddeden bir kapi mesru kullanimi engellerdi.
        for id in 0..MAX_REGISTERED_DOMAINS {
            let id = u32::try_from(id).expect("tavan u32'ye sigar");
            registry
                .register(default_domain(id, ConsensusKind::PoS, 1338, "pos", 0))
                .expect("tavana kadar her kayit kabul edilmeli");
        }
        assert_eq!(registry.domains().len(), MAX_REGISTERED_DOMAINS);

        // Tavanin ustundeki ilk kayit reddedilir.
        let overflow = u32::try_from(MAX_REGISTERED_DOMAINS).expect("tavan+0 u32'ye sigar");
        let err = registry
            .register(default_domain(overflow, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("tavanin ustundeki kayit reddedilmeli");
        assert!(
            err.contains("ceiling"),
            "ret gerekcesi tavani soylemeli: {err}"
        );

        // Ret gercekten kayda girmemis olmali - mesaj verip yine de eklemek
        // tavani sussuz birakirdi.
        assert_eq!(
            registry.domains().len(),
            MAX_REGISTERED_DOMAINS,
            "reddedilen kayit deftere girmemeli"
        );

        // Zaten kayitli bir id ile gelen istek tavan gerekcesiyle degil
        // yinelenme gerekcesiyle reddedilir: yeni yaprak eklemedigi icin
        // tavanla ilgisi yok.
        let dup = registry
            .register(default_domain(0, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("yinelenen kayit reddedilmeli");
        assert!(
            dup.contains("already registered"),
            "yinelenme, tavandan once denetlenmeli: {dup}"
        );
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
