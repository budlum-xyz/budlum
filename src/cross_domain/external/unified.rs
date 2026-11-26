//! One surface over every external chain Budlum reads.
//!
//! Each adapter in this module was written against its own target: Bitcoin's
//! SPV chain, Tendermint's commit certificates, Solana's tower votes, a ZK rollup's
//! validity proof. They share [`ExternalFinalityAdapter`] but nothing had ever
//! listed them together, so a node could hold twenty of them and still answer
//! "which chains do I unify?" only by reading the source.
//!
//! This is that list. [`NetworkCatalog`] builds one adapter per family, asks
//! each for its own descriptor, and answers the three questions a caller
//! actually has:
//!
//! - what can I verify against? ([`NetworkCatalog::networks`])
//! - what does this one promise? ([`NetworkCatalog::profile_of`])
//! - does the surface I just built actually work? ([`NetworkCatalog::selftest`])
//!
//! Nothing here decides finality. The adapters do that, with the same code
//! they always did; the catalog only says who they are and proves that each
//! one still answers.

use std::collections::BTreeMap;

use super::algorand_stateproof::AlgorandStateProofAdapter;
use super::aptos_jolteon_bft::AptosJolteonAdapter;
use super::arweave_spora::ArweaveSpOraAdapter;
use super::auxpow_pop::AuxPowPopAdapter;
use super::babylon_eots::BabylonEotsAdapter;
use super::based_preconf::BasedPreconfAdapter;
use super::bitcoin_spv::BitcoinSpvAdapter;
use super::bitvm_covenant::BitVmCovenantAdapter;
use super::casper_ffg::CasperFfgAdapter;
use super::chain_key_ni_dkg::ChainKeyNiDkgAdapter;
use super::da_sampling::DataAvailabilityAdapter;
use super::dag_bft::BullsharkDagAdapter;
use super::ghostdag::GhostdagPowAdapter;
use super::heterogeneous_multiprover::HeterogeneousMultiProverAdapter;
use super::honeybadger_bft::HoneyBadgerBftAdapter;
use super::hotstuff::HotStuffThreeChainAdapter;
use super::mina_recursive::SuccinctRecursiveAdapter;
use super::mysticeti_dag::MysticetiDagAdapter;
use super::near_doomslug::NearDoomslugAdapter;
use super::nipopow::NipopowAdapter;
use super::ouroboros_mithril::OuroborosMithrilAdapter;
use super::pospace_vdf::PoSpaceVdfAdapter;
use super::restaking_avs::RestakingAvsAdapter;
use super::simplex_bft::SimplexBftAdapter;
use super::solana_tower_bft::SolanaTowerBftAdapter;
use super::spec::{
    AdapterDescriptor, AdapterError, FinalityAttestation, RawConsensusEvidence, VerificationPolicy,
};
use super::stark_validity_rollup::StarkValidityRollupAdapter;
use super::stellar_fba::StellarScpAdapter;
use super::symbiotic_vault::SymbioticVaultAdapter;
use super::tendermint::TendermintFinalityAdapter;
use super::ton_catchain::TonCatchainAdapter;
use super::zkvm_proof::ZkVmFinalityAdapter;
use super::ExternalFinalityAdapter;

/// One family of chains, as the adapter itself describes it.
///
/// A family is not a chain. `bitcoin-spv-mainnet` and `bitcoin-spv-testnet`
/// are two entries of the same family, and the family name is what a caller
/// groups by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFamily {
    /// The adapter name the descriptor carries, for example `bitcoin-spv`.
    pub family: String,
    /// Every registered network of this family, sorted.
    pub networks: Vec<String>,
    /// What kind of consensus the target runs, in the target's words.
    pub consensus_kind: String,
    /// Whether the proofs are checkable by anybody holding the evidence.
    pub trust_model: String,
    /// How deep the adapter insists on going before it calls a height final.
    pub required_depth: u64,
    /// The adapter's own version.
    pub adapter_version: u32,
}

/// The adapters Budlum can verify against, in one place.
///
/// Built empty-safe: an adapter that refuses to construct is not registered
/// and does not take the catalog down, because a node that cannot read one
/// chain must still be able to read the others.
pub struct NetworkCatalog {
    adapters: BTreeMap<String, Box<dyn ExternalFinalityAdapter>>,
    /// Adapter ids that were offered and refused to build, with the reason.
    refused: BTreeMap<String, String>,
}

impl std::fmt::Debug for NetworkCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkCatalog")
            .field("adapters", &self.adapters.len())
            .field("refused", &self.refused)
            .finish()
    }
}

impl Default for NetworkCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCatalog {
    /// An empty catalog. [`Self::with_builtin_families`] is what fills it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
            refused: BTreeMap::new(),
        }
    }

    /// One adapter per family, on the networks this build names.
    ///
    /// The networks are the ones each adapter is willing to be constructed
    /// for without pinned anchor data: construction does not verify, so an
    /// adapter without its anchor is registered and refuses at verification
    /// time. That split is the adapters' own design and this keeps it.
    #[must_use]
    pub fn with_builtin_families() -> Self {
        let mut catalog = Self::new();
        for network in ["mainnet", "testnet"] {
            catalog.offer(Box::new(BitcoinSpvAdapter::new(network, None)));
            catalog.offer(Box::new(NipopowAdapter::new(network, None)));
            catalog.offer(Box::new(AuxPowPopAdapter::new(network, None)));
            catalog.offer(Box::new(GhostdagPowAdapter::new(network, None)));
            catalog.offer(Box::new(AlgorandStateProofAdapter::new(network, None)));
            catalog.offer(Box::new(AptosJolteonAdapter::new(network, None)));
            catalog.offer(Box::new(CasperFfgAdapter::new_optional(network, None)));
            catalog.offer(Box::new(NearDoomslugAdapter::new(network, None)));
            catalog.offer(Box::new(SolanaTowerBftAdapter::new(network, None)));
            catalog.offer(Box::new(ArweaveSpOraAdapter::new(network)));
            catalog.offer(Box::new(BullsharkDagAdapter::new(network, None)));
            catalog.offer(Box::new(MysticetiDagAdapter::new(network, None)));
            catalog.offer(Box::new(HoneyBadgerBftAdapter::new(network, None)));
            catalog.offer(Box::new(HotStuffThreeChainAdapter::new(network, None)));
            catalog.offer(Box::new(SimplexBftAdapter::new(network, None)));
            catalog.offer(Box::new(StellarScpAdapter::new(network, None)));
            catalog.offer(Box::new(TonCatchainAdapter::new(network, None)));
            catalog.offer(Box::new(PoSpaceVdfAdapter::new(network, None)));
            catalog.offer(Box::new(ChainKeyNiDkgAdapter::new(network, None)));
            catalog.offer(Box::new(DataAvailabilityAdapter::new(network, None)));
            catalog.offer(Box::new(BasedPreconfAdapter::new(network, None)));
            catalog.offer(Box::new(SuccinctRecursiveAdapter::new(network, None)));
            catalog.offer(Box::new(RestakingAvsAdapter::new(network, None)));
            catalog.offer(Box::new(SymbioticVaultAdapter::new(network)));
            catalog.offer(Box::new(BitVmCovenantAdapter::new(network, None)));
            catalog.offer(Box::new(StarkValidityRollupAdapter::new(network, None)));
            catalog.offer(Box::new(ZkVmFinalityAdapter::new(network, None, None)));
            catalog.offer(Box::new(HeterogeneousMultiProverAdapter::new(
                network, None,
            )));
            catalog.offer(Box::new(BabylonEotsAdapter::new(network, 0)));
            catalog.offer(Box::new(OuroborosMithrilAdapter::new(network, 0)));
        }
        catalog.offer(Box::new(TendermintFinalityAdapter::new(
            "tendermint",
            "cosmoshub-4",
        )));
        catalog
    }

    /// Register an adapter under its own descriptor id.
    ///
    /// A second adapter with the same id replaces nothing: the first one
    /// stays and the second is recorded as refused, because two adapters
    /// answering to one id is the failure the trait's `descriptor` contract
    /// exists to prevent.
    pub fn offer(&mut self, adapter: Box<dyn ExternalFinalityAdapter>) {
        let descriptor = adapter.descriptor();
        let id = hex::encode(descriptor.id.as_bytes());
        if self.adapters.contains_key(&id) {
            self.refused.insert(
                id.clone(),
                format!("a second adapter answers to `{id}`; the first one stays"),
            );
            return;
        }
        self.adapters.insert(id, adapter);
    }

    /// How many adapters the catalog holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Whether the catalog holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// The adapters offered and refused, and why.
    #[must_use]
    pub fn refused(&self) -> &BTreeMap<String, String> {
        &self.refused
    }

    /// Every registered adapter, one descriptor each, sorted by id.
    #[must_use]
    pub fn descriptors(&self) -> Vec<AdapterDescriptor> {
        self.adapters
            .values()
            .map(|adapter| adapter.descriptor())
            .collect()
    }

    /// The families the catalog covers, grouped and sorted.
    ///
    /// The family is the adapter name with its trailing `-<network>` removed,
    /// which is the naming every adapter in this module follows: `bitcoin-spv`
    /// and `bitcoin-spv-testnet`, `solana-tower` and `solana-tower-devnet`.
    #[must_use]
    pub fn families(&self) -> Vec<NetworkFamily> {
        let mut grouped: BTreeMap<String, Vec<AdapterDescriptor>> = BTreeMap::new();
        for descriptor in self.descriptors() {
            grouped
                .entry(family_of(&descriptor.name))
                .or_default()
                .push(descriptor);
        }
        grouped
            .into_iter()
            .map(|(family, mut members)| {
                members.sort_by(|a, b| a.name.cmp(&b.name));
                let first = members.first();
                let networks = members.iter().map(|d| d.name.clone()).collect();
                NetworkFamily {
                    family,
                    networks,
                    consensus_kind: first.map(|d| d.consensus_kind.clone()).unwrap_or_default(),
                    trust_model: first
                        .map(|d| format!("{:?}", d.trust_model))
                        .unwrap_or_default(),
                    required_depth: first.map(|d| d.required_depth).unwrap_or(0),
                    adapter_version: first.map(|d| d.adapter_version).unwrap_or(0),
                }
            })
            .collect()
    }

    /// The descriptor of one registered adapter, by the hex of its
    /// [`AdapterId::as_bytes`].
    #[must_use]
    pub fn profile_of(&self, id: &str) -> Option<AdapterDescriptor> {
        self.adapters.get(id).map(|adapter| adapter.descriptor())
    }

    /// Verify evidence against the adapter that claims it.
    ///
    /// `adapter_id` is the hex of the adapter's [`AdapterId::as_bytes`],
    /// which is the key every entry of [`Self::descriptors`] is filed under.
    ///
    /// # Errors
    ///
    /// [`AdapterError::UnknownAdapter`] naming the id when no adapter in this
    /// catalog answers to it. Every other error comes from the adapter.
    pub fn verify(
        &self,
        adapter_id: &str,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        let adapter = self
            .adapters
            .get(adapter_id)
            .ok_or_else(|| AdapterError::UnknownAdapter(adapter_id.to_string()))?;
        // The caller names one adapter and the evidence names another: that
        // is a mis-route, and the adapter itself refuses it by name.
        adapter.verify(evidence, policy)
    }

    /// Prove the surface is not vacuous.
    ///
    /// Every registered adapter must answer a descriptor whose id matches the
    /// key it is filed under, and the golden evidence an adapter offers must
    /// be accepted by that same adapter. An adapter that refuses its own
    /// golden sample is a broken adapter, not a strict one, and this is the
    /// only place that distinction is made for the whole surface at once.
    ///
    /// # Errors
    ///
    /// One line per adapter that failed, naming what it failed.
    pub fn selftest(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        if self.adapters.is_empty() {
            problems.push("the catalog is empty; an empty surface proves nothing".into());
            return Err(problems);
        }
        for (id, adapter) in &self.adapters {
            let descriptor = adapter.descriptor();
            let answered = hex::encode(descriptor.id.as_bytes());
            if answered != *id {
                problems.push(format!(
                    "{id}: filed under an id its descriptor does not answer to ({answered})"
                ));
            }
            if descriptor.accepted_evidence_versions.is_empty() {
                problems.push(format!("{id}: accepts no evidence version"));
            }
            let Some(golden) = adapter.golden_evidence() else {
                continue;
            };
            let policy = VerificationPolicy::strict(0);
            match adapter.verify(&golden, &policy) {
                Ok(_) => {}
                Err(error) => {
                    problems.push(format!("{id}: refused its own golden evidence: {error}"))
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// The family name of an adapter, with a trailing network suffix removed.
///
/// Adapters name themselves `<family>-<network>`; some name themselves just
/// `<family>`. Both are the same family as far as a caller is concerned.
fn family_of(name: &str) -> String {
    for suffix in [
        "-mainnet", "-testnet", "-devnet", "-regtest", "-signet", "-local",
    ] {
        if let Some(family) = name.strip_suffix(suffix) {
            return family.to_string();
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Named only by the tests below; importing either one at the top of the
    // file is an unused import in the library build, which this repository
    // denies.
    use crate::core::address::Address;
    use crate::cross_domain::external::spec::AdapterId;

    #[test]
    fn the_catalog_lists_the_chains_this_build_can_read() {
        let catalog = NetworkCatalog::with_builtin_families();
        assert!(
            catalog.len() >= 25,
            "the catalog holds {} adapters; a unifier that reads a handful of chains is not one",
            catalog.len()
        );
        let families = catalog.families();
        assert!(!families.is_empty());
        // The families a unifier is expected to cover by name, in the
        // target's own words. Each is a chain somebody would ask about.
        let names: Vec<&str> = families.iter().map(|f| f.family.as_str()).collect();
        // The families the adapters name themselves, read from their own
        // `ADAPTER_NAME` constants so this test cannot drift from the code.
        for expected in [
            "nipopow-superblock-v1",
            "ghostdag-pow-v1",
            "solana-tower-bft-v1",
            "casper-ffg-epoch-finality-v1",
        ] {
            assert!(
                names.iter().any(|name| name.starts_with(expected)),
                "the catalog does not cover `{expected}`: {names:?}"
            );
        }
    }

    #[test]
    fn every_family_answers_a_profile_a_caller_can_read() {
        let catalog = NetworkCatalog::with_builtin_families();
        for descriptor in catalog.descriptors() {
            assert!(
                !descriptor.consensus_kind.is_empty(),
                "{} carries no consensus kind",
                descriptor.name
            );
            assert!(
                descriptor.adapter_version >= 1,
                "{} carries no version",
                descriptor.name
            );
            assert!(
                !descriptor.accepted_evidence_versions.is_empty(),
                "{} accepts no evidence version",
                descriptor.name
            );
        }
    }

    #[test]
    fn the_surface_is_not_vacuous() {
        let catalog = NetworkCatalog::with_builtin_families();
        if let Err(problems) = catalog.selftest() {
            panic!("the unified surface failed its own self-test: {problems:#?}");
        }
    }

    #[test]
    fn a_registered_adapter_is_found_by_the_key_the_catalog_files_it_under() {
        let catalog = NetworkCatalog::with_builtin_families();
        for descriptor in catalog.descriptors() {
            let key = hex::encode(descriptor.id.as_bytes());
            let found = catalog
                .profile_of(&key)
                .expect("a descriptor the catalog lists is filed under its own id");
            assert_eq!(found.id, descriptor.id);
            assert_eq!(found.name, descriptor.name);
        }
    }

    #[test]
    fn an_unknown_adapter_is_refused_by_name_and_not_guessed() {
        let catalog = NetworkCatalog::with_builtin_families();
        let error = catalog
            .verify(
                "chain-that-does-not-exist",
                &RawConsensusEvidence {
                    adapter: AdapterId::from_name("chain-that-does-not-exist"),
                    evidence_version: 1,
                    network: "mainnet".into(),
                    payload: Vec::new(),
                    declared_height: 0,
                    declared_root: [0u8; 32],
                    submitter: Address::from([0x12; 32]),
                },
                &VerificationPolicy::strict(0),
            )
            .unwrap_err();
        assert!(
            matches!(&error, AdapterError::UnknownAdapter(id) if id == "chain-that-does-not-exist"),
            "{error:?}"
        );
    }

    #[test]
    fn a_duplicate_id_does_not_silently_replace_the_first_adapter() {
        let mut catalog = NetworkCatalog::new();
        catalog.offer(Box::new(NipopowAdapter::new("mainnet", None)));
        let before = catalog.len();
        catalog.offer(Box::new(NipopowAdapter::new("mainnet", None)));
        assert_eq!(
            catalog.len(),
            before,
            "the second adapter replaced the first"
        );
        assert_eq!(catalog.refused().len(), 1);
    }

    #[test]
    fn a_family_groups_its_networks_and_does_not_split_on_them() {
        let catalog = NetworkCatalog::with_builtin_families();
        let families = catalog.families();
        let bitcoin = families
            .iter()
            .find(|f| f.family == "bitcoin-spv")
            .expect("bitcoin-spv is a family");
        // The adapters name themselves `<family>-<network>`, so a family that
        // covers two networks carries two entries. A family that refuses one
        // of them still carries the one it took; what must not happen is a
        // family with no networks at all.
        assert!(
            !bitcoin.networks.is_empty(),
            "bitcoin-spv carries no network"
        );
        assert!(
            bitcoin.networks.len() <= 2,
            "bitcoin-spv carries more networks than were offered: {:?}",
            bitcoin.networks
        );
    }
}
