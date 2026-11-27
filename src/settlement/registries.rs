//! The settlement registries that are consensus state.
//!
//! Budlum settles the finality of other domains, and the registries that
//! record that work used to live on `Blockchain`, outside the account state:
//! written by operator RPCs on one node, persisted beside the chain, and in
//! no block root. Two nodes could disagree on
//! them while agreeing on every block.
//!
//! This struct is where they move. It is a field of `AccountState`, so it is
//! written only by block execution (the executor's transaction doors and the
//! block-end maintenance), rebuilt by block replay, carried whole in the
//! state snapshot, and folded into the state root through
//! [`SettlementRegistries::root`].
//! Each registry joins in the change that gives it a transaction door.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::IntakeState;
use crate::cross_domain::UniversalRelayer;
use crate::domain::{ConsensusDomainRegistry, DomainCommitmentRegistry, SovereignDomainRegistry};
use crate::object_layer::ObjectLayerRegistry;
use crate::prover::ProofClaimRegistry;
use crate::security::quantum_canary::CanaryBook;
use crate::settlement::global_block::GlobalHeaderWindow;
use serde::{Deserialize, Serialize};

/// The settlement registries, one field per registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SettlementRegistries {
    /// The external-domain intake: registrations, prover bonds, version
    /// policies, quorum rounds and accepted attestations. Written by the
    /// `ExternalDomain` transaction door; its clock is advanced at block end.
    pub external_intake: IntakeState,
    /// The consensus domains Budlum settles: genesis bootstrap domains and
    /// the ones registered by the `Settlement` door since.
    pub domains: ConsensusDomainRegistry,
    /// Every accepted domain commitment, applied or staged ahead of its
    /// domain's tip.
    pub commitments: DomainCommitmentRegistry,
    /// Sovereign templates bound to the domains they describe.
    pub sovereign: SovereignDomainRegistry,
    /// Accepted ZK proof claims, first valid claim per domain height.
    pub proof_claims: ProofClaimRegistry,
    /// The universal relayer: the pending relays bridge locks and burns
    /// enqueue, and the ledger of completed relays. Written by the `Bridge`
    /// door; swept at block end.
    pub relayer: UniversalRelayer,
    /// User intents, solver bids, explicit fee escrow and settlement rows.
    /// Written only by `SettlementTx::RelayerIntent`.
    #[serde(default)]
    pub relayer_policy: crate::relayer::RelayerPolicyRegistry,
    /// `AppBinding` applications, mirror payments, externally proven claims, and
    /// solver-intent bindings. Every write enters through `SettlementTx::AppBinding`.
    #[serde(default)]
    pub app_binding: crate::settlement::app_binding::AppBindingRegistry,
    /// Which chain-native assets have been declared to be the same asset.
    ///
    /// A unified balance is only as complete as this set: an asset nobody
    /// denominated cannot be summed (see
    /// [`crate::settlement::unified_balance`]), and an empty set means every
    /// balance stays per-asset and per-chain. Empty on a chain that never
    /// declared a denomination, so its presence changes no root until used.
    #[serde(default)]
    pub denominations: crate::settlement::universal_asset::DenominationIndex,
    /// Open all-or-nothing intent bundles, keyed by bundle id.
    ///
    /// A bundle binds legs that already exist as ordinary intents; it never
    /// opens one. Written only by `SettlementTx::Bundle`, and empty on a chain
    /// that never opened one, so its presence changes no root until used.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub bundles: std::collections::BTreeMap<[u8; 32], crate::relayer::bundle::IntentBundle>,
    /// The finality checkpoint headers: built by the transition of
    /// every checkpoint block from the state at its end.
    pub global_headers: GlobalHeaderWindow,
    /// Mikoriza: registrar contracts, restaked validators and the
    /// allocation events already used. Written only by
    /// `SettlementTx::SharedSecurity`; folded into the root once it holds
    /// anything.
    #[serde(default)]
    pub shared_security: crate::settlement::shared_security::SharedSecurityRegistry,
    /// The quantum canary book: pending commits and the solved
    /// canaries that drive the alarm. Written by the `CanaryCommit` and
    /// `CanaryReveal` doors; empty on a chain that never saw one, and then
    /// absent from the serialization and from the root.
    #[serde(default, skip_serializing_if = "CanaryBook::is_empty")]
    pub quantum: CanaryBook,
    /// The Universal Object Layer. Written only by
    /// `ObjectLayerTx`; closed on the testnet until its activation height.
    /// Empty: absent from the serialization and from the root.
    #[serde(default, skip_serializing_if = "ObjectLayerRegistry::is_empty")]
    pub object_layer: ObjectLayerRegistry,
}

impl SettlementRegistries {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no registry holds a record. An empty value stays out of the
    /// state root, like every other optional registry fold, so a chain that
    /// never used these registries keeps its pinned roots. The block clocks
    /// do not count: every node at a height holds the same clock value, so
    /// the clock alone carries nothing a root has to witness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.has_external_intake()
            && self.domains.is_empty()
            && self.commitments.is_empty()
            && self.sovereign.templates.is_empty()
            && self.proof_claims.is_empty()
            && self.relayer.is_empty()
            && self.relayer_policy.is_empty()
            && self.app_binding.is_empty()
            && self.global_headers.is_empty()
            && self.shared_security.is_empty()
            && self.quantum.is_empty()
            && self.object_layer.is_empty()
    }

    /// True when the external intake holds any record - including governance-
    /// pinned sync committees submitted before the first external domain
    /// registers. The block clock does not count, for the reason given at
    /// [`Self::is_empty`].
    #[must_use]
    pub fn has_external_intake(&self) -> bool {
        let intake = &self.external_intake;
        !(intake.entries.is_empty()
            && intake.registry.is_empty()
            && intake.quorum.policies.is_empty()
            && intake.quorum.rounds.is_empty()
            && intake.pinned_ethereum_committees.is_empty()
            && intake.pinned_bitcoin_anchors.is_empty()
            && intake.pinned_tendermint_anchors.is_empty()
            && intake.pinned_da_committees.is_empty()
            && intake.pinned_hotstuff_committees.is_empty()
            && intake.pinned_dag_committees.is_empty()
            && intake.pinned_casper_ffg_committees.is_empty()
            && intake.pinned_mysticeti_committees.is_empty()
            && intake.pinned_bitvm_anchors.is_empty())
    }

    /// Advance the registries' block clocks. Called once per block, at block
    /// end, by every path that applies a block (production, validation,
    /// replay), so every node sees the same clock at the same height.
    pub fn on_block_end(&mut self, height: u64) {
        self.external_intake.on_block_committed(height);
        self.relayer.sweep_retired(height);
    }

    /// The external intake's digest, for the RPC surface and the root below.
    ///
    /// # Errors
    ///
    /// The serializer's message when the intake cannot be encoded.
    pub fn external_intake_digest(&self) -> Result<[u8; 32], String> {
        self.external_intake.state_digest()
    }

    /// The fold of every registry's own root under one tag. A registry whose
    /// root cannot be computed folds a fixed marker instead of failing the
    /// block: the marker differs from every real digest, so a node that
    /// cannot encode its state cannot agree with one that can.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let intake = self
            .external_intake_digest()
            .unwrap_or_else(|_| hash_fields_bytes(&[b"BDLM_SETTLEMENT_UNENCODABLE_V1"]));
        let domains = self.domains.root();
        let progress = self.domains.progress_root();
        let commitments = self.commitments.root();
        let sovereign = self.sovereign.root();
        let proof_claims = self.proof_claims.root();
        let relayer = self.relayer.state_root();
        let relayer_policy = self.relayer_policy.root();
        let app_binding = self.app_binding.root();
        let headers = self.global_headers.root();
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_SETTLEMENT_REGISTRIES_V1",
            &intake,
            &domains,
            &progress,
            &commitments,
            &sovereign,
            &proof_claims,
            &relayer,
            &relayer_policy,
            &app_binding,
            &headers,
        ];
        // Mikoriza joins only once it holds something, like the canary book.
        let shared_security = self.shared_security.root();
        if !self.shared_security.is_empty() {
            fields.push(b"BDLM_SHARED_SECURITY_V1");
            fields.push(&shared_security);
        }
        // The canary book joins only once it holds something, so a chain that
        // never saw a canary transaction keeps its pinned roots.
        let quantum = self.quantum.state_root();
        if !self.quantum.is_empty() {
            fields.push(&quantum);
        }
        // The object layer joins only once it holds a record, so a chain that
        // never chartered a domain keeps its pinned roots.
        let object_layer = self.object_layer.root();
        if !self.object_layer.is_empty() {
            fields.push(b"BDLM_OBJECT_LAYER_V1");
            fields.push(&object_layer);
        }
        hash_fields_bytes(&fields)
    }

    /// Computes the canonical `ULP-1` binary `Poseidon` Merkle root over all
    /// active external domains that hold a verified commitment at their
    /// `last_committed_height`.
    ///
    /// Returns `None` when no active external domain holds a finalized
    /// commitment, matching the empty-gate convention of the other optional
    /// roots in [`crate::settlement::GlobalBlockHeader`].
    #[must_use]
    pub fn ulp_domains_root(&self) -> Option<[u8; 32]> {
        let snapshots = self.ulp_domain_snapshots();
        if snapshots.is_empty() {
            None
        } else {
            Some(crate::aggregation::universal_light_proof::ulp_domains_root(
                &snapshots,
            ))
        }
    }

    /// Derive the canonical three-bucket [`crate::settlement::GlobalFinalityCertificate`]
    /// for `checkpoint_height` strictly from on-chain settlement state.
    ///
    /// Guarantees are always re-derived from registered consensus domains and
    /// their observed cryptographic posture, never accepted from callers.
    /// Returns `None` when no consensus domain is registered (empty-gate rule).
    #[must_use]
    pub fn universal_finality_certificate(
        &self,
        checkpoint_height: u64,
    ) -> Option<crate::settlement::GlobalFinalityCertificate> {
        use crate::crypto::facts::QuantumClass;
        use crate::domain::types::DomainStatus;
        use crate::settlement::universal_finality::{
            compose, DomainFinalityEntry, FinalityGuarantee, FinalityPendingReason,
            FinalityVerdict, FINALITY_BINDS_ALL,
        };

        if self.domains.is_empty() {
            return None;
        }
        let all_commitments = self.commitments.commitments_for_global_block();
        let mut entries = Vec::new();
        for domain in self.domains.domains() {
            let pq_attested = matches!(
                self.domains.observed(domain.id).quantum_class(),
                Some(QuantumClass::Lattice | QuantumClass::Hash)
            );
            let guarantee = FinalityGuarantee::for_domain(&domain, pq_attested);
            let latest_commitment =
                if domain.last_committed_height > 0 && domain.last_committed_hash != [0u8; 32] {
                    all_commitments.iter().find(|c| {
                        c.domain_id == domain.id
                            && c.domain_height == domain.last_committed_height
                            && c.domain_block_hash == domain.last_committed_hash
                    })
                } else {
                    None
                };
            let (state_root, finality_proof_hash) = latest_commitment
                .map_or(([0u8; 32], [0u8; 32]), |c| {
                    (c.state_root, c.finality_proof_hash)
                });
            let verdict = match domain.status {
                DomainStatus::Frozen => FinalityVerdict::Refuted { code: 1 },
                DomainStatus::Retired => FinalityVerdict::Pending {
                    reason: FinalityPendingReason::RuleNotSatisfied,
                },
                DomainStatus::Active => match latest_commitment {
                    Some(c) if c.state_root != [0u8; 32] => {
                        if guarantee.attestation != FINALITY_BINDS_ALL {
                            FinalityVerdict::Pending {
                                reason: FinalityPendingReason::AttestationUnbound,
                            }
                        } else if guarantee.fault_tolerance_bps == 0 {
                            FinalityVerdict::Pending {
                                reason: FinalityPendingReason::RuleNotSatisfied,
                            }
                        } else {
                            FinalityVerdict::Established
                        }
                    }
                    _ => FinalityVerdict::Pending {
                        reason: FinalityPendingReason::EvidenceMissing,
                    },
                },
            };
            let guarantee_backing_hash = if domain.validator_set_hash != [0u8; 32] {
                domain.validator_set_hash
            } else {
                domain.config_hash
            };
            entries.push(DomainFinalityEntry {
                domain_id: domain.id,
                height: domain.last_committed_height,
                checkpoint_height,
                state_root,
                adapter_id: domain.finality_adapter.clone(),
                adapter_version: 1,
                finality_proof_hash,
                guarantee_backing_hash,
                bond_atoms: u128::from(domain.operator_bond),
                guarantee,
                verdict,
            });
        }
        match compose(&entries) {
            Ok(certificate) => Some(certificate),
            // Unreachable while this derivation holds its own preconditions:
            // the registry map cannot repeat a domain id, every row carries
            // the same checkpoint height, and Established is only assigned
            // after the exact checks compose re-applies. If a future compose
            // rule breaks that pairing, the header must fall back to carrying
            // no certificate (light clients then refuse) rather than a wrong
            // one - and debug builds must fail loudly instead of drifting.
            Err(err) => {
                debug_assert!(
                    false,
                    "state-derived finality certificate failed to compose: {err:?}"
                );
                None
            }
        }
    }

    /// Canonical Keccak-256 digest of the checkpoint
    /// [`crate::settlement::GlobalFinalityCertificate`], or `None` when no
    /// consensus domain is registered.
    #[must_use]
    pub fn finality_certificate_root(&self, checkpoint_height: u64) -> Option<[u8; 32]> {
        self.universal_finality_certificate(checkpoint_height)
            .map(|cert| cert.certificate_digest)
    }

    fn ulp_domain_snapshots(
        &self,
    ) -> Vec<crate::aggregation::universal_light_proof::UlpDomainSnapshot> {
        use crate::aggregation::universal_light_proof::UlpDomainSnapshot;
        use crate::crypto::facts::QuantumClass;

        if self.commitments.is_empty() || self.domains.is_empty() {
            return Vec::new();
        }
        let all_commitments = self.commitments.commitments_for_global_block();
        let mut snapshots = Vec::new();
        for domain in self.domains.active_domains() {
            if domain.id == 0
                || domain.last_committed_height == 0
                || domain.last_committed_hash == [0u8; 32]
            {
                continue;
            }
            let Some(kind) = ulp_domain_kind_for(domain) else {
                continue;
            };
            let Some(commitment) = all_commitments.iter().find(|c| {
                c.domain_id == domain.id
                    && c.domain_height == domain.last_committed_height
                    && c.domain_block_hash == domain.last_committed_hash
            }) else {
                continue;
            };
            if commitment.state_root == [0u8; 32] {
                continue;
            }
            let prev_height = all_commitments
                .iter()
                .filter(|c| {
                    c.domain_id == domain.id && c.domain_height < domain.last_committed_height
                })
                .map(|c| c.domain_height)
                .max()
                .unwrap_or(0);
            let anchor_hash = if domain.validator_set_hash != [0u8; 32] {
                domain.validator_set_hash
            } else {
                domain.config_hash
            };
            if anchor_hash == [0u8; 32] {
                continue;
            }
            let pow_weight = domain.pow_parameters.as_ref().map_or(0u64, |p| {
                u64::try_from(p.min_cumulative_work).unwrap_or(u64::MAX)
            });
            let security_weight = domain.operator_bond.max(pow_weight);
            if security_weight == 0 {
                continue;
            }
            let pq_attested = matches!(
                self.domains.observed(domain.id).quantum_class(),
                Some(QuantumClass::Lattice | QuantumClass::Hash)
            );
            let snapshot = UlpDomainSnapshot {
                domain_id: domain.id,
                external_chain_id: domain.domain_chain_id,
                kind,
                prev_height,
                finalized_height: domain.last_committed_height,
                state_root: commitment.state_root,
                event_root: commitment.event_root,
                anchor_hash,
                security_weight,
                pq_attested,
                outflow_bps: 0,
            };
            if snapshot.validate().is_ok() {
                snapshots.push(snapshot);
            }
        }
        snapshots
    }
}

fn ulp_domain_kind_for(
    domain: &crate::domain::types::ConsensusDomain,
) -> Option<crate::aggregation::universal_light_proof::UlpDomainKind> {
    use crate::aggregation::universal_light_proof::UlpDomainKind;
    use crate::domain::types::ConsensusKind;

    match &domain.kind {
        ConsensusKind::PoW => {
            if domain.finality_adapter == "auxpow-pop-v1" {
                Some(UlpDomainKind::AuxPowPop)
            } else {
                Some(UlpDomainKind::BitcoinSpv)
            }
        }
        ConsensusKind::PoS => Some(UlpDomainKind::EthereumSync),
        ConsensusKind::Bft | ConsensusKind::PoA => Some(UlpDomainKind::TendermintBft),
        ConsensusKind::Dag => Some(UlpDomainKind::DagBft),
        ConsensusKind::Pospace => Some(UlpDomainKind::PoSpaceVdf),
        ConsensusKind::Zk => Some(UlpDomainKind::ZkValidityRollup),
        ConsensusKind::Poh => Some(UlpDomainKind::SimplexBft),
        ConsensusKind::Custom(name) => match name.as_str() {
            "succinct-recursive" => Some(UlpDomainKind::SuccinctRecursive),
            "based-preconf" => Some(UlpDomainKind::BasedPreconf),
            "ton-catchain" => Some(UlpDomainKind::TonCatchain),
            "stellar-scp" => Some(UlpDomainKind::StellarScp),
            "restaking-avs" => Some(UlpDomainKind::RestakingAvs),
            "auxpow-pop" => Some(UlpDomainKind::AuxPowPop),
            "simplex-bft" => Some(UlpDomainKind::SimplexBft),
            "algorand-stateproof" => Some(UlpDomainKind::AlgorandStateProof),
            "tendermint" | "cometbft" => Some(UlpDomainKind::TendermintBft),
            "ethereum-sync" => Some(UlpDomainKind::EthereumSync),
            "bitcoin-spv" => Some(UlpDomainKind::BitcoinSpv),
            "dag-bft" | "mysticeti" => Some(UlpDomainKind::DagBft),
            "pospace-vdf" => Some(UlpDomainKind::PoSpaceVdf),
            "zk-validity-rollup" | "zkvm" => Some(UlpDomainKind::ZkValidityRollup),
            _ => None,
        },
        ConsensusKind::StorageAttestation(_) | ConsensusKind::AiInference => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_tick_alone_leaves_the_registries_empty() {
        let mut registries = SettlementRegistries::new();
        assert!(registries.is_empty());
        registries.on_block_end(5);
        assert!(registries.is_empty());
        assert_eq!(registries.external_intake.registry.height(), 5);
    }

    #[test]
    fn the_root_is_a_pure_function_of_the_registries() {
        let mut a = SettlementRegistries::new();
        let mut b = SettlementRegistries::new();
        a.on_block_end(3);
        b.on_block_end(3);
        assert_eq!(a.root(), b.root());
        b.on_block_end(4);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn object_layer_empty_registry_keeps_state_root() {
        let plain = SettlementRegistries::new();
        let mut with_params = SettlementRegistries::new();
        // Genesis parameters alone are not a record.
        with_params.object_layer.params.min_class_bond = 7;
        assert!(with_params.is_empty());
        assert_eq!(plain.root(), with_params.root());
        // And an empty registry stays out of the serialization.
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("object_layer"));
    }

    #[test]
    fn an_object_layer_record_changes_the_settlement_root() {
        use crate::object_layer::ObjectLayerRegistry;
        let mut registries = SettlementRegistries::new();
        let before = registries.root();
        registries.object_layer = ObjectLayerRegistry::default();
        registries.object_layer.departure_seq = 0;
        registries
            .object_layer
            .home_nonces
            .insert(crate::object_layer::HomeIdentity([1; 32]), 1);
        assert!(!registries.is_empty());
        assert_ne!(before, registries.root());
    }

    #[test]
    fn a_app_binding_registration_changes_the_settlement_root() {
        let mut registries = SettlementRegistries::new();
        let before = registries.root();
        registries
            .app_binding
            .register(7, b"app".to_vec(), [2u8; 32], 1)
            .expect("the test AppBinding row is valid");
        assert_ne!(before, registries.root());
    }

    #[test]
    fn pinned_external_committee_before_domain_registration_binds_state_root() {
        use crate::core::account::AccountState;
        use crate::cross_domain::external::ethereum::PinnedCommittee;

        let mut empty = AccountState::new();
        let empty_root = empty.state_root_body();
        assert!(!empty.settlement.has_external_intake());
        assert!(empty.settlement.is_empty());

        let mut pinned = AccountState::new();
        pinned
            .settlement
            .external_intake
            .pinned_ethereum_committees
            .insert(
                "ethereum-mainnet".into(),
                PinnedCommittee {
                    period: 1_024,
                    aggregate_pubkey: vec![0x33; 48],
                    next_committee_root: [0x34; 32],
                },
            );
        assert!(pinned.settlement.has_external_intake());
        assert!(!pinned.settlement.is_empty());
        assert_ne!(pinned.state_root_body(), empty_root);
    }

    #[test]
    fn ulp_domains_root_folds_active_committed_domains_and_skips_uncommitted_or_frozen() {
        use crate::aggregation::universal_light_proof::{
            ulp_domains_root, UlpDomainKind, UlpDomainSnapshot,
        };
        use crate::core::address::Address;
        use crate::crypto::facts::{AssumptionClass, CryptoFacts, ObservedScheme};
        use crate::domain::types::{
            ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
        };

        let mut registries = SettlementRegistries::new();
        assert_eq!(registries.ulp_domains_root(), None);

        let dom = ConsensusDomain {
            id: 7,
            kind: ConsensusKind::Bft,
            status: DomainStatus::Active,
            domain_chain_id: 7_007,
            operator: Some(Address::from([1u8; 32])),
            operator_bond: crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
            config_hash: [0xAA; 32],
            validator_set_hash: [0xBB; 32],
            finality_adapter: "tendermint-v1".into(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: 15,
            last_committed_hash: [0x15; 32],
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
            genesis_state_root: [0u8; 32],
        };
        registries
            .domains
            .restore_persisted(dom.clone())
            .expect("register active BFT domain");
        // Without a matching DomainCommitment in `commitments`, `ulp_domains_root` stays `None`.
        assert_eq!(registries.ulp_domains_root(), None);

        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
        registries.domains.record_observed(7, &facts);

        let c10 = DomainCommitment {
            domain_id: 7,
            domain_height: 10,
            domain_block_hash: [0x10; 32],
            parent_domain_block_hash: [0x09; 32],
            state_root: [0x20; 32],
            tx_root: [0x21; 32],
            event_root: [0x22; 32],
            finality_proof_hash: [0x23; 32],
            consensus_kind: ConsensusKind::Bft,
            validator_set_hash: [0xBB; 32],
            timestamp_ms: 1_000,
            sequence: 1,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        let c15 = DomainCommitment {
            domain_height: 15,
            domain_block_hash: [0x15; 32],
            parent_domain_block_hash: [0x10; 32],
            state_root: [0x30; 32],
            event_root: [0x32; 32],
            sequence: 2,
            ..c10.clone()
        };
        registries.commitments.insert(c10).expect("insert h=10");
        registries.commitments.insert(c15).expect("insert h=15");

        let expected = ulp_domains_root(&[UlpDomainSnapshot {
            domain_id: 7,
            external_chain_id: 7_007,
            kind: UlpDomainKind::TendermintBft,
            prev_height: 10,
            finalized_height: 15,
            state_root: [0x30; 32],
            event_root: [0x32; 32],
            anchor_hash: [0xBB; 32],
            security_weight: dom.operator_bond,
            pq_attested: true,
            outflow_bps: 0,
        }]);
        assert_eq!(registries.ulp_domains_root(), Some(expected));

        // Freezing the domain excludes it from active ULP-1 settlement roots.
        registries
            .domains
            .set_status(7, DomainStatus::Frozen)
            .expect("freeze domain");
        assert_eq!(registries.ulp_domains_root(), None);
    }

    #[test]
    fn universal_finality_certificate_derives_three_buckets_from_consensus_state() {
        use crate::core::address::Address;
        use crate::crypto::facts::{AssumptionClass, CryptoFacts, ObservedScheme};
        use crate::domain::types::{
            ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
        };
        use crate::settlement::{FinalityBucket, FinalityPendingReason, FinalityVerdict};

        let mut registries = SettlementRegistries::new();
        assert_eq!(registries.finality_certificate_root(100), None);
        assert_eq!(registries.universal_finality_certificate(100), None);

        // Baseline guarantees only certify kinds whose registered adapter
        // attests the full commitment set; a bare BFT registration binds
        // nothing until a verified proof says otherwise, so the Established
        // row uses an attestation-complete kind on purpose.
        let make_domain =
            |id: u32, kind: ConsensusKind, status: DomainStatus, last_h: u64| ConsensusDomain {
                id,
                kind,
                status,
                domain_chain_id: 7_000 + u64::from(id),
                operator: Some(Address::from([1u8; 32])),
                operator_bond: crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
                config_hash: [0xAA; 32],
                validator_set_hash: [0xBB; 32],
                finality_adapter: "tendermint-v1".into(),
                min_confirmations: 1,
                bridge_enabled: true,
                block_hash_scheme: RootScheme::Sha256,
                state_root_scheme: RootScheme::Sha256,
                tx_root_scheme: RootScheme::Sha256,
                last_committed_height: last_h,
                last_committed_hash: if last_h > 0 { [0x15; 32] } else { [0u8; 32] },
                pow_parameters: None,
                zk_program_allowlist: Vec::new(),
                plugin_code_hash: None,
                genesis_state_root: [0u8; 32],
            };

        registries
            .domains
            .restore_persisted(make_domain(
                1,
                ConsensusKind::AiInference,
                DomainStatus::Active,
                15,
            ))
            .expect("register domain 1");
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
        registries.domains.record_observed(1, &facts);
        registries
            .commitments
            .insert(DomainCommitment {
                domain_id: 1,
                domain_height: 15,
                domain_block_hash: [0x15; 32],
                parent_domain_block_hash: [0x14; 32],
                state_root: [0x30; 32],
                tx_root: [0x31; 32],
                event_root: [0x32; 32],
                finality_proof_hash: [0x33; 32],
                consensus_kind: ConsensusKind::AiInference,
                validator_set_hash: [0xBB; 32],
                timestamp_ms: 1_000,
                sequence: 1,
                producer: None,
                state_updates: std::collections::BTreeMap::new(),
            })
            .expect("insert commitment for domain 1");

        registries
            .domains
            .restore_persisted(make_domain(2, ConsensusKind::Bft, DomainStatus::Active, 0))
            .expect("register domain 2");

        registries
            .domains
            .restore_persisted(make_domain(3, ConsensusKind::Bft, DomainStatus::Frozen, 0))
            .expect("register domain 3");

        let cert = registries
            .universal_finality_certificate(100)
            .expect("certificate must be built");
        assert_eq!(
            registries.finality_certificate_root(100),
            Some(cert.certificate_digest)
        );
        assert_eq!(cert.established_count, 1);
        assert_eq!(cert.pending_count, 1);
        assert_eq!(cert.refuted_count, 1);
        assert_eq!(cert.verify_integrity(), Ok(()));

        let p1 = cert.prove_domain(1).expect("proof for domain 1");
        assert_eq!(p1.bucket, FinalityBucket::Established);
        assert_eq!(p1.entry.verdict, FinalityVerdict::Established);
        assert!(p1.verify(&cert.established_root));

        let p2 = cert.prove_domain(2).expect("proof for domain 2");
        assert_eq!(p2.bucket, FinalityBucket::Pending);
        assert_eq!(
            p2.entry.verdict,
            FinalityVerdict::Pending {
                reason: FinalityPendingReason::EvidenceMissing,
            }
        );
        assert!(p2.verify(&cert.pending_root));

        let p3 = cert.prove_domain(3).expect("proof for domain 3");
        assert_eq!(p3.bucket, FinalityBucket::Refuted);
        assert_eq!(p3.entry.verdict, FinalityVerdict::Refuted { code: 1 });
        assert!(p3.verify(&cert.refuted_root));
    }
}
