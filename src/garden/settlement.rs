//! The link between a Garden chain and Budlum.
//!
//! A Garden registers as a sovereign `PoA` domain in Budlum's domain registry
//! and reports its finality through the existing `PoA` finality adapter. There
//! is no bridge: the domain is registered with `bridge_enabled = false`, so
//! nothing of value on Budlum depends on it.
//!
//! The Garden status is visible on Budlum as the domain status: Active while
//! the chain runs, Frozen while it stands still, Retired when it is over.

use super::types::{garden_domain_id, GardenCommit, GardenGenesis, GardenKey};
use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::domain::finality_adapter::{
    hash_finality_proof, poa_authority_set_hash, FinalityProof, PoAAuthoritySignature,
};
use crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainId, DomainStatus, Hash32, RootScheme,
    VerifiedDomainCommitment,
};

/// The finality adapter a Garden domain registers with.
const GARDEN_FINALITY_ADAPTER: &str = "poa-authority-quorum";

/// The Budlum domain record of a Garden.
///
/// `operator_bond` is the registry's declared minimum. The registry records
/// that number and never debits it, and a Garden mints and locks nothing.
fn domain_record(
    genesis: &GardenGenesis,
    operator: GardenKey,
    validator_set_hash: Hash32,
) -> ConsensusDomain {
    ConsensusDomain {
        id: garden_domain_id(genesis.chain_id),
        kind: ConsensusKind::PoA,
        status: DomainStatus::Active,
        domain_chain_id: genesis.chain_id,
        operator: Some(Address(operator)),
        operator_bond: MIN_DOMAIN_OPERATOR_BOND,
        config_hash: genesis.hash(),
        validator_set_hash,
        finality_adapter: GARDEN_FINALITY_ADAPTER.to_string(),
        min_confirmations: 1,
        bridge_enabled: false,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 0,
        last_committed_hash: genesis.hash(),
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: genesis.hash(),
    }
}

/// The hash of an authority set, in the form Budlum's `PoA` adapter derives it.
pub fn authority_set_hash(chain_id: u64, authorities: &[GardenKey]) -> Result<Hash32, String> {
    // The derivation reads only the domain id of the record it is given.
    let probe = ConsensusDomain {
        id: garden_domain_id(chain_id),
        kind: ConsensusKind::PoA,
        status: DomainStatus::Active,
        domain_chain_id: chain_id,
        operator: None,
        operator_bond: 0,
        config_hash: [0u8; 32],
        validator_set_hash: [0u8; 32],
        finality_adapter: GARDEN_FINALITY_ADAPTER.to_string(),
        min_confirmations: 1,
        bridge_enabled: false,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 0,
        last_committed_hash: [0u8; 32],
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0u8; 32],
    };
    let addresses: Vec<Address> = authorities.iter().map(|key| Address(*key)).collect();
    poa_authority_set_hash(&probe, &addresses).map_err(|e| e.to_string())
}

/// Build a [`crate::settlement::domains::ClosedGardenSettlement`] envelope from
/// a closed Garden's genesis parameters, final authority electorate, and final
/// quorum-signed commitment so Budlum can anchor and retire the Garden's final
/// state root in block.
pub fn closing_settlement_from_parts(
    domain_chain_id: u64,
    genesis_hash: Hash32,
    operator: Address,
    final_commitment: VerifiedDomainCommitment,
) -> Result<crate::settlement::domains::ClosedGardenSettlement, String> {
    super::types::verify_garden_execution_chain(domain_chain_id)?;
    if genesis_hash == [0u8; 32] {
        return Err("Garden genesis_hash cannot be zero".into());
    }
    if operator == Address::zero() {
        return Err("Garden operator cannot be the zero address".into());
    }
    let expected_domain_id = garden_domain_id(domain_chain_id);
    if final_commitment.commitment.domain_id != expected_domain_id {
        return Err(format!(
            "Garden commitment domain_id {} does not match derived id {expected_domain_id}",
            final_commitment.commitment.domain_id
        ));
    }
    if final_commitment.commitment.domain_height == 0 {
        return Err("Closed Garden final commitment height must be >= 1".into());
    }
    if final_commitment.commitment.consensus_kind != ConsensusKind::PoA {
        return Err("Garden closing commitment must use ConsensusKind::PoA".into());
    }
    if final_commitment.commitment.validator_set_hash == [0u8; 32] {
        return Err("Garden closing commitment validator_set_hash cannot be zero".into());
    }
    Ok(crate::settlement::domains::ClosedGardenSettlement {
        domain_chain_id,
        genesis_hash,
        operator,
        final_commitment,
    })
}

#[cfg(test)]
fn closing_settlement(
    genesis: &GardenGenesis,
    operator: GardenKey,
    electorate: &[GardenKey],
    final_commit: &GardenCommit,
) -> Result<crate::settlement::domains::ClosedGardenSettlement, String> {
    if final_commit.block.header.chain_id != genesis.chain_id {
        return Err("Garden final commit chain_id does not match genesis".into());
    }
    let verified = verified_commitment(electorate, final_commit)?;
    closing_settlement_from_parts(
        genesis.chain_id,
        genesis.hash(),
        Address(operator),
        verified,
    )
}

/// Turn a finalized Garden block into the payload Budlum verifies.
///
/// The proof carries the electorate of the block and the votes as they were
/// signed: a Garden vote is a Budlum `PoA` commit signature.
fn verified_commitment(
    electorate: &[GardenKey],
    commit: &GardenCommit,
) -> Result<VerifiedDomainCommitment, String> {
    let authorities: Vec<Address> = electorate.iter().map(|key| Address(*key)).collect();
    let signatures = commit
        .votes
        .iter()
        .map(|vote| PoAAuthoritySignature {
            authority: Address(vote.voter),
            signature: vote.signature.clone(),
        })
        .collect();
    let proof = FinalityProof::PoA {
        authorities,
        signatures,
    };
    let mut commitment = commit.block.header.commitment();
    commitment.finality_proof_hash = hash_finality_proof(&proof).map_err(|e| e.to_string())?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// What the node's Budlum chain says about a Garden domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenDomainView {
    pub domain_id: DomainId,
    pub config_hash: Hash32,
    pub status: DomainStatus,
    pub last_committed_height: u64,
    pub last_committed_hash: Hash32,
}

/// The handle through which a Garden node talks to its Budlum chain.
#[derive(Clone)]
pub struct GardenBudlumLink {
    chain: ChainHandle,
}

impl GardenBudlumLink {
    pub const fn new(chain: ChainHandle) -> Self {
        Self { chain }
    }

    /// Register the Garden as a domain on this node's Budlum chain.
    pub async fn register(
        &self,
        genesis: &GardenGenesis,
        operator: GardenKey,
    ) -> Result<(), String> {
        let hash = authority_set_hash(genesis.chain_id, &[genesis.host])?;
        self.chain
            .register_garden_domain(domain_record(genesis, operator, hash))
            .await
    }

    /// Report one finalized Garden block to Budlum.
    ///
    /// The registered authority set is moved to the electorate of the block
    /// first, then the commitment goes through Budlum's own `PoA` verification.
    pub async fn report(
        &self,
        operator: GardenKey,
        electorate: &[GardenKey],
        commit: &GardenCommit,
    ) -> Result<(), String> {
        let domain_id = garden_domain_id(commit.block.header.chain_id);
        self.chain
            .rotate_bridgeless_poa_authority_set(
                domain_id,
                Address(operator),
                commit.block.header.authority_set_hash,
            )
            .await?;
        self.chain
            .submit_verified_garden_commitment(verified_commitment(electorate, commit)?)
            .await
    }

    /// Move the Garden domain to `next` on this node's Budlum chain.
    pub async fn move_domain(
        &self,
        chain_id: u64,
        operator: GardenKey,
        next: DomainStatus,
    ) -> Result<(), String> {
        self.chain
            .transition_bridgeless_poa_domain_status(
                garden_domain_id(chain_id),
                Address(operator),
                next,
            )
            .await
    }

    /// End the Garden domain on this node's Budlum chain. The lifecycle has
    /// no direct step from Active to Retired, so an active domain is frozen
    /// first.
    pub async fn retire(&self, chain_id: u64, operator: GardenKey) -> Result<(), String> {
        self.move_domain(chain_id, operator, DomainStatus::Frozen)
            .await?;
        self.move_domain(chain_id, operator, DomainStatus::Retired)
            .await
    }

    /// The Garden domain as this node's Budlum chain records it.
    ///
    /// Matches on the full Garden identity (`domain_chain_id`, `PoA` kind,
    /// bridgeless flag and Garden finality adapter), never the 31-bit derived
    /// `domain_id` alone, so a hash collision with another Garden cannot adopt
    /// or quarantine the wrong local record.
    #[cfg(test)]
    pub async fn view(&self, chain_id: u64) -> Option<GardenDomainView> {
        self.view_matching(chain_id, None).await
    }

    /// Look up this Garden's local record on Budlum, binding `domain_chain_id`,
    /// `PoA` kind, bridgeless flag, finality adapter, and `config_hash` to
    /// `genesis_hash`.
    pub async fn view_for_genesis(
        &self,
        chain_id: u64,
        genesis_hash: Hash32,
    ) -> Option<GardenDomainView> {
        self.view_matching(chain_id, Some(genesis_hash)).await
    }

    async fn view_matching(
        &self,
        chain_id: u64,
        genesis_hash: Option<Hash32>,
    ) -> Option<GardenDomainView> {
        let domain_id = garden_domain_id(chain_id);
        self.chain
            .get_consensus_domains_with_garden()
            .await
            .into_iter()
            .find(|domain| {
                domain.id == domain_id
                    && domain.domain_chain_id == chain_id
                    && domain.kind == ConsensusKind::PoA
                    && !domain.bridge_enabled
                    && domain.finality_adapter == GARDEN_FINALITY_ADAPTER
                    && genesis_hash.is_none_or(|expected| domain.config_hash == expected)
            })
            .map(|domain| GardenDomainView {
                domain_id,
                config_hash: domain.config_hash,
                status: domain.status,
                last_committed_height: domain.last_committed_height,
                last_committed_hash: domain.last_committed_hash,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::Net;
    use super::super::types::GardenTxKind;
    use super::*;
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::chain_config::Network;

    fn budlum() -> Blockchain {
        Blockchain::new(
            std::sync::Arc::new(PoWEngine::new(2)),
            None,
            Network::Devnet.chain_id().value(),
            None,
        )
    }

    /// Register the Garden of `net` on `chain`, operated by the host.
    fn register(chain: &mut Blockchain, net: &Net) -> DomainId {
        let genesis = &net.ledger.state.genesis;
        let hash = authority_set_hash(genesis.chain_id, &[genesis.host]).unwrap();
        chain
            .register_garden_domain(domain_record(genesis, net.host, hash))
            .unwrap();
        garden_domain_id(genesis.chain_id)
    }

    /// Report the Garden block at `height` the way `GardenBudlumLink::report`
    /// does it: follow the electorate, then hand over the `PoA` proof.
    fn report(chain: &mut Blockchain, net: &Net, height: u64) -> Result<(), String> {
        let (commit, electorate) = net.ledger.commit_at(height).ok_or("no such block")?;
        chain.rotate_bridgeless_poa_authority_set(
            garden_domain_id(commit.block.header.chain_id),
            Address(net.host),
            commit.block.header.authority_set_hash,
        )?;
        let verified = verified_commitment(electorate, commit)?;
        chain.submit_verified_garden_commitment(verified.commitment, verified.proof)
    }

    #[test]
    fn garden_finality_is_accepted_by_the_budlum_poa_adapter_as_members_change() {
        let mut net = Net::new();
        let mut chain = budlum();
        let root_before = chain.state.calculate_state_root();
        let domain_id = register(&mut chain, &net);
        let a = net.join("a");
        let b = net.join("b");
        net.commit(vec![net.publish(&a, 1)]).unwrap();
        net.commit(vec![net.tx(&b, GardenTxKind::Leave)]).unwrap();
        net.commit(vec![net.publish(&a, 2)]).unwrap();
        for height in 1..=net.ledger.state.height {
            report(&mut chain, &net, height).unwrap();
            let domain = chain.garden_domains.get(domain_id).unwrap();
            let (commit, _) = net.ledger.commit_at(height).unwrap();
            assert_eq!(domain.last_committed_height, height);
            assert_eq!(domain.last_committed_hash, commit.block.header.hash());
            assert_eq!(
                domain.validator_set_hash,
                commit.block.header.authority_set_hash
            );
        }
        let domain = chain.garden_domains.get(domain_id).unwrap();
        assert_eq!(domain.status, DomainStatus::Active);
        assert!(!domain.bridge_enabled);
        assert_eq!(domain.kind, ConsensusKind::PoA);
        // Node-local Garden writes never alter the settlement chain state root.
        assert_eq!(chain.state.calculate_state_root(), root_before);
        assert!(chain.state.settlement.domains.get(domain_id).is_none());
    }

    #[test]
    fn garden_block_without_the_quorum_is_refused_by_budlum() {
        let mut net = Net::new();
        let mut chain = budlum();
        let domain_id = register(&mut chain, &net);
        let a = net.join("a");
        net.join("b");
        net.join("c");
        report(&mut chain, &net, 1).unwrap();
        report(&mut chain, &net, 2).unwrap();
        report(&mut chain, &net, 3).unwrap();
        net.commit(vec![net.publish(&a, 1)]).unwrap();

        let (commit, electorate) = net.ledger.commit_at(4).unwrap();
        let mut thin = commit.clone();
        thin.votes.truncate(2);
        chain
            .rotate_bridgeless_poa_authority_set(
                domain_id,
                Address(net.host),
                commit.block.header.authority_set_hash,
            )
            .unwrap();
        let before = chain.garden_domains.get(domain_id).unwrap().clone();
        let verified = verified_commitment(electorate, &thin).unwrap();
        let refusal = chain
            .submit_verified_garden_commitment(verified.commitment, verified.proof)
            .unwrap_err();
        assert!(refusal.contains("required=3, observed=2"), "{refusal}");
        assert_eq!(chain.garden_domains.get(domain_id).unwrap(), &before);

        // A proof that names a smaller electorate than the registered one
        // does not pass either: the adapter recomputes the set hash.
        let small: Vec<GardenKey> = thin.votes.iter().map(|vote| vote.voter).collect();
        let verified = verified_commitment(&small, &thin).unwrap();
        assert!(chain
            .submit_verified_garden_commitment(verified.commitment, verified.proof)
            .is_err());
        assert_eq!(chain.garden_domains.get(domain_id).unwrap(), &before);

        report(&mut chain, &net, 4).unwrap();
    }

    #[test]
    fn garden_domain_changes_only_through_its_operator() {
        let mut net = Net::new();
        let mut chain = budlum();
        let domain_id = register(&mut chain, &net);
        let stranger = net.join("a");
        let before = chain.garden_domains.get(domain_id).unwrap().clone();

        let refusal = chain
            .rotate_bridgeless_poa_authority_set(domain_id, Address(stranger), [7u8; 32])
            .unwrap_err();
        assert!(refusal.contains("not operated by the caller"), "{refusal}");
        let refusal = chain
            .transition_bridgeless_poa_domain_status(
                domain_id,
                Address(stranger),
                DomainStatus::Frozen,
            )
            .unwrap_err();
        assert!(refusal.contains("not operated by the caller"), "{refusal}");
        let refusal = chain
            .rotate_bridgeless_poa_authority_set(domain_id, Address(net.host), [0u8; 32])
            .unwrap_err();
        assert!(refusal.contains("zero"), "{refusal}");
        let refusal = chain
            .rotate_bridgeless_poa_authority_set(domain_id + 1, Address(net.host), [7u8; 32])
            .unwrap_err();
        assert!(refusal.contains("Unknown consensus domain"), "{refusal}");
        assert_eq!(chain.garden_domains.get(domain_id).unwrap(), &before);
    }

    #[test]
    fn garden_operator_entry_points_refuse_a_bridge_domain() {
        let net = Net::new();
        let mut chain = budlum();
        let genesis = &net.ledger.state.genesis;
        let hash = authority_set_hash(genesis.chain_id, &[genesis.host]).unwrap();
        let mut bridged = domain_record(genesis, net.host, hash);
        bridged.id = 99;
        bridged.bridge_enabled = true;
        let domain_id = bridged.id;
        chain.register_consensus_domain(bridged).unwrap();
        let before = chain
            .state
            .settlement
            .domains
            .get(domain_id)
            .unwrap()
            .clone();

        let refusal = chain
            .rotate_bridgeless_poa_authority_set(domain_id, Address(net.host), [7u8; 32])
            .unwrap_err();
        assert!(refusal.contains("bridge-enabled"), "{refusal}");
        let refusal = chain
            .transition_bridgeless_poa_domain_status(
                domain_id,
                Address(net.host),
                DomainStatus::Frozen,
            )
            .unwrap_err();
        assert!(refusal.contains("bridge-enabled"), "{refusal}");
        assert_eq!(
            chain.state.settlement.domains.get(domain_id).unwrap(),
            &before
        );
    }

    #[test]
    fn garden_status_on_budlum_follows_active_frozen_retired() {
        let mut net = Net::new();
        let mut chain = budlum();
        let root_before = chain.state.calculate_state_root();
        let domain_id = register(&mut chain, &net);
        let host = Address(net.host);
        let a = net.join("a");
        report(&mut chain, &net, 1).unwrap();
        let status = |chain: &Blockchain| chain.garden_domains.get(domain_id).unwrap().status;

        let refusal = chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Retired)
            .unwrap_err();
        assert!(refusal.contains("Illegal domain lifecycle"), "{refusal}");
        assert_eq!(status(&chain), DomainStatus::Active);

        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Frozen)
            .unwrap();
        assert_eq!(status(&chain), DomainStatus::Frozen);
        // Budlum takes no Garden block while the domain is frozen.
        net.commit(vec![net.publish(&a, 1)]).unwrap();
        assert!(report(&mut chain, &net, 2).is_err());
        assert_eq!(
            chain
                .garden_domains
                .get(domain_id)
                .unwrap()
                .last_committed_height,
            1
        );

        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Active)
            .unwrap();
        report(&mut chain, &net, 2).unwrap();

        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Frozen)
            .unwrap();
        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Retired)
            .unwrap();
        assert_eq!(status(&chain), DomainStatus::Retired);
        for next in [DomainStatus::Active, DomainStatus::Frozen] {
            assert!(chain
                .transition_bridgeless_poa_domain_status(domain_id, host, next)
                .is_err());
        }
        let refusal = chain
            .rotate_bridgeless_poa_authority_set(domain_id, host, [7u8; 32])
            .unwrap_err();
        assert!(refusal.contains("retired"), "{refusal}");
        assert_eq!(status(&chain), DomainStatus::Retired);
        assert_eq!(chain.state.calculate_state_root(), root_before);
    }

    #[test]
    fn garden_fork_seen_by_budlum_cannot_be_reactivated_by_the_operator() {
        let mut net = Net::new();
        let mut chain = budlum();
        let root_before = chain.state.calculate_state_root();
        let domain_id = register(&mut chain, &net);
        let host = Address(net.host);
        let token = net.tx(&net.host, GardenTxKind::Leave);
        // Two different first blocks, both signed by the host alone.
        let mut other = Net {
            ledger: net.ledger.clone(),
            keys: net.keys.clone(),
            host: net.host,
            clock: net.clock + 500,
        };
        net.join("a");
        other.commit(vec![token]).unwrap();
        report(&mut chain, &net, 1).unwrap();
        assert!(report(&mut chain, &other, 1).is_err());
        assert_eq!(
            chain.garden_domains.get(domain_id).unwrap().status,
            DomainStatus::Frozen
        );
        let refusal = chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Active)
            .unwrap_err();
        assert!(refusal.contains("quarantined"), "{refusal}");
        assert_eq!(
            chain.garden_domains.get(domain_id).unwrap().status,
            DomainStatus::Frozen
        );
        assert_eq!(chain.state.calculate_state_root(), root_before);
    }

    #[test]
    fn garden_retire_prunes_retained_commitments_and_garden_record_wins_merge() {
        let mut net = Net::new();
        let mut chain = budlum();
        let domain_id = register(&mut chain, &net);
        let a = net.join("a");
        net.commit(vec![net.publish(&a, 1)]).unwrap();
        for height in 1..=net.ledger.state.height {
            report(&mut chain, &net, height).unwrap();
        }
        assert_eq!(chain.garden_commitments.len(), 2);
        // Local Garden record appears in `consensus_domains_with_garden` and is
        // never duplicated or shadowed by canonical state.
        let merged = chain.consensus_domains_with_garden();
        assert_eq!(merged.iter().filter(|d| d.id == domain_id).count(), 1);
        // Retiring the Garden drains its retained local commitments.
        let host = Address(net.host);
        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Frozen)
            .unwrap();
        chain
            .transition_bridgeless_poa_domain_status(domain_id, host, DomainStatus::Retired)
            .unwrap();
        assert_eq!(chain.garden_commitments.len(), 0);
    }

    #[tokio::test]
    async fn garden_budlum_link_view_rejects_colliding_chain_or_genesis_record() {
        use crate::chain::chain_actor::ChainActor;

        let net = Net::new();
        let chain_id = net.ledger.state.chain_id();
        let domain_id = garden_domain_id(chain_id);
        let mut bc = budlum();
        // Plant a colliding local Garden record under the same 31-bit
        // `domain_id` but a different 64-bit `domain_chain_id`.
        let mut foreign = domain_record(
            &net.ledger.state.genesis,
            net.host,
            authority_set_hash(chain_id, &net.ledger.state.active()).unwrap(),
        );
        foreign.id = domain_id;
        foreign.domain_chain_id = chain_id.wrapping_add(1);
        bc.register_garden_domain(foreign).unwrap();
        let (actor, handle) = ChainActor::new(bc);
        tokio::spawn(async move {
            actor.run().await;
        });
        let link = GardenBudlumLink::new(handle);
        assert!(
            link.view(chain_id).await.is_none(),
            "view() must refuse a domain record whose domain_chain_id differs"
        );

        // Matching chain_id succeeds for view(), and view_for_genesis() also
        // checks `config_hash == genesis.hash()`.
        let (actor2, handle2) = ChainActor::new(budlum());
        tokio::spawn(async move {
            actor2.run().await;
        });
        let link2 = GardenBudlumLink::new(handle2);
        link2
            .register(&net.ledger.state.genesis, net.host)
            .await
            .unwrap();
        assert!(link2.view(chain_id).await.is_some());
        assert!(link2
            .view_for_genesis(chain_id, net.ledger.state.genesis.hash())
            .await
            .is_some());
        assert!(
            link2
                .view_for_genesis(chain_id, [0xabu8; 32])
                .await
                .is_none(),
            "view_for_genesis() must refuse a record with another genesis hash"
        );
    }

    #[test]
    fn closed_garden_final_commit_anchors_and_retires_in_budlum_settlement() {
        let mut net = Net::new();
        let a = net.join("a");
        let _b = net.join("b");
        net.commit(vec![net.publish(&a, 1)]).unwrap();
        net.commit(vec![net.publish(&a, 2)]).unwrap();

        let (final_commit, electorate) = net.ledger.commit_at(net.ledger.state.height).unwrap();
        let closed = closing_settlement(
            &net.ledger.state.genesis,
            net.host,
            electorate,
            final_commit,
        )
        .unwrap();

        let mut chain = budlum();
        let host_addr = Address(net.host);
        chain.state.get_or_create(&host_addr).balance = MIN_DOMAIN_OPERATOR_BOND * 4;
        let ctx = crate::settlement::domains::SettlementTxContext {
            sender: host_addr,
            chain_id: Network::Devnet.chain_id().value(),
            fee: 0,
            bls: crate::cross_domain::external::IntakeState::production_bls,
        };
        crate::settlement::domains::execute_settlement_tx(
            &mut chain.state,
            &ctx,
            &crate::settlement::domains::SettlementTx::AnchorClosedGarden(Box::new(closed)),
        )
        .unwrap();

        let dom_id = garden_domain_id(net.ledger.state.genesis.chain_id);
        let dom = chain.state.settlement.domains.get(dom_id).unwrap();
        assert_eq!(dom.status, DomainStatus::Retired);
        assert_eq!(dom.last_committed_height, final_commit.block.header.height);
        let stored = chain
            .state
            .settlement
            .commitments
            .find_by_height(dom_id, final_commit.block.header.height)
            .unwrap();
        assert_eq!(stored.state_root, final_commit.block.header.state_root);
    }
}
