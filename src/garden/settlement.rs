use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::KeyPair;
use crate::domain::finality_adapter::{
    poa_authority_set_hash, poa_commit_signing_message, DomainFinalityAdapter, FinalityProof,
    FinalityStatus, PoAAuthoritySignature, PoAFinalityAdapter,
};
use crate::domain::registry::{ConsensusDomainRegistry, MIN_DOMAIN_OPERATOR_BOND};
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainId, DomainStatus, RootScheme,
};
use crate::garden::consensus::GardenChainState;
use crate::garden::types::{GardenBlock, GardenGenesis, TAG_GARDEN_GENESIS};
use std::collections::BTreeMap;

/// Connects a Garden sovereign PoA domain directly to Budlum's
/// `ConsensusDomainRegistry` and `PoAFinalityAdapter` without a bridge
/// (Directive 4.1, 4.2).
#[derive(Clone, Debug)]
pub struct GardenBudlumSettlement {
    pub registry: ConsensusDomainRegistry,
    pub next_domain_id: DomainId,
    /// Maps Garden chain ID string -> registered Budlum DomainId.
    pub chain_to_domain: BTreeMap<String, DomainId>,
    /// Tracks anchored commitments per domain id string.
    pub anchored_heights: BTreeMap<String, u64>,
}

impl Default for GardenBudlumSettlement {
    fn default() -> Self {
        Self::new()
    }
}

impl GardenBudlumSettlement {
    pub fn new() -> Self {
        Self {
            registry: ConsensusDomainRegistry::new(),
            next_domain_id: 1,
            chain_to_domain: BTreeMap::new(),
            anchored_heights: BTreeMap::new(),
        }
    }

    /// Derive a deterministic Budlum `DomainId` for a Garden and register it in
    /// `ConsensusDomainRegistry` as `ConsensusKind::PoA` with `bridge_enabled: false`.
    pub fn register_garden_domain(
        &mut self,
        genesis: &GardenGenesis,
        active_authorities: &[[u8; 32]],
    ) -> Result<DomainId, String> {
        let chain_key = genesis.chain_id.value().to_string();
        if let Some(existing) = self.chain_to_domain.get(&chain_key) {
            return Ok(*existing);
        }
        if active_authorities.is_empty() {
            return Err("cannot register Garden domain with zero authorities".into());
        }

        let mut domain_id = self.next_domain_id;
        while self.registry.get(domain_id).is_some() {
            domain_id = domain_id
                .checked_add(1)
                .ok_or_else(|| "exhausted Budlum DomainId space".to_string())?;
        }
        self.next_domain_id = domain_id.saturating_add(1);

        let authorities: Vec<Address> = active_authorities.iter().map(|pk| Address(*pk)).collect();
        let mut domain = ConsensusDomain {
            id: domain_id,
            kind: ConsensusKind::PoA,
            status: DomainStatus::Active,
            domain_chain_id: genesis.chain_id.value(),
            operator: Some(Address(genesis.host_pubkey)),
            operator_bond: MIN_DOMAIN_OPERATOR_BOND,
            config_hash: genesis.genesis_hash,
            validator_set_hash: [0u8; 32],
            finality_adapter: PoAFinalityAdapter::default().adapter_name().to_string(),
            min_confirmations: 1,
            bridge_enabled: false,
            block_hash_scheme: RootScheme::Sha3_256,
            state_root_scheme: RootScheme::Sha3_256,
            tx_root_scheme: RootScheme::Sha3_256,
            last_committed_height: 0,
            last_committed_hash: genesis.genesis_hash,
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
        };
        domain.validator_set_hash = poa_authority_set_hash(&domain, &authorities)
            .map_err(|e| format!("failed to compute Garden PoA authority set hash: {e}"))?;

        self.registry.register(domain)?;
        self.chain_to_domain.insert(chain_key, domain_id);
        self.anchored_heights.insert(domain_id.to_string(), 0);
        Ok(domain_id)
    }

    /// Anchor a finalized Garden block directly into Budlum's PoA finality
    /// adapter and record its height.
    pub fn anchor_garden_block(
        &mut self,
        state: &mut GardenChainState,
        block: &GardenBlock,
        signer_keypairs: &[&KeyPair],
        budlum_height: u64,
    ) -> Result<DomainId, String> {
        let chain_key = state.genesis.chain_id.value().to_string();
        let domain_id = self
            .chain_to_domain
            .get(&chain_key)
            .copied()
            .ok_or_else(|| "Garden domain is not registered in Budlum registry".to_string())?;

        let mut domain_snapshot = self
            .registry
            .get(domain_id)
            .cloned()
            .ok_or_else(|| format!("missing Budlum domain {domain_id}"))?;

        let current_authorities: Vec<Address> = state
            .liveness
            .active_validator_pubkeys()
            .into_iter()
            .map(Address)
            .collect();
        if current_authorities.is_empty() {
            return Err("cannot anchor block with zero active Garden authorities".into());
        }

        // Update domain's authority set commitment to match the current active
        // Garden validators (classless open participation).
        let updated_set_hash = poa_authority_set_hash(&domain_snapshot, &current_authorities)
            .map_err(|e| format!("failed to refresh Garden authority hash: {e}"))?;
        domain_snapshot.validator_set_hash = updated_set_hash;

        let tx_root = hash_fields_bytes(&[
            TAG_GARDEN_GENESIS,
            &block.block_hash,
            &(block.txs.len() as u64).to_le_bytes(),
        ]);
        let mut commitment = DomainCommitment {
            domain_id,
            domain_height: block.height,
            domain_block_hash: block.block_hash,
            parent_domain_block_hash: block.parent_hash,
            state_root: block.state_root,
            tx_root,
            event_root: block.content_root,
            finality_proof_hash: [0u8; 32],
            consensus_kind: ConsensusKind::PoA,
            validator_set_hash: updated_set_hash,
            timestamp_ms: u128::from(block.timestamp_ms),
            sequence: block.height,
            producer: Some(Address(block.proposer)),
            state_updates: BTreeMap::new(),
        };

        let msg =
            poa_commit_signing_message(domain_snapshot.domain_chain_id, domain_id, &commitment);
        let signatures: Vec<PoAAuthoritySignature> = signer_keypairs
            .iter()
            .map(|kp| PoAAuthoritySignature {
                authority: Address(kp.public_key_bytes()),
                signature: kp.sign(&msg).to_vec(),
            })
            .collect();

        let proof = FinalityProof::PoA {
            authorities: current_authorities,
            signatures,
        };
        let adapter = PoAFinalityAdapter::default();
        let status = adapter
            .verify_finality(&domain_snapshot, &commitment, &proof)
            .map_err(|e| format!("PoA finality verification error: {e}"))?;
        match status {
            FinalityStatus::Finalized => {
                commitment.finality_proof_hash = block.block_hash;
                if let Some(domain_mut) = self.registry.get_mut(domain_id) {
                    domain_mut.validator_set_hash = updated_set_hash;
                    domain_mut.last_committed_height = block.height;
                    domain_mut.last_committed_hash = block.block_hash;
                }
                self.anchored_heights
                    .insert(domain_id.to_string(), budlum_height);
                state.budlum_domain_id = Some(domain_id);
                state.last_anchored_budlum_height = Some(budlum_height);
                for trace in state.traces.values_mut() {
                    if trace.block_height == block.height {
                        trace.budlum_domain_id = Some(domain_id);
                        trace.budlum_anchored_height = Some(budlum_height);
                    }
                }
                Ok(domain_id)
            }
            FinalityStatus::Pending { .. } => Err("Garden PoA finality proof is pending".into()),
            FinalityStatus::Rejected(reason) => {
                Err(format!("Garden PoA finality proof rejected: {reason}"))
            }
        }
    }

    /// Synchronize the Garden's `Active` / `Frozen` / `Retired` status into
    /// Budlum's `ConsensusDomainRegistry` via `transition_status_checked`
    /// (Directive 4.2, 9.7-9.10).
    pub fn sync_domain_status(
        &mut self,
        chain_id: u64,
        target_status: DomainStatus,
    ) -> Result<DomainStatus, String> {
        let domain_id = self
            .chain_to_domain
            .get(&chain_id.to_string())
            .copied()
            .ok_or_else(|| "Garden domain not registered in Budlum registry".to_string())?;
        let current = self
            .registry
            .get(domain_id)
            .map(|d| d.status)
            .ok_or_else(|| format!("missing Budlum domain {domain_id}"))?;
        if current == target_status {
            return Ok(current);
        }
        match (current, target_status) {
            (DomainStatus::Active, DomainStatus::Retired) => {
                self.registry
                    .transition_status_checked(domain_id, DomainStatus::Frozen)?;
                self.registry
                    .transition_status_checked(domain_id, DomainStatus::Retired)?;
            }
            _ => {
                self.registry
                    .transition_status_checked(domain_id, target_status)?;
            }
        }
        Ok(target_status)
    }

    pub fn budlum_domain_status(&self, chain_id: u64) -> Option<DomainStatus> {
        let domain_id = self.chain_to_domain.get(&chain_id.to_string()).copied()?;
        self.registry.get(domain_id).map(|d| d.status)
    }
}
