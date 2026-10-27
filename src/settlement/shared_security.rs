//! WIRING: wired - allocations enter through `SettlementTx::SharedSecurity`,
//! the weights are recomputed at every epoch boundary
//! (`AccountState::advance_epoch`) and read by leader election and the
//! finality snapshot through `Validator::voting_weight`; the Ethereum-side
//! `BudlumRegistrar` and `BudlumSlasher` contracts are.
//!
//! Mikoriza: shared security from restaked Ethereum collateral (testnet
//!).
//!
//! An Ethereum operator that restakes (EigenLayer first; Symbiotic and
//! Babylon are later sources behind the same [`SharedSecuritySource`] trait)
//! allocates part of its collateral to a Budlum operator set and binds a
//! Budlum validator address and BLS key to it on Ethereum. The registrar
//! contract emits one allocation event per change. Budlum reads that event
//! only through an anchored external result, the same verified-evidence path
//! the bridge, the relayer intents and Graft use: no trusted party reports
//! Ethereum state.
//!
//! Two separate PoS systems keep running: Gasper on Ethereum and Budlum PoS
//! (leader election and BLS + ML-DSA finality) here. Keys are separate; an
//! Ethereum validator key is never reused on Budlum.
//!
//! Weight: `effective_weight = bud_stake + f(units)`, with
//! `f(units) = units * units_to_weight_ppm / 1_000_000`, and the restaked
//! part of the total capped at `max_restaked_share_ppm` (below one third on
//! testnet, so ETH-backed weight cannot finalize alone). Above the cap every
//! restaked weight is scaled down by the same ratio. The weights move only at
//! the epoch boundary.
//!
//! Slashing: the offence is a Budlum finality double vote (two BLS
//! signatures for different hashes at one chain id, epoch and height). On
//! Budlum it jails and slashes through the existing evidence path, and a
//! slashed validator's restaked weight drops to zero at the next boundary.
//! On Ethereum `BudlumSlasher` verifies the same two signatures with the
//! EIP-2537 precompiles and slashes the operator set. A liveness fault never
//! slashes ETH on testnet; it only jails on Budlum.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::RelayerExternalResult;
use crate::cross_domain::message::MessageKind;
use crate::settlement::domains::{SettlementTxContext, SettlementTxError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Event kind the registrar contract emits for an allocation change.
pub const ALLOCATION_KIND: &[u8] = b"budlum/mikoriza/allocation/v1";
/// Restaked validators held in state.
pub const MAX_RESTAKED_VALIDATORS: usize = 10_000;
/// Allocation messages remembered for replay protection.
pub const MAX_USED_ALLOCATION_MESSAGES: usize = 100_000;
/// Upper bound of a registrar contract identifier.
pub const MAX_REGISTRAR_BYTES: usize = 32;
/// Length of a compressed BLS12-381 G2 public key, as Budlum registers it.
pub const BLS_PUBLIC_KEY_BYTES: usize = 96;
/// Parts per million.
const PPM: u128 = 1_000_000;

/// The Mikoriza parameters of a profile (genesis parameters, K9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecurityParams {
    /// The genesis flag (10.7).
    pub enabled: bool,
    /// The restaked share of the total weight never exceeds this.
    pub max_restaked_share_ppm: u32,
    /// `f(units) = units * units_to_weight_ppm / 1_000_000`.
    pub units_to_weight_ppm: u64,
}

impl SharedSecurityParams {
    /// The feature off.
    pub const DISABLED: Self = Self {
        enabled: false,
        max_restaked_share_ppm: 0,
        units_to_weight_ppm: 0,
    };

    /// `f(units)`, saturating.
    #[must_use]
    pub fn weight_of_units(&self, units: u64) -> u64 {
        let weight = u128::from(units) * u128::from(self.units_to_weight_ppm) / PPM;
        u64::try_from(weight).unwrap_or(u64::MAX)
    }

    /// The largest total restaked weight `bud_weight` admits: `R` with
    /// `R / (B + R) <= share`, that is `R <= B * share / (1 - share)`.
    #[must_use]
    pub fn restaked_cap(&self, bud_weight: u64) -> u64 {
        let share = u128::from(self.max_restaked_share_ppm).min(PPM);
        if share == 0 {
            return 0;
        }
        if share >= PPM {
            return u64::MAX;
        }
        let cap = u128::from(bud_weight) * share / (PPM - share);
        u64::try_from(cap).unwrap_or(u64::MAX)
    }
}

/// A restaking protocol Budlum reads allocations from. Budlum's side is
/// independent of the protocol: a source names its event kind and the payload
/// its registrar commits to.
pub trait SharedSecuritySource {
    /// The source this adapter reads.
    fn source(&self) -> RestakeSource;

    /// The event kind its registrar emits.
    fn allocation_kind(&self) -> &'static [u8] {
        ALLOCATION_KIND
    }

    /// The payload hash the registrar emits for one allocation.
    fn allocation_payload_hash(&self, allocation: &AllocationClaim) -> [u8; 32] {
        allocation_payload_hash(self.source(), allocation)
    }
}

/// The first adapter: EigenLayer operator sets.
#[derive(Debug, Clone, Copy, Default)]
pub struct EigenLayerSource;

impl SharedSecuritySource for EigenLayerSource {
    fn source(&self) -> RestakeSource {
        RestakeSource::EigenLayer
    }
}

/// The restaking protocol an allocation comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestakeSource {
    EigenLayer,
}

impl RestakeSource {
    const fn tag(self) -> u8 {
        match self {
            Self::EigenLayer => 1,
        }
    }

    /// The adapter of this source.
    #[must_use]
    pub fn adapter(self) -> Box<dyn SharedSecuritySource> {
        match self {
            Self::EigenLayer => Box::new(EigenLayerSource),
        }
    }

    /// The external chain this protocol's allocations are attested on.
    ///
    /// An allocation is only as real as the chain that attests it, and the
    /// source is chosen by the transaction sender. Without this binding an
    /// `EigenLayer` claim could point at evidence anchored on any domain the
    /// sender registered itself, which is a chain nobody else vouched for.
    /// EigenLayer settles on Ethereum, so the evidence must be Ethereum's.
    #[must_use]
    pub const fn external_chain(self) -> crate::core::transaction::ExternalChain {
        match self {
            Self::EigenLayer => crate::core::transaction::ExternalChain::Ethereum,
        }
    }
}

/// Whether a restaked validator counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestakeStatus {
    /// The allocation is live.
    Active,
    /// The operator deallocated (an observed allocation of zero units).
    Exited,
}

/// What the registrar event states, carried in clear by the transaction and
/// bound to the event by its payload hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationClaim {
    /// The Budlum validator address the operator bound.
    pub budlum_validator: Address,
    /// The Ethereum operator address.
    pub eth_operator: [u8; 20],
    /// Allocated magnitude, in units of one gwei of ETH.
    pub allocated_units: u64,
    /// The Ethereum epoch the registrar observed the allocation at; an
    /// update must name a later epoch than the one recorded.
    pub observed_epoch: u64,
    /// The validator's BLS public key as registered on Ethereum (the
    /// slasher verifies double votes against it).
    pub bls_public_key: Vec<u8>,
}

/// One restaked validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestakedValidator {
    pub budlum_validator: Address,
    pub eth_operator: [u8; 20],
    pub allocated_units: u64,
    pub source: RestakeSource,
    pub observed_epoch: u64,
    pub status: RestakeStatus,
    pub bls_public_key: Vec<u8>,
}

/// The Mikoriza state: registrar contracts per external domain, the
/// restaked validators, and the allocation messages already used.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedSecurityRegistry {
    /// The registrar contract of an external domain; allocation events count
    /// only from it.
    pub registrars: BTreeMap<u32, Vec<u8>>,
    pub validators: BTreeMap<Address, RestakedValidator>,
    pub used_messages: BTreeSet<[u8; 32]>,
}

impl SharedSecurityRegistry {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registrars.is_empty() && self.validators.is_empty() && self.used_messages.is_empty()
    }

    /// The registry root, folded into the settlement root once the registry
    /// holds anything.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let encoded = bincode::serialize(self)
            .unwrap_or_else(|_| b"BDLM_SHARED_SECURITY_UNENCODABLE_V1".to_vec());
        hash_fields_bytes(&[b"BDLM_SHARED_SECURITY_V1", &encoded])
    }

    /// The live allocation of `validator`, if any.
    #[must_use]
    pub fn active(&self, validator: &Address) -> Option<&RestakedValidator> {
        self.validators
            .get(validator)
            .filter(|row| row.status == RestakeStatus::Active)
    }
}

/// `H("BDLM_MIKORIZA_ALLOCATION_V1", source, validator, operator, units,
/// epoch, bls key)`: the payload the registrar emits.
#[must_use]
pub fn allocation_payload_hash(source: RestakeSource, allocation: &AllocationClaim) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_MIKORIZA_ALLOCATION_V1",
        &[source.tag()],
        allocation.budlum_validator.as_bytes(),
        &allocation.eth_operator,
        &allocation.allocated_units.to_le_bytes(),
        &allocation.observed_epoch.to_le_bytes(),
        &allocation.bls_public_key,
    ])
}

/// The correlation id of an operator's allocation events.
#[must_use]
pub fn operator_correlation(eth_operator: &[u8; 20]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_MIKORIZA_OPERATOR_V1", eth_operator])
}

/// State-rooted Mikoriza writes, carried by a signed settlement transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SharedSecurityTx {
    /// Name the registrar contract of an external domain (that domain's
    /// operator only).
    SetRegistrar { domain_key: u32, registrar: Vec<u8> },
    /// Record an allocation the registrar emitted, proven by an anchored
    /// result from that domain. Anyone may carry it; the evidence decides.
    Observe {
        domain_key: u32,
        source: RestakeSource,
        allocation: AllocationClaim,
        evidence: Box<RelayerExternalResult>,
    },
}

fn refused(reason: impl Into<String>) -> SettlementTxError {
    SettlementTxError::Refused(reason.into())
}

/// Apply one Mikoriza transaction.
///
/// # Errors
///
/// [`SettlementTxError::Refused`] naming the failed check; a refusal changes
/// nothing.
pub fn execute_shared_security_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &SharedSecurityTx,
) -> Result<(), SettlementTxError> {
    let params = crate::core::chain_config::shared_security_for_chain_id(ctx.chain_id);
    if !params.enabled {
        return Err(refused(
            "shared security (Mikoriza) is not enabled at this chain's genesis",
        ));
    }
    match tx {
        SharedSecurityTx::SetRegistrar {
            domain_key,
            registrar,
        } => {
            let operator = state
                .settlement
                .domains
                .get(*domain_key)
                .ok_or_else(|| refused("Mikoriza registrar names an unregistered domain"))?
                .operator;
            if operator != Some(ctx.sender) {
                return Err(refused(
                    "only the domain operator may name its Mikoriza registrar",
                ));
            }
            if registrar.is_empty() || registrar.len() > MAX_REGISTRAR_BYTES {
                return Err(refused("Mikoriza registrar length is invalid"));
            }
            state
                .settlement
                .shared_security
                .registrars
                .insert(*domain_key, registrar.clone());
            Ok(())
        }
        SharedSecurityTx::Observe {
            domain_key,
            source,
            allocation,
            evidence,
        } => observe(state, *domain_key, *source, allocation, evidence),
    }
}

fn observe(
    state: &mut AccountState,
    domain_key: u32,
    source: RestakeSource,
    allocation: &AllocationClaim,
    evidence: &RelayerExternalResult,
) -> Result<(), SettlementTxError> {
    if allocation.budlum_validator == Address::zero() {
        return Err(refused("Mikoriza allocation names no validator"));
    }
    if allocation.bls_public_key.len() != BLS_PUBLIC_KEY_BYTES {
        return Err(refused("Mikoriza allocation BLS key has the wrong length"));
    }
    let registrar = state
        .settlement
        .shared_security
        .registrars
        .get(&domain_key)
        .cloned()
        .ok_or_else(|| refused("the domain has no Mikoriza registrar"))?;
    if evidence.chain.domain_id() != domain_key {
        return Err(refused("Mikoriza evidence comes from another domain"));
    }
    // The source is the sender's word; the chain is the fact. A source that
    // settles elsewhere cannot back an allocation here, or a caller could
    // name the most valuable restaking protocol and anchor the evidence on a
    // domain it registered itself.
    let attested_on = source.external_chain();
    if evidence.chain != attested_on {
        return Err(refused(format!(
            "Mikoriza allocation is claimed from {source:?}, which attests on {attested_on:?}, \
             but the evidence comes from {:?}",
            evidence.chain
        )));
    }
    // The validator binds the same BLS key on both sides: the slasher on
    // Ethereum verifies double votes against the key Budlum finality uses.
    if let Some(validator) = state.validators.get(&allocation.budlum_validator) {
        if !validator.bls_public_key.is_empty()
            && validator.bls_public_key != allocation.bls_public_key
        {
            return Err(refused(
                "Mikoriza allocation BLS key is not the validator's registered key",
            ));
        }
    }
    let message = crate::relayer::policy::verify_anchored_result(&state.external_roots, evidence)
        .map_err(SettlementTxError::Refused)?;
    let adapter = source.adapter();
    if message.kind != MessageKind::Custom(adapter.allocation_kind().to_vec())
        || message.sender != crate::settlement::graft::origin_emitter(&registrar)
        || message.recipient != allocation.budlum_validator
        || message.correlation_id != Some(operator_correlation(&allocation.eth_operator))
        || message.payload_hash != adapter.allocation_payload_hash(allocation)
    {
        return Err(refused(
            "Mikoriza event does not bind the registrar, the validator and the allocation",
        ));
    }
    let message_id = message.message_id;
    let registry = &mut state.settlement.shared_security;
    if registry.used_messages.contains(&message_id) {
        return Err(refused("Mikoriza allocation event has already been used"));
    }
    if registry.used_messages.len() >= MAX_USED_ALLOCATION_MESSAGES {
        return Err(refused("Mikoriza replay set is full"));
    }
    if let Some(previous) = registry.validators.get(&allocation.budlum_validator) {
        if previous.eth_operator != allocation.eth_operator {
            return Err(refused(
                "the validator is already bound to another Ethereum operator",
            ));
        }
        if allocation.observed_epoch <= previous.observed_epoch {
            return Err(refused(
                "Mikoriza allocation is not newer than the recorded one",
            ));
        }
    } else if registry.validators.len() >= MAX_RESTAKED_VALIDATORS {
        return Err(refused("Mikoriza validator table is full"));
    }
    registry.used_messages.insert(message_id);
    registry.validators.insert(
        allocation.budlum_validator,
        RestakedValidator {
            budlum_validator: allocation.budlum_validator,
            eth_operator: allocation.eth_operator,
            allocated_units: allocation.allocated_units,
            source,
            observed_epoch: allocation.observed_epoch,
            status: if allocation.allocated_units == 0 {
                RestakeStatus::Exited
            } else {
                RestakeStatus::Active
            },
            bls_public_key: allocation.bls_public_key.clone(),
        },
    );
    Ok(())
}

/// Recompute every validator's restaked weight from the live allocations
/// (run at the epoch boundary, so weight changes take effect there).
///
/// A validator counts only while it is eligible and not slashed. The sum is
/// capped at [`SharedSecurityParams::restaked_cap`] of the eligible BUD
/// stake; above the cap every weight is scaled by the same ratio (rounded
/// down, so the cap holds).
pub fn apply_restaked_weights(state: &mut AccountState, params: &SharedSecurityParams) {
    let epoch = state.epoch_index;
    let mut raw: BTreeMap<Address, u64> = BTreeMap::new();
    if params.enabled {
        for (address, row) in &state.settlement.shared_security.validators {
            if row.status != RestakeStatus::Active {
                continue;
            }
            let counts = state
                .validators
                .get(address)
                .is_some_and(|v| v.is_eligible(epoch) && !v.slashed);
            if counts {
                raw.insert(*address, params.weight_of_units(row.allocated_units));
            }
        }
    }
    let bud_total = state
        .validators
        .values()
        .filter(|v| v.is_eligible(epoch))
        .fold(0u64, |acc, v| acc.saturating_add(v.stake));
    let cap = u128::from(params.restaked_cap(bud_total));
    let raw_total: u128 = raw.values().map(|w| u128::from(*w)).sum();
    for validator in state.validators.values_mut() {
        let weight = raw.get(&validator.address).copied().unwrap_or(0);
        let scaled = if raw_total > cap && raw_total > 0 {
            u128::from(weight) * cap / raw_total
        } else {
            u128::from(weight)
        };
        validator.restaked_weight = u64::try_from(scaled).unwrap_or(u64::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::Validator;
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};

    const DOMAIN: u32 = 1;
    const FEE: u64 = 5;
    const REGISTRAR: [u8; 20] = [0xEE; 20];

    fn devnet() -> u64 {
        crate::core::chain_config::Network::Devnet
            .chain_id()
            .value()
    }

    fn ctx(sender: Address, chain_id: u64) -> SettlementTxContext {
        SettlementTxContext {
            sender,
            chain_id,
            fee: FEE,
            bls: crate::cross_domain::external::IntakeState::production_bls,
        }
    }

    fn state_with_registrar(operator: Address) -> AccountState {
        let mut state = AccountState::new();
        let mut domain = crate::domain::plugin::default_domain(
            DOMAIN,
            crate::domain::ConsensusKind::PoW,
            45262,
            crate::domain::POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        // Domain 1 is Ethereum's id: only a domain that declares Ethereum's
        // chain id may anchor the root the Mikoriza gate reads as Ethereum's.
        domain.domain_chain_id = 1;
        domain.operator = Some(operator);
        state.add_balance(&operator, domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, domain).expect("domain");
        execute_shared_security_tx(
            &mut state,
            &ctx(operator, devnet()),
            &SharedSecurityTx::SetRegistrar {
                domain_key: DOMAIN,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .expect("the operator names the registrar");
        state
    }

    fn claim(validator: Address, units: u64, epoch: u64) -> AllocationClaim {
        AllocationClaim {
            budlum_validator: validator,
            eth_operator: [0x0A; 20],
            allocated_units: units,
            observed_epoch: epoch,
            bls_public_key: vec![0xB1; BLS_PUBLIC_KEY_BYTES],
        }
    }

    fn anchored(
        state: &mut AccountState,
        allocation: &AllocationClaim,
        nonce: u64,
    ) -> Box<RelayerExternalResult> {
        let message = CrossDomainMessage::new_correlated(
            CrossDomainMessageParams {
                source_domain: DOMAIN,
                target_domain: 1,
                source_height: 3,
                event_index: 0,
                nonce,
                sender: crate::settlement::graft::origin_emitter(&REGISTRAR),
                recipient: allocation.budlum_validator,
                payload_hash: allocation_payload_hash(RestakeSource::EigenLayer, allocation),
                kind: MessageKind::Custom(ALLOCATION_KIND.to_vec()),
                expiry_height: 0,
            },
            operator_correlation(&allocation.eth_operator),
        );
        let mut result = RelayerExternalResult {
            chain: RestakeSource::EigenLayer.external_chain(),
            tx_hash: "0x01".into(),
            success: true,
            message: Some(message),
            receipt_proof: Vec::new(),
            external_state_root: [0u8; 32],
        };
        let leaf = result.result_leaf();
        result.receipt_proof = bincode::serialize(&crate::cross_domain::event_tree::MerkleProof {
            leaf,
            index: 0,
            siblings: Vec::new(),
        })
        .expect("proof");
        result.external_state_root = leaf;
        assert!(state.anchor_external_root(DOMAIN, leaf));
        Box::new(result)
    }

    fn observe_tx(
        state: &mut AccountState,
        allocation: &AllocationClaim,
        nonce: u64,
    ) -> SharedSecurityTx {
        SharedSecurityTx::Observe {
            domain_key: DOMAIN,
            source: RestakeSource::EigenLayer,
            allocation: allocation.clone(),
            evidence: anchored(state, allocation, nonce),
        }
    }

    #[test]
    fn a_proven_allocation_is_recorded_and_a_replay_is_refused() {
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let validator = Address::from([2u8; 32]);
        let allocation = claim(validator, 1_000, 5);
        let tx = observe_tx(&mut state, &allocation, 0);
        let carrier = Address::from([3u8; 32]);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).expect("records");
        let row = state
            .settlement
            .shared_security
            .active(&validator)
            .expect("active");
        assert_eq!(row.allocated_units, 1_000);
        assert!(execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).is_err());
    }

    #[test]
    fn an_event_that_does_not_bind_the_allocation_is_refused() {
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let validator = Address::from([2u8; 32]);
        let honest = claim(validator, 1_000, 5);
        let evidence = anchored(&mut state, &honest, 0);
        let mut inflated = honest.clone();
        inflated.allocated_units = 1_000_000;
        let tx = SharedSecurityTx::Observe {
            domain_key: DOMAIN,
            source: RestakeSource::EigenLayer,
            allocation: inflated,
            evidence,
        };
        assert!(execute_shared_security_tx(&mut state, &ctx(operator, devnet()), &tx).is_err());
        assert!(state.settlement.shared_security.validators.is_empty());
    }

    #[test]
    fn the_door_is_closed_where_the_genesis_flag_is_off() {
        let operator = Address::from([1u8; 32]);
        let mut state = AccountState::new();
        let testnet = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        let err = execute_shared_security_tx(
            &mut state,
            &ctx(operator, testnet),
            &SharedSecurityTx::SetRegistrar {
                domain_key: DOMAIN,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not enabled"), "{err}");
    }

    #[test]
    fn an_older_allocation_does_not_replace_a_newer_one() {
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let validator = Address::from([2u8; 32]);
        let carrier = Address::from([3u8; 32]);
        let newer = claim(validator, 1_000, 9);
        let tx = observe_tx(&mut state, &newer, 0);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).expect("records");
        let older = claim(validator, 9_000, 4);
        let tx = observe_tx(&mut state, &older, 1);
        assert!(execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).is_err());
    }

    #[test]
    fn an_eigen_layer_claim_must_be_attested_on_ethereum() {
        // The source is the sender's word and the chain is the fact. A caller
        // that anchors its evidence on a domain it registered itself could
        // otherwise claim the most valuable restaking protocol for a chain
        // nobody else vouched for.
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let validator = Address::from([2u8; 32]);
        let allocation = claim(validator, 1_000, 5);
        let honest = anchored(&mut state, &allocation, 0);
        let mut foreign = honest.clone();
        foreign.chain = crate::core::transaction::ExternalChain::Custom(DOMAIN);
        // Re-anchor the forged evidence so only the chain binding can refuse it.
        let leaf = foreign.result_leaf();
        let mut proof = foreign.clone();
        proof.external_state_root = leaf;
        proof.receipt_proof = bincode::serialize(&crate::cross_domain::event_tree::MerkleProof {
            leaf,
            index: 0,
            siblings: Vec::new(),
        })
        .expect("proof");
        assert!(state.anchor_external_root(DOMAIN, leaf));
        let tx = SharedSecurityTx::Observe {
            domain_key: DOMAIN,
            source: RestakeSource::EigenLayer,
            allocation,
            evidence: proof,
        };
        let err = execute_shared_security_tx(&mut state, &ctx(operator, devnet()), &tx)
            .expect_err("a claim attested off Ethereum is refused");
        assert!(err.to_string().contains("attests on"), "{err}");
        assert!(state.settlement.shared_security.validators.is_empty());
    }

    #[test]
    fn restaked_weight_stays_under_the_cap() {
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: 300_000,
            units_to_weight_ppm: 1_000_000,
        };
        let mut state = AccountState::new();
        for (tag, stake, units) in [(1u8, 1_000u64, 0u64), (2, 1_000, 10_000), (3, 0, 10_000)] {
            let address = Address::from([tag; 32]);
            let mut v = Validator::new(address, stake);
            v.active = true;
            state.validators.insert(address, v);
            if units > 0 {
                state.settlement.shared_security.validators.insert(
                    address,
                    RestakedValidator {
                        budlum_validator: address,
                        eth_operator: [tag; 20],
                        allocated_units: units,
                        source: RestakeSource::EigenLayer,
                        observed_epoch: 1,
                        status: RestakeStatus::Active,
                        bls_public_key: Vec::new(),
                    },
                );
            }
        }
        apply_restaked_weights(&mut state, &params);
        let bud: u64 = state.validators.values().map(|v| v.stake).sum();
        let restaked: u64 = state.validators.values().map(|v| v.restaked_weight).sum();
        assert!(restaked > 0);
        // R / (B + R) <= 30 %.
        assert!(u128::from(restaked) * 1_000_000 <= u128::from(bud + restaked) * 300_000);
        // Scaled by one ratio: the two restaked validators keep equal weight.
        let two = state.validators[&Address::from([2u8; 32])].restaked_weight;
        let three = state.validators[&Address::from([3u8; 32])].restaked_weight;
        assert_eq!(two, three);
        // A slashed validator loses it at the next boundary.
        state
            .validators
            .get_mut(&Address::from([2u8; 32]))
            .expect("v2")
            .slashed = true;
        apply_restaked_weights(&mut state, &params);
        assert_eq!(
            state.validators[&Address::from([2u8; 32])].restaked_weight,
            0
        );
    }

    #[test]
    fn the_cap_formula_matches_the_share() {
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: 300_000,
            units_to_weight_ppm: 1_000_000,
        };
        // 30 % of the total is 3/7 of the BUD part.
        assert_eq!(params.restaked_cap(7_000), 3_000);
        assert_eq!(SharedSecurityParams::DISABLED.restaked_cap(7_000), 0);
    }

    /// Cross-language known answers: contracts/test/Parity.t.sol pins the
    /// same values for `BudlumRegistrar`.
    #[test]
    fn allocation_hashes_match_the_solidity_known_answers() {
        let allocation = AllocationClaim {
            budlum_validator: Address::from([0x02; 32]),
            eth_operator: [0x0A; 20],
            allocated_units: 1_000,
            observed_epoch: 5,
            bls_public_key: vec![0xB1; BLS_PUBLIC_KEY_BYTES],
        };
        assert_eq!(
            hex::encode(allocation_payload_hash(
                RestakeSource::EigenLayer,
                &allocation
            )),
            "c96d2795c2307e106fd9c6098059b2ad146ed8499feba20254d53775b209e1b2"
        );
        assert_eq!(
            hex::encode(operator_correlation(&[0x0A; 20])),
            "1d4cf8803bf3fbf7ec0ac2dc3bd646223ffae6bd5a90caf226a8fcb80ac54b3e"
        );
    }
}
