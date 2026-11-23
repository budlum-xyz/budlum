//! Shared security from restaked Ethereum collateral.
//!
//! WIRING: wired - allocations enter through `SettlementTx::SharedSecurity`,
//! the weights are recomputed at every epoch boundary
//! (`AccountState::advance_epoch`) and read by leader election and the
//! finality snapshot through `Validator::voting_weight`; the Ethereum-side
//! `BudlumRegistrar` and `BudlumSlasher` contracts are.
//!
//! The implementation is active only on devnet. Public testnet and mainnet
//! fail closed until their activation gates and external evidence rehearsals
//! pass.
//!
//! An Ethereum operator that restakes (`EigenLayer` first; Symbiotic and
//! Babylon are later sources behind the same [`SharedSecuritySource`] trait)
//! allocates part of its collateral to a Budlum operator set and binds a
//! Budlum validator address and BLS key to it on Ethereum. The registrar
//! contract emits one allocation event per change. Budlum reads that event
//! only through an anchored external result, the same verified-evidence path
//! the bridge, the relayer intents and `AppBinding` use: no trusted party reports
//! Ethereum state.
//!
//! Two separate `PoS` systems keep running: Gasper on Ethereum and Budlum `PoS`
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
/// How many Budlum epochs an attested allocation stays in force.
///
/// Nothing on Budlum re-reads the operator's allocation on the other chain, so
/// a row is only as true as the event that wrote it. The window is long enough
/// for a permissionless `reportAllocation` to be carried and anchored, and an
/// operator that wants its restaked weight re-attests inside it.
pub const MAX_ALLOCATION_AGE_EPOCHS: u64 = 100;
/// Maximum `max_restaked_share_ppm` preserving strict `< 1/3` BFT safety.
///
/// Fixed at `333_333` ppm so restaked external collateral never reaches 1/3 of
/// total voting weight and cannot stall or finalize Budlum without native stake.
/// WIRING: enforced by [`SharedSecurityParams::respects_bft_safety_cap`].
pub const MAX_SAFE_BFT_RESTAKED_SHARE_PPM: u32 = 333_333;
/// Parts per million.
const PPM: u128 = 1_000_000;

/// The Mikoriza parameters of a profile (genesis parameters).
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

    /// Returns `true` iff `max_restaked_share_ppm <= MAX_SAFE_BFT_RESTAKED_SHARE_PPM` (`< 1/3`).
    ///
    /// Convenience: kept for the CLI and genesis parameter auditors.
    #[must_use]
    pub const fn respects_bft_safety_cap(&self) -> bool {
        self.max_restaked_share_ppm <= MAX_SAFE_BFT_RESTAKED_SHARE_PPM
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

/// First adapter: `EigenLayer` operator sets settled on Ethereum.
#[derive(Debug, Clone, Copy, Default)]
pub struct EigenLayerSource;

impl SharedSecuritySource for EigenLayerSource {
    fn source(&self) -> RestakeSource {
        RestakeSource::EigenLayer
    }
}

/// Second adapter: `Symbiotic` restaking vaults settled on Ethereum.
///
/// WIRING: selected by [`RestakeSource::adapter`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SymbioticSource;

impl SharedSecuritySource for SymbioticSource {
    fn source(&self) -> RestakeSource {
        RestakeSource::Symbiotic
    }
}

/// Third adapter: `Babylon` finality-provider BTC staking settled on Bitcoin.
///
/// WIRING: selected by [`RestakeSource::adapter`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BabylonSource;

impl SharedSecuritySource for BabylonSource {
    fn source(&self) -> RestakeSource {
        RestakeSource::Babylon
    }
}

/// Fourth adapter: `CometBFT` / IBC Interchain Security provider (`CosmosIcs`).
///
/// `AllocationClaim::eth_operator` holds the 20-byte `CometBFT` validator
/// address (`SHA256(ed25519_pk)[..20]`), directly slashable via ICS-07
/// [`execute_tendermint_misbehaviour_slash`].
/// WIRING: selected by [`RestakeSource::adapter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosmosIcsSource {
    /// Registered settlement domain id of the `CometBFT` provider chain.
    pub domain_id: u32,
}

impl SharedSecuritySource for CosmosIcsSource {
    fn source(&self) -> RestakeSource {
        RestakeSource::CosmosIcs {
            domain_id: self.domain_id,
        }
    }
}

/// The restaking protocol an allocation comes from (append-only variant order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RestakeSource {
    /// `EigenLayer` operator sets anchored on Ethereum.
    EigenLayer,
    /// `Symbiotic` collateral vaults anchored on Ethereum.
    Symbiotic,
    /// `Babylon` BTC staking finality providers anchored on Bitcoin.
    Babylon,
    /// `CometBFT` / IBC Interchain Security provider bound to `domain_id`.
    CosmosIcs {
        /// Registered `CometBFT` provider settlement domain id.
        domain_id: u32,
    },
}

impl RestakeSource {
    const fn tag(self) -> u8 {
        match self {
            Self::EigenLayer => 1,
            Self::Symbiotic => 2,
            Self::Babylon => 3,
            Self::CosmosIcs { .. } => 4,
        }
    }

    const fn domain_scope(self) -> u32 {
        match self {
            Self::CosmosIcs { domain_id } => domain_id,
            Self::EigenLayer | Self::Symbiotic | Self::Babylon => 0,
        }
    }

    /// Canonical collision-free string key identifying `(self, operator)` in
    /// serialized state maps.
    #[must_use]
    pub fn operator_map_key(self, operator: &[u8; 20]) -> String {
        format!(
            "{}:{}:{}",
            self.tag(),
            self.domain_scope(),
            hex::encode(operator)
        )
    }

    /// The adapter of this source.
    #[must_use]
    pub fn adapter(self) -> Box<dyn SharedSecuritySource> {
        match self {
            Self::EigenLayer => Box::new(EigenLayerSource),
            Self::Symbiotic => Box::new(SymbioticSource),
            Self::Babylon => Box::new(BabylonSource),
            Self::CosmosIcs { domain_id } => Box::new(CosmosIcsSource { domain_id }),
        }
    }

    /// The external chain this protocol's allocations are attested on.
    ///
    /// Prevents claiming a high-value restaking source against evidence from an
    /// unrelated self-registered domain.
    #[must_use]
    pub const fn external_chain(self) -> crate::core::transaction::ExternalChain {
        match self {
            Self::EigenLayer | Self::Symbiotic => crate::core::transaction::ExternalChain::Ethereum,
            Self::Babylon => crate::core::transaction::ExternalChain::Bitcoin,
            Self::CosmosIcs { domain_id } => {
                crate::core::transaction::ExternalChain::Custom(domain_id)
            }
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
    /// Permanently slashed and quarantined by verified consensus misbehaviour.
    Slashed,
}

/// Immutable on-chain slashing receipt recorded when a shared-security operator
/// is slashed via verified external consensus misbehaviour (e.g. ICS-07).
///
/// WIRING: written by [`execute_tendermint_misbehaviour_slash`] and stored in
/// [`SharedSecurityRegistry::slashed_operators`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSlashRecord {
    /// Source protocol where the operator was bonded.
    pub source: RestakeSource,
    /// Slashed 20-byte operator / `CometBFT` validator address.
    pub operator: [u8; 20],
    /// Bound Budlum validator whose restaked backing was forfeited.
    pub budlum_validator: Address,
    /// Allocated restaked units forfeited to zero at slashing time.
    pub slashed_units: u64,
    /// Proven class of `CometBFT` ICS-07 misbehaviour.
    pub kind: crate::cross_domain::external::tendermint::TendermintMisbehaviourKind,
    /// Fault height on the provider chain.
    pub infraction_height: u64,
    /// Budlum epoch at which the slash was executed.
    pub slashed_at_epoch: u64,
    /// Deterministic evidence digest binding the verified misbehaviour proof.
    pub evidence_id: [u8; 32],
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
    /// The Budlum epoch each row was last written from an attested event, so
    /// the weight pass can refuse an allocation that has not been re-attested.
    #[serde(default)]
    pub attested_at: BTreeMap<Address, u64>,
    /// Highest observed external epoch per canonical `(source, operator)` key,
    /// preventing stale out-of-order operator events from exiting newer moves.
    #[serde(default)]
    pub operator_epochs: BTreeMap<String, u64>,
    /// Permanent quarantine records for slashed `(source, operator)` keys.
    #[serde(default)]
    pub slashed_operators: BTreeMap<String, ExternalSlashRecord>,
}

impl SharedSecurityRegistry {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registrars.is_empty()
            && self.validators.is_empty()
            && self.used_messages.is_empty()
            && self.attested_at.is_empty()
            && self.operator_epochs.is_empty()
            && self.slashed_operators.is_empty()
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

    /// Return `true` iff `(source, operator)` has been permanently slashed.
    #[must_use]
    pub fn is_operator_slashed(&self, source: RestakeSource, operator: &[u8; 20]) -> bool {
        self.slashed_operators
            .contains_key(&source.operator_map_key(operator))
    }

    /// Highest observed epoch recorded for `(source, operator)` across all validators.
    #[must_use]
    fn highest_operator_epoch(&self, source: RestakeSource, operator: &[u8; 20]) -> Option<u64> {
        let tracked = self
            .operator_epochs
            .get(&source.operator_map_key(operator))
            .copied();
        let scanned = self
            .validators
            .values()
            .filter(|r| r.source == source && r.eth_operator == *operator)
            .map(|r| r.observed_epoch)
            .max();
        match (tracked, scanned) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}

/// `H("BDLM_MIKORIZA_ALLOCATION_V1", source, [scope], validator, operator, units, epoch, bls)`:
/// canonical allocation payload digest committed by each source registrar.
#[must_use]
pub fn allocation_payload_hash(source: RestakeSource, allocation: &AllocationClaim) -> [u8; 32] {
    let domain_tag = b"BDLM_MIKORIZA_ALLOCATION_V1";
    let tag = [source.tag()];
    let scope = source.domain_scope().to_le_bytes();
    let units = allocation.allocated_units.to_le_bytes();
    let epoch = allocation.observed_epoch.to_le_bytes();
    if matches!(source, RestakeSource::CosmosIcs { .. }) {
        hash_fields_bytes(&[
            domain_tag,
            &tag,
            &scope,
            allocation.budlum_validator.as_bytes(),
            &allocation.eth_operator,
            &units,
            &epoch,
            &allocation.bls_public_key,
        ])
    } else {
        hash_fields_bytes(&[
            domain_tag,
            &tag,
            allocation.budlum_validator.as_bytes(),
            &allocation.eth_operator,
            &units,
            &epoch,
            &allocation.bls_public_key,
        ])
    }
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
            let domain = state
                .settlement
                .domains
                .get(*domain_key)
                .ok_or_else(|| refused("Mikoriza registrar names an unregistered domain"))?;
            if domain.status != crate::domain::types::DomainStatus::Active {
                return Err(refused(
                    "shared-security registrar names an inactive domain",
                ));
            }
            if domain.operator != Some(ctx.sender) {
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

fn is_cosmos_ics_eligible_domain(domain: &crate::domain::types::ConsensusDomain) -> bool {
    match &domain.kind {
        crate::domain::types::ConsensusKind::Bft => true,
        crate::domain::types::ConsensusKind::Custom(label) => label == "tendermint-bft",
        _ => false,
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
    let domain = state
        .settlement
        .domains
        .get(domain_key)
        .ok_or_else(|| refused("shared-security observation names an unregistered domain"))?;
    if domain.status != crate::domain::types::DomainStatus::Active {
        return Err(refused(
            "shared-security observation names an inactive domain",
        ));
    }
    if matches!(source, RestakeSource::CosmosIcs { .. }) && !is_cosmos_ics_eligible_domain(domain) {
        return Err(refused(
            "CosmosIcs allocation requires an active Tendermint/BFT settlement domain",
        ));
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
    let attested_on = source.external_chain();
    if evidence.chain != attested_on {
        return Err(refused(format!(
            "Mikoriza allocation is claimed from {source:?}, which attests on {attested_on:?}, \
             but the evidence comes from {:?}",
            evidence.chain
        )));
    }
    if state
        .settlement
        .shared_security
        .is_operator_slashed(source, &allocation.eth_operator)
    {
        return Err(refused(
            "shared-security operator is permanently slashed for proven consensus misbehaviour",
        ));
    }
    if state
        .settlement
        .shared_security
        .validators
        .values()
        .any(|row| {
            row.status == RestakeStatus::Slashed
                && row.source.external_chain() == attested_on
                && row.bls_public_key == allocation.bls_public_key
        })
    {
        return Err(refused(
            "shared-security consensus BLS key is permanently slashed on this external chain",
        ));
    }
    if allocation.allocated_units > 0
        && state
            .settlement
            .shared_security
            .validators
            .values()
            .any(|row| {
                row.budlum_validator != allocation.budlum_validator
                    && row.status == RestakeStatus::Active
                    && row.bls_public_key == allocation.bls_public_key
                    && (row.source != source || row.eth_operator != allocation.eth_operator)
            })
    {
        return Err(refused(
            "shared-security consensus BLS key is already bound to another active operator or source",
        ));
    }
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
        || message.sender != crate::settlement::app_binding::origin_emitter(&registrar)
        || message.recipient != allocation.budlum_validator
        || message.correlation_id != Some(operator_correlation(&allocation.eth_operator))
        || message.payload_hash != adapter.allocation_payload_hash(allocation)
    {
        return Err(refused(
            "Mikoriza event does not bind the registrar, the validator and the allocation",
        ));
    }
    let message_id = message.message_id;
    let attested_at = state.epoch_index;
    let op_key = source.operator_map_key(&allocation.eth_operator);
    let registry = &mut state.settlement.shared_security;
    if registry.used_messages.contains(&message_id) {
        return Err(refused("Mikoriza allocation event has already been used"));
    }
    if registry.used_messages.len() >= MAX_USED_ALLOCATION_MESSAGES {
        return Err(refused("Mikoriza replay set is full"));
    }
    // Enforce strict per-(source, eth_operator) epoch monotonicity across ALL
    // validators so an unconsumed older operator event cannot silently retire a
    // newer live allocation after the operator moved to another validator.
    if let Some(prev_op_epoch) = registry.highest_operator_epoch(source, &allocation.eth_operator) {
        if allocation.observed_epoch <= prev_op_epoch {
            return Err(refused(
                "shared-security allocation epoch is not newer than the operator's recorded epoch",
            ));
        }
    }
    let validator_exists =
        if let Some(previous) = registry.validators.get(&allocation.budlum_validator) {
            if previous.status == RestakeStatus::Slashed
                && previous.source == source
                && previous.eth_operator == allocation.eth_operator
            {
                return Err(refused(
                    "shared-security validator backing is permanently slashed",
                ));
            }
            if allocation.observed_epoch <= previous.observed_epoch {
                return Err(refused(
                    "Mikoriza allocation is not newer than the recorded one",
                ));
            }
            true
        } else {
            false
        };
    let operator_has_other_active = registry.validators.values().any(|row| {
        row.budlum_validator != allocation.budlum_validator
            && row.source == source
            && row.eth_operator == allocation.eth_operator
            && row.status == RestakeStatus::Active
    });
    // Refuse cold zero-unit observations (where neither the target validator
    // nor the operator holds any live row) so zero-stake events cannot squat
    // and exhaust MAX_RESTAKED_VALIDATORS.
    if allocation.allocated_units == 0 && !validator_exists && !operator_has_other_active {
        return Err(refused(
            "shared-security zero-unit allocation retires no live validator or operator binding",
        ));
    }
    if !validator_exists && registry.validators.len() >= MAX_RESTAKED_VALIDATORS {
        return Err(refused("Mikoriza validator table is full"));
    }
    if !registry.operator_epochs.contains_key(&op_key)
        && registry.operator_epochs.len() >= MAX_USED_ALLOCATION_MESSAGES
    {
        return Err(refused("shared-security operator epoch table is full"));
    }

    registry.used_messages.insert(message_id);
    registry
        .operator_epochs
        .insert(op_key, allocation.observed_epoch);
    for row in registry.validators.values_mut() {
        if row.budlum_validator != allocation.budlum_validator
            && row.source == source
            && row.eth_operator == allocation.eth_operator
            && row.status == RestakeStatus::Active
        {
            row.status = RestakeStatus::Exited;
            row.allocated_units = 0;
        }
    }
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
    registry
        .attested_at
        .insert(allocation.budlum_validator, attested_at);
    Ok(())
}

/// Verify ICS-07 `CometBFT` misbehaviour and slash culpable restaked operators.
///
/// Runs full IBC ICS-07 misbehaviour verification through a pinned
/// [`crate::cross_domain::external::tendermint::TendermintLightClient`],
/// transitions every culpable `CosmosIcs { domain_id: domain_key }` operator to
/// [`RestakeStatus::Slashed`], zeroes its `allocated_units` and live
/// `Validator.restaked_weight`, and writes an immutable [`ExternalSlashRecord`]
/// permanently quarantining future re-entry.
///
/// # Errors
///
/// Returns [`SettlementTxError::Refused`] if shared security is disabled, the
/// domain is unregistered or inactive, the ICS-07 proof fails verification, or
/// no proven culprit holds an active `CosmosIcs` allocation on `domain_key`.
///
/// Convenience: kept for the CLI and IBC Interchain Security slash relayers.
pub fn execute_tendermint_misbehaviour_slash(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    domain_key: u32,
    trusted: &crate::cross_domain::external::tendermint::TrustedTendermintState,
    light_params: &crate::cross_domain::external::tendermint::TendermintLightParams,
    misbehaviour: &crate::cross_domain::external::tendermint::TendermintMisbehaviour,
    now_secs: u64,
) -> Result<Vec<ExternalSlashRecord>, SettlementTxError> {
    use crate::cross_domain::external::tendermint::{
        validator_set_hash, TendermintLightClient, TendermintLightParams,
    };

    let params = crate::core::chain_config::shared_security_for_chain_id(ctx.chain_id);
    if !params.enabled {
        return Err(refused(
            "shared security is not enabled at this chain's genesis",
        ));
    }
    let domain = state
        .settlement
        .domains
        .get(domain_key)
        .ok_or_else(|| refused("Tendermint slash names an unregistered domain"))?;
    if domain.status != crate::domain::types::DomainStatus::Active
        || !is_cosmos_ics_eligible_domain(domain)
    {
        return Err(refused(
            "Tendermint slash requires an active Tendermint/BFT settlement domain",
        ));
    }
    let _ = TendermintLightParams::standard_for_unbonding(light_params.unbonding_period_secs)
        .map_err(|e| refused(format!("Tendermint unbonding period rejected: {e}")))?;
    let anchor_root = validator_set_hash(&trusted.validators);
    let mut client =
        TendermintLightClient::new(trusted.clone(), anchor_root, anchor_root, *light_params)
            .map_err(|e| refused(format!("Tendermint trusted anchor rejected: {e}")))?;
    if client.consensus_state(trusted.height).is_none() {
        return Err(refused(
            "Tendermint light client missing pinned trusted height",
        ));
    }
    let verified = client
        .submit_misbehaviour(misbehaviour, now_secs)
        .map_err(|e| refused(format!("Tendermint ICS-07 misbehaviour rejected: {e}")))?;

    let source = RestakeSource::CosmosIcs {
        domain_id: domain_key,
    };
    let culprit_addrs: BTreeSet<[u8; 20]> = verified.culprits.iter().map(|v| v.address).collect();
    let infraction_height = verified.header_1_height.min(verified.header_2_height);
    let epoch = state.epoch_index;

    // Pre-check match count and capacity before mutating any state.
    let targets: Vec<Address> = state
        .settlement
        .shared_security
        .validators
        .iter()
        .filter(|(_, row)| {
            row.source == source
                && row.status == RestakeStatus::Active
                && culprit_addrs.contains(&row.eth_operator)
        })
        .map(|(addr, _)| *addr)
        .collect();
    if targets.is_empty() {
        return Err(refused(
            "verified Tendermint misbehaviour matches no active unslashed shared-security operator",
        ));
    }
    let chain = source.external_chain();
    let mut correlated_sources: Vec<RestakeSource> = ALL_RESTAKE_SOURCES
        .iter()
        .copied()
        .filter(|candidate| candidate.external_chain() == chain)
        .collect();
    if !correlated_sources.contains(&source) {
        correlated_sources.push(source);
    }
    let new_quarantine_keys = correlated_sources
        .iter()
        .flat_map(|candidate| {
            culprit_addrs
                .iter()
                .map(move |op| candidate.operator_map_key(op))
        })
        .filter(|key| {
            !state
                .settlement
                .shared_security
                .slashed_operators
                .contains_key(key)
        })
        .count();
    if state
        .settlement
        .shared_security
        .slashed_operators
        .len()
        .saturating_add(new_quarantine_keys)
        > MAX_RESTAKED_VALIDATORS
    {
        return Err(refused("shared-security slash quarantine table is full"));
    }

    // Capture the named targets' forfeited units BEFORE the correlation pass
    // zeroes them: the receipt must report what was taken, not what is left.
    let target_units: Vec<(Address, [u8; 20], u64)> = targets
        .iter()
        .filter_map(|addr| {
            state
                .settlement
                .shared_security
                .validators
                .get(addr)
                .map(|row| (*addr, row.eth_operator, row.allocated_units))
        })
        .collect();

    // A verified slashing event on one source must also quarantine every source
    // that settles on the SAME external chain: EigenLayer and Symbiotic both
    // take the operator's own ETH, so slashing one and leaving the other live
    // would let the BFT restaking cap count the same free collateral twice.
    // This runs before the per-target copy and is what zeroes correlated rows
    // the evidence never named.
    let culprits: Vec<[u8; 20]> = culprit_addrs.iter().copied().collect();
    let _correlated_keys =
        quarantine_correlated_sources(state, source, &culprits, RestakeStatus::Slashed);

    let mut records = Vec::with_capacity(targets.len());
    for (val_addr, op, slashed_units) in target_units {
        if let Some(row) = state
            .settlement
            .shared_security
            .validators
            .get_mut(&val_addr)
        {
            row.allocated_units = 0;
            row.status = RestakeStatus::Slashed;
            let rec = ExternalSlashRecord {
                source,
                operator: op,
                budlum_validator: val_addr,
                slashed_units,
                kind: verified.kind,
                infraction_height,
                slashed_at_epoch: epoch,
                evidence_id: verified.evidence_id,
            };
            state
                .settlement
                .shared_security
                .slashed_operators
                .insert(source.operator_map_key(&op), rec.clone());
            records.push(rec);
        }
        if let Some(val) = state.validators.get_mut(&val_addr) {
            val.restaked_weight = 0;
        }
    }
    Ok(records)
}

/// Record `sources` as permanently slashed for each operator in `operators`.
///
/// # Why this is not a loop over `sources`
///
/// The BFT-safety cap (`SHARED_SECURITY_MAX_SAFE_BFT_RESTAKED_SHARE_PPM`) bounds
/// restaked weight at `< 1/3` of the committee by capping the **sum over
/// sources**. That arithmetic only buys safety if the sources are *independent
/// fault domains*. They are not: `RestakeSource::external_chain` maps
/// `EigenLayer` and `Symbiotic` to the same `ExternalChain::Ethereum`, because
/// both take the operator's own ETH as the free downside. One verified slashing
/// event on Ethereum therefore removes every same-chain source at once.
///
/// Quarantining only the source named in the evidence would leave the sibling
/// source live and its weight counted, i.e. the cap would count the same free
/// collateral twice. So an operator slashed on a chain is quarantined on
/// **every source that settles on that chain**; a different chain (Bitcoin,
/// another ICS domain) is a different downside and is left untouched.
///
/// Returns the number of `(source, operator)` quarantine keys newly written.
pub fn quarantine_correlated_sources(
    state: &mut AccountState,
    slashed_source: RestakeSource,
    operators: &[[u8; 20]],
    status: RestakeStatus,
) -> usize {
    let chain = slashed_source.external_chain();
    let mut correlated: Vec<RestakeSource> = ALL_RESTAKE_SOURCES
        .iter()
        .copied()
        .filter(|source| source.external_chain() == chain)
        .collect();
    if !correlated.contains(&slashed_source) {
        correlated.push(slashed_source);
    }
    let mut written = 0usize;
    for source in correlated {
        for operator in operators {
            let key = source.operator_map_key(operator);
            if state
                .settlement
                .shared_security
                .slashed_operators
                .contains_key(&key)
            {
                continue;
            }
            state.settlement.shared_security.slashed_operators.insert(
                key,
                ExternalSlashRecord {
                    source,
                    operator: *operator,
                    budlum_validator: Address::from([0u8; 32]),
                    slashed_units: 0,
                    // The evidence proved equivocation; the correlated source
                    // inherits the same class because the same key, on the same
                    // chain, took the same free downside.
                    kind: crate::cross_domain::external::tendermint::TendermintMisbehaviourKind::DoubleSignEquivocation,
                    infraction_height: 0,
                    slashed_at_epoch: state.epoch_index,
                    // Deterministic, chain-scoped domain tag: the same
                    // evidence is what quarantines the correlated source.
                    evidence_id: crate::core::hash::hash_fields_bytes(&[
                        b"BDLM_SHARED_SECURITY_CORRELATED_SLASH_V1",
                        &[slashed_source.tag()],
                        operator,
                    ]),
                },
            );
            written += 1;
        }
    }
    // Every active row of a correlated source for these operators loses its
    // weight at the next boundary, including rows the evidence never named.
    for (address, row) in &mut state.settlement.shared_security.validators {
        if row.status == RestakeStatus::Active
            && row.source.external_chain() == chain
            && operators.contains(&row.eth_operator)
        {
            row.allocated_units = 0;
            row.status = status;
            if let Some(validator) = state.validators.get_mut(address) {
                validator.restaked_weight = 0;
            }
        }
    }
    written
}

/// Every restaking source Budlum reads, for chain-correlation reasoning.
pub const ALL_RESTAKE_SOURCES: [RestakeSource; 3] = [
    RestakeSource::EigenLayer,
    RestakeSource::Symbiotic,
    RestakeSource::Babylon,
];

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
        let mut eligible_rows: Vec<(
            Address,
            crate::core::transaction::ExternalChain,
            [u8; 20],
            u64,
        )> = Vec::new();
        let mut group_totals: BTreeMap<
            (crate::core::transaction::ExternalChain, [u8; 20]),
            (u128, u128),
        > = BTreeMap::new();
        for (address, row) in &state.settlement.shared_security.validators {
            if row.status != RestakeStatus::Active {
                continue;
            }
            // A row is a claim about collateral that is free to move on the
            // other chain, and nothing here re-reads that chain. The
            // attestation therefore expires and the weight with it; a row with
            // no recorded attestation epoch is not counted, so restored state
            // fails closed.
            let Some(attested) = state
                .settlement
                .shared_security
                .attested_at
                .get(address)
                .copied()
            else {
                continue;
            };
            if epoch.saturating_sub(attested) > MAX_ALLOCATION_AGE_EPOCHS {
                continue;
            }
            // The row must also name the key the validator registered. The
            // `Observe` door can only compare keys when the validator exists
            // already, so an allocation claimed before the validator registers
            // - or while it is bonded without consensus keys - was stored with
            // whatever key the claiming operator chose, and nothing looked at
            // it again. The registry lets an Ethereum-side operator bind any
            // key to any validator address, so that row credited the
            // validator's voting weight to an operator that does not run it,
            // and the ETH behind it was never slashable: the slasher checks
            // double votes against the operator's bound key, not the
            // validator's. The comparison lives here because this is where the
            // registered key is known.
            let counts = state.validators.get(address).is_some_and(|v| {
                v.is_eligible(epoch) && !v.slashed && v.bls_public_key == row.bls_public_key
            });
            if counts {
                let row_weight = params.weight_of_units(row.allocated_units);
                let chain = row.source.external_chain();
                let entry = group_totals
                    .entry((chain, row.eth_operator))
                    .or_insert((0u128, 0u128));
                entry.0 = entry.0.saturating_add(u128::from(row_weight));
                entry.1 = entry.1.max(u128::from(row_weight));
                eligible_rows.push((*address, chain, row.eth_operator, row_weight));
            }
        }
        // Cap same-(external_chain, eth_operator) total weight at that operator's
        // largest single-source allocation on that chain so registering both
        // EigenLayer and Symbiotic against the same free-downside ETH collateral
        // cannot multiply BFT voting weight before slashing occurs.
        for (address, chain, operator, row_weight) in eligible_rows {
            let deduplicated = match group_totals.get(&(chain, operator)).copied() {
                Some((group_sum, group_max)) if group_sum > group_max && group_sum > 0 => {
                    let scaled = u128::from(row_weight) * group_max / group_sum;
                    u64::try_from(scaled).unwrap_or(u64::MAX)
                }
                _ => row_weight,
            };
            raw.insert(address, deduplicated);
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
                sender: crate::settlement::app_binding::origin_emitter(&REGISTRAR),
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
        let mut domain = crate::domain::plugin::default_domain(
            DOMAIN,
            crate::domain::ConsensusKind::PoW,
            45262,
            crate::domain::POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        domain.domain_chain_id = 1;
        domain.operator = Some(operator);
        state.add_balance(&operator, domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, domain).expect("domain");
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let testnet = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        let err = execute_shared_security_tx(
            &mut state,
            &ctx(operator, mainnet),
            &SharedSecurityTx::SetRegistrar {
                domain_key: DOMAIN,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not enabled"), "{err}");
        let testnet_err = execute_shared_security_tx(
            &mut state,
            &ctx(operator, testnet),
            &SharedSecurityTx::SetRegistrar {
                domain_key: DOMAIN,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .unwrap_err();
        assert!(
            testnet_err.to_string().contains("not enabled"),
            "{testnet_err}"
        );
        assert!(execute_shared_security_tx(
            &mut state,
            &ctx(operator, devnet()),
            &SharedSecurityTx::SetRegistrar {
                domain_key: DOMAIN,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .is_ok());
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

    /// The companion of the registrar fix: the first Ethereum operator
    /// recorded for a validator used to own it for good, so a report from the
    /// operator the validator moved to was refused forever. The row now
    /// follows the newest attested claim.
    #[test]
    fn a_newer_allocation_may_name_another_ethereum_operator() {
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let validator = Address::from([2u8; 32]);
        let carrier = Address::from([3u8; 32]);
        let first = claim(validator, 1_000, 5);
        let tx = observe_tx(&mut state, &first, 0);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).expect("records");

        let mut moved = claim(validator, 1_000, 6);
        moved.eth_operator = [0x0B; 20];
        let tx = observe_tx(&mut state, &moved, 1);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx)
            .expect("the newest claim is the validator's");

        let row = state
            .settlement
            .shared_security
            .active(&validator)
            .expect("active");
        assert_eq!(row.eth_operator, [0x0B; 20]);
        assert_eq!(row.observed_epoch, 6);
    }

    /// A move is the operator's own: when its next attested report names
    /// another validator, the row it left behind stops backing the validator,
    /// so one allocation never carries restaked weight twice.
    #[test]
    fn a_move_retires_the_validator_the_operator_left() {
        let operator = Address::from([1u8; 32]);
        let mut state = state_with_registrar(operator);
        let carrier = Address::from([3u8; 32]);
        let left = Address::from([2u8; 32]);
        let moved_to = Address::from([4u8; 32]);
        let tx = observe_tx(&mut state, &claim(left, 1_000, 5), 0);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).expect("records");
        let tx = observe_tx(&mut state, &claim(moved_to, 1_000, 6), 1);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx).expect("moves");

        assert!(state.settlement.shared_security.active(&left).is_none());
        assert!(state.settlement.shared_security.active(&moved_to).is_some());

        // Only the validator the operator still backs carries restaked weight.
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: 1_000_000,
            units_to_weight_ppm: 1_000_000,
        };
        for tag in [2u8, 4u8] {
            let address = Address::from([tag; 32]);
            let mut validator = Validator::new(address, 1_000);
            validator.active = true;
            // The consensus key the allocation names: weight is credited only
            // to the validator that registered the key the row carries, so a
            // fixture without keys would be testing the lax rule.
            validator.bls_public_key = vec![0xB1; BLS_PUBLIC_KEY_BYTES];
            state.validators.insert(address, validator);
        }
        apply_restaked_weights(&mut state, &params);
        assert_eq!(state.validators[&left].restaked_weight, 0);
        assert!(state.validators[&moved_to].restaked_weight > 0);

        // Moving again with zero allocated units (operator rebind + unstake in
        // one Ethereum epoch) must also retire `moved_to`.
        let zero_dest = Address::from([6u8; 32]);
        let tx = observe_tx(&mut state, &claim(zero_dest, 0, 7), 2);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx)
            .expect("zero-unit move records");
        assert!(state.settlement.shared_security.active(&moved_to).is_none());
        assert!(state
            .settlement
            .shared_security
            .active(&zero_dest)
            .is_none());
        apply_restaked_weights(&mut state, &params);
        assert_eq!(state.validators[&moved_to].restaked_weight, 0);
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
        let mut foreign = honest;
        foreign.chain = crate::core::transaction::ExternalChain::Custom(DOMAIN);
        // Re-anchor the forged evidence so only the chain binding can refuse it.
        let leaf = foreign.result_leaf();
        let mut proof = foreign;
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
                state
                    .settlement
                    .shared_security
                    .attested_at
                    .insert(address, state.epoch_index);
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

    /// Restaked weight needs the validator's own BLS key, not just an
    /// allocation row naming it.
    ///
    /// The `Observe` door compares keys when the validator already exists. An
    /// allocation claimed before the validator registers - or while it is
    /// bonded without consensus keys - is therefore stored with whatever key
    /// its claimant chose, and the Ethereum registrar lets an operator bind any
    /// key to any validator address. Crediting that row handed the claiming
    /// operator restaked weight towards a validator it does not run, and the
    /// ETH behind the allocation was never slashable: the slasher checks double
    /// votes against the operator's bound key, not the validator's.
    #[test]
    fn restaked_weight_needs_the_validators_own_bls_key() {
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: 1_000_000,
            units_to_weight_ppm: 1_000_000,
        };
        let mut state = AccountState::new();
        let named_key = vec![0xB1; BLS_PUBLIC_KEY_BYTES];
        let other_key = vec![0xC2; BLS_PUBLIC_KEY_BYTES];
        for (tag, registered_key) in [(1u8, named_key.clone()), (2, other_key)] {
            let address = Address::from([tag; 32]);
            let mut validator = Validator::new(address, 1_000);
            validator.active = true;
            validator.bls_public_key = registered_key;
            state.validators.insert(address, validator);
            state.settlement.shared_security.validators.insert(
                address,
                RestakedValidator {
                    budlum_validator: address,
                    eth_operator: [tag; 20],
                    allocated_units: 10_000,
                    source: RestakeSource::EigenLayer,
                    observed_epoch: 1,
                    status: RestakeStatus::Active,
                    bls_public_key: named_key.clone(),
                },
            );
            state
                .settlement
                .shared_security
                .attested_at
                .insert(address, state.epoch_index);
        }

        apply_restaked_weights(&mut state, &params);

        let matching = state.validators[&Address::from([1u8; 32])].restaked_weight;
        let mismatched = state.validators[&Address::from([2u8; 32])].restaked_weight;
        assert!(
            matching > 0,
            "the validator that registered the key is credited"
        );
        assert_eq!(
            mismatched, 0,
            "a validator registered under another key is not credited with weight it cannot be slashed for"
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

    #[test]
    fn restaked_weight_expires_past_freshness_window_and_resumes_on_refresh() {
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: 300_000,
            units_to_weight_ppm: 1_000_000,
        };
        let mut state = AccountState::new();
        let addr = Address::from([0x44; 32]);
        let key = vec![0xB1; BLS_PUBLIC_KEY_BYTES];
        let mut validator = Validator::new(addr, 1_000);
        validator.active = true;
        validator.bls_public_key = key.clone();
        state.validators.insert(addr, validator);
        state.settlement.shared_security.validators.insert(
            addr,
            RestakedValidator {
                budlum_validator: addr,
                eth_operator: [0x11; 20],
                allocated_units: 10_000,
                source: RestakeSource::EigenLayer,
                observed_epoch: 1,
                status: RestakeStatus::Active,
                bls_public_key: key,
            },
        );
        // Unstamped row fails closed.
        apply_restaked_weights(&mut state, &params);
        assert_eq!(state.validators[&addr].restaked_weight, 0);

        // Stamped at epoch 5: counts up to 5 + MAX_ALLOCATION_AGE_EPOCHS, expires past it.
        state.epoch_index = 5;
        state.settlement.shared_security.attested_at.insert(addr, 5);
        apply_restaked_weights(&mut state, &params);
        assert!(state.validators[&addr].restaked_weight > 0);

        state.epoch_index = 5 + MAX_ALLOCATION_AGE_EPOCHS;
        apply_restaked_weights(&mut state, &params);
        assert!(state.validators[&addr].restaked_weight > 0);

        state.epoch_index = 5 + MAX_ALLOCATION_AGE_EPOCHS + 1;
        apply_restaked_weights(&mut state, &params);
        assert_eq!(state.validators[&addr].restaked_weight, 0);

        // Re-attesting at the current epoch restores weight.
        state
            .settlement
            .shared_security
            .attested_at
            .insert(addr, state.epoch_index);
        apply_restaked_weights(&mut state, &params);
        assert!(state.validators[&addr].restaked_weight > 0);
    }

    fn anchored_for_source(
        state: &mut AccountState,
        domain_key: u32,
        registrar: &[u8],
        source: RestakeSource,
        allocation: &AllocationClaim,
        nonce: u64,
    ) -> Box<RelayerExternalResult> {
        let message = CrossDomainMessage::new_correlated(
            CrossDomainMessageParams {
                source_domain: domain_key,
                target_domain: 1,
                source_height: 10 + nonce,
                event_index: 0,
                nonce,
                sender: crate::settlement::app_binding::origin_emitter(registrar),
                recipient: allocation.budlum_validator,
                payload_hash: allocation_payload_hash(source, allocation),
                kind: MessageKind::Custom(ALLOCATION_KIND.to_vec()),
                expiry_height: 0,
            },
            operator_correlation(&allocation.eth_operator),
        );
        let mut result = RelayerExternalResult {
            chain: source.external_chain(),
            tx_hash: format!("0x{nonce:04x}"),
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
        assert!(state.anchor_external_root(domain_key, leaf));
        Box::new(result)
    }

    #[test]
    fn stale_epoch_replay_refuses_to_exit_newer_operator_rebind() {
        let operator = Address::from([1u8; 32]);
        let carrier = Address::from([3u8; 32]);
        let mut state = state_with_registrar(operator);
        let val_a = Address::from([0xA1; 32]);
        let val_b = Address::from([0xB2; 32]);

        // Operator binds to val_b at epoch 50 first.
        let newer = claim(val_b, 50_000, 50);
        let newer_tx = observe_tx(&mut state, &newer, 1);
        execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &newer_tx)
            .expect("newer epoch 50 records");

        // Attacker replays an unconsumed historical event for val_a from epoch 10 (< 50):
        // MUST fail closed and keep val_b's epoch-50 allocation Active!
        let stale = claim(val_a, 1_000, 10);
        let stale_tx = observe_tx(&mut state, &stale, 2);
        let err = execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &stale_tx)
            .expect_err("stale operator epoch replay must be refused");
        assert!(matches!(err, SettlementTxError::Refused(_)));
        assert_eq!(
            state
                .settlement
                .shared_security
                .active(&val_b)
                .expect("val_b stays live")
                .allocated_units,
            50_000
        );
        assert!(!state
            .settlement
            .shared_security
            .validators
            .contains_key(&val_a));
    }

    #[test]
    fn cold_zero_unit_allocation_refuses_to_squat_registry_slot() {
        let operator = Address::from([1u8; 32]);
        let carrier = Address::from([3u8; 32]);
        let mut state = state_with_registrar(operator);
        let squat_val = Address::from([0xC3; 32]);
        let zero = claim(squat_val, 0, 1);
        let tx = observe_tx(&mut state, &zero, 99);
        let err = execute_shared_security_tx(&mut state, &ctx(carrier, devnet()), &tx)
            .expect_err("cold zero-unit allocation must not squat registry slot");
        assert!(matches!(err, SettlementTxError::Refused(_)));
        assert!(state.settlement.shared_security.validators.is_empty());
    }

    /// A single real-world operator must not multiply a *free* downside across
    /// sources that settle on the **same external chain**.
    ///
    /// The BFT-safety cap guarantees `restaked weight < 1/3` of the committee by
    /// capping the sum over sources. That arithmetic assumes the sources are
    /// independent. `EigenLayer` and `Symbiotic` are not: both settle on
    /// Ethereum, and one operator key can take the same free ETH downside behind
    /// both. A single Ethereum slashing event removes *every* source at once, so
    /// the real independence behind the weight is one chain, not `k` protocols.
    ///
    /// `RestakeSource::external_chain` already models this correlation; this test
    /// requires the quarantine table to honour it too.
    #[test]
    fn one_operator_cannot_multiply_free_downside_across_same_chain_sources() {
        let op = [0x0A; 20];
        let val_eigen = Address::from([0x61; 32]);
        let val_symbiotic = Address::from([0x62; 32]);
        let val_babylon = Address::from([0x63; 32]);
        let mut state = AccountState::new();
        // Committee members exist; the attack is about *whose* weight counts.
        for tag in [0x61u8, 0x62u8, 0x63u8] {
            let address = Address::from([tag; 32]);
            let mut v = Validator::new(address, 1_000_000);
            v.active = true;
            v.bls_public_key = vec![0xB1; BLS_PUBLIC_KEY_BYTES];
            state.validators.insert(address, v);
        }
        for (source, validator) in [
            (RestakeSource::EigenLayer, val_eigen),
            (RestakeSource::Symbiotic, val_symbiotic),
            (RestakeSource::Babylon, val_babylon),
        ] {
            state.settlement.shared_security.validators.insert(
                validator,
                RestakedValidator {
                    budlum_validator: validator,
                    eth_operator: op,
                    allocated_units: 10_000,
                    source,
                    observed_epoch: 5,
                    status: RestakeStatus::Active,
                    bls_public_key: vec![0xB1; BLS_PUBLIC_KEY_BYTES],
                },
            );
        }

        // One verified Ethereum-side slashing event for `op` on the EigenLayer
        // registrar. It names the EigenLayer source only.
        let records = quarantine_correlated_sources(
            &mut state,
            RestakeSource::EigenLayer,
            &[op],
            RestakeStatus::Slashed,
        );

        assert!(
            state
                .settlement
                .shared_security
                .is_operator_slashed(RestakeSource::EigenLayer, &op),
            "the slashed source is quarantined"
        );
        assert!(
            state
                .settlement
                .shared_security
                .is_operator_slashed(RestakeSource::Symbiotic, &op),
            "the same key on the same chain was quarantined too, records={records}"
        );
        assert!(
            !state
                .settlement
                .shared_security
                .is_operator_slashed(RestakeSource::Babylon, &op),
            "a different chain (Bitcoin) is a different downside and must survive"
        );
        let params = SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: MAX_SAFE_BFT_RESTAKED_SHARE_PPM,
            units_to_weight_ppm: 1_000_000,
        };
        apply_restaked_weights(&mut state, &params);
        assert_eq!(
            state.validators[&val_eigen].restaked_weight, 0,
            "the slashed source carries no weight"
        );
        assert_eq!(
            state.validators[&val_symbiotic].restaked_weight, 0,
            "the correlated source must carry no weight either: same ETH"
        );
    }

    #[test]
    fn multi_source_symbiotic_babylon_and_inactive_domain_guard_enforce_invariants() {
        let eth_op = Address::from([0x21; 32]);
        let btc_op = Address::from([0x22; 32]);
        let carrier = Address::from([0x23; 32]);
        let mut state = state_with_registrar(eth_op);

        // Verify < 1/3 BFT restaking cap helper.
        assert!(SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: MAX_SAFE_BFT_RESTAKED_SHARE_PPM,
            units_to_weight_ppm: 1_000_000,
        }
        .respects_bft_safety_cap());
        assert!(!SharedSecurityParams {
            enabled: true,
            max_restaked_share_ppm: MAX_SAFE_BFT_RESTAKED_SHARE_PPM + 1,
            units_to_weight_ppm: 1_000_000,
        }
        .respects_bft_safety_cap());

        // Symbiotic settles on Ethereum (domain 1) with distinct payload domain tag.
        let val_sym = Address::from([0x31; 32]);
        let sym_claim = AllocationClaim {
            budlum_validator: val_sym,
            eth_operator: [0x51; 20],
            allocated_units: 25_000,
            observed_epoch: 7,
            bls_public_key: vec![0xB2; BLS_PUBLIC_KEY_BYTES],
        };
        assert_ne!(
            allocation_payload_hash(RestakeSource::Symbiotic, &sym_claim),
            allocation_payload_hash(RestakeSource::EigenLayer, &sym_claim)
        );
        let sym_ev = anchored_for_source(
            &mut state,
            DOMAIN,
            &REGISTRAR,
            RestakeSource::Symbiotic,
            &sym_claim,
            10,
        );
        execute_shared_security_tx(
            &mut state,
            &ctx(carrier, devnet()),
            &SharedSecurityTx::Observe {
                domain_key: DOMAIN,
                source: RestakeSource::Symbiotic,
                allocation: sym_claim,
                evidence: sym_ev,
            },
        )
        .expect("Symbiotic allocation records");

        // Register Bitcoin domain (id = 2) for Babylon BTC staking.
        let btc_domain_id = crate::core::transaction::ExternalChain::Bitcoin.domain_id();
        let mut btc_domain = crate::domain::plugin::default_domain(
            btc_domain_id,
            crate::domain::ConsensusKind::PoW,
            20_002,
            crate::domain::POW_HEADER_CHAIN_ADAPTER,
            6,
        );
        btc_domain.operator = Some(btc_op);
        state.add_balance(&btc_op, btc_domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, btc_domain).expect("btc domain");
        let btc_reg = [0xBBu8; 20];
        execute_shared_security_tx(
            &mut state,
            &ctx(btc_op, devnet()),
            &SharedSecurityTx::SetRegistrar {
                domain_key: btc_domain_id,
                registrar: btc_reg.to_vec(),
            },
        )
        .expect("btc registrar");

        let val_bab = Address::from([0x32; 32]);
        let bab_claim = AllocationClaim {
            budlum_validator: val_bab,
            eth_operator: [0x61; 20],
            allocated_units: 40_000,
            observed_epoch: 12,
            bls_public_key: vec![0xB3; BLS_PUBLIC_KEY_BYTES],
        };
        let bab_ev = anchored_for_source(
            &mut state,
            btc_domain_id,
            &btc_reg,
            RestakeSource::Babylon,
            &bab_claim,
            11,
        );
        execute_shared_security_tx(
            &mut state,
            &ctx(carrier, devnet()),
            &SharedSecurityTx::Observe {
                domain_key: btc_domain_id,
                source: RestakeSource::Babylon,
                allocation: bab_claim,
                evidence: bab_ev,
            },
        )
        .expect("Babylon BTC allocation records");
        assert_eq!(
            state
                .settlement
                .shared_security
                .active(&val_bab)
                .expect("babylon active")
                .source,
            RestakeSource::Babylon
        );

        // Freezing a settlement domain blocks both SetRegistrar and Observe fail-closed.
        if let Some(dom) = state.settlement.domains.get_mut(DOMAIN) {
            dom.status = crate::domain::types::DomainStatus::Frozen;
        }
        assert!(matches!(
            execute_shared_security_tx(
                &mut state,
                &ctx(eth_op, devnet()),
                &SharedSecurityTx::SetRegistrar {
                    domain_key: DOMAIN,
                    registrar: vec![0xAA; 20],
                },
            ),
            Err(SettlementTxError::Refused(_))
        ));
    }

    #[test]
    fn cosmos_ics_misbehaviour_slashes_only_culprit_and_quarantines_reentry() {
        use crate::cross_domain::external::tendermint::{
            validator_address_of, validator_set_hash, vote_sign_bytes, TendermintCommitEvidence,
            TendermintLightParams, TendermintMisbehaviour, TendermintMisbehaviourKind,
            TendermintSignature, TendermintValidator, TrustedTendermintState,
        };
        use crate::crypto::primitives::KeyPair;

        let dom_id = 777u32;
        let dom_op = Address::from([0x41; 32]);
        let carrier = Address::from([0x42; 32]);
        let mut state = AccountState::new();
        let mut domain = crate::domain::plugin::default_domain(
            dom_id,
            crate::domain::ConsensusKind::Custom("tendermint-bft".to_string()),
            777_001,
            crate::cross_domain::external::EXTERNAL_DOMAIN_FINALITY_ADAPTER,
            1,
        );
        domain.operator = Some(dom_op);
        domain.plugin_code_hash = Some([0x77; 32]);
        state.add_balance(&dom_op, domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, domain).expect("tm domain");

        let ics_reg = [0xCCu8; 20];
        execute_shared_security_tx(
            &mut state,
            &ctx(dom_op, devnet()),
            &SharedSecurityTx::SetRegistrar {
                domain_key: dom_id,
                registrar: ics_reg.to_vec(),
            },
        )
        .expect("ics registrar");

        // 4 CometBFT provider validators (keys 0..4, 100 power each).
        let keys: Vec<KeyPair> = (60u8..=63)
            .map(|s| KeyPair::from_seed(&[s; 32]).expect("key"))
            .collect();
        let tm_vals: Vec<TendermintValidator> = keys
            .iter()
            .map(|k| {
                let pk = k.public_key_bytes();
                TendermintValidator {
                    address: validator_address_of(&pk),
                    public_key: pk,
                    voting_power: 100,
                }
            })
            .collect();

        // Register two CosmosIcs allocations:
        // - honest_val backed by tm_vals[0] (signs only fork A -> MUST STAY ACTIVE!)
        // - culprit_val backed by tm_vals[1] (signs BOTH fork A and fork B -> MUST BE SLASHED!)
        let source = RestakeSource::CosmosIcs { domain_id: dom_id };
        let honest_val = Address::from([0x71; 32]);
        let culprit_val = Address::from([0x72; 32]);
        let bls_h = vec![0xD1; BLS_PUBLIC_KEY_BYTES];
        let bls_c = vec![0xD2; BLS_PUBLIC_KEY_BYTES];
        for (addr, bls) in [(honest_val, bls_h.clone()), (culprit_val, bls_c.clone())] {
            let mut v = Validator::new(addr, 100_000);
            v.active = true;
            v.bls_public_key = bls;
            state.validators.insert(addr, v);
        }

        let honest_claim = AllocationClaim {
            budlum_validator: honest_val,
            eth_operator: tm_vals[0].address,
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: bls_h,
        };
        let culprit_claim = AllocationClaim {
            budlum_validator: culprit_val,
            eth_operator: tm_vals[1].address,
            allocated_units: 15_000,
            observed_epoch: 1,
            bls_public_key: bls_c.clone(),
        };
        for (idx, cl) in [(1u64, &honest_claim), (2u64, &culprit_claim)] {
            let ev = anchored_for_source(&mut state, dom_id, &ics_reg, source, cl, idx);
            execute_shared_security_tx(
                &mut state,
                &ctx(carrier, devnet()),
                &SharedSecurityTx::Observe {
                    domain_key: dom_id,
                    source,
                    allocation: cl.clone(),
                    evidence: ev,
                },
            )
            .expect("ics observe");
        }
        let params = crate::core::chain_config::shared_security_for_chain_id(devnet());
        apply_restaked_weights(&mut state, &params);
        assert!(state.validators[&honest_val].restaked_weight > 0);
        assert!(state.validators[&culprit_val].restaked_weight > 0);

        // Construct two conflicting CometBFT commits at height 900:
        // Fork A signed by [0, 1, 2], Fork B signed by [1, 2, 3].
        let chain_id = "provider-ics-1";
        let set_hash = validator_set_hash(&tm_vals);
        let mk_fork = |app_hash: [u8; 32], signers: &[usize]| -> TendermintCommitEvidence {
            let ts = 1_790_000_600u64;
            let parts = [app_hash[0]; 32];
            let mut c = TendermintCommitEvidence {
                chain_id: chain_id.to_string(),
                height: 900,
                round: 0,
                block_hash: [0u8; 32],
                parts_total: 1,
                parts_hash: parts,
                version_block: 11,
                last_block_hash: [0x11; 32],
                last_parts_total: 1,
                last_parts_hash: [0x22; 32],
                last_commit_hash: [0x33; 32],
                data_hash: [0x44; 32],
                validators_hash: set_hash,
                next_validators_hash: set_hash,
                consensus_hash: [0x66; 32],
                app_hash,
                last_results_hash: [0x88; 32],
                evidence_hash: [0xaa; 32],
                proposer_address: tm_vals[0].address,
                commit_time: ts,
                commit_time_nanos: 0,
                validators: tm_vals.clone(),
                signatures: Vec::new(),
            };
            c.block_hash = c.header_hash();
            c.signatures = signers
                .iter()
                .map(|&i| {
                    let msg = vote_sign_bytes(
                        chain_id,
                        900,
                        0,
                        &c.block_hash,
                        1,
                        &parts,
                        (i64::try_from(ts).expect("timestamp fits i64"), 0),
                    );
                    TendermintSignature {
                        address: tm_vals[i].address,
                        timestamp_seconds: i64::try_from(ts).expect("timestamp fits i64"),
                        timestamp_nanos: 0,
                        signature: keys[i].sign(&msg).to_vec(),
                    }
                })
                .collect();
            c
        };
        let light_params = TendermintLightParams::standard_for_unbonding(1_814_400).unwrap();
        let trusted = TrustedTendermintState {
            chain_id: chain_id.to_string(),
            height: 890,
            time_secs: 1_790_000_000,
            trusting_period_secs: light_params.trusting_period_secs,
            validators: tm_vals.clone(),
            next_validators_hash: set_hash,
        };
        let misbehaviour = TendermintMisbehaviour {
            header_1: mk_fork([0xA1; 32], &[0, 1, 2]),
            header_2: Some(mk_fork([0xB2; 32], &[1, 2, 3])),
        };

        let records = execute_tendermint_misbehaviour_slash(
            &mut state,
            &ctx(carrier, devnet()),
            dom_id,
            &trusted,
            &light_params,
            &misbehaviour,
            1_790_001_000,
        )
        .expect("culprit slashed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].budlum_validator, culprit_val);
        assert_eq!(records[0].slashed_units, 15_000);
        assert_eq!(
            records[0].kind,
            TendermintMisbehaviourKind::DoubleSignEquivocation
        );

        // Culprit is Slashed with zero live weight; honest validator stays 100% Active!
        assert_eq!(state.validators[&culprit_val].restaked_weight, 0);
        assert_eq!(
            state.settlement.shared_security.validators[&culprit_val].status,
            RestakeStatus::Slashed
        );
        assert!(state
            .settlement
            .shared_security
            .active(&honest_val)
            .is_some());
        assert!(state.validators[&honest_val].restaked_weight > 0);

        // Duplicate replay of same slash proof fails closed (already slashed).
        assert!(matches!(
            execute_tendermint_misbehaviour_slash(
                &mut state,
                &ctx(carrier, devnet()),
                dom_id,
                &trusted,
                &light_params,
                &misbehaviour,
                1_790_001_000,
            ),
            Err(SettlementTxError::Refused(_))
        ));

        // Slashed operator attempting re-entry at a higher epoch is permanently refused!
        let reentry = AllocationClaim {
            budlum_validator: Address::from([0x79; 32]),
            eth_operator: tm_vals[1].address,
            allocated_units: 99_000,
            observed_epoch: 50,
            bls_public_key: bls_c,
        };
        let reentry_ev = anchored_for_source(&mut state, dom_id, &ics_reg, source, &reentry, 99);
        assert!(matches!(
            execute_shared_security_tx(
                &mut state,
                &ctx(carrier, devnet()),
                &SharedSecurityTx::Observe {
                    domain_key: dom_id,
                    source,
                    allocation: reentry,
                    evidence: reentry_ev,
                },
            ),
            Err(SettlementTxError::Refused(_))
        ));
    }

    #[test]
    fn same_chain_multi_source_operator_cannot_double_restaked_voting_weight() {
        let reg_op = Address::from([0x01; 32]);
        let mut state = state_with_registrar(reg_op);

        let val_eigen = Address::from([0x81; 32]);
        let val_symb = Address::from([0x82; 32]);
        let val_honest = Address::from([0x83; 32]);
        let bls_eigen = vec![0xE1; BLS_PUBLIC_KEY_BYTES];
        let bls_symb = vec![0xE2; BLS_PUBLIC_KEY_BYTES];
        let bls_honest = vec![0xE3; BLS_PUBLIC_KEY_BYTES];
        for (addr, bls) in [
            (val_eigen, bls_eigen.clone()),
            (val_symb, bls_symb.clone()),
            (val_honest, bls_honest.clone()),
        ] {
            let mut v = Validator::new(addr, 100_000);
            v.active = true;
            v.bls_public_key = bls;
            state.validators.insert(addr, v);
        }

        let claim_eigen = AllocationClaim {
            budlum_validator: val_eigen,
            eth_operator: [0xAA; 20],
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: bls_eigen,
        };
        let claim_symb = AllocationClaim {
            budlum_validator: val_symb,
            eth_operator: [0xAA; 20],
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: bls_symb,
        };
        let claim_honest = AllocationClaim {
            budlum_validator: val_honest,
            eth_operator: [0xBB; 20],
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: bls_honest,
        };
        for (nonce, src, cl) in [
            (1u64, RestakeSource::EigenLayer, &claim_eigen),
            (2u64, RestakeSource::Symbiotic, &claim_symb),
            (3u64, RestakeSource::EigenLayer, &claim_honest),
        ] {
            let ev = anchored_for_source(&mut state, DOMAIN, &REGISTRAR, src, cl, nonce);
            execute_shared_security_tx(
                &mut state,
                &ctx(reg_op, devnet()),
                &SharedSecurityTx::Observe {
                    domain_key: DOMAIN,
                    source: src,
                    allocation: cl.clone(),
                    evidence: ev,
                },
            )
            .expect("observe");
        }

        let params = crate::core::chain_config::shared_security_for_chain_id(devnet());
        apply_restaked_weights(&mut state, &params);
        let same_op_combined = state.validators[&val_eigen]
            .restaked_weight
            .saturating_add(state.validators[&val_symb].restaked_weight);
        let honest_single = state.validators[&val_honest].restaked_weight;
        assert!(same_op_combined <= honest_single);
        assert_eq!(same_op_combined, honest_single);
    }

    #[test]
    fn slashed_or_cloned_consensus_bls_key_is_refused_across_operators() {
        let reg_op = Address::from([0x01; 32]);
        let mut state = state_with_registrar(reg_op);

        let val_1 = Address::from([0x91; 32]);
        let val_2 = Address::from([0x92; 32]);
        let val_3 = Address::from([0x93; 32]);
        let shared_bls = vec![0xF1; BLS_PUBLIC_KEY_BYTES];

        let cl_1 = AllocationClaim {
            budlum_validator: val_1,
            eth_operator: [0x51; 20],
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: shared_bls.clone(),
        };
        let ev_1 = anchored_for_source(
            &mut state,
            DOMAIN,
            &REGISTRAR,
            RestakeSource::EigenLayer,
            &cl_1,
            1,
        );
        execute_shared_security_tx(
            &mut state,
            &ctx(reg_op, devnet()),
            &SharedSecurityTx::Observe {
                domain_key: DOMAIN,
                source: RestakeSource::EigenLayer,
                allocation: cl_1,
                evidence: ev_1,
            },
        )
        .expect("first operator binds key");

        // Cloning an active BLS key under a second operator must be refused.
        let cl_clone = AllocationClaim {
            budlum_validator: val_2,
            eth_operator: [0x52; 20],
            allocated_units: 10_000,
            observed_epoch: 1,
            bls_public_key: shared_bls.clone(),
        };
        let ev_clone = anchored_for_source(
            &mut state,
            DOMAIN,
            &REGISTRAR,
            RestakeSource::EigenLayer,
            &cl_clone,
            2,
        );
        assert!(matches!(
            execute_shared_security_tx(
                &mut state,
                &ctx(reg_op, devnet()),
                &SharedSecurityTx::Observe {
                    domain_key: DOMAIN,
                    source: RestakeSource::EigenLayer,
                    allocation: cl_clone,
                    evidence: ev_clone,
                },
            ),
            Err(SettlementTxError::Refused(_))
        ));

        // Once slashed, re-presenting the same BLS key under a fresh operator proxy on the same
        // external chain must also be refused.
        quarantine_correlated_sources(
            &mut state,
            RestakeSource::EigenLayer,
            &[[0x51; 20]],
            RestakeStatus::Slashed,
        );
        let cl_launder = AllocationClaim {
            budlum_validator: val_3,
            eth_operator: [0x53; 20],
            allocated_units: 10_000,
            observed_epoch: 2,
            bls_public_key: shared_bls,
        };
        let ev_launder = anchored_for_source(
            &mut state,
            DOMAIN,
            &REGISTRAR,
            RestakeSource::Symbiotic,
            &cl_launder,
            3,
        );
        assert!(matches!(
            execute_shared_security_tx(
                &mut state,
                &ctx(reg_op, devnet()),
                &SharedSecurityTx::Observe {
                    domain_key: DOMAIN,
                    source: RestakeSource::Symbiotic,
                    allocation: cl_launder,
                    evidence: ev_launder,
                },
            ),
            Err(SettlementTxError::Refused(_))
        ));
    }

    #[test]
    fn quarantine_correlated_sources_records_cosmos_ics_domain() {
        let reg_op = Address::from([0x01; 32]);
        let mut state = AccountState::new();
        let ics_domain_id = 77u32;
        let mut domain = crate::domain::plugin::default_domain(
            ics_domain_id,
            crate::domain::ConsensusKind::Bft,
            7700,
            "bft-quorum-commit",
            1,
        );
        domain.operator = Some(reg_op);
        state.add_balance(&reg_op, domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, domain).expect("ics domain");
        execute_shared_security_tx(
            &mut state,
            &ctx(reg_op, devnet()),
            &SharedSecurityTx::SetRegistrar {
                domain_key: ics_domain_id,
                registrar: REGISTRAR.to_vec(),
            },
        )
        .expect("ics registrar");

        let source = RestakeSource::CosmosIcs {
            domain_id: ics_domain_id,
        };
        let op = [0x66; 20];
        let val = Address::from([0x96; 32]);
        let cl = AllocationClaim {
            budlum_validator: val,
            eth_operator: op,
            allocated_units: 9_000,
            observed_epoch: 1,
            bls_public_key: vec![0xF6; BLS_PUBLIC_KEY_BYTES],
        };
        let ev = anchored_for_source(&mut state, ics_domain_id, &REGISTRAR, source, &cl, 1);
        execute_shared_security_tx(
            &mut state,
            &ctx(reg_op, devnet()),
            &SharedSecurityTx::Observe {
                domain_key: ics_domain_id,
                source,
                allocation: cl,
                evidence: ev,
            },
        )
        .expect("ics observe");

        let written =
            quarantine_correlated_sources(&mut state, source, &[op], RestakeStatus::Slashed);
        assert_eq!(written, 1);
        assert!(state
            .settlement
            .shared_security
            .is_operator_slashed(source, &op));
        assert_eq!(
            state.settlement.shared_security.validators[&val].status,
            RestakeStatus::Slashed
        );
    }
}
