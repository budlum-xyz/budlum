//! The object-layer registry: charters, classes, placements and departures.
//!
//! Every write is all-or-nothing: an operation runs on a copy and the copy
//! replaces the registry only when every step accepted. A refusal leaves the
//! registry byte for byte unchanged (`composite_refusal_does_not_mutate`).
//!
//! The registry never creates value (N-5). Fungible balances only grow by an
//! arrival whose custody the home endpoint measured, and only shrink by a
//! departure or an escape. `object_layer_never_mints` checks the sums.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};
use crate::object_layer::charter::{
    check_charter, check_charter_at_state_root, CanonicalCodeHashes, CharterRefusal, CharterStatus,
    CodeProof, DomainCharter,
};
use crate::object_layer::family::{
    class_ref_bytes, profile_for, AssetKind, EndpointEvent, FamilyError, HomeVmFamily,
    RawEndpointEvent, SliceSource,
};
use crate::object_layer::ids::{
    ArrivalKey, AssetClassId, AssetId, DepartureId, DependencyId, HomeIdentity,
};
use crate::object_layer::rule::{
    apply_rule, sample_commitment, verify_samples, AssetSlice, ClassRule, ClassSlice, Condition,
    Holder, ReferenceSample, RuleRefusal, TemplateId, Verb,
};
use crate::object_layer::tx::{
    home_stipend_action_digest, HomeKeyStipendAuth, HomeStipendVerifier, ObjectLayerTx,
};
use crate::object_layer::{
    DEFAULT_CHALLENGE_WINDOW_BLOCKS, DEFAULT_MIN_REFERENCE_SAMPLES, MAX_COMPOSITE_CALLS,
    MAX_ESCAPE_ADDRESS_BYTES,
};

/// Maximum single-call gasless stipend authorized via `UOL-K1` (`0.01 BUD`).
pub const MAX_HOME_STIPEND_ATTOS: u128 = 10_000_000_000_000_000;
/// Maximum cumulative gasless stipend per home identity via `UOL-K1` (`0.1 BUD`).
pub const MAX_HOME_STIPEND_TOTAL_ATTOS: u128 = 100_000_000_000_000_000;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The finality phase of a home event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Final,
    /// Opens in a later step. Refused until then.
    Tentative,
}

/// One endpoint event with the position that makes it provable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeEventProof {
    pub domain: DomainId,
    pub home_height: u64,
    pub home_block_hash: Hash32,
    /// The event's position on the home chain (transaction hash and log
    /// index, or the family's equivalent), as bytes.
    pub event_id: Vec<u8>,
    pub event: RawEndpointEvent,
    pub phase: Phase,
    /// The family's inclusion proof of the event in the block. Checked by
    /// the [`HomeFinality`] the caller supplies.
    pub inclusion: Vec<u8>,
}

/// The caller's view of home finality: the external-domain intake in
/// production, a fixture in tests. The core trusts nothing it cannot ask
/// this for.
pub trait HomeFinality {
    /// True when `proof.event` is included in a home block the domain's
    /// finality adapter accepted at `proof.phase`.
    fn event_is_proven(&self, proof: &HomeEventProof) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreezeReason {
    /// The home code's upgrade authority changed.
    UpgradeAuthorityChanged,
    /// Home custody fell below the object-layer record (N-4).
    CustodyDeficit,
    /// A rule-fidelity challenge went un-rebutted past the challenge window.
    UnrebuttedChallenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassStatus {
    Active,
    Frozen(FreezeReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetClass {
    pub id: AssetClassId,
    pub home_domain: DomainId,
    pub kind: AssetKind,
    pub contract: Vec<u8>,
    pub rule: ClassRule,
    pub slice: ClassSlice,
    pub upgrade_authority: Option<Vec<u8>>,
    pub status: ClassStatus,
    pub registrant: Address,
    pub bond: u64,
    pub sample_commitment: Hash32,
}

/// Default minimum class bond required by [`ObjectLayerParams::default`].
pub const DEFAULT_MIN_CLASS_BOND: u64 = 1_000_000;

/// Where an asset is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Location {
    Home,
    ObjectLayer,
    Departing(DepartureId),
    /// Placed as a guest asset on another chartered domain (`UOL-K2`).
    Guest {
        domain: DomainId,
        holder: Holder,
    },
}

type StorageSlotProof = ([u8; 32], [u8; 32], Vec<Vec<u8>>);

/// Home-chain state-inclusion proof anchoring a contract's state slice to
/// a finalized home `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeSliceProof {
    pub state_root: Hash32,
    pub contract_account_proof: Vec<Vec<u8>>,
    pub storage_proofs: Vec<StorageSlotProof>,
}

/// Verify that `proof` proves `slice` at `contract` against `state_root`.
///
/// # Errors
///
/// Returns [`Refusal::UnprovenEvent`] when the state proof fails verification
/// or disagrees with `expected_root` / `slice`.
pub fn verify_home_slice_proof(
    family: HomeVmFamily,
    chain_reference: &str,
    contract: &[u8],
    slice: &ClassSlice,
    proof: &HomeSliceProof,
    expected_root: Option<Hash32>,
) -> Result<(), Refusal> {
    if let Some(root) = expected_root {
        if proof.state_root != root {
            return Err(Refusal::UnprovenEvent);
        }
    }
    profile_for(family).verify_home_slice_proof(chain_reference, contract, slice, proof)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniqueAsset {
    pub class: AssetClassId,
    pub native_id: Vec<u8>,
    pub location: Location,
    /// `None` while the asset is at home.
    pub holder: Option<Holder>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Departure {
    pub asset: AssetId,
    pub class: AssetClassId,
    pub holder: Holder,
    pub amount: u128,
    /// The home address that receives the asset on `release`.
    pub home_to: Vec<u8>,
    pub requested_at: u64,
}

/// One call of a composite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    pub class: AssetClassId,
    /// Empty for a fungible class.
    pub native_id: Vec<u8>,
    pub verb: Verb,
}

/// A standing offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub maker: Holder,
    pub calls: Vec<Call>,
    pub wants: Vec<Condition>,
    pub expiry: u64,
}

/// A class registration request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassRegistration {
    pub home_domain: DomainId,
    pub kind: AssetKind,
    pub contract: Vec<u8>,
    pub rule: ClassRule,
    pub slice: ClassSlice,
    pub slice_source: SliceSource,
    pub samples: Vec<ReferenceSample>,
    pub bond: u64,
    #[serde(default)]
    pub state_proof: Option<HomeSliceProof>,
}

/// Registry parameters, written by genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLayerParams {
    #[serde(with = "crate::object_layer::pairs")]
    pub canonical: BTreeMap<HomeVmFamily, CanonicalCodeHashes>,
    pub min_reference_samples: u32,
    pub min_class_bond: u64,
    pub max_composite_calls: u8,
}

impl Default for ObjectLayerParams {
    fn default() -> Self {
        Self {
            canonical: BTreeMap::new(),
            min_reference_samples: DEFAULT_MIN_REFERENCE_SAMPLES,
            min_class_bond: DEFAULT_MIN_CLASS_BOND,
            max_composite_calls: MAX_COMPOSITE_CALLS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Refusal {
    Charter(CharterRefusal),
    NoCharter,
    CharterNotActive,
    Family(FamilyError),
    WrongEmitter,
    UnprovenEvent,
    TentativeClosed,
    UnexpectedEvent,
    ArrivalAlreadyUsed,
    ClassClosedRule,
    TemplateNotForFamily,
    SliceSourceNotAdmitted,
    TooFewSamples,
    SampleMismatch(usize),
    BondTooSmall,
    ClassExists,
    UnknownClass,
    ClassFrozen,
    KindMismatch,
    UnknownAsset,
    AssetNotHere,
    NotAuthorized,
    Rule(RuleRefusal),
    TooManyCalls,
    EmptyComposite,
    HomeNonce { expected: u64, got: u64 },
    BadCallList,
    UnknownDeparture,
    UnknownOffer,
    OfferExpired,
    WantNotMet(usize),
    EscapeAddressTooLong,
    PendingTentativeDependency,
    UnknownDependency,
    NothingToAdopt,
    ChallengeAlreadyOpen,
    NoChallengeOpen,
    Overflow,
}

impl From<FamilyError> for Refusal {
    fn from(e: FamilyError) -> Self {
        Self::Family(e)
    }
}

impl From<RuleRefusal> for Refusal {
    fn from(e: RuleRefusal) -> Self {
        Self::Rule(e)
    }
}

/// The outcome of a custody audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAudit {
    pub recorded: u128,
    pub home_custody: u128,
    /// `home_custody - recorded`. Negative is a deficit and freezes the class.
    pub delta: i128,
}

/// One unresolved opt-in tentative home arrival dependency (single-dependency rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TentativeDependency {
    pub id: DependencyId,
    pub class: AssetClassId,
    pub asset: AssetId,
    pub holder: Holder,
    pub amount: u128,
    pub kind: AssetKind,
}

/// An open rule-fidelity challenge against a registered class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenger: Address,
    pub opened_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLayerRegistry {
    pub params: ObjectLayerParams,
    #[serde(with = "crate::object_layer::pairs")]
    pub charters: BTreeMap<DomainId, DomainCharter>,
    #[serde(with = "crate::object_layer::pairs")]
    pub classes: BTreeMap<AssetClassId, AssetClass>,
    #[serde(with = "crate::object_layer::pairs")]
    pub unique: BTreeMap<AssetId, UniqueAsset>,
    #[serde(with = "crate::object_layer::pairs")]
    pub balances: BTreeMap<(AssetClassId, Holder), u128>,
    pub arrivals: BTreeSet<ArrivalKey>,
    #[serde(with = "crate::object_layer::pairs")]
    pub departures: BTreeMap<DepartureId, Departure>,
    pub departure_seq: u64,
    #[serde(with = "crate::object_layer::pairs")]
    pub home_nonces: BTreeMap<HomeIdentity, u64>,
    #[serde(with = "crate::object_layer::pairs")]
    pub offers: BTreeMap<Hash32, Offer>,
    pub offer_seq: u64,
    #[serde(with = "crate::object_layer::pairs", default)]
    pub escape_addresses: BTreeMap<Address, Vec<u8>>,
    #[serde(default)]
    pub tentative_consent: BTreeSet<Address>,
    #[serde(with = "crate::object_layer::pairs", default)]
    pub dependencies: BTreeMap<DependencyId, TentativeDependency>,
    #[serde(with = "crate::object_layer::pairs", default)]
    pub challenges: BTreeMap<AssetClassId, ChallengeRecord>,
    #[serde(with = "crate::object_layer::pairs", default)]
    pub home_stipend_nonces: BTreeMap<HomeIdentity, u64>,
    #[serde(with = "crate::object_layer::pairs", default)]
    pub home_stipend_spent: BTreeMap<HomeIdentity, u128>,
}

impl ObjectLayerRegistry {
    #[must_use]
    pub fn with_params(params: ObjectLayerParams) -> Self {
        Self {
            params,
            ..Self::default()
        }
    }

    /// True when the registry holds no record. Parameters alone do not
    /// count: every node holds the same genesis parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.charters.is_empty()
            && self.classes.is_empty()
            && self.unique.is_empty()
            && self.balances.is_empty()
            && self.arrivals.is_empty()
            && self.departures.is_empty()
            && self.home_nonces.is_empty()
            && self.offers.is_empty()
            && self.escape_addresses.is_empty()
            && self.tentative_consent.is_empty()
            && self.dependencies.is_empty()
            && self.challenges.is_empty()
            && self.home_stipend_nonces.is_empty()
            && self.home_stipend_spent.is_empty()
    }

    /// The registry root. Folded into the settlement root only when the
    /// registry is not empty, so an unused object layer keeps every pinned
    /// root (`object_layer_empty_registry_keeps_state_root`).
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let encoded = postcard::to_allocvec(self)
            .unwrap_or_else(|_| b"BDLM_OBJECT_LAYER_UNENCODABLE_V1".to_vec());
        hash_fields_bytes(&[b"BDLM_OBJECT_LAYER_REGISTRY_V1", &encoded])
    }

    /// Run `op` on a copy; keep the copy only if `op` accepted.
    fn atomic<T>(
        &mut self,
        op: impl FnOnce(&mut Self) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        let mut draft = self.clone();
        let out = op(&mut draft)?;
        *self = draft;
        Ok(out)
    }

    // ------------------------------------------------------------ charter

    /// `ObjectLayerTx::Charter`. Returns `false` when the same charter was
    /// already in place (idempotent), `true` when it was written.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn charter(
        &mut self,
        domain: DomainId,
        charter: DomainCharter,
        proof: &CodeProof,
        domain_active: bool,
    ) -> Result<bool, Refusal> {
        self.charter_verified(domain, charter, proof, domain_active, None, false)
    }

    /// `ObjectLayerTx::Charter` verifying the home-chain code proof against
    /// `expected_home_state_root` (required when `require_home_proof` is true).
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Charter`] if charter validation or home-chain state
    /// proof verification fails.
    pub fn charter_verified(
        &mut self,
        domain: DomainId,
        charter: DomainCharter,
        proof: &CodeProof,
        domain_active: bool,
        expected_home_state_root: Option<Hash32>,
        require_home_proof: bool,
    ) -> Result<bool, Refusal> {
        if require_home_proof && (proof.home_proof.is_none() || expected_home_state_root.is_none())
        {
            return Err(Refusal::Charter(CharterRefusal::ProofDisagrees));
        }
        let canonical = self.params.canonical.get(&charter.vm_family);
        let validation = match expected_home_state_root {
            Some(state_root) => check_charter_at_state_root(
                &charter,
                proof,
                canonical,
                domain_active,
                Some(state_root),
            ),
            None => check_charter(&charter, proof, canonical, domain_active),
        };
        validation.map_err(Refusal::Charter)?;
        if let Some(existing) = self.charters.get(&domain) {
            return if existing.same_binding(&charter) {
                Ok(false)
            } else {
                Err(Refusal::Charter(CharterRefusal::AlreadyChartered))
            };
        }
        let mut charter = charter;
        charter.status = CharterStatus::Active;
        self.charters.insert(domain, charter);
        Ok(true)
    }

    fn active_charter(&self, domain: DomainId) -> Result<&DomainCharter, Refusal> {
        let charter = self.charters.get(&domain).ok_or(Refusal::NoCharter)?;
        if charter.status != CharterStatus::Active {
            return Err(Refusal::CharterNotActive);
        }
        Ok(charter)
    }

    /// Check a home event and translate it. Shared by every door that reads
    /// the endpoint: the emitter must be the charter's endpoint, the
    /// finality must be proven, and the event must be one of the four.
    fn read_event(
        &self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
        allow_tentative: bool,
    ) -> Result<(HomeVmFamily, EndpointEvent), Refusal> {
        let charter = self.active_charter(proof.domain)?;
        if !allow_tentative && proof.phase == Phase::Tentative {
            return Err(Refusal::TentativeClosed);
        }
        if proof.event.emitter != charter.endpoint {
            return Err(Refusal::WrongEmitter);
        }
        if !finality.event_is_proven(proof) {
            return Err(Refusal::UnprovenEvent);
        }
        let family = profile_for(charter.vm_family);
        let event = family.translate_event(&charter.context(), &proof.event)?;
        Ok((charter.vm_family, event))
    }

    fn use_arrival(&mut self, proof: &HomeEventProof) -> Result<(), Refusal> {
        let key = ArrivalKey::derive(proof.domain, proof.home_height, &proof.event_id);
        if !self.arrivals.insert(key) {
            return Err(Refusal::ArrivalAlreadyUsed);
        }
        Ok(())
    }

    // ------------------------------------------------------------ classes

    /// `ObjectLayerTx::RegisterClass`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register_class(
        &mut self,
        registrant: Address,
        reg: ClassRegistration,
    ) -> Result<AssetClassId, Refusal> {
        self.register_class_verified(registrant, reg, None, false)
    }

    /// `ObjectLayerTx::RegisterClass` verifying `reg.state_proof` against
    /// `expected_home_state_root` (required when `require_home_proof` is true).
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] if validation, bond floor, or home-state proof fails.
    pub fn register_class_verified(
        &mut self,
        registrant: Address,
        reg: ClassRegistration,
        expected_home_state_root: Option<Hash32>,
        require_home_proof: bool,
    ) -> Result<AssetClassId, Refusal> {
        let charter = self.active_charter(reg.home_domain)?;
        let family = profile_for(charter.vm_family);
        family.validate_address(&reg.contract)?;
        if !reg.rule.is_open() {
            return Err(Refusal::ClassClosedRule);
        }
        match &reg.rule {
            ClassRule::Template { id, .. } => {
                let record_ok = reg.kind == AssetKind::Unique && *id == TemplateId::RecordV1;
                if *id != family.template_for(reg.kind) && !record_ok {
                    return Err(Refusal::TemplateNotForFamily);
                }
            }
            ClassRule::Program | ClassRule::Replica => {}
            ClassRule::Native => return Err(Refusal::ClassClosedRule),
        }
        if !family.slice_read_rule().admits(reg.slice_source) {
            return Err(Refusal::SliceSourceNotAdmitted);
        }
        if reg.samples.len() < self.params.min_reference_samples as usize {
            return Err(Refusal::TooFewSamples);
        }
        verify_samples(&reg.rule, &reg.samples).map_err(Refusal::SampleMismatch)?;
        if reg.bond < self.params.min_class_bond {
            return Err(Refusal::BondTooSmall);
        }
        if require_home_proof && (reg.state_proof.is_none() || expected_home_state_root.is_none()) {
            return Err(Refusal::UnprovenEvent);
        }
        if let Some(sp) = reg.state_proof.as_ref() {
            verify_home_slice_proof(
                charter.vm_family,
                &charter.chain_reference,
                &reg.contract,
                &reg.slice,
                sp,
                expected_home_state_root,
            )?;
        }
        let id = AssetClassId::derive(reg.home_domain, &class_ref_bytes(reg.kind, &reg.contract));
        if self.classes.contains_key(&id) {
            return Err(Refusal::ClassExists);
        }
        let upgrade_authority = reg.slice.get(family.upgrade_authority_field()).cloned();
        self.classes.insert(
            id,
            AssetClass {
                id,
                home_domain: reg.home_domain,
                kind: reg.kind,
                contract: reg.contract,
                rule: reg.rule,
                sample_commitment: sample_commitment(&reg.samples),
                slice: reg.slice,
                upgrade_authority,
                status: ClassStatus::Active,
                registrant,
                bond: reg.bond,
            },
        );
        Ok(id)
    }

    /// `ObjectLayerTx::RefreshClass` with a final slice update. A change of
    /// the home code's upgrade authority freezes the class for new
    /// transitions; exits stay open (N-6).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn refresh_class(
        &mut self,
        caller: Address,
        class: AssetClassId,
        updates: ClassSlice,
        phase: Phase,
    ) -> Result<ClassStatus, Refusal> {
        self.refresh_class_verified(caller, class, updates, phase, (None, None, false))
    }

    /// `ObjectLayerTx::RefreshClass` verifying `proof` against
    /// `expected_home_state_root` (required when `require_home_proof` is true)
    /// before accepting any slice update or upgrade-authority freeze.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] if caller is unauthorized or home-state proof fails.
    pub fn refresh_class_verified(
        &mut self,
        caller: Address,
        class: AssetClassId,
        updates: ClassSlice,
        phase: Phase,
        (proof, expected_home_state_root, require_home_proof): (
            Option<&HomeSliceProof>,
            Option<Hash32>,
            bool,
        ),
    ) -> Result<ClassStatus, Refusal> {
        if phase == Phase::Tentative {
            return Err(Refusal::TentativeClosed);
        }
        // A refresh rewrites the class slice and can freeze the class, so
        // only the account that registered (and bonded) the class may do it.
        if self.class(&class)?.registrant != caller {
            return Err(Refusal::NotAuthorized);
        }
        if require_home_proof && (proof.is_none() || expected_home_state_root.is_none()) {
            return Err(Refusal::UnprovenEvent);
        }
        self.atomic(|r| {
            let (domain, contract, mut merged_slice) = {
                let entry = r.classes.get(&class).ok_or(Refusal::UnknownClass)?;
                (
                    entry.home_domain,
                    entry.contract.clone(),
                    entry.slice.clone(),
                )
            };
            merged_slice.extend(updates.clone());
            let charter = r.active_charter(domain)?.clone();
            if let Some(sp) = proof {
                verify_home_slice_proof(
                    charter.vm_family,
                    &charter.chain_reference,
                    &contract,
                    &merged_slice,
                    sp,
                    expected_home_state_root,
                )?;
            }
            let family = profile_for(charter.vm_family);
            let field = family.upgrade_authority_field();
            let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
            entry.slice = merged_slice;
            let authority = entry.slice.get(field).cloned();
            if authority != entry.upgrade_authority {
                entry.upgrade_authority = authority;
                entry.status = ClassStatus::Frozen(FreezeReason::UpgradeAuthorityChanged);
            }
            Ok(entry.status)
        })
    }

    fn class(&self, id: &AssetClassId) -> Result<&AssetClass, Refusal> {
        self.classes.get(id).ok_or(Refusal::UnknownClass)
    }

    // ------------------------------------------------------------ arrival

    /// `ObjectLayerTx::Arrive`, final or opt-in single-dependency tentative phase.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn arrive(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<AssetId, Refusal> {
        let (_, event) = self.read_event(proof, finality, true)?;
        let EndpointEvent::Arrive {
            kind,
            contract,
            native_id,
            amount,
            depositor,
            recipient,
        } = event
        else {
            return Err(Refusal::UnexpectedEvent);
        };
        if proof.phase == Phase::Tentative {
            let Some(account) = recipient else {
                return Err(Refusal::TentativeClosed);
            };
            if !self.tentative_consent.contains(&account) {
                return Err(Refusal::TentativeClosed);
            }
            if self
                .dependencies
                .values()
                .any(|d| d.holder == Holder::Account(account))
            {
                return Err(Refusal::PendingTentativeDependency);
            }
        }
        self.atomic(|r| {
            r.use_arrival(proof)?;
            let class_id = AssetClassId::derive(proof.domain, &class_ref_bytes(kind, &contract));
            let class = r.class(&class_id)?;
            if class.kind != kind {
                return Err(Refusal::KindMismatch);
            }
            let holder = match recipient {
                Some(account) => Holder::Account(account),
                None => Holder::Home(HomeIdentity::derive(proof.domain, &depositor)),
            };
            let asset = AssetId::derive(&class_id, &native_id);
            match kind {
                AssetKind::Unique => {
                    let entry = r.unique.entry(asset).or_insert_with(|| UniqueAsset {
                        class: class_id,
                        native_id: native_id.clone(),
                        location: Location::Home,
                        holder: None,
                    });
                    // N-3: one location. A second arrival of an asset that is
                    // already here, or departing, is refused.
                    if entry.location != Location::Home {
                        return Err(Refusal::AssetNotHere);
                    }
                    entry.location = Location::ObjectLayer;
                    entry.holder = Some(holder);
                }
                AssetKind::Fungible => {
                    r.credit(class_id, holder, amount)?;
                }
            }
            if proof.phase == Phase::Tentative {
                let dep_id = DependencyId::derive(
                    proof.domain,
                    proof.home_height,
                    &proof.home_block_hash,
                    &proof.event_id,
                );
                r.dependencies.insert(
                    dep_id,
                    TentativeDependency {
                        id: dep_id,
                        class: class_id,
                        asset,
                        holder,
                        amount: if kind == AssetKind::Unique { 1 } else { amount },
                        kind,
                    },
                );
            }
            Ok(asset)
        })
    }

    fn credit(&mut self, class: AssetClassId, holder: Holder, amount: u128) -> Result<(), Refusal> {
        let slot = self.balances.entry((class, holder)).or_insert(0);
        *slot = slot.checked_add(amount).ok_or(Refusal::Overflow)?;
        Ok(())
    }

    fn debit(&mut self, class: AssetClassId, holder: Holder, amount: u128) -> Result<(), Refusal> {
        let key = (class, holder);
        let have = self.balances.get(&key).copied().unwrap_or(0);
        let left = have
            .checked_sub(amount)
            .ok_or(Refusal::Rule(RuleRefusal::BalanceTooLow))?;
        if left == 0 {
            self.balances.remove(&key);
        } else {
            self.balances.insert(key, left);
        }
        Ok(())
    }

    /// The balance of `holder` in a fungible class.
    #[must_use]
    pub fn balance(&self, class: &AssetClassId, holder: &Holder) -> u128 {
        self.balances.get(&(*class, *holder)).copied().unwrap_or(0)
    }

    // ------------------------------------------------------------ calls

    fn run_call(&mut self, actor: &Holder, call: &Call) -> Result<(), Refusal> {
        let class = self.class(&call.class)?.clone();
        // N-12: a composite that touches a frozen class is refused whole.
        if class.status != ClassStatus::Active {
            return Err(Refusal::ClassFrozen);
        }
        let Verb::Transfer { from, to, .. } = &call.verb;
        // The only requirement the templates raise is `SignedBy { from }`,
        // and the acting holder is the only signer a call carries.
        if from != actor {
            return Err(Refusal::NotAuthorized);
        }
        match class.kind {
            AssetKind::Unique => {
                let asset_id = AssetId::derive(&call.class, &call.native_id);
                let asset = self.unique.get(&asset_id).ok_or(Refusal::UnknownAsset)?;
                if asset.location != Location::ObjectLayer {
                    return Err(Refusal::AssetNotHere);
                }
                let holder = asset.holder.ok_or(Refusal::AssetNotHere)?;
                let t = apply_rule(
                    &class.rule,
                    &class.slice,
                    &AssetSlice::Unique { holder },
                    &call.verb,
                )?;
                let AssetSlice::Unique { holder } = t.asset_slice else {
                    return Err(Refusal::Rule(RuleRefusal::WrongShape));
                };
                if let Some(a) = self.unique.get_mut(&asset_id) {
                    a.holder = Some(holder);
                }
            }
            AssetKind::Fungible => {
                if !call.native_id.is_empty() {
                    return Err(Refusal::KindMismatch);
                }
                let before: BTreeMap<Holder, u128> = [*from, *to]
                    .into_iter()
                    .map(|h| (h, self.balance(&call.class, &h)))
                    .filter(|(_, v)| *v > 0)
                    .collect();
                let t = apply_rule(
                    &class.rule,
                    &class.slice,
                    &AssetSlice::Fungible { balances: before },
                    &call.verb,
                )?;
                let AssetSlice::Fungible { balances } = t.asset_slice else {
                    return Err(Refusal::Rule(RuleRefusal::WrongShape));
                };
                for h in [*from, *to] {
                    self.balances.remove(&(call.class, h));
                    if let Some(v) = balances.get(&h) {
                        self.balances.insert((call.class, h), *v);
                    }
                }
            }
        }
        Ok(())
    }

    fn check_composite(&self, calls: &[Call]) -> Result<(), Refusal> {
        if calls.is_empty() {
            return Err(Refusal::EmptyComposite);
        }
        if calls.len() > usize::from(self.params.max_composite_calls.min(MAX_COMPOSITE_CALLS)) {
            return Err(Refusal::TooManyCalls);
        }
        Ok(())
    }

    /// `ObjectLayerTx::Call`: every call runs, or none does.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn call(&mut self, actor: Holder, calls: &[Call]) -> Result<(), Refusal> {
        self.check_composite(calls)?;
        self.atomic(|r| {
            for call in calls {
                r.run_call(&actor, call)?;
            }
            Ok(())
        })
    }

    /// `ObjectLayerTx::Offer`. The maker's calls are checked when the offer
    /// is accepted, not now, so an offer locks nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn offer(
        &mut self,
        maker: Holder,
        offer_calls: Vec<Call>,
        wants: Vec<Condition>,
        expiry: u64,
    ) -> Result<Hash32, Refusal> {
        self.check_composite(&offer_calls)?;
        self.atomic(|r| {
            r.offer_seq = r.offer_seq.checked_add(1).ok_or(Refusal::Overflow)?;
            let encoded = postcard::to_allocvec(&(&maker, &offer_calls, &wants, expiry))
                .map_err(|_| Refusal::Overflow)?;
            let id = hash_fields_bytes(&[
                b"BDLM_OBJECT_LAYER_OFFER_V1",
                &r.offer_seq.to_le_bytes(),
                &encoded,
            ]);
            r.offers.insert(
                id,
                Offer {
                    maker,
                    calls: offer_calls,
                    wants,
                    expiry,
                },
            );
            Ok(id)
        })
    }

    /// `ObjectLayerTx::Accept`: both sides run, and every want of the maker
    /// holds afterwards, or nothing changes
    /// (`offer_accept_runs_both_sides_or_none`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn accept(
        &mut self,
        taker: Holder,
        offer_id: Hash32,
        calls: &[Call],
        height: u64,
    ) -> Result<(), Refusal> {
        self.atomic(|r| {
            let offer = r.offers.remove(&offer_id).ok_or(Refusal::UnknownOffer)?;
            if height > offer.expiry {
                return Err(Refusal::OfferExpired);
            }
            if offer.calls.len() + calls.len()
                > usize::from(r.params.max_composite_calls.min(MAX_COMPOSITE_CALLS))
            {
                return Err(Refusal::TooManyCalls);
            }
            let before = r.clone();
            for call in &offer.calls {
                r.run_call(&offer.maker, call)?;
            }
            for call in calls {
                r.run_call(&taker, call)?;
            }
            for (index, want) in offer.wants.iter().enumerate() {
                if !r.condition_holds(&before, want, &offer.maker, &taker) {
                    return Err(Refusal::WantNotMet(index));
                }
            }
            Ok(())
        })
    }

    fn holds(&self, class: &AssetClassId, holder: &Holder) -> bool {
        self.balance(class, holder) > 0
            || self.unique.values().any(|a| {
                a.class == *class
                    && a.location == Location::ObjectLayer
                    && a.holder == Some(*holder)
            })
    }

    fn condition_holds(
        &self,
        before: &Self,
        condition: &Condition,
        maker: &Holder,
        taker: &Holder,
    ) -> bool {
        match condition {
            Condition::Payment {
                class,
                to,
                min_amount,
            } => {
                let gained = self
                    .balance(class, to)
                    .saturating_sub(before.balance(class, to));
                gained >= *min_amount
            }
            Condition::Holds { class, holder } => self.holds(class, holder),
            Condition::SignedBy { signer } => signer == maker || signer == taker,
            Condition::EscapeAddress { holder, home } => {
                let _ = (holder, home);
                false
            }
        }
    }

    /// `ObjectLayerTx::HomeCall`: the home event's sender acts as its home
    /// identity. The authority is the finality proof; the
    /// per-identity nonce stops a replay of an older call.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn home_call(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<HomeIdentity, Refusal> {
        let (family, event) = self.read_event(proof, finality, false)?;
        let EndpointEvent::Call {
            sender,
            nonce,
            calls,
        } = event
        else {
            return Err(Refusal::UnexpectedEvent);
        };
        profile_for(family).validate_address(&sender)?;
        let calls: Vec<Call> = postcard::from_bytes(&calls).map_err(|_| Refusal::BadCallList)?;
        self.check_composite(&calls)?;
        let identity = HomeIdentity::derive(proof.domain, &sender);
        self.atomic(|r| {
            r.use_arrival(proof)?;
            let expected = r.home_nonces.get(&identity).copied().unwrap_or(0);
            if nonce != expected {
                return Err(Refusal::HomeNonce {
                    expected,
                    got: nonce,
                });
            }
            r.home_nonces
                .insert(identity, expected.checked_add(1).ok_or(Refusal::Overflow)?);
            let actor = Holder::Home(identity);
            for call in &calls {
                r.run_call(&actor, call)?;
            }
            Ok(identity)
        })
    }

    // ------------------------------------------------------------ departure

    /// `ObjectLayerTx::Depart`. Open for a frozen class too (N-6). The
    /// departing value is frozen until `ConfirmDeparture`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn depart(
        &mut self,
        actor: Holder,
        class: AssetClassId,
        native_id: &[u8],
        amount: u128,
        home_to: Vec<u8>,
        height: u64,
    ) -> Result<DepartureId, Refusal> {
        self.atomic(|r| {
            if r.dependencies
                .values()
                .any(|d| d.holder == actor && d.class == class)
            {
                return Err(Refusal::PendingTentativeDependency);
            }
            let entry = r.class(&class)?.clone();
            let family = profile_for(r.active_charter(entry.home_domain)?.vm_family);
            family.validate_address(&home_to)?;
            let asset = AssetId::derive(&class, native_id);
            r.departure_seq = r.departure_seq.checked_add(1).ok_or(Refusal::Overflow)?;
            let departure = DepartureId::derive(&asset, r.departure_seq);
            let amount = match entry.kind {
                AssetKind::Unique => {
                    let a = r.unique.get_mut(&asset).ok_or(Refusal::UnknownAsset)?;
                    if a.location != Location::ObjectLayer {
                        return Err(Refusal::AssetNotHere);
                    }
                    if a.holder != Some(actor) {
                        return Err(Refusal::NotAuthorized);
                    }
                    a.location = Location::Departing(departure);
                    1
                }
                AssetKind::Fungible => {
                    if amount == 0 {
                        return Err(Refusal::Rule(RuleRefusal::ZeroAmount));
                    }
                    r.debit(class, actor, amount)?;
                    amount
                }
            };
            r.departures.insert(
                departure,
                Departure {
                    asset,
                    class,
                    holder: actor,
                    amount,
                    home_to,
                    requested_at: height,
                },
            );
            Ok(departure)
        })
    }

    /// `ObjectLayerTx::ConfirmDeparture`: the endpoint's `released` event
    /// returns the asset to `Home`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn confirm_departure(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<DepartureId, Refusal> {
        let (_, event) = self.read_event(proof, finality, false)?;
        let EndpointEvent::Released { departure } = event else {
            return Err(Refusal::UnexpectedEvent);
        };
        self.atomic(|r| {
            r.use_arrival(proof)?;
            let d = r
                .departures
                .remove(&departure)
                .ok_or(Refusal::UnknownDeparture)?;
            if r.class(&d.class)?.home_domain != proof.domain {
                return Err(Refusal::WrongEmitter);
            }
            if let Some(a) = r.unique.get_mut(&d.asset) {
                a.location = Location::Home;
                a.holder = None;
            }
            Ok(departure)
        })
    }

    /// The endpoint's `escaped` event: after silence the home owner took a
    /// unique asset out by the emergency exit. The object layer lets go of
    /// it (`escape_removes_asset_from_object_layer`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn record_escape(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<AssetId, Refusal> {
        let (_, event) = self.read_event(proof, finality, false)?;
        let EndpointEvent::Escaped {
            kind,
            contract,
            native_id,
            ..
        } = event
        else {
            return Err(Refusal::UnexpectedEvent);
        };
        if kind != AssetKind::Unique {
            // Fungible escape needs per-holder escape addresses (step 5).
            return Err(Refusal::KindMismatch);
        }
        self.atomic(|r| {
            r.use_arrival(proof)?;
            let class = AssetClassId::derive(proof.domain, &class_ref_bytes(kind, &contract));
            let asset = AssetId::derive(&class, &native_id);
            let a = r.unique.get_mut(&asset).ok_or(Refusal::UnknownAsset)?;
            if let Location::Departing(d) = a.location {
                r.departures.remove(&d);
            }
            a.location = Location::Home;
            a.holder = None;
            Ok(asset)
        })
    }

    // ------------------------------------------------------------ custody

    /// What the object layer says the endpoint holds for `class`: every
    /// value placed here plus every departure not yet released.
    #[must_use]
    pub fn recorded_custody(&self, class: &AssetClassId) -> u128 {
        let placed: u128 = match self.classes.get(class).map(|c| c.kind) {
            Some(AssetKind::Unique) => self
                .unique
                .values()
                .filter(|a| {
                    a.class == *class
                        && matches!(a.location, Location::ObjectLayer | Location::Guest { .. })
                })
                .count() as u128,
            Some(AssetKind::Fungible) => self
                .balances
                .iter()
                .filter(|((c, _), _)| c == class)
                .map(|(_, v)| *v)
                .sum(),
            None => 0,
        };
        let departing: u128 = self
            .departures
            .values()
            .filter(|d| d.class == *class)
            .map(|d| d.amount)
            .sum();
        placed + departing
    }

    /// `ObjectLayerTx::AuditCustody`: compare the proven home custody with
    /// the record. A deficit freezes the class (N-4).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn audit_custody(
        &mut self,
        caller: Address,
        class: AssetClassId,
        home_custody: u128,
    ) -> Result<CustodyAudit, Refusal> {
        // `home_custody` is caller-asserted in this transaction: there is no
        // home proof attached. Letting anyone assert a deficit would let
        // anyone freeze any class, so only the registrant may audit until a
        // proven custody attestation exists.
        if self.class(&class)?.registrant != caller {
            return Err(Refusal::NotAuthorized);
        }
        self.atomic(|r| {
            let recorded = r.recorded_custody(&class);
            let delta = i128::try_from(home_custody).unwrap_or(i128::MAX)
                - i128::try_from(recorded).unwrap_or(i128::MAX);
            let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
            if delta < 0 {
                entry.status = ClassStatus::Frozen(FreezeReason::CustodyDeficit);
            }
            Ok(CustodyAudit {
                recorded,
                home_custody,
                delta,
            })
        })
    }

    // ----------------------------------------- consent, escape, adopt, challenge

    /// `ObjectLayerTx::SetEscapeAddress`: register or clear an account's raw
    /// home escape/adoption binding (`<= MAX_ESCAPE_ADDRESS_BYTES`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_escape_address(&mut self, account: Address, home: Vec<u8>) -> Result<(), Refusal> {
        if home.len() > MAX_ESCAPE_ADDRESS_BYTES {
            return Err(Refusal::EscapeAddressTooLong);
        }
        if home.is_empty() {
            self.escape_addresses.remove(&account);
        } else {
            self.escape_addresses.insert(account, home);
        }
        Ok(())
    }

    /// `ObjectLayerTx::SetTentativeConsent`: opt an account in or out of
    /// single-dependency tentative arrivals.
    pub fn set_tentative_consent(&mut self, account: Address, consent: bool) {
        if consent {
            self.tentative_consent.insert(account);
        } else {
            self.tentative_consent.remove(&account);
        }
    }

    /// `ObjectLayerTx::Resolve`: clear an open tentative dependency once
    /// home finality settles.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn resolve(&mut self, dependency: DependencyId) -> Result<(), Refusal> {
        if !self.dependencies.contains_key(&dependency) {
            return Err(Refusal::UnknownDependency);
        }
        self.dependencies.remove(&dependency);
        Ok(())
    }

    /// `ObjectLayerTx::Adopt`: refused on unverified `escape_addresses` blobs;
    /// callers must prove home-chain ownership via [`Self::adopt_with_proof`]
    /// or [`Self::home_call`].
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn adopt(&mut self, account: Address, home: &[u8]) -> Result<u64, Refusal> {
        let _ = (account, home);
        Err(Refusal::NotAuthorized)
    }

    /// Migrate assets held by `Holder::Home` to `Holder::Account(account)`
    /// using a finality-verified home event signed by the home address whose
    /// payload commits to `account.as_bytes()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn adopt_with_proof(
        &mut self,
        account: Address,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<u64, Refusal> {
        let (family, event) = self.read_event(proof, finality, false)?;
        let EndpointEvent::Call {
            sender,
            nonce,
            calls,
        } = event
        else {
            return Err(Refusal::UnexpectedEvent);
        };
        profile_for(family).validate_address(&sender)?;
        if calls.as_slice() != account.as_bytes() {
            return Err(Refusal::NotAuthorized);
        }
        let domain = proof.domain;
        let identity = HomeIdentity::derive(domain, &sender);
        let from = Holder::Home(identity);
        let to = Holder::Account(account);

        self.atomic(|r| {
            r.use_arrival(proof)?;
            let expected = r.home_nonces.get(&identity).copied().unwrap_or(0);
            if nonce != expected {
                return Err(Refusal::HomeNonce {
                    expected,
                    got: nonce,
                });
            }
            r.home_nonces
                .insert(identity, expected.checked_add(1).ok_or(Refusal::Overflow)?);
            let mut moved: u64 = 0;
            let fungible_keys: Vec<(AssetClassId, u128)> = r
                .balances
                .iter()
                .filter_map(|((c, h), v)| {
                    if *h == from && r.classes.get(c).is_some_and(|cl| cl.home_domain == domain) {
                        Some((*c, *v))
                    } else {
                        None
                    }
                })
                .collect();
            for (class_id, amount) in fungible_keys {
                r.debit(class_id, from, amount)?;
                r.credit(class_id, to, amount)?;
                moved = moved.saturating_add(1);
            }
            for asset in r.unique.values_mut() {
                if asset.location == Location::ObjectLayer
                    && asset.holder == Some(from)
                    && r.classes
                        .get(&asset.class)
                        .is_some_and(|cl| cl.home_domain == domain)
                {
                    asset.holder = Some(to);
                    moved = moved.saturating_add(1);
                }
            }
            if moved == 0 {
                return Err(Refusal::NothingToAdopt);
            }
            Ok(moved)
        })
    }

    /// `ObjectLayerTx::AuditCode`: verify that `class`'s charter remains active
    /// and its recorded upgrade-authority slice matches `upgrade_authority`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn audit_code(&mut self, class: AssetClassId) -> Result<ClassStatus, Refusal> {
        self.atomic(|r| {
            let domain = r.class(&class)?.home_domain;
            let charter_ok = r
                .charters
                .get(&domain)
                .is_some_and(|c| c.status == CharterStatus::Active);
            if !charter_ok {
                let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
                entry.status = ClassStatus::Frozen(FreezeReason::UpgradeAuthorityChanged);
                return Ok(entry.status);
            }
            let vm_family = r.active_charter(domain)?.vm_family;
            let field = profile_for(vm_family).upgrade_authority_field();
            let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
            let current = entry.slice.get(field).cloned();
            if current != entry.upgrade_authority {
                entry.upgrade_authority = current;
                entry.status = ClassStatus::Frozen(FreezeReason::UpgradeAuthorityChanged);
            }
            Ok(entry.status)
        })
    }

    /// `ObjectLayerTx::Challenge`: open a rule-fidelity challenge on an active
    /// class, or freeze the class if an existing challenge has passed the
    /// rebuttal window (`DEFAULT_CHALLENGE_WINDOW_BLOCKS`) without rebuttal.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn challenge(
        &mut self,
        challenger: Address,
        class: AssetClassId,
        height: u64,
    ) -> Result<ClassStatus, Refusal> {
        self.atomic(|r| {
            let status = r.class(&class)?.status;
            if let Some(existing) = r.challenges.get(&class).copied() {
                if height
                    >= existing
                        .opened_at
                        .saturating_add(DEFAULT_CHALLENGE_WINDOW_BLOCKS)
                {
                    r.challenges.remove(&class);
                    let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
                    entry.status = ClassStatus::Frozen(FreezeReason::UnrebuttedChallenge);
                    return Ok(entry.status);
                }
                return Err(Refusal::ChallengeAlreadyOpen);
            }
            if status != ClassStatus::Active {
                return Err(Refusal::ClassFrozen);
            }
            if !r.holds(&class, &Holder::Account(challenger)) {
                return Err(Refusal::NotAuthorized);
            }
            r.challenges.insert(
                class,
                ChallengeRecord {
                    challenger,
                    opened_at: height,
                },
            );
            Ok(status)
        })
    }

    /// `ObjectLayerTx::Rebut`: clear an open challenge or lift an
    /// `UnrebuttedChallenge` freeze when signed by the class registrant.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn rebut(
        &mut self,
        actor: Address,
        class: AssetClassId,
        height: u64,
    ) -> Result<(), Refusal> {
        self.atomic(|r| {
            let _ = height;
            let registrant = r.class(&class)?.registrant;
            if actor != registrant {
                return Err(Refusal::NotAuthorized);
            }
            let had_open = r.challenges.remove(&class).is_some();
            let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
            if entry.status == ClassStatus::Frozen(FreezeReason::UnrebuttedChallenge) {
                entry.status = ClassStatus::Active;
                return Ok(());
            }
            if !had_open {
                return Err(Refusal::NoChallengeOpen);
            }
            Ok(())
        })
    }

    /// `ObjectLayerTx::GuestPlace` (`UOL-K2`): place an active unique asset in
    /// guest custody on another chartered domain.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] when the class is frozen, the caller does not hold
    /// the asset, the asset is not at [`Location::ObjectLayer`], or
    /// `guest_domain` has no active charter.
    pub fn guest_place(
        &mut self,
        caller: Holder,
        class: AssetClassId,
        native_id: &[u8],
        guest_domain: DomainId,
        guest_holder: Holder,
    ) -> Result<AssetId, Refusal> {
        self.atomic(|r| {
            let class_entry = r.class(&class)?.clone();
            if class_entry.status != ClassStatus::Active {
                return Err(Refusal::ClassFrozen);
            }
            if class_entry.kind != AssetKind::Unique {
                return Err(Refusal::KindMismatch);
            }
            if guest_domain == class_entry.home_domain {
                return Err(Refusal::CharterNotActive);
            }
            let _ = r.active_charter(guest_domain)?;
            let asset = AssetId::derive(&class, native_id);
            let entry = r.unique.get_mut(&asset).ok_or(Refusal::UnknownAsset)?;
            if entry.location != Location::ObjectLayer {
                return Err(Refusal::AssetNotHere);
            }
            if entry.holder != Some(caller) {
                return Err(Refusal::NotAuthorized);
            }
            entry.location = Location::Guest {
                domain: guest_domain,
                holder: guest_holder,
            };
            entry.holder = Some(guest_holder);
            Ok(asset)
        })
    }

    /// `ObjectLayerTx::GuestReturn` (`UOL-K2`): return a unique asset from
    /// [`Location::Guest`] back to [`Location::ObjectLayer`] upon a finalized
    /// endpoint event emitted by the guest domain.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] when finality is unproven, `proof.domain` does not
    /// match the recorded guest domain, or the asset is not in guest placement.
    pub fn guest_return(
        &mut self,
        class: AssetClassId,
        native_id: &[u8],
        recipient: Holder,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<AssetId, Refusal> {
        let (_, _event) = self.read_event(proof, finality, false)?;
        self.atomic(|r| {
            r.use_arrival(proof)?;
            let asset = AssetId::derive(&class, native_id);
            let entry = r.unique.get_mut(&asset).ok_or(Refusal::UnknownAsset)?;
            let Location::Guest { domain, .. } = entry.location else {
                return Err(Refusal::AssetNotHere);
            };
            if domain != proof.domain {
                return Err(Refusal::WrongEmitter);
            }
            entry.location = Location::ObjectLayer;
            entry.holder = Some(recipient);
            Ok(asset)
        })
    }

    /// `ObjectLayerTx::HomeStipendCall` (`UOL-K1`): execute a home-identity UOL
    /// action authorized directly by the home chain's classical key under a
    /// strict replay nonce, per-call and cumulative stipend cap, PQ holding
    /// ceiling, and automatic Quantum Alert Level 2/3 closure.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] when the verifier is absent or rejects the signature,
    /// the charter is inactive, the nonce mismatches, the stipend cap is
    /// exceeded, or the wrapped action is not an eligible home-identity call.
    pub fn home_stipend_call(
        &mut self,
        domain: DomainId,
        auth: &HomeKeyStipendAuth,
        action: &ObjectLayerTx,
        height: u64,
        verifier: Option<&dyn HomeStipendVerifier>,
    ) -> Result<HomeIdentity, Refusal> {
        if matches!(action, ObjectLayerTx::HomeStipendCall { .. }) {
            return Err(Refusal::NotAuthorized);
        }
        if auth.home_address.is_empty() || auth.home_address.len() > MAX_ESCAPE_ADDRESS_BYTES {
            return Err(Refusal::NotAuthorized);
        }
        if auth.requested_stipend_attos == 0
            || auth.requested_stipend_attos > MAX_HOME_STIPEND_ATTOS
        {
            return Err(Refusal::NotAuthorized);
        }
        let _ = self.active_charter(domain)?;
        let action_digest = home_stipend_action_digest(action)?;
        verifier
            .ok_or(Refusal::NotAuthorized)?
            .verify_stipend(domain, auth, &action_digest)?;
        let home = HomeIdentity::derive(domain, &auth.home_address);
        self.atomic(|r| {
            let expected = *r.home_stipend_nonces.get(&home).unwrap_or(&0);
            if auth.nonce != expected {
                return Err(Refusal::HomeNonce {
                    expected,
                    got: auth.nonce,
                });
            }
            let next = expected.checked_add(1).ok_or(Refusal::Overflow)?;
            r.home_stipend_nonces.insert(home, next);

            let spent = *r.home_stipend_spent.get(&home).unwrap_or(&0);
            let new_spent = spent
                .checked_add(auth.requested_stipend_attos)
                .ok_or(Refusal::Overflow)?;
            if new_spent > MAX_HOME_STIPEND_TOTAL_ATTOS {
                return Err(Refusal::NotAuthorized);
            }
            r.home_stipend_spent.insert(home, new_spent);

            let actor = Holder::Home(home);
            match action {
                ObjectLayerTx::Call { calls } => {
                    r.check_composite(calls)?;
                    for call in calls {
                        r.run_call(&actor, call)?;
                    }
                }
                ObjectLayerTx::Offer {
                    calls,
                    wants,
                    expiry,
                } => {
                    r.offer(actor, calls.clone(), wants.clone(), *expiry)?;
                }
                ObjectLayerTx::Accept { offer, calls } => {
                    r.accept(actor, *offer, calls, height)?;
                }
                ObjectLayerTx::Depart {
                    class,
                    native_id,
                    amount,
                    home_to,
                } => {
                    r.depart(actor, *class, native_id, *amount, home_to.clone(), height)?;
                }
                ObjectLayerTx::GuestPlace {
                    class,
                    native_id,
                    guest_domain,
                    guest_holder,
                } => {
                    r.guest_place(actor, *class, native_id, *guest_domain, *guest_holder)?;
                }
                _ => return Err(Refusal::NotAuthorized),
            }
            Ok(home)
        })
    }
}
