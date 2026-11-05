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
//! other 9.5 item 4 methods. Both land in the next WP-49 step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};
use crate::object_layer::charter::{
    check_charter, CanonicalCodeHashes, CharterRefusal, CharterStatus, CodeProof, DomainCharter,
};
use crate::object_layer::family::{
    class_ref_bytes, profile_for, AssetKind, EndpointEvent, FamilyError, HomeVmFamily,
    RawEndpointEvent, SliceSource,
};
use crate::object_layer::ids::{ArrivalKey, AssetClassId, AssetId, DepartureId, HomeIdentity};
use crate::object_layer::rule::{
    apply_rule, sample_commitment, verify_samples, AssetSlice, ClassRule, ClassSlice, Condition,
    Holder, ReferenceSample, RuleRefusal, Verb,
};
use crate::object_layer::{DEFAULT_MIN_REFERENCE_SAMPLES, MAX_COMPOSITE_CALLS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The finality phase of a home event (9.3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Final,
    /// Opens with WP-49 step 6. Refused until then.
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
    /// The home code's upgrade authority changed (9.3.4 item 6).
    UpgradeAuthorityChanged,
    /// Home custody fell below the object-layer record (N-4).
    CustodyDeficit,
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

/// Where an asset is (9.3.7 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Location {
    Home,
    ObjectLayer,
    Departing(DepartureId),
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

/// One call of a composite (9.3.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    pub class: AssetClassId,
    /// Empty for a fungible class.
    pub native_id: Vec<u8>,
    pub verb: Verb,
}

/// A standing offer (9.3.9 item 2).
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
            min_class_bond: 0,
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

/// The outcome of a custody audit (9.3.7 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAudit {
    pub recorded: u128,
    pub home_custody: u128,
    /// `home_custody - recorded`. Negative is a deficit and freezes the class.
    pub delta: i128,
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
    pub fn charter(
        &mut self,
        domain: DomainId,
        charter: DomainCharter,
        proof: &CodeProof,
        domain_active: bool,
    ) -> Result<bool, Refusal> {
        check_charter(
            &charter,
            proof,
            self.params.canonical.get(&charter.vm_family),
            domain_active,
        )
        .map_err(Refusal::Charter)?;
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
    ) -> Result<(HomeVmFamily, EndpointEvent), Refusal> {
        let charter = self.active_charter(proof.domain)?;
        if proof.phase == Phase::Tentative {
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
    pub fn register_class(
        &mut self,
        registrant: Address,
        reg: ClassRegistration,
    ) -> Result<AssetClassId, Refusal> {
        let charter = self.active_charter(reg.home_domain)?;
        let family = profile_for(charter.vm_family);
        family.validate_address(&reg.contract)?;
        if !reg.rule.is_open() {
            return Err(Refusal::ClassClosedRule);
        }
        let ClassRule::Template { id, .. } = &reg.rule else {
            return Err(Refusal::ClassClosedRule);
        };
        if *id != family.template_for(reg.kind) {
            return Err(Refusal::TemplateNotForFamily);
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
    pub fn refresh_class(
        &mut self,
        class: AssetClassId,
        updates: ClassSlice,
        phase: Phase,
    ) -> Result<ClassStatus, Refusal> {
        if phase == Phase::Tentative {
            return Err(Refusal::TentativeClosed);
        }
        self.atomic(|r| {
            let domain = r
                .classes
                .get(&class)
                .ok_or(Refusal::UnknownClass)?
                .home_domain;
            let family = profile_for(r.active_charter(domain)?.vm_family);
            let field = family.upgrade_authority_field();
            let entry = r.classes.get_mut(&class).ok_or(Refusal::UnknownClass)?;
            entry.slice.extend(updates);
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

    /// `ObjectLayerTx::Arrive`, final phase. Anybody may carry the event.
    pub fn arrive(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<AssetId, Refusal> {
        let (_, event) = self.read_event(proof, finality)?;
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
            // Escape addresses are set by `SetEscapeAddress` (step 5).
            Condition::EscapeAddress { .. } => false,
        }
    }

    /// `ObjectLayerTx::HomeCall`: the home event's sender acts as its home
    /// identity. The authority is the finality proof (9.3.10 item 2); the
    /// per-identity nonce stops a replay of an older call.
    pub fn home_call(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<HomeIdentity, Refusal> {
        let (family, event) = self.read_event(proof, finality)?;
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
    pub fn confirm_departure(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<DepartureId, Refusal> {
        let (_, event) = self.read_event(proof, finality)?;
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
    pub fn record_escape(
        &mut self,
        proof: &HomeEventProof,
        finality: &dyn HomeFinality,
    ) -> Result<AssetId, Refusal> {
        let (_, event) = self.read_event(proof, finality)?;
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
                .filter(|a| a.class == *class && a.location == Location::ObjectLayer)
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
    pub fn audit_custody(
        &mut self,
        class: AssetClassId,
        home_custody: u128,
    ) -> Result<CustodyAudit, Refusal> {
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
}
