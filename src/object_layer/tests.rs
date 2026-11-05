//! The generic object-layer suite. Every family runs the same tests through
//! its own wire format (`family::fixture_for`), so the core is proven not to
//! depend on any family and every family is proven to deliver its parts.

use crate::core::address::Address;
use crate::domain::types::DomainId;
use crate::object_layer::charter::CharterRefusal;
use crate::object_layer::charter::{
    CanonicalCodeHashes, CharterStatus, CodeProof, DataPolicy, DomainCharter,
};
use crate::object_layer::family::class_ref_bytes;
use crate::object_layer::family::{
    fixture_for, profile_for, AssetKind, EventFixture, HomeVmFamily, RawEndpointEvent, SliceSource,
};
use crate::object_layer::ids::{AssetClassId, AssetId, HomeIdentity};
use crate::object_layer::registry::{
    Call, ClassRegistration, ClassStatus, FreezeReason, HomeEventProof, HomeFinality, Location,
    ObjectLayerParams, ObjectLayerRegistry, Phase, Refusal,
};
use crate::object_layer::rule::{
    AssetSlice, ClassRule, ClassSlice, Condition, Holder, ReferenceSample, TemplateId,
    TemplateParams, Verb,
};
use crate::object_layer::tx::{
    ObjectLayerActivation, ObjectLayerTx, TxContext, TxRefusal, ACTIVATION,
};

const DOMAIN: DomainId = 42;
const CANON_ENDPOINT: [u8; 32] = [0xc1; 32];
const CANON_VERIFIER: [u8; 32] = [0xc2; 32];

struct Proven(bool);

impl HomeFinality for Proven {
    fn event_is_proven(&self, _: &HomeEventProof) -> bool {
        self.0
    }
}

const YES: Proven = Proven(true);

fn alice() -> Holder {
    Holder::Account(Address([0xa1; 32]))
}

fn bob() -> Holder {
    Holder::Account(Address([0xb0; 32]))
}

/// One family's test world.
struct World {
    fx: &'static dyn EventFixture,
    reg: ObjectLayerRegistry,
    endpoint: Vec<u8>,
    fungible: Vec<u8>,
    unique: Vec<u8>,
    next_event: u64,
}

fn charter_for(family: HomeVmFamily, fx: &dyn EventFixture) -> DomainCharter {
    let dev = profile_for(family).dev_chain();
    DomainCharter {
        vm_family: family,
        chain_reference: dev.chain_reference.into(),
        address_prefix: dev.address_prefix.into(),
        endpoint: fx.address(0xe0),
        endpoint_code_hash: CANON_ENDPOINT,
        verifier: fx.address(0xe2),
        verifier_code_hash: CANON_VERIFIER,
        upgrade_notice: 100,
        silence_window: 1_000,
        data_policy: DataPolicy::Public,
        status: CharterStatus::Active,
    }
}

fn good_proof() -> CodeProof {
    CodeProof {
        endpoint_code_hash: CANON_ENDPOINT,
        verifier_code_hash: CANON_VERIFIER,
    }
}

fn params(family: HomeVmFamily) -> ObjectLayerParams {
    let mut p = ObjectLayerParams::default();
    p.canonical.insert(
        family,
        CanonicalCodeHashes {
            endpoint: CANON_ENDPOINT,
            verifier: CANON_VERIFIER,
        },
    );
    p
}

fn template(id: TemplateId) -> ClassRule {
    ClassRule::Template {
        id,
        params: TemplateParams::default(),
    }
}

fn samples(kind: AssetKind) -> Vec<ReferenceSample> {
    (1..=3u8)
        .map(|n| {
            let a = Holder::Account(Address([n; 32]));
            let b = Holder::Account(Address([n + 100; 32]));
            match kind {
                AssetKind::Fungible => ReferenceSample {
                    class_slice: ClassSlice::new(),
                    before: AssetSlice::Fungible {
                        balances: [(a, 10)].into_iter().collect(),
                    },
                    verbs: vec![Verb::Transfer {
                        from: a,
                        to: b,
                        amount: u128::from(n),
                    }],
                    after: AssetSlice::Fungible {
                        balances: [(a, 10 - u128::from(n)), (b, u128::from(n))]
                            .into_iter()
                            .collect(),
                    },
                },
                AssetKind::Unique => ReferenceSample {
                    class_slice: ClassSlice::new(),
                    before: AssetSlice::Unique { holder: a },
                    verbs: vec![Verb::Transfer {
                        from: a,
                        to: b,
                        amount: 1,
                    }],
                    after: AssetSlice::Unique { holder: b },
                },
            }
        })
        .collect()
}

fn registration(
    family: HomeVmFamily,
    kind: AssetKind,
    contract: Vec<u8>,
    slice: ClassSlice,
) -> ClassRegistration {
    let id = match kind {
        AssetKind::Fungible => TemplateId::FungibleV1,
        AssetKind::Unique => TemplateId::UniqueV1,
    };
    let source = match profile_for(family).slice_read_rule() {
        crate::object_layer::family::SliceReadRule::AccountAndStorageProof => {
            SliceSource::AccountAndStorageProof
        }
        crate::object_layer::family::SliceReadRule::EndpointEvent => SliceSource::EndpointEvent,
    };
    ClassRegistration {
        home_domain: DOMAIN,
        kind,
        contract,
        rule: template(id),
        slice,
        slice_source: source,
        samples: samples(kind),
        bond: 0,
    }
}

impl World {
    fn new(family: HomeVmFamily) -> Self {
        let fx = fixture_for(family);
        let mut reg = ObjectLayerRegistry::with_params(params(family));
        assert_eq!(
            reg.charter(DOMAIN, charter_for(family, fx), &good_proof(), true),
            Ok(true)
        );
        let fungible = fx.address(0x10);
        let unique = fx.address(0x12);
        let mut slice = ClassSlice::new();
        slice.insert(
            profile_for(family).upgrade_authority_field().into(),
            vec![1],
        );
        reg.register_class(
            Address([9; 32]),
            registration(family, AssetKind::Fungible, fungible.clone(), slice.clone()),
        )
        .expect("fungible class registers");
        reg.register_class(
            Address([9; 32]),
            registration(family, AssetKind::Unique, unique.clone(), slice),
        )
        .expect("unique class registers");
        Self {
            fx,
            reg,
            endpoint: fx.address(0xe0),
            fungible,
            unique,
            next_event: 0,
        }
    }

    fn proof(&mut self, event: RawEndpointEvent) -> HomeEventProof {
        self.next_event += 1;
        HomeEventProof {
            domain: DOMAIN,
            home_height: 1_000 + self.next_event,
            home_block_hash: [self.next_event as u8; 32],
            event_id: self.next_event.to_le_bytes().to_vec(),
            event,
            phase: Phase::Final,
            inclusion: Vec::new(),
        }
    }

    fn class(&self, kind: AssetKind) -> AssetClassId {
        let contract = match kind {
            AssetKind::Fungible => &self.fungible,
            AssetKind::Unique => &self.unique,
        };
        AssetClassId::derive(DOMAIN, &class_ref_bytes(kind, contract))
    }

    fn arrive_unique(
        &mut self,
        seed: u8,
        depositor: &[u8],
        to: Option<Holder>,
    ) -> Result<AssetId, Refusal> {
        let recipient = match to {
            Some(Holder::Account(a)) => Some(a),
            _ => None,
        };
        let raw = self.fx.arrive(
            &self.endpoint,
            AssetKind::Unique,
            &self.unique,
            &self.fx.native_id(seed),
            1,
            depositor,
            recipient,
        );
        let p = self.proof(raw);
        self.reg.arrive(&p, &YES)
    }

    fn arrive_fungible(&mut self, amount: u128, to: Address) -> Result<AssetId, Refusal> {
        let raw = self.fx.arrive(
            &self.endpoint,
            AssetKind::Fungible,
            &self.fungible,
            &[],
            amount,
            &self.fx.address(0x31),
            Some(to),
        );
        let p = self.proof(raw);
        self.reg.arrive(&p, &YES)
    }

    fn unique_call(&self, seed: u8, from: Holder, to: Holder) -> Call {
        Call {
            class: self.class(AssetKind::Unique),
            native_id: self.fx.native_id(seed),
            verb: Verb::Transfer {
                from,
                to,
                amount: 1,
            },
        }
    }

    fn fungible_call(&self, from: Holder, to: Holder, amount: u128) -> Call {
        Call {
            class: self.class(AssetKind::Fungible),
            native_id: Vec::new(),
            verb: Verb::Transfer { from, to, amount },
        }
    }
}

// ------------------------------------------------------------- per family

fn charter_refuses_non_canonical_endpoint(family: HomeVmFamily) {
    let fx = fixture_for(family);
    let mut reg = ObjectLayerRegistry::with_params(params(family));
    let mut bad = charter_for(family, fx);
    bad.endpoint_code_hash = [0xee; 32];
    let proof = CodeProof {
        endpoint_code_hash: [0xee; 32],
        verifier_code_hash: CANON_VERIFIER,
    };
    assert_eq!(
        reg.charter(DOMAIN, bad, &proof, true),
        Err(Refusal::Charter(CharterRefusal::NotCanonicalEndpoint))
    );
    // A proof that disagrees with the declared hashes is refused too.
    let wrong = CodeProof {
        endpoint_code_hash: [0xee; 32],
        verifier_code_hash: CANON_VERIFIER,
    };
    assert_eq!(
        reg.charter(DOMAIN, charter_for(family, fx), &wrong, true),
        Err(Refusal::Charter(CharterRefusal::ProofDisagrees))
    );
    assert_eq!(
        reg.charter(DOMAIN, charter_for(family, fx), &good_proof(), false),
        Err(Refusal::Charter(CharterRefusal::DomainNotActive))
    );
    assert!(reg.is_empty());
    // Idempotent for the same endpoint; a second binding is refused.
    assert_eq!(
        reg.charter(DOMAIN, charter_for(family, fx), &good_proof(), true),
        Ok(true)
    );
    assert_eq!(
        reg.charter(DOMAIN, charter_for(family, fx), &good_proof(), true),
        Ok(false)
    );
    let mut other = charter_for(family, fx);
    other.endpoint = fx.address(0xe4);
    assert_eq!(
        reg.charter(DOMAIN, other, &good_proof(), true),
        Err(Refusal::Charter(CharterRefusal::AlreadyChartered))
    );
}

fn arrival_round_trip_keeps_identity(family: HomeVmFamily) {
    let mut w = World::new(family);
    let depositor = w.fx.address(0x31);
    let first = w.arrive_unique(7, &depositor, Some(alice())).unwrap();

    // Single use: the same event carried twice is refused.
    let raw = w.fx.arrive(
        &w.endpoint,
        AssetKind::Unique,
        &w.unique,
        &w.fx.native_id(8),
        1,
        &depositor,
        None,
    );
    let p = w.proof(raw);
    w.reg.arrive(&p, &YES).unwrap();
    assert_eq!(w.reg.arrive(&p, &YES), Err(Refusal::ArrivalAlreadyUsed));

    // One location: a second arrival while the asset is here is refused.
    assert_eq!(
        w.arrive_unique(7, &depositor, Some(bob())),
        Err(Refusal::AssetNotHere)
    );

    let class = w.class(AssetKind::Unique);
    let native = w.fx.native_id(7);
    let departure = w
        .reg
        .depart(alice(), class, &native, 1, w.fx.address(0x33), 5)
        .unwrap();
    // A departing asset is frozen.
    assert_eq!(
        w.reg.call(alice(), &[w.unique_call(7, alice(), bob())]),
        Err(Refusal::AssetNotHere)
    );
    let raw = w.fx.released(&w.endpoint, &departure);
    let p = w.proof(raw);
    assert_eq!(w.reg.confirm_departure(&p, &YES), Ok(departure));
    assert_eq!(w.reg.unique[&first].location, Location::Home);

    let again = w.arrive_unique(7, &depositor, Some(bob())).unwrap();
    assert_eq!(first, again, "the round trip keeps the asset's identity");
    assert_eq!(w.reg.unique[&again].holder, Some(bob()));
}

fn home_call_binds_sender(family: HomeVmFamily) {
    let mut w = World::new(family);
    let h1 = w.fx.address(0x31);
    let h2 = w.fx.address(0x33);
    let asset = w.arrive_unique(3, &h1, None).unwrap();
    let id1 = Holder::Home(HomeIdentity::derive(DOMAIN, &h1));
    assert_eq!(w.reg.unique[&asset].holder, Some(id1));

    let calls = postcard::to_allocvec(&vec![w.unique_call(3, id1, alice())]).unwrap();
    // Another sender cannot act for h1's home identity.
    let raw = w.fx.call(&w.endpoint, &h2, 0, &calls);
    let p = w.proof(raw);
    assert_eq!(w.reg.home_call(&p, &YES), Err(Refusal::NotAuthorized));
    // An unproven event is refused.
    let raw = w.fx.call(&w.endpoint, &h1, 0, &calls);
    let p = w.proof(raw);
    assert_eq!(
        w.reg.home_call(&p, &Proven(false)),
        Err(Refusal::UnprovenEvent)
    );
    // A forged emitter is refused.
    let mut forged = w.fx.call(&w.endpoint, &h1, 0, &calls);
    forged.emitter = w.fx.address(0xe4);
    let p = w.proof(forged);
    assert_eq!(w.reg.home_call(&p, &YES), Err(Refusal::WrongEmitter));

    let raw = w.fx.call(&w.endpoint, &h1, 0, &calls);
    let p = w.proof(raw);
    assert_eq!(
        w.reg.home_call(&p, &YES),
        Ok(HomeIdentity::derive(DOMAIN, &h1))
    );
    assert_eq!(w.reg.unique[&asset].holder, Some(alice()));
    // Replaying nonce 0 in a new event is refused.
    let raw = w.fx.call(&w.endpoint, &h1, 0, &calls);
    let p = w.proof(raw);
    assert_eq!(
        w.reg.home_call(&p, &YES),
        Err(Refusal::HomeNonce {
            expected: 1,
            got: 0
        })
    );
}

fn slice_reads_follow_family_rule(family: HomeVmFamily) {
    let mut w = World::new(family);
    let mut reg = registration(
        family,
        AssetKind::Fungible,
        w.fx.address(0x14),
        ClassSlice::new(),
    );
    let admitted = reg.slice_source;
    reg.slice_source = match admitted {
        SliceSource::AccountAndStorageProof => SliceSource::EndpointEvent,
        SliceSource::EndpointEvent => SliceSource::AccountAndStorageProof,
    };
    assert_eq!(
        w.reg.register_class(Address([9; 32]), reg.clone()),
        Err(Refusal::SliceSourceNotAdmitted)
    );
    reg.slice_source = admitted;
    assert!(w.reg.register_class(Address([9; 32]), reg).is_ok());
}

fn upgrade_authority_change_freezes_class(family: HomeVmFamily) {
    let mut w = World::new(family);
    let field = profile_for(family).upgrade_authority_field().to_string();
    let class = w.class(AssetKind::Unique);
    w.arrive_unique(1, &w.fx.address(0x31), Some(alice()))
        .unwrap();

    let same: ClassSlice = [(field.clone(), vec![1])].into_iter().collect();
    assert_eq!(
        w.reg.refresh_class(class, same, Phase::Final),
        Ok(ClassStatus::Active)
    );
    let changed: ClassSlice = [(field, vec![2])].into_iter().collect();
    assert_eq!(
        w.reg.refresh_class(class, changed, Phase::Final),
        Ok(ClassStatus::Frozen(FreezeReason::UpgradeAuthorityChanged))
    );
    assert_eq!(
        w.reg.call(alice(), &[w.unique_call(1, alice(), bob())]),
        Err(Refusal::ClassFrozen)
    );
    // N-6: the exit stays open for a frozen class.
    let native = w.fx.native_id(1);
    assert!(w
        .reg
        .depart(alice(), class, &native, 1, w.fx.address(0x33), 9)
        .is_ok());
}

fn custody_parity_holds(family: HomeVmFamily) {
    let mut w = World::new(family);
    let class = w.class(AssetKind::Fungible);
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(100, a).unwrap();
    w.reg
        .call(alice(), &[w.fungible_call(alice(), bob(), 30)])
        .unwrap();
    w.reg
        .depart(alice(), class, &[], 20, w.fx.address(0x33), 3)
        .unwrap();
    assert_eq!(w.reg.balance(&class, &alice()), 50);
    assert_eq!(w.reg.balance(&class, &bob()), 30);
    assert_eq!(w.reg.recorded_custody(&class), 100);

    let audit = w.reg.audit_custody(class, 100).unwrap();
    assert_eq!(audit.delta, 0);
    assert_eq!(w.reg.classes[&class].status, ClassStatus::Active);
    let audit = w.reg.audit_custody(class, 99).unwrap();
    assert_eq!(audit.delta, -1);
    assert_eq!(
        w.reg.classes[&class].status,
        ClassStatus::Frozen(FreezeReason::CustodyDeficit)
    );
}

macro_rules! family_suite {
    ($family:expr, $charter:ident, $round_trip:ident, $home_call:ident, $slice:ident, $upgrade:ident, $parity:ident) => {
        #[test]
        fn $charter() {
            charter_refuses_non_canonical_endpoint($family);
        }
        #[test]
        fn $round_trip() {
            arrival_round_trip_keeps_identity($family);
        }
        #[test]
        fn $home_call() {
            home_call_binds_sender($family);
        }
        #[test]
        fn $slice() {
            slice_reads_follow_family_rule($family);
        }
        #[test]
        fn $upgrade() {
            upgrade_authority_change_freezes_class($family);
        }
        #[test]
        fn $parity() {
            custody_parity_holds($family);
        }
    };
}

family_suite!(
    HomeVmFamily::Evm,
    evm_charter_refuses_non_canonical_endpoint,
    evm_arrival_round_trip_keeps_identity,
    evm_home_call_binds_sender,
    evm_slice_reads_follow_family_rule,
    evm_upgrade_authority_change_freezes_class,
    evm_custody_parity_holds
);
family_suite!(
    HomeVmFamily::CosmWasm,
    cosmwasm_charter_refuses_non_canonical_endpoint,
    cosmwasm_arrival_round_trip_keeps_identity,
    cosmwasm_home_call_binds_sender,
    cosmwasm_slice_reads_follow_family_rule,
    cosmwasm_upgrade_authority_change_freezes_class,
    cosmwasm_custody_parity_holds
);
family_suite!(
    HomeVmFamily::Svm,
    svm_charter_refuses_non_canonical_endpoint,
    svm_arrival_round_trip_keeps_identity,
    svm_home_call_binds_sender,
    svm_slice_reads_follow_family_rule,
    svm_upgrade_authority_change_freezes_class,
    svm_custody_parity_holds
);
family_suite!(
    HomeVmFamily::Move,
    move_charter_refuses_non_canonical_endpoint,
    move_arrival_round_trip_keeps_identity,
    move_home_call_binds_sender,
    move_slice_reads_follow_family_rule,
    move_upgrade_authority_change_freezes_class,
    move_custody_parity_holds
);

// ------------------------------------------------------------- core

#[test]
fn object_layer_core_has_no_family_branch() {
    let core = [
        ("ids.rs", include_str!("ids.rs")),
        ("charter.rs", include_str!("charter.rs")),
        ("rule.rs", include_str!("rule.rs")),
        ("registry.rs", include_str!("registry.rs")),
        ("tx.rs", include_str!("tx.rs")),
        ("mod.rs", include_str!("mod.rs")),
    ];
    for (name, source) in core {
        assert!(
            !source.contains("HomeVmFamily::"),
            "{name} names a family variant; family code belongs behind FamilyProfile"
        );
        for family in [
            "family::evm",
            "family::svm",
            "family::cosmwasm",
            "family::move_family",
        ] {
            assert!(!source.contains(family), "{name} imports {family}");
        }
    }
}

#[test]
fn composite_refusal_does_not_mutate() {
    let mut w = World::new(HomeVmFamily::Evm);
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(10, a).unwrap();
    let before = w.reg.clone();
    let calls = [
        w.fungible_call(alice(), bob(), 4),
        w.fungible_call(alice(), bob(), 7), // only 6 left: refused
    ];
    assert!(w.reg.call(alice(), &calls).is_err());
    assert_eq!(w.reg, before);
}

#[test]
fn composite_call_is_atomic_and_bounded() {
    let mut w = World::new(HomeVmFamily::Move);
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(10, a).unwrap();
    w.arrive_unique(1, &w.fx.address(0x31), Some(alice()))
        .unwrap();
    let class = w.class(AssetKind::Fungible);
    w.reg
        .call(
            alice(),
            &[
                w.fungible_call(alice(), bob(), 4),
                w.unique_call(1, alice(), bob()),
            ],
        )
        .unwrap();
    assert_eq!(w.reg.balance(&class, &bob()), 4);
    let too_many: Vec<Call> = (0..17)
        .map(|_| w.fungible_call(alice(), bob(), 1))
        .collect();
    assert_eq!(w.reg.call(alice(), &too_many), Err(Refusal::TooManyCalls));
    assert_eq!(w.reg.call(alice(), &[]), Err(Refusal::EmptyComposite));
}

#[test]
fn offer_accept_runs_both_sides_or_none() {
    // A Move NFT for 25 units of an SVM-style fungible: here both classes
    // live on one domain, the rule is the same per class either way.
    let mut w = World::new(HomeVmFamily::Svm);
    let Holder::Account(b) = bob() else {
        unreachable!()
    };
    w.arrive_fungible(40, b).unwrap();
    w.arrive_unique(2, &w.fx.address(0x31), Some(alice()))
        .unwrap();
    let fclass = w.class(AssetKind::Fungible);
    let offer = w
        .reg
        .offer(
            alice(),
            vec![w.unique_call(2, alice(), bob())],
            vec![Condition::Payment {
                class: fclass,
                to: alice(),
                min_amount: 25,
            }],
            100,
        )
        .unwrap();
    let before = w.reg.clone();
    // Underpaying: the whole exchange is refused and nothing moves.
    assert_eq!(
        w.reg
            .accept(bob(), offer, &[w.fungible_call(bob(), alice(), 24)], 10),
        Err(Refusal::WantNotMet(0))
    );
    assert_eq!(w.reg, before);
    w.reg
        .accept(bob(), offer, &[w.fungible_call(bob(), alice(), 25)], 10)
        .unwrap();
    assert_eq!(w.reg.balance(&fclass, &alice()), 25);
    let asset = AssetId::derive(&w.class(AssetKind::Unique), &w.fx.native_id(2));
    assert_eq!(w.reg.unique[&asset].holder, Some(bob()));
    assert_eq!(
        w.reg.accept(bob(), offer, &[], 10),
        Err(Refusal::UnknownOffer)
    );
}

#[test]
fn object_layer_never_mints() {
    let mut w = World::new(HomeVmFamily::CosmWasm);
    let class = w.class(AssetKind::Fungible);
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(70, a).unwrap();
    w.arrive_fungible(30, a).unwrap();
    w.reg
        .call(alice(), &[w.fungible_call(alice(), bob(), 55)])
        .unwrap();
    let _ = w.reg.call(bob(), &[w.fungible_call(bob(), alice(), 56)]);
    w.reg
        .depart(bob(), class, &[], 5, w.fx.address(0x33), 1)
        .unwrap();
    let placed: u128 = w.reg.balances.values().sum();
    let departing: u128 = w.reg.departures.values().map(|d| d.amount).sum();
    assert_eq!(placed + departing, 100);
}

#[test]
fn escape_removes_asset_from_object_layer() {
    let mut w = World::new(HomeVmFamily::Evm);
    let asset = w
        .arrive_unique(4, &w.fx.address(0x31), Some(alice()))
        .unwrap();
    let raw = w.fx.escaped(
        &w.endpoint,
        AssetKind::Unique,
        &w.unique,
        &w.fx.native_id(4),
        &w.fx.address(0x31),
    );
    let p = w.proof(raw);
    assert_eq!(w.reg.record_escape(&p, &YES), Ok(asset));
    assert_eq!(w.reg.unique[&asset].location, Location::Home);
    assert_eq!(w.reg.unique[&asset].holder, None);
}

#[test]
fn tentative_events_are_refused_until_step_6() {
    let mut w = World::new(HomeVmFamily::Evm);
    let raw = w.fx.arrive(
        &w.endpoint,
        AssetKind::Unique,
        &w.unique,
        &w.fx.native_id(1),
        1,
        &w.fx.address(0x31),
        None,
    );
    let mut p = w.proof(raw);
    p.phase = Phase::Tentative;
    assert_eq!(w.reg.arrive(&p, &YES), Err(Refusal::TentativeClosed));
}

#[test]
fn class_registration_refuses_closed_rules_and_wrong_templates() {
    let mut w = World::new(HomeVmFamily::Evm);
    let mut reg = registration(
        HomeVmFamily::Evm,
        AssetKind::Fungible,
        w.fx.address(0x16),
        ClassSlice::new(),
    );
    reg.rule = ClassRule::Program;
    assert_eq!(
        w.reg.register_class(Address([9; 32]), reg.clone()),
        Err(Refusal::ClassClosedRule)
    );
    reg.rule = template(TemplateId::UniqueV1);
    assert_eq!(
        w.reg.register_class(Address([9; 32]), reg.clone()),
        Err(Refusal::TemplateNotForFamily)
    );
    reg.rule = template(TemplateId::FungibleV1);
    reg.samples.truncate(2);
    assert_eq!(
        w.reg.register_class(Address([9; 32]), reg),
        Err(Refusal::TooFewSamples)
    );
}

#[test]
fn object_layer_is_closed_on_testnet() {
    let mut reg = ObjectLayerRegistry::default();
    let ctx = TxContext {
        height: 1_000_000,
        signer: Address([1; 32]),
        activation: ACTIVATION,
        finality: &YES,
        domain_active: &|_| true,
    };
    let tx = ObjectLayerTx::Call { calls: Vec::new() };
    assert_eq!(tx.apply(&mut reg, &ctx), Err(TxRefusal::Closed));
    assert!(reg.is_empty());

    let open = TxContext {
        activation: ObjectLayerActivation { height: Some(10) },
        ..ctx
    };
    assert_eq!(
        ObjectLayerTx::Challenge {
            class: AssetClassId([0; 32])
        }
        .apply(&mut reg, &open),
        Err(TxRefusal::StepNotOpen)
    );
}

#[test]
fn registry_round_trips_through_json_and_postcard() {
    let mut w = World::new(HomeVmFamily::Svm);
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(5, a).unwrap();
    w.arrive_unique(1, &w.fx.address(0x31), None).unwrap();
    let json = serde_json::to_vec(&w.reg).expect("the V2 snapshot is JSON");
    let back: ObjectLayerRegistry = serde_json::from_slice(&json).unwrap();
    assert_eq!(back, w.reg);
    let bin = postcard::to_allocvec(&w.reg).unwrap();
    let back: ObjectLayerRegistry = postcard::from_bytes(&bin).unwrap();
    assert_eq!(back.root(), w.reg.root());
}

#[test]
fn object_layer_root_changes_with_content() {
    let mut w = World::new(HomeVmFamily::Move);
    let r0 = w.reg.root();
    let Holder::Account(a) = alice() else {
        unreachable!()
    };
    w.arrive_fungible(5, a).unwrap();
    assert_ne!(r0, w.reg.root());
}
