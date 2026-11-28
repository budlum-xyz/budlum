//! End-to-end tests for ConsensusDomainRegistry fairness, lifecycle safety,
//! inactivity reclamation invariants, and single-domain CAIP-2 deduplication
//! in UniversalDomainCatalog::from_chain_state.

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::domain::plugin::default_domain;
use budlum_core::domain::registry::{
    ConsensusDomainRegistry, DOMAIN_INACTIVITY_RETIREMENT_BLOCKS, MAX_ACTIVE_DOMAINS_PER_OPERATOR,
};
use budlum_core::domain::types::{ConsensusDomain, ConsensusKind, DomainStatus};
use budlum_core::unification::UniversalDomainCatalog;

fn test_domain(id: u32, operator: Address) -> ConsensusDomain {
    let mut d = default_domain(id, ConsensusKind::PoS, u64::from(id) + 1000, "pos", 0);
    d.operator = Some(operator);
    d
}

#[test]
fn reclaim_inactive_domains_protects_root_domain_and_frozen_domains() {
    let mut reg = ConsensusDomainRegistry::new();
    let op = Address::from([0x11; 32]);

    let root_dom = test_domain(0, op);
    let frozen_dom = test_domain(10, op);
    let idle_dom = test_domain(11, op);
    reg.register(root_dom).expect("register root domain 0");
    reg.register(frozen_dom).expect("register domain 10");
    reg.register(idle_dom).expect("register domain 11");
    reg.note_activity(0, 10);
    reg.note_activity(10, 10);
    reg.note_activity(11, 10);

    // Freeze domain 10 (fraud/contradiction investigation pending).
    reg.transition_status_checked(10, DomainStatus::Frozen)
        .expect("freeze domain 10");

    // Advance past the full inactivity window.
    let reclaimed = reg.reclaim_inactive_domains(
        10 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS + 1,
        DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
    );

    // Root domain 0 and Frozen domain 10 MUST NEVER be deleted by inactivity reclamation.
    assert!(
        reg.get(0).is_some(),
        "root domain 0 MUST NOT be reclaimed by inactivity"
    );
    assert!(
        reg.get(10).is_some(),
        "Frozen domain 10 MUST NOT evade freeze/slash investigation via inactivity reclamation"
    );
    // Idle active domain 11 MUST be reclaimed.
    assert!(
        reg.get(11).is_none() && reclaimed.contains(&11),
        "idle active domain 11 must be reclaimed"
    );
}

#[test]
fn single_operator_cannot_bypass_quota_by_retiring_leaves_without_reclamation() {
    let mut reg = ConsensusDomainRegistry::new();
    let attacker = Address::from([0x22; 32]);

    for i in 0..MAX_ACTIVE_DOMAINS_PER_OPERATOR {
        let id = u32::try_from(100 + i).expect("fits u32");
        reg.register(test_domain(id, attacker))
            .expect("within operator quota");
        reg.note_activity(id, 50);
    }

    // Freeze and retire one domain: its leaf STILL occupies self.domains and counts
    // against MAX_REGISTERED_DOMAINS until actually reclaimed.
    reg.transition_status_checked(100, DomainStatus::Frozen)
        .expect("freeze 100");
    reg.transition_status_checked(100, DomainStatus::Retired)
        .expect("retire 100");

    // Attempting to register a 33rd tree leaf while all 32 leaves still occupy the
    // registry MUST fail closed so one operator can never exhaust MAX_REGISTERED_DOMAINS.
    let extra = test_domain(999, attacker);
    let err = reg
        .register(extra.clone())
        .expect_err("retired leaf still occupying tree must count toward operator quota");
    assert!(err.contains("quota"), "expected quota error, got: {err}");
    assert_eq!(reg.len(), MAX_ACTIVE_DOMAINS_PER_OPERATOR);

    // Once the retired leaf is actually reclaimed and removed from the tree, the slot reopens.
    let reclaimed = reg.reclaim_inactive_domains(
        50 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
        DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
    );
    assert!(!reclaimed.is_empty());
    reg.register(extra)
        .expect("registration must succeed once leaves are reclaimed and removed");
}

#[test]
fn unpinged_zombie_domain_without_note_activity_is_still_reclaimed() {
    let mut reg = ConsensusDomainRegistry::new();
    let op = Address::from([0x33; 32]);

    // Register domain 50 WITHOUT calling note_activity (simulating a zombie registration).
    reg.register(test_domain(50, op))
        .expect("register zombie domain 50");

    let reclaimed = reg.reclaim_inactive_domains(
        DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
        DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
    );
    assert!(
        reclaimed.contains(&50) && reg.get(50).is_none(),
        "zombie domain with no note_activity must be reclaimed after inactivity window"
    );
}

#[test]
fn universal_domain_catalog_reflects_live_caip2_bindings_and_excludes_reclaimed_domains() {
    let mut state = AccountState::new();
    let op = Address::from([0x44; 32]);

    let eth = test_domain(77, op);
    state
        .settlement
        .domains
        .register_with_caip2(eth, "eip155:1")
        .expect("register domain 77 with eip155:1");
    state.settlement.domains.note_activity(77, 10);

    let catalog_live = UniversalDomainCatalog::from_chain_state(&state);
    let rec = catalog_live.get(77).expect("live domain 77 present");
    assert_eq!(rec.caip2_reference, "eip155:1");
    let proof = catalog_live
        .prove_domain_inclusion(77)
        .expect("inclusion proof for 77");
    assert!(proof.verify(&catalog_live.catalog_root()));

    // After inactivity reclamation removes domain 77, from_chain_state must drop it immediately
    // and its CAIP-2 slot must become re-registrable cleanly.
    let reclaimed = state.settlement.domains.reclaim_inactive_domains(
        10 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
        DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
    );
    assert_eq!(reclaimed, vec![77]);
    let catalog_after = UniversalDomainCatalog::from_chain_state(&state);
    assert!(catalog_after.get(77).is_none());
    assert!(state
        .settlement
        .domains
        .domain_id_by_caip2("eip155:1")
        .is_none());
}
