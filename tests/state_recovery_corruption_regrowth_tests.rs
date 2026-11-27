//! Regression and security tests for node state recovery (`src/chain/state_recovery`)
//! and the Budlum Name Service (`src/bns`).

use budlum_core::bns::offers::{CreateNameOffer, OfferKind};
use budlum_core::bns::registry::BnsRegistry;
use budlum_core::chain::state_recovery::health::{AlarmReason, HealthPolicy};
use budlum_core::chain::state_recovery::mempool::RecoveryMempool;
use budlum_core::chain::state_recovery::stage::{Stage, Stress};
use budlum_core::chain::state_recovery::tick::{
    Checkpoint, CheckpointView, StateRecoveryTick, TickOutcome,
};
use budlum_core::core::account::AccountState;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::core::Address;
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::domain::pq_canonical::{SealId, SealKind};
use budlum_core::execution::executor::Executor;
use budlum_core::registry::params::{GRACE_PERIOD, MIN_DURATION};

fn pq_seal(stage: Stage, height: u64) -> SealId {
    let kind = match stage {
        Stage::Medusa => SealKind::FinalityQc,
        Stage::Ephyra => SealKind::Anchor,
        Stage::Polyp => SealKind::RootSeal,
    };
    SealId::new(kind, height, &[SchemeId::ML_DSA_65])
}

fn digest(tag: u8, height: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&height.to_le_bytes());
    out[31] = tag;
    out
}

/// BUG 1 (`state_recovery/tick.rs`): Duplicate conflicting checkpoints for the
/// same `(stage, height)` must fail closed instead of silently picking the
/// first entry in `view.checkpoints`.
#[test]
fn duplicate_conflicting_checkpoints_fail_closed_with_alarm() {
    let mut tick = StateRecoveryTick::new(HealthPolicy::default());
    let forged_live = Checkpoint {
        stage: Stage::Medusa,
        height: 2000,
        local: Some(digest(0xAA, 2000)),
        canonical: Some(digest(0xAA, 2000)),
        seal: Some(pq_seal(Stage::Medusa, 2000)),
    };
    let real_live = Checkpoint {
        stage: Stage::Medusa,
        height: 2000,
        local: Some(digest(0xAA, 2000)),
        canonical: Some(digest(0xBB, 2000)),
        seal: Some(pq_seal(Stage::Medusa, 2000)),
    };
    let view = CheckpointView {
        live: 2000,
        previous: Some(1900),
        polyp: Some(1000),
        checkpoints: vec![forged_live, real_live],
    };

    let outcome = tick.observe(&view);
    assert!(
        matches!(
            outcome,
            TickOutcome::Alarm {
                reason: AlarmReason::NoCanonicalSource { height: 2000 },
                ..
            }
        ),
        "conflicting duplicate checkpoints at (Medusa, 2000) must fail closed with NoCanonicalSource alarm, got {outcome:?}"
    );
}

/// BUG 2 (`state_recovery/tick.rs`): A missing local block (`local: None`)
/// must NEVER report `TickOutcome::Healthy`, even if the canonical commitment
/// happens to be all-zero (`[0u8; 32]`).
#[test]
fn missing_local_block_cannot_report_healthy_even_for_zero_canonical_commitment() {
    let mut tick = StateRecoveryTick::new(HealthPolicy::default());
    let live = Checkpoint {
        stage: Stage::Medusa,
        height: 500,
        local: None,
        canonical: Some([0u8; 32]),
        seal: Some(pq_seal(Stage::Medusa, 500)),
    };
    let ephyra = Checkpoint {
        stage: Stage::Ephyra,
        height: 400,
        local: Some(digest(0x01, 400)),
        canonical: Some(digest(0x01, 400)),
        seal: Some(pq_seal(Stage::Ephyra, 400)),
    };
    let view = CheckpointView {
        live: 500,
        previous: Some(400),
        polyp: None,
        checkpoints: vec![live, ephyra],
    };

    let outcome = tick.observe(&view);
    assert!(
        !matches!(outcome, TickOutcome::Healthy),
        "missing local block must never report Healthy even when canonical commitment is zero, got {outcome:?}"
    );
    assert!(
        outcome.opens_sync(),
        "missing local block must request recovery sync, got {outcome:?}"
    );
}

/// BUG 3 (`state_recovery/tick.rs`): When the Ephyra anchor seal is dead/revoked
/// (`seal: None`) at height 1990 and the only valid PQ target is Polyp at height
/// 100, `regrowth_cost` must be priced against the real PQ-sealed target
/// (`2000 - 100 = 1900`), not the unsealed Ephyra (`2000 - 1990 = 10`).
#[test]
fn dead_ephyra_seal_does_not_underprice_polyp_reversion() {
    let mut tick = StateRecoveryTick::new(HealthPolicy::default());
    let diverged_live = Checkpoint {
        stage: Stage::Medusa,
        height: 2000,
        local: Some(digest(0xDE, 2000)),
        canonical: Some(digest(0xC0, 2000)),
        seal: Some(pq_seal(Stage::Medusa, 2000)),
    };
    // Unsealed/revoked Ephyra very close to live: must NOT trick cost model.
    let dead_ephyra = Checkpoint {
        stage: Stage::Ephyra,
        height: 1990,
        local: Some(digest(0xC0, 1990)),
        canonical: Some(digest(0xC0, 1990)),
        seal: None,
    };
    // Only valid PQ-sealed target is far below (regrowth cost = 1900).
    // With default 10:1 ratio, repair_cost (2000) < 10 * 1900 (19000), so the
    // honest economic verdict MUST be Repair (not a deep Polyp reversion).
    let deep_polyp = Checkpoint {
        stage: Stage::Polyp,
        height: 100,
        local: Some(digest(0xC0, 100)),
        canonical: Some(digest(0xC0, 100)),
        seal: Some(pq_seal(Stage::Polyp, 100)),
    };
    let view = CheckpointView {
        live: 2000,
        previous: Some(1990),
        polyp: Some(100),
        checkpoints: vec![diverged_live, dead_ephyra, deep_polyp],
    };

    let outcome = tick.observe(&view);
    assert_eq!(
        outcome,
        TickOutcome::Repair {
            stress: Stress::Divergence,
            repair_cost: 2000,
            regrowth_cost: 1900,
        },
        "regrowth_cost must be priced against sealed Polyp (1900), not dead Ephyra (10)"
    );
    assert_eq!(
        tick.held_stage(),
        Stage::Medusa,
        "node must not perform an uneconomical deep Polyp reversion"
    );
}

/// BUG 4 (`bns/registry.rs`): `verify_state_proof` must reject an inclusion
/// proof whose `extras` pre-image was stripped (`None`) while smuggling an
/// unauthenticated non-empty top-level `branch.address`.
#[test]
fn bns_verify_state_proof_refuses_unauthenticated_address_without_extras() {
    let owner = Address::from([0x11; 32]);
    let legitimate_target = Address::from([0x22; 32]);
    let attacker = Address::from([0xEE; 32]);

    // Seed name through deserialized state.
    let json = serde_json::json!({
        "names": {
            "alice.bud": {
                "name": "alice.bud",
                "owner": owner,
                "address": legitimate_target,
                "registered_at": 1,
                "expires_at": 100,
                "storage_root": null,
                "storage_domain_id": null,
                "storage_root_height": null,
                "content": null,
                "consensus_domain_id": null,
                "subdomains": {},
                "records": {}
            }
        },
        "base_cost": 100,
        "max_names": 1000
    });
    let mut reg: BnsRegistry = serde_json::from_value(json).expect("deserialize registry");
    reg.rebuild_expiry_index();

    let root = reg.root();
    let honest = reg.prove_name("alice.bud", 10);
    let verified = BnsRegistry::verify_state_proof(&honest, &root, 10)
        .expect("honest proof verifies")
        .expect("included");
    assert_eq!(verified.address, Some(legitimate_target));

    // Attack: strip `extras` and replace top-level `address` with `attacker`.
    let mut forged = honest.clone();
    {
        let entry = forged.entry.as_mut().expect("entry present");
        entry.extras = None;
        entry.address = Some(attacker);
    }
    assert!(
        BnsRegistry::verify_state_proof(&forged, &root, 10).is_err(),
        "forged top-level address with extras=None must be rejected fail-closed"
    );

    // Legitimate redaction: withholding `extras` is only valid when top-level
    // `address` is also withheld (`None`).
    let mut redacted = honest;
    {
        let entry = redacted.entry.as_mut().expect("entry present");
        entry.extras = None;
        entry.address = None;
    }
    let ok = BnsRegistry::verify_state_proof(&redacted, &root, 10)
        .expect("honestly redacted proof verifies")
        .expect("included");
    assert_eq!(ok.address, None);
}

/// BUG 5 (`bns/registry.rs`): At the exact grace-expiry boundary
/// (`current_epoch == expires_at + GRACE_PERIOD`), a full registry
/// (`names.len() == max_names`) must reclaim the expired slot consistently with
/// `prune_expired` and `is_renewable_by`.
#[test]
fn bns_full_registry_reclaims_expired_name_at_exact_grace_boundary() {
    let primary_seller = Address::from([0xB2; 32]);
    assert!(
        BnsRegistry::new().is_primary_seller(&primary_seller),
        "default genesis primary seller must be active"
    );

    let alice = Address::from([0x11; 32]);
    let buyer_kp = KeyPair::generate().expect("buyer keypair");
    let buyer = Address::from(buyer_kp.public_key_bytes());

    // Build a full registry with `max_names = 1` holding `old.bud` expiring at epoch 50.
    let json = serde_json::json!({
        "names": {
            "old.bud": {
                "name": "old.bud",
                "owner": alice,
                "address": alice,
                "registered_at": 1,
                "expires_at": 50,
                "storage_root": null,
                "storage_domain_id": null,
                "storage_root_height": null,
                "content": null,
                "consensus_domain_id": null,
                "subdomains": {},
                "records": {}
            }
        },
        "base_cost": 100,
        "max_names": 1
    });
    let mut reg: BnsRegistry = serde_json::from_value(json).expect("deserialize");
    reg.rebuild_expiry_index();

    let exact_grace_end = 50 + GRACE_PERIOD;
    assert!(
        !reg.is_renewable_by("old.bud", &alice, exact_grace_end),
        "old.bud is no longer renewable at exact grace_end"
    );
    assert!(
        reg.is_available_for_primary("fresh.bud", exact_grace_end),
        "fresh.bud is valid"
    );

    let mut state = AccountState::new();
    state.bns_registry = reg;
    state.epoch_index = exact_grace_end;

    // `prune_expired` already treats `exact_grace_end` as reclaimable.
    let mut clone_for_prune = state.bns_registry.clone();
    assert_eq!(clone_for_prune.prune_expired(exact_grace_end), 1);

    // Seed a primary offer and execute `TransactionType::BnsBuyName` at `exact_grace_end`.
    let price = state.bns_registry.calculate_cost("fresh.bud", MIN_DURATION);
    let offer_id = state
        .marketplace
        .create_name_offer(
            primary_seller,
            CreateNameOffer {
                name: "fresh.bud".to_string(),
                price_atoms: price,
                duration: MIN_DURATION,
                kind: OfferKind::Primary,
                expires_at_epoch: exact_grace_end + 10,
            },
            exact_grace_end,
        )
        .expect("create primary offer");

    state.get_or_create(&buyer).balance = price.saturating_add(10_000_000);
    state.get_or_create(&primary_seller).balance = 1_000_000;

    let data = bincode::serialize(&offer_id).expect("encode offer_id");
    let mut tx = Transaction::new(buyer, Address::zero(), price, data);
    tx.fee = 1_000;
    tx.nonce = 0;
    tx.tx_type = TransactionType::BnsBuyName;
    tx.sign(&buyer_kp);

    Executor::apply_transaction(&mut state, &tx).expect(
        "full BNS registry must reclaim post-grace expired name at exact grace_end boundary",
    );
    assert_eq!(
        state
            .bns_registry
            .resolve_owner("fresh.bud", exact_grace_end),
        Some(buyer),
        "fresh.bud must belong to buyer after reclaiming old.bud"
    );
    assert_eq!(
        state.bns_registry.names().len(),
        1,
        "registry size must stay within max_names=1"
    );
}

/// End-to-end corrupted-node recovery lifecycle:
/// - Identical duplicate checkpoint entries remain idempotent and healthy.
/// - On state corruption at height 2000, the tick reverts to PQ-sealed Ephyra
///   at height 1900, stashes transactions from reverted heights in
///   `RecoveryMempool`, regrows back to Medusa once canonical blocks land, and
///   re-offers only transactions missing from the canonical chain.
#[test]
fn identical_duplicate_checkpoints_and_full_revert_regrow_mempool_cycle() {
    let mut tick = StateRecoveryTick::new(HealthPolicy::default());
    let healthy_live = Checkpoint {
        stage: Stage::Medusa,
        height: 2000,
        local: Some(digest(0xC0, 2000)),
        canonical: Some(digest(0xC0, 2000)),
        seal: Some(pq_seal(Stage::Medusa, 2000)),
    };
    let ephyra = Checkpoint {
        stage: Stage::Ephyra,
        height: 1900,
        local: Some(digest(0xC0, 1900)),
        canonical: Some(digest(0xC0, 1900)),
        seal: Some(pq_seal(Stage::Ephyra, 1900)),
    };

    // Identical duplicate checkpoints are harmlessly accepted.
    let dup_healthy = CheckpointView {
        live: 2000,
        previous: Some(1900),
        polyp: None,
        checkpoints: vec![healthy_live.clone(), healthy_live.clone(), ephyra.clone()],
    };
    assert_eq!(tick.observe(&dup_healthy), TickOutcome::Healthy);

    // State corruption at 2000 -> reverts to Ephyra @ 1900.
    let corrupted_live = Checkpoint {
        local: Some(digest(0xDE, 2000)),
        ..healthy_live.clone()
    };
    let corrupted_view = CheckpointView {
        live: 2000,
        previous: Some(1900),
        polyp: None,
        checkpoints: vec![corrupted_live, ephyra.clone()],
    };
    let outcome = tick.observe(&corrupted_view);
    assert!(
        matches!(outcome, TickOutcome::Reverted(ref r) if r.to == Stage::Ephyra && r.height_after == 1900)
    );
    assert!(outcome.opens_sync());
    assert_eq!(tick.held_stage(), Stage::Ephyra);

    // Stash transactions from reverted heights (1901..=2000).
    let mut mempool = RecoveryMempool::new();
    let mut tx_confirmed = Transaction::genesis();
    tx_confirmed.hash = "tx-canonical-confirmed".to_string();
    let mut tx_dropped = Transaction::genesis();
    tx_dropped.hash = "tx-needs-rebroadcast".to_string();
    assert_eq!(
        mempool.stash(&[tx_confirmed, tx_dropped], 1950, &|_| 128),
        2
    );

    // Once canonical blocks sync back, the tick regrows Ephyra -> Medusa.
    let recovered_view = CheckpointView {
        live: 2000,
        previous: Some(1900),
        polyp: None,
        checkpoints: vec![healthy_live, ephyra],
    };
    assert_eq!(tick.observe(&recovered_view), TickOutcome::Healthy);
    assert_eq!(tick.held_stage(), Stage::Medusa);
    assert_eq!(tick.held_height(), 2000);

    // Only unconfirmed transactions are re-offered after regrowth.
    let rebroadcast = mempool.take_unconfirmed(2000, &|h| h == "tx-canonical-confirmed");
    assert_eq!(rebroadcast.len(), 1);
    assert_eq!(rebroadcast[0].hash, "tx-needs-rebroadcast");
}

/// Refused unauthorized BNS mutations must leave the registry root and state
/// bit-for-bit unchanged.
#[test]
fn bns_refused_mutations_preserve_root_and_state() {
    let owner = Address::from([0x11; 32]);
    let attacker = Address::from([0xEE; 32]);
    let json = serde_json::json!({
        "names": {
            "bob.bud": {
                "name": "bob.bud",
                "owner": owner,
                "address": owner,
                "registered_at": 1,
                "expires_at": 100,
                "storage_root": null,
                "storage_domain_id": null,
                "storage_root_height": null,
                "content": null,
                "consensus_domain_id": null,
                "subdomains": {},
                "records": {}
            }
        },
        "base_cost": 100,
        "max_names": 1000
    });
    let mut reg: BnsRegistry = serde_json::from_value(json).expect("deserialize");
    reg.rebuild_expiry_index();
    let root_before = reg.root();

    assert!(reg.renew("bob.bud", &attacker, 10, MIN_DURATION).is_err());
    assert!(reg
        .register_subdomain("bob.bud", "app".to_string(), attacker, &attacker, 10)
        .is_err());
    assert!(reg
        .set_storage("bob.bud", attacker, [0x99; 32], 1, 10)
        .is_err());

    assert_eq!(reg.root(), root_before);
    assert!(reg.list_subdomains("bob.bud", 10).expect("live").is_empty());
}
