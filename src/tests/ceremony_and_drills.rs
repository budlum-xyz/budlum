//! Ceremony rehearsal and T-1..T-4 / T-7 deterministic protocol drills.

use std::collections::BTreeSet;

use crate::chain::genesis_ceremony::{assemble, genesis_hash, CeremonyInputs, OperatorRecord};
use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::crypto::pq::generate_keypair;
use crate::crypto::primitives::ValidatorKeys;
use crate::crypto::scheme::SchemeId;
use crate::rpc::method_class::{Effect, Listener, METHOD_CLASSES};
use crate::storage::bud3::placement::PlacementTable;
use crate::tokenomics::{TokenomicsAddresses, BUD_MAX_SUPPLY};
use crate::validators::handover::{
    handover_spec, is_finality_stalled, DutyKind, HandoverBound, RecoveryTracker,
    SeatHandoverTracker, FINALITY_STALL_BLOCKS, TESTNET_CHECKPOINT_INTERVAL_BLOCKS,
};
use crate::validators::{
    ValidatorClass, ValidatorDirectory, ValidatorRegistration, MIN_MOBILE_QUOTA_BYTES,
    MIN_MOBILE_STAKE,
};

fn make_operator_record(index: usize) -> OperatorRecord {
    let keys = ValidatorKeys::generate().expect("validator keys generate");
    OperatorRecord {
        validator: keys.address(),
        registration: keys
            .consensus_key_registration(Network::Testnet.chain_id().value())
            .expect("consensus registration signs"),
        moniker: format!("rehearsal-full-{index:02}"),
    }
}

fn rehearsal_destinations() -> TokenomicsAddresses {
    TokenomicsAddresses {
        community: Address::from([0x51; 32]),
        liquidity: Address::from([0x52; 32]),
        ecosystem: Address::from([0x53; 32]),
        team: Address::from([0x54; 32]),
        burn_reserve: Address::from([0x55; 32]),
    }
}

#[test]
fn rehearsal_ceremony_assembles_eight_full_validators_deterministically() {
    let records: Vec<OperatorRecord> = (0..8).map(make_operator_record).collect();
    let mut reversed = records.clone();
    reversed.reverse();

    let g1 = assemble(
        Network::Testnet,
        CeremonyInputs {
            operators: records.clone(),
            tokenomics_addresses: rehearsal_destinations(),
            timestamp_ms: Some(1_800_000_000_000),
            allocations: Vec::new(),
        },
    )
    .expect("8-validator rehearsal ceremony must assemble");

    let g2 = assemble(
        Network::Testnet,
        CeremonyInputs {
            operators: reversed,
            tokenomics_addresses: rehearsal_destinations(),
            timestamp_ms: Some(1_800_000_000_000),
            allocations: Vec::new(),
        },
    )
    .expect("reversed operator order must assemble identically");

    assert_eq!(genesis_hash(&g1), genesis_hash(&g2));
    assert_eq!(g1.validators.len(), 8);

    let mut dup = records;
    if let Some(first) = dup.first().cloned() {
        dup.push(first);
    }
    assert!(assemble(
        Network::Testnet,
        CeremonyInputs {
            operators: dup,
            tokenomics_addresses: rehearsal_destinations(),
            timestamp_ms: Some(1_800_000_000_000),
            allocations: Vec::new(),
        },
    )
    .is_err());

    let raw = std::fs::read_to_string("config/ceremony-rehearsal-genesis.json")
        .expect("rehearsal-genesis.json exists");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(doc["chain_id"].as_u64(), Some(45_261));
    let vals = doc["validators"].as_array().expect("validators array");
    assert!(vals.len() >= 8);
    let alloc_sum: u64 = doc["allocations"]
        .as_array()
        .expect("allocations array")
        .iter()
        .filter_map(|entry| entry.get(1).and_then(serde_json::Value::as_u64))
        .sum();
    assert_eq!(alloc_sum, BUD_MAX_SUPPLY);
}

#[test]
fn drill_t1_and_t4_mobile_departure_and_one_epoch_activation() {
    // T-1: When all Mobile validators stop simultaneously (mobile = 0),
    // the Full-only placement row still reconstructs every segment (>= k + 2 symbols)
    // and finality seats never include Mobile or MobileOpportunistic validators (V-1, V-2).
    let table = PlacementTable::default();
    table.validate().expect("default placement table valid");
    let row = table
        .lookup(64, 0)
        .expect("Full-only placement row exists when all Mobile nodes are offline");
    assert_eq!(row.n_mobile, 0);
    assert!(row.total_symbols() >= u64::from(table.k) + 2);

    let candidates = [
        ([1u8; 32], ValidatorClass::Full),
        ([2u8; 32], ValidatorClass::Full),
        ([3u8; 32], ValidatorClass::Full),
        ([4u8; 32], ValidatorClass::Full),
        ([5u8; 32], ValidatorClass::Mobile),
        ([6u8; 32], ValidatorClass::MobileOpportunistic),
    ];
    let tracker = SeatHandoverTracker::from_epoch_candidates(10, &candidates);
    assert_eq!(tracker.active_seats().len(), 4);
    assert_eq!(tracker.standby_len(), 0);

    // T-4: Mobile quota / class changes activate strictly at E + 1 via activate_due.
    let mut dir = ValidatorDirectory::new();
    let owner = Address::from([0x81; 32]);
    let (op_pk, _) = generate_keypair(SchemeId::ML_DSA_65).expect("keygen");
    let reg = ValidatorRegistration {
        owner,
        class: ValidatorClass::Mobile,
        peer_id: b"12D3KooWRehearsalMobile01".to_vec(),
        operator_key: op_pk,
        custody_quota_bytes: MIN_MOBILE_QUOTA_BYTES,
        seat: None,
        relay_offer: None,
        gateway_offer: None,
    };
    dir.register(&reg, MIN_MOBILE_STAKE, MIN_MOBILE_STAKE, 10)
        .expect("mobile registration");
    dir.request_quota_increase(&owner, MIN_MOBILE_QUOTA_BYTES * 2, 0, 10)
        .expect("quota increase queued for E + 1");
    assert_eq!(
        dir.get(&owner).map(|r| r.custody_quota_bytes),
        Some(MIN_MOBILE_QUOTA_BYTES)
    );
    dir.activate_due(11);
    assert_eq!(
        dir.get(&owner).map(|r| r.custody_quota_bytes),
        Some(MIN_MOBILE_QUOTA_BYTES * 2)
    );
}

#[test]
fn drill_t2_and_t3_full_stop_standby_handover_and_recovery_mode() {
    // T-2: 10% of Full validators stop (2 of 20) -> 18/20 >= quorum continues finalizing;
    // after 2 missed checkpoints, standby Full seats replace them within 3 checkpoint intervals.
    let mut candidates = Vec::new();
    for i in 0..24u8 {
        candidates.push(([i + 1; 32], ValidatorClass::Full));
    }
    let mut tracker = SeatHandoverTracker::from_epoch_candidates(20, &candidates);
    assert_eq!(tracker.active_seats().len(), 20);
    assert_eq!(tracker.standby_len(), 4);

    let dropped_a = [1u8; 32];
    let dropped_b = [2u8; 32];
    let online: BTreeSet<[u8; 32]> = tracker
        .active_seats()
        .iter()
        .copied()
        .filter(|a| *a != dropped_a && *a != dropped_b)
        .collect();
    assert!(online.len() >= tracker.quorum_threshold());
    assert!(tracker.record_checkpoint_participation(&online).is_empty());
    let rotated = tracker.record_checkpoint_participation(&online);
    assert_eq!(rotated.len(), 2);
    assert_eq!(
        handover_spec(DutyKind::FinalitySeat).bound,
        HandoverBound::Blocks(3 * TESTNET_CHECKPOINT_INTERVAL_BLOCKS)
    );

    // T-3: > 1/3 of active seats stop for >= 50 blocks -> budlum_finality_stalled triggers;
    // once seats return and finalize a checkpoint, stalled state clears immediately.
    assert!(is_finality_stalled(50, 0));
    assert!(50 >= FINALITY_STALL_BLOCKS);
    let mut recovery = RecoveryTracker::new();
    assert!(recovery.observe_block(50, 2, 0));
    assert!(recovery.is_stalled());
    recovery.observe_finality(50, 2, 50);
    assert!(!recovery.is_stalled());
}

#[test]
fn drill_t7_public_rpc_listener_separation_and_admin_isolation() {
    assert!(!METHOD_CLASSES.is_empty());
    for row in METHOD_CLASSES {
        if row.name.starts_with("bud_admin") || row.name == "bud_requestPrune" {
            assert_eq!(
                row.listener,
                Listener::Operator,
                "{} must never be exposed on the public listener",
                row.name
            );
        }
        if matches!(
            row.name,
            "bud_getCharter" | "bud_getAssetClass" | "bud_getAsset"
        ) {
            assert_eq!(row.listener, Listener::Public);
            assert_eq!(row.effect, Effect::Read);
        }
    }
}
