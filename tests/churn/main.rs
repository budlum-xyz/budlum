// Churn integration test suite (Section 7.6, Section 7.7).

use budlum_core::core::address::Address;
use budlum_core::core::metrics::Metrics;
use budlum_core::registry::handover::{ChurnSimulator, HandoverCoordinator};
use budlum_core::registry::presence::{PresenceAggregate, PresenceClass};
use budlum_core::storage::bud3::placement::{Class, Share};
use budlum_core::storage::bud3::repair::ScheduledRepairDuty;

#[test]
fn proposer_round_handover() {
    let proposers = vec![
        Address::from([1u8; 32]),
        Address::from([2u8; 32]),
        Address::from([3u8; 32]),
    ];
    let r0 = HandoverCoordinator::proposer_for_round(&proposers, 100, 0).unwrap();
    let r1 = HandoverCoordinator::proposer_for_round(&proposers, 100, 1).unwrap();
    assert_ne!(r0, r1);
}

#[test]
fn repair_task_handover_after_20_blocks() {
    let duty = ScheduledRepairDuty {
        object: [0xCD; 32],
        segment: 1,
        assignee: [1u8; 32],
        assigned_height: 50,
        started: false,
    };
    let candidates = [[1u8; 32], [2u8; 32]];
    assert!(HandoverCoordinator::handover_repair_duty(&duty, 69, &candidates).is_none());
    let next = HandoverCoordinator::handover_repair_duty(&duty, 70, &candidates).unwrap();
    assert_eq!(next.assignee, [2u8; 32]);
}

#[test]
fn custody_assignment_handover_after_3_epochs() {
    let share = Share {
        validator: [10u8; 32],
        class: Class::Full,
        first_esi: 0,
        symbols: 4,
    };
    let candidates = [[10u8; 32], [11u8; 32]];
    assert!(HandoverCoordinator::handover_unacked_share(&share, 2, false, 4, &candidates).is_none());
    let next = HandoverCoordinator::handover_unacked_share(&share, 2, false, 5, &candidates).unwrap();
    assert_eq!(next.validator, [11u8; 32]);
}

#[test]
fn presence_aggregate_fallback_next_block() {
    let mut coord = HandoverCoordinator::new();
    let agg = PresenceAggregate {
        window: 3,
        class: PresenceClass::Mobile,
        bitmap: vec![0x01],
        aggregate_sig: vec![0x55; 48],
    };
    assert!(coord.on_presence_window_ready(agg.clone(), false).is_empty());
    assert_eq!(coord.flush_pending_presence_aggregates(), vec![agg]);
}

#[test]
fn ten_percent_full_departure_keeps_finality() {
    let mut sim = ChurnSimulator::new(10, 3, 250, 10);
    sim.packet_drop_ppm = 10_000; // 1% packet drop under churn
    sim.store_coded_object(&b"churn harness payload under 10% full departure".repeat(48))
        .unwrap();
    let departed = [sim.full_validators[0]];
    sim.set_offline(&departed);

    let summary = sim.run_blocks(35);
    assert!(summary.max_finality_gap_checkpoints <= 2);
    assert_eq!(summary.objects_intact, summary.objects_total);
}

#[test]
fn all_mobile_departure_does_not_touch_finality() {
    let mut clean = ChurnSimulator::new(8, 2, 1_000, 10);
    let clean_summary = clean.run_blocks(30);

    let mut sim = ChurnSimulator::new(8, 2, 1_000, 10);
    sim.store_coded_object(&b"churn harness payload under 100% mobile departure".repeat(40))
        .unwrap();
    let all_mobile = sim.mobile_validators.clone();
    sim.set_offline(&all_mobile);

    let churn_summary = sim.run_blocks(30);
    assert_eq!(churn_summary.checkpoints_finalized, clean_summary.checkpoints_finalized);
    assert_eq!(
        churn_summary.max_finality_gap_checkpoints,
        clean_summary.max_finality_gap_checkpoints
    );
    assert_eq!(churn_summary.objects_intact, 1);
}

#[test]
fn finality_stall_enters_recovery_mode() {
    let mut sim = ChurnSimulator::new(9, 0, 100, 10);
    let offline: Vec<Address> = sim.full_validators[..4].to_vec();
    sim.set_offline(&offline);

    let stalled = sim.run_blocks(40);
    assert!(stalled.entered_recovery_mode);
    let metrics = Metrics::new().unwrap();
    sim.coordinator.sync_metrics(&metrics);
    assert_eq!(metrics.finality_stalled.get(), 1);

    let recovered = sim.run_blocks(25);
    assert!(recovered.checkpoints_finalized > 0);
    assert_eq!(sim.coordinator.budlum_finality_stalled(), 0);
}
