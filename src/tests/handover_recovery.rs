//! Instant Duty Handover (Section 7.6) and Disaster Recovery Mode
//! (Section 7.7) unit and live-chain regression suite.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::metrics::Metrics;
use crate::storage::bud3::custody::{
    CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS, CUSTODY_READ_TIMEOUT_MS,
};
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::pipeline::prepare_public_upload;
use crate::storage::bud3::placement::{Class as StorageClass, Share};
use crate::storage::bud3::registry::{Bud3Registry, ShareStatus};
use crate::storage::bud3::repair::{RepairScheduler, REPAIR_TASK_HANDOVER_BLOCKS};
use crate::validators::handover::{
    handover_custody_assignments, handover_repair_tasks, handover_spec, is_finality_stalled,
    proposer_round_for_timestamps, select_next_endpoint, select_round_proposer, DutyKind,
    HandoverBound, PresenceAggregateQueue, RecoveryTracker, SeatHandoverTracker,
    FINALITY_STALL_BLOCKS, FINALITY_STALL_CHECKPOINTS, HANDOVER_TABLE,
    PROPOSER_ROUND_TIMEOUT_MS, TESTNET_CHECKPOINT_INTERVAL_BLOCKS,
};
use crate::validators::ValidatorClass;

const TEST_PROFILE: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 128,
    fps: 10,
    k_max: 16,
};

#[test]
fn handover_table_covers_all_nine_duties_and_bounds() {
    assert_eq!(HANDOVER_TABLE.len(), 9);
    assert_eq!(
        handover_spec(DutyKind::BlockProposal).bound,
        HandoverBound::Milliseconds(PROPOSER_ROUND_TIMEOUT_MS)
    );
    assert_eq!(
        handover_spec(DutyKind::FinalitySeat).bound,
        HandoverBound::Blocks(3 * TESTNET_CHECKPOINT_INTERVAL_BLOCKS)
    );
    assert_eq!(
        handover_spec(DutyKind::CustodyShareRead).bound,
        HandoverBound::Immediate {
            timeout_ms: CUSTODY_READ_TIMEOUT_MS,
        }
    );
    assert_eq!(
        handover_spec(DutyKind::NewCustodyAssignment).bound,
        HandoverBound::Epochs(CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS)
    );
    assert_eq!(
        handover_spec(DutyKind::RepairTask).bound,
        HandoverBound::Blocks(REPAIR_TASK_HANDOVER_BLOCKS)
    );
    assert_eq!(
        handover_spec(DutyKind::UploadGateway).bound,
        HandoverBound::Immediate { timeout_ms: 0 }
    );
    assert_eq!(
        handover_spec(DutyKind::RelayReservation).bound,
        HandoverBound::Immediate { timeout_ms: 0 }
    );
    assert_eq!(
        handover_spec(DutyKind::PresenceAggregation).bound,
        HandoverBound::Blocks(1)
    );
    assert_eq!(
        select_next_endpoint(&[[1u8; 32]], &[[1u8; 32], [2u8; 32]]),
        Some([2u8; 32])
    );
}

#[test]
fn proposer_round_handover() {
    let parent_ts = 1_700_000_000_000u128;
    assert_eq!(proposer_round_for_timestamps(parent_ts, parent_ts + 1_000), 0);
    assert_eq!(proposer_round_for_timestamps(parent_ts, parent_ts + 4_000), 1);
    assert_eq!(proposer_round_for_timestamps(parent_ts, parent_ts + 7_000), 2);

    let active = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let r0 = select_round_proposer(10, 0, &active).unwrap();
    let r1 = select_round_proposer(10, 1, &active).unwrap();
    assert_ne!(r0, r1, "next round must hand proposal duty to a successor");
}

#[test]
fn repair_task_handover_after_20_blocks() {
    let mut scheduler = RepairScheduler::new();
    let key = [0x55; 32];
    let fulls = [[10u8; 32], [11u8; 32], [12u8; 32]];
    let first = scheduler.schedule_task(key, 0, 100, &fulls).unwrap();
    assert!(handover_repair_tasks(&mut scheduler, 119, &fulls).is_empty());
    let moved = handover_repair_tasks(&mut scheduler, 120, &fulls);
    assert_eq!(moved.len(), 1);
    assert_ne!(moved[0].2, first);
    assert!(scheduler.complete_task(&key, 0));
    assert!(scheduler.is_empty());
}

#[test]
fn custody_assignment_handover_after_3_epochs() {
    let mut registry = Bud3Registry::default();
    let upload = prepare_public_upload(
        &b"custody handover".repeat(20),
        &TEST_PROFILE,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    let key = upload.record.commitment;
    let v1 = [0x11; 32];
    let v2 = [0x22; 32];
    let v3 = [0x33; 32];
    let seg_count = u64::try_from(upload.segments.len()).unwrap_or(0);
    let shares: Vec<(u64, Share)> = (0..seg_count)
        .flat_map(|seg| {
            [
                (
                    seg,
                    Share {
                        validator: v1,
                        class: StorageClass::Full,
                        first_esi: 0,
                        symbols: 6,
                    },
                ),
                (
                    seg,
                    Share {
                        validator: v2,
                        class: StorageClass::Full,
                        first_esi: 6,
                        symbols: 6,
                    },
                ),
            ]
        })
        .collect();
    registry
        .register_object([0x01; 32], upload.record, shares, 5, 50)
        .unwrap();
    registry.ack(&key, &v1).unwrap();

    let candidates = [
        (v1, StorageClass::Full),
        (v2, StorageClass::Full),
        (v3, StorageClass::Full),
    ];
    assert_eq!(handover_custody_assignments(&mut registry, 7, &candidates), 0);
    assert_eq!(handover_custody_assignments(&mut registry, 8, &candidates), 1);
    let obj = registry.object(&key).unwrap();
    assert!(obj
        .shares
        .iter()
        .any(|s| s.share.validator == v3 && s.status == ShareStatus::Pending));
}

#[test]
fn presence_aggregate_fallback_next_block() {
    let mut queue = PresenceAggregateQueue::new();
    queue.enqueue(3, 40, vec![0xFF]);
    // Proposer at height 40 omits window 3; height 41 still sees it eligible.
    let at_41 = queue.collect_for_block(41);
    assert_eq!(at_41.len(), 1);
    assert_eq!(at_41[0].window_id, 3);
    assert!(queue.mark_included(3));
    assert_eq!(queue.pending_count(), 0);
}

#[test]
fn ten_percent_full_departure_keeps_finality() {
    let mut candidates = Vec::new();
    for i in 0..25u8 {
        candidates.push(([i + 1; 32], ValidatorClass::Full));
    }
    let mut tracker = SeatHandoverTracker::from_epoch_candidates(20, &candidates);
    assert_eq!(tracker.active_seats().len(), 20);
    assert_eq!(tracker.standby_len(), 5);

    // 10% (2 of 20) active seats stop voting.
    let dropped_a = tracker.active_seats()[0];
    let dropped_b = tracker.active_seats()[1];
    let online: BTreeSet<[u8; 32]> = tracker
        .active_seats()
        .iter()
        .copied()
        .filter(|a| *a != dropped_a && *a != dropped_b)
        .collect();
    assert!(online.len() >= tracker.quorum_threshold());

    // Checkpoint 1: 1st miss, not yet rotated.
    assert!(tracker.record_checkpoint_participation(&online).is_empty());
    // Checkpoint 2: 2nd consecutive miss -> ceil(20/10) == 2 seats rotate immediately.
    let rotated = tracker.record_checkpoint_participation(&online);
    assert_eq!(rotated.len(), 2);
    assert!(!tracker.active_seats().contains(&dropped_a));
    assert!(!tracker.active_seats().contains(&dropped_b));
}

#[test]
fn all_mobile_departure_does_not_touch_finality() {
    let candidates = [
        ([1u8; 32], ValidatorClass::Full),
        ([2u8; 32], ValidatorClass::Full),
        ([3u8; 32], ValidatorClass::Full),
        ([4u8; 32], ValidatorClass::Mobile),
        ([5u8; 32], ValidatorClass::MobileOpportunistic),
    ];
    let tracker = SeatHandoverTracker::from_epoch_candidates(10, &candidates);
    // V-2: neither Mobile nor MobileOpportunistic ever enters active or standby seats.
    assert_eq!(tracker.active_seats().len(), 3);
    assert_eq!(tracker.standby_len(), 0);
}

#[test]
fn finality_stall_enters_recovery_mode() {
    assert_eq!(FINALITY_STALL_CHECKPOINTS, 8);
    assert_eq!(FINALITY_STALL_BLOCKS, 40);
    assert!(!is_finality_stalled(39, 0));
    assert!(is_finality_stalled(40, 0));

    // Verify live Blockchain + Prometheus `budlum_finality_stalled` gauge path.
    let consensus = Arc::new(PoWEngine::new(0));
    let metrics = Arc::new(Metrics::new().expect("metrics registry"));
    let mut bc = Blockchain::new(consensus, None, 45262, None).with_metrics(metrics.clone());
    bc.emit_chain_metrics();
    assert!(metrics.encode().contains("budlum_finality_stalled"));
    assert_eq!(metrics.finality_stalled.get(), 0);

    let miner = Address::from([0x77; 32]);
    let checkpoint = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(45262);
    let stall_height = FINALITY_STALL_CHECKPOINTS * checkpoint;
    assert_eq!(stall_height, 16, "devnet uses two-block checkpoints");
    for _ in 0..stall_height - 1 {
        bc.produce_block(miner);
    }
    assert_eq!(metrics.finality_stalled.get(), 0);
    assert!(!bc.recovery_tracker.is_stalled());

    // The chain-specific threshold triggers disaster recovery and sets gauge = 1.
    bc.produce_block(miner);
    assert!(bc.recovery_tracker.is_stalled());
    assert_eq!(metrics.finality_stalled.get(), 1);
    assert!(bc.recovery_tracker.entered_at().is_some());

    // Verify 1-epoch wait and V-2 Full-only committee derivation in RecoveryTracker.
    let mut tracker = RecoveryTracker::new();
    assert!(tracker.observe_block(40, 2, 0));
    assert!(!tracker.recovery_committee_ready(2));
    assert!(tracker.recovery_committee_ready(3));
    let presence = [
        ([1u8; 32], ValidatorClass::Full, true),
        ([2u8; 32], ValidatorClass::Mobile, true),
        ([3u8; 32], ValidatorClass::Full, false),
    ];
    let recovered = tracker.derive_recovery_committee(3, 10, &presence).unwrap();
    assert_eq!(recovered, vec![[1u8; 32]]);
}


#[test]
fn recovery_threshold_uses_the_running_checkpoint_interval() {
    let mut tracker = RecoveryTracker::new();
    assert!(!tracker.observe_block_at_interval(40, 1, 0, 10));
    assert!(!tracker.observe_block_at_interval(79, 1, 0, 10));
    assert!(tracker.observe_block_at_interval(80, 1, 0, 10));
    assert!(!tracker.observe_finality_at_interval(80, 1, 80, 10));
}
