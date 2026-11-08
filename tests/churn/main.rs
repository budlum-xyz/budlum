//! In-process validator churn simulator and Instant Duty Handover /
//! Disaster Recovery integration suite.
//!
//! Runs `N` Full validators and `M` Mobile validators inside one deterministic
//! process with configurable message latency, packet loss, random departure and
//! return, checkpoint finality seat handover, B.U.D. 3.0 custody/repair
//! handovers, 1-block `PresenceAggregate` fallback, and 40-block disaster
//! recovery mode (`budlum_finality_stalled`).

use std::collections::BTreeSet;

use budlum_core::consensus::{MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS};
use budlum_core::core::metrics::Metrics;
use budlum_core::storage::bud3::custody::CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS;
use budlum_core::storage::bud3::limits::{Bud3Limits, Profile};
use budlum_core::storage::bud3::pipeline::prepare_public_upload;
use budlum_core::storage::bud3::placement::{Class as StorageClass, Share};
use budlum_core::storage::bud3::registry::{Bud3Registry, ShareStatus};
use budlum_core::storage::bud3::repair::{RepairScheduler, REPAIR_TASK_HANDOVER_BLOCKS};
use budlum_core::validators::handover::{
    handover_custody_assignments, handover_repair_tasks, handover_spec,
    proposer_round_for_timestamps, select_round_proposer, DutyKind, HandoverBound,
    PresenceAggregateQueue, RecoveryTracker, SeatHandoverTracker, FINALITY_STALL_BLOCKS,
    PROPOSER_ROUND_TIMEOUT_MS, TESTNET_CHECKPOINT_INTERVAL_BLOCKS,
};
use budlum_core::validators::ValidatorClass;

const TEST_PROFILE: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 128,
    fps: 10,
    k_max: 16,
};

#[derive(Debug, Clone)]
struct SimValidator {
    address: [u8; 32],
    class: ValidatorClass,
    online: bool,
    latency_ms: u64,
}

#[derive(Debug, Clone)]
struct ChurnConfig {
    full_count: usize,
    mobile_count: usize,
    active_seat_cap: usize,
    epoch_blocks: u64,
    drop_ppm: u32,
}

struct ChurnSimulator {
    cfg: ChurnConfig,
    validators: Vec<SimValidator>,
    seat_tracker: SeatHandoverTracker,
    presence_queue: PresenceAggregateQueue,
    recovery: RecoveryTracker,
    metrics: Option<Metrics>,
    height: u64,
    finalized_height: u64,
    rng_state: u64,
}

impl ChurnSimulator {
    fn new(cfg: ChurnConfig, seed: u64) -> Self {
        let mut validators = Vec::with_capacity(cfg.full_count + cfg.mobile_count);
        for idx in 0..cfg.full_count {
            let mut addr = [0u8; 32];
            addr[0] = 0x10;
            let bytes = u32::try_from(idx).unwrap_or(0).to_le_bytes();
            addr[1..5].copy_from_slice(&bytes);
            validators.push(SimValidator {
                address: addr,
                class: ValidatorClass::Full,
                online: true,
                latency_ms: 80,
            });
        }
        for idx in 0..cfg.mobile_count {
            let mut addr = [0u8; 32];
            addr[0] = 0x20;
            let bytes = u32::try_from(idx).unwrap_or(0).to_le_bytes();
            addr[1..5].copy_from_slice(&bytes);
            validators.push(SimValidator {
                address: addr,
                class: ValidatorClass::Mobile,
                online: true,
                latency_ms: 250,
            });
        }
        let candidates: Vec<([u8; 32], ValidatorClass)> = validators
            .iter()
            .map(|v| (v.address, v.class))
            .collect();
        let seat_tracker =
            SeatHandoverTracker::from_epoch_candidates(cfg.active_seat_cap, &candidates);
        Self {
            cfg,
            validators,
            seat_tracker,
            presence_queue: PresenceAggregateQueue::new(),
            recovery: RecoveryTracker::new(),
            metrics: Metrics::new().ok(),
            height: 0,
            finalized_height: 0,
            rng_state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        u32::try_from(x >> 32).unwrap_or(0)
    }

    fn current_epoch(&self) -> u64 {
        if self.cfg.epoch_blocks == 0 {
            return 0;
        }
        self.height / self.cfg.epoch_blocks
    }

    fn set_full_online_prefix(&mut self, online_count: usize) {
        let mut seen = 0usize;
        for v in &mut self.validators {
            if v.class == ValidatorClass::Full {
                v.online = seen < online_count;
                seen += 1;
            }
        }
    }

    fn set_all_mobile_online(&mut self, online: bool) {
        for v in &mut self.validators {
            if v.class != ValidatorClass::Full {
                v.online = online;
            }
        }
    }

    fn online_full_addresses(&self) -> Vec<[u8; 32]> {
        self.validators
            .iter()
            .filter(|v| v.class == ValidatorClass::Full && v.online)
            .map(|v| v.address)
            .collect()
    }

    /// Advance the simulated chain by one slot, performing proposer round
    /// handover if round 0's leader is offline, checkpoint voting every 5
    /// blocks, Instant Seat Handover on finalized checkpoints, and recovery
    /// mode tracking when finality stalls.
    fn step_block(&mut self, omit_presence_in_this_block: bool) -> (u64, [u8; 32], usize) {
        let next_height = self.height + 1;
        let all_full: Vec<[u8; 32]> = self
            .validators
            .iter()
            .filter(|v| v.class == ValidatorClass::Full)
            .map(|v| v.address)
            .collect();
        let online_full: BTreeSet<[u8; 32]> = self.online_full_addresses().into_iter().collect();

        let mut chosen_round = 0u64;
        let mut chosen_proposer = [0u8; 32];
        for round in 0..64u64 {
            if let Some(cand) = select_round_proposer(next_height, round, &all_full) {
                if online_full.contains(&cand) {
                    chosen_round = round;
                    chosen_proposer = cand;
                    break;
                }
            }
        }

        let included_presence = if omit_presence_in_this_block {
            0
        } else {
            let ready = self.presence_queue.collect_for_block(next_height);
            for agg in &ready {
                self.presence_queue.mark_included(agg.window_id);
            }
            ready.len()
        };

        self.height = next_height;
        let epoch = self.current_epoch();

        if self.height.is_multiple_of(TESTNET_CHECKPOINT_INTERVAL_BLOCKS) {
            let mut voters = BTreeSet::new();
            let active: Vec<[u8; 32]> = self.seat_tracker.active_seats().to_vec();
            for seat in active {
                let is_online = self
                    .validators
                    .iter()
                    .any(|v| v.address == seat && v.online && v.latency_ms < 2_500);
                let dropped = (self.next_u32() % 1_000_000) < self.cfg.drop_ppm;
                if is_online && !dropped {
                    voters.insert(seat);
                }
            }
            let quorum = self.seat_tracker.quorum_threshold();
            if quorum > 0 && voters.len() >= quorum {
                self.finalized_height = self.height;
                self.seat_tracker.record_checkpoint_participation(&voters);
                self.recovery
                    .observe_finality(self.height, epoch, self.finalized_height);
            } else {
                self.recovery
                    .observe_block(self.height, epoch, self.finalized_height);
            }
        } else {
            self.recovery
                .observe_block(self.height, epoch, self.finalized_height);
        }

        // If recovery committee is ready at an epoch boundary, re-seat from
        // surviving online Full validators on the available chain.
        if self.cfg.epoch_blocks > 0
            && self.height.is_multiple_of(self.cfg.epoch_blocks)
            && self.recovery.recovery_committee_ready(epoch)
        {
            let available_presence: Vec<([u8; 32], ValidatorClass, bool)> = self
                .validators
                .iter()
                .map(|v| (v.address, v.class, v.online))
                .collect();
            if let Some(recovered) = self.recovery.derive_recovery_committee(
                epoch,
                self.cfg.active_seat_cap,
                &available_presence,
            ) {
                let recovered_candidates: Vec<([u8; 32], ValidatorClass)> = recovered
                    .into_iter()
                    .map(|addr| (addr, ValidatorClass::Full))
                    .collect();
                self.seat_tracker = SeatHandoverTracker::from_epoch_candidates(
                    self.cfg.active_seat_cap,
                    &recovered_candidates,
                );
            }
        }

        if let Some(ref m) = self.metrics {
            m.finality_lag
                .set(i64::try_from(self.height.saturating_sub(self.finalized_height)).unwrap_or(0));
            m.finality_stalled
                .set(i64::from(self.recovery.is_stalled()));
        }

        (chosen_round, chosen_proposer, included_presence)
    }

    fn stalled_metric(&self) -> i64 {
        self.metrics
            .as_ref()
            .map_or(i64::from(self.recovery.is_stalled()), |m| {
                m.finality_stalled.get()
            })
    }
}

#[test]
fn proposer_round_handover() {
    assert_eq!(
        handover_spec(DutyKind::BlockProposal).bound,
        HandoverBound::Milliseconds(PROPOSER_ROUND_TIMEOUT_MS)
    );
    let parent_ts = 1_700_000_000_000u128;
    assert_eq!(
        proposer_round_for_timestamps(parent_ts, parent_ts + MIN_BLOCK_INTERVAL_MS),
        0
    );
    // One missed 3 s round advances the affordable proposer round to 1.
    assert_eq!(
        proposer_round_for_timestamps(
            parent_ts,
            parent_ts + MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS
        ),
        1
    );

    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 8,
            mobile_count: 4,
            active_seat_cap: 6,
            epoch_blocks: 20,
            drop_ppm: 0,
        },
        101,
    );
    let all_full: Vec<[u8; 32]> = sim
        .validators
        .iter()
        .filter(|v| v.class == ValidatorClass::Full)
        .map(|v| v.address)
        .collect();
    let r0_leader = select_round_proposer(1, 0, &all_full).unwrap();
    // Take round 0's leader offline before slot 1; round >= 1 immediately
    // hands the block proposal to an online Full validator.
    for v in &mut sim.validators {
        if v.address == r0_leader {
            v.online = false;
        }
    }
    let (round_used, actual_proposer, _) = sim.step_block(false);
    assert!(round_used >= 1, "expected handover round >= 1 when round 0 leader is offline");
    assert_ne!(actual_proposer, r0_leader);
}

#[test]
fn repair_task_handover_after_20_blocks() {
    assert_eq!(
        handover_spec(DutyKind::RepairTask).bound,
        HandoverBound::Blocks(REPAIR_TASK_HANDOVER_BLOCKS)
    );
    let mut scheduler = RepairScheduler::new();
    let object_key = [0x42; 32];
    let candidates = [[1u8; 32], [2u8; 32], [3u8; 32]];

    let initial = scheduler
        .schedule_task(object_key, 0, 50, &candidates)
        .unwrap();
    assert!(handover_repair_tasks(&mut scheduler, 69, &candidates).is_empty());
    assert_eq!(scheduler.task(&object_key, 0).unwrap().assigned_to, initial);

    let moved = handover_repair_tasks(&mut scheduler, 70, &candidates);
    assert_eq!(moved.len(), 1);
    let reassigned = moved[0].2;
    assert_ne!(reassigned, initial);
    assert_eq!(scheduler.task(&object_key, 0).unwrap().assigned_height, 70);
}

#[test]
fn custody_assignment_handover_after_3_epochs() {
    assert_eq!(
        handover_spec(DutyKind::NewCustodyAssignment).bound,
        HandoverBound::Epochs(CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS)
    );
    let mut registry = Bud3Registry::default();
    let owner = [0x99; 32];
    let v1 = [0xA1; 32];
    let v2 = [0xA2; 32];
    let v3 = [0xA3; 32];

    let payload = b"bud3 custody handover test payload".repeat(16);
    let upload = prepare_public_upload(&payload, &TEST_PROFILE, &Bud3Limits::default(), 12).unwrap();
    let key = upload.record.commitment;
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
        .register_object(owner, upload.record, shares, 10, 100)
        .unwrap();
    // `v1` confirms its share immediately; `v2` stays silent.
    assert_eq!(registry.ack(&key, &v1).unwrap(), 1);

    let candidates = [
        (v1, StorageClass::Full),
        (v2, StorageClass::Full),
        (v3, StorageClass::Full),
    ];
    // Epochs 11 and 12 (< 3 epochs elapsed): no handover yet.
    assert_eq!(handover_custody_assignments(&mut registry, 12, &candidates), 0);

    // Epoch 13 (3 epochs elapsed without `CustodyAck` from `v2`): hands over to `v3`.
    assert_eq!(handover_custody_assignments(&mut registry, 13, &candidates), 1);
    let obj = registry.object(&key).unwrap();
    assert!(obj
        .shares
        .iter()
        .any(|s| s.share.validator == v1 && s.status == ShareStatus::Confirmed));
    assert!(obj
        .shares
        .iter()
        .any(|s| s.share.validator == v3 && s.status == ShareStatus::Pending));
    assert!(!obj.shares.iter().any(|s| s.share.validator == v2));
}

#[test]
fn presence_aggregate_fallback_next_block() {
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 6,
            mobile_count: 4,
            active_seat_cap: 6,
            epoch_blocks: 20,
            drop_ppm: 0,
        },
        202,
    );
    sim.presence_queue.enqueue(7, 1, vec![0b1111_1100]);

    // Block 1 proposer omits the ready PresenceAggregate.
    let (_, _, included_h1) = sim.step_block(true);
    assert_eq!(included_h1, 0);
    assert_eq!(sim.presence_queue.pending_count(), 1);

    // Block 2 proposer immediately picks up and includes window 7 (1-block fallback).
    let (_, _, included_h2) = sim.step_block(false);
    assert_eq!(included_h2, 1);
    assert_eq!(sim.presence_queue.pending_count(), 0);
}

#[test]
fn ten_percent_full_departure_keeps_finality() {
    // 20 Full validators (16 active seats + 4 standby) and 10 Mobile validators.
    // 10% Full departure = 2 active Full validators leave abruptly.
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 20,
            mobile_count: 10,
            active_seat_cap: 16,
            epoch_blocks: 30,
            drop_ppm: 10_000, // 1% transient packet loss
        },
        303,
    );
    let departed_a = sim.seat_tracker.active_seats()[0];
    let departed_b = sim.seat_tracker.active_seats()[1];
    for v in &mut sim.validators {
        if v.address == departed_a || v.address == departed_b {
            v.online = false;
        }
    }

    for _ in 0..25 {
        sim.step_block(false);
    }

    assert_eq!(sim.finalized_height, 25, "finality must advance on every 5-block checkpoint");
    assert_eq!(sim.stalled_metric(), 0);
    assert!(
        !sim.seat_tracker.active_seats().contains(&departed_a)
            && !sim.seat_tracker.active_seats().contains(&departed_b),
        "departed seats must hand over to standby Full validators within 2 checkpoints"
    );
}

#[test]
fn all_mobile_departure_does_not_touch_finality() {
    // V-2: 100% of Mobile validators go offline simultaneously; finality never
    // pauses or drops a single checkpoint.
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 12,
            mobile_count: 50,
            active_seat_cap: 10,
            epoch_blocks: 25,
            drop_ppm: 0,
        },
        404,
    );
    sim.set_all_mobile_online(false);

    for _ in 0..30 {
        sim.step_block(false);
    }

    assert_eq!(sim.finalized_height, 30);
    assert_eq!(sim.stalled_metric(), 0);
    assert!(!sim.recovery.is_stalled());
}

#[test]
fn finality_stall_enters_recovery_mode() {
    // 12 Full validators, 12 active seats -> quorum = 9.
    // 6 Full validators crash simultaneously (50% > 1/3): finality stalls,
    // available chain keeps advancing, at lag == 40 blocks `budlum_finality_stalled`
    // becomes 1 and recovery mode activates; after 1 full epoch in recovery mode
    // the surviving 6 Full validators form the recovery committee and finality
    // resumes, returning `budlum_finality_stalled` to 0.
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 12,
            mobile_count: 8,
            active_seat_cap: 12,
            epoch_blocks: 30,
            drop_ppm: 0,
        },
        505,
    );
    // Finalize checkpoint 5 first under full participation.
    for _ in 0..5 {
        sim.step_block(false);
    }
    assert_eq!(sim.finalized_height, 5);
    assert_eq!(sim.stalled_metric(), 0);

    // Crash half of the Full validators (only 6 remain online < quorum 9) and
    // keep Mobile validators online to prove V-2 holds during recovery too.
    sim.set_full_online_prefix(6);

    // Advance 39 blocks past finalized height 5 (to height 44): not stalled yet.
    while sim.height < 5 + FINALITY_STALL_BLOCKS - 1 {
        sim.step_block(false);
    }
    assert_eq!(sim.finalized_height, 5);
    assert_eq!(sim.stalled_metric(), 0);

    // Block 45 reaches lag == 40 (8 missed checkpoints): enters recovery mode!
    sim.step_block(false);
    assert_eq!(sim.height, 5 + FINALITY_STALL_BLOCKS);
    assert!(sim.recovery.is_stalled());
    assert_eq!(sim.stalled_metric(), 1);

    // Advance past the next epoch boundary (height 60 => epoch 2 > entered epoch 1)
    // and one more checkpoint (height 65): surviving 6 Full validators form the
    // recovery committee, finalize height 65, and clear `budlum_finality_stalled`!
    while sim.height < 65 {
        sim.step_block(false);
    }
    assert_eq!(sim.finalized_height, 65);
    assert!(!sim.recovery.is_stalled());
    assert_eq!(sim.stalled_metric(), 0);
}

#[test]
fn churn_runs_on_the_testnet_schedule() {
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 8,
            mobile_count: 4,
            active_seat_cap: 6,
            epoch_blocks: 20,
            drop_ppm: 0,
        },
        606,
    );
    for expected_height in 1..=40 {
        let (round, proposer, _) = sim.step_block(false);
        assert_eq!(sim.height, expected_height);
        assert!(round <= 63, "the simulator's bounded successor search exhausted");
        assert!(sim.validators.iter().any(|validator| {
            validator.address == proposer && validator.class == ValidatorClass::Full
        }));
    }
    assert_eq!(sim.finalized_height, 40);
    assert_eq!(sim.stalled_metric(), 0);
    assert!(sim.seat_tracker.active_seats().len() <= 6);
    assert!(sim.seat_tracker.active_seats().iter().all(|seat| {
        sim.validators.iter().any(|validator| {
            validator.address == *seat && validator.class == ValidatorClass::Full
        })
    }));
}

#[test]
fn churn_random_leave_and_return_keeps_finality() {
    let mut sim = ChurnSimulator::new(
        ChurnConfig {
            full_count: 20,
            mobile_count: 10,
            active_seat_cap: 16,
            epoch_blocks: 30,
            drop_ppm: 0,
        },
        707,
    );
    let mut departed: Vec<([u8; 32], u64)> = Vec::new();

    for height in 1..=60u64 {
        let returning: Vec<[u8; 32]> = departed
            .iter()
            .filter(|(_, left_at)| height.saturating_sub(*left_at) >= 3)
            .map(|(address, _)| *address)
            .collect();
        for validator in &mut sim.validators {
            if returning.contains(&validator.address) {
                validator.online = true;
            }
        }
        departed.retain(|(address, _)| !returning.contains(address));

        // At most two of twenty Full validators (10%) are away at once. The
        // deterministic weather stream chooses who leaves; every departure is
        // temporary and the same validator returns three blocks later.
        if height % 6 == 0 && height <= 54 && departed.len() < 2 {
            let candidates: Vec<[u8; 32]> = sim
                .validators
                .iter()
                .filter(|validator| {
                    validator.class == ValidatorClass::Full && validator.online
                })
                .map(|validator| validator.address)
                .collect();
            if !candidates.is_empty() {
                let index = usize::try_from(sim.next_u32()).unwrap_or(0) % candidates.len();
                let address = candidates[index];
                for validator in &mut sim.validators {
                    if validator.address == address {
                        validator.online = false;
                    }
                }
                departed.push((address, height));
            }
        }
        sim.step_block(false);
    }

    assert!(departed.is_empty(), "every random departure returned");
    assert_eq!(sim.finalized_height, 60);
    assert_eq!(sim.stalled_metric(), 0);
}
