//! Instant Duty Handover (Section 7.6) and Disaster Recovery Mode (Section 7.7).
//!
//! Budlum validators never forfeit stake merely for going offline (`V-4`), and
//! Mobile / MobileOpportunistic validators never sit on the finality path (`V-2`).
//! Every protocol duty therefore defines a deterministic, bounded-latency
//! handover rule when its current holder fails to respond, alongside a bounded
//! disaster recovery mode when more than one third of active finality seats go
//! silent simultaneously.
//!
//! # Residual Partition Risk (`R-03`)
//!
//! If finality remains stalled for `FINALITY_STALL_BLOCKS` (8 checkpoint
//! intervals = 40 blocks on testnet), nodes raise `budlum_finality_stalled = 1`
//! and enter recovery mode. After `RECOVERY_COMMITTEE_WAIT_EPOCHS` (1 full
//! epoch) in recovery mode without finality, the next epoch's committee is
//! derived from the available chain's presence records (Full validators only).
//! Under a clean mass crash, all surviving nodes share one available chain and
//! converge on the same recovery committee. Under a network partition lasting
//! longer than one epoch where both sides still produce blocks, each side can
//! derive a distinct recovery committee (`R-03`, the same residual safety/liveness
//! trade-off as Ethereum's inactivity leak), requiring post-partition social
//! coordination if conflicting checkpoints finalize.
//!
//! WIRING: `Blockchain` owns `RecoveryTracker` and PoS calls
//! `proposer_round_for_timestamps`. The seat, custody, repair and presence
//! helpers remain drill/churn utilities until their state-transition callers
//! adopt them; those harnesses are not production activation evidence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::consensus::{affordable_leader_round, ROUND_TIMEOUT_MS};
use crate::storage::bud3::custody::{
    CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS, CUSTODY_READ_TIMEOUT_MS,
};
use crate::storage::bud3::placement::Class as StorageClass;
use crate::storage::bud3::registry::{Address, Bud3Registry};
use crate::storage::bud3::repair::{RepairScheduler, REPAIR_TASK_HANDOVER_BLOCKS};

use super::ValidatorClass;

/// Consensus proposer round timeout in milliseconds (`3_000` ms, matching
/// [`ROUND_TIMEOUT_MS`]).
pub const PROPOSER_ROUND_TIMEOUT_MS: u64 = 3_000;
const _: () = assert!(u128::from(PROPOSER_ROUND_TIMEOUT_MS) == ROUND_TIMEOUT_MS);

/// Consecutive missed `SeatParticipation` checkpoints before an active finality
/// seat hands over to the standby Full queue (Section 7.6, Row 2).
pub const SEAT_MISSED_CHECKPOINTS_FOR_HANDOVER: u32 = 2;

/// Divisor capping per-checkpoint seat handovers to `ceil(S / 10)` so seat
/// turnover stays gradual under correlated jitter (Section 7.6, Row 2).
pub const SEAT_MAX_HANDOVER_DIVISOR: usize = 10;

/// Testnet checkpoint interval in blocks (`I = 5`).
pub const TESTNET_CHECKPOINT_INTERVAL_BLOCKS: u64 = 5;

/// Unseen Full validator window before its custody shares enter lazy repair
/// (24 hours, Section 7.6, Row 4).
pub const FULL_DURABILITY_UNSEEN_HOURS: u64 = 24;

/// Unseen Mobile validator window before its custody shares enter lazy repair
/// (7 days = 168 hours, Section 7.6, Row 4).
pub const MOBILE_DURABILITY_UNSEEN_HOURS: u64 = 168;

/// Maximum block delay when a proposer omits a ready `PresenceAggregate`
/// (next block proposer includes it: 1 block, Section 7.6, Row 9).
pub const PRESENCE_FALLBACK_MAX_BLOCKS: u64 = 1;

/// Checkpoint intervals without finality before entering disaster recovery mode
/// (Section 7.7).
pub const FINALITY_STALL_CHECKPOINTS: u64 = 8;

/// Blocks without finality before `budlum_finality_stalled` becomes `1` and the
/// node enters disaster recovery mode (`8 * 5 = 40` blocks, Section 7.7).
pub const FINALITY_STALL_BLOCKS: u64 =
    FINALITY_STALL_CHECKPOINTS * TESTNET_CHECKPOINT_INTERVAL_BLOCKS;

/// Full epochs spent in disaster recovery mode before deriving a recovery
/// committee from the available chain's presence records (Section 7.7).
pub const RECOVERY_COMMITTEE_WAIT_EPOCHS: u64 = 1;

/// Every protocol duty governed by Section 7.6 Instant Duty Handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DutyKind {
    /// Block proposal (1 round / 3 s).
    BlockProposal,
    /// Finality committee seat (2 missed checkpoints, `ceil(S/10)` per checkpoint).
    FinalitySeat,
    /// Custody share client read (2 s timeout -> immediate alternate holder).
    CustodyShareRead,
    /// Custody share long-term durability (1 d Full / 7 d Mobile -> lazy repair).
    CustodyShareDurability,
    /// Newly placed custody share confirmation (3 epochs -> next candidate).
    NewCustodyAssignment,
    /// Segment repair task (20 blocks without `RecordRepair` -> next Full candidate).
    RepairTask,
    /// Upload gateway endpoint (no response -> immediate alternate gateway).
    UploadGateway,
    /// P2P relay reservation (dropped reservation -> immediate next relay).
    RelayReservation,
    /// Presence window aggregation (omitted at `h` -> included at `h + 1`).
    PresenceAggregation,
}

/// Canonical latency ceiling unit for one row of the Section 7.6 handover table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverBound {
    /// Immediate client/peer failover with zero block wait and an optional
    /// request timeout in milliseconds.
    Immediate { timeout_ms: u64 },
    /// Handover bounded by consensus round timeout in milliseconds.
    Milliseconds(u64),
    /// Handover bounded by a fixed number of blocks.
    Blocks(u64),
    /// Handover bounded by a fixed number of epochs.
    Epochs(u64),
    /// Handover bounded by hours unseen before lazy background repair.
    UnseenHours { full_hours: u64, mobile_hours: u64 },
}

/// Specification of one row in the Section 7.6 Instant Duty Handover table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DutyHandoverSpec {
    /// Duty identifier.
    pub duty: DutyKind,
    /// Deterministic handover bound.
    pub bound: HandoverBound,
    /// Whether only `ValidatorClass::Full` may receive this duty (`V-2`).
    pub full_only: bool,
}

/// Complete 9-row Section 7.6 Instant Duty Handover specification table.
pub const HANDOVER_TABLE: [DutyHandoverSpec; 9] = [
    DutyHandoverSpec {
        duty: DutyKind::BlockProposal,
        bound: HandoverBound::Milliseconds(PROPOSER_ROUND_TIMEOUT_MS),
        full_only: true,
    },
    DutyHandoverSpec {
        duty: DutyKind::FinalitySeat,
        // 2 missed checkpoints + ceil(S/10) cap => worst-case 3 checkpoints = 15 blocks (45 s).
        bound: HandoverBound::Blocks(3 * TESTNET_CHECKPOINT_INTERVAL_BLOCKS),
        full_only: true,
    },
    DutyHandoverSpec {
        duty: DutyKind::CustodyShareRead,
        bound: HandoverBound::Immediate {
            timeout_ms: CUSTODY_READ_TIMEOUT_MS,
        },
        full_only: false,
    },
    DutyHandoverSpec {
        duty: DutyKind::CustodyShareDurability,
        bound: HandoverBound::UnseenHours {
            full_hours: FULL_DURABILITY_UNSEEN_HOURS,
            mobile_hours: MOBILE_DURABILITY_UNSEEN_HOURS,
        },
        full_only: false,
    },
    DutyHandoverSpec {
        duty: DutyKind::NewCustodyAssignment,
        bound: HandoverBound::Epochs(CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS),
        full_only: false,
    },
    DutyHandoverSpec {
        duty: DutyKind::RepairTask,
        bound: HandoverBound::Blocks(REPAIR_TASK_HANDOVER_BLOCKS),
        full_only: true,
    },
    DutyHandoverSpec {
        duty: DutyKind::UploadGateway,
        bound: HandoverBound::Immediate { timeout_ms: 0 },
        full_only: true,
    },
    DutyHandoverSpec {
        duty: DutyKind::RelayReservation,
        bound: HandoverBound::Immediate { timeout_ms: 0 },
        full_only: true,
    },
    DutyHandoverSpec {
        duty: DutyKind::PresenceAggregation,
        bound: HandoverBound::Blocks(PRESENCE_FALLBACK_MAX_BLOCKS),
        full_only: true,
    },
];

/// Convenience: look up the canonical Section 7.6 specification for `duty`.
#[must_use]
pub fn handover_spec(duty: DutyKind) -> DutyHandoverSpec {
    for spec in HANDOVER_TABLE {
        if spec.duty == duty {
            return spec;
        }
    }
    DutyHandoverSpec {
        duty,
        bound: HandoverBound::Immediate { timeout_ms: 0 },
        full_only: true,
    }
}

/// Leader round reached between `parent_timestamp_ms` and `now_ms`, using the
/// consensus round-pricing rule (`ROUND_TIMEOUT_MS = 3_000` ms per missed round).
#[must_use]
pub fn proposer_round_for_timestamps(parent_timestamp_ms: u128, now_ms: u128) -> u64 {
    affordable_leader_round(parent_timestamp_ms, now_ms)
}

/// Convenience: select the deterministic proposer for `(slot, round)` from the
/// active Full validator list `active_full`. When round `0`'s leader produces
/// no block within `ROUND_TIMEOUT_MS`, `round + 1` deterministically hands the
/// slot to a successor without waiting for an epoch boundary.
#[must_use]
pub fn select_round_proposer(
    slot: u64,
    round: u64,
    active_full: &[Address],
) -> Option<Address> {
    if active_full.is_empty() {
        return None;
    }
    let len = u64::try_from(active_full.len()).unwrap_or(1);
    let idx = usize::try_from(
        slot.wrapping_mul(131)
            .wrapping_add(round)
            .rem_euclid(len),
    )
    .unwrap_or(0);
    active_full.get(idx).copied()
}

/// Convenience: immediate client/peer failover for custody share reads, upload
/// gateways, and relay reservations (Section 7.6, Rows 3, 7, 8).
#[must_use]
pub fn select_next_endpoint(
    failed: &[Address],
    candidates: &[Address],
) -> Option<Address> {
    candidates
        .iter()
        .find(|cand| !failed.contains(cand))
        .copied()
}

/// Convenience: coordinate 3-epoch unacknowledged custody assignment handover on
/// `registry` (Section 7.6, Row 5).
pub fn handover_custody_assignments(
    registry: &mut Bud3Registry,
    current_epoch: u64,
    candidates: &[(Address, StorageClass)],
) -> usize {
    registry.handover_unacked_shares(current_epoch, candidates)
}

/// Convenience: coordinate 20-block repair task handover on `scheduler`
/// (Section 7.6, Row 6).
pub fn handover_repair_tasks(
    scheduler: &mut RepairScheduler,
    current_height: u64,
    full_candidates: &[Address],
) -> Vec<([u8; 32], u64, Address)> {
    scheduler.handover_expired(current_height, full_candidates)
}

/// One pending `PresenceAggregate` payload awaiting block inclusion (Section 7.6, Row 9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingPresenceAggregate {
    /// Presence window identifier.
    pub window_id: u64,
    /// Height at which the window closed and first became eligible for inclusion.
    pub ready_height: u64,
    /// Aggregated participation bitmap / digest bytes.
    pub bitmap: Vec<u8>,
}

/// Queue ensuring that if proposer at height `h` omits a ready
/// `PresenceAggregate`, proposer at `h + 1` includes it (max 1 block delay).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresenceAggregateQueue {
    pending: BTreeMap<u64, PendingPresenceAggregate>,
}

impl PresenceAggregateQueue {
    /// Convenience: create an empty presence-aggregate fallback queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: enqueue a closed presence window at `ready_height`.
    pub fn enqueue(&mut self, window_id: u64, ready_height: u64, bitmap: Vec<u8>) {
        self.pending
            .entry(window_id)
            .or_insert(PendingPresenceAggregate {
                window_id,
                ready_height,
                bitmap,
            });
    }

    /// Convenience: collect all pending aggregates eligible for inclusion in a
    /// block at `block_height`.
    #[must_use]
    pub fn collect_for_block(&self, block_height: u64) -> Vec<PendingPresenceAggregate> {
        self.pending
            .values()
            .filter(|agg| agg.ready_height <= block_height)
            .cloned()
            .collect()
    }

    /// Convenience: mark `window_id` included on chain so subsequent blocks do
    /// not re-include it.
    pub fn mark_included(&mut self, window_id: u64) -> bool {
        self.pending.remove(&window_id).is_some()
    }

    /// Convenience: number of aggregates still waiting for block inclusion.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Finality seat handover tracker implementing Section 7.6 Row 2 (`Instant Seat Handover`).
///
/// Invariant `V-2` is enforced at construction and registration: only
/// [`ValidatorClass::Full`] validators can enter `active_seats` or `standby_queue`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeatHandoverTracker {
    active_seats: Vec<Address>,
    standby_queue: VecDeque<Address>,
    consecutive_misses: BTreeMap<Address, u32>,
    vacated_this_epoch: BTreeSet<Address>,
}

impl SeatHandoverTracker {
    /// Convenience: build an epoch's seat tracker from candidate `(address, class)`
    /// entries, filtering strictly to `ValidatorClass::Full` (`V-2`).
    #[must_use]
    pub fn from_epoch_candidates(
        max_seats: usize,
        candidates: &[(Address, ValidatorClass)],
    ) -> Self {
        let mut active_seats = Vec::new();
        let mut standby_queue = VecDeque::new();
        for (addr, class) in candidates {
            if *class != ValidatorClass::Full {
                continue;
            }
            if active_seats.contains(addr) || standby_queue.contains(addr) {
                continue;
            }
            if active_seats.len() < max_seats {
                active_seats.push(*addr);
            } else {
                standby_queue.push_back(*addr);
            }
        }
        Self {
            active_seats,
            standby_queue,
            consecutive_misses: BTreeMap::new(),
            vacated_this_epoch: BTreeSet::new(),
        }
    }

    /// Convenience: current active finality seat holders.
    #[must_use]
    pub fn active_seats(&self) -> &[Address] {
        &self.active_seats
    }

    /// Convenience: number of standby Full validators ready to take vacated seats.
    #[must_use]
    pub fn standby_len(&self) -> usize {
        self.standby_queue.len()
    }

    /// Convenience: strict BFT finality seat quorum (`floor(2 * S / 3) + 1`).
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        let s = self.active_seats.len();
        if s == 0 {
            return 0;
        }
        (2 * s) / 3 + 1
    }

    /// Convenience: apply one finalized checkpoint's `participating` set,
    /// rotating up to `ceil(S / 10)` seats that missed at least 2 consecutive
    /// checkpoints to standby Full validators. Returns `(vacated, promoted)` pairs.
    pub fn record_checkpoint_participation(
        &mut self,
        participating: &BTreeSet<Address>,
    ) -> Vec<(Address, Address)> {
        if self.active_seats.is_empty() {
            return Vec::new();
        }
        let cap = self
            .active_seats
            .len()
            .div_ceil(SEAT_MAX_HANDOVER_DIVISOR)
            .max(1);
        let mut replacements = Vec::new();

        for idx in 0..self.active_seats.len() {
            let Some(holder) = self.active_seats.get(idx).copied() else {
                continue;
            };
            if participating.contains(&holder) {
                self.consecutive_misses.insert(holder, 0);
                continue;
            }
            let misses = self
                .consecutive_misses
                .get(&holder)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            self.consecutive_misses.insert(holder, misses);

            if misses >= SEAT_MISSED_CHECKPOINTS_FOR_HANDOVER && replacements.len() < cap {
                let next_standby = self.pop_eligible_standby();
                if let Some(promoted) = next_standby {
                    if let Some(slot) = self.active_seats.get_mut(idx) {
                        *slot = promoted;
                    }
                    self.consecutive_misses.remove(&holder);
                    self.consecutive_misses.insert(promoted, 0);
                    // Vacated validator cannot reclaim a seat in the same epoch.
                    self.vacated_this_epoch.insert(holder);
                    replacements.push((holder, promoted));
                }
            }
        }
        replacements
    }

    fn pop_eligible_standby(&mut self) -> Option<Address> {
        while let Some(cand) = self.standby_queue.pop_front() {
            if !self.vacated_this_epoch.contains(&cand) && !self.active_seats.contains(&cand) {
                return Some(cand);
            }
        }
        None
    }
}

/// Whether finality lag reaches eight of the supplied checkpoint intervals.
#[must_use]
pub const fn is_finality_stalled_at_interval(
    head_height: u64,
    finalized_height: u64,
    checkpoint_interval: u64,
) -> bool {
    head_height.saturating_sub(finalized_height)
        >= FINALITY_STALL_CHECKPOINTS.saturating_mul(checkpoint_interval.max(1))
}

/// Testnet convenience wrapper using the five-block checkpoint interval.
#[must_use]
pub const fn is_finality_stalled(head_height: u64, finalized_height: u64) -> bool {
    is_finality_stalled_at_interval(head_height, finalized_height, TESTNET_CHECKPOINT_INTERVAL_BLOCKS)
}

/// Node-level disaster recovery tracker implementing Section 7.7.
///
/// Tracks when finality stalls (`lag >= 40` blocks), drives the
/// `budlum_finality_stalled` Prometheus gauge (`0` or `1`), and enables
/// available-chain recovery committee derivation after 1 full epoch in recovery
/// mode (`R-03`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryTracker {
    stalled: bool,
    entered_height: Option<u64>,
    entered_epoch: Option<u64>,
}

impl RecoveryTracker {
    /// Create a fresh tracker in normal (non-stalled) finality mode.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a committed block at `(head_height, current_epoch)` against
    /// `finalized_height`, updating recovery mode state. Returns whether
    /// finality is currently stalled.
    pub fn observe_block(
        &mut self,
        head_height: u64,
        current_epoch: u64,
        finalized_height: u64,
    ) -> bool {
        self.observe_block_at_interval(
            head_height,
            current_epoch,
            finalized_height,
            TESTNET_CHECKPOINT_INTERVAL_BLOCKS,
        )
    }

    /// Observe a block using the running chain's checkpoint interval.
    pub fn observe_block_at_interval(
        &mut self,
        head_height: u64,
        current_epoch: u64,
        finalized_height: u64,
        checkpoint_interval: u64,
    ) -> bool {
        if is_finality_stalled_at_interval(head_height, finalized_height, checkpoint_interval) {
            if !self.stalled {
                self.stalled = true;
                self.entered_height = Some(head_height);
                self.entered_epoch = Some(current_epoch);
            }
        } else {
            self.clear();
        }
        self.stalled
    }

    /// Testnet convenience wrapper for an advancing finalized height.
    pub fn observe_finality(
        &mut self,
        head_height: u64,
        current_epoch: u64,
        finalized_height: u64,
    ) -> bool {
        self.observe_block(head_height, current_epoch, finalized_height)
    }

    /// Observe finality using the running chain's checkpoint interval.
    pub fn observe_finality_at_interval(
        &mut self,
        head_height: u64,
        current_epoch: u64,
        finalized_height: u64,
        checkpoint_interval: u64,
    ) -> bool {
        self.observe_block_at_interval(
            head_height,
            current_epoch,
            finalized_height,
            checkpoint_interval,
        )
    }

    /// Whether the chain is currently in disaster recovery mode
    /// (`budlum_finality_stalled == 1`).
    #[must_use]
    pub const fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Convenience: `(entered_height, entered_epoch)` if currently in recovery mode.
    #[must_use]
    pub const fn entered_at(&self) -> Option<(u64, u64)> {
        match (self.entered_height, self.entered_epoch) {
            (Some(h), Some(e)) => Some((h, e)),
            _ => None,
        }
    }

    /// Convenience: whether at least [`RECOVERY_COMMITTEE_WAIT_EPOCHS`] (1 epoch)
    /// has elapsed in recovery mode so the next epoch's committee may be derived
    /// from available-chain presence records.
    #[must_use]
    pub const fn recovery_committee_ready(&self, current_epoch: u64) -> bool {
        match (self.stalled, self.entered_epoch) {
            (true, Some(entered)) => {
                current_epoch.saturating_sub(entered) >= RECOVERY_COMMITTEE_WAIT_EPOCHS
            }
            _ => false,
        }
    }

    /// Convenience: derive the recovery committee from available-chain presence
    /// records `(address, class, present_on_available_chain)` once at least 1
    /// epoch has elapsed in recovery mode.
    ///
    /// Preserves invariant `V-2`: Mobile and MobileOpportunistic validators are
    /// never admitted to the recovery committee. See module docs for residual
    /// partition risk `R-03`.
    #[must_use]
    pub fn derive_recovery_committee(
        &self,
        current_epoch: u64,
        max_seats: usize,
        available_presence: &[(Address, ValidatorClass, bool)],
    ) -> Option<Vec<Address>> {
        if !self.recovery_committee_ready(current_epoch) || max_seats == 0 {
            return None;
        }
        let mut committee = Vec::new();
        for (addr, class, present) in available_presence {
            if *present && *class == ValidatorClass::Full && !committee.contains(addr) {
                committee.push(*addr);
                if committee.len() >= max_seats {
                    break;
                }
            }
        }
        if committee.is_empty() {
            None
        } else {
            Some(committee)
        }
    }

    fn clear(&mut self) {
        self.stalled = false;
        self.entered_height = None;
        self.entered_epoch = None;
    }
}
