//! Instant Task Handover: the duty rules.
//!
//! A validator can leave at any moment. Every duty it holds passes to the next
//! candidate without waiting and without a human (directive 7.6). One duty row
//! is one trigger, one successor rule and one time bound. [`DUTY_RULES`] is
//! that table; the trackers below are its executable rows.
//!
//! Disaster mode (directive 7.7) is the whole-network row: when more than a
//! third of the active seats leave at once, finality stops. Block production
//! continues on the available chain, and [`FinalityStallWatch`] moves the node
//! into recovery mode after eight checkpoint intervals without a finalization.

use crate::core::chain_config::{
    epoch_len_for_chain_id, finality_checkpoint_interval_for_chain_id,
};
use prometheus::IntGauge;

/// The duty classes of the handover table (directive 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DutyKind {
    /// The slot leader publishes no block in its round.
    BlockProposal,
    /// A finality seat is absent from two consecutive finalized participation
    /// records.
    FinalitySeat,
    /// A piece holder does not answer a read within 2 seconds.
    CustodyRead,
    /// A piece is lost under the piece-loss rule (directive 6.10).
    CustodyDurability,
    /// The assignee of a new share does not confirm within 3 epochs.
    ShareAssignment,
    /// The assignee of a repair task starts no `RecordRepair` within 20 blocks.
    RepairTask,
    /// An upload gateway does not answer.
    UploadGateway,
    /// A relay reservation drops.
    Relay,
    /// A block proposer omits the presence aggregate.
    PresenceAggregate,
}

/// The time bound of one handover row (directive 7.6, "max delay" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverBound {
    /// One leader round: [`ROUND_TIMEOUT_MS`](crate::consensus::ROUND_TIMEOUT_MS)
    /// is 3 seconds on every network.
    OneRound,
    /// Three checkpoint intervals: 45 seconds at the testnet interval of 5
    /// blocks and a 3 second slot.
    CheckpointIntervals(u64),
    /// The client re-issues on another holder or gateway at once.
    Immediate,
    /// The repair window that covers the piece: 1 day for Full holders, 7 days
    /// for Mobile holders. The redundancy must outlast this window.
    DurabilityWindow { full_days: u64, mobile_days: u64 },
    /// Plain epoch count.
    Epochs(u64),
    /// Plain block count.
    Blocks(u64),
    /// The mobile validator reconnects to another relay.
    Reconnect,
}

/// One row of the handover table: trigger, successor rule, time bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DutyRule {
    /// The duty class this row governs.
    pub duty: DutyKind,
    /// What starts the handover, in words. The executable triggers live in the
    /// trackers below.
    pub trigger: &'static str,
    /// Where the duty goes when the trigger fires.
    pub successor: &'static str,
    /// The maximum delay before the successor holds the duty.
    pub bound: HandoverBound,
}

/// The complete handover table (directive 7.6). One row per duty, in table
/// order. No row waits for a human or a governance vote.
pub const DUTY_RULES: [DutyRule; 9] = [
    DutyRule {
        duty: DutyKind::BlockProposal,
        trigger: "the slot leader publishes no block in its round",
        successor: "the next round's leader",
        bound: HandoverBound::OneRound,
    },
    DutyRule {
        duty: DutyKind::FinalitySeat,
        trigger: "the seat is absent from two consecutive finalized participation records",
        successor: "the next standby of the seat",
        bound: HandoverBound::CheckpointIntervals(3),
    },
    DutyRule {
        duty: DutyKind::CustodyRead,
        trigger: "the piece holder does not answer within 2 seconds",
        successor: "another piece holder, chosen by the client",
        bound: HandoverBound::Immediate,
    },
    DutyRule {
        duty: DutyKind::CustodyDurability,
        trigger: "the piece-loss rule fires (directive 6.10)",
        successor: "repair writes the piece to a new holder",
        bound: HandoverBound::DurabilityWindow {
            full_days: 1,
            mobile_days: 7,
        },
    },
    DutyRule {
        duty: DutyKind::ShareAssignment,
        trigger: "the assignee does not confirm a new share within 3 epochs",
        successor: "the next candidate",
        bound: HandoverBound::Epochs(3),
    },
    DutyRule {
        duty: DutyKind::RepairTask,
        trigger: "the assignee starts no RecordRepair within 20 blocks",
        successor: "the next candidate",
        bound: HandoverBound::Blocks(20),
    },
    DutyRule {
        duty: DutyKind::UploadGateway,
        trigger: "the upload gateway does not answer",
        successor: "another upload gateway, chosen by the client",
        bound: HandoverBound::Immediate,
    },
    DutyRule {
        duty: DutyKind::Relay,
        trigger: "the relay reservation drops",
        successor: "another relay, chosen by the mobile validator",
        bound: HandoverBound::Reconnect,
    },
    DutyRule {
        duty: DutyKind::PresenceAggregate,
        trigger: "the block proposer omits the presence aggregate",
        successor: "the next block's proposer includes it",
        bound: HandoverBound::Blocks(1),
    },
];

/// A new share assignment must be confirmed within this many epochs before the
/// duty passes to the next candidate (directive 7.6).
pub const SHARE_ASSIGNMENT_CONFIRM_EPOCHS: u64 = 3;

/// A repair task must start `RecordRepair` within this many blocks before the
/// duty passes to the next candidate (directive 7.6).
pub const REPAIR_TASK_START_BLOCKS: u64 = 20;

/// Disaster mode fires after this many checkpoint intervals without a
/// finalization (directive 7.7): 8 intervals, 40 blocks at the testnet
/// interval of 5 blocks.
pub const DISASTER_CHECKPOINT_INTERVALS: u64 = 8;

/// The share-assignment row: the assignee confirms a new share within
/// [`SHARE_ASSIGNMENT_CONFIRM_EPOCHS`] epochs, or the duty passes to the next
/// candidate.
#[derive(Debug, Clone)]
pub struct ShareAssignmentTracker {
    assigned_epoch: u64,
    confirmed: bool,
}

impl ShareAssignmentTracker {
    /// A new share assigned at `assigned_epoch`, awaiting confirmation.
    #[must_use]
    pub fn new(assigned_epoch: u64) -> Self {
        Self {
            assigned_epoch,
            confirmed: false,
        }
    }

    /// The assignee confirmed the share; no handover will be due.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// The epoch at which the handover becomes due if no confirmation lands.
    #[must_use]
    pub fn handover_epoch(&self) -> u64 {
        self.assigned_epoch.saturating_add(SHARE_ASSIGNMENT_CONFIRM_EPOCHS)
    }

    /// True when the duty must pass to the next candidate at `epoch`.
    #[must_use]
    pub fn handover_due(&self, epoch: u64) -> bool {
        !self.confirmed && epoch >= self.handover_epoch()
    }
}

/// The repair-task row: the assignee starts `RecordRepair` within
/// [`REPAIR_TASK_START_BLOCKS`] blocks, or the duty passes to the next
/// candidate.
#[derive(Debug, Clone)]
pub struct RepairTaskTracker {
    assigned_height: u64,
    repair_started: bool,
}

impl RepairTaskTracker {
    /// A repair task assigned at block height `assigned_height`.
    #[must_use]
    pub fn new(assigned_height: u64) -> Self {
        Self {
            assigned_height,
            repair_started: false,
        }
    }

    /// The assignee started `RecordRepair`; no handover will be due.
    pub fn note_repair_started(&mut self) {
        self.repair_started = true;
    }

    /// The block height at which the handover becomes due if the repair has
    /// not started.
    #[must_use]
    pub fn handover_height(&self) -> u64 {
        self.assigned_height.saturating_add(REPAIR_TASK_START_BLOCKS)
    }

    /// True when the duty must pass to the next candidate at `height`.
    #[must_use]
    pub fn handover_due(&self, height: u64) -> bool {
        !self.repair_started && height >= self.handover_height()
    }
}

/// The presence-aggregate row: when a block proposer omits the aggregate for
/// window `w`, the next block's proposer includes it (bound: 1 block,
/// directive 7.6 and 7.8).
#[derive(Debug, Clone, Default)]
pub struct PresenceAggregateFallback {
    omitted_at_height: Option<u64>,
}

impl PresenceAggregateFallback {
    /// The proposer of block `height` omitted the presence aggregate. A new
    /// omission replaces the outstanding one: one omission, one successor.
    pub fn note_omission(&mut self, height: u64) {
        self.omitted_at_height = Some(height);
    }

    /// The highest block that must carry the aggregate, when one is
    /// outstanding: the omission block plus one.
    #[must_use]
    pub fn due_by(&self) -> Option<u64> {
        self.omitted_at_height.map(|height| height.saturating_add(1))
    }

    /// True when block `height` is the successor block that owes the
    /// aggregate.
    #[must_use]
    pub fn is_due(&self, height: u64) -> bool {
        self.due_by().is_some_and(|due| height >= due)
    }
}

/// Disaster mode (directive 7.7). The watch counts blocks since the last
/// finalization. After [`DISASTER_CHECKPOINT_INTERVALS`] checkpoint intervals
/// without one, the node enters recovery mode and the bound
/// `budlum_finality_stalled` gauge reads 1. One epoch after recovery starts,
/// the next epoch's committee is computed from the presence records on the
/// available chain.
///
/// The directive defines recovery entry only. This watch also leaves recovery
/// when finality resumes: a node that regained finality must not keep
/// recomputing committees from presence records. The choice is recorded in the
/// pull request that carries this code.
#[derive(Debug, Clone)]
pub struct FinalityStallWatch {
    chain_id: u64,
    latest_block_height: u64,
    last_finality_height: u64,
    recovery_started_at: Option<u64>,
    metric: Option<IntGauge>,
}

impl FinalityStallWatch {
    /// A watch on `chain_id`, with `genesis_height` as the initial chain head
    /// and the assumed last finalization.
    #[must_use]
    pub fn new(chain_id: u64, genesis_height: u64) -> Self {
        Self {
            chain_id,
            latest_block_height: genesis_height,
            last_finality_height: genesis_height,
            recovery_started_at: None,
            metric: None,
        }
    }

    /// Bind the `budlum_finality_stalled` gauge. The watch sets it to 1 on
    /// entering recovery mode and back to 0 on leaving.
    pub fn bind_metric(&mut self, metric: IntGauge) {
        self.metric = Some(metric);
    }

    /// The node produced or observed block `height`.
    pub fn observe_block(&mut self, height: u64) {
        self.latest_block_height = self.latest_block_height.max(height);
        if self.is_stalled() {
            self.enter_recovery();
        }
    }

    /// Finality advanced to `height`.
    pub fn observe_finality(&mut self, height: u64) {
        self.last_finality_height = self.last_finality_height.max(height);
        self.latest_block_height = self.latest_block_height.max(height);
        if self.recovery_started_at.is_some() {
            self.exit_recovery();
        }
    }

    /// The block count at which a stall becomes a disaster-mode entry: eight
    /// checkpoint intervals on this chain.
    #[must_use]
    pub fn stall_blocks(&self) -> u64 {
        let interval = finality_checkpoint_interval_for_chain_id(self.chain_id);
        DISASTER_CHECKPOINT_INTERVALS.saturating_mul(interval)
    }

    /// Blocks observed since the last finalization.
    #[must_use]
    pub fn blocks_without_finality(&self) -> u64 {
        self.latest_block_height
            .saturating_sub(self.last_finality_height)
    }

    /// True while no finalization has landed for [`Self::stall_blocks`]
    /// blocks. This is the trigger; [`Self::in_recovery_mode`] is the state.
    #[must_use]
    pub fn is_stalled(&self) -> bool {
        self.blocks_without_finality() >= self.stall_blocks()
    }

    /// True while the node runs recovery mode.
    #[must_use]
    pub fn in_recovery_mode(&self) -> bool {
        self.recovery_started_at.is_some()
    }

    /// True once one epoch has passed inside recovery mode. Then the next
    /// epoch's committee is computed from the presence records on the
    /// available chain (directive 7.7).
    #[must_use]
    pub fn committee_recompute_due(&self) -> bool {
        self.recovery_started_at.is_some_and(|started| {
            let epoch_len = epoch_len_for_chain_id(self.chain_id);
            self.latest_block_height.saturating_sub(started) >= epoch_len
        })
    }

    fn enter_recovery(&mut self) {
        if self.recovery_started_at.is_none() {
            self.recovery_started_at = Some(self.latest_block_height);
        }
        if let Some(metric) = &self.metric {
            metric.set(1);
        }
    }

    fn exit_recovery(&mut self) {
        self.recovery_started_at = None;
        if let Some(metric) = &self.metric {
            metric.set(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ROUND_TIMEOUT_MS;

    /// The rule table is the whole of directive 7.6: one trigger, one
    /// successor and one time bound per duty, and nothing else is a duty.
    #[test]
    fn duty_rule_table_matches_directive_7_6() {
        assert_eq!(DUTY_RULES.len(), 9);
        let duties: Vec<DutyKind> = DUTY_RULES.iter().map(|rule| rule.duty).collect();
        assert_eq!(
            duties,
            vec![
                DutyKind::BlockProposal,
                DutyKind::FinalitySeat,
                DutyKind::CustodyRead,
                DutyKind::CustodyDurability,
                DutyKind::ShareAssignment,
                DutyKind::RepairTask,
                DutyKind::UploadGateway,
                DutyKind::Relay,
                DutyKind::PresenceAggregate,
            ]
        );
        for rule in &DUTY_RULES {
            assert!(!rule.trigger.is_empty(), "every row names its trigger");
            assert!(!rule.successor.is_empty(), "every row names its successor");
        }
        // The written bounds of directive 7.6.
        assert_eq!(DUTY_RULES[0].bound, HandoverBound::OneRound);
        assert_eq!(DUTY_RULES[1].bound, HandoverBound::CheckpointIntervals(3));
        assert_eq!(DUTY_RULES[2].bound, HandoverBound::Immediate);
        assert_eq!(
            DUTY_RULES[3].bound,
            HandoverBound::DurabilityWindow {
                full_days: 1,
                mobile_days: 7,
            }
        );
        assert_eq!(DUTY_RULES[4].bound, HandoverBound::Epochs(3));
        assert_eq!(DUTY_RULES[5].bound, HandoverBound::Blocks(20));
        assert_eq!(DUTY_RULES[6].bound, HandoverBound::Immediate);
        assert_eq!(DUTY_RULES[7].bound, HandoverBound::Reconnect);
        assert_eq!(DUTY_RULES[8].bound, HandoverBound::Blocks(1));
        // The block-proposal bound is one round of 3 seconds.
        assert_eq!(ROUND_TIMEOUT_MS, 3_000);
    }

    /// The repair assignee starts no `RecordRepair` within 20 blocks, so the
    /// task passes to the next candidate at block `assigned + 20`.
    #[test]
    fn repair_task_handover_after_20_blocks() {
        let mut task = RepairTaskTracker::new(100);
        assert!(!task.handover_due(119));
        assert_eq!(task.handover_height(), 120);
        assert!(task.handover_due(120));
        assert!(task.handover_due(121));

        let mut started = RepairTaskTracker::new(100);
        started.note_repair_started();
        assert!(!started.handover_due(10_000));

        let mut just_in_time = RepairTaskTracker::new(100);
        just_in_time.note_repair_started();
        assert!(!just_in_time.handover_due(120));
    }

    /// A new share assignment passes to the next candidate after 3 epochs
    /// without confirmation.
    #[test]
    fn custody_assignment_handover_after_3_epochs() {
        let mut assignment = ShareAssignmentTracker::new(10);
        assert!(!assignment.handover_due(12));
        assert_eq!(assignment.handover_epoch(), 13);
        assert!(assignment.handover_due(13));
        assert!(assignment.handover_due(14));

        let mut confirmed = ShareAssignmentTracker::new(10);
        confirmed.confirm();
        assert!(!confirmed.handover_due(10_000));
    }

    /// An omitted presence aggregate is owed by the next block's proposer:
    /// the bound is one block.
    #[test]
    fn presence_aggregate_fallback_next_block() {
        let mut fallback = PresenceAggregateFallback::default();
        assert!(!fallback.is_due(100));
        assert_eq!(fallback.due_by(), None);

        fallback.note_omission(100);
        assert!(!fallback.is_due(100), "the omission block already passed");
        assert_eq!(fallback.due_by(), Some(101));
        assert!(fallback.is_due(101), "the next block owes the aggregate");
        assert!(fallback.is_due(102), "the debt does not expire at one block");

        fallback.note_omission(200);
        assert_eq!(fallback.due_by(), Some(201), "one omission, one successor");
    }

    /// Disaster mode (directive 7.7): 8 checkpoint intervals without a
    /// finalization put the node into recovery mode and the metric to 1. The
    /// committee is recomputed from presence records after one epoch.
    #[test]
    fn finality_stall_enters_recovery_mode() {
        let chain_id = 45261; // testnet: interval 5 blocks, epoch 50 blocks
        let mut watch = FinalityStallWatch::new(chain_id, 0);
        let metric = IntGauge::new("budlum_stall_probe", "test probe").unwrap();
        watch.bind_metric(metric.clone());
        assert_eq!(watch.stall_blocks(), 40);

        // Finality keeps up for a while: no recovery.
        for height in 1..=39 {
            watch.observe_block(height);
            if height % 5 == 0 {
                watch.observe_finality(height);
            }
        }
        assert!(!watch.in_recovery_mode());
        assert_eq!(metric.get(), 0);

        // Finality stops. 40 blocks later the node enters recovery mode.
        for height in 40..=80 {
            watch.observe_block(height);
        }
        assert!(watch.is_stalled());
        assert!(watch.in_recovery_mode());
        assert_eq!(metric.get(), 1);
        assert!(
            !watch.committee_recompute_due(),
            "one epoch is 50 blocks; 40 blocks of stall are not one epoch"
        );

        // One epoch in recovery: the committee is recomputed from presence
        // records on the available chain.
        for height in 81..=130 {
            watch.observe_block(height);
        }
        assert!(watch.committee_recompute_due());

        // Finality resumes: the node leaves recovery mode and the metric drops.
        watch.observe_finality(131);
        assert!(!watch.in_recovery_mode());
        assert_eq!(metric.get(), 0);
        assert!(!watch.committee_recompute_due());
    }
}
