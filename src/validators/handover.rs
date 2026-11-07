//! The Instant Task Handover duty table (directive 7.6).
//!
//! Every duty has a trigger, a successor and a time bound, and no duty waits
//! for a human. This module is WP-14's card path and carries the binding
//! table; the executable rows live in
//! [`crate::registry::handover::HandoverCoordinator`] (triggers, handover
//! rules and the disaster-mode state of directive 7.7) and the churn
//! simulation tool lives in `tests/churn/`. Keeping the table here separates
//! what the directive binds from how the coordinator executes it.
//!
//! WIRING: validator surface - the coordinator and the churn tool read the
//! table at their wiring.

use crate::consensus::ROUND_TIMEOUT_MS;

/// The duty classes of the handover table (directive 7.6).
///
/// WIRING: validator surface - the coordinator's [`HandoverDutyKind`] naming
/// lands with this table.
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
///
/// WIRING: validator surface - the coordinator enforces these bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverBound {
    /// One leader round: [`ROUND_TIMEOUT_MS`] is 3 seconds on every network.
    OneRound,
    /// Finality seat: 3 checkpoint intervals, 45 seconds at the testnet
    /// interval of 5 blocks and a 3 second slot.
    CheckpointIntervals(u64),
    /// The client re-issues on another holder or gateway at once.
    Immediate,
    /// The repair window that covers the piece: 1 day for Full holders, 7
    /// days for Mobile holders. The redundancy must outlast this window.
    DurabilityWindow { full_days: u64, mobile_days: u64 },
    /// Plain epoch count.
    Epochs(u64),
    /// Plain block count.
    Blocks(u64),
    /// The mobile validator reconnects to another relay.
    Reconnect,
}

/// One row of the handover table: trigger, successor rule, time bound.
///
/// WIRING: validator surface - the coordinator enforces each row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DutyRule {
    /// The duty class this row governs.
    pub duty: DutyKind,
    /// What starts the handover. The executable triggers live in the
    /// coordinator.
    pub trigger: &'static str,
    /// Where the duty goes when the trigger fires.
    pub successor: &'static str,
    /// The maximum delay before the successor holds the duty.
    pub bound: HandoverBound,
}

/// The complete handover table (directive 7.6): one row per duty, in table
/// order, in the words of the directive.
///
/// WIRING: validator surface - the coordinator and the churn tool read this
/// table at their wiring.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
