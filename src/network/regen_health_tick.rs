//! The node runtime's regeneration health tick.
//!
//! WIRING: `Node::run` calls [`RegenHealthTick::observe`] once per finality
//! beat, with the node's view of its latest finalized checkpoints. The tick
//! calls [`assess`] and executes the verdict through the reversion ledger.
//!
//! # How live node state maps onto the ledger stages
//!
//! - `Medusa` is the latest finalized checkpoint. The node's own block hash
//!   at that height is the commitment it holds.
//! - `Ephyra` is the finalized checkpoint one interval below it.
//! - `Polyp` is genesis. The runtime has no network-agreed commitment for
//!   genesis, so the canonical source answers nothing for it, and a verdict
//!   that needs a full reversion becomes an alarm.
//!
//! The canonical commitment for a height is the checkpoint hash in the
//! finality certificate stored for that height. A certificate carries a
//! quorum signature, so no single node chose it.
//!
//! # Where the cost estimates come from
//!
//! Both are measured in blocks to re-execute, from the checkpoint heights
//! the node holds. In-place repair cannot know where the damage entered, so
//! it re-verifies the whole local view up to the live checkpoint: the repair
//! cost is the live checkpoint height. A reversion gives up the heights above
//! its target: the re-growth cost is the live height minus the `Ephyra`
//! height.
//!
//! # What execution does and does not do
//!
//! A repair verdict opens a sync round, which is how the runtime fetches
//! canonical blocks and replaces a diverged branch. A revert verdict moves
//! the ledger through [`RegenerationLedger::revert`] (or
//! [`RegenerationLedger::revert_after_forgery`] when the audit trail does not
//! validate) and also opens a sync round to re-grow. The ledger grows back
//! through [`RegenerationLedger::grow`] only when the node's own block at the
//! next checkpoint matches the certificate. Rolling chain storage back to
//! the target checkpoint is a chain state transition that the chain actor
//! does not define, so this tick does not do it.

use crate::domain::regen_health::{assess, AlarmReason, HealthPolicy, HealthVerdict};
use crate::domain::regeneration_stage::{
    RegenerationLedger, Reversion, ReversionError, Stage, StageSnapshot, Stress,
};

/// One finalized checkpoint as the node sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    /// The node's own block hash at this height, if it holds the block.
    pub local: Option<[u8; 32]>,
    /// The checkpoint hash in the stored finality certificate, if any.
    pub canonical: Option<[u8; 32]>,
}

/// The checkpoints one tick looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointView {
    /// Height of the latest finalized checkpoint. Zero means nothing is
    /// finalized yet.
    pub live: u64,
    /// Height of the finalized checkpoint one interval below `live`.
    pub previous: Option<u64>,
    /// Every checkpoint the node fetched for this tick: at least `live`,
    /// `previous` and [`RegenHealthTick::held_height`].
    pub checkpoints: Vec<Checkpoint>,
}

impl CheckpointView {
    fn at(&self, height: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

    fn canonical(&self, stage: Stage, height: u64) -> Option<[u8; 32]> {
        if stage == Stage::Polyp {
            return None;
        }
        self.at(height).and_then(|c| c.canonical)
    }

    fn stage_height(&self, stage: Stage) -> Option<u64> {
        match stage {
            Stage::Medusa => Some(self.live),
            Stage::Ephyra => self.previous,
            Stage::Polyp => Some(0),
        }
    }
}

/// What one tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    /// Nothing is finalized yet, so there is nothing to assess against.
    Idle,
    /// The held view matches the canonical source.
    Healthy,
    /// Repair is cheaper than reversion. The runtime opens a sync round.
    Repair {
        stress: Stress,
        repair_cost: u64,
        regrowth_cost: u64,
    },
    /// The ledger reverted. The runtime opens a sync round to re-grow.
    Reverted(Reversion),
    /// The ledger refused the reversion the verdict asked for.
    RevertRefused(ReversionError),
    /// Self-recovery is impossible or unsafe. An operator must hear it.
    Alarm {
        reason: AlarmReason,
        stress: Option<Stress>,
    },
}

impl TickOutcome {
    /// Whether the runtime must open a sync round to fetch canonical blocks.
    #[must_use]
    pub fn opens_sync(&self) -> bool {
        matches!(self, Self::Repair { .. } | Self::Reverted(_))
    }
}

/// The node's reversion ledger and the policy the tick assesses it with.
#[derive(Debug, Clone)]
pub struct RegenHealthTick {
    ledger: RegenerationLedger,
    policy: HealthPolicy,
}

impl Default for RegenHealthTick {
    fn default() -> Self {
        Self::new(HealthPolicy::default())
    }
}

impl RegenHealthTick {
    #[must_use]
    pub fn new(policy: HealthPolicy) -> Self {
        Self {
            ledger: RegenerationLedger::default(),
            policy,
        }
    }

    /// The checkpoint height the ledger holds. The caller fetches this
    /// checkpoint too, so a reverted stage can still be checked.
    #[must_use]
    pub fn held_height(&self) -> u64 {
        self.ledger.height
    }

    /// Runs one health tick against `view`.
    pub fn observe(&mut self, view: &CheckpointView) -> TickOutcome {
        if view.live == 0 {
            return TickOutcome::Idle;
        }
        let canonical = |stage: Stage, height: u64| view.canonical(stage, height);
        let stage_height = |stage: Stage| view.stage_height(stage);

        if self.ledger.stage == Stage::Medusa {
            // The adult stage follows the live checkpoint. A missing block
            // holds no commitment, so it cannot match the certificate.
            let live = view.at(view.live).and_then(|c| c.local);
            self.ledger.height = view.live;
            self.ledger.commitment = live.unwrap_or_default();
        } else if let Some(next) = self.ledger.stage.later() {
            // A reverted stage grows back one stage at a time, and only when
            // the node's own block at that checkpoint is canonical.
            let local = view
                .stage_height(next)
                .and_then(|height| view.at(height))
                .and_then(|c| c.local.map(|local| (c.height, local)));
            if let Some((height, commitment)) = local {
                let snapshot = StageSnapshot {
                    stage: next,
                    height,
                    commitment,
                    carried: Default::default(),
                };
                // A refusal leaves the ledger unchanged; the next tick tries
                // again after the sync round.
                let _ = self.ledger.grow(&snapshot, &canonical);
            }
        }

        let repair_cost = self.ledger.height;
        let regrowth_cost = self
            .ledger
            .height
            .saturating_sub(view.previous.unwrap_or(0));
        let verdict = assess(
            &self.ledger,
            &self.policy,
            &canonical,
            &stage_height,
            repair_cost,
            regrowth_cost,
        );
        // A reversion leaves the ledger holding an earlier stage, and the
        // divergence that caused it sits at the live checkpoint, above the one
        // `assess` reads. A Healthy verdict for the reverted stage says
        // nothing about the live view, so it must not end the recovery: while
        // the node's own block at the live checkpoint still differs from the
        // certificate - or cannot be compared at all - the tick keeps asking
        // for the repair sync instead of falling silent.
        let reverted = self.ledger.stage != Stage::Medusa;
        let live_diverged = match (
            view.at(view.live).and_then(|c| c.local),
            view.canonical(Stage::Medusa, view.live),
        ) {
            (Some(local), Some(canonical)) => local != canonical,
            _ => true,
        };
        match verdict {
            HealthVerdict::Healthy if reverted && live_diverged => TickOutcome::Repair {
                stress: Stress::Divergence,
                repair_cost,
                regrowth_cost,
            },
            HealthVerdict::Healthy => TickOutcome::Healthy,
            HealthVerdict::RepairRecommended {
                stress,
                repair_cost,
                regrowth_cost,
            } => TickOutcome::Repair {
                stress,
                repair_cost,
                regrowth_cost,
            },
            HealthVerdict::RevertTo { target, stress } => {
                let result = if self.ledger.validate().is_ok() {
                    self.ledger
                        .revert(&target, stress, &self.policy.reversion, &canonical)
                } else {
                    self.ledger.revert_after_forgery(
                        &target,
                        stress,
                        &self.policy.reversion,
                        &canonical,
                    )
                };
                match result {
                    Ok(reversion) => TickOutcome::Reverted(reversion),
                    Err(error) => TickOutcome::RevertRefused(error),
                }
            }
            HealthVerdict::Alarm { reason, stress } => TickOutcome::Alarm { reason, stress },
        }
    }
}

/// Decodes a 32-byte hex hash. Anything else holds no commitment.
#[must_use]
pub fn hash32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::regeneration_stage::ReversionPolicy;

    const INTERVAL: u64 = 100;

    fn hash_of(height: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&height.to_le_bytes());
        h[31] = 0xC0;
        h
    }

    fn honest(height: u64) -> Checkpoint {
        Checkpoint {
            height,
            local: Some(hash_of(height)),
            canonical: Some(hash_of(height)),
        }
    }

    fn diverged(height: u64) -> Checkpoint {
        Checkpoint {
            local: Some([0xFF; 32]),
            ..honest(height)
        }
    }

    /// A view whose live checkpoint is `live_cp`, with the honest previous
    /// checkpoint one interval below it.
    fn view(live_cp: Checkpoint) -> CheckpointView {
        let live = live_cp.height;
        let previous = live - INTERVAL;
        CheckpointView {
            live,
            previous: Some(previous),
            checkpoints: vec![live_cp, honest(previous)],
        }
    }

    #[test]
    fn nothing_finalized_is_idle() {
        let mut tick = RegenHealthTick::default();
        assert_eq!(tick.observe(&CheckpointView::default()), TickOutcome::Idle);
    }

    #[test]
    fn a_healthy_ledger_takes_no_action() {
        let mut tick = RegenHealthTick::default();
        let outcome = tick.observe(&view(honest(300)));
        assert_eq!(outcome, TickOutcome::Healthy);
        assert!(!outcome.opens_sync());
        assert_eq!(tick.held_height(), 300);
    }

    #[test]
    fn damage_with_cheap_repair_opens_the_repair_sync() {
        // A young chain: re-verifying 300 blocks in place is cheaper than
        // ten times the 100 heights a reversion would give up.
        let mut tick = RegenHealthTick::default();
        let outcome = tick.observe(&view(diverged(300)));
        assert_eq!(
            outcome,
            TickOutcome::Repair {
                stress: Stress::Divergence,
                repair_cost: 300,
                regrowth_cost: INTERVAL,
            }
        );
        assert!(outcome.opens_sync());
        // Repair is recorded, not executed on the ledger.
        assert!(tick.ledger.reversion_events.is_empty());
    }

    #[test]
    fn damage_with_costly_repair_reverts_and_regrows_when_canonical() {
        let mut tick = RegenHealthTick::default();
        let outcome = tick.observe(&view(diverged(2000)));
        match &outcome {
            TickOutcome::Reverted(r) => {
                assert_eq!(r.from, Stage::Medusa);
                assert_eq!(r.to, Stage::Ephyra);
                assert_eq!(r.height_after, 1900);
                assert_eq!(r.stress, Stress::Divergence);
            }
            other => panic!("expected Reverted, got {other:?}"),
        }
        assert!(outcome.opens_sync());
        assert_eq!(tick.ledger.stage, Stage::Ephyra);

        // Still diverged: growth is refused, and the reverted stage must not
        // report Healthy while the live view still diverges - it keeps asking
        // for the repair sync that can replace the block.
        assert!(matches!(
            tick.observe(&view(diverged(2000))),
            TickOutcome::Repair { .. }
        ));
        assert_eq!(tick.ledger.stage, Stage::Ephyra);

        // The sync round fetched the canonical block: the ledger grows back.
        assert_eq!(tick.observe(&view(honest(2000))), TickOutcome::Healthy);
        assert_eq!(tick.ledger.stage, Stage::Medusa);
        assert_eq!(tick.held_height(), 2000);
    }

    #[test]
    fn a_ledger_past_its_reversion_budget_alarms_with_the_budget_reason() {
        let policy = HealthPolicy {
            reversion: ReversionPolicy {
                max_events_per_lifetime: 1,
                ..ReversionPolicy::default()
            },
            ..HealthPolicy::default()
        };
        let mut tick = RegenHealthTick::new(policy);
        assert!(matches!(
            tick.observe(&view(diverged(2000))),
            TickOutcome::Reverted(_)
        ));
        assert_eq!(tick.observe(&view(honest(2000))), TickOutcome::Healthy);
        assert_eq!(tick.ledger.stage, Stage::Medusa);

        let outcome = tick.observe(&view(diverged(2100)));
        match &outcome {
            TickOutcome::Alarm { reason, stress } => {
                assert_eq!(reason.kind(), "regen-alarm-budget-exhausted");
                assert_eq!(
                    *reason,
                    AlarmReason::ReversionBudgetExhausted {
                        events: 1,
                        limit: 1
                    }
                );
                assert_eq!(*stress, Some(Stress::Divergence));
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
        assert!(!outcome.opens_sync());
        assert_eq!(tick.ledger.event_count(), 1);
    }

    #[test]
    fn a_missing_certificate_alarms_and_never_reverts_blind() {
        let mut tick = RegenHealthTick::default();
        let live = Checkpoint {
            canonical: None,
            ..diverged(2000)
        };
        let outcome = tick.observe(&view(live));
        match &outcome {
            TickOutcome::Alarm { reason, .. } => {
                assert_eq!(reason.kind(), "regen-alarm-no-canonical-source");
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
        assert!(tick.ledger.reversion_events.is_empty());
    }

    #[test]
    fn a_missing_local_block_cannot_match_the_certificate() {
        let mut tick = RegenHealthTick::default();
        let live = Checkpoint {
            local: None,
            ..honest(300)
        };
        assert!(matches!(
            tick.observe(&view(live)),
            TickOutcome::Repair { .. }
        ));
    }

    #[test]
    fn hash32_accepts_only_32_byte_hex() {
        assert_eq!(hash32(&"ab".repeat(32)), Some([0xAB; 32]));
        assert_eq!(hash32("ab"), None);
        assert_eq!(hash32("zz"), None);
    }
}
