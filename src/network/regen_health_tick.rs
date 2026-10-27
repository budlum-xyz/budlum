//! The node runtime's regeneration health tick.
//!
//! WIRING: `Node::run` calls [`RegenHealthTick::observe`] once per finality
//! beat, with the node's view of its latest finalized checkpoints. The tick
//! calls [`assess`] and executes the verdict through the reversion ledger.
//!
//! # How live node state maps onto the ledger stages
//!
//! Every stage is trusted only through a post-quantum seal
//! ([`crate::domain::pq_canonical`]):
//!
//! - `Medusa` is the latest finalized checkpoint. The node's own block hash
//!   at that height is the commitment it holds; the canonical commitment is
//!   the checkpoint hash of a certificate whose ML-DSA-65 QC was verified.
//! - `Ephyra` is the latest verified Anchor V2 at or below it. The node holds
//!   the aggregate root it recomputes from its own header archive.
//! - `Polyp` is the latest Root Seal. The commitment is the seal digest.
//!
//! A checkpoint whose canonical commitment carries no seal that anchors its
//! stage and height with a post-quantum family counts as having no canonical
//! commitment at all: a BLS-only certificate, an unsigned snapshot or an
//! unverified anchor is never a source, and the verdict becomes an alarm.
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

use crate::domain::pq_canonical::SealId;
use crate::domain::regen_health::{assess, AlarmReason, HealthPolicy, HealthVerdict};
use crate::domain::regeneration_stage::{
    RegenerationLedger, Reversion, ReversionError, Stage, StageSnapshot, Stress,
};

/// One sealed checkpoint of one stage as the node sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The stage this checkpoint belongs to.
    pub stage: Stage,
    pub height: u64,
    /// The commitment the node holds for this stage and height, if any.
    pub local: Option<[u8; 32]>,
    /// The canonical commitment from the post-quantum source, if any.
    pub canonical: Option<[u8; 32]>,
    /// The seal behind `canonical`. Without a seal that anchors this stage
    /// and height through a post-quantum family, `canonical` is ignored.
    pub seal: Option<SealId>,
}

/// The checkpoints one tick looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointView {
    /// Height of the latest finalized checkpoint. Zero means nothing is
    /// finalized yet.
    pub live: u64,
    /// Height of the latest verified anchor at or below `live` (Ephyra).
    pub previous: Option<u64>,
    /// Height of the latest Root Seal (Polyp).
    pub polyp: Option<u64>,
    /// Every checkpoint the node fetched for this tick: at least `live`,
    /// `previous`, `polyp` and [`RegenHealthTick::held_stage`] at
    /// [`RegenHealthTick::held_height`].
    pub checkpoints: Vec<Checkpoint>,
}

impl CheckpointView {
    fn at(&self, stage: Stage, height: u64) -> Option<&Checkpoint> {
        self.checkpoints
            .iter()
            .find(|c| c.stage == stage && c.height == height)
    }

    /// The canonical commitment, only when a post-quantum seal of this stage
    /// and height stands behind it.
    fn canonical(&self, stage: Stage, height: u64) -> Option<[u8; 32]> {
        let checkpoint = self.at(stage, height)?;
        let sealed = checkpoint
            .seal
            .as_ref()
            .is_some_and(|seal| seal.anchors(stage, height));
        if sealed {
            checkpoint.canonical
        } else {
            None
        }
    }

    fn seal(&self, stage: Stage, height: u64) -> Option<SealId> {
        self.at(stage, height).and_then(|c| c.seal.clone())
    }

    /// The height a stage holds a snapshot at, only when a sealed canonical
    /// commitment stands behind it. A stage whose seal the quantum alarm took
    /// away has no height, so `cheapest_target` descends past it to the next
    /// safe seal.
    fn stage_height(&self, stage: Stage) -> Option<u64> {
        let height = match stage {
            Stage::Medusa => Some(self.live),
            Stage::Ephyra => self.previous,
            Stage::Polyp => self.polyp,
        }?;
        if stage == Stage::Medusa || self.canonical(stage, height).is_some() {
            Some(height)
        } else {
            None
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

    /// The stage the ledger holds, the stage of [`Self::held_height`].
    #[must_use]
    pub fn held_stage(&self) -> Stage {
        self.ledger.stage
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
            let live = view.at(Stage::Medusa, view.live).and_then(|c| c.local);
            self.ledger.height = view.live;
            self.ledger.commitment = live.unwrap_or_default();
        } else if let Some(next) = self.ledger.stage.later() {
            // A reverted stage grows back one stage at a time, and only when
            // the node's own block at that checkpoint is canonical.
            let local = view
                .stage_height(next)
                .and_then(|height| view.at(next, height))
                .and_then(|c| c.local.map(|local| (c.height, local)));
            if let Some((height, commitment)) = local {
                let snapshot = StageSnapshot {
                    stage: next,
                    height,
                    commitment,
                    carried: Default::default(),
                    seal: view.seal(next, height),
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
            .saturating_sub(view.previous.or(view.polyp).unwrap_or(0));
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
            view.at(Stage::Medusa, view.live).and_then(|c| c.local),
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
            HealthVerdict::RevertTo { mut target, stress } => {
                // `assess` knows commitments only; the seal is the source's.
                target.seal = view.seal(target.stage, target.height);
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
    use crate::crypto::scheme::SchemeId;
    use crate::domain::pq_canonical::{test_seal, SealKind};
    use crate::domain::regeneration_stage::ReversionPolicy;

    const INTERVAL: u64 = 100;

    fn hash_of(height: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&height.to_le_bytes());
        h[31] = 0xC0;
        h
    }

    fn honest_at(stage: Stage, height: u64) -> Checkpoint {
        Checkpoint {
            stage,
            height,
            local: Some(hash_of(height)),
            canonical: Some(hash_of(height)),
            seal: Some(test_seal(stage, height)),
        }
    }

    fn honest(height: u64) -> Checkpoint {
        honest_at(Stage::Medusa, height)
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
            polyp: None,
            checkpoints: vec![live_cp, honest_at(Stage::Ephyra, previous)],
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
    fn a_bls_only_certificate_is_no_canonical_source() {
        // The checkpoint matches nothing the node holds, and its only seal is
        // the BLS certificate: the tick must alarm, not repair or revert to it.
        let mut tick = RegenHealthTick::default();
        let live = Checkpoint {
            seal: Some(SealId::new(
                SealKind::FinalityQc,
                2000,
                &[SchemeId::BLS12381_MINSIG],
            )),
            ..diverged(2000)
        };
        match tick.observe(&view(live)) {
            TickOutcome::Alarm { reason, .. } => {
                assert_eq!(reason.kind(), "regen-alarm-no-canonical-source");
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
        assert!(tick.ledger.reversion_events.is_empty());
    }

    #[test]
    fn an_unsealed_snapshot_is_no_canonical_source() {
        let mut tick = RegenHealthTick::default();
        let live = Checkpoint {
            seal: None,
            ..diverged(2000)
        };
        assert!(matches!(
            tick.observe(&view(live)),
            TickOutcome::Alarm { .. }
        ));
        // Even a healthy-looking view is not signed off without a seal.
        let mut tick = RegenHealthTick::default();
        let unsealed = Checkpoint {
            seal: None,
            ..honest(300)
        };
        assert!(matches!(
            tick.observe(&view(unsealed)),
            TickOutcome::Alarm { .. }
        ));
    }

    #[test]
    fn a_forged_anchor_target_is_refused() {
        // The live checkpoint diverged, so the tick wants to revert to the
        // Ephyra anchor. That anchor's seal names another height: it does not
        // anchor this stage and height, so the target has no canonical source
        // and the ledger never moves.
        let mut tick = RegenHealthTick::default();
        let forged_anchor = Checkpoint {
            seal: Some(test_seal(Stage::Ephyra, 1)),
            ..honest_at(Stage::Ephyra, 1900)
        };
        let view = CheckpointView {
            live: 2000,
            previous: Some(1900),
            polyp: None,
            checkpoints: vec![diverged(2000), forged_anchor],
        };
        let outcome = tick.observe(&view);
        assert!(
            !matches!(outcome, TickOutcome::Reverted(_)),
            "a forged anchor must not be a reversion target, got {outcome:?}"
        );
        assert_eq!(tick.ledger.stage, Stage::Medusa);
        assert!(tick.ledger.reversion_events.is_empty());
    }

    #[test]
    fn a_dead_anchor_seal_makes_the_tick_descend_to_the_root_seal() {
        // Damage that the Ephyra anchor would normally clear. A lattice break
        // took the anchor's family away, so the observation carries no seal for
        // it and the tick reverts two stages, to the root seal.
        let mut tick = RegenHealthTick::default();
        let dead_anchor = Checkpoint {
            canonical: None,
            seal: None,
            ..honest_at(Stage::Ephyra, 1900)
        };
        let view = CheckpointView {
            live: 2000,
            previous: Some(1900),
            polyp: Some(1800),
            checkpoints: vec![diverged(2000), dead_anchor, honest_at(Stage::Polyp, 1800)],
        };
        // The Polyp snapshot is two stages down: the default policy allows two
        // stages per event.
        match tick.observe(&view) {
            TickOutcome::Reverted(reversion) => {
                assert_eq!(reversion.to, Stage::Polyp);
                assert_eq!(reversion.height_after, 1800);
            }
            other => panic!("expected the descent to the root seal, got {other:?}"),
        }
    }

    #[test]
    fn the_root_seal_is_the_polyp_target_of_a_full_reversion() {
        let mut tick = RegenHealthTick::default();
        // No anchor is held, so only the Polyp seal can clear the damage.
        let view = CheckpointView {
            live: 2000,
            previous: None,
            polyp: Some(1900),
            checkpoints: vec![diverged(2000), honest_at(Stage::Polyp, 1900)],
        };
        match tick.observe(&view) {
            TickOutcome::Reverted(reversion) => {
                assert_eq!(reversion.to, Stage::Polyp);
                assert_eq!(reversion.height_after, 1900);
            }
            other => panic!("expected a reversion to the root seal, got {other:?}"),
        }
    }

    #[test]
    fn hash32_accepts_only_32_byte_hex() {
        assert_eq!(hash32(&"ab".repeat(32)), Some([0xAB; 32]));
        assert_eq!(hash32("ab"), None);
        assert_eq!(hash32("zz"), None);
    }
}
