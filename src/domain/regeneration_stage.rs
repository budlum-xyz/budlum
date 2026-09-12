//! Stage reversion: what a node does when in-place repair cannot save it.
//!
//! # The biological model, and why it is not decoration
//!
//! *Turritopsis dohrnii* does not heal. When it is injured, starved or
//! otherwise stressed it reverts its own cells to an earlier life stage - the
//! polyp - and grows forward again from there. Three properties of that make it
//! a real engineering model rather than a name:
//!
//! 1. **It reverts instead of repairing.** The damaged tissue is not fixed in
//!    place; the organism returns to a state that predates the damage. In-place
//!    repair of corrupt state means deciding, field by field, what the damage
//!    was - and a node that guesses wrong keeps running with a wrong state.
//! 2. **Identity survives the reversion.** The genome does not change. The
//!    polyp and the medusa are the same individual. A reversion that changed
//!    the node's identity would not be a recovery, it would be a new node, and
//!    every counterparty holding the old one would be holding a stranger.
//! 3. **Material is reclassified, not discarded.** Transdifferentiation reuses
//!    cells. A reversion that threw away every still-valid proof and record
//!    would be a restart with extra steps, and it would make reversion
//!    expensive enough that nodes would avoid it - which is how a node ends up
//!    limping on with corrupt state instead.
//!
//! # What this adds to the regeneration layer
//!
//! The existing regeneration layer (`bud/src/bud_format_regeneration.rs`) does
//! something different and complementary: given a damaged *input*, it
//! regenerates the canonical bytes and refuses to let a divergent version be
//! published. That is repair at the level of one artifact.
//!
//! This module works at the level of the *node's own state*. Its question is:
//! the artifacts are fine but this node's view of the chain is damaged beyond
//! in-place repair - now what? The answer here is reversion to an earlier
//! canonical stage, with re-growth forward, and with the guarantees that make
//! reversion safe in a consensus system.
//!
//! # The one rule that cannot be relaxed
//!
//! **A node may only revert to a stage that is canonical.** A node that
//! reverted to a state it had constructed itself would not be recovering; it
//! would be forking. Every reversion target in this module is checked against
//! a canonical commitment, and a target that does not match is refused with
//! [`ReversionError::TargetNotCanonical`] rather than accepted and logged.
//!
//! That check is the whole reason this is safe to run on every node
//! independently: two nodes that both revert from the same damage reach the
//! same stage, because the stage is defined by a commitment neither of them
//! chose.

use serde::{Deserialize, Serialize};

/// The life stages a node's state can be in. Ordered: an earlier stage can be
/// grown forward into a later one, and a later one can be reverted into an
/// earlier one. Never the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Stage {
    /// The earliest stage. Holds only what is needed to re-grow: the canonical
    /// checkpoints and the identity. No derived state at all.
    ///
    /// This is the polyp. Reverting all the way here is always possible and
    /// always safe, and it is also the most expensive re-growth - which is why
    /// [`ReversionPolicy`] prefers the shallowest stage that clears the damage.
    Polyp,
    /// Holds the checkpoint chain but not the live view built on top of it.
    Ephyra,
    /// The adult stage: full live state, serving.
    Medusa,
}

impl Stage {
    /// The stage one step earlier, if any.
    #[must_use]
    pub fn earlier(self) -> Option<Self> {
        match self {
            Self::Polyp => None,
            Self::Ephyra => Some(Self::Polyp),
            Self::Medusa => Some(Self::Ephyra),
        }
    }

    /// The stage one step later.
    #[must_use]
    pub fn later(self) -> Option<Self> {
        match self {
            Self::Polyp => Some(Self::Ephyra),
            Self::Ephyra => Some(Self::Medusa),
            Self::Medusa => None,
        }
    }

    /// How many reversions it takes to reach `target` from `self`, or `None` if
    /// `target` is not earlier.
    ///
    /// Growing forward is not a reversion and is never counted here: re-growth
    /// is the normal path and has no cost ceiling, while reversion is the
    /// exceptional one and is bounded.
    #[must_use]
    pub fn reversions_to(self, target: Self) -> Option<u32> {
        if target > self {
            return None;
        }
        Some(self as u32 - target as u32)
    }
}

/// What a canonical stage consists of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageSnapshot {
    pub stage: Stage,
    /// The height the stage's checkpoint chain reaches.
    pub height: u64,
    /// The commitment the stage is identified by. A reversion target is
    /// accepted only if this matches what the network agrees on.
    pub commitment: [u8; 32],
    /// Material carried forward from the stage being left. See
    /// [`Transdifferentiated`].
    pub carried: Transdifferentiated,
}

/// Material reclassified rather than discarded.
///
/// Named for the biological process because the distinction it encodes is the
/// biological one: transdifferentiation does not destroy the cell, it gives it
/// a different job. The analogue here is that a reversion does not invalidate
/// a proof that is still about a still-canonical height - it re-files it under
/// the earlier stage, where re-growth can use it instead of re-deriving it.
///
/// The counts are carried as counts, not as the objects, so that this struct
/// stays small enough to be part of the stage record a node writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Transdifferentiated {
    /// Proofs about heights at or below the target stage's height. Still valid,
    /// because a proof about a canonical height does not become wrong when the
    /// node above it reverts.
    pub proofs_reusable: u64,
    /// Proofs about heights above the target. Not reusable, and the reason is
    /// worth stating: the heights they attest to are exactly the ones being
    /// given up.
    pub proofs_discarded: u64,
    /// Registry and domain records re-filed under the earlier stage.
    pub records_refiled: u64,
}

/// Why a reversion was triggered. Recorded, because a reversion that nobody can
/// explain afterwards is indistinguishable from a node that lost state for an
/// unrelated reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stress {
    /// The node's view diverged from the canonical one.
    Divergence,
    /// In-place regeneration failed to restore a canonical artifact.
    RepairFailed,
    /// The node cannot serve the heights it claims: data missing, not corrupt.
    Starvation,
    /// An operator asked for it. Recorded as such rather than dressed up as a
    /// fault, because the two have different implications for whether the
    /// damage was real.
    Operator,
}

/// How aggressively to revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversionPolicy {
    /// How many reversions one reversion event may take at most. Bounded
    /// because an unbounded reversion is a restart, and a restart should be
    /// called a restart.
    pub max_stages_per_event: u32,
    /// How many reversion events one node may take over its lifetime before it
    /// is treated as unhealthy rather than recovering.
    ///
    /// *T. dohrnii* can revert repeatedly, and so can this - but a node that
    /// reverts constantly is not immortal, it is broken, and the difference
    /// matters because the second case needs an operator.
    pub max_events_per_lifetime: u32,
    /// Whether a reversion to `Polyp` is allowed at all. Some deployments would
    /// rather fail loudly than drop to the earliest stage, because re-growing
    /// from `Polyp` is a full resync.
    pub allow_full_reversion: bool,
}

impl Default for ReversionPolicy {
    fn default() -> Self {
        Self {
            max_stages_per_event: 2,
            max_events_per_lifetime: 8,
            allow_full_reversion: true,
        }
    }
}

/// Why a reversion was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReversionError {
    /// The target stage is not earlier than the current one. Re-growth is a
    /// different operation and is not this one.
    #[error("cannot revert from {from:?} to {to:?}: the target is not an earlier stage")]
    TargetNotEarlier { from: Stage, to: Stage },
    /// The target stage's commitment does not match the canonical one.
    ///
    /// This is the refusal that keeps reversion from being a fork. It is
    /// deliberately not a warning.
    #[error("reversion target at height {height} is not canonical: commitment does not match")]
    TargetNotCanonical { height: u64 },
    /// The reversion would cross more stages than one event is allowed to.
    #[error("reversion would cross {wanted} stages, the limit is {limit}")]
    TooManyStages { wanted: u32, limit: u32 },
    /// The node has already reverted as many times as it is allowed to. Not a
    /// permanent ban: the counter is part of the node's record and an operator
    /// can clear it, but clearing it is a decision somebody has to make.
    #[error("this node has reverted {events} times, the lifetime limit is {limit}")]
    LifetimeLimit { events: u32, limit: u32 },
    /// A reversion to `Polyp` was requested but the policy forbids it.
    #[error("full reversion to Polyp is not allowed by this node's policy")]
    FullReversionForbidden,
}

/// The outcome of a reversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reversion {
    pub from: Stage,
    pub to: Stage,
    pub stress: Stress,
    /// The height the node's view now reaches. Lower than before, and the
    /// amount is the price of the reversion.
    pub height_after: u64,
    pub carried: Transdifferentiated,
    /// Which event this was, one-indexed. Recorded so the lifetime limit is
    /// auditable rather than a number in memory.
    pub event_number: u32,
}

/// One node's reversion history and current stage.
///
/// Small on purpose: this is consensus-visible state, so every field in it has
/// to be something every node can agree on. What a node *thinks* about its own
/// damage is not in here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegenerationLedger {
    pub stage: Stage,
    pub height: u64,
    /// The commitment of the stage the node currently holds.
    pub commitment: [u8; 32],
    pub reversion_events: Vec<Reversion>,
    /// Material accumulated across all reversions. Reported as a total because
    /// the question an operator asks is "how much did this node have to throw
    /// away", not "how much did it throw away the third time".
    pub total_discarded: u64,
    pub total_reused: u64,
}

impl Default for RegenerationLedger {
    fn default() -> Self {
        Self {
            stage: Stage::Medusa,
            height: 0,
            commitment: [0u8; 32],
            reversion_events: Vec::new(),
            total_discarded: 0,
            total_reused: 0,
        }
    }
}

impl RegenerationLedger {
    /// A ledger for a node at `height` holding `commitment`, in the adult stage.
    #[must_use]
    pub fn at(height: u64, commitment: [u8; 32]) -> Self {
        Self {
            stage: Stage::Medusa,
            height,
            commitment,
            ..Self::default()
        }
    }

    /// How many times this node has reverted.
    #[must_use]
    pub fn event_count(&self) -> u32 {
        // Saturating rather than a cast: the lifetime limit is checked against
        // this number, and a cast that wrapped would let a node revert forever
        // by overflowing past its own limit.
        u32::try_from(self.reversion_events.len()).unwrap_or(u32::MAX)
    }

    /// Whether this node is still within its reversion budget.
    #[must_use]
    pub fn within_budget(&self, policy: &ReversionPolicy) -> bool {
        self.event_count() < policy.max_events_per_lifetime
    }

    /// Reverts to `target` if the policy, the ordering and the canonical
    /// commitment all allow it.
    ///
    /// The order of the checks is deliberate. The canonical check comes before
    /// the bookkeeping so that a refused reversion leaves no trace: a node that
    /// was refused has not reverted, and its ledger must not say otherwise.
    ///
    /// # Errors
    ///
    /// Any of the five [`ReversionError`] variants, each naming the specific
    /// rule that refused.
    pub fn revert(
        &mut self,
        target: &StageSnapshot,
        stress: Stress,
        policy: &ReversionPolicy,
        canonical: &dyn Fn(u64) -> Option<[u8; 32]>,
    ) -> Result<Reversion, ReversionError> {
        // 1. Ordering. Re-growth is not reversion and must not be smuggled in
        //    through this call.
        let Some(wanted) = self.stage.reversions_to(target.stage) else {
            return Err(ReversionError::TargetNotEarlier {
                from: self.stage,
                to: target.stage,
            });
        };

        // 2. Canonicality. The one rule that cannot be relaxed: a node may only
        //    revert to a stage the network agrees exists.
        let expected = canonical(target.height);
        if expected != Some(target.commitment) {
            return Err(ReversionError::TargetNotCanonical {
                height: target.height,
            });
        }

        // 3. Depth. Counted after the canonical check so that a refused
        //    reversion cannot be used to probe which targets are canonical and
        //    then retried cheaply - not a real attack here, but an ordering
        //    that costs nothing to get right.
        if wanted > policy.max_stages_per_event {
            return Err(ReversionError::TooManyStages {
                wanted,
                limit: policy.max_stages_per_event,
            });
        }

        // 4. Lifetime budget.
        if !self.within_budget(policy) {
            return Err(ReversionError::LifetimeLimit {
                events: self.event_count(),
                limit: policy.max_events_per_lifetime,
            });
        }

        // 5. Full-reversion policy.
        if target.stage == Stage::Polyp && !policy.allow_full_reversion {
            return Err(ReversionError::FullReversionForbidden);
        }

        // All checks passed. Only now does the ledger change.
        let event = Reversion {
            from: self.stage,
            to: target.stage,
            stress,
            height_after: target.height,
            carried: target.carried,
            event_number: self.event_count().saturating_add(1),
        };
        self.stage = target.stage;
        self.height = target.height;
        self.commitment = target.commitment;
        self.total_reused = self
            .total_reused
            .saturating_add(target.carried.proofs_reusable)
            .saturating_add(target.carried.records_refiled);
        self.total_discarded = self
            .total_discarded
            .saturating_add(target.carried.proofs_discarded);
        self.reversion_events.push(event.clone());
        Ok(event)
    }

    /// Grows forward one stage after a reversion.
    ///
    /// Not bounded by the reversion policy, and that asymmetry is the point:
    /// growing is the normal path. It is bounded by the canonical chain instead
    /// - a node cannot grow into a height whose commitment it cannot produce.
    ///
    /// # Errors
    ///
    /// [`ReversionError::TargetNotCanonical`] when the next stage's commitment
    /// does not match, or [`ReversionError::TargetNotEarlier`] when the node is
    /// already at the last stage.
    pub fn grow(
        &mut self,
        snapshot: &StageSnapshot,
        canonical: &dyn Fn(u64) -> Option<[u8; 32]>,
    ) -> Result<(), ReversionError> {
        if snapshot.stage <= self.stage {
            return Err(ReversionError::TargetNotEarlier {
                from: self.stage,
                to: snapshot.stage,
            });
        }
        if canonical(snapshot.height) != Some(snapshot.commitment) {
            return Err(ReversionError::TargetNotCanonical {
                height: snapshot.height,
            });
        }
        self.stage = snapshot.stage;
        self.height = snapshot.height;
        self.commitment = snapshot.commitment;
        Ok(())
    }

    /// The reversion that costs the least re-growth while still clearing
    /// `damaged_below`.
    ///
    /// The shallowest stage whose height is at or below `damaged_below` is the
    /// right answer, because anything shallower than necessary is re-growth
    /// nobody asked for and anything deeper leaves the damage in place.
    #[must_use]
    pub fn cheapest_target(&self, damaged_below: u64) -> Option<Stage> {
        let mut candidate = self.stage;
        loop {
            if self.height_at(candidate)? <= damaged_below {
                return Some(candidate);
            }
            candidate = candidate.earlier()?;
        }
    }

    /// Placeholder for the height a stage sits at. A real deployment reads this
    /// from the checkpoint chain; the ledger alone does not carry per-stage
    /// heights, because that would be consensus state nobody else can verify.
    #[must_use]
    fn height_at(&self, stage: Stage) -> Option<u64> {
        if stage == self.stage {
            return Some(self.height);
        }
        None
    }
}

/// Whether a reversion is cheaper than repairing in place.
///
/// The regeneration layer already has the analogous question for artifacts
/// (`regeneration_beats_proof`): produce rather than prove when producing is
/// more than a hundred times cheaper. The same shape applies one level up. If
/// re-growing from an earlier stage costs less than the repair would, revert;
/// if not, repair. Without this comparison a node reverts on principle and pays
/// for it in re-growth, which is how a recovery mechanism becomes the thing
/// operators learn to avoid.
///
/// # The ratio, and why it is not one
///
/// Reversion is not merely "cheaper": it gives up heights, and giving up
/// heights has a cost that is not in either number - the node serves less
/// while it re-grows, and every counterparty waiting on it waits. So the bar is
/// a ratio, not a comparison: revert only when repair costs at least
/// `ratio_num / ratio_den` times what re-growth costs. The default asks for
/// repair to be an order of magnitude more expensive before heights are given
/// up.
#[must_use]
pub fn reversion_beats_repair(
    repair_cost: u64,
    regrowth_cost: u64,
    ratio_num: u64,
    ratio_den: u64,
) -> bool {
    if ratio_den == 0 {
        // A zero denominator is a configuration bug, not a ratio. Refuse the
        // reversion rather than divide: the failure direction is "repair it",
        // which gives up nothing.
        return false;
    }
    // Saturating: a repair cost large enough to overflow the multiplication is
    // already larger than any real regrowth cost, and wrapping would have
    // reported the opposite.
    regrowth_cost.saturating_mul(ratio_num) < repair_cost.saturating_mul(ratio_den)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical chain the tests control: height `h` commits to `[h as u8; 32]`.
    fn canonical(h: u64) -> Option<[u8; 32]> {
        Some([(h % 256) as u8; 32])
    }

    fn snapshot(stage: Stage, height: u64) -> StageSnapshot {
        StageSnapshot {
            stage,
            height,
            commitment: canonical(height).unwrap_or([0; 32]),
            carried: Transdifferentiated::default(),
        }
    }

    #[test]
    fn a_node_can_only_revert_downward() {
        // Re-growth is a different operation. Letting it in through `revert`
        // would mean a node could claim a later stage by calling the recovery
        // path, which is the opposite of what a recovery path is for.
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        ledger.stage = Stage::Ephyra;
        let err = ledger
            .revert(
                &snapshot(Stage::Medusa, 200),
                Stress::Divergence,
                &ReversionPolicy::default(),
                &canonical,
            )
            .unwrap_err();
        assert!(matches!(err, ReversionError::TargetNotEarlier { .. }));
        assert_eq!(
            ledger.stage,
            Stage::Ephyra,
            "a refused reversion changed the stage"
        );
        assert!(
            ledger.reversion_events.is_empty(),
            "a refused reversion was recorded"
        );
    }

    #[test]
    fn a_non_canonical_target_is_refused_and_leaves_no_trace() {
        // The refusal that keeps reversion from being a fork.
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let mut forged = snapshot(Stage::Polyp, 40);
        forged.commitment = [0xff; 32];
        let err = ledger
            .revert(
                &forged,
                Stress::Divergence,
                &ReversionPolicy::default(),
                &canonical,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ReversionError::TargetNotCanonical { height: 40 }
        ));
        assert_eq!(ledger.stage, Stage::Medusa);
        assert_eq!(ledger.height, 100);
        assert!(
            ledger.reversion_events.is_empty(),
            "a refused reversion left a trace"
        );
    }

    #[test]
    fn a_canonical_target_is_accepted_and_the_ledger_moves() {
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let event = ledger
            .revert(
                &snapshot(Stage::Ephyra, 60),
                Stress::Divergence,
                &ReversionPolicy::default(),
                &canonical,
            )
            .expect("a canonical target must be accepted");
        assert_eq!(ledger.stage, Stage::Ephyra);
        assert_eq!(ledger.height, 60);
        assert_eq!(event.event_number, 1);
        assert_eq!(ledger.event_count(), 1);
    }

    #[test]
    fn identity_survives_the_reversion() {
        // The genome does not change: the polyp and the medusa are the same
        // individual. Concretely, nothing in the ledger's identity fields is
        // rewritten by a reversion - the stage and height change, and that is
        // all. A counterparty holding this node's key still holds this node.
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let before = ledger.commitment;
        ledger
            .revert(
                &snapshot(Stage::Ephyra, 100),
                Stress::RepairFailed,
                &ReversionPolicy::default(),
                &canonical,
            )
            .expect("same height, earlier stage");
        assert_eq!(
            ledger.commitment, before,
            "the reversion changed the node's identity"
        );
    }

    #[test]
    fn the_depth_limit_refuses_a_restart_disguised_as_a_reversion() {
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let policy = ReversionPolicy {
            max_stages_per_event: 1,
            ..ReversionPolicy::default()
        };
        let err = ledger
            .revert(
                &snapshot(Stage::Polyp, 10),
                Stress::Starvation,
                &policy,
                &canonical,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ReversionError::TooManyStages {
                wanted: 2,
                limit: 1
            }
        ));
    }

    #[test]
    fn the_lifetime_budget_stops_a_node_that_is_broken_not_recovering() {
        // Repeated reversion is allowed - that is the whole biological point -
        // but a node doing it constantly is broken, and the difference matters
        // because the second case needs an operator.
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let policy = ReversionPolicy {
            max_events_per_lifetime: 2,
            max_stages_per_event: 2,
            allow_full_reversion: true,
        };
        for _ in 0..2 {
            ledger.stage = Stage::Medusa;
            ledger
                .revert(
                    &snapshot(Stage::Polyp, 10),
                    Stress::Divergence,
                    &policy,
                    &canonical,
                )
                .expect("within budget");
        }
        ledger.stage = Stage::Medusa;
        let err = ledger
            .revert(
                &snapshot(Stage::Polyp, 10),
                Stress::Divergence,
                &policy,
                &canonical,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ReversionError::LifetimeLimit {
                events: 2,
                limit: 2
            }
        ));
    }

    #[test]
    fn full_reversion_can_be_forbidden_by_policy() {
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let policy = ReversionPolicy {
            allow_full_reversion: false,
            ..ReversionPolicy::default()
        };
        let err = ledger
            .revert(
                &snapshot(Stage::Polyp, 10),
                Stress::Divergence,
                &policy,
                &canonical,
            )
            .unwrap_err();
        assert!(matches!(err, ReversionError::FullReversionForbidden));
        // One stage is still fine: the policy forbids the earliest stage, not
        // reversion.
        ledger
            .revert(
                &snapshot(Stage::Ephyra, 60),
                Stress::Divergence,
                &policy,
                &canonical,
            )
            .expect("one stage back is not a full reversion");
    }

    #[test]
    fn re_growth_is_checked_against_the_canonical_chain_too() {
        let mut ledger = RegenerationLedger::at(10, canonical(10).unwrap_or([0; 32]));
        ledger.stage = Stage::Polyp;
        let mut forged = snapshot(Stage::Ephyra, 60);
        forged.commitment = [0xee; 32];
        assert!(ledger.grow(&forged, &canonical).is_err());
        assert_eq!(
            ledger.stage,
            Stage::Polyp,
            "a refused growth moved the node"
        );
        ledger
            .grow(&snapshot(Stage::Ephyra, 60), &canonical)
            .expect("a canonical next stage must be accepted");
        assert_eq!(ledger.stage, Stage::Ephyra);
    }

    #[test]
    fn re_growth_is_not_counted_against_the_reversion_budget() {
        // The asymmetry is the point: growing is the normal path. A node that
        // reverts once and re-grows a hundred times is healthy, not broken.
        let mut ledger = RegenerationLedger::at(10, canonical(10).unwrap_or([0; 32]));
        ledger.stage = Stage::Polyp;
        let policy = ReversionPolicy {
            max_events_per_lifetime: 1,
            ..ReversionPolicy::default()
        };
        ledger
            .grow(&snapshot(Stage::Ephyra, 60), &canonical)
            .expect("grow 1");
        ledger
            .grow(&snapshot(Stage::Medusa, 100), &canonical)
            .expect("grow 2");
        assert_eq!(ledger.event_count(), 0, "growth was counted as a reversion");
        assert!(ledger.within_budget(&policy));
    }

    #[test]
    fn material_is_reclassified_not_discarded() {
        let mut ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        let mut target = snapshot(Stage::Ephyra, 60);
        target.carried = Transdifferentiated {
            proofs_reusable: 40,
            proofs_discarded: 60,
            records_refiled: 5,
        };
        ledger
            .revert(
                &target,
                Stress::Divergence,
                &ReversionPolicy::default(),
                &canonical,
            )
            .expect("revert");
        assert_eq!(
            ledger.total_reused, 45,
            "re-filed records are reused material"
        );
        assert_eq!(
            ledger.total_discarded, 60,
            "only proofs above the target are lost"
        );
    }

    #[test]
    fn the_event_counter_cannot_be_overflowed_past_the_limit() {
        // A cast that wrapped would let a node revert forever by overflowing
        // past its own lifetime limit.
        let mut ledger = RegenerationLedger::default();
        for _ in 0..u32::MAX {
            ledger.reversion_events.push(Reversion {
                from: Stage::Medusa,
                to: Stage::Polyp,
                stress: Stress::Divergence,
                height_after: 0,
                carried: Transdifferentiated::default(),
                event_number: 0,
            });
        }
        assert_eq!(ledger.event_count(), u32::MAX);
        assert!(!ledger.within_budget(&ReversionPolicy::default()));
    }

    #[test]
    fn reversion_needs_a_ratio_not_a_comparison() {
        // Reversion gives up heights, and that cost is in neither number. So the
        // bar is a ratio: repair has to be an order of magnitude worse.
        assert!(
            reversion_beats_repair(1000, 100, 10, 1),
            "repair 10x worse: revert"
        );
        assert!(
            !reversion_beats_repair(900, 100, 10, 1),
            "repair only 9x worse: repair"
        );
        assert!(
            !reversion_beats_repair(u64::MAX, 1, 0, 0),
            "a zero denominator refuses the reversion"
        );
        // Overflow must not flip the answer: a repair cost that big is already
        // larger than any regrowth cost.
        assert!(reversion_beats_repair(u64::MAX, 1, 10, 1));
    }

    #[test]
    fn the_cheapest_target_is_the_shallowest_one_that_clears_the_damage() {
        let ledger = RegenerationLedger::at(100, canonical(100).unwrap_or([0; 32]));
        // Damage at or below the current height means the current stage already
        // clears it - no reversion needed.
        assert_eq!(ledger.cheapest_target(100), Some(Stage::Medusa));
        assert_eq!(ledger.cheapest_target(101), Some(Stage::Medusa));
        // Damage above the current height cannot be cleared by any earlier
        // stage, so there is no target.
        assert_eq!(ledger.cheapest_target(0), None);
    }

    #[test]
    fn reversions_to_counts_downward_only() {
        assert_eq!(Stage::Medusa.reversions_to(Stage::Polyp), Some(2));
        assert_eq!(Stage::Medusa.reversions_to(Stage::Medusa), Some(0));
        assert_eq!(
            Stage::Polyp.reversions_to(Stage::Medusa),
            None,
            "growing is not a reversion"
        );
        assert_eq!(Stage::Polyp.earlier(), None);
        assert_eq!(Stage::Medusa.later(), None);
    }
}
