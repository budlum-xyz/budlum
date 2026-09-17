//! The node-health layer: the caller that decides *when* a node reverts.
//!
//! WIRING: unwired - the production caller is the node runtime's health tick
//! (per-block `assess` plus verdict execution through the ledger). Until that tick lands, the rules are pinned by this file's
//! tests, the chaos acceptance suite, and the `regen-health-door` gate.
//!
//! `regeneration_stage` holds the reversion ledger and every rule that makes
//! reversion safe, and it said so in its own header: the ledger is driven by
//! a node-health layer that did not exist. This module is that layer. It owns
//! exactly one decision class — given what the node currently holds and what
//! the network agrees is canonical, is the node healthy, is repair worth
//! trying, must it revert, or must a human hear about it — and it executes
//! nothing. Execution (the actual reversion and re-growth) stays with the
//! ledger, because a layer that both decides and executes is a layer whose
//! decision cannot be reviewed without trusting its hands.
//!
//! # What an assessment looks at, and in what order
//!
//! The order is substance. Each earlier class rules out the later ones:
//!
//! 1. **Audit-trail integrity** ([`RegenerationLedger::validate`]). A ledger
//!    whose own history does not recompute cannot be trusted to choose a
//!    reversion: whatever damaged the node damaged its memory of damage too.
//!    The shallowest honest answer is a full reversion, subject to policy.
//! 2. **Canonicality of the current view.** The node's (stage, height,
//!    commitment) is checked against the network-agreed source. A mismatch is
//!    a divergence; recovery means reverting to the cheapest stage at or
//!    below the damage window, chosen by
//!    [`RegenerationLedger::cheapest_target`] — never deeper than the damage,
//!    never shallower than needed.
//! 3. **Economics** ([`reversion_beats_repair`]). Reversion that costs more
//!    than repair is a recovery mechanism operators learn to avoid, and a
//!    mechanism operators avoid does not recover anything. When repair is
//!    cheaper per the configured ratio, the verdict is to repair.
//! 4. **Budgets.** A node out of reversion budget or forbidden from a full
//!    reversion is not recovered and not healthy: it is an alarm.
//!
//! # What this layer refuses
//!
//! - It never reverts blind. Damage with no canonical entry for the window is
//!   an [`AlarmReason::NoCanonicalSource`], not a guess at a target.
//! - It never reports healthy a node whose audit trail failed to validate.
//! - It never silently swallows an exhausted budget. A recovery system that
//!   stops without saying so is indistinguishable from one that still works.
//!
//! # The three attack classes it answers
//!
//! Per the 2026-09-17 decision record the hardening targets are state
//! corruption, rogue/incompatible upgrade artifacts, and network-layer
//! tampering. This module answers all three through one observation: each of
//! them ultimately presents as a commitment that diverges from the canonical
//! source — corrupt state recomputes to a wrong commitment, an incompatible
//! artifact fails the regeneration pact upstream and lands here as damage,
//! and a tampered network view cannot match a canonical commitment by
//! construction. The canonicality check is the single tripwire; the verdict
//! ladder is what keeps the response proportionate.

use serde::{Deserialize, Serialize};

use super::regeneration_stage::{
    reversion_beats_repair, RegenerationLedger, ReversionPolicy, Stage, StageSnapshot, Stress,
};

/// Why a human must hear about this node instead of the node healing itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlarmReason {
    /// The reversion ledger failed to validate: its audit trail does not
    /// recompute. Nobody may trust its own choices of a target blindly, and a
    /// full reversion was either forbidden by policy or outside the budget.
    AuditTrailCorrupt {
        /// The rule `validate` named. Owned: a serialized verdict travels
        /// without the process that produced it.
        rule: String,
    },
    /// Damage was detected but the canonical source has no entry for the
    /// window. Reverting without a canonical target is forking.
    NoCanonicalSource {
        /// The height whose commitment could not be sourced.
        height: u64,
    },
    /// The node has spent its lifetime reversion budget.
    ReversionBudgetExhausted {
        /// How many reversion events have been recorded.
        events: u32,
        /// The policy's limit.
        limit: u32,
    },
    /// Only a full (Polyp) reversion could clear the damage, and the policy
    /// forbids full reversions.
    FullReversionForbidden {
        /// The height below which damage reaches.
        damaged_below: u64,
    },
}

impl AlarmReason {
    /// A stable label, for alerting pipelines and audits.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuditTrailCorrupt { .. } => "regen-alarm-audit-trail-corrupt",
            Self::NoCanonicalSource { .. } => "regen-alarm-no-canonical-source",
            Self::ReversionBudgetExhausted { .. } => "regen-alarm-budget-exhausted",
            Self::FullReversionForbidden { .. } => "regen-alarm-full-reversion-forbidden",
        }
    }
}

/// The health layer's answer for one assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthVerdict {
    /// The node's audit trail recomputes and its current view matches the
    /// canonical source. Nothing to do; doing anything here would be churn.
    Healthy,
    /// Damage exists but repair is cheaper than reversion by the configured
    /// ratio. Recorded rather than executed — the repair path is the
    /// artifact-level regeneration layer, not this module.
    RepairRecommended {
        /// Which stress class the assessment observed.
        stress: Stress,
        /// The repair cost the caller estimated.
        repair_cost: u64,
        /// The re-growth cost the caller estimated.
        regrowth_cost: u64,
    },
    /// The node must revert to this stage snapshot under this stress class.
    /// Execution belongs to the ledger; this verdict is the instruction,
    /// not the reversion. The executor's honest choice:
    /// [`RegenerationLedger::revert`] when the audit trail validates, and
    /// [`RegenerationLedger::revert_after_forgery`] when it does not - the
    /// ledger refuses to have those two reversed.
    RevertTo {
        /// The target snapshot. Already checked to be at or below the damage
        /// window and reachable within the policy's stage depth.
        target: StageSnapshot,
        /// Why.
        stress: Stress,
    },
    /// Self-recovery is impossible or unsafe. A human hears about it with a
    /// machine-readable reason, never with a shrug.
    Alarm {
        /// Why this cannot be healed in place.
        reason: AlarmReason,
        /// The stress class the assessment observed, if one was identified.
        stress: Option<Stress>,
    },
}

/// The health layer's tunables, kept separate from the reversion policy: the
/// ledger's policy says what a reversion may do once decided; this says how
/// the decision itself is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthPolicy {
    /// The ledger-side reversion policy, handed through unchanged.
    pub reversion: ReversionPolicy,
    /// Repair must be at least this many times costlier than re-growth
    /// (numerator over denominator) before a reversion is chosen. See
    /// [`reversion_beats_repair`] for why a sub-unit ratio is a configuration
    /// bug rather than a threshold.
    pub repair_ratio_num: u64,
    /// Denominator of the repair-vs-regrowth ratio.
    pub repair_ratio_den: u64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            reversion: ReversionPolicy::default(),
            // Revert only when repair is an order of magnitude costlier than
            // re-growing the heights given up.
            repair_ratio_num: 10,
            repair_ratio_den: 1,
        }
    }
}

/// Assesses one node's health against the network-agreed canonical source.
///
/// The two closures are the module's only window onto the world, and are
/// closures (not trait objects with networking behind them) so that every
/// test of this layer behaves deterministically and the production caller is
/// forced to state its source explicitly:
///
/// - `canonical(stage, height)` returns the network-agreed commitment for a
///   stage height, or `None` when the source has nothing for it. `None` is
///   not an error to skip past; it is the difference between "verifiably
///   canonical" and "unverifiable", and unverifiable is never signed off.
/// - `stage_height(stage)` returns the height at which the node holds a
///   snapshot of that stage, feeding
///   [`RegenerationLedger::cheapest_target`].
///
/// `repair_cost` and `regrowth_cost` are the caller's estimates for this
/// damage event; the health layer owns no cost model of its own, because a
/// cost model that lived here would quietly become policy nobody reads.
#[must_use]
pub fn assess(
    ledger: &RegenerationLedger,
    policy: &HealthPolicy,
    canonical: &dyn Fn(Stage, u64) -> Option<[u8; 32]>,
    stage_height: &dyn Fn(Stage) -> Option<u64>,
    repair_cost: u64,
    regrowth_cost: u64,
) -> HealthVerdict {
    // 1. Audit-trail integrity. A corrupted ledger can only be trusted to
    //    revert as far as recovery admits: damage provenance is unknown, so
    //    the damage window is everything.
    if let Err(rule) = ledger.validate() {
        if !ledger.within_budget(&policy.reversion) {
            return HealthVerdict::Alarm {
                reason: AlarmReason::ReversionBudgetExhausted {
                    events: ledger.event_count(),
                    limit: policy.reversion.max_events_per_lifetime,
                },
                stress: Some(Stress::RepairFailed),
            };
        }
        if !policy.reversion.allow_full_reversion {
            return HealthVerdict::Alarm {
                reason: AlarmReason::AuditTrailCorrupt {
                    rule: rule.to_string(),
                },
                stress: Some(Stress::RepairFailed),
            };
        }
        // Full reversion is the only honest move against an unknown damage
        // window. The target snapshot still has to exist and be canonical at
        // execution time; the ledger enforces that in `revert`.
        let Some(polyp_height) = stage_height(Stage::Polyp) else {
            return HealthVerdict::Alarm {
                reason: AlarmReason::NoCanonicalSource { height: 0 },
                stress: Some(Stress::RepairFailed),
            };
        };
        let Some(commitment) = canonical(Stage::Polyp, polyp_height) else {
            // Never issue a target the canonical source cannot vouch for:
            // a zero-filled stand-in would be a fork, not a recovery.
            return HealthVerdict::Alarm {
                reason: AlarmReason::NoCanonicalSource {
                    height: polyp_height,
                },
                stress: Some(Stress::RepairFailed),
            };
        };
        return HealthVerdict::RevertTo {
            target: StageSnapshot {
                stage: Stage::Polyp,
                height: polyp_height,
                commitment,
                carried: Default::default(),
            },
            stress: Stress::RepairFailed,
        };
    }

    // 2. Canonicality of the current view.
    let Some(expected) = canonical(ledger.stage, ledger.height) else {
        return HealthVerdict::Alarm {
            reason: AlarmReason::NoCanonicalSource {
                height: ledger.height,
            },
            stress: None,
        };
    };
    if expected == ledger.commitment {
        return HealthVerdict::Healthy;
    }

    // Divergence. The damage window is everything from this height down,
    // because a wrong commitment at this height means the view at this height
    // is wrong; the point wrongness entered below it is not knowable from
    // here, only bounded.
    let stress = Stress::Divergence;
    let Some(damaged_below) = ledger.height.checked_sub(1) else {
        // Height zero diverging from the canonical source means the node was
        // never on the canonical line at all: no reversion can help, the
        // birth itself was wrong.
        return HealthVerdict::Alarm {
            reason: AlarmReason::NoCanonicalSource { height: 0 },
            stress: Some(stress),
        };
    };
    let Some(target_stage) = ledger.cheapest_target(damaged_below, stage_height) else {
        return HealthVerdict::Alarm {
            reason: AlarmReason::FullReversionForbidden { damaged_below },
            stress: Some(stress),
        };
    };
    let Some(target_height) = stage_height(target_stage) else {
        // cheapest_target only returns stages the closure answers for, so
        // this arm is unreachable in practice; returning an alarm rather than
        // unwrapping keeps that property load-bearing.
        return HealthVerdict::Alarm {
            reason: AlarmReason::NoCanonicalSource {
                height: damaged_below,
            },
            stress: Some(stress),
        };
    };
    // The ledger would refuse a Polyp target the policy forbids; the health
    // layer must not even issue the instruction.
    if target_stage == Stage::Polyp && !policy.reversion.allow_full_reversion {
        return HealthVerdict::Alarm {
            reason: AlarmReason::FullReversionForbidden { damaged_below },
            stress: Some(stress),
        };
    }
    if !ledger.within_budget(&policy.reversion) {
        return HealthVerdict::Alarm {
            reason: AlarmReason::ReversionBudgetExhausted {
                events: ledger.event_count(),
                limit: policy.reversion.max_events_per_lifetime,
            },
            stress: Some(stress),
        };
    }

    // 3. Economics, deliberately after the target is known: a cheap repair
    //    that does not exist for this damage must not be recommended. Only a
    //    converged decision gets priced.
    if !reversion_beats_repair(
        repair_cost,
        regrowth_cost,
        policy.repair_ratio_num,
        policy.repair_ratio_den,
    ) {
        return HealthVerdict::RepairRecommended {
            stress,
            repair_cost,
            regrowth_cost,
        };
    }

    // 4. The converged verdict. Target commitment supplied by the canonical
    //    source: if the source knows nothing for it, the request cannot be
    //    issued as a reversion (the target would fork).
    let Some(target_commitment) = canonical(target_stage, target_height) else {
        return HealthVerdict::Alarm {
            reason: AlarmReason::NoCanonicalSource {
                height: target_height,
            },
            stress: Some(stress),
        };
    };
    HealthVerdict::RevertTo {
        target: StageSnapshot {
            stage: target_stage,
            height: target_height,
            commitment: target_commitment,
            carried: Default::default(),
        },
        stress,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::regeneration_stage::Transdifferentiated;

    const C_POLYP: [u8; 32] = [0xA1; 32];
    const C_EPHYRA: [u8; 32] = [0xB2; 32];
    const C_MEDUSA: [u8; 32] = [0xC3; 32];

    fn canonical(stage: Stage, height: u64) -> Option<[u8; 32]> {
        match (stage, height) {
            (Stage::Polyp, 0) => Some(C_POLYP),
            (Stage::Ephyra, 50) => Some(C_EPHYRA),
            (Stage::Medusa, 100) => Some(C_MEDUSA),
            _ => None,
        }
    }

    fn stage_height(stage: Stage) -> Option<u64> {
        match stage {
            Stage::Polyp => Some(0),
            Stage::Ephyra => Some(50),
            Stage::Medusa => Some(100),
        }
    }

    fn healthy_ledger() -> RegenerationLedger {
        RegenerationLedger::at(100, C_MEDUSA)
    }

    #[test]
    fn an_untampered_adult_is_healthy() {
        let v = assess(
            &healthy_ledger(),
            &HealthPolicy::default(),
            &canonical,
            &stage_height,
            1000,
            10,
        );
        assert_eq!(v, HealthVerdict::Healthy);
    }

    #[test]
    fn divergence_chooses_the_cheapest_stage_below_the_damage() {
        let mut ledger = healthy_ledger();
        ledger.commitment = [0xFF; 32]; // tampered derived view
        let v = assess(
            &ledger,
            &HealthPolicy::default(),
            &canonical,
            &stage_height,
            1000, // repair expensively
            10,   // regrow cheaply
        );
        match v {
            HealthVerdict::RevertTo { target, stress } => {
                assert_eq!(stress, Stress::Divergence);
                assert_eq!(target.stage, Stage::Ephyra);
                assert_eq!(target.height, 50);
                assert_eq!(target.commitment, C_EPHYRA);
            }
            other => panic!("expected RevertTo, got {other:?}"),
        }
    }

    #[test]
    fn cheap_repair_is_recommended_over_unnecessary_reversion() {
        let mut ledger = healthy_ledger();
        ledger.commitment = [0xFF; 32];
        let v = assess(
            &ledger,
            &HealthPolicy::default(),
            &canonical,
            &stage_height,
            10,   // repair cheaper than 10x regrowth
            1000, // regrowth very expensive
        );
        match v {
            HealthVerdict::RepairRecommended {
                stress,
                repair_cost,
                regrowth_cost,
            } => {
                assert_eq!(stress, Stress::Divergence);
                assert_eq!(repair_cost, 10);
                assert_eq!(regrowth_cost, 1000);
            }
            other => panic!("expected RepairRecommended, got {other:?}"),
        }
    }

    #[test]
    fn no_canonical_source_is_an_alarm_never_a_guess() {
        // A ledger at a height the canonical source does not know.
        let ledger = RegenerationLedger::at(200, C_MEDUSA);
        let v = assess(
            &ledger,
            &HealthPolicy::default(),
            &canonical,
            &stage_height,
            1000,
            10,
        );
        match v {
            HealthVerdict::Alarm { reason, .. } => {
                assert_eq!(reason.kind(), "regen-alarm-no-canonical-source");
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
    }

    #[test]
    fn exhausted_budget_alarms_instead_of_silently_stopping() {
        let mut tight = HealthPolicy::default();
        tight.reversion.max_events_per_lifetime = 0;
        let mut ledger = healthy_ledger();
        ledger.commitment = [0xFF; 32];
        let v = assess(&ledger, &tight, &canonical, &stage_height, 1000, 10);
        match v {
            HealthVerdict::Alarm { reason, stress } => {
                assert_eq!(reason.kind(), "regen-alarm-budget-exhausted");
                assert_eq!(stress, Some(Stress::Divergence));
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
    }

    #[test]
    fn corruption_too_deep_for_checkpoints_alarms_when_full_reversion_is_forbidden() {
        let mut policy = HealthPolicy::default();
        policy.reversion.allow_full_reversion = false;
        // Damage at height 1: only the Polyp snapshot (height 0) is below it,
        // and full reversions are forbidden.
        let ledger = RegenerationLedger::at(1, C_EPHYRA);
        // canonical source has no entry at (Ephyra, 1) either; supply one
        // on the fly so canonicality, not sourcing, is what fails.
        let canonical_with_height_one = |stage: Stage, height: u64| -> Option<[u8; 32]> {
            if (stage, height) == (Stage::Medusa, 1) {
                return Some([0xEE; 32]); // differs from the ledger's view
            }
            canonical(stage, height)
        };
        let v = assess(
            &ledger,
            &policy,
            &canonical_with_height_one,
            &stage_height,
            1000,
            10,
        );
        match v {
            HealthVerdict::Alarm { reason, .. } => {
                assert_eq!(reason.kind(), "regen-alarm-full-reversion-forbidden");
            }
            other => panic!("expected Alarm, got {other:?}"),
        }
    }

    #[test]
    fn a_forged_audit_trail_recommends_full_reversion_when_allowed() {
        let mut ledger = healthy_ledger();
        // Forge the history: a reversion event that never happened, so the
        // audit totals no longer recompute... simplest reliable forgery:
        // claim event numbering past what was recorded.
        ledger.stage = Stage::Ephyra;
        ledger.height = 50;
        ledger.commitment = C_EPHYRA;
        ledger.reversion_events.clear();
        // Nothing forged yet; a validator-clean ledger must stay healthy:
        assert!(
            ledger.validate().is_ok(),
            "sanity: consistent ledger validates"
        );

        // Now forge: an inconsistent audit trail via totals that contradict
        // the recorded events.
        let mut forged = ledger.clone();
        forged
            .reversion_events
            .push(crate::domain::regeneration_stage::Reversion {
                from: Stage::Medusa,
                to: Stage::Ephyra,
                stress: Stress::Divergence,
                height_after: 50,
                carried: Transdifferentiated {
                    proofs_reusable: 5,
                    proofs_discarded: 1,
                    records_refiled: 2,
                },
                event_number: 1,
            });
        forged.total_reused = 999; // contradicts carried material
        assert!(forged.validate().is_err(), "forged trail must not validate");
        let v = assess(
            &forged,
            &HealthPolicy::default(),
            &canonical,
            &stage_height,
            1000,
            10,
        );
        match v {
            HealthVerdict::RevertTo { target, stress } => {
                assert_eq!(stress, Stress::RepairFailed);
                assert_eq!(target.stage, Stage::Polyp);
                assert_eq!(target.height, 0);
            }
            other => panic!("expected full-reversion verdict, got {other:?}"),
        }
    }

    #[test]
    fn verdict_kinds_are_stable_labels() {
        assert_eq!(
            AlarmReason::ReversionBudgetExhausted {
                events: 3,
                limit: 4
            }
            .kind(),
            "regen-alarm-budget-exhausted"
        );
        assert_eq!(
            AlarmReason::AuditTrailCorrupt {
                rule: "x".to_string()
            }
            .kind(),
            "regen-alarm-audit-trail-corrupt"
        );
    }
}
