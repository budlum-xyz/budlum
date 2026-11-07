use std::collections::{BTreeMap, BTreeSet};
//! Repair: the repairer side of §6.10.
//!
//! The registry holds what the chain knows - which segments need repair, which
//! shares are lost, and what a `RecordRepair` must satisfy. This module holds
//! the parts that sit beside it and that the chain needs in order to make a
//! repair either happen or cost somebody:
//!
//!   * **assignment** (§6.10 item 3): the repair task for a segment goes to a
//!     Full validator by rendezvous hash, and the task moves to the next
//!     candidate if the assignee has not started within 20 blocks;
//!   * **verification** (§6.10 item 8): every epoch a random 1% of segments are
//!     re-derived from their source symbols and compared with the symbol the
//!     repairer committed to. A mismatch is a proved bad repair;
//!   * **the report** (Bolum 11.7): the mismatch becomes a
//!     [`SlashingReport`] under [`SlashingCondition::BadRepair`], priced by
//!     `RegistryParams::bad_repair_slash_ratio_fixed` at 1%.
//!
//! WIRING: unwired - the same door as the rest of `bud3`. `repairer_at`,
//! `verify` and `bad_repair_report` are called when the block loop takes over
//! repair assignment and the epoch close runs the 1% draw; until then the
//! `bud3-repair-fires` gate holds the shape of the path and the tests here
//! exercise it. `RepairTask` and `Assignment` travel with them.
//!
//! # Why verification is a draw and not a full check
//!
//! Re-deriving a repair symbol costs about as much as decoding the segment it
//! belongs to. Checking every repaired symbol of every segment every epoch
//! would be affordable only if repair were free, and it is not: repair work is
//! paid from the repair and relay pool (§11.4). A 1% draw is enough to make a
//! bad repairer's expected penalty positive while keeping the verification
//! cost at a hundredth of a decode per segment per epoch, and the sample is one
//! the repairer cannot predict, because the seed is consensus state rather
//! than anything the repairer supplies.

use super::custody::symbol_leaf;
use super::fountain::SegmentEncoder;
use super::placement::{rank, segment_key, Candidate, Class};
use super::registry::{Address, Bud3Registry, ObjectKey};
use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::permissionless::SlashingCondition;
use crate::registry::roles;

/// Blocks a repairer has to start before the task moves to the next candidate
/// (§6.10 item 3: an assignee that has not begun within 20 blocks hands the
/// task to the next candidate).
pub const REPAIR_START_DEADLINE_BLOCKS: u64 = 20;

/// One part in `REPAIR_AUDIT_DENOMINATOR` of the repaired segments is
/// re-derived each epoch (§6.10 item 8: a random 1% every epoch).
pub const REPAIR_AUDIT_DENOMINATOR: u64 = 100;

/// A repair task waiting for a repairer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairTask {
    /// The object.
    pub object: ObjectKey,
    /// The segment.
    pub segment: u64,
    /// The block the task formed at.
    pub opened_at: u64,
}

impl RepairTask {
    /// Whether the assignee has run out of time to start (§6.10 item 3).
    #[must_use]
    /// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
    pub const fn is_late(&self, block: u64) -> bool {
        block.saturating_sub(self.opened_at) >= REPAIR_START_DEADLINE_BLOCKS
    }
}

/// One candidate's slice of a repair assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assignment {
    /// The repairer.
    pub repairer: Address,
    /// Its position in the rendezvous order, best first.
    pub place: usize,
}

/// The repairers of `task`, best first.
///
/// Only Full validators are eligible: a Mobile validator can be offline for a
/// week at a time by design and cannot be relied on to decode a segment
/// (§6.10 item 3: a repair task is assigned to a Full validator).
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub fn assign(task: &RepairTask, candidates: &[Candidate]) -> Vec<Assignment> {
    let full: Vec<Candidate> = candidates
        .iter()
        .filter(|c| c.class == Class::Full)
        .copied()
        .collect();
    let key = segment_key(&task.object, task.segment);
    rank(&key, &full)
        .into_iter()
        .enumerate()
        .map(|(place, c)| Assignment {
            repairer: c.validator,
            place,
        })
        .collect()
}

/// The repairer of `task` at `block`: the first candidate in the order that
/// still has time to start.
///
/// `started` reports whether the assignee at a given place has begun. A task
/// whose best candidate has not started within
/// [`REPAIR_START_DEADLINE_BLOCKS`] moves to the next one, and so on down the
/// list; the task is unassigned when every candidate has let its window go by,
/// which is the state an operator has to see rather than one the code retries
/// forever.
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub fn repairer_at(
    task: &RepairTask,
    candidates: &[Candidate],
    block: u64,
    started: impl Fn(Address) -> bool,
) -> Option<Address> {
    let order = assign(task, candidates);
    // The first place is always in time; each later one only comes into play
    // once the place before it has used up its deadline.
    let mut deadline = task.opened_at;
    for assignment in &order {
        if started(assignment.repairer) {
            return Some(assignment.repairer);
        }
        if block < deadline.saturating_add(REPAIR_START_DEADLINE_BLOCKS) {
            // Still inside this candidate's window.
            return Some(assignment.repairer);
        }
        deadline = deadline.saturating_add(REPAIR_START_DEADLINE_BLOCKS);
    }
    None
}

/// Whether the repairer of `task` at `segment` is drawn for verification from
/// `seed` this epoch.
///
/// Deterministic in `(seed, object, segment)` so every node draws the same
/// sample and no repairer can steer it: the seed is the epoch's consensus
/// seed, not anything a repairer supplies.
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub fn audit_drawn(seed: &[u8; 32], object: &ObjectKey, segment: u64) -> bool {
    let h = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_BUD3_REPAIR_AUDIT_V1",
        seed,
        object,
        &segment.to_le_bytes(),
    ]);
    let mut b = [0u8; 8];
    b.copy_from_slice(h.get(..8).unwrap_or(&[0u8; 8]));
    u64::from_le_bytes(b) % REPAIR_AUDIT_DENOMINATOR == 0
}

/// What verification found for one repaired segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// No repair was drawn this epoch.
    NotDrawn,
    /// The drawn repair symbol regenerates from the source symbols.
    Regenerates,
    /// The symbol the repairer committed to does not regenerate. This is the
    /// proved bad repair §6.10 item 8 punishes.
    Mismatch {
        /// The ESI that was re-derived.
        esi: u32,
        /// SHA-256 of the symbol the repairer committed to.
        claimed: [u8; 32],
        /// SHA-256 of the symbol the source symbols produce.
        derived: [u8; 32],
    },
}

/// Verify one repaired segment of `key`.
///
/// `source` must be the segment's source bytes as the holders can supply them;
/// `claimed` is the symbol the repairer committed to, in `(esi, bytes)` form.
/// The check re-derives the same ESI from `source` with the object's own
/// profile and compares digests, so the caller never has to trust a
/// re-derivation the repairer performed.
///
/// # Errors
///
/// Nothing: a segment that cannot be re-coded is a
/// [`Verification::Mismatch`], because from the chain's side "the repairer's
/// symbol does not come out of the source" is the same finding either way. The
/// caller that holds the source keeps the encoder's own error.
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub fn verify(
    seed: &[u8; 32],
    registry: &Bud3Registry,
    object: &ObjectKey,
    segment: u64,
    source: &[u8],
    claimed: (u32, &[u8]),
) -> Verification {
    if !audit_drawn(seed, object, segment) {
        return Verification::NotDrawn;
    }
    let Some(entry) = registry.object(object) else {
        return Verification::NotDrawn;
    };
    let profile = entry.record.profile;
    let Ok(encoder) = SegmentEncoder::new(segment, source, &profile) else {
        return Verification::Mismatch {
            esi: claimed.0,
            claimed: symbol_leaf(claimed.1),
            derived: [0u8; 32],
        };
    };
    let k = encoder.k();
    // Only a repair symbol can be verified this way: a source symbol is the
    // input, so comparing it with itself proves nothing.
    if claimed.0 < k {
        return Verification::NotDrawn;
    }
    let Ok(derived) = encoder.repair_symbols(claimed.0 - k, 1) else {
        return Verification::Mismatch {
            esi: claimed.0,
            claimed: symbol_leaf(claimed.1),
            derived: [0u8; 32],
        };
    };
    let Some(derived) = derived.first() else {
        return Verification::NotDrawn;
    };
    let claimed_leaf = symbol_leaf(claimed.1);
    let derived_leaf = symbol_leaf(&derived.data);
    if claimed_leaf == derived_leaf {
        Verification::Regenerates
    } else {
        Verification::Mismatch {
            esi: claimed.0,
            claimed: claimed_leaf,
            derived: derived_leaf,
        }
    }
}

/// The report a [`Verification::Mismatch`] produces: the repairer's offence,
/// ready for `AccountState::slash_from_report`.
///
/// `epoch` is the epoch the repair was recorded in and the segment travel in
/// the proof, so a second report for the same segment in the same epoch is
/// refused as a replay by the registry's offence-window key rather than
/// charging the bond twice.
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub fn bad_repair_report(
    repairer: Address,
    object: &ObjectKey,
    segment: u64,
    epoch: u64,
    esi: u32,
    claimed: [u8; 32],
    derived: [u8; 32],
    reporter: Option<Address>,
) -> SlashingReport {
    SlashingReport::new_verified(
        repairer,
        roles::VALIDATOR,
        SlashingProof::BadRepair {
            object: *object,
            segment,
            epoch,
            // The two digests are the claim; the ESI is what a reader of the
            // ledger needs to find the symbol again. The registry charges the
            // offence window on `(segment, epoch)`.
            esi,
            claimed,
            derived,
        },
        reporter,
    )
}

/// The ratio §11.7 assigns a proved bad repair, in `FIXED_POINT_SCALE` units.
///
/// The default is 1%; this reads the live parameter so governance can move it.
#[must_use]
/// WIRING: exercised by the B.U.D. 3.0 custody, repair, and readiness paths.
pub const fn slash_ratio(params: &crate::registry::RegistryParams) -> u64 {
    params.slash_ratio(SlashingCondition::BadRepair)
}

/// §11.7's 1%, as a constant for tests and for the parameter's own default.
///
/// Written out rather than derived from [`slash_ratio`] so a test cannot agree
/// with whatever the parameter happens to hold.
pub const BAD_REPAIR_SLASH_RATIO_FIXED: u64 = FIXED_POINT_SCALE / 100;

/// Blocks an assigned Full validator has to submit `RecordRepair` before the
/// task hands over to the next Full candidate (Section 7.6).
pub const REPAIR_TASK_HANDOVER_BLOCKS: u64 = 20;


/// One scheduled segment repair task.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScheduledScheduledRepairTask {
    /// Object commitment.
    pub object_key: ObjectKey,
    /// Segment index within the object.
    pub segment: u64,
    /// Currently assigned Full validator.
    pub assigned_to: Address,
    /// Block height at which `assigned_to` received the task.
    pub assigned_height: u64,
    /// Number of handovers already performed for this repair task.
    pub handovers: u32,
    /// Validators that already timed out on this task in the current cycle.
    pub timed_out: BTreeSet<Address>,
}

impl ScheduledScheduledRepairTask {
    /// Convenience: whether this task has exceeded [`REPAIR_TASK_HANDOVER_BLOCKS`]
    /// at `current_height` without completing `RecordRepair`.
    #[must_use]
    pub const fn is_handover_due(&self, current_height: u64) -> bool {
        current_height.saturating_sub(self.assigned_height) >= REPAIR_TASK_HANDOVER_BLOCKS
    }
}

/// Deterministic scheduler tracking active segment repair tasks.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepairScheduler {
    tasks: BTreeMap<(ObjectKey, u64), ScheduledRepairTask>,
}

impl RepairScheduler {
    /// Convenience: empty repair scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: active repair task for `(object_key, segment)`.
    #[must_use]
    pub fn task(&self, object_key: &ObjectKey, segment: u64) -> Option<&ScheduledRepairTask> {
        self.tasks.get(&(*object_key, segment))
    }

    /// Convenience: number of open repair tasks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Convenience: whether no repair tasks are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Convenience: enqueue a due repair for `(object_key, segment)` at
    /// `current_height` if not already tracked, picking deterministically from
    /// `full_candidates`.
    pub fn schedule_task(
        &mut self,
        object_key: ObjectKey,
        segment: u64,
        current_height: u64,
        full_candidates: &[Address],
    ) -> Option<Address> {
        if let Some(existing) = self.tasks.get(&(object_key, segment)) {
            return Some(existing.assigned_to);
        }
        let assigned_to = pick_initial_repairer(&object_key, segment, full_candidates)?;
        self.tasks.insert(
            (object_key, segment),
            ScheduledRepairTask {
                object_key,
                segment,
                assigned_to,
                assigned_height: current_height,
                handovers: 0,
                timed_out: BTreeSet::new(),
            },
        );
        Some(assigned_to)
    }

    /// Convenience: scan `registry` for due segment repairs and schedule any
    /// newly due segments onto `full_candidates`. Returns how many new tasks
    /// were scheduled.
    pub fn sync_from_registry(
        &mut self,
        registry: &Bud3Registry,
        current_height: u64,
        full_candidates: &[Address],
    ) -> usize {
        let due = registry.all_repairs_due();
        let due_set: BTreeSet<(ObjectKey, u64)> = due.iter().copied().collect();
        self.tasks.retain(|target, _| due_set.contains(target));
        let mut added = 0;
        for (key, segment) in due {
            if !self.tasks.contains_key(&(key, segment))
                && self
                    .schedule_task(key, segment, current_height, full_candidates)
                    .is_some()
            {
                added += 1;
            }
        }
        added
    }

    /// Convenience: mark `(object_key, segment)` completed after `RecordRepair`.
    pub fn complete_task(&mut self, object_key: &ObjectKey, segment: u64) -> bool {
        self.tasks.remove(&(*object_key, segment)).is_some()
    }

    /// Convenience: hand over every task whose 20-block window expired by
    /// `current_height` to the next Full candidate in `full_candidates`.
    /// Returns the `(object_key, segment, new_assignee)` tuples handed over.
    pub fn handover_expired(
        &mut self,
        current_height: u64,
        full_candidates: &[Address],
    ) -> Vec<(ObjectKey, u64, Address)> {
        if full_candidates.is_empty() {
            return Vec::new();
        }
        let mut handed_over = Vec::new();
        for ((key, segment), task) in &mut self.tasks {
            if !task.is_handover_due(current_height) {
                continue;
            }
            let previous = task.assigned_to;
            task.timed_out.insert(previous);
            let next = full_candidates
                .iter()
                .find(|cand| **cand != previous && !task.timed_out.contains(*cand))
                .copied()
                .or_else(|| {
                    // Every candidate timed out once; start a fresh cycle with
                    // the next candidate after `previous`.
                    task.timed_out.clear();
                    let pos = full_candidates
                        .iter()
                        .position(|cand| *cand == previous)
                        .unwrap_or(0);
                    let next_idx = (pos + 1) % full_candidates.len();
                    full_candidates.get(next_idx).copied()
                });
            if let Some(next_holder) = next {
                if next_holder != previous || full_candidates.len() == 1 {
                    task.assigned_to = next_holder;
                    task.assigned_height = current_height;
                    task.handovers = task.handovers.saturating_add(1);
                    handed_over.push((*key, *segment, next_holder));
                }
            }
        }
        handed_over
    }
}

fn pick_initial_repairer(
    object_key: &ObjectKey,
    segment: u64,
    full_candidates: &[Address],
) -> Option<Address> {
    if full_candidates.is_empty() {
        return None;
    }
    let head = object_key
        .first()
        .copied()
        .map_or(0u64, u64::from)
        .wrapping_add(segment);
    let len = u64::try_from(full_candidates.len()).unwrap_or(1);
    let idx = usize::try_from(head % len).unwrap_or(0);
    full_candidates.get(idx).copied()
}



#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(i: u8, class: Class) -> Candidate {
        let mut v = [0u8; 32];
        v[0] = i;
        Candidate {
            validator: v,
            account: v,
            class,
            stake: 1_000,
            free_quota_bytes: u64::MAX,
            network: None,
        }
    }

    fn task() -> RepairTask {
        RepairTask {
            object: [7u8; 32],
            segment: 3,
            opened_at: 100,
        }
    }

    /// §6.10 item 3: Full only, and the task moves on after the deadline.
    #[test]
    fn the_task_moves_down_the_order_after_twenty_blocks() {
        let candidates: Vec<Candidate> = (1..=4)
            .map(|i| candidate(i, Class::Full))
            .chain(std::iter::once(candidate(9, Class::Mobile)))
            .collect();
        let t = task();
        let order = assign(&t, &candidates);
        assert_eq!(order.len(), 4, "the Mobile candidate is not a repairer");
        assert!(
            order.iter().all(|a| a.repairer != [9u8; 32]),
            "a Mobile validator is never assigned a repair"
        );
        assert_eq!(order[0].place, 0);

        // Nobody started. Inside the first window the first candidate still
        // owns the task.
        let first = repairer_at(&t, &candidates, 100, |_| false).expect("assigned");
        assert_eq!(first, order[0].repairer);
        assert_eq!(
            repairer_at(&t, &candidates, 119, |_| false),
            Some(order[0].repairer)
        );
        // At the deadline the task is the second candidate's.
        assert_eq!(
            repairer_at(&t, &candidates, 120, |_| false),
            Some(order[1].repairer)
        );
        assert_eq!(
            repairer_at(&t, &candidates, 140, |_| false),
            Some(order[2].repairer)
        );
        // A candidate that did start keeps the task.
        assert_eq!(
            repairer_at(&t, &candidates, 150, |r| r == order[2].repairer),
            Some(order[2].repairer)
        );
        // Everyone let their window go by: unassigned, which is a state an
        // operator has to see.
        assert_eq!(repairer_at(&t, &candidates, 200, |_| false), None);
    }

    #[test]
    fn a_late_task_is_late_at_exactly_the_deadline() {
        let t = task();
        assert!(!t.is_late(119));
        assert!(t.is_late(120));
    }

    /// The draw is 1% and it is a function of consensus data only.
    #[test]
    fn the_verification_draw_is_about_one_in_a_hundred() {
        let object = [3u8; 32];
        let mut drawn = 0u64;
        for epoch in 0..200u8 {
            for segment in 0..50u64 {
                if audit_drawn(&[epoch; 32], &object, segment) {
                    drawn += 1;
                }
            }
        }
        let total = 200 * 50;
        // 1% of 10 000 is 100; a binomial with n = 10 000 and p = 0.01 has a
        // standard deviation of about 10, so ±60 is six sigma and still far
        // from the 0% or 100% a broken draw would produce.
        assert!(
            (40..=160).contains(&drawn),
            "the draw selected {drawn} of {total}, which is not near 1%"
        );
        // Deterministic: the same inputs give the same answer, which is what
        // lets every node agree on who is accused.
        assert_eq!(
            audit_drawn(&[1; 32], &object, 5),
            audit_drawn(&[1; 32], &object, 5)
        );
        assert_ne!(
            audit_drawn(&[1; 32], &object, 5),
            audit_drawn(&[2; 32], &object, 5),
            "the seed must move the sample, or an epoch's draw is a constant"
        );
    }

    /// A report cannot accuse a repairer whose symbol regenerates: the shape
    /// check refuses it, and the registry would otherwise burn a bond for
    /// correct work.
    #[test]
    fn a_report_that_says_the_symbol_regenerates_is_refused() {
        let same = [4u8; 32];
        let report = bad_repair_report([1u8; 32], &[2u8; 32], 0, 7, 20, same, same, None);
        assert_eq!(
            report.validate_shape(),
            Err(crate::registry::evidence::EvidenceError::RepairRegenerates)
        );
        let real = bad_repair_report(
            [1u8; 32],
            &[2u8; 32],
            0,
            7,
            20,
            [1u8; 32],
            [2u8; 32],
            None,
        );
        assert_eq!(real.validate_shape(), Ok(()));
        assert_eq!(real.condition(), SlashingCondition::BadRepair);
    }

    /// §11.7 prices a proved bad repair at 1%, and the parameter default is
    /// that number.
    #[test]
    fn the_default_ratio_is_one_percent() {
        let params = crate::registry::RegistryParams::default();
        assert_eq!(slash_ratio(&params), BAD_REPAIR_SLASH_RATIO_FIXED);
        assert_eq!(BAD_REPAIR_SLASH_RATIO_FIXED, FIXED_POINT_SCALE / 100);
        // It is not the malice rate, which is what a fourth `Other` tag would
        // have charged.
        assert_ne!(
            slash_ratio(&params),
            params.slash_ratio(SlashingCondition::MaliciousBehaviour)
        );
        // And it is distinct from downtime even where the two numbers agree
        // today: moving one must not move the other.
        let mut moved = params;
        moved.liveness_slash_ratio_fixed = FIXED_POINT_SCALE / 2;
        assert_eq!(slash_ratio(&moved), FIXED_POINT_SCALE / 100);
    }
}
