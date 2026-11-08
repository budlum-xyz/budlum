//! Lazy repair scheduling and Instant Duty Handover for B.U.D. 3.0 segments.
//!
//! A segment enters repair when lost shares reach at least `max(1, floor(f / 2))`
//! (`Bud3Registry::repairs_due`). Only Full validators take repair tasks (`V-2`
//! / storage class rule: Mobile validators hold shares and answer audits, never
//! decode/re-encode whole segments). If the assigned Full validator does not
//! land `RecordRepair` within [`REPAIR_TASK_HANDOVER_BLOCKS`] (20 blocks), the
//! task hands over deterministically to the next eligible Full candidate
//! without slashing or waiting for epoch close.
//!
//! WIRING: available to `validators::handover` and the churn simulator. The
//! canonical registry duty handover continues to use `ScheduledRepairDuty`.

use std::collections::{BTreeMap, BTreeSet};

use super::super::registry::{Address, Bud3Registry, ObjectKey};

use super::REPAIR_TASK_HANDOVER_BLOCKS;

/// One scheduled segment repair task.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepairTask {
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

impl RepairTask {
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
    tasks: BTreeMap<(ObjectKey, u64), RepairTask>,
}

impl RepairScheduler {
    /// Convenience: empty repair scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: active repair task for `(object_key, segment)`.
    #[must_use]
    pub fn task(&self, object_key: &ObjectKey, segment: u64) -> Option<&RepairTask> {
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
            RepairTask {
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

    #[test]
    fn repair_task_hands_over_after_20_blocks() {
        let mut sched = RepairScheduler::new();
        let key = [0xAA; 32];
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let v3 = [3u8; 32];
        let candidates = [v1, v2, v3];

        let first = sched.schedule_task(key, 0, 100, &candidates).unwrap();
        assert!(sched.handover_expired(119, &candidates).is_empty());
        assert_eq!(sched.task(&key, 0).unwrap().assigned_to, first);

        let moved = sched.handover_expired(120, &candidates);
        assert_eq!(moved.len(), 1);
        let second = moved[0].2;
        assert_ne!(second, first);
        assert_eq!(sched.task(&key, 0).unwrap().handovers, 1);
    }
}
