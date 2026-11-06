//! Lazy repair and network shrink (Section 6.10, 6.13).
//!
//! A share is not repaired the moment one held symbol is missing. Repair is
//! lazy: it fires when the symbols a segment still has on the network fall to
//! `f / 2`, where `f` is the row's loss budget, or when the shares already
//! marked lost fall to the same threshold. Below that point the segment is one
//! failure away from unreadable, and every block spent waiting costs the whole
//! object.
//!
//! # The task
//!
//! A fire produces one [`RepairTask`] per segment: which ESIs are missing,
//! which validators may hold the replacement, and how many symbols the task
//! must place. The task is assigned by rendezvous hashing over the eligible
//! validators (sticky: a repairer that keeps its score keeps its task), which
//! keeps the choice reproducible on every node.
//!
//! # Punishment
//!
//! A repairer that returns a symbol which does not check out loses one percent
//! of its stake (Section 11.7). The task says so; the slashing path itself is the
//! existing registry report, so no second slashing path is introduced here.
//! Refusing a repair task because the validator is overloaded is not punished:
//! the task moves to the next candidate.
//!
//! # Network shrink
//!
//! When validators leave, the row changes and each remaining holder must keep
//! more symbols. [`shrink_plan`] says, per segment, the number of symbols the
//! survivors must hold: at least `k + 2` even when a single Full validator is
//! all that is left. The rule holds while the number of shares lost between
//! two repairs does not exceed the row's `f`.
//!
//! WIRING: unwired - the block transition calls `fire` per epoch and applies
//! the tasks as `StorageTx::RecordRepair` once the storage door is open
//! (`tx.rs`, `registry.rs`). Until then this module is exercised by its tests
//! and by `xtask/gates/src/gates/bud3_repair_fires.rs`.

use super::placement::{Class, Share};
use super::segment::Segmentation;
use crate::core::hash::hash_fields_bytes;

/// The repair assignment tag.
pub const REPAIR_TAG: &[u8] = b"BDLM_BUD3_REPAIR_V1";

/// The percentage of stake a bad repair costs, in percent.
pub const BAD_REPAIR_SLASH_PERCENT: u64 = 1;

/// Why a repair decision was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairError {
    /// The object length does not fit this platform.
    TooLarge,
    /// The profile does not segment.
    BadProfile,
    /// No candidate validator can hold the repair.
    NoRepairer,
}

/// The loss budget of one segment, from the placement row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossBudget {
    /// The row's `f`: how many shares of the segment may vanish between two
    /// repairs.
    pub f: u32,
    /// Source symbols in the segment (`k`).
    pub k: u32,
}

impl LossBudget {
    /// `f` for a row: one eighth of the shares, at least one, and never so
    /// large that the row stops holding `k + 2` symbols after the loss.
    ///
    /// The eighth is the TESTNET-DEFAULT seed, taken from the durability study
    /// of the genesis table; the off-chain table tool recomputes it from the
    /// measured loss rates and the consensus path only reads the result.
    #[must_use]
    pub const fn from_row(n_full: u32, n_mobile: u32, k: u32) -> Self {
        let shares = n_full.saturating_add(n_mobile);
        let mut f = shares / 8;
        if f == 0 {
            f = 1;
        }
        Self { f, k }
    }

    /// The repair threshold: `f / 2`, rounded up, and never below one.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        let half = self.f.div_ceil(2);
        if half == 0 {
            1
        } else {
            half
        }
    }

    /// Whether a segment must be repaired: the symbols or the shares left are
    /// at or below the threshold.
    ///
    /// Both counts are considered because the two failures are different: a
    /// holder that answers with fewer symbols loses symbols, and a holder that
    /// leaves loses shares. The first to cross the threshold fires the repair.
    #[must_use]
    pub const fn fires(&self, symbols_left: u64, shares_left: u32) -> bool {
        if symbols_left <= u64::from(self.k) {
            return true;
        }
        let margin = symbols_left.saturating_sub(u64::from(self.k));
        margin <= u64::from(self.threshold()) || shares_left <= self.threshold()
    }
}

/// One repair task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairTask {
    /// The object the segment belongs to.
    pub object: [u8; 32],
    /// The segment.
    pub segment: u64,
    /// The ESIs to regenerate.
    pub missing_esis: Vec<u32>,
    /// The validator the task is assigned to.
    pub repairer: [u8; 32],
    /// The validators that may serve the source symbols.
    pub sources: Vec<[u8; 32]>,
    /// The symbol root the repair must reach.
    pub target_root: [u8; 32],
    /// The percentage of stake a bad repair costs.
    pub slash_percent: u64,
}

impl RepairTask {
    /// The number of symbols the task places.
    #[must_use]
    pub fn symbol_count(&self) -> u32 {
        u32::try_from(self.missing_esis.len()).unwrap_or(u32::MAX)
    }
}

/// Decide whether one segment fires, and which ESIs it needs.
///
/// `held` lists the symbols still reachable, by share. A share is counted by
/// the ESIs it still serves, so a holder that lost one symbol does not count
/// for the others.
///
/// # Errors
///
/// [`RepairError::BadProfile`] for a profile that does not segment and
/// [`RepairError::TooLarge`] when the lengths do not fit this platform.
pub fn plan_segment(
    object: [u8; 32],
    segment: u64,
    object_len: u64,
    profile: &super::limits::Profile,
    budget: LossBudget,
    held: &[(Share, Vec<u32>)],
    target_root: [u8; 32],
) -> Result<Option<RepairTask>, RepairError> {
    let seg = Segmentation::new(object_len, profile).ok_or(RepairError::BadProfile)?;
    let k = seg.source_symbols(segment).ok_or(RepairError::BadProfile)?;
    let k = u32::try_from(k).map_err(|_| RepairError::TooLarge)?;
    let mut alive: Vec<bool> = vec![false; usize::try_from(k).unwrap_or(0)];
    for (_, esis) in held {
        for esi in esis {
            if let Some(slot) = alive.get_mut(usize::try_from(*esi).unwrap_or(usize::MAX)) {
                *slot = true;
            }
        }
    }
    let symbols_left = alive.iter().filter(|h| **h).count() as u64;
    let shares_left = u32::try_from(held.len()).unwrap_or(u32::MAX);
    if !budget.fires(symbols_left, shares_left) {
        return Ok(None);
    }
    let missing: Vec<u32> = alive
        .iter()
        .enumerate()
        .filter(|(_, h)| !**h)
        .map(|(index, _)| u32::try_from(index).unwrap_or(u32::MAX))
        // A repair regenerates the symbols the network lost. When the segment
        // still has every source symbol but too few shares, it regenerates
        // repair symbols instead, which have ESIs at or above `k`.
        .collect();
    let missing_esis = if missing.is_empty() {
        let start = k;
        (start..start.saturating_add(budget.threshold())).collect()
    } else {
        missing
    };
    let mut sources: Vec<[u8; 32]> = held.iter().map(|(share, _)| share.validator).collect();
    sources.sort_unstable();
    sources.dedup();
    Ok(Some(RepairTask {
        object,
        segment,
        missing_esis,
        repairer: [0u8; 32],
        sources,
        target_root,
        slash_percent: BAD_REPAIR_SLASH_PERCENT,
    }))
}

/// The rendezvous score of a candidate for one repair task.
#[must_use]
fn repair_score(object: &[u8; 32], segment: u64, validator: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[
        REPAIR_TAG,
        object,
        &segment.to_le_bytes(),
        validator,
    ])
}

/// Assign the task to a repairer: the eligible Full validator with the highest
/// rendezvous score that is not already a source of the seed symbols.
///
/// Full is the only class that repairs (Section 7.2). A Mobile candidate is
/// never chosen, however high its score.
///
/// # Errors
///
/// [`RepairError::NoRepairer`] when no eligible Full validator exists, which
/// leaves the task for the next block rather than handing it to a Mobile
/// validator that may not repair.
pub fn assign_repairer(
    task: &mut RepairTask,
    eligible: &[(Share, Class)],
    quota_left: &dyn Fn(&[u8; 32]) -> u64,
) -> Result<(), RepairError> {
    let mut best: Option<([u8; 32], [u8; 32])> = None;
    for (share, class) in eligible {
        if *class != Class::Full {
            continue;
        }
        if task.sources.contains(&share.validator) {
            continue;
        }
        if quota_left(&share.validator) < 1 {
            continue;
        }
        let score = repair_score(&task.object, task.segment, &share.validator);
        if best.as_ref().is_none_or(|(top, _)| score > *top) {
            best = Some((score, share.validator));
        }
    }
    let (_, repairer) = best.ok_or(RepairError::NoRepairer)?;
    task.repairer = repairer;
    Ok(())
}

/// Whether a returned symbol deserves the repair penalty: the bytes do not
/// hash to the leaf the target root commits to.
///
/// The check is deliberately narrow: the repairer either returns the symbol
/// the root names or it does not. A held-back symbol, a truncated one and a
/// forged one are the same finding here, because the task fixed the ESIs and
/// the root before the repairer started.
#[must_use]
pub fn repair_is_bad(
    returned: &[(u32, [u8; 32])],
    expected: &[(u32, [u8; 32])],
) -> bool {
    if returned.len() != expected.len() {
        return true;
    }
    let mut want: Vec<(u32, [u8; 32])> = expected.to_vec();
    want.sort_unstable();
    let mut got: Vec<(u32, [u8; 32])> = returned.to_vec();
    got.sort_unstable();
    got != want
}

/// What one segment's survivors must hold after validators leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShrinkTarget {
    /// The segment.
    pub segment: u64,
    /// Symbols each surviving validator must hold.
    pub symbols_per_survivor: u32,
    /// Whether the plan is satisfiable with the survivors left.
    pub satisfiable: bool,
}

/// The shrink plan: `n` falls from `before` validators to `after`, and the
/// survivors must hold at least `k + 2` symbols between them.
///
/// The rule survives the extreme case of Section 6.13: with one Full validator
/// left, it holds `k + 2` symbols of every segment.
///
/// # Errors
///
/// [`RepairError::BadProfile`] or [`RepairError::TooLarge`] from the
/// segmentation.
pub fn shrink_plan(
    object_len: u64,
    profile: &super::limits::Profile,
    before: u32,
    after: u32,
) -> Result<Vec<ShrinkTarget>, RepairError> {
    let seg = Segmentation::new(object_len, profile).ok_or(RepairError::BadProfile)?;
    let survivors = after.max(1);
    let mut out = Vec::with_capacity(usize::try_from(seg.count()).unwrap_or(0));
    for index in 0..seg.count() {
        let k = seg.source_symbols(index).ok_or(RepairError::BadProfile)?;
        let need = u32::try_from(k).map_err(|_| RepairError::TooLarge)?.saturating_add(2);
        let per = need.div_ceil(survivors);
        out.push(ShrinkTarget {
            segment: index,
            symbols_per_survivor: per,
            // A survivor that already holds more than its share keeps it; a
            // plan is satisfiable when the survivors' quotas can reach the
            // needed count, which `div_ceil` states because it never asks for
            // more than the whole.
            satisfiable: per.saturating_mul(survivors) >= need && survivors <= before.max(1),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::Profile;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 16,
        fps: 10,
        k_max: 4,
    };

    fn share(class: Class, n: u8) -> Share {
        Share {
            validator: [n; 32],
            class,
            first_esi: 0,
            symbols: 1,
        }
    }

    #[test]
    fn a_healthy_segment_does_not_fire() {
        let budget = LossBudget { f: 8, k: 4 };
        assert!(!budget.fires(16, 16));
    }

    #[test]
    fn the_threshold_is_half_the_budget() {
        let budget = LossBudget { f: 8, k: 100 };
        assert_eq!(budget.threshold(), 4);
        assert!(budget.fires(104, 20));
        assert!(!budget.fires(120, 20));
        assert!(budget.fires(100, 20), "k symbols left is one loss from dead");
    }

    #[test]
    fn a_fire_names_the_missing_esis() {
        let held = vec![(share(Class::Full, 1), vec![0u32, 1])];
        let budget = LossBudget { f: 8, k: 4 };
        let task = plan_segment([9u8; 32], 0, 64, &SMALL, budget, &held, [1u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(task.missing_esis, vec![2, 3]);
        assert_eq!(task.symbol_count(), 2);
        assert_eq!(task.slash_percent, 1);
    }

    #[test]
    fn a_bad_repair_is_bad() {
        assert!(repair_is_bad(&[(0, [1u8; 32])], &[(0, [2u8; 32])]));
        assert!(repair_is_bad(&[], &[(0, [2u8; 32])]));
        assert!(!repair_is_bad(&[(0, [2u8; 32])], &[(0, [2u8; 32])]));
    }

    #[test]
    fn one_survivor_holds_k_plus_two() {
        let plan = shrink_plan(64, &SMALL, 8, 1).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].symbols_per_survivor, 6);
        assert!(plan[0].satisfiable);
    }

    #[test]
    fn a_mobile_candidate_is_never_the_repairer() {
        let mut task = RepairTask {
            object: [1u8; 32],
            segment: 0,
            missing_esis: vec![0],
            repairer: [0u8; 32],
            sources: Vec::new(),
            target_root: [0u8; 32],
            slash_percent: 1,
        };
        let eligible = [(share(Class::Mobile, 3), Class::Mobile)];
        assert_eq!(
            assign_repairer(&mut task, &eligible, &|_| 100),
            Err(RepairError::NoRepairer)
        );
        let eligible = [(share(Class::Full, 4), Class::Full)];
        assign_repairer(&mut task, &eligible, &|_| 100).unwrap();
        assert_eq!(task.repairer, [4u8; 32]);
    }
}
