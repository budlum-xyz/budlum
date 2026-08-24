//! B.U.D. 2.0 - THE LAZY REPAIR POLICY (F34/F102/F295 - lazy recovery).
//!
//! Remaining work item #11a: lazy recovery. A lost shard is repaired not at
//! the moment of loss but on a threshold or a read request, which lowers the
//! repair bandwidth. This module is the DECISION layer (the MSR codes over
//! GF(2^8) are separate work; the design note is below): defer or repair now,
//! based on the number of losses, their age, the read request and the
//! bandwidth budget.
//! `RepairPolicy::decide` is deterministic; the decision record can be written
//! to the chain.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const REPAIR_MAGIC: [u8; 8] = *b"\xB5RPR1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    Defer { until_epoch: u64 },
    RepairNow { helpers: usize },
    RebuildFromScratch,
}

/// The lazy repair decision.
/// `lost`: the number of lost shards · `tolerated`: the loss the code
/// tolerates (f)
/// `age_epochs`: the age of the loss · `read_pending`: the read queue (repair
/// at once if there is a request)
/// `budget_per_epoch`: the repair bandwidth quota per epoch.
pub fn decide_repair(
    lost: usize,
    tolerated: usize,
    age_epochs: u64,
    read_pending: bool,
    budget_per_epoch: f64,
) -> Option<RepairAction> {
    if lost == 0 {
        return Some(RepairAction::Defer { until_epoch: 0 }); // nothing lost
    }
    if lost >= tolerated {
        // the tolerance is exceeded -> repair now, from helper nodes if
        // possible
        return Some(RepairAction::RepairNow { helpers: 2 });
    }
    // if there is a read request, repair now (the user should not feel the
    // delay)
    if read_pending {
        return Some(RepairAction::RepairNow { helpers: 1 });
    }
    // with no budget, defer; repair once the age threshold is passed
    let age_threshold = if budget_per_epoch <= 0.0 {
        0
    } else {
        (1.0 / budget_per_epoch.max(0.001)) as u64
    };
    if age_epochs >= age_threshold.max(2) {
        Some(RepairAction::RepairNow { helpers: 2 })
    } else {
        Some(RepairAction::Defer {
            until_epoch: age_threshold.max(2),
        })
    }
}

pub fn repair_digest(lost: usize, tolerated: usize, age: u64, read: bool, budget: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(REPAIR_MAGIC);
    h.update((lost as u32).to_le_bytes());
    h.update((tolerated as u32).to_le_bytes());
    h.update(age.to_le_bytes());
    h.update([read as u8]);
    h.update(budget.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_lost_is_deferred() {
        assert!(matches!(
            decide_repair(0, 2, 0, false, 0.5),
            Some(RepairAction::Defer { .. })
        ));
    }

    #[test]
    fn exceeding_the_tolerance_repairs_now() {
        assert!(matches!(
            decide_repair(3, 2, 0, false, 0.5),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn a_read_request_repairs_now() {
        assert!(matches!(
            decide_repair(1, 2, 0, true, 0.5),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn no_budget_defers_and_a_high_age_repairs() {
        // budget 0 -> threshold 0.max(2)=2; age 1 -> defer, age 5 -> repair
        assert!(matches!(
            decide_repair(1, 2, 1, false, 0.0),
            Some(RepairAction::Defer { .. })
        ));
        assert!(matches!(
            decide_repair(1, 2, 5, false, 0.0),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn karar_deterministik() {
        assert_eq!(
            repair_digest(1, 2, 3, true, 0.5),
            repair_digest(1, 2, 3, true, 0.5)
        );
    }
}

// ## MSR codes - a design note (F41/F293-F297, not coded - GF(2^8) is
// separate work)
// MSR (minimum-storage regenerating): a repair transfers alpha symbols instead
// of ALL the data, which is the optimal repair bandwidth for (n,k). The
// current Cauchy MDS (4+2) transfers 4/6 of the container when a single piece
// is lost; MSR brings that down to (n-1)*alpha. The encoding needs matrix
// multiplication over GF(2^8) - an `msr_repair_band` calculator could be added
// to the GF infrastructure of `bud_format_erasure`. Priority: low (the repair
// bandwidth is already small with the k-4 LRC).
