//! Network-shrink repair prioritization, decline/release share reassignment, and
//! B.U.D. 3.0 storage health metrics.
//! exposed for validator maintenance engine and `Bud3RpcService` telemetry.
//!
//! Per Sections 6.10, 6.13, and WP-20 items 9-13:
//! * As the validator set shrinks, repair prioritizes segments with the smallest
//!   remaining fault margin (`f - lost_shares`) first (Section 6.13 item 6).
//! * `DeclineContent` and `ReleaseShares` mark shares for reassignment without
//!   any stake penalty; replacement candidates exclude the repairer, current
//!   holders of the segment, and validators that declined the content id.
//! * Exposes the four canonical B.U.D. 3.0 Prometheus metrics:
//!   `budlum_bud3_segments_at_risk`, `budlum_bud3_repair_backlog`,
//!   `budlum_bud3_audit_latency`, and `budlum_bud3_custody_bytes{class}`.

use super::placement::{rank, segment_key, Candidate, Class};
use super::registry::{Address, ObjectKey};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Health snapshot of one segment for shrink-aware repair scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRisk {
    /// Object commitment.
    pub object: ObjectKey,
    /// Segment index.
    pub segment: u64,
    /// Maximum tolerable lost shares (`f`) before symbols drop below `k + 2`.
    pub max_lost_shares: u64,
    /// Currently lost / declined / released shares on this segment.
    pub lost_shares: u64,
}

impl SegmentRisk {
    /// Remaining share losses the segment can absorb (`f - lost_shares`).
    #[must_use]
    pub const fn remaining_margin(&self) -> u64 {
        self.max_lost_shares.saturating_sub(self.lost_shares)
    }

    /// Whether the segment has crossed the lazy-repair threshold (`(f / 2).max(1)`).
    #[must_use]
    pub const fn needs_repair(&self) -> bool {
        let threshold = if self.max_lost_shares / 2 == 0 {
            1
        } else {
            self.max_lost_shares / 2
        };
        self.lost_shares >= threshold
    }
}

/// Order due repairs so segments closest to their fault ceiling `f` (smallest
/// `remaining_margin`) are repaired first during network shrink (Section 6.13.6).
#[must_use]
pub fn prioritize_shrink_repairs(segments: &[SegmentRisk]) -> Vec<SegmentRisk> {
    let mut due: Vec<SegmentRisk> = segments
        .iter()
        .copied()
        .filter(SegmentRisk::needs_repair)
        .collect();
    due.sort_by(|a, b| {
        a.remaining_margin()
            .cmp(&b.remaining_margin())
            .then_with(|| b.lost_shares.cmp(&a.lost_shares))
            .then_with(|| a.object.cmp(&b.object))
            .then_with(|| a.segment.cmp(&b.segment))
    });
    due
}

/// Select replacement holders for lost/declined/released shares of `(object, segment)`
/// via stake-weighted rendezvous hashing, skipping the repairer, existing segment
/// holders, declined validators, and candidates without enough free quota.
/// Convenience: exposed for repair reassignment scheduler.
#[must_use]
pub fn select_reassignment_holders(
    target: (&ObjectKey, u64),
    spec: (Class, u32, u32, usize),
    excluded: (&Address, &BTreeSet<Address>, &BTreeSet<Address>),
    candidates: &[Candidate],
) -> Vec<(Address, Class, u32)> {
    let (object, segment) = target;
    let (class, symbols_per_share, symbol_size, want_shares) = spec;
    let (repairer, existing_holders, declined_validators) = excluded;
    let share_bytes = u64::from(symbols_per_share).saturating_mul(u64::from(symbol_size));
    let key = segment_key(object, segment);
    let ordered = rank(&key, candidates);
    let mut out = Vec::with_capacity(want_shares);
    for c in ordered {
        if out.len() >= want_shares {
            break;
        }
        if c.class != class
            || c.validator == *repairer
            || existing_holders.contains(&c.validator)
            || declined_validators.contains(&c.validator)
            || c.free_quota_bytes < share_bytes
        {
            continue;
        }
        out.push((c.validator, class, symbols_per_share));
    }
    out
}

/// Canonical B.U.D. 3.0 storage maintenance metrics (WP-20 item 13).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bud3StorageMetrics {
    /// `budlum_bud3_segments_at_risk`: segments with `lost_shares > 0`.
    pub segments_at_risk: u64,
    /// `budlum_bud3_repair_backlog`: segments at or above the `f / 2` repair trigger.
    pub repair_backlog: u64,
    /// `budlum_bud3_audit_latency`: p50/observed audit response latency in epochs.
    pub audit_latency_epochs: u64,
    /// `budlum_bud3_custody_bytes{class="full"}`.
    pub custody_bytes_full: u64,
    /// `budlum_bud3_custody_bytes{class="mobile"}`.
    pub custody_bytes_mobile: u64,
}

impl Bud3StorageMetrics {
    /// Render Prometheus text exposition lines for the four B.U.D. 3.0 storage gauges.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(320);
        let _ = writeln!(
            out,
            "budlum_bud3_segments_at_risk {}",
            self.segments_at_risk
        );
        let _ = writeln!(out, "budlum_bud3_repair_backlog {}", self.repair_backlog);
        let _ = writeln!(
            out,
            "budlum_bud3_audit_latency {}",
            self.audit_latency_epochs
        );
        let _ = writeln!(
            out,
            "budlum_bud3_custody_bytes{{class=\"full\"}} {}",
            self.custody_bytes_full
        );
        let _ = writeln!(
            out,
            "budlum_bud3_custody_bytes{{class=\"mobile\"}} {}",
            self.custody_bytes_mobile
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrink_repairs_prioritize_smallest_fault_margin_first() {
        let risks = vec![
            SegmentRisk {
                object: [1; 32],
                segment: 0,
                max_lost_shares: 10,
                lost_shares: 5, // margin 5
            },
            SegmentRisk {
                object: [2; 32],
                segment: 0,
                max_lost_shares: 6,
                lost_shares: 5, // margin 1 -> urgent!
            },
            SegmentRisk {
                object: [3; 32],
                segment: 0,
                max_lost_shares: 10,
                lost_shares: 2, // below f/2 = 5 -> not due
            },
        ];
        let ordered = prioritize_shrink_repairs(&risks);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].object, [2; 32]);
        assert_eq!(ordered[1].object, [1; 32]);
    }

    #[test]
    fn prometheus_metrics_export_all_four_bud3_series() {
        let m = Bud3StorageMetrics {
            segments_at_risk: 3,
            repair_backlog: 1,
            audit_latency_epochs: 1,
            custody_bytes_full: 12_000_000,
            custody_bytes_mobile: 6_000_000,
        };
        let text = m.render_prometheus();
        assert!(text.contains("budlum_bud3_segments_at_risk 3"));
        assert!(text.contains("budlum_bud3_repair_backlog 1"));
        assert!(text.contains("budlum_bud3_audit_latency 1"));
        assert!(text.contains("budlum_bud3_custody_bytes{class=\"full\"} 12000000"));
        assert!(text.contains("budlum_bud3_custody_bytes{class=\"mobile\"} 6000000"));
    }
}
