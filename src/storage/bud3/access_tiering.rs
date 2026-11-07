//! Access tiering and temperature observation log (Section 6.14 items 8-9; WP-24).
//! exposed for RPC access telemetry and archival tier monitoring.
//!
//! At testnet launch, `SlowY` archival codecs are closed, so [`AccessTierTracker`]
//! records access observations and [`TierTransition`] events without performing
//! autonomous object re-encoding (`testnet_converts_objects() == false`).
//! Sealed objects (`is_sealed == true`) are never converted by validators.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::registry::ObjectKey;

/// Seconds in 7 days (hot window: `>= 5` accesses in 7 days).
pub const HOT_WINDOW_SECS: u64 = 7 * 86_400;

/// Minimum accesses inside [`HOT_WINDOW_SECS`] to classify an object as [`AccessTier::Hot`].
pub const HOT_MIN_ACCESSES: usize = 5;

/// Seconds in 90 days (cold window: `<= 1` access in 90 days).
pub const COLD_WINDOW_SECS: u64 = 90 * 86_400;

/// Maximum accesses inside [`COLD_WINDOW_SECS`] to classify an object as [`AccessTier::Cold`].
pub const COLD_MAX_ACCESSES: usize = 1;

/// Additional seconds (`30` days) an object must remain [`AccessTier::Cold`] before archival eligibility.
pub const COLD_DWELL_FOR_ARCHIVE_SECS: u64 = 30 * 86_400;

/// Observed access temperature tier (Section 6.14 item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessTier {
    Hot,
    Normal,
    Cold,
}

/// Logged tier transition observation (`TierTransition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierTransition {
    pub object: ObjectKey,
    pub from: AccessTier,
    pub to: AccessTier,
    pub observed_at_secs: u64,
    pub archival_candidate: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ObjectAccessLog {
    is_sealed: bool,
    current_tier: Option<AccessTier>,
    cold_since_secs: Option<u64>,
    recent_access_secs: Vec<u64>,
}

/// Node-local access estimator recording temperature transitions (Section 6.14 item 8).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessTierTracker {
    objects: BTreeMap<ObjectKey, ObjectAccessLog>,
    transitions: Vec<TierTransition>,
}

impl AccessTierTracker {
    /// On testnet launch, `SlowY` codecs are closed so tiering logs observations only.
    /// Convenience: exposed for maintenance policy inspection.
    #[must_use]
    pub const fn testnet_converts_objects() -> bool {
        false
    }

    /// Track a newly observed object (`is_sealed` prevents validator-side tier conversion).
    /// Convenience: exposed for upload and registration telemetry.
    pub fn track_object(&mut self, object: ObjectKey, is_sealed: bool) {
        self.objects.entry(object).or_insert(ObjectAccessLog {
            is_sealed,
            current_tier: Some(AccessTier::Normal),
            cold_since_secs: None,
            recent_access_secs: Vec::new(),
        });
    }

    /// Record a paid view or gateway read at `now_secs` and evaluate tier change.
    /// Convenience: exposed for RPC paid-view telemetry.
    pub fn record_access(&mut self, object: ObjectKey, is_sealed: bool, now_secs: u64) -> AccessTier {
        self.track_object(object, is_sealed);
        if let Some(entry) = self.objects.get_mut(&object) {
            let cutoff = now_secs.saturating_sub(COLD_WINDOW_SECS);
            entry.recent_access_secs.retain(|&ts| ts >= cutoff);
            entry.recent_access_secs.push(now_secs);
        }
        self.evaluate_tier(object, now_secs)
    }

    /// Evaluate the current [`AccessTier`] of `object` at `now_secs` and append a
    /// [`TierTransition`] if its tier changed.
    /// Convenience: exposed for periodic tier observation sweeps.
    pub fn evaluate_tier(&mut self, object: ObjectKey, now_secs: u64) -> AccessTier {
        let Some(entry) = self.objects.get_mut(&object) else {
            return AccessTier::Normal;
        };
        let hot_cutoff = now_secs.saturating_sub(HOT_WINDOW_SECS);
        let cold_cutoff = now_secs.saturating_sub(COLD_WINDOW_SECS);
        entry.recent_access_secs.retain(|&ts| ts >= cold_cutoff);

        let hot_hits = entry
            .recent_access_secs
            .iter()
            .filter(|&&ts| ts >= hot_cutoff)
            .count();
        let cold_hits = entry.recent_access_secs.len();

        let next_tier = if hot_hits >= HOT_MIN_ACCESSES {
            AccessTier::Hot
        } else if cold_hits <= COLD_MAX_ACCESSES {
            AccessTier::Cold
        } else {
            AccessTier::Normal
        };

        if next_tier == AccessTier::Cold {
            if entry.cold_since_secs.is_none() {
                entry.cold_since_secs = Some(now_secs);
            }
        } else {
            entry.cold_since_secs = None;
        }

        let archival_candidate = !entry.is_sealed
            && next_tier == AccessTier::Cold
            && entry
                .cold_since_secs
                .is_some_and(|since| now_secs.saturating_sub(since) >= COLD_DWELL_FOR_ARCHIVE_SECS);

        let prev = entry.current_tier.unwrap_or(AccessTier::Normal);
        if prev != next_tier {
            entry.current_tier = Some(next_tier);
            self.transitions.push(TierTransition {
                object,
                from: prev,
                to: next_tier,
                observed_at_secs: now_secs,
                archival_candidate,
            });
        }
        next_tier
    }

    /// Recorded [`TierTransition`] observations.
    /// Convenience: exposed for RPC diagnostics and tests.
    #[must_use]
    pub fn transitions(&self) -> &[TierTransition] {
        &self.transitions
    }

    /// Return public objects eligible for archival `SlowY` / Codec `13` conversion
    /// when expansion-tier conversion is enabled (`Section 6.14 item 8`, `WP-54 item 5`).
    ///
    /// Returns an empty list on testnet launch (`expansion_enabled == false`) and never
    /// selects sealed objects (`is_sealed == true`).
    /// Convenience: exposed for expansion-tier archival re-encoding sweeps.
    #[must_use]
    pub fn expansion_archival_candidates(
        &self,
        now_secs: u64,
        expansion_enabled: bool,
    ) -> Vec<ObjectKey> {
        if !expansion_enabled {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (obj, log) in &self.objects {
            if !log.is_sealed
                && log.current_tier == Some(AccessTier::Cold)
                && log
                    .cold_since_secs
                    .is_some_and(|since| now_secs.saturating_sub(since) >= COLD_DWELL_FOR_ARCHIVE_SECS)
            {
                out.push(*obj);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_and_cold_thresholds_record_transitions_without_converting() {
        assert!(!AccessTierTracker::testnet_converts_objects());
        let mut tracker = AccessTierTracker::default();
        let obj = [0x42u8; 32];
        tracker.track_object(obj, false);

        // Zero accesses over 90 days -> Cold.
        assert_eq!(tracker.evaluate_tier(obj, 100 * 86_400), AccessTier::Cold);
        assert_eq!(tracker.transitions().len(), 1);
        assert_eq!(tracker.transitions()[0].to, AccessTier::Cold);

        // 5 accesses within 7 days -> Hot.
        let base = 101 * 86_400;
        for i in 0..5 {
            tracker.record_access(obj, false, base + i * 60);
        }
        assert_eq!(tracker.evaluate_tier(obj, base + 600), AccessTier::Hot);
        assert_eq!(tracker.transitions().last().unwrap().to, AccessTier::Hot);
    }
}

/// Alias used by `ChainActor` node-local access observation.
pub type AccessTiering = AccessTierTracker;
