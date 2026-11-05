//! The access layer: per-object access estimates and tier records.
//!
//! The estimate is kept per object and it is node-local: reads are not
//! transactions, so no chain state carries it and no state root folds it.
//! Windows are counted in epochs, the same time unit the registry uses.
//!
//! A tier transition is recorded, never executed. At testnet launch the
//! Slow-class codecs are closed, so the conversion this layer would ask
//! for is an object replacement on a layer-transition ground, and that
//! flow is proposed separately.

use std::collections::BTreeMap;

/// An object is named by its commitment.
pub type ObjectKey = [u8; 32];

/// The tier an object's estimate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// At least the hot count of accesses inside the hot window.
    Hot,
    /// Above the cold allowance and below the hot count.
    Normal,
    /// At most the cold allowance of accesses inside the cold window.
    Cold,
}

/// The tier transition one observation records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierTransition {
    /// The hot threshold was crossed at this observation.
    ToHot,
    /// The object stayed below the cold threshold for the whole streak the
    /// rules name: a conversion to the smallest Slow-class representation
    /// is due. At launch this is recorded only and nothing converts.
    SlowConversionDue,
    /// No threshold was crossed.
    None,
}

/// The thresholds. Windows are epochs; the testnet defaults convert the
/// day figures the rules name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieringRules {
    /// The cold window in epochs: at most `cold_accesses` inside it.
    pub cold_window_epochs: u64,
    /// The hot window in epochs: at least `hot_accesses` inside it.
    pub hot_window_epochs: u64,
    /// The access count the hot window needs.
    pub hot_accesses: u32,
    /// The access count the cold window allows.
    pub cold_accesses: u32,
    /// Epochs below the cold threshold before a conversion is due.
    pub cold_streak_epochs: u64,
}

impl Default for TieringRules {
    fn default() -> Self {
        Self::TESTNET_DEFAULT
    }
}

impl TieringRules {
    /// Epochs per day at the testnet default: one-hour epochs, the same
    /// assumption the audit parameters carry.
    pub const TESTNET_EPOCHS_PER_DAY: u64 = 24;

    /// The testnet defaults, in epochs. The cold window is ninety days
    /// (2160 epochs) with at most one access; the hot window is seven days
    /// (168 epochs) with at least five accesses; a conversion is due after
    /// thirty cold days (720 epochs). TESTNET-DEFAULT values are launch
    /// parameters, not protocol constants.
    pub const TESTNET_DEFAULT: Self = Self {
        cold_window_epochs: 90 * Self::TESTNET_EPOCHS_PER_DAY,
        hot_window_epochs: 7 * Self::TESTNET_EPOCHS_PER_DAY,
        hot_accesses: 5,
        cold_accesses: 1,
        cold_streak_epochs: 30 * Self::TESTNET_EPOCHS_PER_DAY,
    };
}

/// The per-object access estimates.
#[derive(Debug, Clone, Default)]
pub struct AccessTiering {
    rules: TieringRules,
    /// Per object: epoch -> access count, only epochs the windows can    /// still reach.
    days: BTreeMap<ObjectKey, BTreeMap<u64, u32>>,
}

impl AccessTiering {
    /// Record one access to `key` at `epoch`. Epochs no window can reach
    /// are dropped, so the map stays bounded by the rules.
    pub fn record_access(&mut self, key: &ObjectKey, epoch: u64) {
        let retention = self.retention_epochs();
        let days = self.days.entry(*key).or_default();
        days.retain(|&e, _| e.saturating_add(retention) >= epoch);
        let count = days.entry(epoch).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// The tier the estimate reads for `key` at `epoch`.
    ///
    /// WIRING: unwired - the proposal flow reads this when the Slow-class
    /// codecs open and a layer-transition replacement can be proposed.
    #[must_use]
    pub fn tier_of(&self, key: &ObjectKey, epoch: u64) -> Tier {
        if self.accesses_in(key, epoch, self.rules.hot_window_epochs)
            >= u64::from(self.rules.hot_accesses)
        {
            Tier::Hot
        } else if self.accesses_in(key, epoch, self.rules.cold_window_epochs)
            <= u64::from(self.rules.cold_accesses)
        {
            Tier::Cold
        } else {
            Tier::Normal
        }
    }

    /// The transition this observation records. The conversion itself is
    /// never performed here.
    ///
    /// WIRING: unwired - the proposal flow reads this when the Slow-class
    /// codecs open and a layer-transition replacement can be proposed.
    #[must_use]
    pub fn transition_at(&self, key: &ObjectKey, epoch: u64) -> TierTransition {
        if self.tier_of(key, epoch) == Tier::Hot {
            return TierTransition::ToHot;
        }
        // The object must have been below the cold threshold at every
        // epoch of the streak, each judged on its own rolling window.
        let streak = self.rules.cold_streak_epochs.max(1);
        for back in 0..streak {
            let at = epoch.saturating_sub(back);
            if self.tier_of(key, at) != Tier::Cold {
                return TierTransition::None;
            }
        }
        TierTransition::SlowConversionDue
    }

    /// The accesses to `key` in the `window` epochs ending at `epoch`.
    fn accesses_in(&self, key: &ObjectKey, epoch: u64, window: u64) -> u64 {
        let Some(days) = self.days.get(key) else {
            return 0;
        };
        let from = epoch.saturating_sub(window.saturating_sub(1));
        days.iter()
            .filter(|(&e, _)| e >= from && e <= epoch)
            .map(|(_, &c)| u64::from(c))
            .sum()
    }

    /// Epochs any window can still reach.
    fn retention_epochs(&self) -> u64 {
        self.rules.cold_window_epochs + self.rules.cold_streak_epochs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> ObjectKey {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&n.to_le_bytes());
        k
    }

    #[test]
    fn hot_needs_five_accesses_in_seven_days() {
        let mut a = AccessTiering::default();
        let k = key(1);
        for e in [20, 60, 100, 140] {
            a.record_access(&k, e);
        }
        assert_eq!(a.tier_of(&k, 168), Tier::Normal);
        a.record_access(&k, 150);
        assert_eq!(a.tier_of(&k, 168), Tier::Hot);
        assert_eq!(a.transition_at(&k, 168), TierTransition::ToHot);
    }

    #[test]
    fn cold_is_at_most_one_access_in_ninety_days() {
        let mut a = AccessTiering::default();
        let k = key(2);
        a.record_access(&k, 0);
        a.record_access(&k, 100);
        assert_eq!(a.tier_of(&k, 200), Tier::Normal);
        // Past the window the old access leaves the count at one.
        assert_eq!(a.tier_of(&k, 2200), Tier::Cold);
        // A never-accessed object is cold.
        assert_eq!(a.tier_of(&key(3), 2200), Tier::Cold);
    }

    #[test]
    fn thirty_cold_days_record_a_due_conversion() {
        let mut a = AccessTiering::default();
        let k = key(4);
        a.record_access(&k, 0);
        assert_eq!(
            a.transition_at(&k, 720),
            TierTransition::SlowConversionDue
        );
        // A second access inside the streak's reach breaks the streak.
        let mut b = AccessTiering::default();
        b.record_access(&k, 0);
        b.record_access(&k, 500);
        assert_eq!(b.transition_at(&k, 720), TierTransition::None);
    }

    #[test]
    fn epochs_no_window_reaches_are_evicted() {
        let mut a = AccessTiering::default();
        let k = key(5);
        a.record_access(&k, 0);
        a.record_access(&k, 3000);
        assert_eq!(a.days.get(&k).map_or(0, BTreeMap::len), 1);
    }
}
