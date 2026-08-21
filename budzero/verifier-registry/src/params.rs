//! Tunable economic / timing parameters for the registry.
//!
//! Parameters are governance / config driven, never hard-coded.
//! [`RegistryParams::default`] provides sane devnet defaults.

use serde::{Deserialize, Serialize};

/// Fixed-point scale factor (1_000_000 == 100%).
pub const FIXED_POINT_SCALE: u64 = 1_000_000;

/// The penalty a slash of `slash_ratio_fixed` takes from `stake`, capped at
/// the bond.
///
/// This mirrors `budlum_core::core::chain_config::slash_penalty`. The two are
/// separate because this crate is in the BudZero workspace and does not depend
/// on `budlum-core`; `slash_expression_is_the_same_in_both_workspaces` in the
/// core tree compares them so the copy cannot drift silently.
///
/// The cap is not decoration. Written the obvious way, as
/// `((stake as u128 * ratio as u128) / SCALE as u128) as u64`, a ratio above
/// `FIXED_POINT_SCALE` produces a quotient wider than `u64` and the narrowing
/// truncates it. At `stake = u64::MAX` and `ratio = FIXED_POINT_SCALE + 1`
/// that turned a 100.0001% slash into one that took about 1.8e13 from a bond
/// of about 1.8e19, leaving the offender 99.9999% of the stake. See B35.
#[must_use]
pub fn slash_penalty(stake: u64, slash_ratio_fixed: u64) -> u64 {
    let quotient =
        (u128::from(stake) * u128::from(slash_ratio_fixed)) / u128::from(FIXED_POINT_SCALE);
    if quotient > u128::from(u64::MAX) {
        return stake;
    }
    let narrow = quotient as u64;
    if narrow > stake {
        stake
    } else {
        narrow
    }
}

/// Economic / timing parameters that gate participation and slashing.
///
/// `*_slash_ratio_fixed` values are `FIXED_POINT_SCALE`-scaled fractions in
/// `[0, FIXED_POINT_SCALE]` (e.g. `FIXED_POINT_SCALE / 2` == 50%).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryParams {
    /// Minimum stake required to *newly* register for a role.
    pub min_stake: u64,
    /// Number of epochs unbonded stake stays locked before withdrawal.
    pub unbonding_epochs: u64,
    /// Penalty ratio for equivocation / double-sign (severe).
    pub double_sign_slash_ratio_fixed: u64,
    /// Penalty ratio for liveness / downtime faults (light).
    pub liveness_slash_ratio_fixed: u64,
    /// Penalty ratio for provable malicious behaviour (maximal).
    pub malicious_slash_ratio_fixed: u64,
}

impl RegistryParams {
    /// Resolve the slash ratio for a given condition.
    pub fn slash_ratio(&self, condition: super::registry::SlashingCondition) -> u64 {
        use super::registry::SlashingCondition::*;
        match condition {
            DoubleSign => self.double_sign_slash_ratio_fixed,
            LivenessFault => self.liveness_slash_ratio_fixed,
            MaliciousBehaviour => self.malicious_slash_ratio_fixed,
        }
    }

    /// Validate parameter bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_stake == 0 {
            return Err("min_stake must be > 0".into());
        }
        if self.unbonding_epochs == 0 {
            return Err("unbonding_epochs must be > 0".into());
        }
        if self.double_sign_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("double_sign_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        if self.liveness_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("liveness_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        if self.malicious_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("malicious_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        Ok(())
    }
}

impl Default for RegistryParams {
    fn default() -> Self {
        RegistryParams {
            min_stake: 1_000,
            unbonding_epochs: 7,
            // 50% - equivocation is severe.
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE / 2,
            // 1% - downtime is light.
            liveness_slash_ratio_fixed: FIXED_POINT_SCALE / 100,
            // 100% - proven malice burns the whole bond.
            malicious_slash_ratio_fixed: FIXED_POINT_SCALE,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_params_are_valid() {
        assert!(RegistryParams::default().validate().is_ok());
    }

    #[test]
    fn zero_min_stake_rejected() {
        let p = RegistryParams {
            min_stake: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn slash_ratio_above_scale_rejected() {
        let p = RegistryParams {
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE + 1,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn slash_ratio_resolves_correctly() {
        let p = RegistryParams::default();
        assert_eq!(
            p.slash_ratio(super::super::registry::SlashingCondition::DoubleSign),
            FIXED_POINT_SCALE / 2
        );
        assert_eq!(
            p.slash_ratio(super::super::registry::SlashingCondition::LivenessFault),
            FIXED_POINT_SCALE / 100
        );
        assert_eq!(
            p.slash_ratio(super::super::registry::SlashingCondition::MaliciousBehaviour),
            FIXED_POINT_SCALE
        );
    }
}
