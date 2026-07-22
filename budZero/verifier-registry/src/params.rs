//! Tunable economic / timing parameters for the registry.
//!
//! Parameters are governance / config driven, never hard-coded.
//! [`RegistryParams::default`] provides sane devnet defaults.

use serde::{Deserialize, Serialize};

/// Fixed-point scale factor (1_000_000 == 100%).
pub const FIXED_POINT_SCALE: u64 = 1_000_000;

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
            // 50% — equivocation is severe.
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE / 2,
            // 1% — downtime is light.
            liveness_slash_ratio_fixed: FIXED_POINT_SCALE / 100,
            // 100% — proven malice burns the whole bond.
            malicious_slash_ratio_fixed: FIXED_POINT_SCALE,
        }
    }
}

#[cfg(test)]
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
