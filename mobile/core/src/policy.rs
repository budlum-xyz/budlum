//! Runtime policy of a mobile validator (section 7.9.4).

use crate::error::CoreError;
use crate::quota::{QUOTA_DEFAULT_BYTES, QUOTA_MAX_BYTES, QUOTA_MIN_BYTES};

/// How the core uses the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Only an unmetered network (Wi-Fi). The default.
    UnmeteredOnly,
    /// Metered networks are allowed, with a daily cap in megabytes.
    Metered { daily_cap_mb: u32 },
}

/// How the core uses power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerPolicy {
    /// Run while charging, or while the battery is above 50 percent and
    /// battery saver is off. The default.
    ChargingOrBatteryAbove50,
    /// Run only while charging.
    ChargingOnly,
}

/// The policy a host may set. Thermal pause is not a field the host can
/// clear: [`Policy::thermal_pause`] is always true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Network use.
    pub network: NetworkPolicy,
    /// Power use.
    pub power: PowerPolicy,
    /// Always true. The host cannot disable it.
    pub thermal_pause: bool,
    /// Custody quota in bytes.
    pub quota_bytes: u64,
    /// Serve symbols on an unmetered network.
    pub serve_symbols: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            network: NetworkPolicy::UnmeteredOnly,
            power: PowerPolicy::ChargingOrBatteryAbove50,
            thermal_pause: true,
            quota_bytes: QUOTA_DEFAULT_BYTES,
            serve_symbols: true,
        }
    }
}

impl Policy {
    /// A policy with the given quota. Quota outside 1 GiB..64 GiB is refused.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the quota is outside the class range.
    pub fn with_quota(quota_bytes: u64) -> Result<Self, CoreError> {
        let mut policy = Self::default();
        policy.set_quota(quota_bytes)?;
        Ok(policy)
    }

    /// Set the custody quota.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the quota is outside 1 GiB..64 GiB.
    pub fn set_quota(&mut self, quota_bytes: u64) -> Result<(), CoreError> {
        if quota_bytes < QUOTA_MIN_BYTES || quota_bytes > QUOTA_MAX_BYTES {
            return Err(CoreError::new(
                "mobile_quota_out_of_range",
                "a mobile quota is 1 GiB to 64 GiB",
            ));
        }
        self.quota_bytes = quota_bytes;
        Ok(())
    }

    /// Refuse any attempt to disable the thermal pause.
    ///
    /// # Errors
    ///
    /// Always [`CoreError`] when `enabled` is false. True is a no-op.
    pub fn set_thermal_pause(&mut self, enabled: bool) -> Result<(), CoreError> {
        if !enabled {
            return Err(CoreError::new(
                "mobile_thermal_pause_locked",
                "the thermal pause cannot be disabled",
            ));
        }
        self.thermal_pause = true;
        Ok(())
    }

    /// Whether the default policy uses only an unmetered network.
    #[must_use]
    pub fn unmetered_only_by_default() -> bool {
        matches!(Self::default().network, NetworkPolicy::UnmeteredOnly)
    }
}
