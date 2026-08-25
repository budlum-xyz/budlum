//! P12-9: Mobile Self - the mobile node profile, and hosting your own B.U.D.
//!
//! Mobile Self lets people run a Budlum node on their own phone. This module
//! defines the working profile that fits what a mobile device actually has:
//! battery, bandwidth, and storage are all limited.
//!
//! # What it provides
//!
//! - **Battery-aware challenge policy:** verification frequency follows the
//!   battery level.
//! - **NAT connectivity:** relay/STUN for mobile nodes sitting behind a NAT.
//! - **Self-hosted B.U.D.:** serving B.U.D. storage from the device.
//! - **Lightweight sync:** stateless verification.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// A mobile node profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileNodeProfile {
    /// Node address.
    pub address: Address,
    /// Device kind.
    pub device_type: DeviceType,
    /// Battery state.
    pub battery: BatteryStatus,
    /// Network state.
    pub network: NetworkStatus,
    /// Storage state.
    pub storage: StorageStatus,
    /// Challenge policy, tuned to the battery state.
    pub challenge_policy: ChallengePolicy,
    /// NAT traversal state.
    pub nat_status: NatTraversalStatus,
    /// When it was last seen (epoch).
    pub last_seen_epoch: u64,
}

/// The kind of device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// A smartphone.
    Phone,
    /// Tablet.
    Tablet,
    /// A laptop on a mobile connection.
    Laptop,
    /// An IoT device.
    IoT,
}

/// Battery state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BatteryStatus {
    /// Battery level, 0-100.
    pub level_pct: u8,
    /// Is it charging?
    pub charging: bool,
    /// Estimated minutes remaining.
    pub estimated_minutes: u32,
}

impl BatteryStatus {
    pub fn full() -> Self {
        Self {
            level_pct: 100,
            charging: true,
            estimated_minutes: u32::MAX,
        }
    }

    pub fn critical() -> Self {
        Self {
            level_pct: 5,
            charging: false,
            estimated_minutes: 15,
        }
    }

    /// The working mode implied by the battery level.
    pub fn power_mode(&self) -> PowerMode {
        if self.charging {
            PowerMode::Full
        } else if self.level_pct > 50 {
            PowerMode::Normal
        } else if self.level_pct > 20 {
            PowerMode::PowerSaving
        } else {
            PowerMode::Critical
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.level_pct > 100 {
            return Err("BatteryStatus level_pct must be <= 100".into());
        }
        if !self.charging && self.level_pct == 0 && self.estimated_minutes > 0 {
            return Err("BatteryStatus empty battery cannot report remaining minutes".into());
        }
        Ok(())
    }
}

/// Power mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerMode {
    /// Full power: accept every task.
    Full,
    /// Normal: standard tasks.
    Normal,
    /// Saving: essential tasks only.
    PowerSaving,
    /// Critical: listen only, accept no tasks.
    Critical,
}

/// Network state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Connection kind.
    pub connection_type: ConnectionType,
    /// Estimated bandwidth, in Kbps.
    pub bandwidth_kbps: u64,
    /// Gecikme (ms).
    pub latency_ms: u32,
    /// NAT tipi.
    pub nat_type: NatType,
    /// Is there public IP reachability?
    pub public_ip: bool,
}

/// The kind of connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    WiFi,
    Cellular4G,
    Cellular5G,
    Ethernet,
    Unknown,
}

/// NAT tipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// NAT yok - genel IP.
    None,
    /// Full cone NAT: the most permissive.
    FullCone,
    /// Restricted Cone NAT.
    RestrictedCone,
    /// Port Restricted Cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT: the most restrictive.
    Symmetric,
    /// Unknown.
    Unknown,
}

impl NetworkStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.bandwidth_kbps == 0 {
            return Err("NetworkStatus bandwidth_kbps must be >= 1".into());
        }
        if self.latency_ms > 60_000 {
            return Err("NetworkStatus latency_ms too high".into());
        }
        if self.nat_type == NatType::None && !self.public_ip {
            return Err("NetworkStatus NatType::None requires public_ip".into());
        }
        Ok(())
    }
}

/// Storage state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    /// Toplam depolama (bayt).
    pub total_bytes: u64,
    /// Usable storage, in bytes.
    pub available_bytes: u64,
    /// Space reserved for B.U.D., in bytes.
    pub bud_reserved_bytes: u64,
}

impl StorageStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.total_bytes == 0 {
            return Err("StorageStatus total_bytes must be >= 1".into());
        }
        if self.available_bytes > self.total_bytes {
            return Err("StorageStatus available_bytes cannot exceed total_bytes".into());
        }
        if self.bud_reserved_bytes > self.total_bytes {
            return Err("StorageStatus bud_reserved_bytes cannot exceed total_bytes".into());
        }
        Ok(())
    }

    /// Space available to B.U.D., in bytes.
    pub fn bud_available(&self) -> u64 {
        self.bud_reserved_bytes.min(self.available_bytes)
    }

    /// Is there enough storage, meaning at least 1 GB for B.U.D.?
    pub fn is_sufficient_for_bud(&self) -> bool {
        self.bud_available() >= 1_073_741_824 // 1 GB
    }
}

/// The challenge policy, tuned automatically to the battery state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePolicy {
    /// The most challenges accepted per epoch.
    pub max_challenges_per_epoch: u32,
    /// The most proof tasks accepted.
    pub max_proof_tasks: u32,
    /// Is sync-committee participation on?
    pub sync_committee_participation: bool,
    /// Storage attestation kabul ediyor mu?
    pub storage_attestation: bool,
    /// Background sync aktif mi?
    pub background_sync: bool,
}

impl ChallengePolicy {
    /// How many peers a node in this mode should hold open.
    ///
    /// `node.rs` used to answer this with `if mobile_mode { 10 } else { 50 }`,
    /// a second table for the same question this type already answers. Two
    /// tables for one question drift: this one distinguishes four power modes
    /// and that one distinguished two, so a phone at 5% battery and a phone on
    /// mains held the same ten connections while every other budget on the
    /// device had already been cut to zero.
    ///
    /// Derived from the work the mode admits rather than picked separately. A
    /// node accepting no challenges and no proof tasks has nothing to gossip
    /// about and needs only enough peers to follow the chain; one running at
    /// full power carries the server budget.
    #[must_use]
    pub const fn peer_budget(mode: PowerMode, server_budget: usize) -> usize {
        match mode {
            PowerMode::Full => server_budget,
            PowerMode::Normal => 20,
            PowerMode::PowerSaving => 10,
            // Not zero: a node that accepts no work still has to hear about
            // blocks, or it stops being a node rather than becoming a frugal
            // one.
            PowerMode::Critical => 4,
        }
    }

    /// Builds a challenge policy from the battery state.
    pub fn from_power_mode(mode: PowerMode) -> Self {
        match mode {
            PowerMode::Full => Self {
                max_challenges_per_epoch: 100,
                max_proof_tasks: 10,
                sync_committee_participation: true,
                storage_attestation: true,
                background_sync: true,
            },
            PowerMode::Normal => Self {
                max_challenges_per_epoch: 50,
                max_proof_tasks: 5,
                sync_committee_participation: true,
                storage_attestation: true,
                background_sync: true,
            },
            PowerMode::PowerSaving => Self {
                max_challenges_per_epoch: 10,
                max_proof_tasks: 1,
                sync_committee_participation: false,
                storage_attestation: true,
                background_sync: false,
            },
            PowerMode::Critical => Self {
                max_challenges_per_epoch: 0,
                max_proof_tasks: 0,
                sync_committee_participation: false,
                storage_attestation: false,
                background_sync: false,
            },
        }
    }

    /// The default policy, for normal mode.
    pub fn default_policy() -> Self {
        Self::from_power_mode(PowerMode::Normal)
    }
}

/// NAT traversal state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatTraversalStatus {
    /// Is a relay server in use?
    pub using_relay: bool,
    /// Relay sunucusu adresi.
    pub relay_address: Option<String>,
    /// Was the NAT type detected via the STUN server?
    pub nat_detected: bool,
    /// Did punch-through succeed?
    pub hole_punched: bool,
}

impl NatTraversalStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.using_relay {
            let relay = self.relay_address.as_ref().ok_or_else(|| {
                "NatTraversalStatus relay_address required when using_relay".to_string()
            })?;
            if relay.is_empty()
                || relay.len() > 256
                || relay.bytes().any(|b| b.is_ascii_whitespace())
            {
                return Err("NatTraversalStatus relay_address invalid".into());
            }
            if self.hole_punched {
                return Err("NatTraversalStatus cannot use relay and claim hole_punched".into());
            }
        }
        Ok(())
    }
}

impl MobileNodeProfile {
    /// Creates a new mobile node profile.
    pub fn new(address: Address, device_type: DeviceType) -> Self {
        Self {
            address,
            device_type,
            battery: BatteryStatus::full(),
            network: NetworkStatus {
                connection_type: ConnectionType::WiFi,
                bandwidth_kbps: 10_000,
                latency_ms: 50,
                nat_type: NatType::Unknown,
                public_ip: false,
            },
            storage: StorageStatus {
                total_bytes: 64_000_000_000, // 64 GB
                available_bytes: 32_000_000_000,
                bud_reserved_bytes: 5_000_000_000,
            },
            challenge_policy: ChallengePolicy::default_policy(),
            nat_status: NatTraversalStatus::default(),
            last_seen_epoch: 0,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.address == Address::zero() {
            return Err("MobileNodeProfile address cannot be zero".into());
        }
        self.battery.validate()?;
        self.network.validate()?;
        self.storage.validate()?;
        self.nat_status.validate()?;
        if self.last_seen_epoch == u64::MAX {
            return Err("MobileNodeProfile last_seen_epoch sentinel invalid".into());
        }
        Ok(())
    }

    pub fn try_update_battery(
        &mut self,
        level_pct: u8,
        charging: bool,
        estimated_minutes: u32,
    ) -> Result<(), String> {
        let battery = BatteryStatus {
            level_pct,
            charging,
            estimated_minutes,
        };
        battery.validate()?;
        self.battery = battery;
        self.challenge_policy = ChallengePolicy::from_power_mode(self.battery.power_mode());
        Ok(())
    }

    /// Updates the battery state and retunes the challenge policy.
    pub fn update_battery(&mut self, level_pct: u8, charging: bool, estimated_minutes: u32) {
        self.battery = BatteryStatus {
            level_pct,
            charging,
            estimated_minutes,
        };
        self.challenge_policy = ChallengePolicy::from_power_mode(self.battery.power_mode());
    }

    /// Updates the NAT state.
    pub fn update_nat(&mut self, nat_type: NatType, public_ip: bool) {
        self.network.nat_type = nat_type;
        self.network.public_ip = public_ip;

        // Symmetric NAT means a relay is required
        if nat_type == NatType::Symmetric && !public_ip {
            self.nat_status.using_relay = true;
            self.nat_status.hole_punched = false;
        } else if nat_type == NatType::None || public_ip {
            self.nat_status.using_relay = false;
            self.nat_status.hole_punched = true;
        }

        self.nat_status.nat_detected = true;
    }

    pub fn set_relay_address(&mut self, relay_address: String) -> Result<(), String> {
        self.nat_status.using_relay = true;
        self.nat_status.relay_address = Some(relay_address);
        self.nat_status.hole_punched = false;
        self.nat_status.validate()
    }

    /// Can the node take on active tasks?
    pub fn can_accept_tasks(&self) -> bool {
        self.challenge_policy.max_challenges_per_epoch > 0
            || self.challenge_policy.max_proof_tasks > 0
    }

    /// Returns a summary of the profile.
    pub fn summary(&self) -> String {
        format!(
            "MobileNode({}{}): battery={}%, mode={:?}, nat={:?}, tasks={}",
            &self.address.to_string()[..8],
            self.device_type_suffix(),
            self.battery.level_pct,
            self.battery.power_mode(),
            self.network.nat_type,
            if self.can_accept_tasks() { "yes" } else { "no" },
        )
    }

    fn device_type_suffix(&self) -> &'static str {
        match self.device_type {
            DeviceType::Phone => ":phone",
            DeviceType::Tablet => ":tablet",
            DeviceType::Laptop => ":laptop",
            DeviceType::IoT => ":iot",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from([1u8; 32])
    }

    #[test]
    fn mobile_profile_default_policy() {
        let profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert!(profile.can_accept_tasks());
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 50);
    }

    #[test]
    fn battery_power_modes() {
        assert_eq!(BatteryStatus::full().power_mode(), PowerMode::Full);
        assert_eq!(
            BatteryStatus {
                level_pct: 60,
                charging: false,
                estimated_minutes: 300,
            }
            .power_mode(),
            PowerMode::Normal
        );
        assert_eq!(
            BatteryStatus {
                level_pct: 30,
                charging: false,
                estimated_minutes: 120,
            }
            .power_mode(),
            PowerMode::PowerSaving
        );
        assert_eq!(BatteryStatus::critical().power_mode(), PowerMode::Critical);
    }

    #[test]
    fn update_battery_adjusts_policy() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 50);

        // Pil kritik
        profile.update_battery(5, false, 15);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 0);
        assert!(!profile.can_accept_tasks());

        // Plug it in to charge
        profile.update_battery(5, true, 60);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 100);
    }

    #[test]
    fn nat_symmetric_requires_relay() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::Symmetric, false);
        assert!(profile.nat_status.using_relay);
        assert!(!profile.nat_status.hole_punched);
    }

    #[test]
    fn nat_public_ip_no_relay() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::None, true);
        assert!(!profile.nat_status.using_relay);
        assert!(profile.nat_status.hole_punched);
    }

    #[test]
    fn storage_sufficient_for_bud() {
        let storage = StorageStatus {
            total_bytes: 64_000_000_000,
            available_bytes: 10_000_000_000,
            bud_reserved_bytes: 5_000_000_000,
        };
        assert!(storage.is_sufficient_for_bud());
        assert_eq!(storage.bud_available(), 5_000_000_000);
    }

    #[test]
    fn storage_insufficient_for_bud() {
        let storage = StorageStatus {
            total_bytes: 64_000_000_000,
            available_bytes: 500_000_000,
            bud_reserved_bytes: 5_000_000_000,
        };
        assert!(!storage.is_sufficient_for_bud());
        assert_eq!(storage.bud_available(), 500_000_000);
    }

    #[test]
    fn challenge_policy_scales_with_power() {
        let full = ChallengePolicy::from_power_mode(PowerMode::Full);
        let normal = ChallengePolicy::from_power_mode(PowerMode::Normal);
        let saving = ChallengePolicy::from_power_mode(PowerMode::PowerSaving);
        let critical = ChallengePolicy::from_power_mode(PowerMode::Critical);

        assert!(full.max_challenges_per_epoch > normal.max_challenges_per_epoch);
        assert!(normal.max_challenges_per_epoch > saving.max_challenges_per_epoch);
        assert_eq!(critical.max_challenges_per_epoch, 0);
        assert!(full.sync_committee_participation);
        assert!(!saving.sync_committee_participation);
    }

    #[test]
    fn profile_summary_format() {
        let profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        let summary = profile.summary();
        assert!(summary.contains("phone"));
        assert!(summary.contains("100%"));
    }

    #[test]
    fn mobile_profile_validate_rejects_impossible_battery() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert!(profile.validate().is_ok());
        assert!(profile.try_update_battery(101, false, 1).is_err());
    }

    #[test]
    fn mobile_profile_validate_rejects_invalid_storage_accounting() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.storage.available_bytes = profile.storage.total_bytes.saturating_add(1);
        assert!(profile.validate().unwrap_err().contains("available_bytes"));
    }

    #[test]
    fn relay_address_required_for_symmetric_nat_profile() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::Symmetric, false);
        assert!(profile.validate().unwrap_err().contains("relay_address"));
        profile
            .set_relay_address("relay.budlum.local:4001".into())
            .unwrap();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn exported_mobile_module_compiles_and_rejects_zero_address() {
        let profile = MobileNodeProfile::new(Address::zero(), DeviceType::Phone);
        assert!(profile
            .validate()
            .unwrap_err()
            .contains("address cannot be zero"));
    }
}

#[cfg(test)]
mod peer_budget_tests {
    use super::*;

    const SERVER_BUDGET: usize = 50;

    /// The budget must fall as the device's own policy shuts work down.
    ///
    /// The defect this replaces: `node.rs` decided the peer cap with
    /// `if mobile_mode { 10 } else { 50 }`, a two-way split against a
    /// four-way profile. A phone on mains and a phone at 5% both held ten
    /// connections, even though at 5% the profile already declines every
    /// challenge and every proof task. The device paid the largest recurring
    /// cost it has, an open connection, for work it had refused.
    #[test]
    fn peer_budget_falls_with_the_power_mode() {
        let full = ChallengePolicy::peer_budget(PowerMode::Full, SERVER_BUDGET);
        let normal = ChallengePolicy::peer_budget(PowerMode::Normal, SERVER_BUDGET);
        let saving = ChallengePolicy::peer_budget(PowerMode::PowerSaving, SERVER_BUDGET);
        let critical = ChallengePolicy::peer_budget(PowerMode::Critical, SERVER_BUDGET);

        assert_eq!(
            full, SERVER_BUDGET,
            "a charging device pays the server budget"
        );
        assert!(
            full > normal && normal > saving && saving > critical,
            "each step down in power must cost connections: \
             {full} > {normal} > {saving} > {critical}"
        );
        assert!(
            critical > 0,
            "a node that accepts no work must still hear about blocks, or it \
             has stopped being a node rather than become a frugal one"
        );
    }

    /// The two tables must agree about the case that made them disagree.
    ///
    /// Pinned as a relationship rather than as numbers: whenever the policy
    /// says no challenges and no proof tasks, the peer budget has to be
    /// strictly below the one for a device that is accepting work. The old
    /// split could not express this, because it did not know the difference.
    #[test]
    fn a_device_that_declines_work_holds_fewer_peers_than_one_that_does_not() {
        for mode in [
            PowerMode::Full,
            PowerMode::Normal,
            PowerMode::PowerSaving,
            PowerMode::Critical,
        ] {
            let policy = ChallengePolicy::from_power_mode(mode);
            let budget = ChallengePolicy::peer_budget(mode, SERVER_BUDGET);
            let accepting = policy.max_challenges_per_epoch > 0 || policy.max_proof_tasks > 0;
            if accepting {
                assert!(
                    budget >= ChallengePolicy::peer_budget(PowerMode::PowerSaving, SERVER_BUDGET),
                    "{mode:?} accepts work and must not be budgeted below a saving device"
                );
            } else {
                assert!(
                    budget < ChallengePolicy::peer_budget(PowerMode::PowerSaving, SERVER_BUDGET),
                    "{mode:?} accepts no work at all and must cost less than one that does"
                );
            }
        }
    }

    /// A flat battery must move the peer budget, not only the task budget.
    #[test]
    fn draining_the_battery_lowers_the_budget_the_profile_reports() {
        let mut profile = MobileNodeProfile::new(Address::from([9u8; 32]), DeviceType::Phone);
        let charged = ChallengePolicy::peer_budget(profile.battery.power_mode(), SERVER_BUDGET);

        profile
            .try_update_battery(5, false, 15)
            .expect("5% on battery is a valid reading");
        let flat = ChallengePolicy::peer_budget(profile.battery.power_mode(), SERVER_BUDGET);

        assert!(
            flat < charged,
            "a battery going from full to 5% must cost connections: {charged} -> {flat}"
        );
        assert!(
            !profile.can_accept_tasks(),
            "the profile already declined every task at this level, which is \
             why the peer budget had to move with it"
        );
    }
}
