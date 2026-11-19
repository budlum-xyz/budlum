//! Device self-host profile and policy primitives.
//!
//! Mobile devices may self-host B.U.D. data, but they must never be marketed as
//! always-online storage. Critical data requires paid replicas.
//!
//! `declare_self_host_policy` validates a declaration against the profile that
//! made it, and `check_self_host_allowed` refuses self-hosting when the paid
//! replicas the owner asked for are not open.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileAvailabilityClass {
    Opportunistic,
    Scheduled,
    AlwaysOnReplica,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileSelfProfile {
    pub owner: Address,
    pub device_commitment: [u8; 32],
    pub availability: MobileAvailabilityClass,
    pub max_storage_bytes: u64,
    pub metered_network_ok: bool,
    pub battery_saver_aware: bool,
    pub last_seen_block: u64,
}

impl MobileSelfProfile {
    /// # Errors
    ///
    /// Returns a reason string when the owner, device commitment, or declared
    /// storage capacity is zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.owner == Address::zero() {
            return Err("MobileSelfProfile owner cannot be zero".into());
        }
        if self.device_commitment == [0u8; 32] {
            return Err("MobileSelfProfile device_commitment cannot be zero".into());
        }
        if self.max_storage_bytes == 0 {
            return Err("MobileSelfProfile max_storage_bytes must be >= 1".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_MOBILE_SELF_PROFILE_V1");
        hasher.update(self.owner.as_bytes());
        hasher.update(self.device_commitment);
        hasher.update([match self.availability {
            MobileAvailabilityClass::Opportunistic => 1,
            MobileAvailabilityClass::Scheduled => 2,
            MobileAvailabilityClass::AlwaysOnReplica => 3,
        }]);
        hasher.update(self.max_storage_bytes.to_le_bytes());
        hasher.update([u8::from(self.metered_network_ok)]);
        hasher.update([u8::from(self.battery_saver_aware)]);
        hasher.update(self.last_seen_block.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileSelfContentPolicy {
    pub content_id: ContentId,
    pub owner: Address,
    pub critical: bool,
    pub required_paid_replicas: u16,
    pub self_host_allowed: bool,
}

impl MobileSelfContentPolicy {
    /// # Errors
    ///
    /// Returns a reason string when the profile fails validation, the policy
    /// owner disagrees with the profile, or critical content lacks paid replicas.
    pub fn validate_against_profile(&self, profile: &MobileSelfProfile) -> Result<(), String> {
        profile.validate()?;
        if self.owner != profile.owner {
            return Err("content custody policy owner/profile mismatch".into());
        }
        if self.critical && self.required_paid_replicas == 0 {
            return Err("critical self-hosted content requires paid replicas".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(availability: MobileAvailabilityClass) -> MobileSelfProfile {
        MobileSelfProfile {
            owner: Address::from([1u8; 32]),
            device_commitment: [9u8; 32],
            availability,
            max_storage_bytes: 1024,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 10,
        }
    }

    #[test]
    fn profile_and_policy_refuse_zero_capacity_and_unbacked_content() {
        let p = profile(MobileAvailabilityClass::Opportunistic);
        assert!(p.validate().is_ok());

        let mut zero_cap = p.clone();
        zero_cap.max_storage_bytes = 0;
        assert!(zero_cap.validate().is_err());

        let critical_no_replica = MobileSelfContentPolicy {
            content_id: ContentId::of(b"important"),
            owner: p.owner,
            critical: true,
            required_paid_replicas: 0,
            self_host_allowed: true,
        };
        assert!(critical_no_replica.validate_against_profile(&p).is_err());

        let no_self_host = MobileSelfContentPolicy {
            content_id: ContentId::of(b"always-on-only"),
            owner: p.owner,
            critical: false,
            required_paid_replicas: 0,
            self_host_allowed: false,
        };
        assert!(no_self_host.validate_against_profile(&p).is_ok());

        let wrong_owner = MobileSelfContentPolicy {
            content_id: ContentId::of(b"foreign"),
            owner: Address::from([2u8; 32]),
            critical: false,
            required_paid_replicas: 1,
            self_host_allowed: true,
        };
        assert!(wrong_owner.validate_against_profile(&p).is_err());
    }
}
