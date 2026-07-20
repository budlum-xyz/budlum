//! Mobile Self profile primitives (Phase 12 / ARENA4).
//!
//! Mobile devices may self-host B.U.D. data, but they must never be marketed as
//! always-online storage. Critical data should use paid replicas.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaRecommendation {
    SelfHostOnly,
    AddPaidReplica,
    RequirePaidReplica,
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

    pub fn recommendation_for_content(
        &self,
        content_size: u64,
        critical: bool,
    ) -> ReplicaRecommendation {
        if critical {
            return ReplicaRecommendation::RequirePaidReplica;
        }
        if content_size > self.max_storage_bytes {
            return ReplicaRecommendation::AddPaidReplica;
        }
        match self.availability {
            MobileAvailabilityClass::AlwaysOnReplica => ReplicaRecommendation::SelfHostOnly,
            MobileAvailabilityClass::Scheduled | MobileAvailabilityClass::Opportunistic => {
                ReplicaRecommendation::AddPaidReplica
            }
        }
    }

    pub fn availability_label(&self) -> &'static str {
        match self.availability {
            MobileAvailabilityClass::Opportunistic => "self-hosted: available when device is online",
            MobileAvailabilityClass::Scheduled => "self-hosted: available during scheduled windows",
            MobileAvailabilityClass::AlwaysOnReplica => "replica-grade mobile node",
        }
    }

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
    pub fn validate_against_profile(&self, profile: &MobileSelfProfile) -> Result<(), String> {
        profile.validate()?;
        if self.owner != profile.owner {
            return Err("MobileSelfContentPolicy owner/profile mismatch".into());
        }
        if self.critical && self.required_paid_replicas == 0 {
            return Err("critical Mobile Self content requires paid replicas".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn profile(availability: MobileAvailabilityClass) -> MobileSelfProfile {
        MobileSelfProfile {
            owner: addr(1),
            device_commitment: [9u8; 32],
            availability,
            max_storage_bytes: 1024,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 10,
        }
    }

    #[test]
    fn opportunistic_mobile_self_never_claims_always_online() {
        let p = profile(MobileAvailabilityClass::Opportunistic);
        assert!(p.validate().is_ok());
        assert!(p.availability_label().contains("when device is online"));
        assert!(!p.availability_label().contains("always online"));
    }

    #[test]
    fn critical_content_requires_paid_replica() {
        let p = profile(MobileAvailabilityClass::AlwaysOnReplica);
        assert_eq!(
            p.recommendation_for_content(10, true),
            ReplicaRecommendation::RequirePaidReplica
        );
    }

    #[test]
    fn critical_policy_without_paid_replica_is_rejected() {
        let p = profile(MobileAvailabilityClass::Opportunistic);
        let policy = MobileSelfContentPolicy {
            content_id: ContentId::of(b"important"),
            owner: p.owner,
            critical: true,
            required_paid_replicas: 0,
            self_host_allowed: true,
        };
        assert!(policy.validate_against_profile(&p).is_err());
    }
}
