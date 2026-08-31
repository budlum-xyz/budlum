//! Mobile Self profile primitives.
//!
//! Mobile devices may self-host B.U.D. data, but they must never be marketed as
//! Always-online storage. Critical data should use paid replicas.
//!
//! `StorageRegistry::declare_self_host_policy` validates a declaration
//! against the profile that made it, and `check_self_host_allowed` refuses
//! self-hosting when the paid replicas the owner asked for are not open. The
//! rule that critical content needs a paid replica is enforced there rather
//! than only described here.

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
    /// # Errors
    ///
    /// Propagates `String` from the step that failed; its variants name the refused conditions.
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

    pub const fn recommendation_for_content(
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

    pub const fn availability_label(&self) -> &'static str {
        match self.availability {
            MobileAvailabilityClass::Opportunistic => {
                "self-hosted: available when device is online"
            }
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
    /// # Errors
    ///
    /// Propagates `String` from the step that failed; its variants name the refused conditions.
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

/// B.U.D. 1.0 semantics: in the 1.0 product, a user's device enters the network
/// *as a server-like node* and the device itself (not the network) carries the
/// storage responsibility. This measures exactly that, without adding any
/// network dependency: it is deterministic and unit-testable, and it is the
/// piece that says "the storage load lives on the user's node, not on us".
///
/// `CustodyMode` answers the question that decides who pays and who holds:
/// * [`CustodyMode::NetworkHeld`] - the network stores it (never true in 1.0).
/// * [`CustodyMode::UserHeld`] - the user's node stores it (the 1.0 default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    NetworkHeld,
    UserHeld,
}

/// The storage-custody decision for a single content item under a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyDecision {
    pub mode: CustodyMode,
    /// The bytes the user's node is responsible for (its own bytes only).
    pub user_held_bytes: u64,
}

/// Decide which mode a put uses. This is so the network never silently becomes
/// the custodian of 1.0 content: critical content always returns
/// `NetworkHeld` only through a paid replica decision, while non-critical
/// self-host-capable content stays `UserHeld` so the device is the server.
pub const fn decide_custody(
    profile: &MobileSelfProfile,
    content_size: u64,
    critical: bool,
) -> CustodyDecision {
    let mode = if critical {
        // A paid replica is required and the network holds it.
        CustodyMode::NetworkHeld
    } else if content_size <= profile.max_storage_bytes {
        // The device can hold it; it stays the server. User-held.
        CustodyMode::UserHeld
    } else {
        // Too big for this device -> the network (or another node) holds it.
        CustodyMode::NetworkHeld
    };
    let user_held_bytes = match mode {
        CustodyMode::UserHeld => content_size,
        CustodyMode::NetworkHeld => 0,
    };
    CustodyDecision {
        mode,
        user_held_bytes,
    }
}

/// In B.U.D. 1.0 the network is never the default custodian. Every put is
/// either held by the user's node (the robust, cheapest path) or goes to the
/// network only because the content is critical or exceeds the device.
#[cfg(test)]
mod custody_tests {
    use super::*;

    fn av(availability: MobileAvailabilityClass) -> MobileSelfProfile {
        MobileSelfProfile {
            owner: Address::from([7u8; 32]),
            device_commitment: [9u8; 32],
            availability,
            max_storage_bytes: 1000,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 100,
        }
    }

    #[test]
    fn user_content_within_device_capacity_is_user_held() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let d = decide_custody(&p, 500, false);
        assert_eq!(d.mode, CustodyMode::UserHeld);
        assert_eq!(d.user_held_bytes, 500);
    }

    #[test]
    fn device_becomes_a_server_not_a_passive_client() {
        // A scheduled phone that fits the content still hosts it (server-like),
        // so the responsibility sits with the user, never with us.
        let p = av(MobileAvailabilityClass::Scheduled);
        let d = decide_custody(&p, 300, false);
        assert_eq!(d.mode, CustodyMode::UserHeld);
    }

    #[test]
    fn critical_content_goes_network_held_and_no_user_bytes() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let d = decide_custody(&p, 200, true);
        assert_eq!(d.mode, CustodyMode::NetworkHeld);
        assert_eq!(d.user_held_bytes, 0);
    }

    #[test]
    fn content_larger_than_the_device_becomes_network_held() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let d = decide_custody(&p, 20_000, false);
        assert_eq!(d.mode, CustodyMode::NetworkHeld);
        assert_eq!(d.user_held_bytes, 0);
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
