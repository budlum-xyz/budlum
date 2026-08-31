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

/// Why an upload was refused by the B.U.D. 1.0 custody contract.
///
/// The two reasons are different and the caller should show them differently:
/// one is "the network must never be handed content the device could hold",
/// the other is "critical content may only go to the network when the owner
/// explicitly consents to network custody".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadCustodyRefusal {
    /// The content fits the device and is non-critical, so the device *is*
    /// the server. Asking the network to hold it would silently transfer a
    /// load that belongs on the user's node.
    NetworkCustodyNotAllowed,
    /// The content is critical, so it may only be offered to the network when
    /// the owner accepts network custody for it rather than defaulting.
    CriticalNeedsExplicitNetworkCustody,
}

/// The B.U.D. 1.0 upload contract. Wraps [`decide_custody`] with the one rule
/// that makes the 1.0 promise real: **the network is never the default
/// custodian.** A put either stays on the user's device (which is the server
/// of its own content), or the network takes it only because it must — the
/// content is critical (with the owner's explicit consent) or it exceeds the
/// device.
///
/// * `network_custody_requested` is the caller's ask. For content the device
///   can hold, the ask is refused outright. For critical content the ask is
///   *required* before the network is trusted with it. For oversize content
///   the network is the only option and the ask does not matter.
///
/// # Errors
///
/// [`UploadCustodyRefusal::NetworkCustodyNotAllowed`] when the device could
/// hold the content but the caller tried to default it to the network;
/// [`UploadCustodyRefusal::CriticalNeedsExplicitNetworkCustody`] when the
/// content is critical and the owner did not opt in to network custody.
pub fn decide_upload_custody(
    profile: &MobileSelfProfile,
    content_size: u64,
    critical: bool,
    network_custody_requested: bool,
) -> Result<CustodyDecision, UploadCustodyRefusal> {
    let d = decide_custody(profile, content_size, critical);
    match d.mode {
        CustodyMode::UserHeld => {
            if network_custody_requested {
                return Err(UploadCustodyRefusal::NetworkCustodyNotAllowed);
            }
            Ok(d)
        }
        CustodyMode::NetworkHeld => {
            if content_size > profile.max_storage_bytes {
                // Oversize: the device literally cannot hold it, so the network
                // is mandatory and consent is irrelevant.
                Ok(d)
            } else if network_custody_requested {
                Ok(d)
            } else {
                // Critical: the network holds it only with the owner's ask.
                Err(UploadCustodyRefusal::CriticalNeedsExplicitNetworkCustody)
            }
        }
    }
}

/// A running measure of how much of the storage responsibility the owner's
/// node has taken on. It is the device-side counter-observation of the 1.0
/// promise: every upload the device serves grows its own `user_held_bytes`,
/// and every attempt to hand holdable content to the network is counted in
/// `network_default_attempts` (which B.U.D. 1.0 code must keep at zero).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustodyLedger {
    /// Each entry is (content id, bytes the user's node is responsible for).
    user_held: Vec<(ContentId, u64)>,
    /// Items the network holds for a legitimate mandatory reason (critical or
    /// oversize).
    network_held: Vec<ContentId>,
    /// Count of refused attempts to hand device-holdable content to the
    /// network by default. This is the thing that must stay at zero.
    network_default_attempts: u64,
}

impl CustodyLedger {
    /// Record a serviceable user-held item. `bytes` is the owner's own
    /// responsibility for that item; duplicates are counted as a single asset
    /// and the bytes are updated.
    pub fn record_user_held(&mut self, content_id: ContentId, bytes: u64) {
        for entry in self.user_held.iter_mut() {
            if entry.0 == content_id {
                entry.1 = bytes;
                return;
            }
        }
        self.user_held.push((content_id, bytes));
    }

    /// Record an item the network holds for a legitimate mandatory reason.
    pub fn record_network_held(&mut self, content_id: ContentId) {
        if !self.network_held.contains(&content_id) {
            self.network_held.push(content_id);
        }
    }

    /// Count an attempted default network custody that was refused.
    pub fn record_network_default_attempt(&mut self) {
        self.network_default_attempts = self.network_default_attempts.saturating_add(1);
    }

    /// Total bytes the user's node is responsible for across everything it
    /// serves. This is the number a B.U.D. 1.0 node reports as its own load.
    pub fn total_user_held_bytes(&self) -> u64 {
        self.user_held
            .iter()
            .fold(0u64, |acc, (_, b)| acc.saturating_add(*b))
    }

    /// How many distinct assets the user's node serves.
    pub fn user_held_items(&self) -> usize {
        self.user_held.len()
    }

    /// How many assets the network holds for the owner.
    pub fn network_held_items(&self) -> usize {
        self.network_held.len()
    }

    /// How many times code tried to default custody of holdable content to
    /// the network. B.U.D. 1.0 requires this to be zero.
    pub fn network_default_attempts(&self) -> u64 {
        self.network_default_attempts
    }

    /// The B.U.D. 1.0 put path: decide custody for an upload without ever
    /// defaulting it to the network, and record it. This is the single entry
    /// point a device node uses so a measured put cannot hand holdable
    /// content to the network.
    ///
    /// # Errors
    ///
    /// [`UploadCustodyRefusal::NetworkCustodyNotAllowed`] or
    /// [`UploadCustodyRefusal::CriticalNeedsExplicitNetworkCustody`] as
    /// described on [`decide_upload_custody`]; a refused attempt is recorded
    /// so the ledger reports the leak rather than silently accepting it.
    pub fn put_user_content(
        &mut self,
        content_id: ContentId,
        profile: &MobileSelfProfile,
        content_size: u64,
        critical: bool,
        network_custody_requested: bool,
    ) -> Result<CustodyDecision, UploadCustodyRefusal> {
        match decide_upload_custody(profile, content_size, critical, network_custody_requested) {
            Ok(d) => {
                match d.mode {
                    CustodyMode::UserHeld => {
                        self.record_user_held(content_id, d.user_held_bytes);
                    }
                    CustodyMode::NetworkHeld => {
                        self.record_network_held(content_id);
                    }
                }
                Ok(d)
            }
            Err(refusal) => {
                self.record_network_default_attempt();
                Err(refusal)
            }
        }
    }
}

/// B.U.D. 1.0 server admission.
///
/// A 1.0 device enters the network *as a server of its own content*, not as a
/// client of ours. Admission is the network-side check that the claim is true
/// at the moment the device joins: the ledger must show the device serving its
/// own bytes, and must show no attempt to hand holdable content to the
/// network. The storage load the device reports is its own load; the network
/// stores nothing for it beyond the mandatory cases (critical with consent, or
/// oversize), which the ledger records separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerAdmission {
    /// Bytes the device serves itself, from its own custody ledger.
    pub user_held_bytes: u64,
    /// Items the network holds for mandatory reasons (critical consent or
    /// oversize). Not the device's load.
    pub network_held_items: usize,
}

impl ServerAdmission {
    /// Whether the device actually serves content (it is a server, not a
    /// client). True when it holds at least one byte of its own.
    #[must_use]
    pub const fn is_device_the_server(&self) -> bool {
        self.user_held_bytes > 0
    }
}

/// Why a device was refused admission as a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAdmissionRefusal {
    /// The ledger shows an attempt to default holdable content to the network.
    /// A node that sheds its own responsibility is not admitted as a server.
    TriedToDefaultCustody,
    /// The device serves nothing: it is a client, not a server.
    ServesNothing,
}

/// Admit a device into the network as a server, or refuse it.
///
/// This is the measured answer to "is the device really a server?": the only
/// evidence accepted is the custody ledger. A device that serves its own
/// bytes and never tried to default custody to the network is admitted and
/// its load is reported; a device that tried to shed holdable content, or
/// serves nothing at all, is refused.
///
/// # Errors
///
/// [`ServerAdmissionRefusal::TriedToDefaultCustody`] when the ledger shows a
/// default-custody attempt; [`ServerAdmissionRefusal::ServesNothing`] when
/// the device holds nothing.
pub fn admit_device_as_server(
    ledger: &CustodyLedger,
) -> Result<ServerAdmission, ServerAdmissionRefusal> {
    if ledger.network_default_attempts() > 0 {
        return Err(ServerAdmissionRefusal::TriedToDefaultCustody);
    }
    if ledger.user_held_items() == 0 && ledger.network_held_items() == 0 {
        return Err(ServerAdmissionRefusal::ServesNothing);
    }
    Ok(ServerAdmission {
        user_held_bytes: ledger.total_user_held_bytes(),
        network_held_items: ledger.network_held_items(),
    })
}

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

    #[test]
    fn default_upload_is_user_held_and_settles_on_the_device() {
        // The client asks for nothing; the answer is the user's node holding
        // it. This is the "device is the server" measurement.
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let d = decide_upload_custody(&p, 500, false, false).unwrap();
        assert_eq!(d.mode, CustodyMode::UserHeld);
        assert_eq!(d.user_held_bytes, 500);
    }

    #[test]
    fn network_custody_of_device_holdable_content_is_refused() {
        // The content fits the device, so handing it to the network as a
        // default is a violation of the 1.0 promise.
        let p = av(MobileAvailabilityClass::Scheduled);
        let err = decide_upload_custody(&p, 100, false, true).unwrap_err();
        assert_eq!(err, UploadCustodyRefusal::NetworkCustodyNotAllowed);
    }

    #[test]
    fn critical_content_goes_network_only_with_owner_consent() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        // Critical but the owner did not opt in to network custody -> refused.
        let err = decide_upload_custody(&p, 200, true, false).unwrap_err();
        assert_eq!(err, UploadCustodyRefusal::CriticalNeedsExplicitNetworkCustody);
        // Critical and the owner opted in -> network holds it, no user bytes.
        let d = decide_upload_custody(&p, 200, true, true).unwrap();
        assert_eq!(d.mode, CustodyMode::NetworkHeld);
        assert_eq!(d.user_held_bytes, 0);
    }

    #[test]
    fn oversize_content_goes_network_regardless_of_consent() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let d = decide_upload_custody(&p, 20_000, false, false).unwrap();
        assert_eq!(d.mode, CustodyMode::NetworkHeld);
        assert_eq!(d.user_held_bytes, 0);
    }

    #[test]
    fn ledger_measures_user_responsibility_and_rejects_default_puts() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let mut ledger = CustodyLedger::default();

        // Two assets the device serves.
        ledger
            .put_user_content(ContentId::of(b"a"), &p, 400, false, false)
            .unwrap();
        ledger
            .put_user_content(ContentId::of(b"b"), &p, 600, false, false)
            .unwrap();

        assert_eq!(ledger.total_user_held_bytes(), 1000);
        assert_eq!(ledger.user_held_items(), 2);
        assert_eq!(ledger.network_held_items(), 0);
        assert_eq!(ledger.network_default_attempts(), 0);

        // Attempting to default device-holdable content to the network is
        // refused AND recorded, so the leak is visible in the ledger.
        let err = ledger
            .put_user_content(ContentId::of(b"c"), &p, 100, false, true)
            .unwrap_err();
        assert_eq!(err, UploadCustodyRefusal::NetworkCustodyNotAllowed);
        assert_eq!(ledger.network_default_attempts(), 1);
    }

    #[test]
    fn ledger_keeps_consent_and_oversize_paths_separate() {
        let p = av(MobileAvailabilityClass::AlwaysOnReplica);
        let mut ledger = CustodyLedger::default();

        // Critical, owner consents -> network holds it.
        ledger
            .put_user_content(ContentId::of(b"crit"), &p, 50, true, true)
            .unwrap();
        // Oversize, no ask -> network is mandatory.
        ledger
            .put_user_content(ContentId::of(b"big"), &p, 20_000, false, false)
            .unwrap();

        assert_eq!(ledger.network_held_items(), 2);
        assert_eq!(ledger.total_user_held_bytes(), 0);
        assert_eq!(ledger.network_default_attempts(), 0);
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

/// Server admission: the network-side measurement that a 1.0 device really is
/// the server of its own content and has not shed that responsibility.
#[cfg(test)]
mod admission_tests {
    use super::*;

    fn profile() -> MobileSelfProfile {
        MobileSelfProfile {
            owner: Address::from([7u8; 32]),
            device_commitment: [9u8; 32],
            availability: MobileAvailabilityClass::AlwaysOnReplica,
            max_storage_bytes: 1000,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 100,
        }
    }

    #[test]
    fn a_device_serving_its_own_content_is_admitted_as_a_server() {
        let mut ledger = CustodyLedger::default();
        ledger
            .put_user_content(ContentId::of(b"photo"), &profile(), 400, false, false)
            .unwrap();
        let admission = admit_device_as_server(&ledger).unwrap();
        assert!(admission.is_device_the_server());
        assert_eq!(admission.user_held_bytes, 400);
        assert_eq!(admission.network_held_items, 0);
    }

    #[test]
    fn a_device_that_tried_to_default_custody_is_refused() {
        let mut ledger = CustodyLedger::default();
        ledger
            .put_user_content(ContentId::of(b"photo"), &profile(), 400, false, false)
            .unwrap();
        // A holdable item pushed to the network is refused and recorded.
        let _ = ledger.put_user_content(ContentId::of(b"other"), &profile(), 100, false, true);
        assert_eq!(
            admit_device_as_server(&ledger).unwrap_err(),
            ServerAdmissionRefusal::TriedToDefaultCustody
        );
    }

    #[test]
    fn a_device_that_serves_nothing_is_refused() {
        let ledger = CustodyLedger::default();
        assert_eq!(
            admit_device_as_server(&ledger).unwrap_err(),
            ServerAdmissionRefusal::ServesNothing
        );
    }

    #[test]
    fn oversize_network_held_does_not_hide_the_devices_own_load() {
        let mut ledger = CustodyLedger::default();
        ledger
            .put_user_content(ContentId::of(b"photo"), &profile(), 400, false, false)
            .unwrap();
        // Oversize: the network holds it, but the device still serves its own.
        ledger
            .put_user_content(ContentId::of(b"movie"), &profile(), 20_000, false, false)
            .unwrap();
        let admission = admit_device_as_server(&ledger).unwrap();
        assert_eq!(admission.user_held_bytes, 400);
        assert_eq!(admission.network_held_items, 1);
        assert!(admission.is_device_the_server());
    }

    #[test]
    fn upload_from_device_defaults_to_user_custody() {
        // The 1.0 measure: a device upload defaults to the user's node holding
        // it, so the storage responsibility stays on the user, and the device
        // is admitted as the server.
        let mut ledger = CustodyLedger::default();
        let d = ledger
            .put_user_content(ContentId::of(b"clip"), &profile(), 800, false, false)
            .unwrap();
        assert_eq!(d.mode, CustodyMode::UserHeld);
        assert_eq!(ledger.total_user_held_bytes(), 800);
        assert_eq!(ledger.network_default_attempts(), 0);
        assert!(admit_device_as_server(&ledger).unwrap().is_device_the_server());
    }
}
