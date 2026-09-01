//! B.U.D. 1.0 share: the NFT that marks a share, and the custody contract.
//!
//! 1.0 is sharing, not storage rental. A share is a marker - the NFT - that
//! says "this content, held on this endpoint, is shared". The bytes never move
//! to the network: the share records where the holder keeps them (the
//! endpoint, the user's own device or their own server), and the network is
//! never the default custodian. A share whose custody decision would push the
//! content network-held is refused, not quietly re-homed.
//!
//! The only charge is the share NFT's transaction fee. There is no storage fee
//! because there is no storage: the network holds a marker, the user holds the
//! bytes. The single screen assembles from these shares, so everything the
//! user can see is shown in one place with its responsibility attributed.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use crate::storage::mobile_self::{decide_custody, CustodyLedger, CustodyMode, MobileSelfProfile};
use crate::storage::one_view::{EndpointRef, SingleScreenView};
use crate::storage::server_admission::{ServerAdmission, ServerAdmissionRefusal};
use std::collections::BTreeMap;

/// A 1.0 share: content held on an endpoint, marked as shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    pub id: u64,
    pub content_id: ContentId,
    pub size: u64,
    /// The endpoint the holder keeps the bytes on: the user's own device or
    /// their own server. 1.0 content is never moved off it.
    pub endpoint: Address,
}

/// Why a share was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRefusal {
    /// The custody decision for this size is network-held (the device cannot
    /// hold it). 1.0 refuses rather than let the network become the
    /// custodian: there is no 1.0 economy that pays for network custody.
    WouldBeNetworkHeld,
    /// The profile behind the share is not valid (zero owner, zero device
    /// commitment, or zero declared capacity). A marker cannot be attributed
    /// to a holder that has no identity.
    ProfileInvalid,
    /// The endpoint the bytes are claimed to sit on is the zero address: a
    /// marker pointing nowhere. 1.0 says where the holder keeps the bytes, so
    /// a share without a real endpoint is refused, not recorded.
    EndpointMissing,
}

/// The 1.0 share registry: share NFTs and the one-screen assembly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OneShareRegistry {
    next_id: u64,
    shares: BTreeMap<u64, Share>,
}

impl OneShareRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a share. Refuses any share whose custody decision would be
    /// network-held: in 1.0 the network is never the custodian, and refusing
    /// is the only honest answer to a put the device cannot hold. The marker
    /// itself must also be attributable: an invalid profile or a zero
    /// endpoint is refused before anything is recorded.
    ///
    /// # Errors
    ///
    /// [`ShareRefusal::ProfileInvalid`] when the profile fails its own
    /// validation; [`ShareRefusal::EndpointMissing`] when the endpoint is the
    /// zero address; [`ShareRefusal::WouldBeNetworkHeld`] when the device
    /// cannot hold the bytes under the profile.
    pub fn create(
        &mut self,
        profile: &MobileSelfProfile,
        content_id: ContentId,
        size: u64,
        endpoint: Address,
    ) -> Result<u64, ShareRefusal> {
        // A marker names a holder and a place. If either is missing the share
        // is refused before the custody decision, so no invalid marker can
        // reach the registry (and the single screen) at all.
        if profile.validate().is_err() {
            return Err(ShareRefusal::ProfileInvalid);
        }
        if endpoint == Address::zero() {
            return Err(ShareRefusal::EndpointMissing);
        }
        // 1.0 shares are never critical: critical means paid replicas and
        // network custody, which is a 2.0 notion. Passing `false` here is the
        // whole of the 1.0 custody policy.
        if decide_custody(profile, size, false).mode == CustodyMode::NetworkHeld {
            return Err(ShareRefusal::WouldBeNetworkHeld);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.shares.insert(
            id,
            Share {
                id,
                content_id,
                size,
                endpoint,
            },
        );
        Ok(id)
    }

    /// Remove the share marker. The bytes stay with the holder; deleting the
    /// share deletes the marker only, which is why it cannot be refused.
    pub fn remove(&mut self, id: u64) -> bool {
        self.shares.remove(&id).is_some()
    }

    /// Every share as an endpoint ref, for the single screen.
    #[must_use]
    pub fn endpoint_refs(&self) -> Vec<EndpointRef> {
        self.shares
            .values()
            .map(|s| EndpointRef {
                content_id: s.content_id,
                size: s.size,
                critical: false,
            })
            .collect()
    }

    /// The single screen: every share the user holds, custody attributed by
    /// the profile. Honest by construction, because [`Self::create`] already
    /// refused every network-held put.
    #[must_use]
    pub fn screen(&self, profile: &MobileSelfProfile) -> SingleScreenView {
        let mut view = SingleScreenView::assemble(profile, &self.endpoint_refs());
        view.device_is_server = self
            .admit_as_server()
            .map(|a| a.is_device_the_server())
            .unwrap_or(false);
        view
    }

    /// The device behind this registry, measured as a server: a custody
    /// ledger built from the registry's own shares (every share is
    /// user-held, because [`Self::create`] refused every network-held put)
    /// is handed to the admission rule. The screen shows the result; the
    /// rule itself lives in
    /// [`admit_device_as_server`](crate::storage::server_admission::admit_device_as_server).
    pub fn admit_as_server(&self) -> Result<ServerAdmission, ServerAdmissionRefusal> {
        let mut ledger = CustodyLedger::default();
        for s in self.shares.values() {
            ledger.record_user_held(s.content_id, s.size);
        }
        crate::storage::server_admission::admit_device_as_server(&ledger)
    }

    /// True when every share's custody decision is user-held. In 1.0 this is
    /// always true: the only path to network custody was refused at creation.
    #[must_use]
    pub fn all_user_held(&self, profile: &MobileSelfProfile) -> bool {
        self.shares
            .values()
            .all(|s| decide_custody(profile, s.size, false).mode == CustodyMode::UserHeld)
    }

    /// 1.0 charges only the share NFT's transaction fee; there is no storage
    /// fee because the network stores no bytes. This is a function, not a
    /// comment, so the claim cannot silently drift to a nonzero number: the
    /// test pins it to zero for any registry.
    #[must_use]
    pub const fn storage_fee_owed_usd(&self) -> f64 {
        0.0
    }
}

#[cfg(test)]
mod one_share_tests {
    use super::*;
    use crate::storage::mobile_self::MobileAvailabilityClass;

    fn profile(max_storage_bytes: u64) -> MobileSelfProfile {
        MobileSelfProfile {
            owner: Address::from([7u8; 32]),
            device_commitment: [9u8; 32],
            availability: MobileAvailabilityClass::AlwaysOnReplica,
            max_storage_bytes,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 100,
        }
    }

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn creating_a_share_that_fits_is_user_held() {
        let mut reg = OneShareRegistry::new();
        let id = reg
            .create(&profile(1000), ContentId([1; 32]), 500, addr(0xA1))
            .unwrap();
        let share = reg.shares.get(&id).unwrap();
        assert_eq!(share.endpoint, addr(0xA1));
        assert!(reg.all_user_held(&profile(1000)));
    }

    #[test]
    fn a_share_too_big_for_the_device_is_refused_not_rehomed() {
        let mut reg = OneShareRegistry::new();
        let refused = reg
            .create(&profile(1000), ContentId([2; 32]), 5000, addr(0xA2))
            .unwrap_err();
        assert_eq!(refused, ShareRefusal::WouldBeNetworkHeld);
        assert!(
            reg.shares.is_empty(),
            "a refused share must not be recorded"
        );
    }

    #[test]
    fn the_screen_is_honest_and_holds_zero_network_bytes() {
        let p = profile(1000);
        let mut reg = OneShareRegistry::new();
        reg.create(&p, ContentId([3; 32]), 300, addr(0xA3)).unwrap();
        reg.create(&p, ContentId([4; 32]), 400, addr(0xA4)).unwrap();

        let screen = reg.screen(&p);
        assert!(screen.honest_custody(&p));
        assert_eq!(screen.user_held_bytes(), 700);
        assert_eq!(
            screen.network_held_bytes(),
            0,
            "1.0 never holds network bytes"
        );
    }

    #[test]
    fn removing_a_share_removes_only_the_marker() {
        let p = profile(1000);
        let mut reg = OneShareRegistry::new();
        let id = reg.create(&p, ContentId([5; 32]), 250, addr(0xA5)).unwrap();
        assert!(reg.remove(id));
        assert!(!reg.remove(id), "removing the same share twice is a no-op");
        assert!(reg.endpoint_refs().is_empty());
    }

    #[test]
    fn a_share_needs_a_valid_profile_and_a_real_endpoint() {
        let mut reg = OneShareRegistry::new();
        // An unvalidated profile (zero owner) cannot attribute a marker.
        let bad_profile = MobileSelfProfile {
            owner: Address::zero(),
            device_commitment: [9u8; 32],
            availability: MobileAvailabilityClass::AlwaysOnReplica,
            max_storage_bytes: 1000,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 100,
        };
        assert_eq!(
            reg.create(&bad_profile, ContentId([7; 32]), 100, addr(1))
                .unwrap_err(),
            ShareRefusal::ProfileInvalid
        );
        // The zero endpoint points nowhere: refused, and nothing is recorded.
        assert_eq!(
            reg.create(&profile(1000), ContentId([7; 32]), 100, Address::zero())
                .unwrap_err(),
            ShareRefusal::EndpointMissing
        );
        assert!(reg.shares.is_empty(), "refused shares must not be recorded");
    }

    #[test]
    fn one_zero_charges_no_storage_fee() {
        let p = profile(1000);
        let mut reg = OneShareRegistry::new();
        for n in 0..5u8 {
            // n + 1 keeps every endpoint non-zero: the zero address is a
            // refused endpoint, not a holder.
            reg.create(&p, ContentId([n; 32]), 100, addr(n + 1))
                .unwrap();
        }
        assert_eq!(reg.storage_fee_owed_usd(), 0.0);
    }

    #[test]
    fn the_share_nft_is_the_only_charge_and_bytes_stay_with_the_holder() {
        // The whole 1.0 promise in one test: the registry records markers on
        // the holder's endpoint, custody is user-held, the screen is honest,
        // and there is no storage fee - the NFT's transaction fee is the only
        // charge, so the bytes never become the network's to bill for.
        let p = profile(1000);
        let mut reg = OneShareRegistry::new();
        let endpoint = addr(0xEE);
        let id = reg
            .create(&p, ContentId([6; 32]), 640, endpoint)
            .expect("a fitting share must be created");
        assert_eq!(reg.shares.get(&id).unwrap().endpoint, endpoint);
        assert!(reg.all_user_held(&p));
        assert!(reg.screen(&p).honest_custody(&p));
        assert_eq!(reg.screen(&p).network_held_bytes(), 0);
        assert_eq!(reg.storage_fee_owed_usd(), 0.0);
    }
}
