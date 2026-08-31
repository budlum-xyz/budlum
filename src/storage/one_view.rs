//! B.U.D. 1.0 single-screen share surface.
//!
//! 1.0 is sharing, not storage rental. The user's device (or their own server)
//! holds the content; the network is never the default custodian. This module
//! is the one screen that shows everything the user can see, with every item
//! carrying the custody decision that says who is responsible for its bytes.
//!
//! The responsibility contract is bound here, not merely described: custody is
//! decided by the profile, never supplied by whoever builds the list, and the
//! surface commits to its attribution with a digest. An item shown as held by
//! the user is one whose custody decision really is `UserHeld`; a screen that
//! misattributes responsibility fails its own honesty check.

use crate::storage::content_id::ContentId;
use crate::storage::mobile_self::{
    decide_custody, CustodyDecision, CustodyMode, MobileSelfProfile,
};

/// One visible item offered to the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointRef {
    /// Content the item names.
    pub content_id: ContentId,
    /// Bytes the item is made of.
    pub size: u64,
    /// Whether the item is critical (paid replicas required, network-held).
    pub critical: bool,
}

/// One item on the screen, with the custody decision that answers who holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenItem {
    pub content_id: ContentId,
    pub size: u64,
    pub critical: bool,
    pub custody: CustodyDecision,
}

/// The single share surface: everything visible in one place, each item with
/// its responsibility attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleScreenView {
    pub items: Vec<ScreenItem>,
}

impl SingleScreenView {
    /// Assemble the screen from endpoint refs under a device profile.
    ///
    /// Custody is decided here, not supplied by the caller, so an item cannot
    /// be mis-attributed by whoever builds the list: the profile is the only
    /// input to the decision.
    #[must_use]
    pub fn assemble(profile: &MobileSelfProfile, refs: &[EndpointRef]) -> Self {
        let items = refs
            .iter()
            .map(|r| ScreenItem {
                content_id: r.content_id,
                size: r.size,
                critical: r.critical,
                custody: decide_custody(profile, r.size, r.critical),
            })
            .collect();
        Self { items }
    }

    /// Re-derive custody for every item and compare. True only when every item
    /// on the screen carries the decision the profile would produce for it -
    /// a screen with a forged attribution fails this check.
    #[must_use]
    pub fn honest_custody(&self, profile: &MobileSelfProfile) -> bool {
        self.items.iter().all(|item| {
            item.custody == decide_custody(profile, item.size, item.critical)
        })
    }

    /// Bytes the user's device is responsible for on this screen. The 1.0
    /// promise: this is the user's own load, never the network's.
    #[must_use]
    pub fn user_held_bytes(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.custody.mode == CustodyMode::UserHeld)
            .map(|i| i.custody.user_held_bytes)
            .fold(0, u64::saturating_add)
    }

    /// Bytes the network holds on this screen (critical-with-replica or
    /// oversize). The part the user's device is not responsible for.
    #[must_use]
    pub fn network_held_bytes(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.custody.mode == CustodyMode::NetworkHeld)
            .map(|i| i.size)
            .fold(0, u64::saturating_add)
    }

    /// The share contract: a digest over the ordered surface, so two viewers
    /// that see the same digest see the same list with the same responsibility
    /// attribution. Order-sensitive on purpose: two screens that list the same
    /// items in a different order are not the same view.
    #[must_use]
    pub fn contract_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"BDLM_SINGLE_SCREEN_V1");
        for item in &self.items {
            h.update(item.content_id.0);
            h.update(item.size.to_le_bytes());
            h.update([item.critical as u8, item.custody.mode as u8]);
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod one_view_tests {
    use super::*;
    use crate::core::address::Address;
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

    fn r(n: u8, size: u64, critical: bool) -> EndpointRef {
        EndpointRef {
            content_id: ContentId([n; 32]),
            size,
            critical,
        }
    }

    #[test]
    fn assemble_attributes_custody_from_the_profile() {
        let p = profile(1000);
        let view = SingleScreenView::assemble(
            &p,
            &[r(1, 500, false), r(2, 200, true), r(3, 20_000, false)],
        );
        assert_eq!(view.items.len(), 3);
        assert_eq!(view.items[0].custody.mode, CustodyMode::UserHeld);
        assert_eq!(view.items[1].custody.mode, CustodyMode::NetworkHeld);
        assert_eq!(view.items[2].custody.mode, CustodyMode::NetworkHeld);
    }

    #[test]
    fn assembled_screen_is_honest_and_a_forged_one_is_not() {
        let p = profile(1000);
        let view = SingleScreenView::assemble(&p, &[r(1, 500, false)]);
        assert!(view.honest_custody(&p));

        // Forge the same item into claiming the network holds it.
        let mut forged = view.clone();
        forged.items[0].custody = CustodyDecision {
            mode: CustodyMode::NetworkHeld,
            user_held_bytes: 0,
        };
        assert!(!forged.honest_custody(&p));
    }

    #[test]
    fn the_screen_separates_the_users_load_from_the_networks() {
        let p = profile(1000);
        let view = SingleScreenView::assemble(
            &p,
            &[r(1, 400, false), r(2, 600, false), r(3, 5000, false), r(4, 100, true)],
        );
        assert_eq!(view.user_held_bytes(), 1000);
        assert_eq!(view.network_held_bytes(), 5100);
    }

    #[test]
    fn the_contract_digest_is_deterministic_and_attribution_sensitive() {
        let p = profile(1000);
        let a = SingleScreenView::assemble(&p, &[r(1, 400, false), r(2, 100, true)]);
        let b = SingleScreenView::assemble(&p, &[r(1, 400, false), r(2, 100, true)]);
        assert_eq!(a.contract_digest(), b.contract_digest());

        // Changing an item's responsibility changes the contract.
        let mut flipped = a.clone();
        flipped.items[1].critical = false; // network-held becomes user-held
        assert_ne!(a.contract_digest(), flipped.contract_digest());
    }

    #[test]
    fn the_contract_digest_is_order_sensitive() {
        let p = profile(1000);
        let forward = SingleScreenView::assemble(&p, &[r(1, 400, false), r(2, 600, false)]);
        let reversed = SingleScreenView::assemble(&p, &[r(2, 600, false), r(1, 400, false)]);
        assert_ne!(forward.contract_digest(), reversed.contract_digest());
    }
}
