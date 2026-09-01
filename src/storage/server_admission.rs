//! Server admission for the 1.0 mobile-self profile: the network-side
//! measurement that a device really is the server of its own content.

use crate::storage::mobile_self::CustodyLedger;

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
    /// The device holds none of its own bytes: it is a client, not a server.
    /// Network-held items do not count toward this - they are not the
    /// device's load, so a device whose every upload went to the network
    /// (all oversize) is refused here rather than admitted as a server that
    /// would launder network custody as B.U.D. 1.0.
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
    // The device must serve at least one byte of its own. Network-held items
    // are not the device's load, so "has network items" is not evidence of
    // serving: without this, an all-oversize uploader (every byte network
    // held) would be admitted as a "server" while holding nothing.
    if ledger.total_user_held_bytes() == 0 {
        return Err(ServerAdmissionRefusal::ServesNothing);
    }
    Ok(ServerAdmission {
        user_held_bytes: ledger.total_user_held_bytes(),
        network_held_items: ledger.network_held_items(),
    })
}

/// Server admission: the network-side measurement that a 1.0 device really is
/// the server of its own content and has not shed that responsibility.
#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::core::address::Address;
    use crate::storage::content_id::ContentId;
    use crate::storage::mobile_self::{MobileAvailabilityClass, MobileSelfProfile};

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
    fn a_device_that_only_pushed_oversize_content_is_refused() {
        // Everything it uploaded went to the network (oversize), so the device
        // serves nothing of its own. The admission contract is "the device
        // serves its own bytes"; a node that holds nothing is a client, and
        // admitting it as a server would launder network custody as 1.0.
        let mut ledger = CustodyLedger::default();
        ledger
            .put_user_content(ContentId::of(b"movie"), &profile(), 20_000, false, false)
            .unwrap();
        assert_eq!(ledger.total_user_held_bytes(), 0);
        assert_eq!(
            admit_device_as_server(&ledger).unwrap_err(),
            ServerAdmissionRefusal::ServesNothing
        );
    }
}
