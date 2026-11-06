//! The presence message, defined once (directive section 7.8).
//!
//! A validator proves it is online by BLS-signing one message per presence
//! window. The node verifies and aggregates that signature; the mobile core
//! produces it. Built separately on each side, a one-byte drift would make
//! every phone look absent and suspend it, and nothing would fail at compile
//! time. So the message lives in the crate both sides bind (K-4).
//!
//! # The bytes
//!
//! Section 7.8 item 2 names the fields: `SHA3-256(BDLM_PRESENCE_V1 || chain_id
//! || window || class)`. Invariant G-5 sits above every package and requires
//! every hash input to be length-prefixed, so each field is preceded by its
//! byte length as a little-endian `u64`:
//!
//! ```text
//! SHA3-256( "BDLM_PRESENCE_V1"
//!         || 8u64 LE || chain_id LE
//!         || 8u64 LE || window   LE
//!         || 1u64 LE || class tag )
//! ```
//!
//! This is byte for byte the layout of the node-side presence work in flight
//! (#70, `src/validators/presence.rs`). The vectors in the tests were computed
//! independently of this code and pin it. A layout without the length
//! prefixes (#45, `src/registry/presence.rs`) hashes to a different digest
//! for the same window; see BLG-301 in `docs/audit/FINDINGS.md`.
//!
//! The class is inside the signed bytes on purpose: two signatures for one
//! window under two classes are a provable double sign (section 7.8 item 8).

use crate::ValidatorClass;
use sha3::{Digest, Sha3_256};

/// The gossipsub topic presence signals travel on (section 7.8 item 3).
pub const PRESENCE_TOPIC: &str = "/budlum/presence/1";

/// The domain tag of the presence message. Listed in the inventory at
/// `src/crypto/domain_tags.rs`.
pub const PRESENCE_DOMAIN_TAG: &[u8] = b"BDLM_PRESENCE_V1";

/// The 32-byte message a validator BLS-signs for `window` (section 7.8
/// item 2, length-prefixed per G-5).
#[must_use]
pub fn presence_message(chain_id: u64, window: u64, class: ValidatorClass) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(PRESENCE_DOMAIN_TAG);
    hasher.update(8u64.to_le_bytes());
    hasher.update(chain_id.to_le_bytes());
    hasher.update(8u64.to_le_bytes());
    hasher.update(window.to_le_bytes());
    hasher.update(1u64.to_le_bytes());
    hasher.update([class.tag()]);
    hasher.finalize().into()
}

/// The presence window an epoch falls in, for a class: windows are counted
/// from epoch zero in units of [`ValidatorClass::presence_window_epochs`].
#[must_use]
pub const fn window_of_epoch(epoch: u64, class: ValidatorClass) -> u64 {
    epoch / class.presence_window_epochs()
}

/// The first epoch of a presence window.
#[must_use]
pub const fn first_epoch_of_window(window: u64, class: ValidatorClass) -> u64 {
    window.saturating_mul(class.presence_window_epochs())
}

#[cfg(test)]
mod tests {
    use super::{first_epoch_of_window, presence_message, window_of_epoch};
    use crate::ValidatorClass;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Vectors computed with Python's `hashlib.sha3_256` over the layout in
    /// the module documentation, not with this code. Testnet chain id 45261.
    #[test]
    fn presence_message_matches_independent_vectors() {
        assert_eq!(
            hex(&presence_message(45_261, 7, ValidatorClass::Mobile)),
            "d8d5ba6f3f2de2719bf7fa3a53b27fc0eb98baa9ecc98c0683253fb09cbd5f92"
        );
        assert_eq!(
            hex(&presence_message(
                45_261,
                7,
                ValidatorClass::MobileOpportunistic
            )),
            "afdb7f87f37319cc852d447ce2d0f852f5ac2faab57929b720511a298cae1176"
        );
        assert_eq!(
            hex(&presence_message(45_261, 7, ValidatorClass::Full)),
            "9daed004bf85771874f7eafce9e525e757cc82ec434de78874ba49c4cef50ced"
        );
        assert_eq!(
            hex(&presence_message(1, 0, ValidatorClass::Full)),
            "5645a3e63432420528cb4bab9542ddfe57bab234605cfc431fcd69df72bce42a"
        );
    }

    /// The unprefixed layout `tag || chain_id || window || class` gives
    /// another digest for the same inputs. Pinned so a "simplification" back
    /// to it fails here instead of suspending every phone.
    #[test]
    fn the_unprefixed_layout_is_not_the_presence_message() {
        assert_ne!(
            hex(&presence_message(45_261, 7, ValidatorClass::Mobile)),
            "6772963e8c6b2ca769ab2832d6e8f642739bbd6053209567a08a51c434b77b24"
        );
    }

    /// Every input field changes the digest: chain, window and class.
    #[test]
    fn every_field_is_bound() {
        let base = presence_message(45_261, 7, ValidatorClass::Mobile);
        assert_ne!(base, presence_message(45_262, 7, ValidatorClass::Mobile));
        assert_ne!(base, presence_message(45_261, 8, ValidatorClass::Mobile));
        assert_ne!(base, presence_message(45_261, 7, ValidatorClass::Full));
    }

    #[test]
    fn windows_count_from_epoch_zero() {
        assert_eq!(window_of_epoch(0, ValidatorClass::Mobile), 0);
        assert_eq!(window_of_epoch(3, ValidatorClass::Mobile), 0);
        assert_eq!(window_of_epoch(4, ValidatorClass::Mobile), 1);
        assert_eq!(window_of_epoch(9, ValidatorClass::Full), 9);
        assert_eq!(first_epoch_of_window(2, ValidatorClass::Mobile), 8);
        assert_eq!(
            first_epoch_of_window(u64::MAX, ValidatorClass::Mobile),
            u64::MAX
        );
    }
}
