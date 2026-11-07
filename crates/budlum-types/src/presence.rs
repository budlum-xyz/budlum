//! Convenience: shared wire types consumed across workspaces by mobile/core and mobile/ffi (`WP-11`).
//! The presence message and signal, defined once (directive section 7.8).
//!
//! A validator proves it is online by BLS-signing one message per presence
//! window. The node verifies and aggregates that signature; the mobile core
//! produces it. Built separately on each side, a one-byte drift would make
//! every phone look absent and suspend it, and nothing would fail at compile
//! time. So the message and the signal live in the crate both sides bind
//! (K-4).
//!
//! # The bytes
//!
//! Section 7.8 item 2 names the fields: `SHA3-256(BDLM_PRESENCE_V1 || chain_id
//! || window || class)`. Invariant G-5 sits above every package and says every
//! hash input is length-prefixed, the domain tag included, so each of the four
//! fields is preceded by its byte length as a little-endian `u64`:
//!
//! ```text
//! SHA3-256( 16u64 LE || "BDLM_PRESENCE_V1"
//!         ||  8u64 LE || chain_id LE
//!         ||  8u64 LE || window   LE
//!         ||  1u64 LE || class tag )
//! ```
//!
//! The preimage is 65 bytes. It is the layout of the mobile core stack (#82,
//! #88) and of the shared vector in `tests/vectors/presence/v1/`, which the
//! tests below read. Two node-side layouts in flight differ from it: #70 leaves
//! the tag unprefixed and #45 prefixes nothing. Each yields another digest for
//! the same window (pinned below), so a phone signing this message is absent
//! to either node until it calls [`presence_message`] instead of its own copy
//! (BLG-288, BLG-350 in `docs/audit/FINDINGS.md`).
//!
//! The class is inside the signed bytes on purpose: two signatures for one
//! window under two classes are a provable double sign (section 7.8 item 8).

use crate::{Address, ValidatorClass};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// The gossipsub topic presence signals travel on (section 7.8 item 3).
pub const PRESENCE_TOPIC: &str = "/budlum/presence/1";

/// The domain tag of the presence message. Listed in the inventory at
/// `src/crypto/domain_tags.rs`.
pub const PRESENCE_DOMAIN_TAG: &[u8] = b"BDLM_PRESENCE_V1";

/// The domain tag of the network hint. Listed in the same inventory.
pub const PRESENCE_HINT_DOMAIN_TAG: &[u8] = b"BDLM_PRESENCE_HINT_V1";

/// The byte length of [`presence_preimage`]: four length prefixes of eight
/// bytes, a 16-byte tag, two `u64` fields and the class byte.
pub const PRESENCE_PREIMAGE_LEN: usize = 8 + 16 + 8 + 8 + 8 + 8 + 8 + 1;

/// The bytes [`presence_message`] hashes, each field length-prefixed (G-5).
#[must_use]
pub fn presence_preimage(
    chain_id: u64,
    window: u64,
    class: ValidatorClass,
) -> [u8; PRESENCE_PREIMAGE_LEN] {
    let chain = chain_id.to_le_bytes();
    let win = window.to_le_bytes();
    let class_tag = [class.tag()];
    let fields: [&[u8]; 4] = [PRESENCE_DOMAIN_TAG, &chain, &win, &class_tag];
    let mut out = [0u8; PRESENCE_PREIMAGE_LEN];
    let mut at = 0;
    for field in fields {
        let len = (field.len() as u64).to_le_bytes();
        for byte in len.iter().chain(field) {
            if let Some(slot) = out.get_mut(at) {
                *slot = *byte;
            }
            at += 1;
        }
    }
    out
}

/// The 32-byte message a validator BLS-signs for `window` (section 7.8
/// item 2): SHA3-256 of [`presence_preimage`].
#[must_use]
pub fn presence_message(chain_id: u64, window: u64, class: ValidatorClass) -> [u8; 32] {
    Sha3_256::digest(presence_preimage(chain_id, window, class)).into()
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

/// The network hint of an IPv4 address: a digest of its /24 prefix (section
/// 7.8 item 1), length-prefixed like the message.
#[must_use]
pub fn network_hint_ipv4(addr: [u8; 4]) -> [u8; 32] {
    hint_digest(&addr[..3])
}

/// The network hint of an IPv6 address: a digest of its /48 prefix.
#[must_use]
pub fn network_hint_ipv6(addr: [u8; 16]) -> [u8; 32] {
    hint_digest(&addr[..6])
}

fn hint_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for field in [PRESENCE_HINT_DOMAIN_TAG, prefix] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// `PresenceSignal { validator, window, class, network_hint, sig_bls }`
/// (section 7.8 item 1). The field order and types are the node's (#70), so
/// the serde form is the same on both sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceSignal {
    /// The validator's owner address.
    pub validator: Address,
    /// The presence window index, in window units (not epochs).
    pub window: u64,
    /// The class the validator signs under for this window.
    pub class: ValidatorClass,
    /// [`network_hint_ipv4`] or [`network_hint_ipv6`] of the sending address.
    /// A hint, not a security claim.
    pub network_hint: [u8; 32],
    /// The BLS signature over [`presence_message`].
    pub sig_bls: Vec<u8>,
}

impl PresenceSignal {
    /// Build a signal, signing [`presence_message`] with `sign`. The signer is
    /// a closure so this crate carries no BLS implementation.
    pub fn sign<F>(
        validator: Address,
        chain_id: u64,
        window: u64,
        class: ValidatorClass,
        network_hint: [u8; 32],
        sign: F,
    ) -> Self
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let message = presence_message(chain_id, window, class);
        Self {
            validator,
            window,
            class,
            network_hint,
            sig_bls: sign(&message),
        }
    }

    /// Check the signature with `verify(validator, message, signature)`.
    #[must_use]
    pub fn verify_with<F>(&self, chain_id: u64, verify: F) -> bool
    where
        F: FnOnce(&[u8], &[u8; 32], &[u8]) -> bool,
    {
        let message = presence_message(chain_id, self.window, self.class);
        verify(self.validator.as_bytes(), &message, &self.sig_bls)
    }

    /// Two signals of one validator for one window under different classes
    /// are a double sign (section 7.8 item 8).
    #[must_use]
    pub fn is_double_sign_with(&self, other: &Self) -> bool {
        self.validator == other.validator
            && self.window == other.window
            && self.class != other.class
    }
}

#[cfg(test)]
mod tests {
    use super::{
        first_epoch_of_window, network_hint_ipv4, network_hint_ipv6, presence_message,
        presence_preimage, window_of_epoch, PresenceSignal,
    };
    use crate::{Address, ValidatorClass};

    /// The shared vector of the mobile core stack (#88): chain 45261,
    /// window 11, class Mobile. Generated with Python's `hashlib`.
    const SHARED_PREIMAGE: &[u8; 65] =
        include_bytes!("../../../tests/vectors/presence/v1/preimage.bin");
    const SHARED_DIGEST: &[u8; 32] =
        include_bytes!("../../../tests/vectors/presence/v1/digest.bin");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn presence_message_matches_the_shared_vector() {
        assert_eq!(
            &presence_preimage(45_261, 11, ValidatorClass::Mobile),
            SHARED_PREIMAGE
        );
        assert_eq!(
            &presence_message(45_261, 11, ValidatorClass::Mobile),
            SHARED_DIGEST
        );
    }

    /// Vectors computed with Python's `hashlib.sha3_256` over the layout in
    /// the module documentation, not with this code.
    #[test]
    fn presence_message_matches_independent_vectors() {
        assert_eq!(
            hex(&presence_message(45_261, 7, ValidatorClass::Mobile)),
            "9b42327ee892e3d0cdf15a5559c0d250073f12428adbe1388685d1af8c20d191"
        );
        assert_eq!(
            hex(&presence_message(
                45_261,
                7,
                ValidatorClass::MobileOpportunistic
            )),
            "5a3449c75d41b7f6ed2d6807fc8a01a65af085b7b4d761f5069ecea76d0a0cd3"
        );
        assert_eq!(
            hex(&presence_message(45_261, 7, ValidatorClass::Full)),
            "fa7d7b78d6246d1b74df2733f74f55f22d2b1c53224bc2002144d82b6ce453d4"
        );
        assert_eq!(
            hex(&presence_message(1, 0, ValidatorClass::Full)),
            "cb56efd75f4f40082f263cef3013b7c104b68eaa5e6a9417abbc2b4bcb901ddc"
        );
    }

    /// The two node-side layouts in flight hash the same window differently:
    /// #70 (unprefixed tag) and #45 (nothing prefixed). Pinned so a drift
    /// back to either fails here instead of suspending every phone.
    #[test]
    fn the_other_layouts_are_not_the_presence_message() {
        let message = hex(&presence_message(45_261, 11, ValidatorClass::Mobile));
        assert_ne!(
            message,
            "f14a3db552fa9b83037c7b5f0a4749ff05ea1390b436b40c8b071ef45d6ab7fd"
        );
        let message = hex(&presence_message(45_261, 7, ValidatorClass::Mobile));
        assert_ne!(
            message,
            "d8d5ba6f3f2de2719bf7fa3a53b27fc0eb98baa9ecc98c0683253fb09cbd5f92"
        );
        assert_ne!(
            message,
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
        assert_ne!(
            base,
            presence_message(45_261, 7, ValidatorClass::MobileOpportunistic)
        );
    }

    #[test]
    fn windows_follow_the_class() {
        assert_eq!(window_of_epoch(7, ValidatorClass::Full), 7);
        assert_eq!(window_of_epoch(7, ValidatorClass::Mobile), 1);
        assert_eq!(window_of_epoch(8, ValidatorClass::Mobile), 2);
        assert_eq!(first_epoch_of_window(2, ValidatorClass::Mobile), 8);
        assert_eq!(
            first_epoch_of_window(u64::MAX, ValidatorClass::Mobile),
            u64::MAX
        );
    }

    /// The hint keeps only the /24 or /48 prefix.
    #[test]
    fn network_hints_cover_only_the_prefix() {
        assert_eq!(
            network_hint_ipv4([10, 1, 2, 3]),
            network_hint_ipv4([10, 1, 2, 250])
        );
        assert_ne!(
            network_hint_ipv4([10, 1, 2, 3]),
            network_hint_ipv4([10, 1, 3, 3])
        );
        let mut a = [0u8; 16];
        a[0] = 0x20;
        let mut b = a;
        b[15] = 1;
        assert_eq!(network_hint_ipv6(a), network_hint_ipv6(b));
        b[5] = 1;
        assert_ne!(network_hint_ipv6(a), network_hint_ipv6(b));
    }

    /// A signal verifies over the shared message, and a class switch in the
    /// same window is a double sign.
    #[test]
    fn presence_signal_signs_the_shared_message() {
        let owner = Address([9u8; 32]);
        let sign = |m: &[u8; 32]| m.to_vec();
        let hint = [0u8; 32];
        let signal = PresenceSignal::sign(owner, 45_261, 11, ValidatorClass::Mobile, hint, sign);
        assert_eq!(signal.sig_bls.as_slice(), SHARED_DIGEST.as_slice());
        assert!(signal.verify_with(45_261, |v, m, s| v == owner.as_bytes() && s == m));
        assert!(!signal.verify_with(45_262, |_, m, s| s == m));
        let other = PresenceSignal::sign(owner, 45_261, 11, ValidatorClass::Full, hint, sign);
        assert!(signal.is_double_sign_with(&other));
        let next = PresenceSignal::sign(owner, 45_261, 12, ValidatorClass::Full, hint, sign);
        assert!(!signal.is_double_sign_with(&next));
    }
}
