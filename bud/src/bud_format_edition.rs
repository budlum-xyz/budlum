//! B.U.D. - EDITION SELECTION
//!
//! The design: B.U.D. 3.0 and 2.0 are kept apart, the caller picks the version,
//! and B.U.D. 1.0 must be selectable too.
//!
//! The three versions live in the same code tree, but the user chooses the
//! TARIFF LEVEL:
//!
//! - B.U.D. 1.0 - storage on your own server or device, bring your own. It does
//!   not have to obey the B.U.D. rules; the NFT data is outside and the
//!   liability is the user's. While the device is active it is a validator, and
//!   its data is visible on social media.
//! - B.U.D. 2.0 - storage in a `.bud` container, the $0.016 target and the
//!   format transforms.
//! - B.U.D. 3.0 - recipe as the only object, with no notion of storage; the QR
//!   video is a derivative of it.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const ED_MAGIC: [u8; 8] = *b"\xB5EDN\0\0\0\0";
pub const ED_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    Bud1, // your own server or device: no rules, bring your own
    Bud2, // storage in a .bud container
    Bud3, // the recipe as the only object
}

impl Edition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bud1 => "B.U.D. 1.0",
            Self::Bud2 => "B.U.D. 2.0",
            Self::Bud3 => "B.U.D. 3.0",
        }
    }

    /// Which version did the user choose? Deterministic, and recorded on chain.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Bud1),
            2 => Some(Self::Bud2),
            3 => Some(Self::Bud3),
            _ => None,
        }
    }

    /// The tariff model: whether a recipe, and therefore rent, is required.
    pub fn recipe_required(&self) -> bool {
        match self {
            Self::Bud1 => false, // no rules: your data, your liability
            Self::Bud2 => true,  // the .bud record is required
            Self::Bud3 => true,  // the recipe record is required
        }
    }
}

// ============================ B.U.D. 1.0 ============================

/// B.U.D. 1.0: your own storage, bring your own.
///
/// - The user can add their own server or a third party server.
/// - It does not have to obey the B.U.D. rules, even when it is decentralised.
/// - The NFT data is outside, on the user's server, and the liability is the
///   user's.
/// - If it is stored on a device: while the device is active it is a validator,
///   and the data is visible on social media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bud1Custody {
    External { server: String }, // their own server or a third party
    Device,                      // their own device, a validator while active
}

#[derive(Debug, Clone)]
pub struct Bud1Nft {
    pub id: [u8; 32],
    pub content_uri: String, // where the data is HELD, which is outside
    pub custody: Bud1Custody,
    pub social_visible: bool, // is the data visible on social media?
}

impl Bud1Nft {
    /// In 1.0 the content DOES NOT HAVE TO obey a B.U.D. recipe or rule; the
    /// data is outside.
    pub fn new_external(id: [u8; 32], server: String, uri: String) -> Self {
        Self {
            id,
            content_uri: uri,
            custody: Bud1Custody::External { server },
            social_visible: false,
        }
    }

    /// Storage on a device: while the device is active it is a validator, and the
    /// data is visible on social media.
    pub fn new_device(id: [u8; 32], uri: String, social_visible: bool) -> Self {
        Self {
            id,
            content_uri: uri,
            custody: Bud1Custody::Device,
            social_visible,
        }
    }

    /// The liability is ALWAYS the user's, which is the core of 1.0.
    pub fn liability_user(&self) -> bool {
        true
    }

    /// If the device stores and is active, it contributes as a validator.
    pub fn device_validator(&self, device_active: bool) -> bool {
        matches!(self.custody, Bud1Custody::Device) && device_active
    }
}

/// The 1.0 record digest, writable on chain.
pub fn bud1_digest(nft: &Bud1Nft) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ED_MAGIC);
    h.update([1]); // edition 1
    h.update(nft.id);
    h.update(nft.content_uri.as_bytes());
    match &nft.custody {
        Bud1Custody::External { server } => {
            h.update([0]);
            h.update(server.as_bytes());
        }
        Bud1Custody::Device => h.update([1]),
    }
    h.update([nft.social_visible as u8]);
    h.finalize().into()
}

// ========================= The edition choice record =========================

/// The user's choice: fixed on chain, and upgrading the version is a governance
/// decision.
#[derive(Debug, Clone)]
pub struct EditionChoice {
    pub edition: Edition,
    pub ts_unix: u64,
}

impl EditionChoice {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(ED_MAGIC);
        h.update([self.edition as u8]);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edition_selection_is_deterministic() {
        assert_eq!(Edition::from_u8(1).unwrap(), Edition::Bud1);
        assert_eq!(Edition::from_u8(2).unwrap(), Edition::Bud2);
        assert_eq!(Edition::from_u8(3).unwrap(), Edition::Bud3);
        assert!(Edition::from_u8(0).is_none());
        assert!(Edition::from_u8(9).is_none());
    }

    #[test]
    fn bud1_is_unruled_self_storage() {
        let ext = Bud1Nft::new_external(
            [1u8; 32],
            "my-own-server.example".into(),
            "https://my-own-server.example/nft-1".into(),
        );
        assert!(!Edition::Bud1.recipe_required(), "1.0 has no rules");
        assert!(ext.liability_user(), "the liability is the user's");
        // Device mode: a validator while active.
        let dev = Bud1Nft::new_device([2u8; 32], "cid://1".into(), true);
        assert!(dev.device_validator(true));
        assert!(!dev.device_validator(false));
        assert!(dev.social_visible, "the data is visible on social media");
    }

    #[test]
    fn editions_digest_differently() {
        let e1 = Bud1Nft::new_external([1u8; 32], "s".into(), "u".into());
        let e2 = Bud1Nft::new_device([1u8; 32], "u".into(), true);
        assert_ne!(
            bud1_digest(&e1),
            bud1_digest(&e2),
            "a difference in custody reaches the digest"
        );
        assert_eq!(bud1_digest(&e1), bud1_digest(&e1));
    }

    #[test]
    fn the_choice_record_is_deterministic() {
        let c = EditionChoice {
            edition: Edition::Bud3,
            ts_unix: 1_768_000_000,
        };
        assert_eq!(c.digest(), c.digest());
    }
}
