//! Presence signal (section 7.8).
//!
//! The BLS signature is over SHA3-256 of length-prefixed
//! `BDLM_PRESENCE_V1`, chain id, window and class.

use sha3::{Digest, Sha3_256};

/// Domain-separation tag. WP-13 registers it in the node inventory.
pub const PRESENCE_TAG: &[u8] = b"BDLM_PRESENCE_V1";
/// Gossip topic for presence.
pub const PRESENCE_TOPIC: &str = "/budlum/presence/1";
/// A mobile presence window is 4 epochs (testnet: 10 minutes).
pub const MOBILE_WINDOW_EPOCHS: u64 = 4;
/// A Full presence window is 1 epoch.
pub const FULL_WINDOW_EPOCHS: u64 = 1;

/// Validator class, the same tags as `src/validators/mod.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorClass {
    /// Runs every block, proposes, holds a finality seat.
    Full,
    /// A phone: stores content, answers audits, holds no seat.
    Mobile,
    /// An iPhone: the same duties, only while the app is open or charging.
    MobileOpportunistic,
}

impl ValidatorClass {
    /// The byte written into the presence preimage.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Mobile => 1,
            Self::MobileOpportunistic => 2,
        }
    }

    /// Epochs in one presence window for this class.
    #[must_use]
    pub const fn window_epochs(self) -> u64 {
        match self {
            Self::Full => FULL_WINDOW_EPOCHS,
            Self::Mobile | Self::MobileOpportunistic => MOBILE_WINDOW_EPOCHS,
        }
    }
}

/// `PresenceSignal { validator, window, class, network_hint, sig_bls }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSignal {
    /// Validator owner address (32 bytes).
    pub validator: [u8; 32],
    /// Window index.
    pub window: u64,
    /// Class at the time of the signal.
    pub class: ValidatorClass,
    /// Hash of the IPv4 /24 or IPv6 /48 prefix.
    pub network_hint: [u8; 32],
    /// BLS signature over [`presence_preimage`].
    pub sig_bls: Vec<u8>,
}

/// SHA3-256 over length-prefixed `BDLM_PRESENCE_V1`, `chain_id`, `window`,
/// `class`.
#[must_use]
pub fn presence_preimage(chain_id: u64, window: u64, class: ValidatorClass) -> [u8; 32] {
    let class_tag = [class.tag()];
    let chain = chain_id.to_le_bytes();
    let win = window.to_le_bytes();
    let mut hasher = Sha3_256::new();
    let fields: [&[u8]; 4] = [PRESENCE_TAG, &chain, &win, &class_tag];
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Hash of an IPv4 /24 prefix (first three octets).
#[must_use]
pub fn network_hint_ipv4(addr: [u8; 4]) -> [u8; 32] {
    crate::hash::hash_fields_bytes(&[b"BDLM_PRESENCE_HINT_V1", &addr[..3]])
}

/// Hash of an IPv6 /48 prefix (first six octets).
#[must_use]
pub fn network_hint_ipv6(addr: [u8; 16]) -> [u8; 32] {
    crate::hash::hash_fields_bytes(&[b"BDLM_PRESENCE_HINT_V1", &addr[..6]])
}

impl PresenceSignal {
    /// Build a signal signed by `sign`.
    pub fn sign<F>(
        validator: [u8; 32],
        chain_id: u64,
        window: u64,
        class: ValidatorClass,
        network_hint: [u8; 32],
        sign: F,
    ) -> Self
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let preimage = presence_preimage(chain_id, window, class);
        Self {
            validator,
            window,
            class,
            network_hint,
            sig_bls: sign(&preimage),
        }
    }

    /// Verify with a BLS verifier over the bound preimage.
    #[must_use]
    pub fn verify_with<F>(&self, chain_id: u64, verify: F) -> bool
    where
        F: FnOnce(&[u8], &[u8; 32], &[u8]) -> bool,
    {
        let preimage = presence_preimage(chain_id, self.window, self.class);
        verify(&self.validator, &preimage, &self.sig_bls)
    }
}

/// Two signals from the same validator for the same window with a different
/// class field are a double-sign.
#[must_use]
pub fn is_presence_double_sign(a: &PresenceSignal, b: &PresenceSignal) -> bool {
    a.validator == b.validator && a.window == b.window && a.class != b.class
}

/// `ResumeValidator`: the duty that restores a suspended validator one epoch
/// later (section 7.8.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeValidator {
    /// Owner address.
    pub owner: [u8; 32],
}
