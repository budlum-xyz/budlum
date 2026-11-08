//! Presence signal (section 7.8).
//!
//! The message, the signal and the network hint are defined once, in
//! `budlum-types` (K-4): the node verifies the bytes the phone signs, so the
//! two must not each carry a copy. This core had its own copy of the class
//! enum and of the preimage until the shared crate carried them; this module
//! now re-exports the shared definitions and adds only the mobile-side duty
//! that has no shared counterpart yet.

pub use budlum_types::presence::{
    first_epoch_of_window, network_hint_ipv4, network_hint_ipv6, presence_message,
    presence_preimage, window_of_epoch, PresenceSignal, PRESENCE_DOMAIN_TAG,
    PRESENCE_HINT_DOMAIN_TAG, PRESENCE_PREIMAGE_LEN, PRESENCE_TOPIC,
};
pub use budlum_types::ValidatorClass;

/// `ResumeValidator`: the duty that restores a suspended validator one epoch
/// later (section 7.8.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeValidator {
    /// Owner address.
    pub owner: [u8; 32],
}
