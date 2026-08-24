//! Verification strength: every answer **declares** how much it was verified.
//!
//! # The most important design decision in the system
//!
//! Content that cannot be verified is not banned, it is **labelled**. Banning
//! makes the browser unusable and sends the user to another browser that
//! verifies nothing. Labelling tells the user what they are looking at.
//!
//! The price of that is that the label has to be honest. For an answer to be
//! [`Strength::Verified`], an **equality** must have been established: the hash
//! of the fetched bytes equals the expected identity. Nothing else is
//! `Verified`, and in particular "a trusted RPC said so" is not.
//!
//! # Why a single enum
//!
//! Strength is produced separately by the fetcher, the resolver and the light
//! client, and the **weakest link** wins. Keeping the three in separate fields
//! and combining them at the address bar allows a call site to forget the
//! combination. [`Evidence::weakest`] does that combining in one place.
use serde::{Deserialize, Serialize};
use std::fmt;

/// How much an answer was verified.
///
/// The ordering is deliberate: `Ord` runs weak to strong, and `weakest` is
/// built on top of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Strength {
    /// Not verified, and the content must not be shown: the hash did not
    /// match, the proof was invalid, or decryption failed.
    Refused,
    /// Somebody's claim and nothing more. An RPC answered, with no proof, or
    /// with a proof that could not be verified. Displayable, but not
    /// `verified`.
    RpcClaimOnly,
    /// Transport security only: TLS says who sent it, not what was sent. This
    /// is the ordinary web.
    TransportOnly,
    /// Content-addressed, and the hash of the bytes equals the expected
    /// identity.
    Verified,
}

impl fmt::Display for Strength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => write!(f, "refused"),
            Self::RpcClaimOnly => write!(f, "claim only"),
            Self::TransportOnly => write!(f, "transport only"),
            Self::Verified => write!(f, "verified"),
        }
    }
}

/// A single measurement: who verified what, and how far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// Which layer: `name-rule`, `bns-resolution`, `bud-fetcher`, `ipfs`, and
    /// so on.
    pub layer: String,
    pub strength: Strength,
    /// Why this strength. It cannot be left empty: a label without a reason is
    /// not a label.
    pub reason: String,
}

impl Claim {
    #[must_use]
    pub fn new(layer: &str, strength: Strength, reason: &str) -> Self {
        debug_assert!(
            !reason.is_empty(),
            "a claim without a reason cannot be written"
        );
        Self {
            layer: layer.to_string(),
            strength,
            reason: reason.to_string(),
        }
    }
}

/// Every claim about one answer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub claims: Vec<Claim>,
}

impl Evidence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, claim: Claim) -> Self {
        self.claims.push(claim);
        self
    }

    pub fn push(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    /// The weakest link in the chain.
    ///
    /// With no claims at all the answer is `Refused`: something unmeasured does
    /// not count as verified. That stops an empty `Evidence` from passing by
    /// accident, and it is a decision about which way the default points -
    /// silence does not say `verified`.
    #[must_use]
    pub fn weakest(&self) -> Strength {
        self.claims
            .iter()
            .map(|c| c.strength)
            .min()
            .unwrap_or(Strength::Refused)
    }

    /// May the content be shown to the user?
    ///
    /// Everything but `Refused` may be shown, because that is exactly what the
    /// labelling decision means: show it, and say what it is.
    #[must_use]
    pub fn is_displayable(&self) -> bool {
        self.weakest() != Strength::Refused
    }

    /// The single line shown in the address bar.
    #[must_use]
    pub fn badge(&self) -> String {
        let w = self.weakest();
        let reason = self
            .claims
            .iter()
            .filter(|c| c.strength == w)
            .map(|c| format!("{}: {}", c.layer, c.reason))
            .collect::<Vec<_>>()
            .join("; ");
        if reason.is_empty() {
            format!("{w} (no measurement was made)")
        } else {
            format!("{w} - {reason}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_measurement_is_not_verified() {
        let e = Evidence::new();
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(!e.is_displayable());
    }

    #[test]
    fn the_weakest_link_wins() {
        let e = Evidence::new()
            .with(Claim::new(
                "bud-fetcher",
                Strength::Verified,
                "the hash matched",
            ))
            .with(Claim::new(
                "bns-resolution",
                Strength::RpcClaimOnly,
                "no state proof arrived",
            ));
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.is_displayable());
    }

    #[test]
    fn one_refusal_refuses_the_whole_answer() {
        let e = Evidence::new()
            .with(Claim::new(
                "bns-resolution",
                Strength::Verified,
                "the proof is valid",
            ))
            .with(Claim::new(
                "ipfs",
                Strength::Refused,
                "the digest did not match the CID",
            ));
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(!e.is_displayable());
    }

    #[test]
    fn the_badge_names_the_weakest_layer() {
        let e = Evidence::new()
            .with(Claim::new(
                "bud-fetcher",
                Strength::Verified,
                "the hash matched",
            ))
            .with(Claim::new("https", Strength::TransportOnly, "TLS only"));
        let badge = e.badge();
        assert!(badge.contains("transport only"), "{badge}");
        assert!(badge.contains("https"), "{badge}");
        assert!(!badge.contains("bud-fetcher"), "{badge}");
    }

    #[test]
    fn strength_ordering_is_weak_to_strong() {
        assert!(Strength::Refused < Strength::RpcClaimOnly);
        assert!(Strength::RpcClaimOnly < Strength::TransportOnly);
        assert!(Strength::TransportOnly < Strength::Verified);
    }
}
