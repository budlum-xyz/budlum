//! The wire types the node and the mobile core share, defined once.
//!
//! K-4 says every cryptographic primitive has a single definition that the
//! wallet, the chain and the VM all call. The mobile core makes that rule load
//! bearing in a new direction: a phone must verify the same addresses, sign the
//! same transactions and follow the same checkpoints as a validator, but it
//! must not link the whole node to do it (7.9.5). So the shared types live here,
//! below both, and each side binds this crate.
//!
//! # Why a copy would not fail loudly
//!
//! Two structs with the same fields and the same `to_hex` agree on every input
//! anyone tests them with, right up until one of them is edited. The divergence
//! does not arrive as a compile error, because both crates still build against
//! their own copy, and it does not arrive as a failing test, because each copy
//! round-trips perfectly against itself. It arrives as a phone that derives a
//! different address from the same key than the validator does, and the funds
//! land somewhere nobody can sign for. Only one definition removes that failure
//! mode, so this crate is the definition and `budlum-core` re-exports it.
//!
//! # Scope
//!
//! The first slice carried the address. The second carries what the mobile
//! core needs to sign its first message: the validator class with its per-class
//! windows ([`class`]) and the presence preimage, message, signal and network
//! hint ([`presence`], section 7.8).
//! The transaction, signature, handoff-certificate, checkpoint-certificate and
//! B.U.D. 3.0 symbol/share/proof types follow in later slices of the same
//! package; each move has to keep the wire shape byte-identical, so they move
//! one at a time rather than together.
//!
//! Every dependency here is one the phone inherits, so the list stays short.
//! `sha3` is the presence digest's hash, at the major the root manifest already
//! links, so the node's lockfile gains no new package.

#![forbid(unsafe_code)]

pub mod class;
pub mod presence;

pub use class::{
    hours_to_epochs, AuditWindow, ClassParameterError, ValidatorClass,
    MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// A 32-byte account address.
///
/// The wire form is lowercase hex with no prefix. Parsing accepts exactly 64
/// hexadecimal digits, optionally preceded by `0x` or `0X`.
///
/// # The input contract is owned by  (#43)
///
/// The accepted input spellings are **not** settled by this crate's move. #43
/// closes  by making `"0"` and `"0x0"` errors and adding a `0X` prefix.
/// That change is still correct and still needed; it now lands **here**, on
/// `from_hex` below, rather than in `src/core/address.rs`, which is a re-export
/// as of this commit. The behaviour was moved verbatim so that this PR decides
/// nothing about the finding either way.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid address length: expected 32, got {}",
                bytes.len()
            ));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(Address(addr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn zero() -> Self {
        Address([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zero()
    }
}

impl FromStr for Address {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Address(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    /// The wire form is lowercase hex, 64 characters, no prefix. A validator and
    /// a phone must print the same string for the same account.
    #[test]
    fn hex_is_lowercase_and_unprefixed() {
        let addr = Address::from([0xabu8; 32]);
        assert_eq!(addr.to_hex(), "ab".repeat(32));
        assert_eq!(addr.to_hex().len(), 64);
        assert_eq!(addr.to_string(), addr.to_hex());
    }

    /// The zero address and its printed form.
    ///
    /// Which *input strings* parse to zero is 's question, and #43 owns
    /// it: that PR makes `"0"` and `"0x0"` errors and adds a `0X` prefix. This
    /// slice moves the definition without answering that question, so it pins
    /// only the value and its output, not the accepted spellings.
    #[test]
    fn zero_address_prints_as_sixty_four_zeros() {
        assert_eq!(Address::default(), Address::zero());
        assert_eq!(Address::zero().to_hex(), "0".repeat(64));
        assert_eq!(Address::zero().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn parser_requires_canonical_hex_digits() {
        assert!(Address::from_hex("0").is_err());
        assert!(Address::from_hex("0x0").is_err());
        assert!(Address::from_hex(&"01".repeat(31)).is_err());
        let upper = format!("0X{}", "0A".repeat(32));
        assert_eq!(Address::from_hex(&upper).ok(), Some(Address([0x0a; 32])));
    }

    #[test]
    fn hex_round_trips_with_and_without_prefix() {
        let addr = Address::from([0x11u8; 32]);
        assert_eq!(Address::from_hex(&addr.to_hex()).ok(), Some(addr));
        let prefixed = format!("0x{}", addr.to_hex());
        assert_eq!(Address::from_hex(&prefixed).ok(), Some(addr));
        assert_eq!(addr.to_hex().parse::<Address>().ok(), Some(addr));
    }

    /// A wrong-length or non-hex string is refused, never silently padded: a
    /// padded address would name a different account than the caller wrote.
    #[test]
    fn malformed_input_is_refused() {
        assert!(Address::from_hex("ab").is_err());
        assert!(Address::from_hex(&"ab".repeat(31)).is_err());
        assert!(Address::from_hex(&"ab".repeat(33)).is_err());
        assert!(Address::from_hex(&"zz".repeat(32)).is_err());
    }

    /// Ordering is part of the contract: deterministic tie-breaks rank by
    /// address, so the byte order must not depend on which side compares.
    #[test]
    fn ordering_is_by_bytes() {
        let mut low = [0u8; 32];
        low[0] = 0x01;
        let mut high = [0u8; 32];
        high[31] = 0x01;
        assert!(Address::from(low) < Address::from(high));
        assert_eq!(Address::from(low), Address::from(low));
    }

    #[test]
    fn as_bytes_exposes_the_raw_array() {
        let addr = Address::from([0x7fu8; 32]);
        assert_eq!(addr.as_bytes(), &[0x7fu8; 32]);
        assert_eq!(addr.0, [0x7fu8; 32]);
    }
}
