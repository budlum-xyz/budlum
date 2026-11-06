use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s == "0" {
            return Ok(Address([0u8; 32]));
        }
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
mod single_definition_tests {
    use super::Address;

    /// K-4 (single definition): the node's address and the shared type crate's
    /// address must be the *same* type, not two lookalikes that happen to agree
    /// today. `identity` coerces with no conversion, so this file only compiles
    /// when `core::address::Address` IS `budlum_types::Address`. A second copy of
    /// the struct breaks the build here instead of drifting silently.
    #[test]
    fn node_address_is_the_shared_type() {
        fn identity(shared: budlum_types::Address) -> Address {
            shared
        }
        let shared = budlum_types::Address::from([7u8; 32]);
        assert_eq!(identity(shared).as_bytes(), &[7u8; 32]);
    }

    /// The wire shape the node has always written must survive the move:
    /// lowercase hex with no `0x`, and the zero address still parses from `"0"`.
    #[test]
    fn address_wire_shape_survives_the_move() {
        assert_eq!(Address::zero().to_hex(), "0".repeat(64));
        assert_eq!(Address::from_hex("0").ok(), Some(Address::zero()));
        assert_eq!(Address::from_hex("0x0").ok(), Some(Address::zero()));
        let addr = Address::from([0xabu8; 32]);
        assert_eq!(addr.to_hex(), "ab".repeat(32));
        assert_eq!(Address::from_hex(&addr.to_hex()).ok(), Some(addr));
        assert!(Address::from_hex("ab").is_err());
    }
}
