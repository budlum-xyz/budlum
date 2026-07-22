//! Minimal 32-byte address type for the standalone verifier registry.
//!
//! This is intentionally a thin newtype — the registry only needs
//! equality, ordering, and hashing.  Full address utilities (hex parsing,
//! Bech32, etc.) live in the host crate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const fn zero() -> Self {
        Address([0u8; 32])
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s == "0" {
            return Ok(Address::zero());
        }
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid address length: expected 32, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Address(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
