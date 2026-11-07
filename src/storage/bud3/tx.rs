//! Signed storage transaction carrier for B.U.D. 3.0.
//!
//! At Milestone M1 (`WP-07`) the legacy storage transaction variants are gone
//! and the signed carrier holds an explicit 10-byte [`BINDING_HEADER`] plus an
//! opaque payload committed field-by-field into the transaction signature.
//! Every execution call refuses cleanly with [`StorageError::Bud3NotReady`]
//! before mutating state or charging fees.

use serde::{Deserialize, Serialize};

use crate::storage::bud3::content_ref::StorageError;

/// Domain-separating header written into the transaction signing preimage.
pub const BINDING_HEADER: [u8; 10] = *b"BUD3_TX_V1";

/// Maximum opaque storage transaction payload accepted into a wire envelope.
pub const MAX_STORAGE_TX_BYTES: usize = 1 << 20;

/// Signed B.U.D. 3.0 storage transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTx {
    /// Fixed 10-byte generation binding header (`BUD3_TX_V1`).
    pub header: [u8; 10],
    /// Encoded B.U.D. 3.0 storage operation bytes.
    pub payload: Vec<u8>,
}

impl StorageTx {
    /// Construct a new `StorageTx` carrying `BINDING_HEADER` and `payload`.
    /// WIRING: exposed for: B.U.D. 3.0 storage transaction construction.
    #[must_use]
    pub const fn new(payload: Vec<u8>) -> Self {
        Self {
            header: BINDING_HEADER,
            payload,
        }
    }

    /// Deterministic byte encoding bound into the outer `Transaction` signature.
    /// WIRING: exposed for: B.U.D. 3.0 storage transaction signing.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.len() + 8 + self.payload.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Apply a signed storage transaction.
///
/// # Errors
///
/// Refuses every call with [`StorageError::Bud3NotReady`] until the B.U.D. 3.0
/// object lifecycle lands in `WP-18..24`.
pub fn apply(tx: &StorageTx) -> Result<(), StorageError> {
    if tx.header != BINDING_HEADER || tx.payload.len() > MAX_STORAGE_TX_BYTES {
        return Err(StorageError::Bud3NotReady);
    }
    Err(StorageError::Bud3NotReady)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_bytes_bind_header_and_length() {
        let a = StorageTx::new(b"alpha".to_vec());
        let b = StorageTx::new(b"beta".to_vec());
        assert!(a.signing_bytes().starts_with(&BINDING_HEADER));
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn apply_refuses_until_bud3_lifecycle_lands() {
        let tx = StorageTx::new(vec![1, 2, 3]);
        assert_eq!(apply(&tx), Err(StorageError::Bud3NotReady));
    }
}
