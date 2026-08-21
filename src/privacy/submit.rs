//! On-chain private transfer submit payload (public + spend linkage).

use super::note_registry::NoteHash;
use serde::{Deserialize, Serialize};

/// Max inputs/outputs per private transfer (DoS bound).
pub const MAX_PRIVATE_IO: usize = 16;

/// Chain-submitted private transfer (from wallet intent).
///
/// `spent_commitments` are required in v1 so the note set can be updated
/// Without a full membership STARK inside L1; nullifiers remain the public
/// Double-spend tags. TEE path may later replace spent_commitments with a
/// Proof-only membership argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferSubmit {
    pub spent_commitments: Vec<NoteHash>,
    pub nullifiers: Vec<NoteHash>,
    pub output_commitments: Vec<NoteHash>,
    /// Wallet authorization over public digest (ed25519, 64 bytes).
    pub authorization_sig: Vec<u8>,
    /// Echo of wallet `public_digest` for audit / light clients.
    pub public_digest: [u8; 32],
}

impl PrivateTransferSubmit {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.spent_commitments.is_empty() || self.nullifiers.is_empty() {
            return Err("private transfer: empty inputs".into());
        }
        if self.spent_commitments.len() != self.nullifiers.len() {
            return Err("private transfer: input arity mismatch".into());
        }
        if self.output_commitments.is_empty() {
            return Err("private transfer: empty outputs".into());
        }
        if self.spent_commitments.len() > MAX_PRIVATE_IO
            || self.output_commitments.len() > MAX_PRIVATE_IO
        {
            return Err(format!(
                "private transfer: exceeds MAX_PRIVATE_IO ({MAX_PRIVATE_IO})"
            ));
        }
        if self.authorization_sig.len() != 64 {
            return Err("private transfer: authorization_sig must be 64 bytes".into());
        }
        Ok(())
    }

    /// Domain-separated digest binding public halves (must match wallet).
    pub fn compute_public_digest(nullifiers: &[NoteHash], outputs: &[NoteHash]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PRIVATE_TRANSFER_V1");
        h.update((nullifiers.len() as u64).to_le_bytes());
        for n in nullifiers {
            h.update(n);
        }
        h.update((outputs.len() as u64).to_le_bytes());
        for c in outputs {
            h.update(c);
        }
        h.finalize().into()
    }

    pub fn verify_digest_matches(&self) -> bool {
        self.public_digest
            == Self::compute_public_digest(&self.nullifiers, &self.output_commitments)
    }
}
