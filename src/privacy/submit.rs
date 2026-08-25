//! On-chain private transfer submit payload (public + spend linkage).

use super::note_registry::NoteHash;
use serde::{Deserialize, Serialize};

/// Max inputs/outputs per private transfer (DoS bound).
pub const MAX_PRIVATE_IO: usize = 16;

/// The length of the legacy Ed25519 authorisation signature.
pub const ED25519_AUTH_SIG_LEN: usize = 64;

/// The length of the ML-DSA-87 authorisation signature.
pub const ML_DSA_87_AUTH_SIG_LEN: usize = crate::crypto::primitives::ML_DSA_87_SIGNATURE_LEN;

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
        // The authorization signature can take one of two shapes: the older
        // Ed25519 (64 bytes) or ML-DSA-87 (4627 bytes). The length is only a
        // **shape** check; which one is actually valid is decided in the
        // `Executor`, from the signature version of the transaction.
        //
        // Previously only 64 was accepted. That made a private transfer
        // authorization **impossible** for an account holding an ML-DSA-87 key
        // (V5): even when it produced the correct signature, the transaction
        // fell at the shape gate with "must be 64 bytes". Since ML-DSA-87 is
        // the default wallet of the chain, this meant the feature did not work
        // at all in the default configuration.
        if self.authorization_sig.len() != ED25519_AUTH_SIG_LEN
            && self.authorization_sig.len() != ML_DSA_87_AUTH_SIG_LEN
        {
            return Err(format!(
                "private transfer: authorization_sig must be {ED25519_AUTH_SIG_LEN} bytes \
                 (Ed25519) or {ML_DSA_87_AUTH_SIG_LEN} bytes (ML-DSA-87), got {}",
                self.authorization_sig.len()
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn submit_with_sig(len: usize) -> PrivateTransferSubmit {
        let nullifiers = vec![[1u8; 32]];
        let outputs = vec![[2u8; 32]];
        PrivateTransferSubmit {
            spent_commitments: vec![[3u8; 32]],
            nullifiers: nullifiers.clone(),
            output_commitments: outputs.clone(),
            authorization_sig: vec![0u8; len],
            public_digest: PrivateTransferSubmit::compute_public_digest(&nullifiers, &outputs),
        }
    }

    /// The legacy Ed25519 authorisation must keep being accepted.
    #[test]
    fn an_ed25519_authorization_keeps_its_shape() {
        assert!(submit_with_sig(ED25519_AUTH_SIG_LEN)
            .validate_shape()
            .is_ok());
    }

    /// An ML-DSA-87 authorization has to be accepted too.
    ///
    /// ML-DSA-87 is the default wallet of the chain. As long as the shape gate
    /// allowed only 64 bytes, a V5 account could not make a private transfer
    /// even when it produced the correct signature.
    #[test]
    fn an_ml_dsa_87_authorization_is_accepted() {
        assert!(submit_with_sig(ML_DSA_87_AUTH_SIG_LEN)
            .validate_shape()
            .is_ok());
    }

    /// A length matching neither shape has to be refused.
    #[test]
    fn an_authorization_of_any_other_length_is_refused() {
        for len in [0usize, 1, 63, 65, 4626, 4628] {
            let err = submit_with_sig(len)
                .validate_shape()
                .expect_err("an invalid length has to be refused");
            assert!(err.contains("authorization_sig"), "{err}");
        }
    }
}
