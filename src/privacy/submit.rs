//! On-chain private transfer submit payload (public + spend linkage).

use super::note_registry::{is_note_hash, NoteHash};
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
/// Without a full membership STARK inside the chain; nullifiers remain the public
/// Double-spend tags. TEE path may later replace spent_commitments with a
/// Proof-only membership argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferSubmit {
    pub spent_commitments: Vec<NoteHash>,
    pub nullifiers: Vec<NoteHash>,
    pub output_commitments: Vec<NoteHash>,
    /// One derivation proof per input, checked as
    /// `nullifier[i] == derive_nullifier(commitment[i], proof[i])`. The
    /// registry refuses a transfer without them.
    #[serde(default)]
    pub nullifier_proofs: Vec<NoteHash>,
    /// Wallet authorization over the public digest; verified using the
    /// transaction's signature version.
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
        // Proofs are part of the transaction, one per input.
        if self.nullifier_proofs.len() != self.nullifiers.len() {
            return Err("private transfer: nullifier proof arity mismatch".into());
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
        // Every hash here is a packed field element or it is not a note. See
        // `is_note_hash` for why the registry must never see another shape.
        let hashes = self
            .spent_commitments
            .iter()
            .chain(&self.nullifiers)
            .chain(&self.nullifier_proofs)
            .chain(&self.output_commitments);
        for h in hashes {
            if !is_note_hash(h) {
                return Err(
                    "private transfer: a commitment or nullifier is not a packed field element"
                        .into(),
                );
            }
        }
        // The transaction's signature version selects the verifier. Accept
        // legacy single-scheme forms or a structurally valid composite encoding;
        // the executor verifies the signature itself.
        if self.authorization_sig.len() != ED25519_AUTH_SIG_LEN
            && self.authorization_sig.len() != ML_DSA_87_AUTH_SIG_LEN
            && crate::crypto::composite::CompositeSignature::decode(&self.authorization_sig)
                .is_err()
        {
            return Err(
                "private transfer: authorization_sig has an unsupported encoding or length"
                    .into(),
            );
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

    /// Domain-separated authorization preimage binding `public_digest` to the
    /// chain id, sending account, and sender nonce.
    #[must_use]
    pub fn authorization_message(
        chain_id: u64,
        sender: &[u8; 32],
        sender_nonce: u64,
        public_digest: &[u8; 32],
    ) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PRIVATE_TRANSFER_AUTH_V1");
        h.update(chain_id.to_le_bytes());
        h.update(sender);
        h.update(sender_nonce.to_le_bytes());
        h.update(public_digest);
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
        let commitment = budlum_note_packing::hash_from_field(3);
        let proof = budlum_note_packing::hash_from_field(1);
        let nullifiers = vec![
            crate::privacy::note_registry::L1NoteRegistry::derive_nullifier(&commitment, &proof),
        ];
        let outputs = vec![budlum_note_packing::hash_from_field(2)];
        PrivateTransferSubmit {
            spent_commitments: vec![commitment],
            nullifiers: nullifiers.clone(),
            output_commitments: outputs.clone(),
            nullifier_proofs: vec![proof],
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
    #[test]
    fn an_ml_dsa_87_authorization_is_accepted() {
        assert!(submit_with_sig(ML_DSA_87_AUTH_SIG_LEN)
            .validate_shape()
            .is_ok());
    }

    #[test]
    fn a_composite_authorization_is_accepted() {
        use crate::crypto::composite::{CompositeSignature, ED25519_SIGNATURE_LEN};
        use crate::crypto::scheme::SuiteId;

        let signature = CompositeSignature {
            suite: SuiteId::USER,
            pq: vec![0u8; ML_DSA_87_AUTH_SIG_LEN],
            ed: [0u8; ED25519_SIGNATURE_LEN],
        }
        .encode();
        assert_eq!(
            signature.len(),
            3 + ML_DSA_87_AUTH_SIG_LEN + ED25519_SIGNATURE_LEN
        );
        assert_eq!(
            signature.len(),
            CompositeSignature::encoded_len(SuiteId::USER).expect("known composite suite")
        );
        assert!(CompositeSignature::decode(&signature).is_ok());

        let mut submit = submit_with_sig(signature.len());
        submit.authorization_sig = signature;
        assert!(submit.validate_shape().is_ok());
    }

    #[test]
    fn a_composite_authorization_with_an_unknown_suite_is_refused() {
        use crate::crypto::composite::{CompositeSignature, ED25519_SIGNATURE_LEN};
        use crate::crypto::scheme::SuiteId;

        let mut signature = CompositeSignature {
            suite: SuiteId::USER,
            pq: vec![0u8; ML_DSA_87_AUTH_SIG_LEN],
            ed: [0u8; ED25519_SIGNATURE_LEN],
        }
        .encode();
        signature[1..3].copy_from_slice(&u16::MAX.to_be_bytes());

        let mut submit = submit_with_sig(signature.len());
        submit.authorization_sig = signature;
        assert!(submit.validate_shape().is_err());
    }

    /// Unsupported signature lengths have to be refused.
    #[test]
    fn an_authorization_of_any_other_length_is_refused() {
        for len in [0usize, 1, 63, 65, 4626, 4628, 4693, 4695] {
            let err = submit_with_sig(len)
                .validate_shape()
                .expect_err("an invalid length has to be refused");
            assert!(err.contains("authorization_sig"), "{err}");
        }
    }

    /// A hash that is not a packed field element is refused at the shape gate,
    /// whichever of the three lists it sits in.
    #[test]
    fn a_hash_that_is_not_a_packed_element_is_refused() {
        let mut foreign = budlum_note_packing::hash_from_field(9);
        foreign[31] = 1;
        for slot in 0..3 {
            let mut sub = submit_with_sig(ED25519_AUTH_SIG_LEN);
            match slot {
                0 => sub.spent_commitments[0] = foreign,
                1 => sub.nullifiers[0] = foreign,
                _ => sub.output_commitments[0] = foreign,
            }
            let err = sub.validate_shape().unwrap_err();
            assert!(err.contains("packed field element"), "slot {slot}: {err}");
        }
    }
}
