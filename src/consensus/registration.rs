//! The validator key binding of a registration.
//!
//! A validator's address is its Ed25519 public key. Its primary signing key is ML-DSA-65. The
//! registration binds the two with two signatures over one payload: the Ed25519 key signs that
//! it claims the ML-DSA-65 key, and the ML-DSA-65 key signs that it accepts the Ed25519 key. Either
//! signature alone would let one key holder attach a key it does not control, so both are
//! required, and the payload carries the chain id so a binding made for one chain is no use on
//! another.

use sha3::{Digest, Sha3_256};

use crate::crypto::ctx;
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};

const BINDING_TAG: &[u8] = b"BDLM_VALIDATOR_BINDING_V1";

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// The Ed25519 address is not 32 bytes.
    BadAddress,
    /// The Ed25519 signature over the binding payload is invalid.
    Ed25519Signature,
    /// The ML-DSA-65 key or signature over the binding payload is invalid or not verifiable.
    PqSignature(String),
}

/// A validator key registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRegistration {
    /// The validator address: the Ed25519 public key.
    pub ed25519_public_key: Vec<u8>,
    /// The ML-DSA-65 public key.
    pub pq_public_key: Vec<u8>,
    /// Ed25519 signature over [`binding_payload`].
    pub ed25519_signature: Vec<u8>,
    /// ML-DSA-65 signature over [`binding_payload`], context `BDLM/KEY_BINDING/V1`.
    pub pq_signature: Vec<u8>,
}

fn push_field(hasher: &mut Sha3_256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

/// The digest both keys sign: tag, chain id and the two public keys, length prefixed.
#[must_use]
pub fn binding_payload(chain_id: u64, ed25519_public_key: &[u8], pq_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    push_field(&mut hasher, BINDING_TAG);
    hasher.update(chain_id.to_le_bytes());
    push_field(&mut hasher, ed25519_public_key);
    push_field(&mut hasher, pq_public_key);
    hasher.finalize().into()
}

/// Verifies both signatures of a registration under the scheme statuses of the chain.
///
/// # Errors
///
/// [`RegistrationError`] naming the first check that failed. Both signatures are required.
pub fn verify_registration(
    registry: &SchemeStatusRegistry,
    chain_id: u64,
    registration: &KeyRegistration,
) -> Result<(), RegistrationError> {
    if registration.ed25519_public_key.len() != 32 {
        return Err(RegistrationError::BadAddress);
    }
    let payload = binding_payload(
        chain_id,
        &registration.ed25519_public_key,
        &registration.pq_public_key,
    );
    verify_signature(
        &payload,
        &registration.ed25519_signature,
        &registration.ed25519_public_key,
    )
    .map_err(|_| RegistrationError::Ed25519Signature)?;
    pq::verify_in(
        registry,
        SchemeId::ML_DSA_65,
        &registration.pq_public_key,
        &payload,
        ctx::KEY_BINDING_V1,
        &registration.pq_signature,
    )
    .map_err(|e| RegistrationError::PqSignature(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const PQ_SEED: [u8; 32] = [21; 32];

    fn registration(chain_id: u64) -> KeyRegistration {
        let ed = SigningKey::from_bytes(&[22; 32]);
        let ed_pk = ed.verifying_key().to_bytes().to_vec();
        let pq_pk = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &PQ_SEED).expect("pq key");
        let payload = binding_payload(chain_id, &ed_pk, &pq_pk);
        let ed_sig = ed.sign(&payload).to_bytes().to_vec();
        let pq_sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &PQ_SEED,
            &payload,
            ctx::KEY_BINDING_V1,
            &[0; 32],
        )
        .expect("pq sig");
        KeyRegistration {
            ed25519_public_key: ed_pk,
            pq_public_key: pq_pk,
            ed25519_signature: ed_sig,
            pq_signature: pq_sig,
        }
    }

    #[test]
    fn a_registration_with_both_signatures_verifies() {
        let reg = registration(7);
        assert_eq!(
            verify_registration(&SchemeStatusRegistry::genesis(), 7, &reg),
            Ok(())
        );
    }

    #[test]
    fn a_binding_made_for_another_chain_is_refused() {
        let reg = registration(7);
        assert!(verify_registration(&SchemeStatusRegistry::genesis(), 8, &reg).is_err());
    }

    #[test]
    fn a_missing_ed25519_signature_is_refused() {
        let mut reg = registration(7);
        reg.ed25519_signature = vec![0; 64];
        assert_eq!(
            verify_registration(&SchemeStatusRegistry::genesis(), 7, &reg),
            Err(RegistrationError::Ed25519Signature)
        );
    }

    #[test]
    fn a_missing_pq_signature_is_refused() {
        let mut reg = registration(7);
        reg.pq_signature = vec![0; reg.pq_signature.len()];
        assert!(matches!(
            verify_registration(&SchemeStatusRegistry::genesis(), 7, &reg),
            Err(RegistrationError::PqSignature(_))
        ));
    }

    #[test]
    fn a_swapped_pq_key_is_refused() {
        let mut reg = registration(7);
        reg.pq_public_key =
            pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &[99; 32]).expect("other key");
        assert!(verify_registration(&SchemeStatusRegistry::genesis(), 7, &reg).is_err());
    }
}
