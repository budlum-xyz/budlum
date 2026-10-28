//! The composite block signature of a validator.
//!
//! A block is signed with the validator suite (`0x0002`): ML-DSA-65 and Ed25519 over one message
//! representative, both required. The validator address stays its Ed25519 public key, so a block
//! signature is accepted only when the Ed25519 half of the signing key is the producer's
//! address: a valid composite signature by some other key never stands in for the producer.
//! PoA and evidence signatures use the same suite and the same address rule under their own
//! contexts (`BDLM/POA/V2`, `BDLM/EVIDENCE/V2`), so a signature made for one purpose is no
//! signature for another.

use crate::crypto::composite::{
    verify_in, CompositeError, CompositeKeypair, CompositePublicKey, CompositeSignature,
};
use crate::crypto::ctx;
use crate::crypto::scheme::{SchemeStatusRegistry, SuiteId};

/// Why a block signature was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSignatureError {
    /// The public key or signature bytes do not decode.
    Malformed(String),
    /// The key is not of the validator suite.
    NotValidatorSuite(SuiteId),
    /// The Ed25519 half of the key is not the producer's address.
    WrongProducer,
    /// A component or the suite check failed.
    Rejected(String),
}

impl From<CompositeError> for BlockSignatureError {
    fn from(error: CompositeError) -> Self {
        Self::Rejected(error.to_string())
    }
}

/// Signs `message` with the validator composite key under `context`.
///
/// # Errors
///
/// [`CompositeError`] when the suite is not signable under the genesis statuses or a component
/// fails to sign.
pub fn sign_with_context(
    keypair: &CompositeKeypair,
    context: &[u8],
    message: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    Ok(keypair.sign(context, message, rnd)?.encode())
}

/// Signs `block_hash` with the validator composite key under the block context.
///
/// # Errors
///
/// See [`sign_with_context`].
pub fn sign_block(
    keypair: &CompositeKeypair,
    block_hash: &[u8; 32],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    sign_with_context(keypair, ctx::BLOCK_V6, block_hash, rnd)
}

/// Signs a PoA proposal digest under the PoA context.
///
/// # Errors
///
/// See [`sign_with_context`].
pub fn sign_poa(
    keypair: &CompositeKeypair,
    digest: &[u8; 32],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    sign_with_context(keypair, ctx::POA_V2, digest, rnd)
}

/// Signs an evidence header digest under the evidence context.
///
/// # Errors
///
/// See [`sign_with_context`].
/// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
pub fn sign_evidence(
    keypair: &CompositeKeypair,
    digest: &[u8; 32],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    sign_with_context(keypair, ctx::EVIDENCE_V2, digest, rnd)
}

/// Verifies a block signature against the producer's Ed25519 address.
///
/// # Errors
///
/// See [`verify_with_context`].
pub fn verify_block(
    registry: &SchemeStatusRegistry,
    producer: &[u8; 32],
    public_key: &[u8],
    block_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), BlockSignatureError> {
    verify_with_context(
        registry,
        producer,
        public_key,
        ctx::BLOCK_V6,
        block_hash,
        signature,
    )
}

/// Verifies a PoA signature. A block signature does not verify here: the contexts differ.
///
/// # Errors
///
/// See [`verify_with_context`].
pub fn verify_poa(
    registry: &SchemeStatusRegistry,
    signer: &[u8; 32],
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), BlockSignatureError> {
    verify_with_context(registry, signer, public_key, ctx::POA_V2, digest, signature)
}

/// Verifies an evidence signature, context `BDLM/EVIDENCE/V2`.
///
/// # Errors
///
/// See [`verify_with_context`].
pub fn verify_evidence(
    registry: &SchemeStatusRegistry,
    signer: &[u8; 32],
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), BlockSignatureError> {
    verify_with_context(
        registry,
        signer,
        public_key,
        ctx::EVIDENCE_V2,
        digest,
        signature,
    )
}

/// Signs a snapshot manifest digest under the snapshot context.
///
/// # Errors
///
/// See [`sign_with_context`].
/// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
pub fn sign_snapshot(
    keypair: &CompositeKeypair,
    manifest_digest: &[u8; 32],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, CompositeError> {
    sign_with_context(keypair, ctx::SNAPSHOT_V2, manifest_digest, rnd)
}

/// Verifies a snapshot manifest signature against a trusted signer address, context
/// `BDLM/SNAPSHOT/V2`. The trust list stays a list of Ed25519 addresses: the address of a
/// signer is the Ed25519 half of its composite key, so a snapshot is accepted only when that
/// address is trusted and both components verify.
///
/// # Errors
///
/// See [`verify_with_context`].
pub fn verify_snapshot(
    registry: &SchemeStatusRegistry,
    trusted_signer: &[u8; 32],
    public_key: &[u8],
    manifest_digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), BlockSignatureError> {
    verify_with_context(
        registry,
        trusted_signer,
        public_key,
        ctx::SNAPSHOT_V2,
        manifest_digest,
        signature,
    )
}

/// Verifies a validator composite signature under `context` against the signer's Ed25519 address.
///
/// # Errors
///
/// [`BlockSignatureError`] for undecodable bytes, a key of another suite, an Ed25519 half that is
/// not `producer`, or a failed composite verification (either component).
pub fn verify_with_context(
    registry: &SchemeStatusRegistry,
    producer: &[u8; 32],
    public_key: &[u8],
    context: &[u8],
    block_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), BlockSignatureError> {
    let public = CompositePublicKey::decode(public_key)
        .map_err(|e| BlockSignatureError::Malformed(e.to_string()))?;
    if public.suite != SuiteId::VALIDATOR {
        return Err(BlockSignatureError::NotValidatorSuite(public.suite));
    }
    if &public.ed != producer {
        return Err(BlockSignatureError::WrongProducer);
    }
    let signature = CompositeSignature::decode(signature)
        .map_err(|e| BlockSignatureError::Malformed(e.to_string()))?;
    verify_in(registry, &public, context, block_hash, &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ML_DSA_SEED_LEN;

    fn keypair(tag: u8) -> CompositeKeypair {
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[tag; ML_DSA_SEED_LEN], &[tag + 1; 32])
            .expect("keypair")
    }

    #[test]
    fn a_block_signed_by_the_producer_verifies() {
        let kp = keypair(1);
        let public = kp.public_key().expect("public");
        let hash = [5u8; 32];
        let sig = sign_block(&kp, &hash, &[0; 32]).expect("sign");
        assert_eq!(
            verify_block(
                &SchemeStatusRegistry::genesis(),
                &public.ed,
                &public.encode(),
                &hash,
                &sig
            ),
            Ok(())
        );
    }

    #[test]
    fn a_valid_signature_by_another_key_is_not_the_producer() {
        let signer = keypair(1);
        let other = keypair(3);
        let public = signer.public_key().expect("public");
        let hash = [5u8; 32];
        let sig = sign_block(&signer, &hash, &[0; 32]).expect("sign");
        let other_address = other.public_key().expect("public").ed;
        assert_eq!(
            verify_block(
                &SchemeStatusRegistry::genesis(),
                &other_address,
                &public.encode(),
                &hash,
                &sig
            ),
            Err(BlockSignatureError::WrongProducer)
        );
    }

    #[test]
    fn another_block_hash_is_refused() {
        let kp = keypair(1);
        let public = kp.public_key().expect("public");
        let sig = sign_block(&kp, &[5; 32], &[0; 32]).expect("sign");
        assert!(verify_block(
            &SchemeStatusRegistry::genesis(),
            &public.ed,
            &public.encode(),
            &[6; 32],
            &sig
        )
        .is_err());
    }

    #[test]
    fn contexts_do_not_cross() {
        let kp = keypair(1);
        let public = kp.public_key().expect("public");
        let registry = SchemeStatusRegistry::genesis();
        let hash = [5u8; 32];
        let block = sign_block(&kp, &hash, &[0; 32]).expect("block");
        let poa = sign_poa(&kp, &hash, &[0; 32]).expect("poa");
        let evidence = sign_evidence(&kp, &hash, &[0; 32]).expect("evidence");
        assert!(verify_block(&registry, &public.ed, &public.encode(), &hash, &block).is_ok());
        assert!(verify_poa(&registry, &public.ed, &public.encode(), &hash, &poa).is_ok());
        assert!(verify_evidence(&registry, &public.ed, &public.encode(), &hash, &evidence).is_ok());
        let snapshot = sign_snapshot(&kp, &hash, &[0; 32]).expect("snapshot");
        assert!(verify_snapshot(&registry, &public.ed, &public.encode(), &hash, &snapshot).is_ok());
        assert!(verify_snapshot(&registry, &public.ed, &public.encode(), &hash, &block).is_err());
        assert!(verify_poa(&registry, &public.ed, &public.encode(), &hash, &block).is_err());
        assert!(verify_evidence(&registry, &public.ed, &public.encode(), &hash, &poa).is_err());
        assert!(verify_block(&registry, &public.ed, &public.encode(), &hash, &evidence).is_err());
    }

    #[test]
    fn an_ed25519_only_signature_is_malformed() {
        let kp = keypair(1);
        let public = kp.public_key().expect("public");
        assert!(matches!(
            verify_block(
                &SchemeStatusRegistry::genesis(),
                &public.ed,
                &public.encode(),
                &[5; 32],
                &[0u8; 64]
            ),
            Err(BlockSignatureError::Malformed(_))
        ));
    }
}
