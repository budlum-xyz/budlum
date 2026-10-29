use crate::core::address::Address;
use crate::crypto::primitives::{BlsKeypair, CryptoError, KeyPair, PqKeyPair};

pub trait ConsensusSigner: Send + Sync {
    fn public_key_bytes(&self) -> [u8; 32];
    fn address(&self) -> Address {
        Address::from(self.public_key_bytes())
    }
    fn sign_block(&self, block_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
    /// Domain-separated default: a prevote over `msg` must never
    /// equal the block signature over the same bytes. The old default hashed
    /// the message bare, so one Ed25519 key produced interchangeable
    /// signatures for block, prevote and precommit.
    fn sign_prevote(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut tagged = b"BDLM_PREVOTE_ED25519_V1".to_vec();
        tagged.extend_from_slice(msg);
        self.sign_block(&crate::core::hash::calculate_hash_bytes(&tagged))
    }
    /// Domain-separated default , see [`Self::sign_prevote`].
    fn sign_precommit(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut tagged = b"BDLM_PRECOMMIT_ED25519_V1".to_vec();
        tagged.extend_from_slice(msg);
        self.sign_block(&crate::core::hash::calculate_hash_bytes(&tagged))
    }
    fn bls_sign(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "BLS signing not supported by this backend".to_string(),
        ))
    }
    /// Pure Ed25519 over `msg` itself, no prehash and no tag: the Ed25519
    /// half of a composite signature signs the composite message
    /// representative. A backend that cannot sign arbitrary
    /// messages keeps the default refusal.
    fn ed25519_sign_message(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "raw Ed25519 message signing not supported by this backend".to_string(),
        ))
    }
    /// Sign `msg` with the validator PQ key under the FIPS 204 context `ctx`.
    fn pq_sign(&self, _ctx: &[u8], _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "PQ signing not supported by this backend".to_string(),
        ))
    }
    /// Public BLS key advertised by this signer, if the backend owns one.
    ///
    /// This lets mainnet policy and finality code distinguish
    /// “Ed25519-only PKCS#11” from a backend that can also serve BLS material,
    /// Without exposing the BLS secret key to the consensus engine.
    fn bls_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    /// Public Dilithium/PQ key advertised by this signer, if the backend owns one.
    fn pq_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    fn has_bls_key(&self) -> bool {
        self.bls_public_key().is_some()
    }
    fn has_pq_key(&self) -> bool {
        self.pq_public_key().is_some()
    }
    fn backend_name(&self) -> &'static str;
}

pub struct KeyPairSigner {
    keypair: KeyPair,
    bls_key: Option<BlsKeypair>,
    pq_key: Option<PqKeyPair>,
}

impl KeyPairSigner {
    pub fn new(keypair: KeyPair) -> Self {
        Self {
            keypair,
            bls_key: None,
            pq_key: None,
        }
    }

    pub fn with_bls(mut self, bls: BlsKeypair) -> Self {
        self.bls_key = Some(bls);
        self
    }

    pub fn with_pq(mut self, pq: PqKeyPair) -> Self {
        self.pq_key = Some(pq);
        self
    }
}

impl ConsensusSigner for KeyPairSigner {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.public_key_bytes()
    }

    fn sign_block(&self, block_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.keypair.sign(block_hash).to_vec())
    }

    fn ed25519_sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.keypair.sign(msg).to_vec())
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bls = self
            .bls_key
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No BLS key available".to_string()))?;
        Ok(crate::chain::finality::sign_bls(&bls.secret_key, msg))
    }

    fn pq_sign(&self, ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pq = self
            .pq_key
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No PQ key available".to_string()))?;
        pq.sign(ctx, msg)
    }

    fn bls_public_key(&self) -> Option<Vec<u8>> {
        self.bls_key.as_ref().map(|bls| bls.public_key.clone())
    }

    fn pq_public_key(&self) -> Option<Vec<u8>> {
        self.pq_key
            .as_ref()
            .map(|pq| pq.public_key_bytes().to_vec())
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }
}

/// The validator-suite composite public key a signer holds: its ML-DSA-65
/// key and its Ed25519 key. `None` when the backend has no PQ key.
#[must_use]
pub fn composite_public_key(
    signer: &dyn ConsensusSigner,
) -> Option<crate::crypto::composite::CompositePublicKey> {
    Some(crate::crypto::composite::CompositePublicKey {
        suite: crate::crypto::scheme::SuiteId::VALIDATOR,
        pq: signer.pq_public_key()?,
        ed: signer.public_key_bytes(),
    })
}

/// A validator-suite composite signature made through a signer backend (an
/// HSM): ML-DSA-65 through `pq_sign` under `ctx` and Ed25519 through
/// `ed25519_sign_message`, both over the one composite message
/// representative, so `composite::verify_in` accepts it like a signature of
/// a local composite key. No secret leaves the backend.
///
/// # Errors
///
/// A backend without a PQ key or raw Ed25519 signing, or a component that
/// fails or returns a signature of the wrong length.
pub fn sign_composite_with(
    signer: &dyn ConsensusSigner,
    ctx: &[u8],
    payload: &[u8],
) -> Result<crate::crypto::composite::CompositeSignature, CryptoError> {
    let suite = crate::crypto::scheme::SuiteId::VALIDATOR;
    let m_prime = crate::crypto::composite::message_representative(suite, ctx, payload)
        .map_err(|e| CryptoError::Signing(e.to_string()))?;
    let pq = signer.pq_sign(ctx, &m_prime)?;
    let ed_bytes = signer.ed25519_sign_message(&m_prime)?;
    let ed = <[u8; 64]>::try_from(ed_bytes.as_slice())
        .map_err(|_| CryptoError::Signing("the Ed25519 half is not 64 bytes".into()))?;
    Ok(crate::crypto::composite::CompositeSignature { suite, pq, ed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_signer_advertises_bls_pq_capabilities_only_when_bound() {
        let keypair = KeyPair::generate().expect("ed25519 key");
        let signer = KeyPairSigner::new(keypair.clone());
        assert!(!signer.has_bls_key());
        assert!(!signer.has_pq_key());
        assert!(signer.bls_public_key().is_none());
        assert!(signer.pq_public_key().is_none());

        let bls = BlsKeypair::generate().expect("bls key");
        let pq = PqKeyPair::generate();
        let expected_bls_pk = bls.public_key.clone();
        let expected_pq_pk = pq.public_key_bytes().to_vec();

        let signer = KeyPairSigner::new(keypair).with_bls(bls).with_pq(pq);
        assert!(signer.has_bls_key());
        assert!(signer.has_pq_key());
        assert_eq!(signer.bls_public_key(), Some(expected_bls_pk));
        assert_eq!(signer.pq_public_key(), Some(expected_pq_pk));
    }

    #[test]
    fn default_consensus_signer_rejects_missing_bls_pq_material() {
        let signer = KeyPairSigner::new(KeyPair::generate().expect("ed25519 key"));
        assert!(signer.bls_sign(b"msg").is_err());
        assert!(signer
            .pq_sign(crate::crypto::ctx::BLOCK_V6, b"msg")
            .is_err());
    }

    /// through a signer backend: the composite signature it assembles
    /// verifies under the composite public key it reports.
    #[test]
    fn a_signer_backend_makes_a_verifiable_composite_signature() {
        let keypair = KeyPair::generate().unwrap();
        let signer = KeyPairSigner::new(keypair).with_pq(PqKeyPair::generate());
        let public = composite_public_key(&signer).expect("PQ key present");
        let signature =
            sign_composite_with(&signer, crate::crypto::ctx::BLOCK_V6, &[7u8; 32]).unwrap();
        assert!(crate::crypto::composite::verify(
            &public,
            crate::crypto::ctx::BLOCK_V6,
            &[7u8; 32],
            &signature
        )
        .is_ok());
        assert!(sign_composite_with(
            &KeyPairSigner::new(KeyPair::generate().unwrap()),
            b"c",
            b"m"
        )
        .is_err());
    }
}
