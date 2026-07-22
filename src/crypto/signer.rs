use crate::core::address::Address;
use crate::crypto::primitives::{BlsKeypair, CryptoError, KeyPair, PqKeyPair};

pub trait ConsensusSigner: Send + Sync {
    fn public_key_bytes(&self) -> [u8; 32];
    fn address(&self) -> Address {
        Address::from(self.public_key_bytes())
    }
    fn sign_block(&self, block_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
    fn sign_prevote(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_block(&crate::core::hash::calculate_hash_bytes(_msg))
    }
    fn sign_precommit(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_block(&crate::core::hash::calculate_hash_bytes(_msg))
    }
    fn bls_sign(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "BLS signing not supported by this backend".to_string(),
        ))
    }
    fn pq_sign(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "PQ signing not supported by this backend".to_string(),
        ))
    }
    /// Public BLS key advertised by this signer, if the backend owns one.
    ///
    /// Task 2 §1.1: this lets mainnet policy and finality code distinguish
    /// “Ed25519-only PKCS#11” from a backend that can also serve BLS material,
    /// without exposing the BLS secret key to the consensus engine.
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

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bls = self
            .bls_key
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No BLS key available".to_string()))?;
        Ok(crate::chain::finality::sign_bls(&bls.secret_key, msg))
    }

    fn pq_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pq = self
            .pq_key
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No PQ key available".to_string()))?;
        pq.sign(msg)
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
        assert!(signer.pq_sign(b"msg").is_err());
    }
}
