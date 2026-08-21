//! Kuantum direnci - NIST FIPS 204/205 FINAL (politika:
//! "kuantum NIST final haliyle kodlanmalı; Dilithium round-3 DEĞİL").
//!
//! NIST final suite'leri:
//!   - İmza: ML-DSA-87 (FIPS 204, Category 5) - Dilithium5 (round-3) RED.
//!   - KEM : ML-KEM-768 (FIPS 205, Category 3).
//!   - Hash: SHA3-256 (Grover 128-bit) - BLAKE3 opsiyonel.
//!     Ed25519/AES-128/SHA2-256 (eski) her zaman RED (KQ kapısı).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suite {
    MlDsa87Sha3MlKem768,            // NIST final (varsayılan)
    MlDsa65Sha3MlKem768,            // NIST final (Category 3)
    Dilithium5Aes256Blake3,         // round-3 ESKİ - RED (NIST final değil)
    Ed25519Aes128Sha256,            // eski, KQ'yu kırar - RED
}

#[derive(Debug, Clone)]
pub struct QuantumSuite {
    pub sig: &'static str,
    pub cipher: &'static str,
    pub hash: &'static str,
    pub kem: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantumError {
    NotQuantumResistant,
}

impl QuantumSuite {
    pub fn from_suite(s: Suite) -> Self {
        match s {
            Suite::MlDsa87Sha3MlKem768 => QuantumSuite { sig: "ML-DSA-87", cipher: "AES-256-GCM", hash: "SHA3-256", kem: Some("ML-KEM-768") },
            Suite::MlDsa65Sha3MlKem768 => QuantumSuite { sig: "ML-DSA-65", cipher: "AES-256-GCM", hash: "SHA3-256", kem: Some("ML-KEM-768") },
            Suite::Dilithium5Aes256Blake3 => QuantumSuite { sig: "Dilithium5", cipher: "AES-256-GCM-SIV", hash: "BLAKE3-256", kem: Some("ML-KEM-768") },
            Suite::Ed25519Aes128Sha256 => QuantumSuite { sig: "Ed25519", cipher: "AES-128", hash: "SHA2-256", kem: None },
        }
    }

    pub fn is_quantum_resistant(&self) -> Result<(), QuantumError> {
        // NIST FINAL kuralı: sig yalnız ML-DSA (FIPS 204) kabul; Dilithium5 (round-3) RED.
        let sig_ok = self.sig.starts_with("ML-DSA");
        let cipher_ok = self.cipher.contains("256");
        let hash_ok = self.hash.contains("SHA3-256") || self.hash.contains("BLAKE3");
        if sig_ok && cipher_ok && hash_ok {
            Ok(())
        } else {
            Err(QuantumError::NotQuantumResistant)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ml_dsa_87_final_gecer() {
        let s = QuantumSuite::from_suite(Suite::MlDsa87Sha3MlKem768);
        assert!(s.is_quantum_resistant().is_ok());
    }
    #[test]
    fn ml_dsa_65_final_gecer() {
        let s = QuantumSuite::from_suite(Suite::MlDsa65Sha3MlKem768);
        assert!(s.is_quantum_resistant().is_ok());
    }
    #[test]
    fn dilithium5_round3_reddedilir() {
        // NIST final DEĞİL - politika gereği RED
        let s = QuantumSuite::from_suite(Suite::Dilithium5Aes256Blake3);
        assert!(s.is_quantum_resistant().is_err(), "Dilithium5 (round-3) RED olmali");
    }
    #[test]
    fn ed25519_fails() {
        let s = QuantumSuite::from_suite(Suite::Ed25519Aes128Sha256);
        assert!(s.is_quantum_resistant().is_err());
    }
}
