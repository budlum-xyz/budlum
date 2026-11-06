//! Kuantum direnci - NIST FIPS 204/205 FINAL (politika:
//! "the quantum layer has to be coded in its final NIST form; NOT Dilithium
//! round-3").
//!
//! NIST final suite'leri:
//!   - Signature: ML-DSA-87 (FIPS 204, Category 5). Dilithium5 (round-3) is
//!     REFUSED.
//!   - KEM : ML-KEM-768 (FIPS 203, Category 3).
//!   - Hash: SHA3-256 (Grover 128-bit) - BLAKE3 opsiyonel.
//!     The legacy Ed25519, AES-128 and SHA2-256 are always REFUSED (the KQ
//!     gate).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suite {
    MlDsa87Sha3MlKem768,    // the final NIST form (the default)
    MlDsa65Sha3MlKem768,    // NIST final (Category 3)
    Dilithium5Aes256Blake3, // round-3, LEGACY - REFUSED (not the final NIST form)
    Ed25519Aes128Sha256,    // legacy, breaks KQ - REFUSED
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
            Suite::MlDsa87Sha3MlKem768 => QuantumSuite {
                sig: "ML-DSA-87",
                cipher: "AES-256-GCM",
                hash: "SHA3-256",
                kem: Some("ML-KEM-768"),
            },
            Suite::MlDsa65Sha3MlKem768 => QuantumSuite {
                sig: "ML-DSA-65",
                cipher: "AES-256-GCM",
                hash: "SHA3-256",
                kem: Some("ML-KEM-768"),
            },
            Suite::Dilithium5Aes256Blake3 => QuantumSuite {
                sig: "Dilithium5",
                cipher: "AES-256-GCM-SIV",
                hash: "BLAKE3-256",
                kem: Some("ML-KEM-768"),
            },
            Suite::Ed25519Aes128Sha256 => QuantumSuite {
                sig: "Ed25519",
                cipher: "AES-128",
                hash: "SHA2-256",
                kem: None,
            },
        }
    }

    pub fn is_quantum_resistant(&self) -> Result<(), QuantumError> {
        // The FINAL NIST rule: the signature is only accepted as ML-DSA
        // (FIPS 204); Dilithium5 (round-3) is REFUSED.
        // Every part is matched by its exact name: a prefix or a substring
        // would pass "ML-DSA-fake" or any cipher with "256" in its name.
        let sig_ok = matches!(self.sig, "ML-DSA-87" | "ML-DSA-65");
        let cipher_ok = matches!(self.cipher, "AES-256-GCM" | "AES-256-GCM-SIV");
        let hash_ok = matches!(self.hash, "SHA3-256" | "BLAKE3-256");
        // The key exchange is part of the suite: no KEM, or a legacy one, fails.
        let kem_ok = self.kem == Some("ML-KEM-768");
        if sig_ok && cipher_ok && hash_ok && kem_ok {
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
    fn dilithium5_round3_is_refused() {
        // NOT the final NIST form, so policy REFUSES it.
        let s = QuantumSuite::from_suite(Suite::Dilithium5Aes256Blake3);
        assert!(
            s.is_quantum_resistant().is_err(),
            "Dilithium5 (round-3) has to be REFUSED"
        );
    }
    #[test]
    fn names_are_matched_exactly_and_the_kem_is_required() {
        let good = QuantumSuite::from_suite(Suite::MlDsa87Sha3MlKem768);
        let mut fake_sig = good.clone();
        fake_sig.sig = "ML-DSA-fake";
        assert!(fake_sig.is_quantum_resistant().is_err());
        let mut odd_cipher = good.clone();
        odd_cipher.cipher = "XOR-256";
        assert!(odd_cipher.is_quantum_resistant().is_err());
        let mut no_kem = good.clone();
        no_kem.kem = None;
        assert!(no_kem.is_quantum_resistant().is_err());
        let mut old_kem = good;
        old_kem.kem = Some("RSA-2048");
        assert!(old_kem.is_quantum_resistant().is_err());
    }
    #[test]
    fn ed25519_fails() {
        let s = QuantumSuite::from_suite(Suite::Ed25519Aes128Sha256);
        assert!(s.is_quantum_resistant().is_err());
    }
}
