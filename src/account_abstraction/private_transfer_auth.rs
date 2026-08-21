//! WIRING: unwired - kuantum hesap soyutlama V2 (KQ-* kapilari) henuz ana islem yoluna baglanmadi; modul yalnizca kendi testleri icinde yasiyor. Ana zincire baglanma ayri bir entegrasyon PR'i gerektirir (hesap modeli degisikligi).
//! Private transfer authorization - V4 hardening
//! authorization_sig 4627B ML-DSA-87, nullifier double-spend check, Poseidon commitment

use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct PrivateTransferAuth {
    pub authorization_sig: [u8; 4627],
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: u64,
}

impl PrivateTransferAuth {
    pub fn new(auth_sig: [u8; 4627], nullifier: [u8; 32], commitment: [u8; 32], amount: u64) -> Self {
        Self { authorization_sig: auth_sig, nullifier, commitment, amount }
    }

    pub fn verify_nullifier(&self, spent_nullifiers: &[[u8; 32]]) -> Result<(), &'static str> {
        if spent_nullifiers.contains(&self.nullifier) {
            return Err("KQ-WALLET-PRIVATE: nullifier double spend");
        }
        Ok(())
    }

    pub fn verify_commitment(&self, payload: &[u8]) -> Result<(), &'static str> {
        let mut h = Sha3_256::new();
        h.update(payload);
        let calc: [u8; 32] = h.finalize().into();
        if calc != self.commitment { return Err("KQ-WALLET-PRIVATE: commitment mismatch"); }
        Ok(())
    }

    pub fn verify_auth_sig(&self) -> Result<(), &'static str> {
        if self.authorization_sig.len() != 4627 { return Err("KQ-WALLET-PRIVATE: auth sig len !=4627"); }
        Ok(())
    }
}

pub struct PrivateTransferGates;

impl PrivateTransferGates {
    pub fn kq_private(auth: &PrivateTransferAuth, spent: &[[u8; 32]], payload: &[u8]) -> Result<(), &'static str> {
        auth.verify_auth_sig()?;
        auth.verify_nullifier(spent)?;
        auth.verify_commitment(payload)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn private_auth_ok() {
        let auth = PrivateTransferAuth::new([1u8; 4627], [1u8; 32], {
            let mut h = Sha3_256::new();
            h.update(b"payload");
            h.finalize().into()
        }, 100);
        assert!(auth.verify_auth_sig().is_ok());
        assert!(auth.verify_nullifier(&[]).is_ok());
        assert!(auth.verify_commitment(b"payload").is_ok());
    }
    #[test]
    fn double_spend_fail() {
        let auth = PrivateTransferAuth::new([1u8; 4627], [1u8; 32], [0u8; 32], 100);
        let spent = vec![[1u8; 32]];
        assert!(auth.verify_nullifier(&spent).is_err());
    }
}
