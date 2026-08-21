
//! WIRING: unwired - kuantum hesap soyutlama V2 (KQ-* kapilari) henuz ana
//! islem yoluna baglanmadi; `QuantumAccount` bu dalda yalnizca kendi
//! modulu ve testleri icinde yasiyor. Kapilarin tamami `validate_all`
//! altinda tek giris noktasindan cagrilir; ana zincire baglanma ayri bir
//! entegrasyon PR'i gerektirir (hesap modeli degisikligi).
//! Quantum-safe deterministic account abstraction V2 - storage-bound + BFT guardian finality
//! Kapılar + kaos + economics + threshold research

use sha3::{Digest, Sha3_256};

pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;
pub const MAX_MULTISIG_OWNERS: usize = 16;
pub const ADDRESS_DOMAIN_V2: &[u8] = b"BUDLUM_ADDRESS_V2";
pub const SEED_DOMAIN_V1: &[u8] = b"BUDLUM_MLDSA87_SEED_V1";
pub const RECOVERY_DOMAIN_V1: &[u8] = b"BUDLUM_WALLET_RECOVERY_PROPOSAL_V1";
pub const STORAGE_PACT_DOMAIN: &[u8] = b"BUDLUM_STORAGE_PACT_V1";
pub const BUD_MAGIC: [u8; 8] = *b"BUDLUM\x01\x00";

#[derive(Debug, Clone)]
pub struct QuantumAccount {
    pub address: [u8; 32],
    pub pq_public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub storage_root: [u8; 32],
    pub pact_root: [u8; 32],
    pub guardian_root: [u8; 32],
    pub guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
    pub multisig_threshold: usize,
    pub recovery_threshold: usize,
    pub timelock_blocks: u64,
    pub nonce: u64,
    pub balance: u64,
    pub storage_bytes: u64, // for economics
}

impl QuantumAccount {
    pub fn address_from_public_key(pubkey: &[u8; 2592]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(ADDRESS_DOMAIN_V2);
        h.update(pubkey);
        h.finalize().into()
    }

    pub fn seed_from_entropy(entropy: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(SEED_DOMAIN_V1);
        h.update(entropy);
        h.finalize().into()
    }

    pub fn guardian_root(guardians: &[[u8; 2592]]) -> [u8; 32] {
        let mut sorted = guardians.to_vec();
        sorted.sort();
        sorted.dedup();
        let mut h = Sha3_256::new();
        for g in sorted {
            h.update(g);
        }
        h.finalize().into()
    }

    pub fn storage_cost(&self) -> f64 {
        // physical 0.23342 * e / r, device-only 0
        // For simplicity: storage_bytes * 0.23342 / 1_099_511_627_776 (1TB) / 16.68 (Duz ratio)
        let tb = self.storage_bytes as f64 / 1_099_511_627_776.0;
        if self.storage_bytes == 0 { 0.0 } else { tb * 0.23342 / 16.68 }
    }

    pub fn verify_multisig_threshold(&self) -> Result<(), &'static str> {
        if self.guardians.is_empty() { return Err("KQ-WALLET-MULTISIG-16: guardians empty"); }
        if self.guardians.len() > MAX_MULTISIG_OWNERS { return Err("KQ-WALLET-MULTISIG-16: exceeds 16"); }
        if self.multisig_threshold==0 || self.multisig_threshold>self.guardians.len() { return Err("KQ-WALLET-MULTISIG-16: threshold outside"); }
        Ok(())
    }

    pub fn verify_recovery_policy(&self) -> Result<(), &'static str> {
        if self.guardians.is_empty() { return Err("KQ-WALLET-RECOVERY-16: empty"); }
        if self.guardians.len() > MAX_MULTISIG_OWNERS { return Err("KQ-WALLET-RECOVERY-16: exceeds 16"); }
        if self.recovery_threshold==0 || self.recovery_threshold>self.guardians.len() { return Err("KQ-WALLET-RECOVERY-16: threshold outside"); }
        Ok(())
    }

    pub fn verify_storage_bound(&self) -> Result<(), &'static str> {
        // storage_root zero but pact_root non-zero -> inconsistent
        if self.storage_root == [0u8;32] && self.pact_root != [0u8;32] {
            return Err("KQ-STORAGE-BOUND: storage_root zero but pact_root non-zero");
        }
        Ok(())
    }

    /// Tüm KQ-* guard'larını tek giriş noktasından çağırır.
    ///
    /// `verify_multisig_threshold`, `verify_recovery_policy` ve
    /// `verify_storage_bound` ayrı ayrı `pub` oldukları için gate bunların
    /// üretim yolundan çağrıldığını göremez; bu fonksiyon üçünü de sırayla
    /// doğrular ve ilk hatada döner. Ana zincire bağlanacak entegrasyonun
    /// çağıracağı tek yüzey budur.
    pub fn validate_all(&self) -> Result<(), &'static str> {
        self.verify_multisig_threshold()?;
        self.verify_recovery_policy()?;
        self.verify_storage_bound()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryProposal {
    pub current_owner: [u8; 2592],
    pub current_address: [u8; 32],
    pub new_owner: [u8; 2592],
    pub new_address: [u8; 32],
    pub created_block: u64,
    pub executable_after: u64,
}

impl RecoveryProposal {
    pub fn new(current_owner: [u8; 2592], new_owner: [u8; 2592], timelock: u64, created: u64) -> Result<Self, &'static str> {
        if current_owner==new_owner { return Err("KQ-WALLET-RECOVERY-16: new==current"); }
        let executable_after = created.checked_add(timelock).ok_or("KQ-WALLET-RECOVERY-16: timelock overflow")?;
        let current_address = QuantumAccount::address_from_public_key(&current_owner);
        let new_address = QuantumAccount::address_from_public_key(&new_owner);
        Ok(Self{current_owner, current_address, new_owner, new_address, created_block: created, executable_after})
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(RECOVERY_DOMAIN_V1);
        h.update(&self.current_owner);
        h.update(&self.current_address);
        h.update(&self.new_owner);
        h.update(&self.new_address);
        h.update(&self.created_block.to_be_bytes());
        h.update(&self.executable_after.to_be_bytes());
        h.finalize().into()
    }

    pub fn is_timelock_satisfied(&self, current: u64) -> bool { current >= self.executable_after }
}

#[derive(Debug, Clone)]
pub struct PactBinding {
    pub tarif_hash: [u8; 32],
    pub tohum: [u8; 32],
    pub commitment: [u8; 32],
    pub reziduel_commitment: [u8; 32],
    pub bayt_butcesi: u64,
}

impl PactBinding {
    pub fn new(tarif_hash: [u8;32], tohum: [u8;32], commitment: [u8;32], reziduel: [u8;32], butce: u64) -> Result<Self, &'static str> {
        if butce>128 { return Err("KQ-STORAGE-PACT: bayt_butcesi >128"); }
        Ok(Self{tarif_hash, tohum, commitment, reziduel_commitment: reziduel, bayt_butcesi: butce})
    }

    pub fn verify_commitment(&self, payload: &[u8]) -> Result<(), &'static str> {
        let mut h = Sha3_256::new();
        h.update(payload);
        let calc: [u8;32] = h.finalize().into();
        if calc != self.commitment { return Err("KQ-STORAGE-PACT: commitment mismatch"); }
        Ok(())
    }
}

// BFT finality for guardian votes (ratio of guardians)
#[derive(Debug, Clone)]
pub struct GuardianVote {
    pub guardian_id: [u8; 2592],
    pub proposal_digest: [u8; 32],
    pub signature: [u8; 4627],
}

pub struct BftGuardianFinality;

impl BftGuardianFinality {
    pub fn finalize(votes: Vec<GuardianVote>, n: usize, threshold: usize) -> Result<Vec<GuardianVote>, &'static str> {
        if votes.len() < threshold { return Err("K-BUD-BFT-GUARDIAN: quorum < threshold"); }
        let quorum = (n*2).div_ceil(3);
        if votes.len() < quorum { return Err("K-BUD-BFT-GUARDIAN: quorum <2n/3"); }
        Ok(votes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn address_v2() {
        let pk = [1u8; 2592];
        let addr = QuantumAccount::address_from_public_key(&pk);
        assert_eq!(addr.len(), 32);
    }
    #[test]
    fn multisig_16_ok() {
        let guardians = vec![[1u8;2592]; 16];
        let acc = QuantumAccount{
            address: [0u8;32], pq_public_key: [0u8;2592], storage_root: [0u8;32], pact_root: [0u8;32],
            guardian_root: QuantumAccount::guardian_root(&guardians),
            guardians, multisig_threshold: 10, recovery_threshold: 10, timelock_blocks: 100, nonce:0, balance:0, storage_bytes: 0
        };
        assert!(acc.verify_multisig_threshold().is_ok());
        assert!(acc.verify_storage_bound().is_ok());
    }
    #[test]
    fn storage_bound_fail() {
        let acc = QuantumAccount{
            address: [0u8;32], pq_public_key: [0u8;2592], storage_root: [0u8;32], pact_root: [1u8;32],
            guardian_root: [0u8;32], guardians: vec![[1u8;2592]], multisig_threshold:1, recovery_threshold:1, timelock_blocks:0, nonce:0, balance:0, storage_bytes:0
        };
        assert!(acc.verify_storage_bound().is_err());
    }
    #[test]
    fn pact_commitment() {
        let payload = b"hello";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8;32] = h.finalize().into();
        let pact = PactBinding::new([0u8;32], [0u8;32], comm, [0u8;32], 10).unwrap();
        assert!(pact.verify_commitment(payload).is_ok());
        assert!(pact.verify_commitment(b"other").is_err());
    }
    #[test]
    fn guardian_bft() {
        let votes = vec![
            GuardianVote{guardian_id: [1u8;2592], proposal_digest: [0u8;32], signature: vec![1u8;4627]},
            GuardianVote{guardian_id: [2u8;2592], proposal_digest: [0u8;32], signature: vec![1u8;4627]},
            GuardianVote{guardian_id: [3u8;2592], proposal_digest: [0u8;32], signature: vec![1u8;4627]},
        ];
        assert!(BftGuardianFinality::finalize(votes, 4, 2).is_ok());
    }
}
