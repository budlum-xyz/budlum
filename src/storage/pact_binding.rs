//! Depolama PACT baglamasi: tarif + rezidüel taahhüdü ve kayit koku.
//!
//! # Nereden cagriliyor
//!
//! `QuantumAccountRegistry::register_with_pacts` bir hesabin `pact_root`
//! alanini buradaki kayit defterinin koküyle karsilastirir
//! (`src/account_abstraction/registry.rs`). Uzun sure oyle degildi: hesap
//! bir `pact_root` tasiyordu ama o kokün gercek bir pact kumesini
//! adlandirdigini hicbir sey denetlemiyordu, dolayisiyla alan bir iddiaydi,
//! bir baglama degil.
//!
//! # Ne dogrulanir
//!
//! Bir pact'in taahhüdü kendi yükünün hash'i olmali (`verify_commitment`),
//! ve kayit defterinin koku icindeki pact'lerden yeniden hesaplanabilmeli
//! (`verify_root`). Ikincisi olmadan bir kok, hicbir pact icermeyen bir
//! kumeyle de eslesebilirdi.

use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct Pact {
    pub id: [u8; 32],
    pub tarif_hash: [u8; 32],
    pub tohum: [u8; 32],
    pub commitment: [u8; 32],
    pub reziduel_commitment: [u8; 32],
    pub bayt_butcesi: u64,
    pub mod_flag: u8, // 0=saf üretim, 1=tarif+rezidüel, 2=rezidüel-yalnız
}

impl Pact {
    /// # Errors
    ///
    /// Returns an error when the byte budget exceeds 128 or the mode flag is
    /// outside the `0..=2` range.
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        id: [u8; 32],
        tarif_hash: [u8; 32],
        tohum: [u8; 32],
        commitment: [u8; 32],
        reziduel: [u8; 32],
        butce: u64,
        mod_flag: u8,
    ) -> Result<Self, &'static str> {
        if butce > 128 {
            return Err("KQ-STORAGE-PACT: bayt_butcesi >128");
        }
        if mod_flag > 2 {
            return Err("KQ-STORAGE-PACT: mod_flag >2");
        }
        Ok(Self {
            id,
            tarif_hash,
            tohum,
            commitment,
            reziduel_commitment: reziduel,
            bayt_butcesi: butce,
            mod_flag,
        })
    }

    /// # Errors
    ///
    /// Returns an error when the payload does not hash to the committed value.
    pub fn verify_commitment(&self, payload: &[u8]) -> Result<(), &'static str> {
        let mut h = Sha3_256::new();
        h.update(payload);
        let calc: [u8; 32] = h.finalize().into();
        if calc != self.commitment {
            return Err("KQ-STORAGE-PACT: commitment mismatch");
        }
        Ok(())
    }

    #[must_use]
    pub fn is_pure_production(&self) -> bool {
        self.mod_flag == 0 && self.reziduel_commitment == [0u8; 32]
    }
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_residual_only(&self) -> bool {
        self.mod_flag == 2
    }
}

#[derive(Debug, Clone)]
pub struct PactRegistry {
    pub pacts: Vec<Pact>,
    pub root: [u8; 32],
}

impl Default for PactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PactRegistry {
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new() -> Self {
        Self {
            pacts: Vec::new(),
            root: [0u8; 32],
        }
    }

    pub fn add_pact(&mut self, pact: Pact) {
        self.pacts.push(pact);
        self.recompute_root();
    }

    pub fn recompute_root(&mut self) {
        self.root = self.computed_root();
    }

    /// Kayittaki pact'lerden kökü hesapla, saklanan kökü okumadan.
    ///
    /// Boş küme sıfıra taahhüt eder. `new()` sıfır kök ile başlıyordu ama
    /// hesap `H(etiket)` veriyordu: taze bir kayıt kendi `verify_root`'undan
    /// geçemiyordu. İki cevaptan sıfır seçildi, çünkü hesap tarafında sıfır
    /// `pact_root` zaten "pact yok" demek (`kq_storage_bound` onu böyle
    /// okuyor); boş kümeye ayrı bir etiket hash'i vermek aynı durumu iki
    /// farklı bayt dizisiyle anlatırdı.
    #[must_use]
    pub fn computed_root(&self) -> [u8; 32] {
        if self.pacts.is_empty() {
            return [0u8; 32];
        }
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PACT_REGISTRY_V1");
        for p in &self.pacts {
            h.update(p.id);
            h.update(p.commitment);
        }
        h.finalize().into()
    }

    /// # Errors
    ///
    /// Returns an error when the recomputed root does not match the stored
    /// root.
    pub fn verify_root(&self) -> Result<(), &'static str> {
        if self.computed_root() != self.root {
            return Err("KQ-STORAGE-PACT: root mismatch");
        }
        Ok(())
    }
}

pub struct PactGates;

impl PactGates {
    /// # Errors
    ///
    /// Returns an error when the pact commitment does not match its payload.
    pub fn kq_storage_pact(pact: &Pact, payload: &[u8]) -> Result<(), &'static str> {
        pact.verify_commitment(payload)
    }
    /// # Errors
    ///
    /// Returns an error when the registry root is stale.
    pub fn kq_pact_registry(registry: &PactRegistry) -> Result<(), &'static str> {
        registry.verify_root()
    }
    /// # Errors
    ///
    /// Returns an error when the storage root is zero while the pact root is
    /// non-zero.
    pub fn kq_storage_bound(
        storage_root: &[u8; 32],
        pact_root: &[u8; 32],
    ) -> Result<(), &'static str> {
        if storage_root == &[0u8; 32] && pact_root != &[0u8; 32] {
            return Err("KQ-STORAGE-BOUND: storage_root zero but pact_root non-zero");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pact_commitment_ok() {
        let payload = b"hello";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0).unwrap();
        assert!(pact.verify_commitment(payload).is_ok());
        assert!(pact.is_pure_production());
    }
    /// Taze bir kayit kendi kokuyle tutarli olmali.
    ///
    /// `new()` sifir kok ile basliyor; hesap ondan farkli bir deger
    /// donseydi bos bir kayit kendi `verify_root`'undan gecemezdi.
    #[test]
    fn an_empty_registry_agrees_with_its_own_root() {
        let reg = PactRegistry::new();
        assert_eq!(reg.computed_root(), [0u8; 32]);
        assert!(reg.verify_root().is_ok());
    }

    /// Bir pact eklenince kok sifirdan cikmali.
    #[test]
    fn adding_a_pact_moves_the_root_off_zero() {
        let mut reg = PactRegistry::new();
        reg.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("gecerli pact"),
        );
        assert_ne!(
            reg.root, [0u8; 32],
            "dolu kume bos kumeyle ayni kokte olamaz"
        );
        assert!(reg.verify_root().is_ok());
    }

    /// Elle bozulmus bir kok reddedilmeli.
    #[test]
    fn a_hand_edited_root_is_refused() {
        let mut reg = PactRegistry::new();
        reg.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("gecerli pact"),
        );
        reg.root = [0xAA; 32];
        assert!(reg.verify_root().is_err());
    }

    #[test]
    fn registry_root() {
        let mut reg = PactRegistry::new();
        let payload = b"data";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0).unwrap();
        reg.add_pact(pact);
        assert!(reg.verify_root().is_ok());
    }
}
