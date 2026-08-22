//! Kuantum hesap kayıt defteri: hesap soyutlamanın durum katmanı.
//!
//! # Bu modül neden var
//!
//! `QuantumAccount` ve onun `validate_all` koruması yazılmıştı, gerçek
//! ML-DSA-87'ye bağlıydı ve testleri geçiyordu; ama hiçbir üretim yolu onu
//! çağırmıyordu, çünkü **hiçbir yerde saklanmıyordu**. Bir hesap türü, onu
//! tutan bir kayıt olmadan yalnızca bir tiptir.
//!
//! Kayıt defteri bir kapı olarak yazıldı: bir hesap ancak `validate_all`
//! geçerse içeri girer. Böylece "çok imzalı eşik 1..=16 arasında olmalı" ya
//! da "storage_root sıfırken pact_root sıfır olmamalı" gibi kurallar, kayıt
//! anında bir kez ve gerçekten uygulanır - sonradan okuyan her kod bunları
//! yeniden denetlemek zorunda kalmaz.
//!
//! # Sınır
//!
//! Bu katman hesabın **şeklini** doğrular. Bir işlemin çok imzalı yetkiyle
//! harcanması ayrı bir karardır: işlem şeması bugün tek imza taşıyor, çok
//! imzalı yetkilendirme yeni bir imza sürümü gerektiriyor. O iş buraya
//! değil, işlem şemasına ait.

use super::quantum_account::QuantumAccount;
use crate::storage::pact_binding::PactRegistry;
use std::collections::BTreeMap;

/// Kayıt defteri hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantumAccountRegistryError {
    /// Hesap `validate_all` denetiminden geçmedi.
    InvalidAccount { address: [u8; 32], reason: String },
    /// Aynı adres ikinci kez kaydedilmeye çalışıldı.
    AlreadyRegistered { address: [u8; 32] },
    /// Bilinmeyen adres.
    NotRegistered { address: [u8; 32] },
    /// Adres, hesabın açık anahtarından türetilen adresle uyuşmuyor.
    AddressDoesNotMatchKey {
        declared: [u8; 32],
        derived: [u8; 32],
    },
    /// Hesabın `pact_root`'u sunulan pact kümesinin köküyle eşleşmiyor.
    PactRootDoesNotMatchRegistry {
        declared: [u8; 32],
        computed: [u8; 32],
    },
    /// Sunulan pact kaydının kendi kökü bayat: içindeki pact'lerden yeniden
    /// hesaplanan kök, kaydın taşıdığı kökle aynı değil.
    PactRegistryRootIsStale { reason: &'static str },
}

impl std::fmt::Display for QuantumAccountRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAccount { address, reason } => write!(
                f,
                "quantum account {} refused: {reason}",
                hex::encode(address)
            ),
            Self::AlreadyRegistered { address } => {
                write!(
                    f,
                    "quantum account {} already registered",
                    hex::encode(address)
                )
            }
            Self::NotRegistered { address } => {
                write!(
                    f,
                    "quantum account {} is not registered",
                    hex::encode(address)
                )
            }
            Self::AddressDoesNotMatchKey { declared, derived } => write!(
                f,
                "declared address {} does not match the address derived from the public key {}",
                hex::encode(declared),
                hex::encode(derived)
            ),
            Self::PactRootDoesNotMatchRegistry { declared, computed } => write!(
                f,
                "declared pact root {} does not match the presented pact set root {}",
                hex::encode(declared),
                hex::encode(computed)
            ),
            Self::PactRegistryRootIsStale { reason } => {
                write!(f, "presented pact registry is inconsistent: {reason}")
            }
        }
    }
}

impl std::error::Error for QuantumAccountRegistryError {}

/// Kuantum hesapların kayıt defteri.
#[derive(Debug, Clone, Default)]
pub struct QuantumAccountRegistry {
    accounts: BTreeMap<[u8; 32], QuantumAccount>,
}

impl QuantumAccountRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hesabı kaydet.
    ///
    /// Kapı buradadır: `validate_all` geçmeyen bir hesap içeri girmez, ve
    /// bildirilen adres açık anahtardan türetilen adresle eşleşmek
    /// zorundadır. İkincisi olmadan bir hesap, başkasının anahtarını
    /// taşıyan bir adresle kaydedilebilirdi.
    ///
    /// # Errors
    ///
    /// Hesap geçersizse, adres anahtarla uyuşmuyorsa ya da adres zaten
    /// kayıtlıysa hata döner.
    pub fn register(&mut self, account: QuantumAccount) -> Result<(), QuantumAccountRegistryError> {
        let derived = QuantumAccount::address_from_public_key(&account.pq_public_key);
        if derived != account.address {
            return Err(QuantumAccountRegistryError::AddressDoesNotMatchKey {
                declared: account.address,
                derived,
            });
        }
        if let Err(reason) = account.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: account.address,
                reason: reason.to_string(),
            });
        }
        if self.accounts.contains_key(&account.address) {
            return Err(QuantumAccountRegistryError::AlreadyRegistered {
                address: account.address,
            });
        }
        self.accounts.insert(account.address, account);
        Ok(())
    }

    /// Hesabı, `pact_root`'unun adlandırdığı pact kümesiyle birlikte kaydet.
    ///
    /// `register` bir hesabın **şeklini** doğrular ve `pact_root`'u olduğu
    /// gibi kabul eder. Bu yeterli değildi: alan bir kök taşıyordu ama o
    /// kökün gerçek bir pact kümesini adlandırdığını hiçbir şey
    /// denetlemiyordu, dolayısıyla `pact_root` bir iddiaydı, bir bağlama
    /// değil. Aynı sınıf `ProofFixture::bind_verified`'da da vardı: bir
    /// alanın sıfırdan farklı olması, arkasında bir şey olduğu anlamına
    /// gelmez.
    ///
    /// İki kapı vardır. Sunulan kayıt defterinin kendi kökü içindeki
    /// pact'lerden yeniden hesaplanabilmeli, **ve** hesabın `pact_root`'u o
    /// köke eşit olmalı.
    ///
    /// # Errors
    ///
    /// [`register`](Self::register)'ın döndürdüğü her hata, ayrıca pact
    /// kaydının kökü bayatsa ya da hesabın kökü onunla eşleşmiyorsa hata
    /// döner.
    pub fn register_with_pacts(
        &mut self,
        account: QuantumAccount,
        pacts: &PactRegistry,
    ) -> Result<(), QuantumAccountRegistryError> {
        pacts
            .verify_root()
            .map_err(|reason| QuantumAccountRegistryError::PactRegistryRootIsStale { reason })?;
        if account.pact_root != pacts.root {
            return Err(QuantumAccountRegistryError::PactRootDoesNotMatchRegistry {
                declared: account.pact_root,
                computed: pacts.root,
            });
        }
        self.register(account)
    }

    #[must_use]
    pub fn get(&self, address: &[u8; 32]) -> Option<&QuantumAccount> {
        self.accounts.get(address)
    }

    #[must_use]
    pub fn is_registered(&self, address: &[u8; 32]) -> bool {
        self.accounts.contains_key(address)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Kayıtlı bir hesabı değiştir.
    ///
    /// Değişiklik sonrası hesap yine `validate_all`'dan geçer; geçmezse
    /// değişiklik uygulanmaz ve kayıt eski hâlinde kalır. Bir kaydın
    /// geçerliliği, ona yazan her yolun ayrı ayrı dikkatli olmasına
    /// bırakılmamalı.
    ///
    /// # Errors
    ///
    /// Adres kayıtlı değilse, ya da değişiklik hesabı geçersiz kılıyorsa
    /// hata döner.
    pub fn update<F>(
        &mut self,
        address: &[u8; 32],
        change: F,
    ) -> Result<(), QuantumAccountRegistryError>
    where
        F: FnOnce(&mut QuantumAccount),
    {
        let current = self
            .accounts
            .get(address)
            .ok_or(QuantumAccountRegistryError::NotRegistered { address: *address })?;
        let mut candidate = current.clone();
        change(&mut candidate);
        if let Err(reason) = candidate.validate_all() {
            return Err(QuantumAccountRegistryError::InvalidAccount {
                address: *address,
                reason: reason.to_string(),
            });
        }
        self.accounts.insert(*address, candidate);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN;

    fn account_with(threshold: usize, guardians: usize) -> QuantumAccount {
        let pk = [3u8; ML_DSA_87_PUBLIC_KEY_LEN];
        let guardian_keys: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = (0..guardians)
            .map(|i| {
                let mut g = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
                g[0] = u8::try_from(i + 1).unwrap_or(u8::MAX);
                g
            })
            .collect();
        QuantumAccount {
            address: QuantumAccount::address_from_public_key(&pk),
            pq_public_key: pk,
            storage_root: [0u8; 32],
            pact_root: [0u8; 32],
            guardian_root: QuantumAccount::guardian_root(&guardian_keys),
            guardians: guardian_keys,
            multisig_threshold: threshold,
            recovery_threshold: threshold,
            timelock_blocks: 10,
            nonce: 0,
            balance: 0,
            storage_bytes: 0,
        }
    }

    /// Geçerli bir hesap kaydedilebilmeli.
    #[test]
    fn a_valid_account_registers() {
        let mut registry = QuantumAccountRegistry::new();
        let account = account_with(2, 3);
        let address = account.address;
        registry.register(account).expect("gecerli hesap");
        assert!(registry.is_registered(&address));
        assert_eq!(registry.len(), 1);
    }

    /// `validate_all` artık gerçekten bir kapı: eşiği gardiyan sayısını aşan
    /// bir hesap içeri giremez. Bu koruma yazılmıştı ama hiçbir üretim yolu
    /// onu çağırmıyordu.
    #[test]
    fn an_account_whose_threshold_exceeds_its_guardians_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        let err = registry
            .register(account_with(5, 3))
            .expect_err("esik gardiyan sayisini asamaz");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::InvalidAccount { .. }
        ));
        assert!(registry.is_empty(), "reddedilen hesap kayda girmemeli");
    }

    /// Adres, hesabın kendi anahtarından türemeli.
    #[test]
    fn an_address_that_does_not_match_the_key_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        let mut account = account_with(2, 3);
        account.address = [7u8; 32];
        assert!(matches!(
            registry
                .register(account)
                .expect_err("adres anahtarla eslesmeli"),
            QuantumAccountRegistryError::AddressDoesNotMatchKey { .. }
        ));
    }

    /// Aynı hesap iki kez kaydedilemez.
    #[test]
    fn registering_the_same_account_twice_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        registry.register(account_with(2, 3)).expect("ilk kayit");
        assert!(matches!(
            registry
                .register(account_with(2, 3))
                .expect_err("ikinci kayit reddedilmeli"),
            QuantumAccountRegistryError::AlreadyRegistered { .. }
        ));
        assert_eq!(registry.len(), 1);
    }

    /// Geçersiz kılan bir değişiklik uygulanmamalı ve kayıt bozulmamalı.
    #[test]
    fn an_update_that_invalidates_the_account_is_refused_and_changes_nothing() {
        let mut registry = QuantumAccountRegistry::new();
        let account = account_with(2, 3);
        let address = account.address;
        registry.register(account).expect("gecerli hesap");

        let err = registry
            .update(&address, |a| a.multisig_threshold = 99)
            .expect_err("gecersiz kilan degisiklik reddedilmeli");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::InvalidAccount { .. }
        ));
        assert_eq!(
            registry.get(&address).map(|a| a.multisig_threshold),
            Some(2),
            "reddedilen degisiklik kaydi bozmamali"
        );
    }

    /// Gerçek bir pact kümesi taşıyan hesap kaydedilebilmeli.
    #[test]
    fn an_account_bound_to_its_pact_set_registers() {
        use crate::storage::pact_binding::Pact;
        use sha3::{Digest, Sha3_256};

        let payload = b"tarif";
        let mut h = Sha3_256::new();
        h.update(payload);
        let commitment: [u8; 32] = h.finalize().into();

        let mut pacts = PactRegistry::new();
        pacts.add_pact(
            Pact::new(
                [1u8; 32], [0u8; 32], [0u8; 32], commitment, [0u8; 32], 10, 0,
            )
            .expect("gecerli pact"),
        );

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = pacts.root;
        let address = account.address;

        let mut registry = QuantumAccountRegistry::new();
        registry
            .register_with_pacts(account, &pacts)
            .expect("kok eslesiyor");
        assert!(registry.is_registered(&address));
    }

    /// Uydurma bir `pact_root` reddedilmeli: alanın sıfırdan farklı olması
    /// arkasında bir pact kümesi olduğu anlamına gelmez.
    #[test]
    fn a_pact_root_naming_no_pact_set_is_refused() {
        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = [7u8; 32];

        let mut registry = QuantumAccountRegistry::new();
        let err = registry
            .register_with_pacts(account, &PactRegistry::new())
            .expect_err("uydurma kok reddedilmeli");
        assert!(matches!(
            err,
            QuantumAccountRegistryError::PactRootDoesNotMatchRegistry { .. }
        ));
        assert!(registry.is_empty(), "reddedilen hesap kayda girmemeli");
    }

    /// Bayat köklü bir pact kaydı kabul edilmemeli.
    #[test]
    fn a_pact_registry_with_a_stale_root_is_refused() {
        use crate::storage::pact_binding::Pact;

        let mut pacts = PactRegistry::new();
        pacts.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("gecerli pact"),
        );
        // Kok elle bozulur: icindeki pact'lerden yeniden hesaplanamaz.
        // Sifir kullanilmaz - sifir, bos kumenin gecerli koku.
        pacts.root = [0xAA; 32];

        let mut account = account_with(2, 3);
        account.storage_root = [9u8; 32];
        account.pact_root = [0xAA; 32];

        let mut registry = QuantumAccountRegistry::new();
        assert!(matches!(
            registry
                .register_with_pacts(account, &pacts)
                .expect_err("bayat kok reddedilmeli"),
            QuantumAccountRegistryError::PactRegistryRootIsStale { .. }
        ));
    }

    /// Bilinmeyen bir adres güncellenemez.
    #[test]
    fn updating_an_unknown_address_is_refused() {
        let mut registry = QuantumAccountRegistry::new();
        assert!(matches!(
            registry
                .update(&[1u8; 32], |a| a.nonce += 1)
                .expect_err("bilinmeyen adres"),
            QuantumAccountRegistryError::NotRegistered { .. }
        ));
    }
}
