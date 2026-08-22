//! Esik ML-DSA-87 yetkilendirme: t-of-n imza dogrulamasi.
//!
//! # Bu modulun onceki hali
//!
//! Bu dosya once bir iskeletti ve iskelet oldugunu kendi yorumlarinda
//! soyluyordu: `shamir_split` gercek Shamir degil `secret XOR index` idi,
//! `shamir_reconstruct` sabit bir maskeyle geri donuyordu ("This is NOT
//! secure, just for iskelet"), `verify` yalnizca dizinin uzunluguna bakiyordu.
//! Isimler ise gercek guvenlik gibi okunuyordu: `ThresholdMldsaSignature`,
//! `kq_threshold_mldsa_sig`. Bir cagiran bu yuzeye bakip esik imzalamanin
//! dogrulandigini varsayabilirdi.
//!
//! Iskelet, `src/account_abstraction/` dizini `lib.rs`'ten hic ulasilmadigi
//! icin derlenmiyordu bile; olculdu: dosyaya gecersiz Rust yazildiginda
//! `cargo check` yine geciyordu. Derlenmeyen kod, hicbir kapinin gormedigi
//! koddur.
//!
//! # Simdi ne yapiyor
//!
//! Sir paylasimi bu modulden tamamen kaldirildi. Bir zincir dogrulayicisinin
//! gizli anahtari boluyor olmasi icin bir neden yok: zincirin gordugu sey
//! imzalardir, anahtarlar degil. `t-of-n` sorusu "n sahipten en az t tanesi
//! bu mesaji imzaladi mi" sorusudur ve her imza tek basina
//! `verify_ml_dsa_87_signature` ile dogrulanir.
//!
//! Bu, esik imzalamanin (tek bir toplu imza ureten protokol) yerine gecmez;
//! `t` ayri imzayi tek tek dogrulayan coklu-imzadir. Fark tasarim geregidir
//! ve isimlendirmede saklanmaz: tip `MultisigAuthorization`, cunku yaptigi
//! sey budur.
//!
//! # Reddedilen seyler
//!
//! * Ayni imzalayanin iki kez sayilmasi. Sahip listesi yinelenirse veya ayni
//!   sahip iki imza gonderirse esik sahte olarak karsilanir.
//! * Listede olmayan bir sahibin imzasi.
//! * `t == 0`. Sifir esik "kimse imzalamasin yeter" demektir.
//! * `t > n`. Karsilanmasi imkansiz bir esik, sessizce her zaman reddeden bir
//!   hesap uretir; bu bir kilitlenmedir, hata olarak soylenir.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};

/// Bir hesabin tasiyabilecegi en fazla sahip sayisi.
///
/// Dogrulama maliyeti sahip sayisiyla dogru orantili: her imza bir ML-DSA-87
/// dogrulamasidir. Ust sinir, tek bir islemin dugume yukleyebilecegi isi
/// sinirlar.
pub const MAX_THRESHOLD_OWNERS: usize = 16;

/// Esik yapilandirmasi veya dogrulama neden reddedildi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// Sahip listesi bos.
    NoOwners,
    /// Sahip sayisi [`MAX_THRESHOLD_OWNERS`] ustunde.
    TooManyOwners { count: usize },
    /// Sahip listesinde ayni anahtar birden fazla kez var.
    DuplicateOwner,
    /// Esik sifir: hicbir imza istemeyen bir politika.
    ZeroThreshold,
    /// Esik sahip sayisindan buyuk: karsilanmasi imkansiz.
    ThresholdAboveOwnerCount { threshold: usize, owners: usize },
    /// Gecerli imza sayisi esigin altinda kaldi.
    ThresholdNotMet { valid: usize, threshold: usize },
    /// Imza, sahip listesinde olmayan bir anahtara ait.
    UnknownSigner { index: usize },
    /// Ayni sahip birden fazla imza gonderdi.
    RepeatedSigner { index: usize },
    /// Imza ML-DSA-87 dogrulamasindan gecmedi.
    InvalidSignature { index: usize },
}

impl core::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoOwners => write!(f, "KQ-THRESHOLD-MLDSA: owner set is empty"),
            Self::TooManyOwners { count } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: {count} owners exceeds the {MAX_THRESHOLD_OWNERS} allowed"
            ),
            Self::DuplicateOwner => {
                write!(f, "KQ-THRESHOLD-MLDSA: the owner set repeats a key")
            }
            Self::ZeroThreshold => write!(f, "KQ-THRESHOLD-MLDSA: threshold is zero"),
            Self::ThresholdAboveOwnerCount { threshold, owners } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: threshold {threshold} exceeds {owners} owners and can never be met"
            ),
            Self::ThresholdNotMet { valid, threshold } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: {valid} valid signatures below the threshold of {threshold}"
            ),
            Self::UnknownSigner { index } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: signature {index} is from a key outside the owner set"
            ),
            Self::RepeatedSigner { index } => write!(
                f,
                "KQ-THRESHOLD-MLDSA: signature {index} repeats an owner that already signed"
            ),
            Self::InvalidSignature { index } => {
                write!(f, "KQ-THRESHOLD-MLDSA: signature {index} does not verify")
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

/// Bir sahibin bir mesaj icin urettigi imza.
#[derive(Debug, Clone)]
pub struct OwnerSignature {
    /// Imzalayanin ML-DSA-87 acik anahtari.
    pub public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    /// FIPS 204 ML-DSA-87 imzasi.
    pub signature: [u8; ML_DSA_87_SIGNATURE_LEN],
}

/// `t-of-n` coklu imza politikasi.
///
/// Esik imzalama degil: `t` ayri imza tek tek dogrulanir. Isim bunu soyluyor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigPolicy {
    owners: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
    threshold: usize,
}

impl MultisigPolicy {
    /// Politikayi kurar ve karsilanamaz yapilandirmayi kurulusta reddeder.
    ///
    /// Reddetmenin dogrulama aninda degil burada olmasi onemli: `t > n` olan
    /// bir hesap her islemi reddeder ve disaridan "imzalar yanlis" gibi
    /// gorunur. Hata kurulusta soylenirse, kilitlenmis hesap hic olusmaz.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::NoOwners`], [`ThresholdError::TooManyOwners`],
    /// [`ThresholdError::DuplicateOwner`], [`ThresholdError::ZeroThreshold`],
    /// [`ThresholdError::ThresholdAboveOwnerCount`].
    pub fn new(
        owners: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
        threshold: usize,
    ) -> Result<Self, ThresholdError> {
        if owners.is_empty() {
            return Err(ThresholdError::NoOwners);
        }
        if owners.len() > MAX_THRESHOLD_OWNERS {
            return Err(ThresholdError::TooManyOwners {
                count: owners.len(),
            });
        }
        let mut sorted = owners.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        if sorted.len() != before {
            return Err(ThresholdError::DuplicateOwner);
        }
        if threshold == 0 {
            return Err(ThresholdError::ZeroThreshold);
        }
        if threshold > owners.len() {
            return Err(ThresholdError::ThresholdAboveOwnerCount {
                threshold,
                owners: owners.len(),
            });
        }
        Ok(Self { owners, threshold })
    }

    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    #[must_use]
    pub fn owners(&self) -> &[[u8; ML_DSA_87_PUBLIC_KEY_LEN]] {
        &self.owners
    }

    /// `message` icin gonderilen imzalarin esigi karsilayip karsilamadigi.
    ///
    /// Her imza tek tek dogrulanir; ayni sahibin iki imzasi bir sayilir, daha
    /// dogrusu ikincisi reddedilir. Bu, esigin en ucuz atlatma yoludur:
    /// bir anahtari elinde tutan taraf `t` kopya gonderip `t-of-n`'i tek
    /// basina karsilardi.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::UnknownSigner`], [`ThresholdError::RepeatedSigner`],
    /// [`ThresholdError::InvalidSignature`], [`ThresholdError::ThresholdNotMet`].
    pub fn verify(
        &self,
        message: &[u8],
        signatures: &[OwnerSignature],
    ) -> Result<(), ThresholdError> {
        let mut seen: Vec<&[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = Vec::with_capacity(signatures.len());
        for (index, entry) in signatures.iter().enumerate() {
            if !self.owners.contains(&entry.public_key) {
                return Err(ThresholdError::UnknownSigner { index });
            }
            if seen.contains(&&entry.public_key) {
                return Err(ThresholdError::RepeatedSigner { index });
            }
            verify_ml_dsa_87_signature(message, &entry.signature, &entry.public_key)
                .map_err(|_| ThresholdError::InvalidSignature { index })?;
            seen.push(&entry.public_key);
        }
        if seen.len() < self.threshold {
            return Err(ThresholdError::ThresholdNotMet {
                valid: seen.len(),
                threshold: self.threshold,
            });
        }
        Ok(())
    }
}

/// Bir mesaj ve onu yetkilendiren imzalar.
#[derive(Debug, Clone)]
pub struct MultisigAuthorization {
    pub signatures: Vec<OwnerSignature>,
}

impl MultisigAuthorization {
    /// # Errors
    ///
    /// [`MultisigPolicy::verify`]'nin dondurdugu her hata.
    pub fn authorize(&self, policy: &MultisigPolicy, message: &[u8]) -> Result<(), ThresholdError> {
        policy.verify(message, &self.signatures)
    }
}

/// KQ-* kapi yuzeyi: uretim yolundan cagrilacak tek giris noktasi.
pub struct ThresholdGates;

impl ThresholdGates {
    /// # Errors
    ///
    /// [`MultisigPolicy::verify`]'nin dondurdugu her hata.
    pub fn kq_threshold_mldsa_sig(
        policy: &MultisigPolicy,
        message: &[u8],
        auth: &MultisigAuthorization,
    ) -> Result<(), ThresholdError> {
        auth.authorize(policy, message)
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn owner() -> (WalletKeyPair, [u8; ML_DSA_87_PUBLIC_KEY_LEN]) {
        let kp = WalletKeyPair::generate();
        let pk = kp.public_key_bytes();
        (kp, pk)
    }

    fn sign_with(kp: &WalletKeyPair, msg: &[u8]) -> OwnerSignature {
        OwnerSignature {
            public_key: kp.public_key_bytes(),
            signature: kp.sign(msg),
        }
    }

    #[test]
    fn two_of_three_accepts_two_real_signatures() {
        let (a, pa) = owner();
        let (b, pb) = owner();
        let (_c, pc) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb, pc], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg), sign_with(&b, msg)],
        };
        assert_eq!(auth.authorize(&policy, msg), Ok(()));
    }

    #[test]
    fn one_signature_does_not_meet_a_threshold_of_two() {
        let (a, pa) = owner();
        let (_b, pb) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::ThresholdNotMet {
                valid: 1,
                threshold: 2
            })
        );
    }

    /// Esigin en ucuz atlatma yolu: tek anahtar sahibi ayni imzayi `t` kez
    /// gonderir. Sayim yinelenen imzalayaniyi elemezse `2-of-3` tek kisiyle
    /// karsilanir.
    #[test]
    fn the_same_owner_signing_twice_does_not_meet_a_threshold_of_two() {
        let (a, pa) = owner();
        let (_b, pb) = owner();
        let (_c, pc) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb, pc], 2).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, msg), sign_with(&a, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::RepeatedSigner { index: 1 })
        );
    }

    #[test]
    fn a_signature_from_outside_the_owner_set_is_refused() {
        let (_a, pa) = owner();
        let (_b, pb) = owner();
        let (outsider, _po) = owner();
        let policy = MultisigPolicy::new(vec![pa, pb], 1).expect("valid policy");
        let msg = b"transfer 100";
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&outsider, msg)],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::UnknownSigner { index: 0 })
        );
    }

    /// Baska bir mesaj icin uretilmis gecerli imza bu mesaji yetkilendirmez.
    /// Iskelet surumu bunu goremezdi: yalnizca uzunluga bakiyordu.
    #[test]
    fn a_signature_over_another_message_is_refused() {
        let (a, pa) = owner();
        let policy = MultisigPolicy::new(vec![pa], 1).expect("valid policy");
        let auth = MultisigAuthorization {
            signatures: vec![sign_with(&a, b"transfer 1")],
        };
        assert_eq!(
            auth.authorize(&policy, b"transfer 1000"),
            Err(ThresholdError::InvalidSignature { index: 0 })
        );
    }

    /// Tek bir bitin bozulmasi imzayi gecersiz kilmali.
    #[test]
    fn a_tampered_signature_is_refused() {
        let (a, pa) = owner();
        let policy = MultisigPolicy::new(vec![pa], 1).expect("valid policy");
        let msg = b"transfer 100";
        let mut entry = sign_with(&a, msg);
        entry.signature[0] ^= 0x01;
        let auth = MultisigAuthorization {
            signatures: vec![entry],
        };
        assert_eq!(
            auth.authorize(&policy, msg),
            Err(ThresholdError::InvalidSignature { index: 0 })
        );
    }

    #[test]
    fn an_unmeetable_or_empty_policy_is_refused_at_construction() {
        let (_a, pa) = owner();
        assert_eq!(
            MultisigPolicy::new(vec![], 1),
            Err(ThresholdError::NoOwners)
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa], 0),
            Err(ThresholdError::ZeroThreshold)
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa], 2),
            Err(ThresholdError::ThresholdAboveOwnerCount {
                threshold: 2,
                owners: 1
            })
        );
        assert_eq!(
            MultisigPolicy::new(vec![pa, pa], 1),
            Err(ThresholdError::DuplicateOwner)
        );
        let many = vec![pa; MAX_THRESHOLD_OWNERS + 1];
        assert_eq!(
            MultisigPolicy::new(many, 1),
            Err(ThresholdError::TooManyOwners {
                count: MAX_THRESHOLD_OWNERS + 1
            })
        );
    }
}
