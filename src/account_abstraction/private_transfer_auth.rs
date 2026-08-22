//! Gizli transfer yetkilendirmesi: nullifier + baglanti (commitment) + imza.
//!
//! # Bu modulun onceki hali
//!
//! Uc dogrulamanin ucu de bos cikiyordu:
//!
//! * `verify_auth_sig` yalnizca `self.authorization_sig.len() != 4627` bakiyordu.
//!   Alan `[u8; 4627]` oldugu icin bu kosul derleme zamaninda her zaman
//!   yanlisti; fonksiyon `Ok(())` disinda bir sey donduremezdi. Imza hic
//!   dogrulanmiyordu, hicbir anahtara bagli degildi.
//! * `verify_commitment` yalnizca `SHA3-256(payload)` hesapliyordu. Baglanti
//!   tutari, nullifier'i veya hesabi icermedigi icin ayni yuku tasiyan farkli
//!   bir transfer ayni baglantiyi verirdi.
//! * `verify_nullifier` dogruydu ama `verify_auth_sig` bos oldugu icin tek
//!   basina bir sey ifade etmiyordu: harcamayi kimin yetkilendirdigi
//!   bilinmiyordu.
//!
//! Dizin `lib.rs`'ten hic ulasilmadigi icin bu uc bosluk derlenmiyordu bile.
//!
//! # Simdi ne yapiyor
//!
//! Yetkilendirme, tutari ve nullifier'i da iceren bir baglanti uzerine
//! atilmis gercek bir ML-DSA-87 imzasidir. Nullifier harcanmislar kumesine
//! karsi denetlenir.
//!
//! # Ne soylemiyor
//!
//! Bu bir sifir-bilgi devresi degildir: modul, nullifier'in gercekten
//! harcanan cikisa ait oldugunu *kanitlamaz*, cunku bunu kanitlayan sey
//! kanit sistemidir. Modulun soyledigi sey sudur: "bu nullifier daha once
//! gorulmedi ve bu tam yetkilendirme, bu anahtar tarafindan imzalandi".
//! Gizlilik iddiasi burada yapilmaz; yapilan sey cifte harcamayi ve
//! yetkisiz harcamayi ayirmaktir.
//!
//! WIRING: unwired - olculdu, ve isaretin eski gerekcesi yanlisti. Uretimde
//! bir gizli transfer yolu **var**: `TransactionType::PrivateTransferSubmit`
//! -> `Executor` (`src/execution/executor.rs`). O yol bu modulu cagirmiyor,
//! ayni isi ikinci kez yaziyor. Bu modul su an yalnizca testlerden ulasilir.
//!
//! # Iki uygulama ayni sey degil
//!
//! Fark olculdu, tahmin edilmedi. Uretimin imzaladigi on-goruntu
//! (`compute_public_digest`) nullifier'lari ve cikis baglantilarini
//! kapsar; **tutari kapsamaz**, cunku tutar gizli transferde acikta
//! tasinmaz. Bu modulun on-goruntusu (`authorization_payload`) tutari da
//! baglar, cunku burada tutar biliniyor varsayilir.
//!
//! Ikisi ayni soruya iki farkli cevap uretir, dolayisiyla biri digerinin
//! yerine gecirilemez: bir tarafin urettigi imza otekinde dogrulanmaz.
//! Birlestirme, hangi modelin dogru oldugu kararini gerektirir - tutar
//! zincirde acikta mi, degil mi. Bu bir uzlasma yuzeyi karari oldugu icin
//! kendi commit'inde yapilir; iki uygulamayi "benziyorlar" diye birlestirmek
//! sessizce yeni bir imza semasi yaratirdi.
//!
//! Kayit `PLAN.md` Borc K deseninin ayni sinifi: ayni isin iki yerde ayri
//! yazilmasi, once **olculur**, sonra tek kaynaga indirilir.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

/// Baglantinin alan ayiricisi.
pub const PRIVATE_TRANSFER_COMMITMENT_DOMAIN: &[u8] = b"BUDLUM_PRIVATE_TRANSFER_COMMITMENT_V1";
/// Yetkilendirme imzasinin alan ayiricisi.
pub const PRIVATE_TRANSFER_AUTH_DOMAIN: &[u8] = b"BUDLUM_PRIVATE_TRANSFER_AUTH_V1";

/// Gizli transfer neden reddedildi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateTransferError {
    /// Nullifier daha once harcanmis: cifte harcama.
    NullifierAlreadySpent,
    /// Baglanti, bildirilen alanlarla uyusmuyor.
    CommitmentMismatch,
    /// Tutar sifir.
    ZeroAmount,
    /// ML-DSA-87 yetkilendirme imzasi dogrulanmadi.
    InvalidAuthorization,
}

impl core::fmt::Display for PrivateTransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NullifierAlreadySpent => {
                write!(f, "KQ-WALLET-PRIVATE: nullifier was already spent")
            }
            Self::CommitmentMismatch => write!(
                f,
                "KQ-WALLET-PRIVATE: commitment does not match the declared transfer"
            ),
            Self::ZeroAmount => write!(f, "KQ-WALLET-PRIVATE: amount is zero"),
            Self::InvalidAuthorization => {
                write!(
                    f,
                    "KQ-WALLET-PRIVATE: authorization signature does not verify"
                )
            }
        }
    }
}

impl std::error::Error for PrivateTransferError {}

/// Transferin baglantisi: nullifier, tutar ve gizleyici birlikte.
///
/// Gizleyici (`blinding`) olmadan baglanti tahmin edilebilirdi: tutar
/// alani dar bir kumeden geliyorsa (1, 10, 100 ...) saldirgan olasi tum
/// baglantilari hesaplayip tutari geri okurdu.
#[must_use]
pub fn transfer_commitment(nullifier: &[u8; 32], amount: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PRIVATE_TRANSFER_COMMITMENT_DOMAIN);
    h.update(nullifier);
    h.update(amount.to_be_bytes());
    h.update(blinding);
    h.finalize().into()
}

/// Yetkilendirme imzasinin uzerine alindigi baytlar.
#[must_use]
pub fn authorization_payload(commitment: &[u8; 32], nullifier: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRIVATE_TRANSFER_AUTH_DOMAIN.len() + 72);
    out.extend_from_slice(PRIVATE_TRANSFER_AUTH_DOMAIN);
    out.extend_from_slice(commitment);
    out.extend_from_slice(nullifier);
    out.extend_from_slice(&amount.to_be_bytes());
    out
}

/// Bir gizli transferin yetkilendirmesi.
#[derive(Debug, Clone)]
pub struct PrivateTransferAuth {
    pub authorization_sig: [u8; ML_DSA_87_SIGNATURE_LEN],
    pub spender_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: u64,
}

impl PrivateTransferAuth {
    /// Nullifier harcanmislar kumesinde mi.
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::NullifierAlreadySpent`].
    pub fn verify_nullifier(&self, spent: &BTreeSet<[u8; 32]>) -> Result<(), PrivateTransferError> {
        if spent.contains(&self.nullifier) {
            return Err(PrivateTransferError::NullifierAlreadySpent);
        }
        Ok(())
    }

    /// Baglanti, bildirilen nullifier ve tutarla yeniden hesaplandiginda
    /// tutuyor mu.
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::ZeroAmount`], [`PrivateTransferError::CommitmentMismatch`].
    pub fn verify_commitment(&self, blinding: &[u8; 32]) -> Result<(), PrivateTransferError> {
        if self.amount == 0 {
            return Err(PrivateTransferError::ZeroAmount);
        }
        if transfer_commitment(&self.nullifier, self.amount, blinding) != self.commitment {
            return Err(PrivateTransferError::CommitmentMismatch);
        }
        Ok(())
    }

    /// Yetkilendirme imzasi gecerli mi.
    ///
    /// # Errors
    ///
    /// [`PrivateTransferError::InvalidAuthorization`].
    pub fn verify_auth_sig(&self) -> Result<(), PrivateTransferError> {
        let payload = authorization_payload(&self.commitment, &self.nullifier, self.amount);
        verify_ml_dsa_87_signature(&payload, &self.authorization_sig, &self.spender_key)
            .map_err(|_| PrivateTransferError::InvalidAuthorization)
    }
}

/// KQ-* kapi yuzeyi: uretim yolundan cagrilacak tek giris noktasi.
pub struct PrivateTransferGates;

impl PrivateTransferGates {
    /// Uc denetimi sirayla yapar: imza, baglanti, cifte harcama.
    ///
    /// # Errors
    ///
    /// [`PrivateTransferAuth`]'in uc dogrulayicisinin dondurdugu her hata.
    pub fn kq_private(
        auth: &PrivateTransferAuth,
        spent: &BTreeSet<[u8; 32]>,
        blinding: &[u8; 32],
    ) -> Result<(), PrivateTransferError> {
        auth.verify_auth_sig()?;
        auth.verify_commitment(blinding)?;
        auth.verify_nullifier(spent)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn authorized(
        kp: &WalletKeyPair,
        nullifier: [u8; 32],
        amount: u64,
        blinding: &[u8; 32],
    ) -> PrivateTransferAuth {
        let commitment = transfer_commitment(&nullifier, amount, blinding);
        let payload = authorization_payload(&commitment, &nullifier, amount);
        PrivateTransferAuth {
            authorization_sig: kp.sign(&payload),
            spender_key: kp.public_key_bytes(),
            nullifier,
            commitment,
            amount,
        }
    }

    #[test]
    fn a_correctly_authorized_transfer_is_accepted() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 100, &blinding);
        assert_eq!(
            PrivateTransferGates::kq_private(&auth, &BTreeSet::new(), &blinding),
            Ok(())
        );
    }

    #[test]
    fn a_spent_nullifier_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 100, &blinding);
        let mut spent = BTreeSet::new();
        spent.insert([1u8; 32]);
        assert_eq!(
            PrivateTransferGates::kq_private(&auth, &spent, &blinding),
            Err(PrivateTransferError::NullifierAlreadySpent)
        );
    }

    /// Iskeletin kaciridigi sey: imza hicbir anahtara bagli degildi, yani
    /// rastgele baytlar da kabul edilirdi.
    #[test]
    fn arbitrary_bytes_in_place_of_a_signature_are_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 100, &blinding);
        auth.authorization_sig = [1u8; ML_DSA_87_SIGNATURE_LEN];
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    /// Yetkilendirme tutari kapsadigi icin tutari degistirmek imzayi bozar.
    /// Baglanti tutari kapsamasaydi, 1 icin alinan yetki 1000 harcardi.
    #[test]
    fn raising_the_amount_after_signing_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 1, &blinding);
        auth.amount = 1000;
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
        assert_eq!(
            auth.verify_commitment(&blinding),
            Err(PrivateTransferError::CommitmentMismatch)
        );
    }

    /// Bir nullifier icin alinan yetki baska nullifier'a tasinamaz.
    #[test]
    fn an_authorization_cannot_be_replayed_on_another_nullifier() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&kp, [1u8; 32], 100, &blinding);
        auth.nullifier = [2u8; 32];
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    /// Baska bir taraf ayni transferi kendi anahtariyla yetkilendiremez.
    #[test]
    fn an_authorization_from_another_key_is_refused() {
        let owner = WalletKeyPair::generate();
        let attacker = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let mut auth = authorized(&owner, [1u8; 32], 100, &blinding);
        auth.spender_key = attacker.public_key_bytes();
        assert_eq!(
            auth.verify_auth_sig(),
            Err(PrivateTransferError::InvalidAuthorization)
        );
    }

    #[test]
    fn a_zero_amount_is_refused() {
        let kp = WalletKeyPair::generate();
        let blinding = [9u8; 32];
        let auth = authorized(&kp, [1u8; 32], 0, &blinding);
        assert_eq!(
            auth.verify_commitment(&blinding),
            Err(PrivateTransferError::ZeroAmount)
        );
    }

    /// Gizleyici olmadan baglanti tahmin edilebilirdi; farkli gizleyici
    /// farkli baglanti vermeli.
    #[test]
    fn the_blinding_factor_changes_the_commitment() {
        let a = transfer_commitment(&[1u8; 32], 100, &[1u8; 32]);
        let b = transfer_commitment(&[1u8; 32], 100, &[2u8; 32]);
        assert_ne!(a, b);
    }
}
