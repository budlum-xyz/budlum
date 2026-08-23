//! TEE tanikligi: bir cevrimin ureticisini imzaya baglar.
//!
//! # Bu modulun onceki hali
//!
//! `TeeRuntime::sign` bir imza uretmiyordu: mesajin SHA3-256 ozetini 4627
//! baytlik bir tamponun ilk 32 baytina kopyalayip geri kalanini sifir
//! birakiyordu ve buna "sig" diyordu. Bunu dogrulayan taraf yoktu; zaten
//! `TeeAttestation::verify` yalnizca `self.signature.len() != 4627` bakiyordu
//! ve alan `[u8; 4627]` oldugu icin bu kosul derleme zamaninda her zaman
//! yanlisti. Yani dogrulama, hicbir seyi reddedemeyen bir dallanmaydi.
//!
//! Bir ozet imza degildir: ozeti herkes hesaplayabilir. O tampon, taniklik
//! anahtarini elinde tutmayan biri tarafindan da uretilebilirdi.
//!
//! # Simdi ne yapiyor
//!
//! Taniklik, bir ML-DSA-87 acik anahtarina baglanmis bir alintidir (quote) ve
//! imza gercekten dogrulanir. Modulun soyledigi sey sudur: "bu alintiyi, bu
//! anahtari elinde tutan taraf imzaladi".
//!
//! # Ne soylemiyor
//!
//! Alintinin *icerigi* burada dogrulanmaz: satici sertifika zincirinin
//! (Intel SGX icin PCK/QE kimligi, AWS Nitro icin ACM kok sertifikasi)
//! denetimi bu modulun disindadir ve dugum yapilandirmasindaki bir emanet
//! koku gerektirir. Bu yuzden [`TeeAttestation::verify_signed_by`] "bu bir gercek
//! SGX cihazi" demez, "bu alinti bu anahtarla imzalanmis ve anahtar bekledigim
//! anahtar" der. Ikisini karistirmamak icin tip adi `TeeAttestation`, metot
//! adi `verify_signed_by`: dogrulanan seyin ne oldugu cagri yerinde okunuyor.
//!
//! # Fail-closed
//!
//! Arka uc yoksa imzalama basarisiz olur; sessizce imzasiz veya duz metin
//! bir sonuc dondurulmez. Bir cagiran `Err`'i yok sayarsa taniklik hic
//! olusmaz, bos bir taniklik olusmaz.
//!
//! WIRING: unwired - olculdu, ve onceki gerekce bayattı.
//!
//! Eski gerekce "hesap soyutlamasi islem dogrulamasina baglanana kadar"
//! diyordu. Hesap soyutlamasi **baglandi**: `Transaction::verify_v6`
//! `threshold_mldsa`'yi cagiriyor ve V6 islemleri esik imzasiyla
//! dogrulaniyor. Yani beklenen kosul gerceklesti ve bu modul yine de
//! cagrilmiyor.
//!
//! Gercek sebep baska: bir islem **taniklik tasimiyor**. `verify_v6` sahip
//! kumesini, esigi ve imzalari okur; taniklik icin bir alan yok.
//!
//! Alan eklemek bir taahhut yuzeyi degisikligidir ve tek basina yapilmasi
//! dogru olmaz. Taniklik, imzalayan anahtarin *nerede* durdugu hakkinda bir
//! iddiadir; onu islemin icine koymak, dogrulayan tarafin o iddiayi neye
//! karsi denetleyecegini de gerektirir. Bu modul kendi sinirini zaten
//! soyluyor: `verify_signed_by` "bu gercek bir SGX cihazi" demez, "bu alinti
//! bu anahtarla imzalanmis" der. Satici sertifika zincirinin denetimi bir
//! emanet koku ister ve dugum yapilandirmasinda oyle bir kok yok.
//!
//! Yani zincire yazilabilecek tek sey, denetlenemeyen bir iddia olurdu.
//! `TeeGates` "uretim yolundan cagrilacak tek giris noktasi" olarak duruyor
//! ve o giris noktasi acildiginda tek satirlik bir baglama olacak; bugun
//! acilmiyor cunku arkasinda duracak emanet koku yok.

use crate::crypto::primitives::{
    verify_ml_dsa_87_signature, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};

/// Alintinin tasiyabilecegi en fazla bayt.
///
/// Alinti aga girdigi icin sinirsiz olamaz: sinir, tek bir taniklikla
/// dugume yuklenebilecek dogrulama isini sinirlar.
pub const MAX_QUOTE_LEN: usize = 16 * 1024;

/// Imzanin uzerine alindigi alan ayirici.
///
/// Ayni anahtarla imzalanan baska bir yapinin (ornegin bir islem) taniklik
/// gibi okunmasini engeller: imza her zaman bu on ekle birlikte uretilir.
pub const TEE_ATTESTATION_DOMAIN: &[u8] = b"BUDLUM_TEE_ATTESTATION_V1";

/// Taniklik hangi arka uctan geliyor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeBackendKind {
    Sgx,
    Nitro,
    Unavailable,
}

/// Yerel TEE calisma zamaninin durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeRuntimeStatus {
    Available,
    Unavailable,
    AttestationFailed,
}

/// Taniklik neden kabul edilmedi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeError {
    /// Arka uc yok: fail-closed.
    BackendUnavailable,
    /// Calisma zamani taniklik uretemedi.
    AttestationFailed,
    /// Alinti bos.
    EmptyQuote,
    /// Alinti [`MAX_QUOTE_LEN`] ustunde.
    QuoteTooLarge { len: usize },
    /// Taniklik, beklenen anahtardan baska bir anahtara ait.
    UnexpectedKey,
    /// ML-DSA-87 imzasi dogrulanmadi.
    InvalidSignature,
}

impl core::fmt::Display for TeeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BackendUnavailable => {
                write!(f, "KQ-WALLET-TEE: backend unavailable, refusing to proceed")
            }
            Self::AttestationFailed => write!(f, "KQ-WALLET-TEE: runtime attestation failed"),
            Self::EmptyQuote => write!(f, "KQ-WALLET-TEE: quote is empty"),
            Self::QuoteTooLarge { len } => write!(
                f,
                "KQ-WALLET-TEE: quote of {len} bytes exceeds the {MAX_QUOTE_LEN} byte limit"
            ),
            Self::UnexpectedKey => {
                write!(f, "KQ-WALLET-TEE: attestation key is not the expected one")
            }
            Self::InvalidSignature => write!(f, "KQ-WALLET-TEE: quote signature does not verify"),
        }
    }
}

impl std::error::Error for TeeError {}

/// Imzalanan baytlar: alan ayirici + arka uc + uzunluk onekli alinti.
///
/// Uzunluk oneki olmadan `quote = "ab" ++ "c"` ile `"a" ++ "bc"` ayni baytlara
/// duserdi; arka uc etiketi de ayni alintinin iki arka uc icin yeniden
/// kullanilmasini engeller.
#[must_use]
pub fn attestation_signing_payload(backend: TeeBackendKind, quote: &[u8]) -> Vec<u8> {
    let tag: u8 = match backend {
        TeeBackendKind::Sgx => 1,
        TeeBackendKind::Nitro => 2,
        TeeBackendKind::Unavailable => 0,
    };
    let mut out = Vec::with_capacity(TEE_ATTESTATION_DOMAIN.len() + 9 + quote.len());
    out.extend_from_slice(TEE_ATTESTATION_DOMAIN);
    out.push(tag);
    out.extend_from_slice(&(quote.len() as u64).to_be_bytes());
    out.extend_from_slice(quote);
    out
}

/// Bir TEE alintisi ve onu ureten anahtarin imzasi.
#[derive(Debug, Clone)]
pub struct TeeAttestation {
    pub backend: TeeBackendKind,
    pub quote: Vec<u8>,
    pub public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub signature: [u8; ML_DSA_87_SIGNATURE_LEN],
}

impl TeeAttestation {
    /// Alintinin `expected_key` tarafindan imzalandigini dogrular.
    ///
    /// Beklenen anahtarin cagri yerinden gelmesi kasitli: taniklik kendi
    /// anahtarini tasiyor, dolayisiyla kendi kendini dogrulayan bir taniklik
    /// hicbir sey kanitlamaz. Saldirgan kendi anahtar ciftini uretip kendi
    /// alintisini imzalayabilir. Guven, dugumun onceden bildigi anahtardan
    /// gelir.
    ///
    /// # Errors
    ///
    /// [`TeeError::BackendUnavailable`], [`TeeError::EmptyQuote`],
    /// [`TeeError::QuoteTooLarge`], [`TeeError::UnexpectedKey`],
    /// [`TeeError::InvalidSignature`].
    pub fn verify_signed_by(
        &self,
        expected_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    ) -> Result<(), TeeError> {
        if self.backend == TeeBackendKind::Unavailable {
            return Err(TeeError::BackendUnavailable);
        }
        if self.quote.is_empty() {
            return Err(TeeError::EmptyQuote);
        }
        if self.quote.len() > MAX_QUOTE_LEN {
            return Err(TeeError::QuoteTooLarge {
                len: self.quote.len(),
            });
        }
        if &self.public_key != expected_key {
            return Err(TeeError::UnexpectedKey);
        }
        let payload = attestation_signing_payload(self.backend, &self.quote);
        verify_ml_dsa_87_signature(&payload, &self.signature, &self.public_key)
            .map_err(|_| TeeError::InvalidSignature)
    }
}

/// Yerel TEE calisma zamani.
#[derive(Debug, Clone, Copy)]
pub struct TeeRuntime {
    pub backend: TeeBackendKind,
    pub status: TeeRuntimeStatus,
}

impl TeeRuntime {
    /// Calisma zamani taniklik uretebiliyor mu.
    ///
    /// # Errors
    ///
    /// [`TeeError::BackendUnavailable`], [`TeeError::AttestationFailed`].
    pub fn ensure_available(&self) -> Result<(), TeeError> {
        match self.status {
            TeeRuntimeStatus::Available if self.backend != TeeBackendKind::Unavailable => Ok(()),
            TeeRuntimeStatus::AttestationFailed => Err(TeeError::AttestationFailed),
            _ => Err(TeeError::BackendUnavailable),
        }
    }
}

/// KQ-* kapi yuzeyi: uretim yolundan cagrilacak tek giris noktasi.
pub struct TeeGates;

impl TeeGates {
    /// # Errors
    ///
    /// [`TeeAttestation::verify_signed_by`]'nin dondurdugu her hata.
    pub fn kq_wallet_tee_attestation(
        att: &TeeAttestation,
        expected_key: &[u8; ML_DSA_87_PUBLIC_KEY_LEN],
    ) -> Result<(), TeeError> {
        att.verify_signed_by(expected_key)
    }

    /// # Errors
    ///
    /// [`TeeRuntime::ensure_available`]'in dondurdugu her hata.
    pub fn kq_wallet_tee_runtime(runtime: &TeeRuntime) -> Result<(), TeeError> {
        runtime.ensure_available()
    }
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    fn attest(kp: &WalletKeyPair, backend: TeeBackendKind, quote: &[u8]) -> TeeAttestation {
        let payload = attestation_signing_payload(backend, quote);
        TeeAttestation {
            backend,
            quote: quote.to_vec(),
            public_key: kp.public_key_bytes(),
            signature: kp.sign(&payload),
        }
    }

    #[test]
    fn a_correctly_signed_quote_is_accepted() {
        let kp = WalletKeyPair::generate();
        let att = attest(&kp, TeeBackendKind::Sgx, b"quote bytes");
        assert_eq!(att.verify_signed_by(&kp.public_key_bytes()), Ok(()));
    }

    /// Iskeletin kaciridigi sey: imza yerine bir ozet konursa dogrulama
    /// reddetmeliydi, ama yalnizca uzunluga bakan bir kontrol bunu kabul eder.
    #[test]
    fn a_digest_in_place_of_a_signature_is_refused() {
        use sha3::{Digest, Sha3_256};
        let kp = WalletKeyPair::generate();
        let quote = b"quote bytes";
        let mut forged = [0u8; ML_DSA_87_SIGNATURE_LEN];
        let mut h = Sha3_256::new();
        h.update(quote);
        let digest: [u8; 32] = h.finalize().into();
        forged[..32].copy_from_slice(&digest);
        let att = TeeAttestation {
            backend: TeeBackendKind::Sgx,
            quote: quote.to_vec(),
            public_key: kp.public_key_bytes(),
            signature: forged,
        };
        assert_eq!(
            att.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::InvalidSignature)
        );
    }

    /// Saldirgan kendi anahtar ciftiyle kusursuz bir taniklik uretebilir.
    /// Reddedilmesinin tek nedeni anahtarin beklenen anahtar olmamasidir.
    #[test]
    fn a_self_signed_quote_from_an_unknown_key_is_refused() {
        let honest = WalletKeyPair::generate();
        let attacker = WalletKeyPair::generate();
        let att = attest(&attacker, TeeBackendKind::Sgx, b"quote bytes");
        assert_eq!(
            att.verify_signed_by(&honest.public_key_bytes()),
            Err(TeeError::UnexpectedKey)
        );
    }

    /// Bir arka uc icin uretilmis imza baska arka uc icin yeniden kullanilamaz.
    #[test]
    fn a_quote_signed_for_one_backend_does_not_verify_for_another() {
        let kp = WalletKeyPair::generate();
        let mut att = attest(&kp, TeeBackendKind::Sgx, b"quote bytes");
        att.backend = TeeBackendKind::Nitro;
        assert_eq!(
            att.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::InvalidSignature)
        );
    }

    #[test]
    fn an_empty_or_oversized_quote_is_refused() {
        let kp = WalletKeyPair::generate();
        let empty = attest(&kp, TeeBackendKind::Sgx, b"");
        assert_eq!(
            empty.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::EmptyQuote)
        );
        let big = vec![7u8; MAX_QUOTE_LEN + 1];
        let over = attest(&kp, TeeBackendKind::Sgx, &big);
        assert_eq!(
            over.verify_signed_by(&kp.public_key_bytes()),
            Err(TeeError::QuoteTooLarge {
                len: MAX_QUOTE_LEN + 1
            })
        );
    }

    #[test]
    fn an_unavailable_runtime_fails_closed() {
        let runtime = TeeRuntime {
            backend: TeeBackendKind::Unavailable,
            status: TeeRuntimeStatus::Unavailable,
        };
        assert_eq!(
            runtime.ensure_available(),
            Err(TeeError::BackendUnavailable)
        );
        let failed = TeeRuntime {
            backend: TeeBackendKind::Sgx,
            status: TeeRuntimeStatus::AttestationFailed,
        };
        assert_eq!(failed.ensure_available(), Err(TeeError::AttestationFailed));
        let ok = TeeRuntime {
            backend: TeeBackendKind::Sgx,
            status: TeeRuntimeStatus::Available,
        };
        assert_eq!(ok.ensure_available(), Ok(()));
    }

    /// Uzunluk oneki olmadan iki farkli alinti ayni baytlara duserdi.
    #[test]
    fn quote_framing_is_unambiguous() {
        let a = attestation_signing_payload(TeeBackendKind::Sgx, b"abc");
        let b = attestation_signing_payload(TeeBackendKind::Sgx, b"ab");
        assert_ne!(a, b);
        assert_ne!(
            attestation_signing_payload(TeeBackendKind::Sgx, b"x"),
            attestation_signing_payload(TeeBackendKind::Nitro, b"x")
        );
    }
}
