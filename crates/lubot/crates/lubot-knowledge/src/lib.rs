// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-knowledge - kapalı-devre bilgi katmanı
//!
//! Lubot'un kapalı-devre ilkesini koruyarak kaynak kod ve dokümanlardan
//! bilgi üretir: sır maskeleme (`redact`), satır-aralıklı parçalama
//! (`chunk`), bağımlılıksız TF-IDF gömme (`embed`), kompakt bağlam
//! tablosu (`context`), görev hafızası (`memory`) ve LLM çıktı
//! önbelleği (`cache`).
//!
//! Tüm modüller yalnızca `std` + `serde` + `sha2` taşır; harici vektör
//! API'si veya bulut hizmeti yoktur. Veri, bu crate'in ürettiği
//! JSONL/SQLite dosyalarında ve Lubot'un kendi B.U.D. kayıtlarında
//! kalır.

pub mod cache;
pub mod chunk;
pub mod context;
pub mod embed;
pub mod memory;
pub mod redact;

/// İçerik için sabit kararlı SHA-256 özeti.
///
/// # Errors
///
/// Yalnızca SHA-256 başlatma hatasında (pratikte imkânsız).
pub fn content_hash(data: &[u8]) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_is_stable_and_distinct() {
        let a = super::content_hash(b"budlum").unwrap();
        let b = super::content_hash(b"budlum").unwrap();
        let c = super::content_hash(b"budlun").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
