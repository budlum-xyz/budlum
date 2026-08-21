//! B.U.D. 2.0 - ŞİFRELİ-PACT SINIFI (fikirler3.0 Y13)
//!
//! `ContentManifest`'teki şifreleme beyanının (Plaintext/ClientSide, manifest V3'te
//! id'ye bağlı) karşılığı PACT'e taşınır: `ClientSide` içerik otomatik rezidüel
//! sınıfa girer ve mod alanında `encrypted-residual` işareti taşır - "şifreli =
//! üretilemez" gerçeği ekonomiye girer. Tenant-içi dedup + şifreli sözlük geçerli;
//! çapraz-tenant dedup Pollen consent + PoW challenge ile (2.0 kararı korunur).
//! DÜRÜSTLÜK: zincir şifrelemeyi doğrulayamaz - işaret BEYANDIR, garanti satılmaz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const ENCPACT_MAGIC: [u8; 8] = *b"\xB5EPC1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionDecl {
    Plaintext,     // açık - üretilebilir sınıfa aday
    ClientSide,    // istemci şifreli - otomatik rezidüel (encrypted-residual)
}

/// Y13: sınıflandırma - ClientSide içerik rezidüel sınıfa girer.
pub fn class_for_decl(decl: EncryptionDecl) -> &'static str {
    match decl {
        EncryptionDecl::Plaintext => "regenerable-or-residual",
        EncryptionDecl::ClientSide => "encrypted-residual",
    }
}

/// Y13: şifreli PACT mod işareti (tarif alanı boş olabilir; fiyat tamamen
/// rezidüel + uyanıklık üzerinden - Y11 ile).
pub fn pact_mode_encrypted(decl: EncryptionDecl) -> bool {
    decl == EncryptionDecl::ClientSide
}

/// Y13: şifreli içerik üretilebilir sınıfa GİREMEZ (entropi reddi - canary).
/// Bir PACT'in üretilebilir sayılması için beyan Plaintext olmalı.
pub fn regenerable_ok(decl: EncryptionDecl) -> bool {
    decl == EncryptionDecl::Plaintext
}

/// Y13: beyan değişikliği id'ye bağlıdır (manifest V3 deseni) - aynı içerik kimliği
/// aynı beyanı taşımalı; değişiklik yeni kimlik üretir.
pub fn declaration_bound(content_id: &[u8; 32], decl: EncryptionDecl) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ENCPACT_MAGIC);
    h.update(content_id);
    h.update([match decl {
        EncryptionDecl::Plaintext => 0,
        EncryptionDecl::ClientSide => 1,
    }]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y13_sinif_ve_entropi_reddi() {
        assert_eq!(class_for_decl(EncryptionDecl::ClientSide), "encrypted-residual");
        assert_eq!(class_for_decl(EncryptionDecl::Plaintext), "regenerable-or-residual");
        assert!(pact_mode_encrypted(EncryptionDecl::ClientSide));
        assert!(!pact_mode_encrypted(EncryptionDecl::Plaintext));
        assert!(regenerable_ok(EncryptionDecl::Plaintext));
        assert!(!regenerable_ok(EncryptionDecl::ClientSide), "şifreli → üretilebilir değil");
    }

    #[test]
    fn y13_beyan_idye_bagli() {
        let cid = [7u8; 32];
        assert_eq!(declaration_bound(&cid, EncryptionDecl::Plaintext), declaration_bound(&cid, EncryptionDecl::Plaintext));
        // aynı kimlik farklı beyan → farklı bağ (değişiklik yeni kimlik üretir)
        assert_ne!(declaration_bound(&cid, EncryptionDecl::Plaintext), declaration_bound(&cid, EncryptionDecl::ClientSide));
    }
}
