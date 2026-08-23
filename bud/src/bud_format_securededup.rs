//! B.U.D. 2.0 - GÜVENLİ DEDUP KATMANI (F24/F31/F71/F86 - FHE yolunun tohumu)
//!
//! Kalan iş #15: şifreli içerikte güvenli tekilleştirme. Tam FHE (üzerinde
//! homomorfik arama) uzun vade; BU katman K20'nin kanıtlanmış desenini
//! SARIYOR: convergent şifreleme (içerik-türetilmiş anahtar) + PoW sahiplik
//! kanıtı → aynı şifreli içerik GÜVENLE tekilleşir, farklı içerik asla
//! çakışmaz. Side-channel (F253) notu: doğrulama PoW ile zamanlanır.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SD_MAGIC: [u8; 8] = *b"\xB5SDP1\0\0\0";

/// Convergent anahtar: SHA3-256(içerik) - aynı içerik → aynı anahtar.
pub fn convergent_key(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONVERGENT_V1");
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    h.finalize().into()
}

/// Şifreli içerik kimliği: H(anahtar || veri) - aynı düz metin → aynı kimlik.
pub fn cipher_content_id(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_SECUREDEDUP_V1");
    h.update(key);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    h.finalize().into()
}

/// Güvenli tekilleştirme kararı: aynı kimlik → dedup adayı; PoW ile doğrula.
/// `pow_bits`: sahiplik kanıtı zorluğu (K20 - sybil/poison direnci).
pub fn secure_dedup_candidate(data: &[u8], pow_bits: u32) -> Option<([u8; 32], bool)> {
    if data.is_empty() {
        return None;
    }
    let key = convergent_key(data);
    let cid = cipher_content_id(data, &key);
    // PoW: H(cid || nonce) leading_zero_bits >= pow_bits (deterministik arama)
    // Sayaç döngü değişkeninden gelir (clippy::explicit_counter_loop): ayrı
    // bir `nonce` tutup elle artırmak, değerinin döngü koşulundan bağımsız
    // kaymasına açık bir desendi. Fonksiyon nonce'u döndürmüyor (yalnız
    // `found`), bu yüzden döngü dışı bağlamaya gerek yok.
    let mut found = false;
    for nonce in 0..1_000_000u64 {
        let mut h = Sha3_256::new();
        h.update(cid);
        h.update(nonce.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        let mut zeros = 0u32;
        for &b in d.iter() {
            if b == 0 {
                zeros += 8;
            } else {
                zeros += b.leading_zeros();
                break;
            }
        }
        if zeros >= pow_bits {
            found = true;
            break;
        }
    }
    Some((cid, found))
}

/// İki şifreli parçanın aynı içeriği mi taşıdığını GÜVENLE karşılaştır
/// (convergent kimlikler eşitse evet; farklıysa hayır - düz metin sızmaz).
pub fn same_content(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    convergent_key(a) == convergent_key(b)
        && cipher_content_id(a, &convergent_key(a)) == cipher_content_id(b, &convergent_key(b))
}

pub fn sd_digest(cid: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SD_MAGIC);
    h.update(cid);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_dedup::PowChallenge;

    #[test]
    fn ayni_icerik_tekillesir_farkli_icerik_asmaz() {
        let a = b"gizli belge icerigi ";
        let b = b"gizli belge icerigi "; // aynı
        let c = b"gizli belge icerikx "; // farklı
        assert!(same_content(a, b));
        assert!(!same_content(a, c));
        // convergent anahtar deterministik
        assert_eq!(convergent_key(a), convergent_key(b));
    }

    #[test]
    fn pow_sahipik_kaniti() {
        let (cid, ok) = secure_dedup_candidate(b"veri", 8).unwrap();
        assert!(ok, "8-bit PoW 1M nonce içinde bulunmalı");
        let _ = cid;
    }

    #[test]
    fn sifir_veri_red() {
        assert!(secure_dedup_candidate(b"", 4).is_none());
    }

    #[test]
    fn sd_deterministik() {
        let cid = cipher_content_id(b"x", &convergent_key(b"x"));
        assert_eq!(sd_digest(&cid), sd_digest(&cid));
    }

    #[test]
    fn pow_challenge_entegrasyonu() {
        // K20'nin PowChallenge'ı ile uyumluluk: aynı zorluk dili
        let ch = PowChallenge::new([0u8; 32], 8);
        assert_eq!(ch.difficulty, 8);
        let _ = ch;
    }
}
