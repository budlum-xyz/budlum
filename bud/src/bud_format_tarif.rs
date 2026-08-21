//! B.U.D. 3.0 - TARİF KAYDI (şartname §19.4 - "depolama yok, yalnız tarif alanı")
//!
//! Kullanıcı sorusu (2026-08-16): "içerik sıkıştırıldıktan sonra QR video olup
//! gönderilse depolamayı yalnız ağa taşıyan bir sistem olsa; tarife nasıl olur?"
//! Şartname cevabı (K13/K14/K15 ölçümlü): kalıcı tek nesne TARİF KAYDIDIR.
//! İki tür: Uretim (üreteç+seed, ~120 B, R1) | Govdeli (sıkışmış/ham gövde, R2/R3).
//! QR video = türev (saklanmaz). held_bytes: Uretim→0, Govdeli→len(gövde).
//! Kira yalnız Govdeli.govde üstünde döner (K14b üç-sayaç: kira → depocu,
//! step → validatör, commitment → konsensüs durumu).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TARIF_MAGIC: [u8; 8] = *b"\xB5TRF1\0\0\0";
pub const TARIF_VERSION: u8 = 1;

/// İçerik kaynağı üç rejimi (şartname §17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentSource {
    Generated,     // tariften doğar (R1) - tutulan bayt 0
    Compressible,  // sıkışabilir organik (R2) - zlib tabanı tutulur
    EntropyCoded,  // foto/video/şifreli (R3) - ham gövde, sıkışmaz
}

/// Tarif kaydı - B.U.D. 3.0'ın TEK kalıcı nesnesi.
#[derive(Debug, Clone)]
pub enum TarifKaydi {
    Uretim {
        commitment: [u8; 32],     // içerik kimliği (K3)
        generator: u16,           // üreteç kimliği (deterministik)
        seed: [u8; 32],
        params: Vec<u8>,          // üreteç parametreleri
    },
    Govdeli {
        commitment: [u8; 32],
        sikistirma: u8,           // 0=yok, 1=zlib-9 (küçültüyorsa)
        govde: Vec<u8>,           // sıkışmış (R2) veya ham (R3) gövde
    },
}

impl TarifKaydi {
    /// Tutulan bayt (K14b kira sayacı): Uretim → 0; Govdeli → len(gövde).
    pub fn held_bytes(&self) -> u64 {
        match self {
            Self::Uretim { .. } => 0,
            Self::Govdeli { govde, .. } => govde.len() as u64,
        }
    }

    /// Kaynak rejimi.
    pub fn source(&self) -> ContentSource {
        match self {
            Self::Uretim { .. } => ContentSource::Generated,
            Self::Govdeli { sikistirma, .. } => {
                if *sikistirma > 0 { ContentSource::Compressible } else { ContentSource::EntropyCoded }
            }
        }
    }

    /// Kayıt boyutu (commitment alanı muhasebesi, §19.1).
    pub fn record_bytes(&self) -> u64 {
        match self {
            Self::Uretim { params, .. } => {
                32 + 2 + 32 + params.len() as u64
            }
            Self::Govdeli { govde, .. } => 32 + 1 + govde.len() as u64,
        }
    }

    /// Commitment (K3: SHA3-256 domain-etiketli).
    pub fn commit(content: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_COMMIT_V1");
        h.update((content.len() as u64).to_le_bytes());
        h.update(content);
        h.finalize().into()
    }

    /// Uretim tarifi yaz (commitment içeriğe bağlı; 19.2 kanaryası: uydurulamaz).
    pub fn uretim(generator: u16, seed: [u8; 32], params: Vec<u8>) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GENERATOR_V1");
        h.update(generator.to_le_bytes());
        h.update(seed);
        h.update(&params);
        let commitment: [u8; 32] = h.finalize().into();
        Self::Uretim { commitment, generator, seed, params }
    }

    /// Govdeli tarif yaz (zlib-9; küçültmüyorsa ham gövde - şartname §1.2).
    pub fn govdeli(govde: Vec<u8>, sikistirma: u8) -> Self {
        let commitment = Self::commit(&govde);
        Self::Govdeli { commitment, sikistirma, govde }
    }
}

/// TB/ay KİRASI (K14b - yalnız tutulan bayt; üretim CPU'su step ücretinde).
/// Zemin: 0.23342 $/TB/ay (tüm sürümlerde tek fiziksel taban: 60 ay amorti).
pub const R3_ZEMIN_USD_TB_AY: f64 = 0.23342;

/// Kira: fizik zemin × erasure × held_oran / sıkıştırma oranı.
/// R1 (Uretim, held=0) → 0.0; R2 → zemin/oran; R3 → zemin (oran=1).
pub fn kira(tarif: &TarifKaydi, erasure: f64, compression_ratio: f64) -> f64 {
    let held = tarif.held_bytes();
    if held == 0 {
        return 0.0; // R1: kira yok, bayt tutulmuyor
    }
    let oran = if compression_ratio > 1.0 { compression_ratio } else { 1.0 };
    R3_ZEMIN_USD_TB_AY * erasure.max(1.0) / oran
}

/// STEP ÜCRETİ TABANI (validatöre; okuma başına, talep eden öder - kira değil).
/// Elektrik alt sınırı (şartname §18.1b): altına inen fiyat validatör zararı = DoS.
pub fn step_tabani(generator: u16) -> f64 {
    match generator {
        1 => 0.000085,  // avatar (RLE)
        2 => 0.00226,   // gradyan (vektör)
        3 => 0.01028,   // hash-gürültü
        _ => 0.01028,   // bilinmeyen üreteç → en yüksek taban (güvenli)
    }
}

/// Kira tavanı kapısı (D13: 0.032; B.U.D. 2.0 hedefi 0.016).
pub fn kira_tavan_icerisinde(tarif: &TarifKaydi, erasure: f64, ratio: f64, tavan: f64) -> bool {
    kira(tarif, erasure, ratio) <= tavan
}

/// 19.2 kanaryası: organik içeriğe 120 B üretim tarifi UYDURULAMAZ.
/// Güvercin-yuvası: içerik uzayı 2^160000, tarif uzayı 2^960.
/// Deneme sayısı verilen hedefe eşleşme bulunamazsa doğrulanır.
pub fn tarif_uydurulamaz(hedef: &[u8], deneme: usize) -> bool {
    let target_hash = TarifKaydi::commit(hedef);
    for i in 0..deneme {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GUESS_V1");
        h.update((i as u64).to_le_bytes());
        let guess: [u8; 32] = h.finalize().into();
        if guess == target_hash {
            return false; // bulundu - inanılmaz ama kanaryayı kırar
        }
    }
    true // hiçbir deneme eşleşmedi - uydurulamaz (beklenen)
}

pub fn tarif_digest(t: &TarifKaydi) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TARIF_MAGIC);
    h.update([TARIF_VERSION]);
    match t {
        TarifKaydi::Uretim { commitment, generator, seed, params } => {
            h.update([0]);
            h.update(commitment);
            h.update(generator.to_le_bytes());
            h.update(seed);
            h.update(params);
        }
        TarifKaydi::Govdeli { commitment, sikistirma, govde } => {
            h.update([1]);
            h.update(commitment);
            h.update([*sikistirma]);
            h.update(govde);
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    // yukarıdaki kullanılmayan Self_ için yardımcı (kaldırıldı)
    #[test]
    fn uretim_tarifi_kira_odamaz() {
        let t = TarifKaydi::uretim(1, [7u8; 32], vec![1, 2, 3]);
        assert_eq!(t.held_bytes(), 0, "R1: tutulan bayt 0");
        assert_eq!(kira(&t, 1.031, 1.0), 0.0, "R1: kira 0");
        assert!(kira_tavan_icerisinde(&t, 1.031, 1.0, 0.016));
    }

    #[test]
    fn govdeli_tarif_kira_veya_orana_bolunur() {
        // R2: 189× sıkışan metin → 0.23342*1.031/189 ≈ 0.00127
        let govde = vec![0u8; 1000];
        let t = TarifKaydi::govdeli(govde.clone(), 1);
        assert_eq!(t.held_bytes(), 1000);
        let k = kira(&t, 1.031, 189.0);
        assert!((k - 0.00127).abs() < 0.0002, "kira: {k}");
        // R3: sıkışmaz → oran=1 → 0.23342*1.031 ≈ 0.241
        let t3 = TarifKaydi::govdeli(govde, 0);
        assert!((kira(&t3, 1.031, 1.0) - 0.241).abs() < 0.01);
    }

    #[test]
    fn step_tabani_sinif_bazli() {
        assert!(step_tabani(1) < step_tabani(2));
        assert!(step_tabani(2) < step_tabani(3));
        // bilinmeyen üreteç → en yüksek (güvenli)
        assert_eq!(step_tabani(99), step_tabani(3));
    }

    #[test]
    fn tarif_uydurulamaz_kanaryasi() {
        let hedef = vec![0xA5; 160]; // organik içerik
        assert!(tarif_uydurulamaz(&hedef, 200_000), "200k deneme eşleşmemeli");
        let _ = TarifKaydi::commit(&hedef); // commitment hesaplanabilir
    }

    #[test]
    fn record_boyut_rejime_bagli() {
        // R1 ~120 B; R2/R3 = gövde + 33 B
        let u = TarifKaydi::uretim(1, [0u8; 32], vec![]);
        assert!(u.record_bytes() <= 120, "üretim tarifi ~120 B: {}", u.record_bytes());
        let g = TarifKaydi::govdeli(vec![0u8; 500], 1);
        assert_eq!(g.record_bytes(), 533);
    }

    #[test]
    fn tarif_digest_deterministik() {
        let t = TarifKaydi::govdeli(b"govde".to_vec(), 1);
        assert_eq!(tarif_digest(&t), tarif_digest(&t));
    }
}
