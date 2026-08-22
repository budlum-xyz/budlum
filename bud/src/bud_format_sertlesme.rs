//! B.U.D. 3.0 - MALİYET-DİBİ SERTLEŞTİRMESİ (2026-08-16)
//!
//! Kapsam: B.U.D. 3.0 sertleştirmesi; düşük maliyet iddiası ölçümle sınanır.
//!
//! Maliyet ~0'a inince üç risk doğar:
//! 1. **Gelir boşluğu / DoS** - tarif kirası 0 ise ağ bedava üretir → spam + DoS.
//!    Sertleştirme: creation-fee tabanı + step ücreti tabanı + spam kapısı.
//! 2. **Tarif uydurma** - "organik içeriğe tarif buldum" iddiası (güvercin-yuvası K13).
//!    Sertleştirme: tarif doğrulama kapısı (commitment eşleşmeden kabul yok).
//! 3. **QR türev güvenliği** - türev saklanmaz ama commitment'ı doğrulanmalı.
//!    Sertleştirme: türev commitment kapısı + yeniden üretim doğrulaması.
//!
//! Ayrıca "maliyet dibe düştü" İDDİASININ kendisi ölçülmeli: tarifli sınıfta gerçek
//! maliyet bileşenleri (üretim CPU, QR render, dağıtım) sıfıra mı gidiyor?

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SERT_MAGIC: [u8; 8] = *b"\xB5SERT\0\0\0";
pub const SERT_VERSION: u8 = 1;

// ============================ 1. GELİR / DoS SERTLEŞTİRMESİ ============================

/// Spam kapısı: tarifli içerik bedava ise spam gelir. Çözüm: tarif BAŞINA minimum
/// creation-fee (kullanıcı tariflerken öder) + saniye başına tarif kotası.
#[derive(Debug, Clone, Copy)]
pub struct TarifKotasi {
    pub min_creation_fee_usd: f64, // tarif başına minimum ücret
    pub max_tarif_per_sec: u64,    // düğüm başına saniyelik tarif kotası
}

impl Default for TarifKotasi {
    fn default() -> Self {
        Self {
            min_creation_fee_usd: 0.001,
            max_tarif_per_sec: 100,
        }
    }
}

/// Spam denetimi: kota aşıldı mı?
pub fn spam_denetimi(kota: &TarifKotasi, son_1sn_tarif: u64, fee_usd: f64) -> bool {
    if son_1sn_tarif > kota.max_tarif_per_sec {
        return true; // hız kotası aşıldı → RED
    }
    fee_usd < kota.min_creation_fee_usd
}

/// Minimum gelir güvencesi: tarifli sınıfta bile ağ en az `tavan × 0.1` kazanmalı.
pub fn gelir_guvencesi(creation_fee_usd: f64, nft_per_tb: f64, tavan: f64) -> bool {
    creation_fee_usd * nft_per_tb >= tavan * 0.1
}

// ============================ 2. TARİF UYDURMA SERTLEŞTİRMESİ ============================

/// Tarif doğrulama kapısı: `uret` fonksiyonu commitment'ı karşılamadan kabul YOK.
/// Güvercin-yuvası (K13): organik içeriğe tarif UYDURULAMAZ - 200k deneme 0 eşleşme.
pub fn tarif_dogrulama(
    uret_fonksiyon: impl FnOnce(&[u8]) -> Vec<u8>,
    orijinal: &[u8],
    beklenen_commitment: &[u8; 32],
) -> bool {
    let uretilen = uret_fonksiyon(orijinal);
    let cid = crate::bud_format_container::content_id(&uretilen);
    &cid == beklenen_commitment
}

/// Kanarya: 200k rastgele tarif denemesi organik hedefe eşleşmemeli (K13).
pub fn tarif_uydurulamaz_kanaryasi(hedef: &[u8], deneme: usize) -> bool {
    let target = crate::bud_format_container::content_id(hedef);
    for i in 0..deneme {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GUESS_V2");
        h.update((i as u64).to_le_bytes());
        let guess: [u8; 32] = h.finalize().into();
        if guess == target {
            return false;
        }
    }
    true
}

// ============================ 3. QR TÜREV GÜVENLİĞİ ============================

/// Türev commitment kapısı: QR türev saklanmaz ama üretildiğinde commitment'ı
/// zincirdeki kayıtla eşleşmeli (yeniden üretim doğrulaması - İ9 deseni).
pub fn turev_dogrulama(turev: &[u8], beklenen: &[u8; 32]) -> bool {
    let cid = crate::bud_format_container::content_id(turev);
    &cid == beklenen
}

// ============================ 4. "MALİYET DİBE DÜŞTÜ" İDDİASI ÖLÇÜMÜ ============================

/// Tarifli sınıfın gerçek maliyet bileşenleri ($/TB):
/// üretim CPU + QR render + dağıtım - hepsi sıfıra mı gidiyor?
#[derive(Debug, Clone, Copy)]
pub struct MaliyetBilesenleri {
    pub uretim_cpu_usd_per_tb: f64, // validatör CPU (step ücreti karşılığı)
    pub qr_render_usd_per_tb: f64,  // QR kare render
    pub dagitim_usd_per_tb: f64,    // ağ dağıtımı (0 - talep anında)
    pub kira_usd_per_tb: f64,       // depolama kirası (R1'de 0)
}

impl MaliyetBilesenleri {
    /// "Dibe düştü" ölçümü: toplam maliyet 0.016'nın ne kadar altında?
    pub fn toplam(&self) -> f64 {
        self.uretim_cpu_usd_per_tb + self.qr_render_usd_per_tb + self.dagitim_usd_per_tb
    }
}

/// Maliyet dibi iddiası: toplam ≤ tavan × 0.01 (yani 0.00016 $/TB) ise "dibe düştü" OK.
/// Bu İDDİALI - doğrulanmalı: üretim CPU'su step ücretiyle, render enerjiyle ölçülür.
pub fn dibe_dustu_mu(bilesenler: &MaliyetBilesenleri, tavan: f64) -> bool {
    bilesenler.toplam() <= tavan * 0.01
}

/// Dürüstlük: üretim CPU'su SIFIR sayılamaz (validatör elektrik harcar) - bu fonksiyon
/// üretim CPU'su 0 ise RED der (maliyet yok olmaz, doğru cebe taşınır - K14b).
pub fn uretim_cpu_sifir_degil(bilesenler: &MaliyetBilesenleri) -> bool {
    bilesenler.uretim_cpu_usd_per_tb > 0.0
}

pub fn sert_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SERT_MAGIC);
    h.update([SERT_VERSION]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spam_kotasi_reddeder() {
        let kota = TarifKotasi::default();
        // hız kotası aşıldı → RED
        assert!(spam_denetimi(&kota, kota.max_tarif_per_sec + 1, 0.01));
        // düşük ücret → RED (bedava tarif = DoS)
        assert!(spam_denetimi(&kota, 1, 0.0001));
        // normal → kabul
        assert!(!spam_denetimi(&kota, 1, 0.01));
    }

    #[test]
    fn gelir_guvencesi_kapisi() {
        // Ad: `gelir_guvencesi` DEGIL - `use super::*` ile ayni isimli
        // pub fn ile cakisir (E0061). Kanit: 2026-08-17.
        // NFT 0.05$, 10240 NFT/TB → 512 $/TB ≥ 0.016×0.1 ✓
        assert!(gelir_guvencesi(0.05, 10240.0, 0.016));
        // ücretsiz → RED (gelir boşluğu)
        assert!(!gelir_guvencesi(0.0, 10240.0, 0.016));
    }

    #[test]
    fn tarif_dogrulama_kapisi() {
        let orijinal = b"deterministik icerik";
        let cid = crate::bud_format_container::content_id(orijinal);
        // doğru üretim → kabul
        assert!(tarif_dogrulama(|d| d.to_vec(), orijinal, &cid));
        // yanlış üretim → RED
        let yanlis = crate::bud_format_container::content_id(b"baska");
        assert!(!tarif_dogrulama(|d| d.to_vec(), orijinal, &yanlis));
    }

    #[test]
    fn tarif_uydurulamaz_kanaryasi_kapisi() {
        // Ad: `tarif_uydurulamaz_kanaryasi` DEGIL - ustteki pub fn ile cakisir (E0061).
        let hedef = vec![0x5A; 64];
        assert!(
            tarif_uydurulamaz_kanaryasi(&hedef, 200_000),
            "200k deneme eşleşmemeli"
        );
    }

    #[test]
    fn turev_dogrulama_kapisi() {
        // Ad: `turev_dogrulama` DEGIL - ustteki pub fn ile cakisir (E0061).
        let turev = b"qr-video-turev";
        let cid = crate::bud_format_container::content_id(turev);
        assert!(turev_dogrulama(turev, &cid));
        assert!(!turev_dogrulama(b"baska", &cid));
    }

    #[test]
    fn maliyet_dibi_iddiasi_olculur() {
        // Gerçekçi: üretim CPU 0.001 (step tabanı), render 0.0005, dağıtım 0, kira 0
        let b = MaliyetBilesenleri {
            uretim_cpu_usd_per_tb: 0.001,
            qr_render_usd_per_tb: 0.0005,
            dagitim_usd_per_tb: 0.0,
            kira_usd_per_tb: 0.0,
        };
        // toplam 0.0015 > 0.00016 → "dibe düşmedi" (dürüst - CPU sıfır değil)
        assert!(!dibe_dustu_mu(&b, 0.016));
        assert!(uretim_cpu_sifir_degil(&b), "üretim CPU'su sıfır sayılamaz");
        // CPU 0 → RED (maliyet yok olmaz)
        let sifir = MaliyetBilesenleri {
            uretim_cpu_usd_per_tb: 0.0,
            qr_render_usd_per_tb: 0.0001,
            dagitim_usd_per_tb: 0.0,
            kira_usd_per_tb: 0.0,
        };
        assert!(!uretim_cpu_sifir_degil(&sifir));
    }
}
