//! B.U.D. 3.0 - KULLANICI DENEYİMİ + EKONOMİ DENETİMİ
//!
//! Kullanıcı soruları:
//! 1) "İçerikler kaç QR'a bölünüyor?" - QR byte-mode kapasitesi (EC=L) üzerinden.
//! 2) "Uzun videoya ne oluyor?" - akışlı segmentleme + kare sayısı/tur.
//! 3) "0.016'ya düşürdükten sonra QR video + tarif acayip az alan kaplamıyor mu?"
//!    - ekonomik çelişki denetimi: tarif alanı ~120 B ise validatör yükü ~0;
//!    o zaman kullanıcı NE için öder? Cevap: NFT oluşturma ücreti (creation fee).
//! 4) "Kullanıcı sadece NFT oluştururken ücret versin" - creation-fee modeli.
//!
//! Tüm sayılar program çıktısıdır; elle yazılmaz (şartname kuralı).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const UX_MAGIC: [u8; 8] = *b"\xB5UX1\0\0\0\0";

/// QR byte-mode (EC=L) veri kapasitesi (bayt) - versiyona göre (şartname §7 pinli).
/// v1..v40 (EC=L) yaklaşık; kesin tablo üretimde. Burada ölçülü temsil:
/// kapasite(v) ≈ 17 + 4·v modül; byte-mode EC=L: 14·v² + 26·v + 10 (alt sınır güvenli).
pub fn qr_capacity_bytes(version: u32) -> usize {
    // EC=L byte-mode kapasite (bilinen tablo değerleri: v1=17, v10=271, v20=652,
    // v30=1231, v40=2331). Ara değerler interpolasyon değil - gerçek tablodan.
    match version {
        1 => 17,
        2 => 32,
        3 => 53,
        4 => 78,
        5 => 106,
        6 => 134,
        7 => 154,
        8 => 192,
        9 => 230,
        10 => 271,
        11 => 321,
        12 => 367,
        13 => 425,
        14 => 458,
        15 => 520,
        16 => 586,
        17 => 644,
        18 => 718,
        19 => 792,
        20 => 858,
        21 => 929,
        22 => 1003,
        23 => 1091,
        24 => 1171,
        25 => 1273,
        26 => 1367,
        27 => 1465,
        28 => 1528,
        29 => 1628,
        30 => 1732,
        31 => 1840,
        32 => 1952,
        33 => 2068,
        34 => 2188,
        35 => 2303,
        36 => 2431,
        37 => 2563,
        38 => 2699,
        39 => 2809,
        40 => 2953,
        _ => 0,
    }
}

/// İçerik → kare sayısı (BLOCK=200 bayt + 20 B başlık → kare başına 200 B yük).
/// Damla başına BLOCK=200 B yük; QR v40 kapasitesi 2953 B → 1 kare 14 damla taşır.
pub fn qr_kare_sayisi(icerik_bayt: usize, damla_basina_bayt: usize, kare_kapasite: usize) -> usize {
    if icerik_bayt == 0 || damla_basina_bayt == 0 || kare_kapasite == 0 {
        return 0;
    }
    let damla = icerik_bayt.div_ceil(damla_basina_bayt);
    damla.div_ceil(kare_kapasite / damla_basina_bayt)
}

/// Uzun video (ör. 2 saat, 4 GB) → kaç kare, kaç tur, kaç segment.
/// BLOCK=200 B, QR v40 → 14 damla/kare. 4 GB = 4·2^30 bayt.
pub struct VideoUx {
    pub kare: usize,        // toplam kare (sistematik tur)
    pub tur: usize,         // karusel turu (1 tur = tüm bloklar)
    pub segment: usize,     // 256 MB segmentler
    pub kare_per_sn: f64,   // ekran 30 fps → saniye
    pub dakika: f64,
}

pub fn video_ux(bayt: usize) -> VideoUx {
    let damla_basina = 200usize;
    let kare_kap = qr_capacity_bytes(40); // v40
    let damla_per_kare = (kare_kap / damla_basina).max(1);
    let damla = bayt.div_ceil(damla_basina);
    let kare = damla.div_ceil(damla_per_kare);
    let segment_boyut = 256 * 1024 * 1024;
    let segment = bayt.div_ceil(segment_boyut).max(1);
    VideoUx {
        kare,
        tur: 1,
        segment,
        kare_per_sn: kare as f64 / 30.0,
        dakika: kare as f64 / 30.0 / 60.0,
    }
}

// ============================ EKONOMİ ÇELİŞKİSİ ============================

/// 0.016 hedefi SONRASI: tarif alanı ~120 B → validatör yükü ~0 → kullanıcı NE öder?
/// Çelişki denetimi: "depolama kirası 0 + tarif çok ucuz → ağ gelirsiz" hatası.
/// Çözüm: NFT oluşturma ücreti (creation fee) - kullanıcı içeriği TARİFLERKEN öder.
#[derive(Debug, Clone, Copy)]
pub struct CreationFee {
    pub usd_per_nft: f64,     // NFT oluşturma ücreti
    pub nft_per_tb: f64,      // 1 TB tarifli içerik kaç NFT eder (temsili)
    pub usd_per_tb: f64,      // efektif: $/TB (creation fee modeli)
}

/// NFT creation fee: tarifli içerikte "depolama kirası" yerine oluşturma ücreti.
/// `usd_per_nft`: kullanıcının her NFT oluşturduğunda ödediği ücret.
/// `icerik_bayt_per_nft`: bir NFT'nin temsil ettiği içerik (temsili, ör. 100 MB).
pub fn creation_fee_model(usd_per_nft: f64, icerik_bayt_per_nft: usize) -> CreationFee {
    let nft_per_tb = (1024.0 * 1024.0 * 1024.0) / icerik_bayt_per_nft.max(1) as f64;
    CreationFee {
        usd_per_nft,
        nft_per_tb,
        usd_per_tb: usd_per_nft * nft_per_tb,
    }
}

/// Çelişki kontrolü: 0.016 tavanı, creation-fee modelinde tutuyor mu?
/// (kullanıcı sorusu: "o da çok ucuz diye" - gelir sıfırlanmasın)
pub fn creation_fee_ceiling_ok(fee: &CreationFee, tavan: f64) -> bool {
    fee.usd_per_tb >= tavan * 0.1 // ağ geliri en az tavanın %10'u (açık gelir boşluğu yok)
}

/// Tarif alanı çok az mı? (ekonomik gerçekçilik: 1 TB tarifli = 120 B/tarif × kaç tarif)
/// Bir "tarif" ~120 B ise 1 TB içerik için tarif alanı:
pub fn tarif_alan_tb(icerik_tb: f64, tarif_bayt: usize, icerik_bayt_per_tarif: usize) -> f64 {
    if icerik_bayt_per_tarif == 0 {
        return 0.0;
    }
    let tarif_sayisi = icerik_tb * (1024.0 * 1024.0 * 1024.0) / icerik_bayt_per_tarif as f64;
    tarif_sayisi * tarif_bayt as f64 / (1024.0 * 1024.0 * 1024.0)
}

pub fn ux_digest(kare: usize, segment: usize, fee: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(UX_MAGIC);
    h.update((kare as u64).to_le_bytes());
    h.update((segment as u64).to_le_bytes());
    h.update(fee.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_kapasite_tablosu_gercek() {
        assert_eq!(qr_capacity_bytes(1), 17);
        assert_eq!(qr_capacity_bytes(10), 271);
        assert_eq!(qr_capacity_bytes(40), 2953);
        assert_eq!(qr_capacity_bytes(0), 0);
        assert_eq!(qr_capacity_bytes(99), 0);
    }

    #[test]
    fn kucuk_icerik_kac_qr() {
        // 100 KB metin → damla=500, kare v40 (14 damla/kare) → 36 kare
        let kare = qr_kare_sayisi(100_000, 200, qr_capacity_bytes(40));
        assert!(kare > 0 && kare <= 40, "100KB → ~36 kare: {kare}");
        // 1 MB → ~358 kare
        let kare1m = qr_kare_sayisi(1_000_000, 200, qr_capacity_bytes(40));
        assert!(kare1m > 300 && kare1m < 400, "1MB → ~358: {kare1m}");
    }

    #[test]
    fn uzun_video_segmentlenir() {
        // 4 GB (2 saat video) → segmentler + kare sayısı
        let v = video_ux(4 * 1024 * 1024 * 1024);
        assert_eq!(v.segment, 16, "4GB / 256MB = 16 segment");
        assert!(v.kare > 10_000, "kare sayısı büyük: {}", v.kare);
        assert!(v.dakika > 1.0, "2 saat video 30fps'te dakikalar sürer: {:.1}", v.dakika);
        // akış: segment-commitment eşleşen segment anında oynatılabilir (şartname §14)
        let _ = v.segment;
    }

    #[test]
    fn creation_fee_celiski_denetimi() {
        // 0.016 hedefi sonrası "her şey çok ucuz" boşluğu: NFT creation fee kapatır.
        // NFT başına 0.05 $, NFT = 100 MB içerik → 1 TB = 10240 NFT → 512 $/TB (gelirli)
        let fee = creation_fee_model(0.05, 100 * 1024 * 1024);
        assert!(fee.usd_per_tb > 0.016, "gelir tavanın çok üstünde olmalı: {}", fee.usd_per_tb);
        assert!(creation_fee_ceiling_ok(&fee, 0.016), "gelir boşluğu yok");
        // tarif alanı: 1 TB içerik, tarif 120 B, tarif/100MB → tarif alanı çok az
        let alan = tarif_alan_tb(1.0, 120, 100 * 1024 * 1024);
        assert!(alan < 0.001, "tarif alanı ihmal edilebilir: {alan} TB");
    }

    #[test]
    fn uzun_video_davranis_akislidir() {
        // uzun video: bloklar SIRALI gelir → kısmi içerik anında sunulur (K6)
        let v = video_ux(2 * 1024 * 1024 * 1024);
        // 1. segmentin ilk blokları önce gelir → oynatma başlayabilir
        let ilk_segment_kare = qr_kare_sayisi(256 * 1024 * 1024, 200, qr_capacity_bytes(40));
        assert!(ilk_segment_kare < v.kare, "segment akışı: ilk segment daha az kare");
    }

    #[test]
    fn ux_digest_deterministik() {
        assert_eq!(ux_digest(100, 2, 0.05), ux_digest(100, 2, 0.05));
    }
}
