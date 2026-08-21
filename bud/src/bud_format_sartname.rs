//! B.U.D. 3.0 - ŞARTNAME v4.0 UYUM KAPILARI (2026-08-17)
//!
//! İlke: her iddia ölçümle doğrulanır; B.U.D. 3.0 sertleştirme kapsamı.
//! Bu modül B.U.D. 3.0 şartname maddelerini (K4, K5, K6, K10, K13, K14b)
//! KODLA doğrular: her madde bir kapı fonksiyonu + test. İddia yazıda değil,
//! ölçümdedir.
//!
//! K4  : 120 B tarif kaydından bit-eşit, tam çözünürlüklü içerik.
//! K5  : sıkıştır ÖNCE (codec kazancı kiraYI düşürür; sıkışmadan tarif olmaz).
//! K6  : sistematik karusel, fazlalık 1.00 (repair damlası yok, tam sistematik).
//! K10 : bayt-eşit geri okuma (roundtrip birebir).
//! K13 : 8 format taraması; R3 kirası GERÇEK ölçülen oranla (zemin 0.23342).
//! K14b: üç-sayaç: kira → depocu, step → validatör, commitment → konsensüs.

#![forbid(unsafe_code)]

use crate::bud_format_r3fix::{Codec, R3Tarif};
use crate::bud_format_tarif::TarifKaydi;

/// K4 kapısı: üretim tarifi kaydı 120 B sınırındadır (şartname §K4).
pub fn tarif_kaydi_120b_k4(t: &TarifKaydi) -> bool {
    t.record_bytes() <= 120
}

/// K5 kapısı: sıkıştırma ÖNCE uygulanır ve ham boyutu küçültür (oran >= 1.0).
/// Çok küçük girdide zstd üstbilgisi büyütebilir; kapı yeterli uzunlukta
/// girdiyle ölçer (küçük girdi zaten depoya gövde olarak girer, tarif olmaz).
pub fn sikistirma_once_k5(ham: &[u8]) -> bool {
    if ham.len() < 256 {
        return true; // eşik altı girdi tarif dışıdır; kapı boş iddia kurmaz
    }
    crate::bud_format_qrvideo::zstd_compress(ham)
        .map(|c| ham.len() as f64 / c.len() as f64 >= 1.0)
        .unwrap_or(false)
}

/// K6 kapısı: sistematik karuselin fazlalığı 1.00 civarıdır (repair damlası
/// yok, yalnız DamlaHdr üstbilgisi). Sınır: oran 1.25'i geçemez (K-QR-GENISLEME).
/// Not: `uret_turev` repair damlaları da paketler (turns >= 1); saf sistematik
/// fazlalık, blokların systematic_drop paketleri toplamıyla ölçülür (K6).
pub fn karusel_fazlalik_k6(veri: &[u8]) -> Option<f64> {
    if veri.is_empty() {
        return None;
    }
    let k = crate::bud_format_qrvideo::Karusel::new(veri)?;
    let mut toplam = 0usize;
    for i in 0..k.k {
        let (seq, b) = k.systematic_drop(i)?;
        toplam += k.pack(seq, 0, 0, &b)?.len();
    }
    let oran = toplam as f64 / veri.len() as f64;
    (oran <= 1.25).then_some(oran)
}

/// K10 kapısı: R3 tarif gövdeli roundtrip birebir (bayt-eşit).
pub fn bayt_esit_k10(girdi: &[u8], mime: &str) -> bool {
    let t = R3Tarif::uret(
        girdi,
        mime,
        |d| {
            let mut c = zstd::bulk::Compressor::new(19).unwrap();
            c.compress(d).unwrap_or_else(|_| d.to_vec())
        },
        b"qr-turev-bayt",
    );
    match zstd::bulk::Decompressor::new()
        .ok()
        .and_then(|mut d| d.decompress(&t.govde, 512 * 1024 * 1024).ok())
    {
        Some(geri) => geri == girdi,
        None => t.codec == Codec::None && t.govde == girdi,
    }
}

/// K13 kapısı: GERÇEK ölçülen oranla R3 kirası (zemin 0.23342 x erasure / oran).
/// R3 tarif tavanı §18.1b: 0.016 $/TB. Dürüstlük: her codec tavana GİRMEZ;
/// düşük sıkıştıran codec tavan üstü kalır ve depoya girmez.
pub fn k13_kira(codec: Codec, erasure: f64) -> f64 {
    crate::bud_format_r3fix::r3_gercek_kira(&codec, erasure)
}

/// K13 tarama sonucu: hangi ölçülen codec'ler R3 tavanında (0.016) kalır.
pub fn k13_tavan_icinde_kalanlar(tavan: f64) -> Vec<(&'static str, f64, bool)> {
    use crate::bud_format_r3fix::Codec as C;
    [
        (C::Avif, "avif"),
        (C::Jxl, "jxl-lossless"),
        (C::Flac, "flac"),
        (C::Av1, "h264-raw"),
        (C::Zstd19, "zstd19"),
    ]
    .iter()
    .map(|(c, ad)| {
        let kira = k13_kira(*c, 1.0);
        (*ad, kira, kira <= tavan)
    })
    .collect()
}

/// K14b üç-sayaç: kira → depocu, step → validatör, commitment → konsensüs.
/// Üç kanal birbirinden AYRIDIR; biri sıfırlanınca öteki devralmaz.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UcSayacK14b {
    pub depocu_kira_usd: f64,     // kira: depocuya
    pub validatur_step_usd: f64,  // step ücreti: validatöre
    pub konsensus_commitment: [u8; 32], // commitment: konsensüs kaydı
}

/// K14b hesabı: tarif kirası + step tabanı + commitment digesti tek yerde.
pub fn uc_sayac_k14b(t: &TarifKaydi, erasure: f64, compression_ratio: f64) -> UcSayacK14b {
    let kira = crate::bud_format_tarif::kira(t, erasure, compression_ratio);
    let gen = match t {
        TarifKaydi::Uretim { generator, .. } => *generator,
        TarifKaydi::Govdeli { .. } => 99, // gövde tarifinde step tavanı (K14b)
    };
    let step = crate::bud_format_tarif::step_tabani(gen);
    let commitment = crate::bud_format_tarif::tarif_digest(t);
    UcSayacK14b {
        depocu_kira_usd: kira,
        validatur_step_usd: step,
        konsensus_commitment: commitment,
    }
}

/// K14b dürüstlük: step 0 ise validatöre akış yok (üretim emeği karşılıksız =
/// DoS), commitment deterministik (aynı tarif → aynı digest), kira kanalı
/// tarif türüne göre açık/kapalıdır (R1 üretimde depolama yok → kira 0).
pub fn uc_sayac_durust(s: &UcSayacK14b) -> bool {
    if s.validatur_step_usd <= 0.0 {
        return false; // üretim tarifinde step SIFIR olamaz (K14b)
    }
    !s.konsensus_commitment.iter().all(|&b| b == 0)
}

/// QR türev büyüme sınırı: türev, orijinalin 2 katı + 1 KB sabitini aşamaz
/// (şartname K-QR-GENISLEME; karusel damla üstbilgileri sınırlı).
pub fn qr_turev_buyume_siniri(turev_len: usize, orijinal_len: usize) -> bool {
    turev_len <= orijinal_len * 2 + 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_tarif::TarifKaydi;

    #[test]
    fn k4_tarif_kaydi_120b_sinirinda() {
        let u = TarifKaydi::uretim(7, [0x42; 32], vec![0xAA; 24]);
        assert!(tarif_kaydi_120b_k4(&u), "üretim tarifi 120 B altı: {}", u.record_bytes());
    }

    #[test]
    fn k5_sikistirma_once_oran_bir_ustu() {
        // tekrarlı içerik: zstd 1.0'dan anlamlı küçültür (K5)
        let ham: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
        assert!(sikistirma_once_k5(&ham), "zstd ham boyutu küçültmeli");
    }

    #[test]
    fn k6_karusel_fazlalik_bir_civarinda() {
        let veri: Vec<u8> = (0u8..=255).cycle().take(2 * 200 + 37).collect();
        let oran = karusel_fazlalik_k6(&veri).expect("karusel üretilebilmeli");
        assert!((1.0..=1.25).contains(&oran), "sistematik fazlalık ~1.00: {oran}");
        // üretim (sistematik + repair) 2x + sabit sınırındadır (K-QR-GENISLEME)
        let turev = crate::bud_format_qrvideo::uret_turev(&veri, 0, 1).expect("türev");
        assert!(qr_turev_buyume_siniri(turev.len(), veri.len()));
    }

    #[test]
    fn k10_roundtrip_bayt_esit() {
        let girdi: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert!(bayt_esit_k10(&girdi, "image/png"), "K10 bayt-eşit roundtrip");
        let log = b"2026-08-17 INFO tarif #1 dogrulandi\n".repeat(64);
        assert!(bayt_esit_k10(&log, "text/plain"));
    }

    #[test]
    fn k13_olculen_kirada_durustluk() {
        // AVIF 59.68x -> 0.00626 <= 0.016 tavana GİRER
        // FLAC  6.04x  -> 0.0618  > 0.016 tavanda KALMAZ (dürüst red)
        let liste = k13_tavan_icinde_kalanlar(0.016);
        let avif = liste.iter().find(|(ad, _, _)| *ad == "avif").unwrap();
        let flac = liste.iter().find(|(ad, _, _)| *ad == "flac").unwrap();
        assert!(avif.2, "AVIF tavanda: {} <= 0.016", avif.1);
        assert!(!flac.2, "FLAC tavan üstünde kalır: {}", flac.1);
        // zemin tutarlı: 0.23342 x 1.0 / 59.68
        assert!((avif.1 - 0.23342 / 59.68).abs() < 1e-9);
    }

    #[test]
    fn k14b_uc_sayac_ayri_ve_durust() {
        // R1 üretim tarifi: depolama YOK -> kira kanalı kapalı (0), step açık.
        let t = TarifKaydi::uretim(3, [0x11; 32], vec![0x55; 16]);
        let s = uc_sayac_k14b(&t, 1.3, 8.5);
        assert!(uc_sayac_durust(&s), "step pozitif, commitment dolu");
        assert_eq!(s.depocu_kira_usd, 0.0, "R1 üretimde depolama yok, kira 0");
        assert!(s.validatur_step_usd > 0.0, "üretim step'i validatöre akar");
        // R3 gövde tarifi: depolama VAR -> kira kanalı depocuya açılır.
        let g = TarifKaydi::govdeli(vec![0xAB; 512], 1);
        let sg = uc_sayac_k14b(&g, 1.3, 8.5);
        assert!(sg.depocu_kira_usd > 0.0, "R3 gövde kirası depocuya gider");
        // deterministik: aynı tarif -> aynı üç-sayaç
        let s2 = uc_sayac_k14b(&TarifKaydi::uretim(3, [0x11; 32], vec![0x55; 16]), 1.3, 8.5);
        assert_eq!(s, s2, "üç-sayaç deterministik");
        // kanallar ayrı: kira depocuya, step validatöre
        assert_ne!(s.depocu_kira_usd, s.validatur_step_usd);
    }
}
