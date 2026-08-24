//! B.U.D. 3.0 - CANLI UÇTAN UCA DENEY
//!
//! Zincir: orijinal → (içerik-türüne-göre codec sıkıştır) → R3Tarif (gövde + QR türev
//! commitment) → QR türev üret (karusel) → GERİ: gövdeyi aç → SHA3 doğrula → birebir.
//! Görsel + video + metin ile KAYIPSIZLIK + TAM ÇÖZÜNÜRLÜK kanıtı.
//!
//! Not: gerçek AVIF/AV1 ffmpeg üretimde; burada zstd-19 vekili (kayıpsız) ile
//! zincirin DOĞRULUĞU test edilir - oranlar codec'e göre değişir, kayıpsızlık değil.
//!
//! Veriler `tests/fixtures/` altında repo icindedir (CI'da /tmp yoktur; kanit:
//! 2026-08-17 gorsel.png video.yuv text.log repo'ya gomuldu).

#![cfg(test)]

use crate::bud_format_r3fix::{Codec, R3Tarif};

fn fixture(ad: &str) -> Vec<u8> {
    let yol = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(ad);
    std::fs::read(&yol).unwrap_or_else(|e| panic!("fixture {ad}: {e}"))
}

/// Orijinal → R3 tarif → geri oku → birebir mi? (kayıpsızlık + tam çözünürlük)
fn r3_roundtrip(orijinal: &[u8], mime: &str) -> bool {
    // 1) tarif üret (codec sıkıştır + QR türev commitment)
    let t = R3Tarif::uret(
        orijinal,
        mime,
        |d| {
            let mut c = zstd::bulk::Compressor::new(19).unwrap();
            c.compress(d).unwrap_or_else(|_| d.to_vec())
        },
        b"qr-turev-bayt",
    );
    // 2) gövdeyi aç (zstd) → orijinal
    let acik = zstd::bulk::Decompressor::new()
        .ok()
        .and_then(|mut d| d.decompress(&t.govde, 512 * 1024 * 1024).ok());
    match acik {
        Some(geri) => {
            // 3) SHA3 doğrula: commitment orijinalle eşleşmeli
            let cid = crate::bud_format_container::content_id(&geri);
            cid == t.commitment && geri == orijinal
        }
        None => {
            // codec None (şifreli) ise gövde = orijinal
            t.codec == Codec::None && t.govde == orijinal
        }
    }
}

#[test]
fn gorsel_png_kayipsiz_tam_cozunurluk() {
    // 128x128 gercek PNG (PIL ile uretildi, tests/fixtures/gorsel.png)
    let png = fixture("gorsel.png");
    assert!(
        r3_roundtrip(&png, "image/png"),
        "PNG kayıpsız + tam çözünürlük"
    );
    // çözünürlük: PNG header 0x10..0x14 (width), 0x14..0x18 (height)
    let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
    let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
    assert_eq!((w, h), (128, 128), "tam çözünürlük korunur: {w}x{h}");
}

#[test]
fn video_yuv_kayipsiz_tam_cozunurluk() {
    // 60 kare YUV420 64x48 (276480 B) - video benzeri, tests/fixtures/video.yuv
    let yuv = fixture("video.yuv");
    assert!(r3_roundtrip(&yuv, "video/x-raw-yuv"), "YUV kayıpsız");
    // kare boyutu: 64*48*1.5 = 4608 B/kare → 60 kare
    let kare_bayt = 4608usize;
    assert_eq!(yuv.len() % kare_bayt, 0, "kare hizası tam");
    assert!(
        yuv.len() / kare_bayt >= 60,
        "kare sayısı korunur (en az 60)"
    );
}

#[test]
fn metin_log_kayipsiz() {
    let log = fixture("text.log");
    assert!(r3_roundtrip(&log, "text/plain"), "log kayıpsız");
}

#[test]
fn edition_her_ucu_kodda_var() {
    use crate::bud_format_edition::{Bud1Custody, Bud1Nft, Edition};
    // 1.0: BYO - kendi sunucu + cihaz
    let _ext = Bud1Nft::new_external([1u8; 32], "sunucum.example".into(), "uri".into());
    let _dev = Bud1Nft::new_device([2u8; 32], "uri".into(), true);
    // 2.0 ve 3.0 seçilebilir
    assert_eq!(Edition::from_u8(1).unwrap().name(), "B.U.D. 1.0");
    assert_eq!(Edition::from_u8(2).unwrap().name(), "B.U.D. 2.0");
    assert_eq!(Edition::from_u8(3).unwrap().name(), "B.U.D. 3.0");
    let _ = Bud1Custody::Device;
}
