//! B.U.D. 2.0 değişmez testleri.
//!
//! Bu dosya `#[test] fn placeholder() { assert!(true); }` idi — hiçbir şey
//! doğrulamayan, ama yeşil görünen bir kayıt. `assert!(true)` clippy'nin
//! `assertions_on_constants` kapısına takılıyordu ve takılması doğruydu: boş
//! bir test, testi olmayan koddan daha kötüdür, çünkü kapsama varmış izlenimi
//! bırakır.
//!
//! Yerine 2.0 şartnamesinin **1. değişmezi** koşuluyor: KAYIPSIZLIK — orijinal
//! baytlar birebir geri üretilir. Testler `engine_store`/`engine_restore_container`
//! turunu farklı içerik sınıflarında sürer, çünkü boru hattı sınıfa göre farklı
//! transform seçer (columnar / logfield / none) ve kayıpsızlık kırılacaksa
//! transform sınırında kırılır.

use bud_core::bud_format_engine::{engine_restore_container, engine_store};

/// Sabit bir zaman damgası: PACT kaydı zamana bağlı, test belirleyici olmalı.
const TS: u64 = 1_768_000_000;

/// Turu sürer ve orijinal baytların birebir döndüğünü doğrular.
fn roundtrip_bayt_esit(data: &[u8], etiket: &str) {
    let res = engine_store(data, false, TS)
        .unwrap_or_else(|| panic!("{etiket}: engine_store None döndürdü"));

    // `res.container` KONTEYNER baytlarıdır (engine blob'u değil), bu yüzden
    // `engine_restore_container` kullanılır — `bud` CLI de aynısını çağırır.
    let geri = engine_restore_container(&res.container, res.transform_kind as u8, false)
        .unwrap_or_else(|| panic!("{etiket}: engine_restore_container None döndürdü"));

    assert_eq!(
        geri.len(),
        data.len(),
        "{etiket}: uzunluk değişti ({} -> {})",
        data.len(),
        geri.len()
    );
    assert!(
        geri == data,
        "{etiket}: baytlar birebir dönmedi (format={}, transform={:?})",
        res.format_name,
        res.transform_kind
    );
    assert_eq!(
        res.original_len,
        data.len() as u64,
        "{etiket}: kayıtlı original_len girdiyle uyuşmuyor"
    );
}

#[test]
fn json_kayipsiz_doner() {
    // Columnar transform yolu: tekrarlı anahtarlar sütunlara ayrılır.
    let mut satirlar = Vec::new();
    for i in 0..200 {
        satirlar.push(format!(
            r#"{{"kullanici":"u{}","gun":"2026-08-{:02}","deger":{},"durum":{}}}"#,
            i % 40,
            (i % 28) + 1,
            i,
            [200, 201, 404, 500][i % 4]
        ));
    }
    let json = format!("[{}]", satirlar.join(",")).into_bytes();
    roundtrip_bayt_esit(&json, "json");
}

#[test]
fn duz_metin_kayipsiz_doner() {
    let metin = "B.U.D. 2.0 kayıpsızlık değişmezi.\n\
                 Türkçe karakterler de birebir dönmeli: çğıöşü ÇĞİÖŞÜ.\n"
        .repeat(80)
        .into_bytes();
    roundtrip_bayt_esit(&metin, "metin");
}

#[test]
fn sikismayan_veri_kayipsiz_doner() {
    // Entropi-kodlu/rastgele sınıfın taklidi: sıkışmaz, boru hattı sıkıştırmayı
    // ATLAMALI ve yine de baytları birebir döndürmeli. Sıkıştırma atlanınca
    // konteyner yolunun bozulması klasik hatadır; kapı burada.
    let mut veri = Vec::with_capacity(8192);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..8192 {
        // xorshift: deterministik ama sıkışmayan
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        veri.push((x & 0xFF) as u8);
    }
    roundtrip_bayt_esit(&veri, "rastgele");
}

#[test]
fn tek_bayt_ve_kucuk_girdi_kayipsiz_doner() {
    // Sınır: parça boyutunun çok altındaki girdiler.
    roundtrip_bayt_esit(b"x", "tek bayt");
    roundtrip_bayt_esit(b"kisa girdi", "kisa");
}

#[test]
fn bos_girdi_reddedilir_sessizce_bozulmaz() {
    // Boş girdi depolanamaz; önemli olan panik değil, açık ret.
    assert!(
        engine_store(b"", false, TS).is_none(),
        "boş girdi kabul edilmemeli"
    );
}

#[test]
fn olculen_oran_boyutlardan_tutarlidir() {
    // K19: oran İDDİA edilmez, boyutlardan ÖLÇÜLÜR. Kayıtlı oranın gerçekten
    // original_len/stored_len olduğunu doğrula — ölçüm üstü iddia kapısının
    // dayandığı sayı bu.
    let mut satirlar = Vec::new();
    for i in 0..300 {
        satirlar.push(format!("2026-08-21T00:00:{:02}Z seviye=bilgi kod={}", i % 60, i));
    }
    let log = satirlar.join("\n").into_bytes();

    let res = engine_store(&log, false, TS).expect("engine_store");
    assert!(res.stored_len > 0, "stored_len sıfır olamaz");

    let beklenen = res.original_len as f64 / res.stored_len as f64;
    assert!(
        (res.measured_ratio - beklenen).abs() < 1e-9,
        "measured_ratio ({}) boyut oranıyla ({}) uyuşmuyor",
        res.measured_ratio,
        beklenen
    );
}
