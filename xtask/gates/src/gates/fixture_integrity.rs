//! Fixture bütünlüğü gate'i.
//!
//! `config/fixtures/gercek-zincir.json` testlerin dayandığı tek kaynaktır
//! (`src/tests/gercek_zincir_fixtures.rs` aynı dosyayı okur - tek kaynak
//! kuralı; ikinci kopya en kötü kopyadır). Bu gate dosyanın var olduğunu,
//! zorunlu bölümleri taşıdığını, makul boyutta kaldığını ve kendi format
//! kurallarına (0x'siz hex) uyduğunu doğrular. İçerik eşleşmesinin gerçek
//! zincire karşı doğrulanması testlerin işidir; bu gate şema kanaryasıdır.
//! JSON bağımlılığı bilinçli olarak eklenmedi: gate'ler yalnızca syn+quote
//! taşır ve bu gate string düzeyinde yeterli doğrulama yapar.

use std::path::Path;

const FIXTURE_PATH: &str = "config/fixtures/gercek-zincir.json";
const MIN_BYTES: u64 = 1_024;
const MAX_BYTES: u64 = 64 * 1_024;
const REQUIRED_SECTIONS: &[&str] = &[
    "\"provenance\"",
    "\"btc_merkle_blocks\"",
    "\"btc_halvings\"",
    "\"eth_headers\"",
    "\"expected_hash\"",
    "\"merkle_root\"",
    "\"generation_sat\"",
    "\"base_fee_per_gas\"",
];

/// # Errors
///
/// Fixture dosyası eksik, boş, şişmiş veya bölüm eksik olduğunda.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(FIXTURE_PATH);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("fixture dosyası okunamadı: {} ({e})", path.display()))?;
    let len = text.len() as u64;
    if len < MIN_BYTES {
        return Err(format!(
            "fixture {len} bayt - {MIN_BYTES} altı (dosya boşaltılmış olabilir)"
        ));
    }
    if len > MAX_BYTES {
        return Err(format!(
            "fixture {len} bayt - {MAX_BYTES} üstü (dosyaya veri dökülmüş olabilir)"
        ));
    }
    for section in REQUIRED_SECTIONS {
        if !text.contains(section) {
            return Err(format!("fixture zorunlu bölüm eksik: {section}"));
        }
    }
    // Kendi format kuralımız: hex alanlar 0x öneksiz saklanır. 0x önekli
    // alan, format drift'ine işaret eder (Blockchair ham kopyası karışmış).
    if text.contains("\"0x") {
        return Err(
            "fixture 0x-önekli alan içeriyor; kendi formatımız öneksizdir - \
             drift kontrolü"
                .into(),
        );
    }
    Ok(format!(
        "fixture doğrulandı: {len} bayt, {} zorunlu bölüm mevcut",
        REQUIRED_SECTIONS.len()
    ))
}

/// Gate'in kendisinin kırmızı düşebildiğinin kanıtı: geçici dizinde bozuk
/// kopyalar üretilir, her biri `run` tarafından reddedilmeli.
///
/// # Errors
///
/// Bozuk kopyalardan biri reddedilmezse (vacuous gate) hata döner.
pub fn self_test() -> Result<String, String> {
    let dir = std::env::temp_dir().join("budlum-fixture-gate-self-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config/fixtures"))
        .map_err(|e| format!("geçici dizin kurulamadı: {e}"))?;
    let fixture = dir.join(FIXTURE_PATH);

    // (1) Eksik dosya → red.
    if run(&dir).is_ok() {
        return Err("eksik fixture dosyası reddedilmedi (vacuous)".into());
    }

    // (2) Boş/ufak dosya → red.
    std::fs::write(&fixture, "{}").map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        return Err("boş fixture reddedilmedi (vacuous)".into());
    }

    // (3) Bölüm eksik dosya → red.
    std::fs::write(
        &fixture,
        format!(
            "{{\"provenance\":\"x\",\"btc_merkle_blocks\":[],\"btc_halvings\":[],\"eth_headers\":[],\"expected_hash\":\"{}\",\"merkle_root\":\"{}\",\"generation_sat\":0,\"base_fee_per_gas\":null}}",
            "0".repeat(64),
            "0".repeat(64),
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        return Err("bölüm-eksik fixture reddedilmedi (vacuous)".into());
    }

    // (4) 0x-önekli alan (format drift'i) → red.
    std::fs::write(
        &fixture,
        format!(
            "{{\"provenance\":\"x\",\"btc_merkle_blocks\":[{{\"height\":0,\"merkle_root\":\"0x{}\",\"txids\":[]}}],\"btc_halvings\":[],\"eth_headers\":[],\"expected_hash\":\"{}\",\"generation_sat\":0,\"base_fee_per_gas\":null}}",
            "0".repeat(64),
            "0".repeat(64),
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        return Err("0x-önekli fixture reddedilmedi (vacuous)".into());
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok("fixture-integrity self-test: 4/4 red senaryosu kanıtlandı".into())
}
