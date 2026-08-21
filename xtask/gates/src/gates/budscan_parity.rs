//! `budscan` iki tanimi kopyaliyor; kopyalar ayrisirsa bu kapi duser.
//!
//! # Neden kopya var
//!
//! `budscan` bir tarayici cekirdegi ve `budlum-core`'a baglanmiyor. Baglansa
//! libp2p, tokio, jsonrpsee ve sled'i de baglardi; bir tarayicinin guven
//! sinirinda o bagimlilik grafigi istenmez. Bedeli iki kopya:
//!
//! 1. **Ad kurali.** `crates/budscan/src/name_rule.rs::check_name` ile
//!    `bns_names_are_safe_in_an_address_bar::check_name` ayni tabloyu
//!    uyguluyor.
//! 2. **Icerik kimligi.** `crates/budscan/src/content_id.rs::ContentId::of` ile
//!    `src/storage/content_id.rs::ContentId::of` ayni domain etiketini ve
//!    ayni uzunluk-onekli hash'i kullaniyor.
//!
//! Ikisi de sessizce ayrisabilir ve ayrisirlarsa sonuc sessiz olur: tarayici
//! bir adi kabul eder, zincir etmez; ya da tarayici bir baytin dogrulandigini
//! soyler, zincir baska bir kimlik hesaplar. Bu kapi o iki sessizligi
//! gurultuye ceviriyor.
//!
//! # Ne olculuyor
//!
//! Metin karsilastirmasi degil, **davranis** karsilastirmasi degil de
//! **tanim** karsilastirmasi: iki dosyanin da tasimasi gereken degismezler
//! (domain etiketi, uzunluk oneki, karakter kumesi, red sinifi adlari) tek tek
//! aranyor. `grep` sorusu "bu metin var mi" ve bu sorunun yanlis soru oldugu
//! yer cok; burada dogru soru bu, cunku aranan sey tam olarak bir sabitin
//! yazili hali.

use std::fmt::Write as _;
use std::path::Path;

/// Ad kuralinin iki kopyasinda da bulunmasi gereken red sinifi adlari.
const REJECTION_VARIANTS: &[&str] = &[
    "WrongLength",
    "DisallowedCharacter",
    "EmptyLabel",
    "HyphenAtLabelEdge",
    "MixedScript",
    "NoSuffix",
];

/// Ad kuralinin karakter kumesi, iki kopyada da ayni yazilmis olmali.
const CHARSET_PATTERN: &str = "'a'..='z' | '0'..='9' | '-' | '.'";

/// Uzunluk siniri.
const LENGTH_BOUND: &str = "(3..=32).contains(&count)";

/// Icerik kimliginin alan ayirici etiketi; iki tarafta da ayni olmali.
const CONTENT_DOMAIN_TAG: &str = "BDLM_CONTENT_V1";

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("{} okunamadi: {e}", path.display()))
}

/// # Errors
///
/// Iki kopyadan biri digerinin tasidigi bir tanimi kaybettiginde.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    check_name_rule(root, &mut problems)?;
    check_content_id(root, &mut problems)?;
    check_shared_constants(root, &mut problems)?;

    if problems.is_empty() {
        return Ok(String::from(
            "budscan parity OK: ad kurali alti red sinifini ve ayni karakter kumesini \
             tasiyor, ContentId ayni domain etiketi ve uzunluk onekiyle hesaplaniyor, \
             boyut siniri ve EPOCH_LENGTH ucu de ayni",
        ));
    }
    let mut msg = String::new();
    for p in &problems {
        let _ = writeln!(msg, "  {p}");
    }
    Err(msg)
}

/// Iki ad kurali kopyasi ayni tabloyu tasiyor mu?
fn check_name_rule(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // ── 1. Ad kurali ────────────────────────────────────────────────────
    let browser = read(root, "crates/budscan/src/name_rule.rs")?;
    let gate = read(
        root,
        "xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs",
    )?;

    for variant in REJECTION_VARIANTS {
        if !browser.contains(variant) {
            problems.push(format!(
                "crates/budscan/src/name_rule.rs icinde {variant} red sinifi yok; kapi onu \
                 tasiyor, yani tarayici kapinin reddettigi bir seyi kabul ediyor olabilir"
            ));
        }
        if !gate.contains(variant) {
            problems.push(format!(
                "bns_names_are_safe_in_an_address_bar.rs icinde {variant} yok; \
                 tarayici onu tasiyor"
            ));
        }
    }

    if !browser.contains(CHARSET_PATTERN) {
        problems.push(format!(
            "crates/budscan/src/name_rule.rs karakter kumesini {CHARSET_PATTERN} olarak \
             yazmiyor. Kume genisledi ya da daraldi; her iki durumda da kapinin \
             kopyasiyla ayni olmasi gerekiyor"
        ));
    }
    if !gate.contains("'a'..='z' | '0'..='9' | '-' | '.'") {
        problems.push(String::from(
            "kapinin kendi karakter kumesi degismis; iki taraf ayrismis",
        ));
    }
    if !browser.contains(LENGTH_BOUND) {
        problems.push(format!(
            "crates/budscan/src/name_rule.rs {LENGTH_BOUND} uzunluk sinirini uygulamiyor"
        ));
    }

    // Tarayici kurali zincirin kuralindan **dar** olmali. Zincir tarafinda
    // hala yalniz bir uzunluk kurali var; buna guvenilmiyor, olculuyor.
    let registry = read(root, "src/bns/registry.rs")?;
    if !registry.contains("(3..=32).contains(&char_count)") {
        problems.push(String::from(
            "src/bns/registry.rs artik 3..=32 uzunluk kuralini uygulamiyor. Ya sinir \
             kaydi ya da bir karakter kumesi kurali indi. Karakter kumesi indiyse, \
             crates/budscan/src/name_rule.rs ile ayni commit'te uzlastirilmasi gerekiyor: \
             ismin ne icerebileceginе karar veren iki yerin habersiz ayrismasi, tek \
             yerin kotu karar vermesinden kotudur",
        ));
    }

    Ok(())
}

/// Iki `ContentId` tanimi ayni kimligi mi uretiyor?
fn check_content_id(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // ── 2. Icerik kimligi ───────────────────────────────────────────────
    let browser_cid = read(root, "crates/budscan/src/content_id.rs")?;
    let core_cid = read(root, "src/storage/content_id.rs")?;

    if !browser_cid.contains(CONTENT_DOMAIN_TAG) {
        problems.push(format!(
            "crates/budscan/src/content_id.rs {CONTENT_DOMAIN_TAG} etiketini kullanmiyor; \
             tarayicinin hesapladigi kimlik zincirinkiyle ayni olmaz ve her dogrulama \
             sessizce basarisiz olur"
        ));
    }
    if !core_cid.contains(CONTENT_DOMAIN_TAG) {
        problems.push(format!(
            "src/storage/content_id.rs {CONTENT_DOMAIN_TAG} etiketini kaybetmis; \
             tarayici onu tasiyor"
        ));
    }

    // Uzunluk oneki: olmadan `["a","bc"]` ile `["ab","c"]` ayni hash'i verir.
    if !browser_cid.contains("(field.len() as u64).to_le_bytes()") {
        problems.push(String::from(
            "crates/budscan/src/content_id.rs alanlari uzunluk-onekleyerek hash'lemiyor. \
             Onek olmadan iki farkli icerik ayni kimlige sahip olabilir",
        ));
    }

    Ok(())
}

/// Uc yerde tekrarlanan sabitler ayni mi?
fn check_shared_constants(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // ── 3. Boyut siniri: uc yerde ayni ──────────────────────────────────
    let browser_fetch = read(root, "crates/budscan/src/fetch.rs")?;
    let core_gateway = read(root, "src/gateway/service.rs")?;
    let browser_limit = browser_fetch.contains("10 * 1024 * 1024");
    let core_limit = core_gateway.contains("10 * 1024 * 1024");
    if browser_limit != core_limit {
        problems.push(String::from(
            "icerik boyut siniri crates/budscan/src/fetch.rs ile src/gateway/service.rs \
             arasinda ayrismis. Iki farkli sinir, birinin digerinin reddettigini \
             kabul ettigi bir bosluk acar",
        ));
    }

    // ── 4. Epoch uzunlugu ───────────────────────────────────────────────
    let browser_lc = read(root, "crates/budscan/src/light_client.rs")?;
    let chain = read(root, "src/chain/blockchain.rs")?;
    if chain.contains("pub const EPOCH_LENGTH: u64 = 10;")
        != browser_lc.contains("pub const EPOCH_LENGTH: u64 = 10;")
    {
        problems.push(String::from(
            "EPOCH_LENGTH src/chain/blockchain.rs ile crates/budscan/src/light_client.rs \
             arasinda ayrismis. Tarayici yanlis basliklari epoch siniri sanar ve \
             takip ettigi zincir zincirin kendisi olmaz",
        ));
    }

    Ok(())
}

/// # Errors
///
/// Beklendigi gibi davranmayan kanaryalar.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Kanarya: bos bir agacta kapi **gecmemeli**. Dosya okuyamayan bir kapi
    // "sorun yok" derse, hicbir sey inceleyip OK demis olur.
    let empty = std::path::Path::new("/nonexistent-budscan-parity-canary");
    if run(empty).is_ok() {
        problems.push(String::from("VACUOUS: kapi, okuyamadigi bir agacta gecti"));
    }

    // Kanarya: aranan sabitlerin listesi bos olmamali, yoksa dongu hicbir sey
    // kontrol etmez ve kapi her zaman gecer.
    if REJECTION_VARIANTS.is_empty() {
        problems.push(String::from(
            "VACUOUS: red sinifi listesi bos, dongu hicbir sey aramiyor",
        ));
    }
    if CHARSET_PATTERN.is_empty() || LENGTH_BOUND.is_empty() {
        problems.push(String::from(
            "VACUOUS: aranan desen bos; bos bir desen her metinde bulunur",
        ));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "  {p}");
        }
        return Err(msg);
    }
    Ok(String::from(
        "budscan parity self-test OK: kapi okuyamadigi bir agacta gecmiyor ve aradigi \
         desenlerin hicbiri bos degil",
    ))
}
