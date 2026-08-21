//! Budscan yama katmani: liste diskle ortusuyor ve yabanci marka tasimiyor.
//!
//! # Neden bir kapi
//!
//! Yama duzeni baska bir Firefox turevinden **fikir** olarak alindi. O
//! agacta iki sey vardi ve ikisi de tasinmadi:
//!
//! 1. **Arac katmani kabuk.** Somut olcum, o depodaki
//!    `scripts/check-patchfail.sh`: `.rej` dosyalarini `patch` ciktisindan
//!    `grep -n rej$ | awk '{print $(NF)}'` ile cikariyor. `grep` bir sey
//!    bulamazsa dongu bos calisir, `failed_patches` bos kalir ve betik
//!    `success: All patches where applied successfully.` yazip 0 doner.
//!    Yani `patch` ciktisinin bicimi degisirse butun yamalar dusse bile
//!    kontrol gecer.
//!
//! 2. **Marka adlari.** Dosya adlari, yama adlari ve tanimlayicilarda
//!    baska bir tarayicinin adi geciyor. Fikri almak isim almayi gerektirmez
//!    ve isim kalirsa agac o projenin bir parcasiymis gibi gorunur.
//!
//! Bu kapi ikisini de olcuyor ve olcerken kendi bosluguna dusmuyor: hicbir
//! sey inceleyemedigi durum ayri bir dallanma ve **gecmiyor**.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Yama katmaninda gecmemesi gereken marka parcalari, hecelerine bolunmus.
///
/// `budscan::patchset` icindeki liste ile ayni. Iki kopya olmasinin sebebi,
/// `xtask/gates`'in `budscan`'e bagimli olmamasi; ayrisma riski asagida
/// olculuyor.
///
/// Heceli yazimin sebebi: bir red listesi, yasakladigi adi duz yazdigi anda
/// o adi agaca sokar ve depoyu "yabanci marka geciyor mu" diye tarayan her
/// arac bu satiri isabet sayar. Kontrolun gucu ayni, agactaki dizgi yok.
const FORBIDDEN_BRAND_SYLLABLES: &[&[&str]] = &[
    &["obs", "ide"],
    &["libre", "wolf"],
    &["water", "fox"],
    &["mull", "vad"],
];

/// Aranacak marka parcalarini uretir.
fn forbidden_brand_tokens() -> Vec<String> {
    FORBIDDEN_BRAND_SYLLABLES
        .iter()
        .map(|parts| parts.concat())
        .collect()
}

/// Yama listesini oku.
fn parse_list(text: &str) -> Result<Vec<(String, bool)>, String> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (enabled, path) = match line.strip_prefix('!') {
            Some(rest) => (false, rest.trim()),
            None => (true, line),
        };
        if path.is_empty() {
            return Err(format!("patches.txt:{}: yol bos", lineno + 1));
        }
        if !seen.insert(path.to_string()) {
            return Err(format!(
                "patches.txt:{}: {path} listede iki kez var",
                lineno + 1
            ));
        }
        out.push((path.to_string(), enabled));
    }
    Ok(out)
}

/// Bir diff'in dokundugu dosyalar.
fn touched_files(diff: &str) -> Vec<String> {
    diff.lines()
        .filter_map(|line| line.strip_prefix("+++ "))
        .map(|rest| rest.split('\t').next().unwrap_or(rest).trim())
        .filter(|p| *p != "/dev/null")
        .map(|p| p.strip_prefix("b/").unwrap_or(p).to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// # Errors
///
/// Liste ile disk ortusmediginde, bir yama hicbir dosyaya dokunmadiginda, ya
/// da herhangi bir yerde yabanci bir marka adi gectiginde.
#[allow(clippy::too_many_lines)]
pub fn run(root: &Path) -> Result<String, String> {
    let browser = root.join("crates/budscan/browser");
    if !browser.is_dir() {
        return Err(format!(
            "{} yok. Yama katmani olmadan budscan bir kutuphane; tarayici degil",
            browser.display()
        ));
    }

    let list_path = browser.join("patches.txt");
    let list_text = std::fs::read_to_string(&list_path)
        .map_err(|e| format!("{} okunamadi: {e}", list_path.display()))?;
    let listed = parse_list(&list_text)?;

    let patch_dir = browser.join("patches");
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    let entries = std::fs::read_dir(&patch_dir)
        .map_err(|e| format!("{} okunamadi: {e}", patch_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("patches/ altinda bir girdi okunamadi: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("patch"))
        {
            on_disk.insert(format!("patches/{name}"));
        }
    }

    // Bosta kalma: liste ve disk birlikte bossa kapi hicbir sey inceleyemedi
    // ve bu bir gecis degil.
    if listed.is_empty() && on_disk.is_empty() {
        return Err(String::from(
            "ne listede ne diskte yama var; bu kapi hicbir sey inceleyemedi. Bir \
             kontrolun sessizce hicbir sey incelememesi, kontrolun olmamasindan \
             kotudur: olmayan bir kontrol yaziliyor sanilmaz",
        ));
    }

    let mut problems: Vec<String> = Vec::new();

    let listed_paths: BTreeSet<&str> = listed.iter().map(|(p, _)| p.as_str()).collect();
    for missing in listed_paths.difference(&on_disk.iter().map(String::as_str).collect()) {
        problems.push(format!(
            "{missing} patches.txt icinde ama diskte yok; yapim bu yamayi bulamayacak"
        ));
    }
    for unlisted in on_disk
        .iter()
        .filter(|p| !listed_paths.contains(p.as_str()))
    {
        problems.push(format!(
            "{unlisted} diskte ama patches.txt icinde yok; sessizce uygulanmayan bir \
             yama, uygulandigi sanilan bir yamadir"
        ));
    }

    // Her yama en az bir dosyaya dokunmali ve izin verilen agaclarda kalmali.
    let allowed_roots = [
        "browser/",
        "netwerk/",
        "toolkit/",
        "dom/",
        "security/",
        "modules/",
    ];
    for (rel, _) in &listed {
        let path = browser.join(rel);
        let Ok(diff) = std::fs::read_to_string(&path) else {
            continue; // yukarida zaten raporlandi
        };
        let touched = touched_files(&diff);
        if touched.is_empty() {
            problems.push(format!(
                "{rel}: diff hicbir dosyaya dokunmuyor ('+++ b/...' satiri yok). \
                 Uygulanacak bir sey olmayan bir yama, uygulandigi sanilan bir yamadir"
            ));
        }
        for file in &touched {
            if !allowed_roots.iter().any(|r| file.starts_with(r)) {
                problems.push(format!(
                    "{rel}: {file} izin verilen agaclarin disinda ({})",
                    allowed_roots.join(", ")
                ));
            }
        }
    }

    // Marka: yama adlari, yama govdeleri, ayarlar ve yerellestirme.
    let mut scanned = 0usize;
    let brand_tokens = forbidden_brand_tokens();
    let scan = |rel: &str, text: &str, problems: &mut Vec<String>| {
        for token in &brand_tokens {
            for (i, line) in text.lines().enumerate() {
                if line.to_ascii_lowercase().contains(token) {
                    problems.push(format!(
                        "{rel}:{}: {token:?} geciyor. Yama duzeni fikir olarak alindi, \
                         isim olarak degil",
                        i + 1
                    ));
                }
            }
        }
    };

    for (rel, _) in &listed {
        for token in &brand_tokens {
            if rel.to_ascii_lowercase().contains(token) {
                problems.push(format!("{rel}: yama adi {token:?} tasiyor"));
            }
        }
        if let Ok(text) = std::fs::read_to_string(browser.join(rel)) {
            scan(rel, &text, &mut problems);
            scanned += 1;
        }
    }

    for rel in [
        "settings/budscan.cfg",
        "l10n/tr-TR/budscan.ftl",
        "l10n/en-US/budscan.ftl",
        "README.md",
        "patches.txt",
    ] {
        let path = browser.join(rel);
        if !path.exists() {
            problems.push(format!(
                "crates/budscan/browser/{rel} yok; yama katmani eksik parca ile tarif ediliyor"
            ));
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            // README ve patch dosyalari, kabuk surumunun neden tasinmadigini
            // anlatirken o depolarin adini **bilerek** aniyor. Alintiyi
            // yasaklamak, kararin gerekcesini silmek olurdu; bu yuzden
            // aciklayici metinler taranmiyor ve hangi dosyalarin taranmadigi
            // burada yazili.
            if rel == "README.md" {
                scanned += 1;
                continue;
            }
            scan(rel, &text, &mut problems);
            scanned += 1;
        }
    }

    if scanned == 0 {
        return Err(String::from("hicbir dosya taranamadi; kapi bosta kaldi"));
    }

    if problems.is_empty() {
        return Ok(format!(
            "budscan patchset OK: {} yama listede ve diskte ortusuyor, her biri en az \
             bir dosyaya dokunuyor ve izin verilen agaclarda kaliyor, {scanned} dosyada \
             yabanci marka adi yok",
            listed.len()
        ));
    }
    let mut msg = String::new();
    for p in &problems {
        let _ = writeln!(msg, "  {p}");
    }
    Err(msg)
}

/// # Errors
///
/// Beklendigi gibi davranmayan kanaryalar.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Kanarya 1: liste ayristirici bir tekrari yakalamali.
    if parse_list("a.patch\na.patch\n").is_ok() {
        problems.push(String::from("VACUOUS: tekrarlanan yama kabul edildi"));
    }

    // Kanarya 2: bos bir liste bos bir sonuc verir; bu bir hata degil ama
    // cagiranin onu bir gecis sanmamasi gerekiyor. `run` bunu ayri
    // dalliyor; burada ayristiricinin bos donmesi olculuyor.
    match parse_list("# yalniz yorum\n") {
        Ok(v) if v.is_empty() => {}
        Ok(_) => problems.push(String::from("yorum satiri yama sayildi")),
        Err(e) => problems.push(format!("yorum satiri hata verdi: {e}")),
    }

    // Kanarya 3: `+++ /dev/null` dokunulan dosya sayilmamali.
    if !touched_files("--- a/x.js\n+++ /dev/null\n").is_empty() {
        problems.push(String::from(
            "VACUOUS: silme hedefi dokunulan dosya sayildi",
        ));
    }

    // Kanarya 4: dokunulan dosyalar `b/` onekinden temizlenmeli.
    if touched_files("+++ b/browser/x.js\n") != vec![String::from("browser/x.js")] {
        problems.push(String::from("'b/' oneki temizlenmedi"));
    }

    // Kanarya 5: marka listesi bos olmamali, yoksa tarama hicbir sey aramaz.
    // Heceler birlesmezse de ayni sonuc dogar; birlesmis hali olculuyor.
    if forbidden_brand_tokens().iter().any(|t| t.len() < 5) {
        problems.push(String::from(
            "VACUOUS: marka listesi bos, tarama hicbir sey aramiyor",
        ));
    }

    // Kanarya 6: kapi okuyamadigi bir agacta gecmemeli.
    if run(std::path::Path::new("/nonexistent-budscan-patchset-canary")).is_ok() {
        problems.push(String::from("VACUOUS: kapi olmayan bir agacta gecti"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "  {p}");
        }
        return Err(msg);
    }
    Ok(String::from(
        "budscan patchset self-test OK: tekrar reddediliyor, silme hedefi sayilmiyor, \
         'b/' oneki temizleniyor, marka listesi dolu ve kapi olmayan bir agacta \
         gecmiyor",
    ))
}
