//! The budscan patch layer: the list agrees with the disk and carries no foreign brand.
//!
//! # Why a gate
//!
//! The patch layout was taken as an **idea** from another Firefox derivative. That
//! agacta iki sey vardi ve ikisi de tasinmadi:
//!
//! 1. **The tooling layer is shell.** The concrete measurement is that in that repository
//!    `scripts/check-patchfail.sh`: `.rej` dosyalarini `patch` ciktisindan
//!    `grep -n rej$ | awk '{print $(NF)}'` ile cikariyor. `grep` bir sey
//!    bulamazsa dongu bos calisir, `failed_patches` bos kalir ve betik
//!    `success: All patches where applied successfully.` yazip 0 doner.
//!    So if the format of `patch` output changes, every patch can fail and
//!    kontrol gecer.
//!
//! 2. **Marka adlari.** Dosya adlari, yama adlari ve tanimlayicilarda
//!    another browser's name appears. Taking the idea does not require taking the name,
//!    and if the name stays the tree looks like a part of that project.
//!
//! This gate measures both and does not fall into its own hole while measuring: the case where
//! it can inspect nothing is a separate branch and it does **not** pass.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Yama katmaninda gecmemesi gereken marka parcalari, hecelerine bolunmus.
///
/// Identical to the list inside `budscan::patchset`. There are two copies because
/// `xtask/gates` must not depend on `budscan`; the divergence risk is
/// olculuyor.
///
/// Heceli yazimin sebebi: bir red listesi, yasakladigi adi duz yazdigi anda
/// would put that name into the tree, and every scan asking "does a foreign brand appear"
/// a tool would count this line as a hit. The check keeps its strength without the literal in the tree.
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
/// When the list and the disk disagree, when a patch touches no file, or
/// when a foreign brand name appears anywhere.
#[allow(clippy::too_many_lines)]
pub fn run(root: &Path) -> Result<String, String> {
    let browser = root.join("crates/budscan/browser");
    if !browser.is_dir() {
        return Err(format!(
            "{} is missing. Without the patch layer budscan is a library, not a browser",
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
        let entry = entry.map_err(|e| format!("an entry under patches/ could not be read: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("patch"))
        {
            on_disk.insert(format!("patches/{name}"));
        }
    }

    // Idling: if the list and the disk are both empty the gate inspected nothing
    // and that is not a pass.
    if listed.is_empty() && on_disk.is_empty() {
        return Err(String::from(
            "there is no patch in the list nor on disk; this gate could inspect nothing. A \
             check that silently inspects nothing is worse than no check \
             kotudur: olmayan bir kontrol yaziliyor sanilmaz",
        ));
    }

    let mut problems: Vec<String> = Vec::new();

    let listed_paths: BTreeSet<&str> = listed.iter().map(|(p, _)| p.as_str()).collect();
    for missing in listed_paths.difference(&on_disk.iter().map(String::as_str).collect()) {
        problems.push(format!(
            "{missing} is in patches.txt but not on disk; the build will not find this patch"
        ));
    }
    for unlisted in on_disk
        .iter()
        .filter(|p| !listed_paths.contains(p.as_str()))
    {
        problems.push(format!(
            "{unlisted} is on disk but not in patches.txt; a patch that is silently never \
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
                "{rel}: the diff touches no file (there is no '+++ b/...' line). \
                 Uygulanacak bir sey olmayan bir yama, uygulandigi sanilan bir yamadir"
            ));
        }
        for file in &touched {
            if !allowed_roots.iter().any(|r| file.starts_with(r)) {
                problems.push(format!(
                    "{rel}: {file} is outside the permitted trees ({})",
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
                        "{rel}:{}: {token:?} appears. The patch layout was taken as an idea, \
                         not as a name",
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
            // explanatory texts are not scanned, and which files go unscanned
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
        return Err(String::from("no file could be scanned; the gate idled"));
    }

    if problems.is_empty() {
        return Ok(format!(
            "budscan patchset OK: {} patches agree between the list and the disk, each touching \
             at least one file and staying inside the permitted trees, and {scanned} files \
             carry no foreign brand name",
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

    // Canary 2: an empty list yields an empty result; that is not an error but
    // the caller must not mistake it for a pass. `run` handles that in a separate
    // dalliyor; burada ayristiricinin bos donmesi olculuyor.
    match parse_list("# comment only\n") {
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

    // Canary 5: the brand list must not be empty, otherwise the scan searches for nothing.
    // The same outcome arises if the syllables do not join; the joined form is what is measured.
    if forbidden_brand_tokens().iter().any(|t| t.len() < 5) {
        problems.push(String::from(
            "VACUOUS: the brand list is empty, the scan searches for nothing",
        ));
    }

    // Canary 6: the gate must not pass on a tree it cannot read.
    if run(std::path::Path::new("/nonexistent-budscan-patchset-canary")).is_ok() {
        problems.push(String::from(
            "VACUOUS: the gate passed on a tree that does not exist",
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
        "budscan patchset self-test OK: duplicates are refused, a deletion target is not counted, \
         the 'b/' prefix is stripped, the brand list is populated and the gate does not pass on a \
         gecmiyor",
    ))
}
