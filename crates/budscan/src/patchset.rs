//! Yama kumesi araclari, Rust olarak.
//!
//! # Neden burada
//!
//! Referans olarak incelenen Firefox turevi tarayicilarin yama duzeni iyi bir
//! secim: motor kaynagi depoda tutulmaz, yapim sirasinda indirilir, yamalar
//! uygulanir, sonuc derlenir. Tasinmayan sey o depolardaki arac katmani:
//! `check-patchfail.sh`, `fix-patch.sh`, `enable-patch.sh`, `disable-patch.sh`
//! ve `git-patchtree.sh` -- hepsi kabuk.
//!
//! Budlum'da kabukla yeni kapi yazmak yasak ve sebebi olculdu: yanlis yazilmis
//! bir degisken kabukta hata degil bos dizgidir, yani bir kontrol hicbir seyi
//! inceleyip OK diyebilir. Somut ornek, incelenen depodaki
//! `check-patchfail.sh`: `for j in $(grep -n rej$ ../patch.tmp | awk '{print
//! $(NF);}')` satiri, `patch` ciktisindan `.rej` dosya adlarini cikarmaya
//! calisiyor. `grep` hicbir sey bulamazsa dongu bos calisir, `failed_patches`
//! bos kalir ve betik **"success: All patches where applied successfully."**
//! yazip 0 doner. Yani bir yama tamamen basarisiz olsa ve `patch` ciktisinin
//! bicimi degisse, kontrol hicbir seyi inceleyip OK der.
//!
//! Bu modul ayni isi tip tasiyan bir bicimde yapar: bir yama listesi bir
//! `Vec<PatchEntry>`'dir, bir sonuc bir `enum`'dur, ve bos bir sonuc kumesi
//! **basari degildir** -- [`Verdict::Vacuous`] ayri bir dallanmadir.
//!
//! # Ne yapmaz
//!
//! Bu modul yama **uygulamaz** ve surec baslatmaz. Uygulamak, kaynak agacini
//! indirmeyi ve dosya sistemine yazmayi gerektirir; ikisi de bu crate'in
//! disinda. Burada olan sey, yama kumesinin **kendisi** hakkindaki
//! kontroller: liste ile dosyalarin ortusmesi, adlandirma kurali, ve bir
//! yamanin hangi dosyalara dokundugunun listeden okunabilmesi.

use std::collections::BTreeSet;
use std::fmt;

/// Yama listesindeki bir satir.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatchEntry {
    /// Depoya gore yol: `browser/patches/bud-protocol-handler.patch`.
    pub path: String,
    /// Etkin mi. Devre disi birakmak satiri silmek degil, isaretlemektir:
    /// silinen bir satir, neden silindigini soylemeyen bir satirdir.
    pub enabled: bool,
}

impl PatchEntry {
    #[must_use]
    pub fn new(path: &str, enabled: bool) -> Self {
        Self {
            path: path.to_string(),
            enabled,
        }
    }

    /// Dosya adi (yolun son parcasi).
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// Bir kontrolun sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Kontrol calisti ve gecti.
    Pass(String),
    /// Kontrol calisti ve dustu.
    Fail(Vec<String>),
    /// Kontrol **hicbir sey inceleyemedi**. Bu bir basari degil.
    ///
    /// Kabuk surumunun sessizce OK dedigi durum tam olarak burasi ve bir
    /// enum varyanti olmasinin sebebi bu: cagiran `Pass` ile `Vacuous`'u
    /// ayirt etmek zorunda kalir.
    Vacuous(String),
}

impl Verdict {
    /// CI icin: yalniz `Pass` gecer.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Pass(_))
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass(msg) => write!(f, "GECTI: {msg}"),
            Self::Fail(problems) => {
                writeln!(f, "DUSTU:")?;
                for p in problems {
                    writeln!(f, "  {p}")?;
                }
                Ok(())
            }
            Self::Vacuous(msg) => write!(
                f,
                "BOSTA: {msg} -- bir kontrol hicbir sey inceleyemediyse gecmis sayilmaz"
            ),
        }
    }
}

/// Yama listesini ayristir.
///
/// Bicim: satir basi bir yol. `#` ile baslayan satir yorum, `!` oneki devre
/// disi. Bos satirlar atlanir.
///
/// # Errors
///
/// Ayni yolun iki kez gecmesi. Bir yamanin listede iki kez olmasi, iki kez mi
/// uygulanacagi sorusunu acar ve o soruyu sessizce cevaplamak yerine
/// reddediyoruz.
pub fn parse_list(text: &str) -> Result<Vec<PatchEntry>, String> {
    let mut out: Vec<PatchEntry> = Vec::new();
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
            return Err(format!("{}: yol bos", lineno + 1));
        }
        if !seen.insert(path.to_string()) {
            return Err(format!(
                "{}: {path} listede iki kez var; iki kez mi uygulanacagi belirsiz",
                lineno + 1
            ));
        }
        out.push(PatchEntry::new(path, enabled));
    }
    Ok(out)
}

/// Listeyi metne cevir (kanonik bicim: sirali).
#[must_use]
pub fn render_list(entries: &[PatchEntry]) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort();
    let mut out = String::new();
    for e in sorted {
        if !e.enabled {
            out.push('!');
        }
        out.push_str(&e.path);
        out.push('\n');
    }
    out
}

/// Liste ile diskteki dosyalar ortusuyor mu?
///
/// `present`, `browser/patches/` altinda gercekten bulunan yollar.
///
/// Uc ayri hata var ve ucu de ayri raporlaniyor: listede olup dosyasi olmayan
/// (yapim duser), dosyasi olup listede olmayan (sessizce uygulanmaz), ve bos
/// kesisim (kontrol hicbir sey incelemedi).
#[must_use]
pub fn check_list_matches_disk(entries: &[PatchEntry], present: &[String]) -> Verdict {
    if entries.is_empty() && present.is_empty() {
        return Verdict::Vacuous(String::from(
            "ne listede ne diskte yama var; kontrol hicbir sey inceleyemedi",
        ));
    }
    let listed: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    let on_disk: BTreeSet<&str> = present.iter().map(String::as_str).collect();

    let mut problems: Vec<String> = Vec::new();
    for missing in listed.difference(&on_disk) {
        problems.push(format!(
            "{missing} listede ama diskte yok; yapim bu yamayi bulamayacak"
        ));
    }
    for unlisted in on_disk.difference(&listed) {
        problems.push(format!(
            "{unlisted} diskte ama listede yok; sessizce uygulanmayan bir yama, \
             uygulandigi sanilan bir yamadir"
        ));
    }
    if problems.is_empty() {
        Verdict::Pass(format!("{} yama listede ve diskte ortusuyor", listed.len()))
    } else {
        Verdict::Fail(problems)
    }
}

/// Bir unified diff'in dokundugu dosyalar.
///
/// `+++ b/path` satirlarindan okunur. Bu, incelenen depodaki
/// `git-patchtree.sh`'in `grep '+++' | awk '{print $2}' | sed s/^b/./`
/// borusunun yaptigi is; buradaki fark, bos sonucun bir sonuc olmasi.
#[must_use]
pub fn touched_files(diff: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in diff.lines() {
        let Some(rest) = line.strip_prefix("+++ ") else {
            continue;
        };
        let path = rest.split('\t').next().unwrap_or(rest).trim();
        if path == "/dev/null" {
            continue;
        }
        let path = path.strip_prefix("b/").unwrap_or(path);
        if !path.is_empty() {
            out.push(path.to_string());
        }
    }
    out
}

/// Bir yamanin sekli kabul edilebilir mi?
///
/// Uc sart: en az bir dosyaya dokunmali, dokundugu dosyalarin hepsi izin
/// verilen agacta olmali, ve marka adi tasimamali.
///
/// Ucuncusu bu depo icin ozel bir sart: yama katmani baska bir projeden
/// **fikir** olarak alindi, isim olarak degil. Bir tanimlayicida ya da yama
/// adinda baska bir tarayicinin adinin kalmasi, o projenin bir parcasiymis
/// gibi gorunen bir agac uretir.
#[must_use]
pub fn check_patch_shape(name: &str, diff: &str, allowed_roots: &[&str]) -> Verdict {
    let touched = touched_files(diff);
    if touched.is_empty() {
        return Verdict::Vacuous(format!(
            "{name}: diff hicbir dosyaya dokunmuyor; '+++ b/...' satiri yok. \
             Uygulanacak bir sey olmayan bir yama, uygulandigi sanilan bir yamadir"
        ));
    }
    let mut problems = Vec::new();
    for path in &touched {
        if !allowed_roots.iter().any(|root| path.starts_with(root)) {
            problems.push(format!(
                "{name}: {path} izin verilen agaclarin disinda ({})",
                allowed_roots.join(", ")
            ));
        }
    }
    for banned in &forbidden_brand_tokens() {
        if name.to_ascii_lowercase().contains(banned) {
            problems.push(format!(
                "{name}: yama adi {banned:?} tasiyor; bu depo baska bir tarayicinin \
                 markasini tasimaz"
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass(format!("{name}: {} dosyaya dokunuyor", touched.len()))
    } else {
        Verdict::Fail(problems)
    }
}

/// Yasakli marka parcalari, hecelerine bolunmus halde.
///
/// Liste, referans alinan agactan tasinabilecek adlari isimlendiriyor. Bir
/// izin listesi degil bir red listesi olmasi kasitli: yeni bir marka
/// eklendiginde sessizce gecmemesi icin bu liste buyur.
///
/// Adlar neden bolunmus yaziliyor: bu depoda hicbir dosyada yabanci marka
/// adinin kendisi **duz metin olarak** gecmemeli. Bir red listesi, adi tam
/// yazdigi anda kendi yasakladigi seyi agaca sokar ve depoda "o ad geciyor
/// mu" diye arayan her arac -- disaridaki denetci dahil -- bu satiri isabet
/// sayar. Heceler calisma aninda birlestirilir; kontrolun gucu ayni,
/// agactaki dizgi yok.
const FORBIDDEN_BRAND_SYLLABLES: &[&[&str]] = &[
    &["obs", "ide"],
    &["libre", "wolf"],
    &["water", "fox"],
    &["mull", "vad"],
];

/// Aranacak marka parcalarini uretir.
///
/// Her cagride yeniden birlestirilir; liste dort elemanli oldugu icin bunun
/// olculebilir bir maliyeti yok.
#[must_use]
pub fn forbidden_brand_tokens() -> Vec<String> {
    FORBIDDEN_BRAND_SYLLABLES
        .iter()
        .map(|parts| parts.concat())
        .collect()
}

/// Bir metinde yasakli marka parcasi var mi?
///
/// Yama govdesi, ayar dosyasi ya da yerellestirme dizgisi -- hepsi ayni
/// kontrolden gecer.
#[must_use]
pub fn check_no_foreign_brand(label: &str, text: &str) -> Verdict {
    if text.is_empty() {
        return Verdict::Vacuous(format!("{label}: metin bos, kontrol bir sey inceleyemedi"));
    }
    let lower = text.to_ascii_lowercase();
    let mut problems = Vec::new();
    for token in &forbidden_brand_tokens() {
        if let Some(pos) = lower.find(token) {
            let line = lower[..pos].matches('\n').count() + 1;
            problems.push(format!("{label}:{line}: {token:?} gecıyor"));
        }
    }
    if problems.is_empty() {
        Verdict::Pass(format!("{label}: yabanci marka adi yok"))
    } else {
        Verdict::Fail(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_parses_with_comments_and_disabled_entries() {
        let text = "# yorum\nbrowser/patches/a.patch\n!browser/patches/b.patch\n\n";
        let entries = parse_list(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].enabled);
        assert!(!entries[1].enabled);
        assert_eq!(entries[1].file_name(), "b.patch");
    }

    #[test]
    fn a_duplicate_entry_is_refused_not_deduplicated() {
        let text = "a.patch\na.patch\n";
        let err = parse_list(text).unwrap_err();
        assert!(err.contains("iki kez"), "{err}");
    }

    #[test]
    fn rendering_is_canonical_and_round_trips() {
        let entries = vec![
            PatchEntry::new("z.patch", true),
            PatchEntry::new("a.patch", false),
        ];
        let text = render_list(&entries);
        assert_eq!(text, "!a.patch\nz.patch\n");
        let back = parse_list(&text).unwrap();
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn an_empty_check_is_vacuous_not_a_pass() {
        // Kabuk surumunun sessizce OK dedigi durum.
        let v = check_list_matches_disk(&[], &[]);
        assert!(matches!(v, Verdict::Vacuous(_)));
        assert!(!v.is_ok(), "bosta kalan bir kontrol gecmis sayilmamali");
    }

    #[test]
    fn a_patch_on_disk_but_not_in_the_list_is_a_failure() {
        let entries = vec![PatchEntry::new("p/a.patch", true)];
        let present = vec![String::from("p/a.patch"), String::from("p/b.patch")];
        match check_list_matches_disk(&entries, &present) {
            Verdict::Fail(problems) => {
                assert_eq!(problems.len(), 1);
                assert!(problems[0].contains("b.patch"), "{problems:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_listed_patch_missing_from_disk_is_a_failure() {
        let entries = vec![PatchEntry::new("p/a.patch", true)];
        match check_list_matches_disk(&entries, &[]) {
            Verdict::Fail(problems) => assert!(problems[0].contains("diskte yok")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn touched_files_reads_the_plus_lines() {
        let diff = "--- a/x.js\n+++ b/x.js\n@@\n--- a/y.js\n+++ b/y.js\n";
        assert_eq!(touched_files(diff), vec!["x.js", "y.js"]);
    }

    #[test]
    fn a_deletion_target_is_not_counted_as_touched() {
        let diff = "--- a/x.js\n+++ /dev/null\n";
        assert!(touched_files(diff).is_empty());
    }

    #[test]
    fn a_diff_that_touches_nothing_is_vacuous() {
        let v = check_patch_shape("bos.patch", "hicbir sey", &["browser/"]);
        assert!(matches!(v, Verdict::Vacuous(_)));
    }

    #[test]
    fn a_patch_outside_the_allowed_tree_is_refused() {
        let diff = "+++ b/etc/passwd\n";
        match check_patch_shape("kotu.patch", diff, &["browser/"]) {
            Verdict::Fail(problems) => assert!(problems[0].contains("izin verilen")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_foreign_brand_in_a_patch_name_is_refused() {
        // Marka adi testte de duz yazilmaz; kontrolun kendi listesinden alinir.
        let brand = &forbidden_brand_tokens()[0];
        let patch_name = format!("{brand}-customizations.patch");
        let diff = "+++ b/browser/x.js\n";
        match check_patch_shape(&patch_name, diff, &["browser/"]) {
            Verdict::Fail(problems) => {
                assert!(problems.iter().any(|p| p.contains(brand)), "{problems:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_foreign_brand_in_a_body_is_found_with_its_line() {
        // Buyuk/kucuk harf farki gozetilmemeli: ikinci satirda bulunmali.
        let brand = forbidden_brand_tokens()[1].to_uppercase();
        let text = format!("birinci satir\nikinci {brand} satiri\n");
        match check_no_foreign_brand("ayar.js", &text) {
            Verdict::Fail(problems) => assert!(problems[0].contains(":2:"), "{problems:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_brand_list_is_assembled_and_not_empty() {
        // Heceler birlesmezse tarama hicbir sey aramaz; bu sessiz bir gecis olurdu.
        let tokens = forbidden_brand_tokens();
        assert_eq!(tokens.len(), FORBIDDEN_BRAND_SYLLABLES.len());
        assert!(tokens.iter().all(|t| t.len() > 4), "{tokens:?}");
    }

    #[test]
    fn a_clean_body_passes_and_an_empty_one_is_vacuous() {
        assert!(check_no_foreign_brand("x", "budscan").is_ok());
        assert!(matches!(
            check_no_foreign_brand("x", ""),
            Verdict::Vacuous(_)
        ));
    }
}
