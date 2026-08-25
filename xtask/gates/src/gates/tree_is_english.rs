//! The tree is written in English, except for the Turkish README.
//!
//! The repository was translated to English over many passes. A translation
//! pass that is not gated regresses: a new comment, a new test name or a new
//! error message written in Turkish is invisible to review because nothing
//! fails, and the tree drifts back one line at a time.
//!
//! # What is allowed to stay Turkish
//!
//! Exactly three things:
//!
//!   * [`ALLOWED_FILES`] - `README.tr.md` is a deliberate translation for
//!     Turkish readers and is published as such.
//!   * [`ALLOWED_DIRS`] - a Turkish localisation directory. The strings shown
//!     to a Turkish user ARE the product there; translating them into English
//!     would delete the feature rather than clean the tree.
//!   * The word "Türkçe" itself, wherever it appears. It is the label on the
//!     link that points at that README, so banning it would ban the link.
//!
//! Everything else is a finding.
//!
//! # Why a ratchet and not a ban
//!
//! The translation is not finished. Measured at the time of writing: 5738
//! lines across 346 files still carry Turkish. A gate that fails on all of
//! them fails on every commit and gets switched off, which is worse than no
//! gate. So this has the same shape as `udeps` and `no-idle-code`: the files
//! that still carry Turkish are recorded in [`BASELINE_PATH`] with their line
//! counts, and the gate fails when
//!
//!   * a file **not on the baseline** gains a Turkish line, or
//!   * a file on the baseline gains **more** Turkish lines than recorded.
//!
//! The baseline only shrinks. A file whose count drops is reported so the
//! recorded number is lowered in the same change, and a file that reaches zero
//! must leave the list. That way finishing the translation is the only way the
//! gate stays green, and no pass can quietly regress.
//!
//! # Why two signals rather than one
//!
//! A Turkish-character scan alone is not enough: the tree already contains
//! Turkish written without diacritics (`kanit`, `dogrulama`, `olculen`), which
//! is exactly what a hurried translation leaves behind. That class was measured
//! in this tree and it is the class a character scan misses.
//!
//! So there are two:
//!
//!   1. **Characters.** Any of `şğıçöüŞĞİÇÖÜ`. Unambiguous.
//!   2. **Words.** A vocabulary of Turkish words that do not collide with
//!      English. Words that are spelled the same in both languages (`test`,
//!      `var`, `son`, `kok`, `dal`, `bos`, `once`) are deliberately absent: a
//!      gate that fires on `once` teaches people to disable it.
//!
//! # A green gate is only as wide as its vocabulary
//!
//! The word list started at 60 entries and the gate was green, which was read
//! as "the tree has 9 Turkish lines left in 3 files". It did not. A scan with
//! a wider list of undiacriticised Turkish found **121 further lines in 86
//! files** that the gate walked straight past: `kilidi`, `satir`, `icin`,
//! `sadece`, `derleme`, `kapisi` and the rest of the everyday vocabulary a
//! hurried translation leaves behind. The gate was not wrong about what it
//! looked for; it was never asked to look for those.
//!
//! This is the failure mode of every list-driven gate: the report says
//! "clean", and what it means is "clean, as far as the list goes". So the
//! vocabulary is now 114 entries, and the entries were chosen by measuring the
//! tree rather than by guessing - each one was counted, and each surviving
//! collision with English is handled by [`ENGLISH_COLLISIONS`] rather than by
//! dropping the Turkish word and reopening the hole.
//!
//! # Why proper nouns are scrubbed first
//!
//! `Gröbner`, `Schrödinger` and `Poincaré` carry diacritics that are not
//! Turkish. They are removed from the line before the character scan, or the
//! gate would report a mathematician as a translation defect.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Files that are allowed to contain Turkish, by file name.
const ALLOWED_FILES: &[&str] = &[
    // A deliberate Turkish translation of the README, linked from the English
    // one. This is the reason the gate exists in this shape rather than as a
    // blanket ban.
    "README.tr.md",
    // A typo dictionary: the entries are Turkish words precisely because it is
    // teaching the typo checker about them.
    "typos.toml",
    // This gate itself. Its vocabulary list IS Turkish words, and its canaries
    // must write Turkish fixtures to prove they can still detect it. A gate
    // that cannot name what it is looking for cannot look for it. Exempting
    // the file is honest; the alternative is obfuscating the dictionary until
    // nobody can audit what the gate actually bans.
    "tree_is_english.rs",
];

/// Path fragments whose contents are a Turkish localisation.
///
/// A localisation file is not untranslated source: its Turkish is what the
/// Turkish user reads. The exemption is by directory rather than by file name
/// so that a localisation gains files without the gate having to be edited,
/// and it is deliberately narrow - only the Turkish locale of the browser,
/// never a source tree.
const ALLOWED_DIRS: &[&str] = &["browser/l10n/tr-TR/"];

/// The one Turkish word that may appear anywhere: the label on the link to the
/// Turkish README. Scrubbed before both scans.
const ALLOWED_WORD: &str = "Türkçe";

/// Names that carry non-Turkish diacritics and must not be reported.
const PROPER_NOUNS: &[&str] = &["Gröbner", "Schrödinger", "Poincaré", "Ångström", "Erdős"];

/// English words that begin with a Turkish vocabulary word.
///
/// The vocabulary is matched on a left word boundary only, so `satir` is meant
/// to catch `satiri` and `satirlari`. It also catches the English `satire`,
/// and `icin` catches `icing`. Dropping those two entries from the vocabulary
/// would be the easy fix and the wrong one: `satir` and `icin` are two of the
/// most frequent Turkish words in this tree, so dropping them keeps the hole
/// open. Removing the English word from the line first keeps both.
///
/// Matched case-insensitively, after the line is lowercased.
const ENGLISH_COLLISIONS: &[&str] = &[
    "satire",
    "satires",
    "satirical",
    "satirically",
    "satirist",
    "satirists",
    "satirize",
    "satirized",
    "icing",
];

/// Turkish-specific characters. Their presence is unambiguous.
const TURKISH_CHARS: &[char] = &['ş', 'ğ', 'ı', 'ç', 'ö', 'ü', 'Ş', 'Ğ', 'İ', 'Ç', 'Ö', 'Ü'];

/// Turkish words that do not collide with English, for catching Turkish
/// written without diacritics. Kept lowercase; matched on word boundaries.
///
/// Deliberately absent: `test`, `var`, `son`, `ilk`, `kok`, `dal`, `bos`,
/// `once`, `an`, `ad`, `at`, `el`, `it`, `on`, `o`. Each is either an English
/// word or an English substring, and a gate with false positives gets
/// switched off.
const TURKISH_WORDS: &[&str] = &[
    "acikca",
    "acikken",
    "acikla",
    "adresleme",
    "agac",
    "alinir",
    "altinda",
    "anahtar",
    "anlasma",
    "arasinda",
    "artik",
    "asagidaki",
    "ayirma",
    "ayrica",
    "ayrint",
    "bagimli",
    "bagimsiz",
    "baglamak",
    "baglant",
    "bakiniz",
    "baska",
    "bayraga",
    "baytlik",
    "belirtir",
    "betigin",
    "birakir",
    "birlikte",
    "butun",
    "buyuk",
    "cagir",
    "cagri",
    "calis",
    "cikar",
    "cozul",
    "cozum",
    "cunku",
    "degeri",
    "degil",
    "degisik",
    "denetimi",
    "denetler",
    "derleme",
    "devam",
    "dogru",
    "dogrula",
    "dosyanin",
    "dugum",
    "durum",
    "dusuk",
    "edildi",
    "edilebilir",
    "edilir",
    "edilmeli",
    "eklenir",
    "gecerken",
    "gecerli",
    "gecersiz",
    "gecmeli",
    "gecti",
    "gerekce",
    "gereken",
    "gerekir",
    "gerekli",
    "girdiler",
    "gizli",
    "gorunur",
    "guvenl",
    "hangi",
    "herhangi",
    "hicbir",
    "hizli",
    "icerik",
    "icin",
    "iliski",
    "ilki",
    "imzalama",
    "isaretlemek",
    "kademesi",
    "kanarya",
    "kanit",
    "kapali",
    "kapisi",
    "kapiyi",
    "kararsiz",
    "katman",
    "kaydi",
    "kayit",
    "kilidi",
    "kisit",
    "kopyalanmayan",
    "korumaz",
    "kosar",
    "kosur",
    "kucuk",
    "kullanici",
    "kurulamazsa",
    "kurulur",
    "nasil",
    "nobetci",
    "noktasi",
    "okunamazsa",
    "olarak",
    "olcul",
    "olcum",
    "olmali",
    "olmasi",
    "olmayan",
    "olustur",
    "onceki",
    "oncesi",
    "onemli",
    "ornegin",
    "ornek",
    "ozellik",
    "ozet",
    "parcasi",
    "reddedil",
    "sadece",
    "satir",
    "sayfa",
    "sessizce",
    "silinen",
    "sinir",
    "siralanir",
    "sirasinda",
    "sisirilmis",
    "sonraki",
    "sonrasi",
    "soylemeyen",
    "surum",
    "surumunde",
    "tamami",
    "tarafindan",
    "tasima",
    "tohumunu",
    "turetir",
    "tutulan",
    "tutulur",
    "uretil",
    "uretim",
    "uretiyordu",
    "uzerinden",
    "uzlasma",
    "uzunlugu",
    "verilir",
    "yalniz",
    "yanlis",
    "yapild",
    "yardimcisi",
    "yazilir",
    "yeniden",
    "yerine",
    "yerlesim",
    "yukaridaki",
    "yurut",
    "zorunlu",
];

/// Directories never scanned.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".cargo",
    "corpus",
    "__pycache__",
];

/// Files never scanned: lockfiles and binary-ish payloads carry no prose.
const SKIP_FILES: &[&str] = &["Cargo.lock", "flake.lock", "imports.lock"];

/// Extensions never scanned.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "gz", "tar", "bin", "wasm", "so", "a", "o",
    "lock", "svg", "woff", "woff2", "ttf", "webp",
];

/// The recorded per-file counts of Turkish lines that still remain.
const BASELINE_PATH: &str = ".github/turkish-baseline.txt";

/// A scan that walks too few files is vacuous and must fail rather than pass.
const VACUITY_FLOOR: usize = 50;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 40;

/// Report every finding instead of the first [`MAX_REPORTED`], so the output
/// can be turned into a baseline.
///
/// Regenerating the baseline used to mean editing `MAX_REPORTED` by hand and
/// remembering to put it back. Once it was not put back, and CI caught the
/// leftover `100000` as an unreadable literal. An env var cannot be forgotten
/// in a commit.
fn report_limit() -> usize {
    if std::env::var_os("BUDLUM_GATE_REPORT_ALL").is_some() {
        usize::MAX
    } else {
        MAX_REPORTED
    }
}

/// Remove the strings that are allowed to carry Turkish characters, so neither
/// scan sees them. Order matters only in that all of them run before scanning.
fn scrub(line: &str) -> String {
    let mut out = line.replace(ALLOWED_WORD, " ");
    for noun in PROPER_NOUNS {
        out = out.replace(noun, " ");
    }
    for word in ENGLISH_COLLISIONS {
        out = replace_ascii_case_insensitive(&out, word, " ");
    }
    out
}

/// Replace every ASCII-case-insensitive occurrence of `needle` with `with`.
///
/// [`str::replace`] is case-sensitive, and the collision list has to hold for
/// `Satire` at the start of a sentence as well as `satire` mid-line.
fn replace_ascii_case_insensitive(haystack: &str, needle: &str, with: &str) -> String {
    let lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find(&needle_lower) {
        let start = cursor + rel;
        let end = start + needle_lower.len();
        out.push_str(haystack.get(cursor..start).unwrap_or_default());
        out.push_str(with);
        cursor = end;
    }
    out.push_str(haystack.get(cursor..).unwrap_or_default());
    out
}

/// The first Turkish character on the line, if any.
fn turkish_char(scrubbed: &str) -> Option<char> {
    scrubbed.chars().find(|c| TURKISH_CHARS.contains(c))
}

/// A byte is a word character for the purposes of boundary matching.
///
/// `_` is deliberately NOT a word byte. Rust identifiers are `snake_case`, so
/// the Turkish inside `kayit_gecerli_mi` sits behind an underscore; treating
/// `_` as a word character made the gate miss every Turkish function and test
/// name, which is the largest class this tree had. Measured: the canary for
/// `fn kayit_gecerli_mi()` failed until this changed.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// The first Turkish vocabulary word on the line, matched at a word boundary
/// on the left so `kanit` matches `kanitlari` but not `dokanit`.
///
/// Returns [`None`] when the line carries no vocabulary word.
fn turkish_word(scrubbed: &str) -> Option<&'static str> {
    let lower = scrubbed.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for needle in TURKISH_WORDS {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(needle) {
            let start = from + rel;
            let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
            if before_ok {
                return Some(needle);
            }
            from = start + 1;
            if from >= lower.len() {
                break;
            }
        }
    }
    None
}

/// Is this path exempt by file name, or by living in a localisation directory?
fn is_allowed(path: &Path) -> bool {
    if path
        .file_name()
        .is_some_and(|n| ALLOWED_FILES.contains(&n.to_string_lossy().as_ref()))
    {
        return true;
    }
    let text = path.to_string_lossy().replace('\\', "/");
    ALLOWED_DIRS.iter().any(|dir| text.contains(dir))
}

/// Is this path skipped by extension?
fn skipped_ext(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| SKIP_EXTS.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
}

fn truncate100(s: &str) -> String {
    s.trim().chars().take(100).collect()
}

/// Recursively collect files in deterministic (sorted) order.
fn sorted_walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        // `file_type` reports the entry itself, so a committed symlink to a
        // directory is not followed: following one would walk outside the
        // repository and re-scan in a loop.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name_str.as_ref()) {
                walk_into(&path, out);
            }
        } else if kind.is_file() && !SKIP_FILES.contains(&name_str.as_ref()) && !skipped_ext(&path)
        {
            out.push(path);
        }
    }
}

/// Read the baseline into `path -> allowed line count`.
fn read_baseline(root: &Path) -> BTreeMap<String, usize> {
    let Ok(text) = fs::read_to_string(root.join(BASELINE_PATH)) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((path, count)) = line.rsplit_once('\t') else {
            continue;
        };
        let Ok(n) = count.trim().parse::<usize>() else {
            continue;
        };
        out.insert(path.trim().to_string(), n);
    }
    out
}

/// The per-file Turkish line counts, and one example line per file.
struct Scan {
    counts: BTreeMap<String, usize>,
    examples: BTreeMap<String, String>,
    scanned: usize,
}

fn scan(root: &Path) -> Scan {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut examples: BTreeMap<String, String> = BTreeMap::new();
    let mut scanned = 0usize;

    for path in sorted_walk(root) {
        if is_allowed(&path) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            // Non-UTF-8 files carry no prose we can judge.
            continue;
        };
        scanned += 1;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (lineno, line) in text.lines().enumerate() {
            let scrubbed = scrub(line);
            let finding = turkish_char(&scrubbed)
                .map(|c| format!("Turkish character '{c}'"))
                .or_else(|| turkish_word(&scrubbed).map(|w| format!("Turkish word \"{w}\"")));
            if let Some(what) = finding {
                *counts.entry(rel.clone()).or_default() += 1;
                examples.entry(rel.clone()).or_insert_with(|| {
                    format!("{rel}:{}: {what}\n      {}", lineno + 1, truncate100(line))
                });
            }
        }
    }

    Scan {
        counts,
        examples,
        scanned,
    }
}

/// # Errors
///
/// Returns a finding when a file not on the baseline carries Turkish, when a
/// baselined file carries more Turkish than recorded, when a recorded count is
/// stale, or when the scan would be vacuous.
pub fn run(root: &Path) -> Result<String, String> {
    let result = scan(root);

    if result.scanned < VACUITY_FLOOR {
        return Err(format!(
            "only {} readable files scanned under {}; the gate would be vacuous",
            result.scanned,
            root.display()
        ));
    }

    let baseline = read_baseline(root);
    let mut regressions: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();

    for (file, count) in &result.counts {
        let allowed = baseline.get(file).copied().unwrap_or(0);
        if *count > allowed {
            let example = result
                .examples
                .get(file)
                .map_or_else(String::new, |e| format!("\n      {e}"));
            if allowed == 0 {
                regressions.push(format!(
                    "  {file}: {count} Turkish line(s), not on the baseline{example}"
                ));
            } else {
                regressions.push(format!(
                    "  {file}: {count} Turkish line(s), baseline allows {allowed}{example}"
                ));
            }
        }
    }

    // A file whose count dropped, or which is now clean, must have its recorded
    // number lowered in the same change, or the baseline stops meaning anything.
    for (file, allowed) in &baseline {
        let now = result.counts.get(file).copied().unwrap_or(0);
        if now < *allowed {
            stale.push(format!(
                "  {file}: baseline says {allowed}, actual {now} - lower it (or delete the line at 0)"
            ));
        }
    }

    if !regressions.is_empty() {
        let n = regressions.len();
        let mut msg = format!("{n} file(s) gained Turkish:\n");
        for r in regressions.iter().take(report_limit()) {
            msg.push_str(r);
            msg.push('\n');
        }
        if n > report_limit() {
            writeln!(msg, "  ... and {} more", n - report_limit())
                .expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\n  The tree is written in English. Translate the line.\n  \
             Turkish is allowed only in README.tr.md, in a Turkish localisation\n  \
             directory, and in the word \"Türkçe\", which is the label on the link\n  \
             pointing at that README.\n  \
             The baseline only shrinks: do not raise a number in ",
        );
        msg.push_str(BASELINE_PATH);
        msg.push('.');
        return Err(msg);
    }

    if !stale.is_empty() {
        let n = stale.len();
        let mut msg = format!("{n} stale baseline entr(ies) in {BASELINE_PATH}:\n");
        for s in stale.iter().take(report_limit()) {
            msg.push_str(s);
            msg.push('\n');
        }
        if n > report_limit() {
            writeln!(msg, "  ... and {} more", n - report_limit())
                .expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\n  These files carry less Turkish than recorded, which is progress the\n  \
             baseline is not admitting. Lower the numbers so the next regression is\n  \
             measured against what is actually there.",
        );
        return Err(msg);
    }

    let remaining: usize = result.counts.values().sum();
    Ok(format!(
        "Tree is English: {} files scanned, {} file(s) still carrying {remaining} Turkish line(s) on the baseline.",
        result.scanned,
        result.counts.len()
    ))
}

/// A fresh scratch directory for a self-test run.
fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-english-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// An English fixture tree large enough to clear the vacuity floor.
fn build_clean_tree(root: &Path) -> std::io::Result<()> {
    let src = root.join("src");
    fs::create_dir_all(&src)?;
    for i in 1..=60 {
        fs::write(
            src.join(format!("f{i}.rs")),
            format!("/// Verify the record and refuse a bad one.\nfn f{i}() {{ let a = 1; }}\n"),
        )?;
    }
    fs::write(
        root.join("README.md"),
        "# Title\n\nPlain English prose, nothing to translate here.\n",
    )?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    for f in sorted_walk(src) {
        let rel = f.strip_prefix(src).expect("walked file is under src");
        let target = dst.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&f, &target)?;
    }
    Ok(())
}

/// Stage a copy of the clean tree with one extra file, and report whether the
/// gate accepted it.
fn accepts_with(
    clean: &Path,
    tmp: &Path,
    tag: &str,
    name: &str,
    body: &str,
) -> Result<bool, String> {
    let dir = tmp.join(tag);
    copy_tree(clean, &dir).map_err(|e| format!("cannot stage {tag}: {e}"))?;
    let target = dir.join(name);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("cannot create dir for {tag}: {e}"))?;
    }
    fs::write(&target, body).map_err(|e| format!("cannot write fixture for {tag}: {e}"))?;
    Ok(run(&dir).is_ok())
}

/// The ratchet canaries: the baseline must exempt what it records, must not
/// absorb new Turkish in a file it already lists, and must not stay higher
/// than what the file actually carries.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn baseline_canaries(clean: &Path, tmp: &Path) -> Result<(), String> {
    // The baseline must exempt a recorded file, or the ratchet cannot be
    // adopted while the translation is unfinished.
    if !accepts_with(
        clean,
        tmp,
        "baselined",
        "LEGACY.rs",
        "// kanit dogrulama yapilir\n",
    )
    .and_then(|_| {
        let dir = tmp.join("baselined");
        let bl = dir.join(BASELINE_PATH);
        fs::create_dir_all(bl.parent().expect("baseline has a parent"))
            .map_err(|e| format!("cannot create baseline dir: {e}"))?;
        fs::write(&bl, "# known debt\nLEGACY.rs\t1\n")
            .map_err(|e| format!("cannot write baseline: {e}"))?;
        Ok(run(&dir).is_ok())
    })? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a baselined file still failed, so the ratchet cannot be adopted",
        ));
    }

    // Going OVER the recorded count must fail, or a baselined file becomes a
    // place to keep adding Turkish.
    {
        let dir = tmp.join("overbaseline");
        copy_tree(clean, &dir).map_err(|e| format!("cannot stage overbaseline: {e}"))?;
        fs::write(
            dir.join("LEGACY.rs"),
            "// kanit dogrulama yapilir\n// ikinci yanlis satir gecersiz\n",
        )
        .map_err(|e| format!("cannot write fixture: {e}"))?;
        let bl = dir.join(BASELINE_PATH);
        fs::create_dir_all(bl.parent().expect("baseline has a parent"))
            .map_err(|e| format!("cannot create baseline dir: {e}"))?;
        fs::write(&bl, "LEGACY.rs\t1\n").map_err(|e| format!("cannot write baseline: {e}"))?;
        if run(&dir).is_ok() {
            let _ = fs::remove_dir_all(tmp);
            return Err(String::from(
                "canary: a baselined file gained a Turkish line and still passed",
            ));
        }
    }

    // A count that dropped must be reported, or the baseline rots into a
    // permanent excuse and stops measuring the next regression.
    {
        let dir = tmp.join("stalebaseline");
        copy_tree(clean, &dir).map_err(|e| format!("cannot stage stalebaseline: {e}"))?;
        fs::write(dir.join("LEGACY.rs"), "// kanit dogrulama yapilir\n")
            .map_err(|e| format!("cannot write fixture: {e}"))?;
        let bl = dir.join(BASELINE_PATH);
        fs::create_dir_all(bl.parent().expect("baseline has a parent"))
            .map_err(|e| format!("cannot create baseline dir: {e}"))?;
        fs::write(&bl, "LEGACY.rs\t9\n").map_err(|e| format!("cannot write baseline: {e}"))?;
        if run(&dir).is_ok() {
            let _ = fs::remove_dir_all(tmp);
            return Err(String::from(
                "canary: a stale baseline count passed, so progress can go unrecorded",
            ));
        }
    }

    Ok(())
}

/// Canaries for the two scans themselves: every Turkish character, and the
/// diacritic-free vocabulary.
///
/// Split out of [`self_test`] because that function grew past the line
/// ceiling `clippy::too_many_lines` enforces, and the honest fix for a long
/// function is fewer lines rather than an `#[allow]`. The split follows what
/// the canaries actually test, so a reader looking for "does the gate still
/// catch `ş`" lands in one place.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn scan_canaries(clean: &Path, tmp: &Path) -> Result<usize, String> {
    let mut ran = 0usize;
    // Each Turkish character has to be caught on its own.
    for (idx, ch) in TURKISH_CHARS.iter().enumerate() {
        let body = format!("// bir a{ch}iklama\n");
        if counted_accepts_with(&mut ran, clean, tmp, &format!("ch{idx}"), "DIRTY.rs", &body)? {
            let _ = fs::remove_dir_all(tmp);
            return Err(format!("canary: Turkish character '{ch}' was not detected"));
        }
    }

    // Turkish written WITHOUT diacritics is the class a character scan misses,
    // and it is the class this tree actually accumulated. Each of these is
    // pure ASCII.
    for (idx, body) in [
        "// kanit dogrulama yapilir\n",
        "// olculen deger yanlis\n",
        "fn kayit_gecerli_mi() -> bool { true }\n",
        "    return Err(\"gecersiz kullanici\");\n",
    ]
    .iter()
    .enumerate()
    {
        if counted_accepts_with(
            &mut ran,
            clean,
            tmp,
            &format!("ascii{idx}"),
            "DIRTY.rs",
            body,
        )? {
            let _ = fs::remove_dir_all(tmp);
            return Err(format!(
                "canary: diacritic-free Turkish was not detected: {}",
                body.trim()
            ));
        }
    }

    // The vocabulary was widened after a measurement showed the gate reporting
    // "clean" while 121 Turkish lines sat in 86 files it walked past. These are
    // the words that were missing, taken verbatim from lines the gate let
    // through. If one of them is ever dropped from the vocabulary, that hole
    // reopens silently, so each is nailed down here.
    for (idx, body) in [
        "// Unsafe kilidi: bu crate su an 0 unsafe.\n",
        "// derleme FAIL eder (regresyon kapisi).\n",
        "let text = b\"birinci satir\\nikinci satir\\n\";\n",
        "// K-BUD-GENERATIVE-REMOVED: sadece deterministic\n",
        "# Arweave `data_root` icin SHA-384.\n",
        "/// Bir ML-DSA-87 imzalama anahtarinin tohumu.\n",
        "// Programlar sonradan, acikca eklenir.\n",
        "/// `None` = servis edilebilir.\n",
        "// Ekleme sirasinda tutulan girdiler.\n",
        "/// Lubot kademesi.\n",
        "// Kalanlar arasinda >= n olan en kucuk kod noktasi.\n",
        "// veri tasidiginda. Onceki test bunu kaciriyordu.\n",
        "/// Push oncesi kontrolleri kosur.\n",
        "// TEE: success-sonrasi guard.\n",
        "// Iki dosyanin emilim dizileri ayrisirsa.\n",
        "// besler. Mevcut testlerin tamami elle kurulmustu.\n",
        "// Dilim boyu: shard listesi uzerinden kurulur.\n",
        "/// Eski imzanin uzunlugu.\n",
        "// bir sonraki accumulator olur.\n",
        "// baglamak, Kani'nin bir sonraki surumunde.\n",
        "// bir band degeri paniklemek yerine siralanir.\n",
        "// stake MIN_VERIFIER_STAKE altindaysa.\n",
        "// Dizin kurulamazsa veya dosya okunamazsa.\n",
        "// 45 baytlik girdiyle buyuk ayirma talebi.\n",
        "// sisirilmis count uretiyordu.\n",
        "// SHA3 alani korumaz.\n",
        "// blok ozeti ve genesis ozeti.\n",
        "// Kani proofs (hizli set).\n",
        "// bolum parcasi dusuruldu.\n",
        "// olarak stdout'a yazilir.\n",
        "// halt sirasinda hook kosmaz.\n",
        "// yanit, istenen blok icin gelmeli.\n",
        "// Trivy IMAGE kapisi.\n",
        "// tarafindan kuruldu.\n",
        "// Ayrica betigin son satiri sayiyordu.\n",
        "// ornek bir deger.\n",
        "// bir sayfa delta kayipsiz.\n",
        "// en buyuk oran secimi.\n",
    ]
    .iter()
    .enumerate()
    {
        if counted_accepts_with(
            &mut ran,
            clean,
            tmp,
            &format!("vocab{idx}"),
            "DIRTY.rs",
            body,
        )? {
            let _ = fs::remove_dir_all(tmp);
            return Err(format!(
                "canary: a widened-vocabulary Turkish line was not detected: {}",
                body.trim()
            ));
        }
    }

    Ok(ran)
}

/// Canaries for the collision list: it must not become a smuggling route,
/// and each English word on it must still pass on its own.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn collision_canaries(clean: &Path, tmp: &Path) -> Result<usize, String> {
    let mut ran = 0usize;
    // The collision list must not become a way to smuggle Turkish through: the
    // English word is removed from the line, and what remains is still scanned.
    if counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "collisionsmuggle",
        "DIRTY.rs",
        "// satire: bu satir hala Turkce, kanit dogrulama\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: Turkish hid behind an ENGLISH_COLLISIONS word",
        ));
    }

    // Each English collision must survive on its own, or the widened
    // vocabulary would report English prose as a translation defect.
    for (idx, body) in [
        "/// A satire of the protocol, written in English.\n",
        "/// Satire, capitalised at the start of a sentence.\n",
        "/// The satirical reading of the specification.\n",
        "/// A satirist reviewed the design document.\n",
        "/// The icing on the cake is the second gate.\n",
    ]
    .iter()
    .enumerate()
    {
        if !counted_accepts_with(
            &mut ran,
            clean,
            tmp,
            &format!("collision{idx}"),
            "CLEAN.rs",
            body,
        )? {
            let _ = fs::remove_dir_all(tmp);
            return Err(format!(
                "canary: English prose was reported as Turkish: {}",
                body.trim()
            ));
        }
    }

    Ok(ran)
}

/// Canaries for the three exemptions: the Turkish README, the localisation
/// directory, the word "Türkçe" - and the proper nouns that carry
/// non-Turkish diacritics.
///
/// # Errors
///
/// Returns the first canary that misbehaves.
fn exemption_canaries(clean: &Path, tmp: &Path) -> Result<usize, String> {
    let mut ran = 0usize;
    // README.tr.md is exempt: full Turkish, with characters and words.
    if !counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "trreadme",
        "README.tr.md",
        "# Başlık\n\nBu belge Türkçe okuyucular için yazılmıştır; kanit dogrulama.\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: README.tr.md was rejected, but it is a deliberate translation",
        ));
    }

    // A Turkish localisation is exempt: what is written there is what the
    // Turkish user reads.
    if !counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "l10n",
        "browser/l10n/tr-TR/app.ftl",
        "badge-verified =\n    .value = doğrulandı; kanit dogrulama\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: the Turkish localisation was rejected, but its strings are the product",
        ));
    }

    // The exemption must not spill over: the same text one directory up, or in
    // another locale, is still a finding.
    if counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "l10nspill",
        "browser/l10n/en-US/app.ftl",
        "badge-verified =\n    .value = doğrulandı; kanit dogrulama\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: the localisation exemption leaked into another locale",
        ));
    }

    // The word "Türkçe" is the link label and must survive anywhere.
    if !counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "label",
        "LINK.md",
        "[Architecture](docs/ARCHITECTURE.md) - [Türkçe](README.tr.md)\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: the link label \"Türkçe\" was rejected, so the link cannot be written",
        ));
    }

    // A proper noun carrying non-Turkish diacritics is not a finding.
    if !counted_accepts_with(
        &mut ran,
        clean,
        tmp,
        "noun",
        "MATH.rs",
        "/// A Gröbner basis, after Schrödinger and Poincaré.\n",
    )? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a proper noun was reported as Turkish",
        ));
    }

    Ok(ran)
}

/// [`accepts_with`], counting the canary as it runs.
///
/// The count is what makes the split honest: a group that silently runs zero
/// canaries - an empty loop, a dropped call - reports zero, and `self_test`
/// refuses a total it did not expect. Reporting only "3 groups ran" would not
/// have caught that, and did not when it was tried.
///
/// # Errors
///
/// Propagates whatever `accepts_with` reports.
fn counted_accepts_with(
    ran: &mut usize,
    clean: &Path,
    tmp: &Path,
    name: &str,
    file: &str,
    body: &str,
) -> Result<bool, String> {
    *ran += 1;
    accepts_with(clean, tmp, name, file, body)
}

/// One named group of canaries, called through [`CANARY_GROUPS`].
type CanaryGroup = (&'static str, fn(&Path, &Path) -> Result<usize, String>);

/// Every canary group `self_test` must run.
///
/// A table rather than one call per line: dropping a line would drop a whole
/// group of canaries and nothing would go red. The length is reported in the
/// success message, so a removed group changes the gate's own output.
const CANARY_GROUPS: [CanaryGroup; 3] = [
    (
        "scan",
        scan_canaries as fn(&Path, &Path) -> Result<usize, String>,
    ),
    ("collision", collision_canaries),
    ("exemption", exemption_canaries),
];

/// How many canaries [`CANARY_GROUPS`] must run in total.
///
/// Hard-coded on purpose. A group that stops testing anything still returns
/// `Ok`, so the only way to notice is to know the number beforehand. Raise it
/// deliberately when a canary is added; a drop is a defect.
const EXPECTED_CANARIES: usize = 65;

pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let clean = tmp.join("clean");
    build_clean_tree(&clean).map_err(|e| format!("cannot build clean tree: {e}"))?;

    // An English tree passes, or every canary below would be meaningless.
    if let Err(msg) = run(&clean) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: an English tree was rejected: {msg}"));
    }

    let mut ran = 0usize;
    for (name, group) in CANARY_GROUPS {
        match group(&clean, &tmp) {
            Ok(count) => ran += count,
            Err(msg) => {
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("{name} canaries: {msg}"));
            }
        }
    }
    if ran != EXPECTED_CANARIES {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "canary: {ran} canaries ran, {EXPECTED_CANARIES} were expected - \
             a canary group stopped testing anything"
        ));
    }

    // English words that a careless vocabulary would catch must pass, or the
    // gate gets switched off in a week.
    if !accepts_with(
        &clean,
        &tmp,
        "english",
        "PROSE.md",
        "The test ran once. Var, son, kok, dal and bos are not flagged.\n\
         It is read once per epoch and the root is on the main branch.\n",
    )? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: ordinary English prose was reported as Turkish",
        ));
    }

    baseline_canaries(&clean, &tmp)?;

    // The vacuity floor must fire, or an empty checkout would pass.
    let empty = tmp.join("empty");
    fs::create_dir_all(&empty).map_err(|e| format!("cannot create empty tree: {e}"))?;
    fs::write(empty.join("only.txt"), "nothing\n")
        .map_err(|e| format!("cannot write vacuity fixture: {e}"))?;
    if run(&empty).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a near-empty tree passed, so the gate can be vacuous",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "tree-is-english canary OK, {ran} canaries in {} groups (English PASSes, every Turkish \
         character FAILs, diacritic-free Turkish FAILs, README.tr.md and \"Türkçe\" PASS, \
         baseline exempts, going over the count FAILs, a stale count FAILs, empty tree FAILs).",
        CANARY_GROUPS.len()
    ))
}
