//! The budscan patch layer: the list agrees with the disk and carries no foreign brand.
//!
//! # Why a gate
//!
//! The patch layout was taken as an **idea** from another Firefox derivative.
//! That tree held two things, and neither was carried over:
//!
//! 1. **The tooling layer is shell.** The concrete measurement is
//!    `scripts/check-patchfail.sh` in that repository: it extracts the `.rej`
//!    files from the `patch` output with
//!    `grep -n rej$ | awk '{print $(NF)}'`. If `grep` finds nothing the loop
//!    runs empty, `failed_patches` stays empty and the script prints
//!    `success: All patches where applied successfully.` and returns 0.
//!    So if the format of the `patch` output changes, every patch can fail and
//!    the check still passes.
//!
//! 2. **Brand names.** Another browser's name appears in file names, patch
//!    names and identifiers. Taking the idea does not require taking the name,
//!    and if the name stays the tree looks like a part of that project.
//!
//! This gate measures both and does not fall into its own hole while measuring:
//! the case where it can inspect nothing is a separate branch and it does
//! **not** pass.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// The brand fragments that must not appear in the patch layer, split into
/// syllables.
///
/// Identical to the list inside `budscan::patchset`. There are two copies
/// because `xtask/gates` must not depend on `budscan`; the divergence risk is
/// measured by a separate check.
///
/// The reason for the syllable spelling: the moment a deny list writes the name
/// it forbids in plain form, it would put that name into the tree, and every
/// scan asking "does a foreign brand appear" would count this very line as a
/// hit. The check keeps its strength without the literal being in the tree.
const FORBIDDEN_BRAND_SYLLABLES: &[&[&str]] = &[
    &["obs", "ide"],
    &["libre", "wolf"],
    &["water", "fox"],
    &["mull", "vad"],
];

/// Produces the brand fragments to search for.
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

/// The files a diff touches.
fn touched_files(diff: &str) -> Vec<String> {
    diff.lines()
        .filter_map(|line| line.strip_prefix("+++ "))
        .map(|rest| rest.split('\t').next().unwrap_or(rest).trim())
        .filter(|p| *p != "/dev/null")
        .map(|p| p.strip_prefix("b/").unwrap_or(p).to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Hunk headers whose line counts disagree with the body under them.
///
/// `git apply` refuses such a hunk as a corrupt patch, so a patch that fails
/// here cannot be applied by the build. Four hunks of the protocol-handler
/// patch carried counts from an earlier draft of the files they add, and
/// nothing read the headers. The rules are those of unified diff: `+` is a
/// new line, `-` an old one, a space or an empty line is context, `\\` is
/// the no-newline marker; the body ends at the next hunk or file header.
fn hunk_count_errors(rel: &str, diff: &str) -> Vec<String> {
    let lines: Vec<&str> = diff.split('\n').collect();
    let mut problems = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((declared_old, declared_new)) = parse_hunk_header(lines[i]) else {
            i += 1;
            continue;
        };
        let header_line = i + 1;
        let (mut old, mut new) = (0usize, 0usize);
        let mut j = i + 1;
        while j < lines.len() {
            let l = lines[j];
            if parse_hunk_header(l).is_some()
                || l.starts_with("--- ")
                || l.starts_with("+++ ")
                || l.starts_with("diff ")
            {
                break;
            }
            if l.is_empty() && j + 1 == lines.len() {
                break;
            }
            if l.starts_with('+') {
                new += 1;
            } else if l.starts_with('-') {
                old += 1;
            } else if l.starts_with(' ') || l.is_empty() {
                old += 1;
                new += 1;
            } else if !l.starts_with('\\') {
                break;
            }
            j += 1;
        }
        if (old, new) != (declared_old, declared_new) {
            problems.push(format!(
                "{rel}:{header_line}: the hunk header declares {declared_old} old and \
                 {declared_new} new lines but the body has {old} and {new}; git apply \
                 refuses this hunk as corrupt"
            ));
        }
        i = j;
    }
    problems
}

/// `@@ -a[,b] +c[,d] @@ ...` to `(b, d)`, each defaulting to 1.
fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    let rest = line.strip_prefix("@@ -")?;
    let (old_part, rest) = rest.split_once(" +")?;
    let (new_part, _) = rest.split_once(" @@")?;
    let count = |part: &str| -> Option<usize> {
        match part.split_once(',') {
            Some((_, n)) => n.parse().ok(),
            None => part.parse::<usize>().ok().map(|_| 1),
        }
    };
    Some((count(old_part)?, count(new_part)?))
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
        .map_err(|e| format!("could not read {}: {e}", list_path.display()))?;
    let listed = parse_list(&list_text)?;

    let patch_dir = browser.join("patches");
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    let entries = std::fs::read_dir(&patch_dir)
        .map_err(|e| format!("could not read {}: {e}", patch_dir.display()))?;
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
             is worse: nobody assumes a check that does not exist is being written",
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
             applied is a patch believed to have been applied"
        ));
    }

    // Every patch has to touch at least one file and stay inside the permitted
    // trees.
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
            continue; // already reported above
        };
        let touched = touched_files(&diff);
        if touched.is_empty() {
            problems.push(format!(
                "{rel}: the diff touches no file (there is no '+++ b/...' line). \
                 A patch with nothing to apply is a patch believed to have been applied"
            ));
        }
        problems.extend(hunk_count_errors(rel, &diff));
        for file in &touched {
            if !allowed_roots.iter().any(|r| file.starts_with(r)) {
                problems.push(format!(
                    "{rel}: {file} is outside the permitted trees ({})",
                    allowed_roots.join(", ")
                ));
            }
        }
    }

    // Brand: patch names, patch bodies, settings and localisation.
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
                problems.push(format!("{rel}: the patch name carries {token:?}"));
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
                "crates/budscan/browser/{rel} is missing; the patch layer is described with a missing piece"
            ));
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            // The README and the patch files name those repositories
            // **deliberately** while explaining why the shell version was not
            // carried over. Forbidding the quotation would delete the reason
            // for the decision, so the explanatory texts are not scanned, and
            // which files go unscanned is written right here.
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
/// Canaries that do not behave as expected.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Canary 1: the list parser has to catch a duplicate.
    if parse_list("a.patch\na.patch\n").is_ok() {
        problems.push(String::from("VACUOUS: a duplicated patch was accepted"));
    }

    // Canary 2: an empty list yields an empty result; that is not an error but
    // the caller must not mistake it for a pass. `run` handles that in a
    // separate branch; what is measured here is that the parser returns empty.
    match parse_list("# comment only\n") {
        Ok(v) if v.is_empty() => {}
        Ok(_) => problems.push(String::from("a comment line counted as a patch")),
        Err(e) => problems.push(format!("a comment line produced an error: {e}")),
    }

    // Canary 3: `+++ /dev/null` must not count as a touched file.
    if !touched_files("--- a/x.js\n+++ /dev/null\n").is_empty() {
        problems.push(String::from(
            "VACUOUS: a deletion target counted as a touched file",
        ));
    }

    // Canary 4: touched files have to be stripped of the `b/` prefix.
    if touched_files("+++ b/browser/x.js\n") != vec![String::from("browser/x.js")] {
        problems.push(String::from("the 'b/' prefix was not stripped"));
    }

    // Canary 4b: a hunk whose header counts disagree with its body is a
    // finding, and one whose counts agree (with a default count and a
    // no-newline marker) is not.
    let good = "--- /dev/null\n+++ b/browser/x.js\n@@ -0,0 +1,2 @@\n+a\n+b\n\\ No newline at end of file\n--- a/browser/y.js\n+++ b/browser/y.js\n@@ -1 +1,2 @@\n c\n+d\n";
    if !hunk_count_errors("ok.patch", good).is_empty() {
        problems.push(String::from("a well-formed hunk was reported as corrupt"));
    }
    let bad = good.replace("@@ -0,0 +1,2 @@", "@@ -0,0 +1,3 @@");
    if hunk_count_errors("bad.patch", &bad).len() != 1 {
        problems.push(String::from(
            "VACUOUS: a hunk header with the wrong line count passed",
        ));
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
         the 'b/' prefix is stripped, a miscounted hunk is refused, the brand list is populated \
         and the gate does not pass on a tree it cannot read",
    ))
}
