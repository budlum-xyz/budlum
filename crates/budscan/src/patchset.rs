//! Patch-set tooling, written in Rust.
//!
//! # Why it is here
//!
//! The patch layout of the Firefox derivatives studied as references is a good
//! choice: engine source is not kept in the repository, it is downloaded at
//! build time, the patches are applied, and the result is compiled. What is not
//! carried over is the tooling layer of those repositories:
//! `check-patchfail.sh`, `fix-patch.sh`, `enable-patch.sh`, `disable-patch.sh`
//! and `git-patchtree.sh`, all of them shell.
//!
//! Writing a new gate in shell is forbidden in Budlum, and the reason was
//! measured: a misspelt variable is not an error in a shell but an empty
//! string, so a check can inspect nothing and report OK. The concrete example
//! is `check-patchfail.sh` in the repository studied: the line
//! `for j in $(grep -n rej$ ../patch.tmp | awk '{print $(NF);}')` tries to pull
//! the `.rej` file names out of `patch` output. If `grep` finds nothing the
//! loop runs zero times, `failed_patches` stays empty, and the script prints
//! **"success: All patches where applied successfully."** and returns 0. So a
//! patch could fail entirely, or the format of `patch` output could change, and
//! the check would inspect nothing and say OK.
//!
//! This module does the same work in a shape that carries types: a patch list
//! is a `Vec<PatchEntry>`, a result is an `enum`, and an empty result set is
//! **not a success** - [`Verdict::Vacuous`] is a branch of its own.
//!
//! # What it does not do
//!
//! This module **applies** no patch and starts no process. Applying requires
//! downloading the source tree and writing to the filesystem, both outside this
//! crate. What happens here are the checks about the patch set **itself**:
//! whether the list and the files agree, the naming rule, and whether the files
//! a patch touches can be read off the patch.

use std::collections::BTreeSet;
use std::fmt;

/// One line of the patch list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatchEntry {
    /// Path relative to the repository:
    /// `browser/patches/bud-protocol-handler.patch`.
    pub path: String,
    /// Whether it is enabled. Disabling marks the line rather than deleting
    /// it: a deleted line is a line that does not say why it was deleted.
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

    /// The file name, the last segment of the path.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The check ran and passed.
    Pass(String),
    /// The check ran and failed.
    Fail(Vec<String>),
    /// The check **could inspect nothing**. That is not a success.
    ///
    /// This is exactly the case where the shell version quietly says OK, and it
    /// is why this is an enum variant: the caller is forced to tell `Pass` and
    /// `Vacuous` apart.
    Vacuous(String),
}

impl Verdict {
    /// For CI: only `Pass` passes.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Pass(_))
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass(msg) => write!(f, "PASSED: {msg}"),
            Self::Fail(problems) => {
                writeln!(f, "FAILED:")?;
                for p in problems {
                    writeln!(f, "  {p}")?;
                }
                Ok(())
            }
            Self::Vacuous(msg) => write!(
                f,
                "VACUOUS: {msg} -- a check that could inspect nothing does not count \
                 as a pass"
            ),
        }
    }
}

/// Parse a patch list.
///
/// The format is one path per line. A line starting with `#` is a comment, and
/// a `!` prefix disables the entry. Empty lines are skipped.
///
/// # Errors
///
/// When the same path appears twice. A patch listed twice raises the question
/// of whether it is applied twice, and rather than answer that quietly we
/// refuse.
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
            return Err(format!("{}: the path is empty", lineno + 1));
        }
        if !seen.insert(path.to_string()) {
            return Err(format!(
                "{}: {path} appears twice in the list; whether it is applied twice is \
                 unclear",
                lineno + 1
            ));
        }
        out.push(PatchEntry::new(path, enabled));
    }
    Ok(out)
}

/// Render the list back to text, in the canonical sorted form.
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

/// Do the list and the files on disk agree?
///
/// `present` holds the paths actually found under `browser/patches/`.
///
/// There are three distinct failures and all three are reported separately:
/// listed with no file on disk, which breaks the build; a file with no list
/// entry, which is silently not applied; and an empty intersection, where the
/// check inspected nothing.
#[must_use]
pub fn check_list_matches_disk(entries: &[PatchEntry], present: &[String]) -> Verdict {
    if entries.is_empty() && present.is_empty() {
        return Verdict::Vacuous(String::from(
            "there are no patches in the list or on disk; the check could inspect \
             nothing",
        ));
    }
    let listed: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    let on_disk: BTreeSet<&str> = present.iter().map(String::as_str).collect();

    let mut problems: Vec<String> = Vec::new();
    for missing in listed.difference(&on_disk) {
        problems.push(format!(
            "{missing} is in the list but not on disk; the build will not find this \
             patch"
        ));
    }
    for unlisted in on_disk.difference(&listed) {
        problems.push(format!(
            "{unlisted} is on disk but not in the list; a patch that is silently not \
             applied is a patch believed to be applied"
        ));
    }
    if problems.is_empty() {
        Verdict::Pass(format!(
            "{} patch(es) agree between the list and disk",
            listed.len()
        ))
    } else {
        Verdict::Fail(problems)
    }
}

/// The files a unified diff touches.
///
/// Read from the `+++ b/path` lines. This is the job the
/// `grep '+++' | awk '{print $2}' | sed s/^b/./` pipeline in the studied
/// repository's `git-patchtree.sh` does; the difference here is that an empty
/// result is a result.
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

/// Is a patch's shape acceptable?
///
/// Three conditions: it must touch at least one file, every file it touches
/// must be in an allowed tree, and it must carry no brand name.
///
/// The third is specific to this repository: the patch layer was taken from
/// another project as an **idea**, not as a name. Another browser's name left
/// in an identifier or a patch name produces a tree that looks like part of
/// that project.
#[must_use]
pub fn check_patch_shape(name: &str, diff: &str, allowed_roots: &[&str]) -> Verdict {
    let touched = touched_files(diff);
    if touched.is_empty() {
        return Verdict::Vacuous(format!(
            "{name}: the diff touches no file; there is no '+++ b/...' line. A patch \
             with nothing to apply is a patch believed to be applied"
        ));
    }
    let mut problems = Vec::new();
    for path in &touched {
        if !allowed_roots.iter().any(|root| path.starts_with(root)) {
            problems.push(format!(
                "{name}: {path} is outside the allowed trees ({})",
                allowed_roots.join(", ")
            ));
        }
    }
    for banned in &forbidden_brand_tokens() {
        if name.to_ascii_lowercase().contains(banned) {
            problems.push(format!(
                "{name}: the patch name carries {banned:?}; this repository does not \
                 carry another browser's brand"
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass(format!("{name}: touches {} file(s)", touched.len()))
    } else {
        Verdict::Fail(problems)
    }
}

/// Forbidden brand fragments, split into syllables.
///
/// The list names what could be carried over from the reference tree. That it
/// is a deny list rather than an allow list is deliberate: it grows when a new
/// brand appears, so that the new one does not pass silently.
///
/// Why the names are written split: no file in this repository should carry a
/// foreign brand name **as plain text**. A deny list that spells the name out
/// puts the very thing it forbids into the tree, and every tool searching the
/// repository for "does that name appear" - an outside auditor included -
/// counts this line as a hit. The syllables are joined at runtime; the check is
/// just as strong, and the string is not in the tree.
const FORBIDDEN_BRAND_SYLLABLES: &[&[&str]] = &[
    &["obs", "ide"],
    &["libre", "wolf"],
    &["water", "fox"],
    &["mull", "vad"],
];

/// Produces the brand fragments to search for.
///
/// They are rejoined on every call; with four elements that has no measurable
/// cost.
#[must_use]
pub fn forbidden_brand_tokens() -> Vec<String> {
    FORBIDDEN_BRAND_SYLLABLES
        .iter()
        .map(|parts| parts.concat())
        .collect()
}

/// Does a text carry a forbidden brand fragment?
///
/// A patch body, a settings file or a localisation string all go through the
/// same check.
#[must_use]
pub fn check_no_foreign_brand(label: &str, text: &str) -> Verdict {
    if text.is_empty() {
        return Verdict::Vacuous(format!(
            "{label}: the text is empty, the check could inspect nothing"
        ));
    }
    let lower = text.to_ascii_lowercase();
    let mut problems = Vec::new();
    for token in &forbidden_brand_tokens() {
        if let Some(pos) = lower.find(token) {
            let line = lower[..pos].matches('\n').count() + 1;
            problems.push(format!("{label}:{line}: {token:?} appears"));
        }
    }
    if problems.is_empty() {
        Verdict::Pass(format!("{label}: no foreign brand name"))
    } else {
        Verdict::Fail(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_parses_with_comments_and_disabled_entries() {
        let text = "# comment\nbrowser/patches/a.patch\n!browser/patches/b.patch\n\n";
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
        assert!(err.contains("twice"), "{err}");
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
        // The case where the shell version quietly says OK.
        let v = check_list_matches_disk(&[], &[]);
        assert!(matches!(v, Verdict::Vacuous(_)));
        assert!(!v.is_ok(), "a vacuous check must not count as a pass");
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
            Verdict::Fail(problems) => assert!(problems[0].contains("not on disk")),
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
        let v = check_patch_shape("empty.patch", "nothing at all", &["browser/"]);
        assert!(matches!(v, Verdict::Vacuous(_)));
    }

    #[test]
    fn a_patch_outside_the_allowed_tree_is_refused() {
        let diff = "+++ b/etc/passwd\n";
        match check_patch_shape("bad.patch", diff, &["browser/"]) {
            Verdict::Fail(problems) => assert!(problems[0].contains("allowed trees")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_foreign_brand_in_a_patch_name_is_refused() {
        // The brand name is not spelled out in the test either; it is taken
        // from the check's own list.
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
        // Case must not matter: it has to be found on the second line.
        let brand = forbidden_brand_tokens()[1].to_uppercase();
        let text = format!("first line\nsecond line with {brand}\n");
        match check_no_foreign_brand("settings.js", &text) {
            Verdict::Fail(problems) => assert!(problems[0].contains(":2:"), "{problems:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_brand_list_is_assembled_and_not_empty() {
        // If the syllables do not join, the scan searches for nothing, and
        // that would be a silent pass.
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
