//! FSF/FSD research is a clean-room input, not a source import.
//!
//! `docs/FSF_PROJECT_FIT.md` maps Free Software Foundation high-priority
//! projects to Budlum modules. That map is useful only if it cannot silently
//! become a licence bypass: several of the interesting projects are GPL/AGPL or
//! have mixed/unknown licensing, while this tree is `PolyForm` Shield. The rule is
//! therefore simple: Budlum may learn protocols, threat models and interface
//! shapes, but product code must be Budlum-native unless a later legal and
//! provenance decision creates an explicit boundary.
//!
//! # What this gate checks
//!
//! 1. The phase-0 docs still say they are clean-room curation, not a completed
//!    port or permission to copy upstream source.
//! 2. Controlled FSF project names that are design-only / review-first do not
//!    appear in product code or vendored-looking paths. They may appear in the
//!    FSF curation docs, attribution/provenance files and this gate.
//! 3. A directory that looks like an imported source bundle cannot carry a
//!    GPL/AGPL/LGPL/MPL/copyleft licence marker without an explicit
//!    `BUDLUM_IMPORT_BOUNDARY.md` note beside it or above it.
//!
//! The check is deliberately conservative. It does not ban future
//! implementations; it requires them to be written as Budlum modules, with the
//! outside project named in the design/provenance record rather than smuggled in
//! as a source tree.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const FIT_DOC: &str = "docs/FSF_PROJECT_FIT.md";
const PLAN_DOC: &str = "docs/FSF_ADAPTATION_PLAN.md";
const CURATION_TOOL: &str = "tools/fsf_project_fit.py";
const SELF_PATH: &str = "xtask/gates/src/gates/fsf_import_boundaries.rs";
const BOUNDARY_NOTE: &str = "BUDLUM_IMPORT_BOUNDARY.md";
const VACUITY_FLOOR: usize = 100;
const MAX_REPORTED: usize = 24;

#[derive(Clone, Copy)]
enum Boundary {
    DesignOnly,
    ReviewFirst,
    /// Renamed from `BoundaryOnly`: the variant repeated its own enum name,
    /// which clippy's `enum_variant_names` refuses. The user-visible label is
    /// unchanged.
    InterfaceOnly,
}

impl Boundary {
    const fn label(self) -> &'static str {
        match self {
            Self::DesignOnly => "design-only",
            Self::ReviewFirst => "review-first",
            Self::InterfaceOnly => "boundary-only",
        }
    }
}

struct ControlledProject {
    name: &'static str,
    terms: &'static [&'static str],
    boundary: Boundary,
    reason: &'static str,
}

const CONTROLLED: &[ControlledProject] = &[
    ControlledProject {
        name: "GNU Taler",
        terms: &["gnu taler", "taler"],
        boundary: Boundary::DesignOnly,
        reason: "FSF entry is AGPL/GPL/LGPL mixed; use receipt/accountability ideas only",
    },
    ControlledProject {
        name: "GNUnet",
        terms: &["gnunet", "gnu net"],
        boundary: Boundary::ReviewFirst,
        reason: "network architecture reference with licence/provenance still requiring review",
    },
    ControlledProject {
        name: "GnuPG / Libgcrypt / GnuTLS",
        terms: &["gnupg", "libgcrypt", "gnutls", "gnu privacy guard"],
        boundary: Boundary::ReviewFirst,
        reason: "crypto/key-management references stay as test-vector/protocol knowledge, not vendored code",
    },
    ControlledProject {
        name: "FOSSology / GNU Licenseutils",
        terms: &["fossology", "licenseutils", "gnu licenseutils"],
        boundary: Boundary::InterfaceOnly,
        reason: "compliance tooling inspiration is process/gate-level unless a boundary is documented",
    },
    ControlledProject {
        name: "Monero Core",
        terms: &["monero"],
        boundary: Boundary::ReviewFirst,
        reason: "privacy-crypto research needs a BPQS-like review bar before code exists here",
    },
    ControlledProject {
        name: "Ricochet",
        terms: &["ricochet"],
        boundary: Boundary::ReviewFirst,
        reason: "anonymity-network UX/proxy ideas stay design-only until a network privacy seam is specified",
    },
];

const COPYLEFT_MARKERS: &[&str] = &[
    "gnu general public license",
    "gnu affero general public license",
    "agpl-3.0",
    "agplv3",
    "gpl-3.0",
    "gplv3",
    "gpl-2.0",
    "gplv2",
    "lesser general public license",
    "lgpl-2.1",
    "lgpl-3.0",
    "mozilla public license",
    "mpl-2.0",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".cargo",
    "__pycache__",
    "dist",
    "build",
    "coverage",
];

const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "gz", "tar", "bin", "wasm", "so", "a", "o",
    "lock", "svg", "woff", "woff2", "ttf", "webp",
];

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn skipped_ext(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| SKIP_EXTS.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name.as_ref()) {
                walk_into(&path, out);
            }
        } else if kind.is_file() && !skipped_ext(&path) {
            out.push(path);
        }
    }
}

fn sorted_walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out.sort();
    out
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn contains_term(haystack_lower: &str, term_lower: &str) -> bool {
    let bytes = haystack_lower.as_bytes();
    let term = term_lower.as_bytes();
    let mut from = 0usize;
    while let Some(pos) = haystack_lower[from..].find(term_lower) {
        let at = from + pos;
        let end = at + term.len();
        let before_ok = at == 0 || !is_word_byte(bytes[at - 1]);
        let after_ok = end >= bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = at + term.len();
    }
    false
}

fn is_allowed_reference(rel: &str) -> bool {
    rel == FIT_DOC
        || rel == PLAN_DOC
        || rel == CURATION_TOOL
        || rel == SELF_PATH
        || rel == "docs/NOTICE"
        || rel == "docs/NOTICE.md"
        || rel == "docs/PROVENANCE_NOTES.md"
        || rel == "LICENSE.md"
        || rel.ends_with(&format!("/{BOUNDARY_NOTE}"))
        || (rel.starts_with("docs/FSF_")
            && std::path::Path::new(rel)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md")))
}

fn is_import_surface(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.starts_with("vendor/")
        || lower.starts_with("third_party/")
        || lower.starts_with("third-party/")
        || lower.starts_with("external/")
        || lower.starts_with("upstream/")
        || lower.contains("/vendor/")
        || lower.contains("/third_party/")
        || lower.contains("/third-party/")
        || lower.contains("/external/")
        || lower.contains("/upstream/")
}

fn has_boundary_note(root: &Path, file: &Path) -> bool {
    let mut dir = file.parent();
    while let Some(d) = dir {
        if d.join(BOUNDARY_NOTE).is_file() {
            return true;
        }
        if d == root {
            break;
        }
        dir = d.parent();
    }
    false
}

fn controlled_hits(rel: &str, text: &str) -> Vec<String> {
    if is_allowed_reference(rel) {
        return Vec::new();
    }
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();
    for project in CONTROLLED {
        if project
            .terms
            .iter()
            .any(|term| contains_term(&lower, &term.to_ascii_lowercase()))
        {
            hits.push(format!(
                "{rel}: names {} ({}) outside the clean-room/provenance boundary: {}",
                project.name,
                project.boundary.label(),
                project.reason
            ));
        }
    }
    hits
}

fn path_hits(rel: &str) -> Vec<String> {
    if is_allowed_reference(rel) {
        return Vec::new();
    }
    let lower: String = rel
        .to_ascii_lowercase()
        .chars()
        .map(|c| if matches!(c, '_' | '-') { ' ' } else { c })
        .collect();
    let mut hits = Vec::new();
    for project in CONTROLLED {
        if project
            .terms
            .iter()
            .any(|term| contains_term(&lower, &term.to_ascii_lowercase()))
        {
            hits.push(format!(
                "{rel}: path names {} ({}) without an import-boundary record",
                project.name,
                project.boundary.label()
            ));
        }
    }
    hits
}

fn copyleft_hits(root: &Path, path: &Path, rel: &str, text: &str) -> Vec<String> {
    if !is_import_surface(rel) || has_boundary_note(root, path) {
        return Vec::new();
    }
    let lower = text.to_ascii_lowercase();
    COPYLEFT_MARKERS
        .iter()
        .filter(|marker| lower.contains(*marker))
        .map(|marker| {
            format!(
                "{rel}: imported-looking source contains `{}` but no {BOUNDARY_NOTE} records the boundary",
                *marker
            )
        })
        .collect()
}

fn check_fit_doc(text: &str) -> Vec<String> {
    let required = [
        "phase 0",
        "not a completed implementation",
        "does **not** copy upstream project code",
        "design-only",
        "docs/FSF_ADAPTATION_PLAN.md",
    ];
    required
        .iter()
        .filter(|needle| !text.contains(**needle))
        .map(|needle| format!("{FIT_DOC}: missing clean-room phrase `{needle}`"))
        .collect()
}

fn check_plan_doc(text: &str) -> Vec<String> {
    let required = [
        "No GPL/AGPL source enters",
        "Phase 1",
        "Phase 2",
        "import-boundary gate",
        "No FSF upstream code has been imported",
    ];
    required
        .iter()
        .filter(|needle| !text.contains(**needle))
        .map(|needle| format!("{PLAN_DOC}: missing phased-adaptation phrase `{needle}`"))
        .collect()
}

fn read_required(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {rel}: {e}"))
}

/// # Errors
///
/// Returns every clean-room boundary violation found in the tree.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    problems.extend(check_fit_doc(&read_required(root, FIT_DOC)?));
    problems.extend(check_plan_doc(&read_required(root, PLAN_DOC)?));

    let mut scanned = 0usize;
    for path in sorted_walk(root) {
        let rel = rel_path(root, &path);
        problems.extend(path_hits(&rel));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        problems.extend(controlled_hits(&rel, &text));
        problems.extend(copyleft_hits(root, &path, &rel, &text));
    }

    if scanned < VACUITY_FLOOR {
        problems.push(format!(
            "only {scanned} files were scanned, below the floor of {VACUITY_FLOOR}; the gate is vacuous"
        ));
    }

    if problems.is_empty() {
        return Ok(format!(
            "FSF clean-room boundaries held: {scanned} text files scanned, {} controlled project families guarded",
            CONTROLLED.len()
        ));
    }

    let mut msg = format!("{} FSF clean-room boundary problem(s):\n", problems.len());
    for problem in problems.iter().take(MAX_REPORTED) {
        let _ = writeln!(msg, "  - {problem}");
    }
    if problems.len() > MAX_REPORTED {
        let _ = writeln!(msg, "  ... and {} more", problems.len() - MAX_REPORTED);
    }
    msg.push_str(
        "Budlum may learn from FSF-listed projects, but source imports require an explicit boundary record.\n",
    );
    Err(msg)
}

/// # Errors
///
/// Returns the first canary whose boundary expectation is wrong.
pub fn self_test() -> Result<String, String> {
    if !controlled_hits("src/settlement/taler.rs", "pub struct Receipt;").is_empty() {
        return Err(String::from(
            "canary 1: allowed path test used a bad expectation",
        ));
    }
    if path_hits("src/settlement/taler.rs").is_empty() {
        return Err(String::from(
            "canary 2: a product path named after GNU Taler was not caught",
        ));
    }
    if controlled_hits("src/settlement/receipt.rs", "// GNU Taler receipt model").is_empty() {
        return Err(String::from(
            "canary 3: product code naming a design-only project was not caught",
        ));
    }
    if !controlled_hits(FIT_DOC, "GNU Taler is design-only").is_empty() {
        return Err(String::from("canary 4: the FSF fit doc was not exempt"));
    }
    if !controlled_hits("docs/FSF_TALER_BRIEF.md", "GNU Taler design brief").is_empty() {
        return Err(String::from(
            "canary 5: FSF design briefs must be allowed to name their source",
        ));
    }
    if controlled_hits("docs/ARCHITECTURE.md", "GNUnet routing was copied").is_empty() {
        return Err(String::from(
            "canary 6: ordinary docs cannot become an import boundary",
        ));
    }
    if !is_import_surface("vendor/taler/COPYING") {
        return Err(String::from(
            "canary 7: vendor/ was not treated as an import surface",
        ));
    }
    if copyleft_hits(
        Path::new("/nonexistent-root"),
        Path::new("/nonexistent-root/vendor/x/COPYING"),
        "vendor/x/COPYING",
        "GNU AFFERO GENERAL PUBLIC LICENSE",
    )
    .is_empty()
    {
        return Err(String::from(
            "canary 8: copyleft import without a boundary note was not caught",
        ));
    }
    if !copyleft_hits(
        Path::new("/nonexistent-root"),
        Path::new("/nonexistent-root/src/lib.rs"),
        "src/lib.rs",
        "GNU GENERAL PUBLIC LICENSE",
    )
    .is_empty()
    {
        return Err(String::from(
            "canary 9: normal source text was treated as a vendored bundle",
        ));
    }
    if !check_fit_doc(
        "phase 0\nnot a completed implementation\ndoes **not** copy upstream project code\ndesign-only\ndocs/FSF_ADAPTATION_PLAN.md",
    )
    .is_empty()
    {
        return Err(String::from("canary 10: complete fit-doc wording failed"));
    }
    if check_plan_doc("Phase 1\nPhase 2\nimport-boundary gate").is_empty() {
        return Err(String::from("canary 11: incomplete adaptation plan passed"));
    }

    Ok(String::from("fsf-import-boundaries: 11 canaries"))
}
