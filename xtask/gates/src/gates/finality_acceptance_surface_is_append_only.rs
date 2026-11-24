//! The finality acceptance surface may only grow at its end.
//!
//! # Why this gate exists
//!
//! "Consensus of consensuses" is a claim about one certificate holding many
//! families' finality at once. Two tables carry that claim, and both are
//! order-sensitive in a way the compiler cannot see:
//!
//! * `ExternalVerifierFamily` is `#[repr(u8)]`. Its discriminants are the
//!   family identity that `AdapterDescriptor::consensus_kind` resolves to, and
//!   `FinalityProofShape::from_external_attestation` reads that identity to
//!   decide which commitment fields a proof binds. Insert a variant in the
//!   middle, or leave one without an explicit discriminant, and every stored
//!   registration that names a family by number is reinterpreted silently.
//! * `AdapterSpec` is persisted in consensus state through `bincode`. Its
//!   variants are therefore a wire format. The enum's own documentation says
//!   "APPENDED LAST" on every variant; nothing measured that.
//!
//! The identity is also written twice, as a string table in each direction:
//! `from_consensus_kind` maps a canonical kind string to a family, and
//! `consensus_kind` maps the family back. Those two are the seam the common
//! proof model resolves through. If they drift - a kind string edited on one
//! side, a family added to only one of them, two families sharing a kind - then
//! a proof's shape is derived from the wrong family, and composition is
//! unsound while every test still passes, because each table is individually
//! exhaustive and the compiler checks only that.
//!
//! So this gate measures four things and refuses the tree when any fails:
//!
//! 1. every `ExternalVerifierFamily` variant carries an explicit discriminant,
//!    and the discriminants are exactly `0..n` in declaration order;
//! 2. the `AdapterSpec` variant order equals a committed, ordered baseline,
//!    so adding a family is an edit a reviewer sees rather than a renumbering
//!    nobody notices;
//! 3. `from_consensus_kind` is total over the variants and injective on its
//!    kind strings;
//! 4. `consensus_kind` is the exact inverse of `from_consensus_kind`.
//!
//! # Why the baseline is ordered and exact
//!
//! A ratchet that only counts would let a variant be deleted and another added
//! in the same change, keeping the number while moving every discriminant after
//! the deletion. The baseline is therefore the ordered list itself, and it must
//! match exactly. Appending a family is allowed - that is the growth this tree
//! wants - and it costs one deliberate line in
//! `.github/adapter-spec-variant-baseline.txt`.
//!
//! # What this gate does not do
//!
//! It does not check that an adapter *verifies* correctly, and it does not
//! check that a family is *reachable* from a block path; `capability-wiring`
//! and `unwired-code-is-ratcheted` own those questions. It pins identity and
//! order, which is the part that must not move silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Where the family identity table lives.
const FAMILY_MODEL: &str = "src/domain/finality_proof_model.rs";

/// Where the persisted acceptance surface lives.
const INTAKE: &str = "src/cross_domain/external/intake.rs";

/// The committed, ordered pin of `AdapterSpec` variants.
const BASELINE: &str = ".github/adapter-spec-variant-baseline.txt";

/// Below this the family table is not a table and the measurement is vacuous.
const MIN_FAMILIES: usize = 8;

/// The enum whose discriminants are the family identity.
const FAMILY_ENUM: &str = "ExternalVerifierFamily";

/// The enum whose variant order is a wire format.
const SPEC_ENUM: &str = "AdapterSpec";

/// Largest source file this gate will read. A file past this is not source.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    let meta = fs::metadata(&path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{} is {} bytes, past this gate's {} byte limit",
            path.display(),
            meta.len(),
            MAX_FILE_BYTES
        ));
    }
    fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Blank out comments, preserving byte offsets and newlines.
///
/// Doc comments on these enums are full of angle brackets, commas and the word
/// `Option`, all of which look like syntax to a text scanner. Offsets are kept
/// so a finding still names the line a reader will open.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// The text between the braces of `enum <name>` (or of a block opened by
/// `sig`), or a finding when it cannot be located.
///
/// A missing enum is a finding rather than an empty slice: a gate that scans
/// nothing and reports OK is worse than no gate.
fn block_after<'a>(src: &'a str, needle: &str) -> Result<&'a str, String> {
    let start = src.find(needle).ok_or_else(|| {
        format!("`{needle}` was not found; the surface this gate measures has moved")
    })?;
    let open = src[start..]
        .find('{')
        .ok_or_else(|| format!("`{needle}` has no opening brace"))?
        + start;
    let mut depth = 0usize;
    for (off, c) in src[open..].char_indices() {
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Ok(&src[open + 1..open + off]);
            }
        }
    }
    Err(format!("`{needle}` braces never balance"))
}

/// Split an enum body on the commas that separate variants.
///
/// Commas inside a variant's field list are not separators, so braces are
/// counted; a split that ignored them would read `network: String,` as the
/// start of a variant named `network`.
fn split_variants(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for c in body.chars() {
        match c {
            '{' | '(' => {
                depth += 1;
                current.push(c);
            }
            '}' | ')' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The first identifier in a variant declaration, which is the variant's name.
fn first_ident(seg: &str) -> Option<&str> {
    let trimmed = seg.trim_start();
    let end = trimmed
        .char_indices()
        .find(|(_, c)| !ident_char(*c))
        .map_or(trimmed.len(), |(i, _)| i);
    if end == 0 {
        None
    } else {
        Some(&trimmed[..end])
    }
}

/// The literal after `=` in a variant declaration, as text.
///
/// Returned as text rather than a number so a discriminant written `0x0` or
/// `1_0` is not silently accepted as the decimal it happens to equal.
fn discriminant_text(seg: &str) -> Option<&str> {
    let after = seg.split_once('=')?.1.trim_start();
    let end = after
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map_or(after.len(), |(i, _)| i);
    if end == 0 {
        None
    } else {
        Some(&after[..end])
    }
}

/// Ordered variant names of an enum body, refusing a body it cannot read.
fn variant_names(body: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for seg in split_variants(body) {
        let name = first_ident(&seg).ok_or_else(|| {
            format!(
                "a variant of the acceptance surface has no name: `{}`",
                truncate(seg.as_str())
            )
        })?;
        names.push(name.to_string());
    }
    Ok(names)
}

/// The arms of `match kind { "<kind>" => Some(Self::Family) }`.
fn kind_arms(block: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in block.lines() {
        let Some(rest) = line.trim().strip_prefix('"') else {
            continue;
        };
        let Some(close) = rest.find('"') else {
            continue;
        };
        let kind = &rest[..close];
        let Some(at) = rest[close..].find("Some(Self::") else {
            continue;
        };
        let tail = &rest[close + at + "Some(Self::".len()..];
        let Some(stop) = tail.find(')') else {
            continue;
        };
        map.insert(kind.to_string(), tail[..stop].to_string());
    }
    map
}

/// The arms of `match self { Self::Family => "<kind>" }`.
fn variant_arms(block: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in block.lines() {
        let Some(rest) = line.trim().strip_prefix("Self::") else {
            continue;
        };
        let Some(arrow) = rest.find(" => ") else {
            continue;
        };
        let variant = &rest[..arrow];
        let Some(open) = rest[arrow..].find('"') else {
            continue;
        };
        let tail = &rest[arrow + open + 1..];
        let Some(stop) = tail.find('"') else {
            continue;
        };
        map.insert(variant.to_string(), tail[..stop].to_string());
    }
    map
}

fn truncate(s: &str) -> String {
    s.chars().take(60).collect()
}

fn missing_and_extra(
    label: &str,
    measured: &BTreeSet<&String>,
    expected: &BTreeSet<&String>,
) -> Option<String> {
    let missing: Vec<&String> = expected.difference(measured).copied().collect();
    let extra: Vec<&String> = measured.difference(expected).copied().collect();
    if missing.is_empty() && extra.is_empty() {
        return None;
    }
    let mut msg = format!("{label}:");
    if !missing.is_empty() {
        let list: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        let _ = write!(msg, " missing [{}]", list.join(", "));
    }
    if !extra.is_empty() {
        let list: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
        let _ = write!(msg, " unexpected [{}]", list.join(", "));
    }
    Some(msg)
}

/// The family table must be a bijection with its own kind strings.
fn check_identity(
    variants: &[String],
    kind_to_variant: &BTreeMap<String, String>,
    variant_to_kind: &BTreeMap<String, String>,
) -> Result<(), String> {
    let declared: BTreeSet<&String> = variants.iter().collect();
    let targets: BTreeSet<&String> = kind_to_variant.values().collect();
    if let Some(msg) = missing_and_extra(
        "`from_consensus_kind` does not cover every family",
        &targets,
        &declared,
    ) {
        return Err(format!("{msg}. A family with no kind string cannot be resolved, so its proof shape is derived from nothing."));
    }
    let sources: BTreeSet<&String> = variant_to_kind.keys().collect();
    if let Some(msg) = missing_and_extra(
        "`consensus_kind` does not name every family",
        &sources,
        &declared,
    ) {
        return Err(format!(
            "{msg}. A family missing here has no canonical name to match against."
        ));
    }
    if kind_to_variant.len() != variants.len() {
        return Err(format!(
            "`from_consensus_kind` has {} arms for {} families: two families share a kind string, \
             so one of them is unreachable by name",
            kind_to_variant.len(),
            variants.len()
        ));
    }
    for (kind, variant) in kind_to_variant {
        match variant_to_kind.get(variant) {
            Some(back) if back == kind => {}
            _ => {
                return Err(format!(
                    "`{kind}` resolves to `{variant}`, but `{variant}` names `{}`: the two tables \
                     are not inverse, so a proof's family is ambiguous",
                    variant_to_kind
                        .get(variant)
                        .map_or("nothing", String::as_str)
                ));
            }
        }
    }
    Ok(())
}

fn read_baseline(root: &Path) -> Result<Vec<String>, String> {
    let text = read(root, BASELINE)?;
    let names: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        return Err(format!(
            "{BASELINE} names no variant: an empty baseline pins nothing and would pass any tree"
        ));
    }
    Ok(names)
}

fn check_spec_order(measured: &[String], baseline: &[String]) -> Result<(), String> {
    if measured == baseline {
        return Ok(());
    }
    let mut msg = String::from(
        "`AdapterSpec` variant order no longer matches its baseline. This enum is persisted in \
         consensus state through bincode, so a variant that moves, disappears or is inserted \
         rather than appended reinterprets every stored registration:\n",
    );
    for (idx, (left, right)) in measured.iter().zip(baseline).enumerate() {
        if left != right {
            let _ = writeln!(
                msg,
                "  position {idx}: tree has `{left}`, baseline pins `{right}`"
            );
        }
    }
    if measured.len() != baseline.len() {
        let _ = writeln!(
            msg,
            "  the tree declares {} variants, the baseline pins {}",
            measured.len(),
            baseline.len()
        );
    }
    let _ = writeln!(
        msg,
        "  Append new families at the end and add the same line to {BASELINE} in the same change."
    );
    Err(msg)
}

/// # Errors
///
/// Returns a finding when the family table has a gap, an implicit discriminant
/// or a non-zero base; when the two kind tables are not mutual inverses; when
/// the `AdapterSpec` order differs from its committed baseline; or when a file
/// this gate reads is missing, oversized or unparseable. An unmeasurable tree
/// is a finding, never a pass.
pub fn run(root: &Path) -> Result<String, String> {
    let raw_model = read(root, FAMILY_MODEL)?;
    let raw_intake = read(root, INTAKE)?;
    let model = strip_comments(&raw_model);
    let intake = strip_comments(&raw_intake);

    let family_body = block_after(&model, &format!("enum {FAMILY_ENUM}"))?;
    let segments = split_variants(family_body);
    if segments.len() < MIN_FAMILIES {
        return Err(format!(
            "{FAMILY_MODEL} declares {} families, under the {MIN_FAMILIES} this gate needs to be a \
             measurement rather than a formality",
            segments.len()
        ));
    }
    let mut variants: Vec<String> = Vec::with_capacity(segments.len());
    for (idx, seg) in segments.iter().enumerate() {
        let name = first_ident(seg).ok_or_else(|| {
            format!(
                "{FAMILY_MODEL}: a family variant has no name: `{}`",
                truncate(seg)
            )
        })?;
        let disc = discriminant_text(seg).ok_or_else(|| {
            format!(
                "{FAMILY_MODEL}: `{name}` has no explicit discriminant. A variant that relies on \
                 its position is renumbered by any insertion above it, and `#[repr(u8)]` makes \
                 that renumbering a wire change."
            )
        })?;
        if disc != idx.to_string() {
            return Err(format!(
                "{FAMILY_MODEL}: `{name}` is discriminant {disc} but sits at position {idx}. The \
                 table is `#[repr(u8)]` and must read 0, 1, 2, ... in order; a gap or a repeat \
                 means two families share an identity or one was deleted in place."
            ));
        }
        variants.push(name.to_string());
    }

    let forward = block_after(&model, "fn from_consensus_kind")?;
    let backward = block_after(&model, "fn consensus_kind")?;
    check_identity(&variants, &kind_arms(forward), &variant_arms(backward))?;

    let spec_body = block_after(&intake, &format!("enum {SPEC_ENUM}"))?;
    let measured = variant_names(spec_body)?;
    if measured.is_empty() {
        return Err(format!("{INTAKE}: `{SPEC_ENUM}` declares no variant"));
    }
    let baseline = read_baseline(root)?;
    check_spec_order(&measured, &baseline)?;

    Ok(format!(
        "Finality acceptance surface is append-only: {} families with explicit discriminants \
         0..{}, kind table total and self-inverse, `{SPEC_ENUM}` order matches its {}-entry \
         baseline.",
        variants.len(),
        variants.len() - 1,
        baseline.len()
    ))
}

fn scratch_dir() -> Result<PathBuf, String> {
    crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-finality-surface")
}

/// Eight families, each with an explicit discriminant and a kind string in both
/// directions: the smallest table that is still a measurement.
fn family_fixture(broken: &str) -> String {
    let names = [
        "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel",
    ];
    let mut src = String::from("pub(crate) enum ExternalVerifierFamily {\n");
    for (idx, name) in names.iter().enumerate() {
        let disc = if *name == "Echo" && broken == "gap" {
            9
        } else if *name == "Alpha" && broken == "base" {
            1
        } else {
            idx
        };
        if *name == "Golf" && broken == "implicit" {
            let _ = writeln!(src, "    {name},");
        } else {
            let _ = writeln!(src, "    {name} = {disc},");
        }
    }
    src.push_str("}\n\nimpl ExternalVerifierFamily {\n    pub(crate) fn from_consensus_kind(kind: &str) -> Option<Self> {\n        match kind {\n");
    for name in names {
        let kind = format!("kind-{}", name.to_lowercase());
        let kind = if name == "Delta" && broken == "drift" {
            "kind-delta-renamed".to_string()
        } else {
            kind
        };
        let kind = if name == "Echo" && broken == "duplicate" {
            "kind-delta".to_string()
        } else {
            kind
        };
        let _ = writeln!(src, "            \"{kind}\" => Some(Self::{name}),");
    }
    src.push_str("            _ => None,\n        }\n    }\n\n    pub(crate) const fn consensus_kind(self) -> &'static str {\n        match self {\n");
    for name in names {
        let _ = writeln!(
            src,
            "            Self::{name} => \"kind-{}\",",
            name.to_lowercase()
        );
    }
    src.push_str("        }\n    }\n}\n");
    src
}

/// Two `AdapterSpec` variants, or three when the fixture needs an append.
fn spec_fixture(appended: bool) -> String {
    let mut src = String::from(
        "pub enum AdapterSpec {\n    /// A spec whose doc comment carries commas, <angle brackets> and the\n    /// word Option, none of which is a variant.\n    First {\n        network: String,\n        committee: Option<PinnedCommittee>,\n    },\n    Second {\n        network: String,\n    },\n",
    );
    if appended {
        src.push_str("    Third {\n        network: String,\n    },\n");
    }
    src.push_str("}\n");
    src
}

fn write_tree(dir: &Path, family: &str, spec: &str, baseline: &str) -> Result<(), String> {
    let model = dir.join(FAMILY_MODEL);
    let intake = dir.join(INTAKE);
    let base = dir.join(BASELINE);
    for parent in [model.parent(), intake.parent(), base.parent()]
        .into_iter()
        .flatten()
    {
        fs::create_dir_all(parent).map_err(|e| format!("cannot create fixture dir: {e}"))?;
    }
    fs::write(&model, family).map_err(|e| format!("cannot write family fixture: {e}"))?;
    fs::write(&intake, spec).map_err(|e| format!("cannot write spec fixture: {e}"))?;
    fs::write(&base, baseline).map_err(|e| format!("cannot write baseline fixture: {e}"))?;
    Ok(())
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries are the four failure
/// modes this gate exists for plus the legitimate growth path: a clean tree
/// passes, a gap and a non-zero base are caught, an implicit discriminant is
/// caught, a drifted or duplicated kind string is caught, a deleted or
/// reordered `AdapterSpec` variant is caught, and an appended variant with a
/// matching baseline passes.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let clean = tmp.join("clean");
    write_tree(
        &clean,
        &family_fixture("clean"),
        &spec_fixture(false),
        "# AdapterSpec variant order, append-only.\nFirst\nSecond\n",
    )?;
    if let Err(msg) = run(&clean) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: a clean tree was rejected: {msg}"));
    }

    for broken in ["gap", "base", "implicit", "drift", "duplicate"] {
        let dir = tmp.join(broken);
        write_tree(
            &dir,
            &family_fixture(broken),
            &spec_fixture(false),
            "First\nSecond\n",
        )?;
        if run(&dir).is_ok() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "canary: a family table broken by `{broken}` passed"
            ));
        }
    }

    let deleted = tmp.join("deleted");
    write_tree(
        &deleted,
        &family_fixture("clean"),
        &spec_fixture(false),
        "First\nSecond\nThird\n",
    )?;
    if run(&deleted).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(
            "canary: a baseline pinning a variant the tree no longer declares passed".into(),
        );
    }

    let reordered = tmp.join("reordered");
    write_tree(
        &reordered,
        &family_fixture("clean"),
        &spec_fixture(false),
        "Second\nFirst\n",
    )?;
    if run(&reordered).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("canary: a reordered `AdapterSpec` passed its own baseline".into());
    }

    let grown = tmp.join("grown");
    write_tree(
        &grown,
        &family_fixture("clean"),
        &spec_fixture(true),
        "First\nSecond\nThird\n",
    )?;
    if let Err(msg) = run(&grown) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "canary: an appended family with a matching baseline was rejected: {msg}"
        ));
    }

    let empty = tmp.join("empty");
    write_tree(
        &empty,
        "pub(crate) enum ExternalVerifierFamily {\n    Only = 0,\n}\n",
        &spec_fixture(false),
        "First\nSecond\n",
    )?;
    if run(&empty).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("canary: a one-family table passed; the vacuity floor is not working".into());
    }

    let missing = tmp.join("missing");
    fs::create_dir_all(&missing).map_err(|e| format!("cannot create empty tree: {e}"))?;
    if run(&missing).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("canary: a tree with no family table passed".into());
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Self-test OK: clean tree passes; gap, non-zero base, implicit discriminant, drifted kind, \
         duplicate kind, deleted variant, reordered variant and the vacuity floor are each caught; \
         an appended family with a matching baseline passes.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, family: &str, spec: &str, baseline: &str) -> PathBuf {
        let dir = scratch_dir().expect("scratch dir");
        let root = dir.join(name);
        write_tree(&root, family, spec, baseline).expect("fixture tree");
        root
    }

    #[test]
    fn clean_tree_passes_and_reports_counts() {
        let root = tree(
            "clean",
            &family_fixture("clean"),
            &spec_fixture(false),
            "First\nSecond\n",
        );
        let msg = run(&root).expect("clean tree must pass");
        assert!(msg.contains("8 families"), "{msg}");
        assert!(msg.contains("2-entry"), "{msg}");
        let _ = fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn every_break_is_a_finding() {
        for broken in ["gap", "base", "implicit", "drift", "duplicate"] {
            let root = tree(
                broken,
                &family_fixture(broken),
                &spec_fixture(false),
                "First\nSecond\n",
            );
            assert!(run(&root).is_err(), "{broken} passed");
            let _ = fs::remove_dir_all(root.parent().expect("parent"));
        }
    }

    #[test]
    fn a_variant_may_be_appended_but_not_moved() {
        let grown = tree(
            "grown",
            &family_fixture("clean"),
            &spec_fixture(true),
            "First\nSecond\nThird\n",
        );
        assert!(
            run(&grown).is_ok(),
            "an append with a matching baseline must pass"
        );
        let _ = fs::remove_dir_all(grown.parent().expect("parent"));

        let moved = tree(
            "moved",
            &family_fixture("clean"),
            &spec_fixture(true),
            "First\nThird\nSecond\n",
        );
        assert!(run(&moved).is_err(), "a moved variant must fail");
        let _ = fs::remove_dir_all(moved.parent().expect("parent"));
    }

    #[test]
    fn comments_do_not_read_as_variants() {
        let spec = spec_fixture(false);
        let body = block_after(&spec, "enum AdapterSpec").expect("body");
        let names = variant_names(body).expect("names");
        assert_eq!(names, vec!["First", "Second"]);
        assert_eq!(discriminant_text("Alpha = 0,"), Some("0"));
        assert_eq!(discriminant_text("Alpha,"), None);
        assert_eq!(first_ident("  Braced { a: u8 }"), Some("Braced"));
    }

    #[test]
    fn the_two_kind_tables_must_be_inverse() {
        let variants: Vec<String> = ["A", "B"].iter().map(|s| (*s).to_string()).collect();
        let mut forward = BTreeMap::new();
        forward.insert("ka".to_string(), "A".to_string());
        forward.insert("kb".to_string(), "B".to_string());
        let mut backward = BTreeMap::new();
        backward.insert("A".to_string(), "ka".to_string());
        backward.insert("B".to_string(), "kb".to_string());
        assert!(check_identity(&variants, &forward, &backward).is_ok());

        backward.insert("B".to_string(), "kc".to_string());
        let err = check_identity(&variants, &forward, &backward).expect_err("drift must fail");
        assert!(err.contains("not inverse"), "{err}");
    }
}
