//! Every classical cryptographic use in production code is on the list.
//!
//! no object is accepted on a classical signature alone. The
//! only classical components allowed are (a) the Ed25519 half of a composite
//! signature, (b) the BLS12-381 finality peer, (c) X25519 inside a hybrid KEM,
//! (d) proofs of external networks, marked in the profile, and (e) TEE
//! attestation, which is not on a security path.
//!
//! This gate reads production Rust for the classical crates and protocols
//! (`ed25519_dalek`, `schnorrkel`, `bls12_381`, `x25519`, `libp2p::noise`) and
//! turns every use into a site: a file and the function it sits in (an import
//! line is the site `(imports)`). A site needs an entry in
//! `docs/pq/classical_allowlist.toml`: path, function (`*` for a whole file),
//! the PQ companion that pairs it, and the item.
//!
//! # Count mode
//!
//! The tree starts with classical uses that Phases 2 and 3 have not replaced
//! yet, so the gate opens in count mode like its siblings: the allow list
//! carries `unregistered_baseline`, the number of sites with no entry today.
//! A count above it fails (a new classical use with no entry). A count below it
//! also fails, naming the number to write, so the baseline can only fall. The
//! baseline is locked at zero when Phase 3 ends; a non-zero baseline after that
//! is the open work, in plain sight.
//!
//! An entry that no site uses any more is stale and fails: an exemption for a
//! use that is gone would hide the next use that takes its name.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Roots holding shipped code.
const SCAN_ROOTS: &[&str] = &["src", "crates", "budzero", "bud/src"];

/// The allow list.
const ALLOWLIST: &str = "docs/pq/classical_allowlist.toml";

/// The classical crates and protocols this gate watches, as whole tokens.
const CLASSICAL_TOKENS: &[&str] = &[
    "ed25519_dalek",
    "schnorrkel",
    "bls12_381",
    "x25519",
    "x25519_dalek",
    "libp2p::noise",
    "libp2p_noise",
    "noise::Config",
];

/// The five permitted items.
const ALLOWED_CATEGORIES: &[&str] = &["a", "b", "c", "d", "e"];

/// A classical use: a file and the function it sits in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    /// Repository-relative path.
    pub path: String,
    /// The enclosing function, or `(imports)` for a `use` line.
    pub function: String,
}

/// One allow list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Repository-relative path.
    pub path: String,
    /// A function name, or `*` for every site in the file.
    pub function: String,
    /// The post-quantum component that pairs this use.
    pub pq_companion: String,
    /// The item, `a` to `e`.
    pub category: String,
}

impl Entry {
    fn covers(&self, site: &Site) -> bool {
        self.path == site.path && (self.function == "*" || self.function == site.function)
    }
}

/// Read the allow list: `unregistered_baseline = N` and `[[entry]]` tables.
///
/// # Errors
///
/// A line that is not a comment, a table header or `key = value`, an unknown
/// key, an entry missing a field, a item outside `a` to `e`, or a missing
/// baseline.
pub fn parse_allowlist(text: &str) -> Result<(u64, Vec<Entry>), String> {
    let mut baseline: Option<u64> = None;
    let mut entries: Vec<Entry> = Vec::new();
    let mut current: Option<[Option<String>; 4]> = None;
    let finish =
        |slot: Option<[Option<String>; 4]>, entries: &mut Vec<Entry>| -> Result<(), String> {
            let Some([path, function, pq_companion, category]) = slot else {
                return Ok(());
            };
            let entry = Entry {
                path: path.ok_or("an entry has no `path`")?,
                function: function.ok_or("an entry has no `function`")?,
                pq_companion: pq_companion.ok_or("an entry has no `pq_companion`")?,
                category: category.ok_or("an entry has no `category`")?,
            };
            if entry.pq_companion.trim().is_empty() {
                return Err(format!("entry {} has an empty `pq_companion`", entry.path));
            }
            if !ALLOWED_CATEGORIES.contains(&entry.category.as_str()) {
                return Err(format!(
                    "entry {} namesitem `{}`; the items are a to e",
                    entry.path, entry.category
                ));
            }
            entries.push(entry);
            Ok(())
        };
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[entry]]" {
            finish(current.take(), &mut entries)?;
            current = Some([None, None, None, None]);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: not `key = value`: {line}", n + 1));
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "unregistered_baseline" {
            baseline = Some(
                value
                    .parse()
                    .map_err(|_| format!("line {}: the baseline is not a number", n + 1))?,
            );
            continue;
        }
        let text_value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(|| format!("line {}: `{key}` needs a quoted string", n + 1))?
            .to_string();
        let slot = current
            .as_mut()
            .ok_or_else(|| format!("line {}: `{key}` outside an [[entry]]", n + 1))?;
        let index = match key {
            "path" => 0,
            "function" => 1,
            "pq_companion" => 2,
            "category" => 3,
            other => return Err(format!("line {}: unknown key `{other}`", n + 1)),
        };
        if let Some(cell) = slot.get_mut(index) {
            *cell = Some(text_value);
        }
    }
    finish(current.take(), &mut entries)?;
    let baseline = baseline.ok_or("the allow list has no `unregistered_baseline`")?;
    Ok((baseline, entries))
}

/// The line with the inside of every string literal blanked, so a canonical
/// name such as `"hpke-mlkem768-x25519-0x647a"` is not a use of X25519.
fn without_strings(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut inside = false;
    let mut escaped = false;
    for c in code.chars() {
        if inside {
            if c == '"' && !escaped {
                inside = false;
                out.push(c);
            } else {
                escaped = c == '\\' && !escaped;
                out.push(' ');
            }
        } else {
            if c == '"' {
                inside = true;
                escaped = false;
            }
            out.push(c);
        }
    }
    out
}

/// The classical sites of one source text.
#[must_use]
pub fn sites_of(path: &str, text: &str) -> BTreeSet<Site> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let masked = without_strings(super::pq_scan::code_part(line));
        let code = masked.as_str();
        if !CLASSICAL_TOKENS
            .iter()
            .any(|t| super::pq_scan::has_token(code, t))
        {
            continue;
        }
        let function =
            if code.trim_start().starts_with("use ") || code.trim_start().starts_with("pub use ") {
                String::from("(imports)")
            } else {
                super::pq_scan::enclosing_fn(&lines, index)
            };
        out.insert(Site {
            path: path.to_string(),
            function,
        });
    }
    out
}

/// Judge a set of sites against the allow list.
///
/// # Errors
///
/// A count above or below the baseline, or a stale entry.
pub fn evaluate(
    sites: &BTreeSet<Site>,
    entries: &[Entry],
    baseline: u64,
) -> Result<String, String> {
    let unregistered: Vec<&Site> = sites
        .iter()
        .filter(|s| !entries.iter().any(|e| e.covers(s)))
        .collect();
    let stale: Vec<&Entry> = entries
        .iter()
        .filter(|e| !sites.iter().any(|s| e.covers(s)))
        .collect();
    let count = u64::try_from(unregistered.len()).unwrap_or(u64::MAX);
    let mut msg = String::new();
    if !stale.is_empty() {
        let _ = writeln!(
            msg,
            "{} allow list entr(ies) cover no classical use any more; delete them:",
            stale.len()
        );
        for e in &stale {
            let _ = writeln!(msg, "  {} :: {}", e.path, e.function);
        }
    }
    if count > baseline {
        let _ = writeln!(
            msg,
            "{count} classical use(s) have no allow list entry, the baseline is {baseline}. \
             Add an entry to {ALLOWLIST}, or pair the \
             use with a post-quantum component. The sites:"
        );
        for site in unregistered.iter().take(200) {
            let _ = writeln!(msg, "  {} :: {}", site.path, site.function);
        }
    } else if count < baseline {
        let _ = writeln!(
            msg,
            "only {count} classical use(s) are unregistered but the baseline says {baseline}. \
             Lower `unregistered_baseline` in {ALLOWLIST} to {count}: the number only falls."
        );
    }
    if msg.is_empty() {
        Ok(format!(
            "Classical crypto is paired: {} sites, {} registered, {count} unregistered (baseline {baseline}).",
            sites.len(),
            sites.len() - unregistered.len()
        ))
    } else {
        Err(msg)
    }
}

/// Run the gate.
///
/// # Errors
///
/// An unreadable or malformed allow list, or any finding of [`evaluate`].
pub fn run(root: &Path) -> Result<String, String> {
    let list = std::fs::read_to_string(root.join(ALLOWLIST))
        .map_err(|e| format!("cannot read {ALLOWLIST}: {e}"))?;
    let (baseline, entries) = parse_allowlist(&list)?;
    let files = super::pq_scan::rust_files(root, SCAN_ROOTS);
    if files.len() < 100 {
        return Err(format!(
            "only {} source files found under the scan roots; the gate would be vacuous",
            files.len()
        ));
    }
    let mut sites = BTreeSet::new();
    for (rel, path) in &files {
        if let Some(text) = super::pq_scan::production_text(path) {
            sites.extend(sites_of(rel, &text));
        }
    }
    evaluate(&sites, &entries, baseline)
}

/// Canaries: a staged allow list and staged sources.
///
/// # Errors
///
/// A canary that does not behave as stated.
pub fn self_test() -> Result<String, String> {
    let source = "use ed25519_dalek::Signer;\nfn verify_it() {\n    let _k = ed25519_dalek::VerifyingKey::from_bytes(&b);\n}\n// bls12_381 in a comment\nfn x25519_only_name() {}\n";
    let sites = sites_of("src/x.rs", source);
    let names: Vec<String> = sites.iter().map(|s| s.function.clone()).collect();
    if names != ["(imports)", "verify_it"] {
        return Err(format!("site extraction is off: {names:?}"));
    }

    let list = "unregistered_baseline = 1\n[[entry]]\npath = \"src/x.rs\"\nfunction = \"verify_it\"\npq_companion = \"ML-DSA-65\"\ncategory = \"a\"\n";
    let (baseline, entries) = parse_allowlist(list)?;
    if evaluate(&sites, &entries, baseline).is_err() {
        return Err(String::from(
            "a registered use with the exact baseline failed",
        ));
    }
    if evaluate(&sites, &entries, 0).is_ok() {
        return Err(String::from(
            "an unregistered use above a zero baseline passed",
        ));
    }
    if evaluate(&sites, &entries, 2).is_ok() {
        return Err(String::from(
            "a baseline above the count passed; it must fall",
        ));
    }
    let mut stale = entries.clone();
    stale.push(Entry {
        path: String::from("src/gone.rs"),
        function: String::from("*"),
        pq_companion: String::from("none"),
        category: String::from("b"),
    });
    if evaluate(&sites, &stale, baseline).is_ok() {
        return Err(String::from("a stale entry passed"));
    }
    let whole_file = "unregistered_baseline = 0\n[[entry]]\npath = \"src/x.rs\"\nfunction = \"*\"\npq_companion = \"ML-DSA-65\"\ncategory = \"a\"\n";
    let (b0, e0) = parse_allowlist(whole_file)?;
    if evaluate(&sites, &e0, b0).is_err() {
        return Err(String::from("a whole-file entry did not cover its sites"));
    }
    if parse_allowlist("unregistered_baseline = 0\n[[entry]]\npath = \"p\"\nfunction = \"*\"\npq_companion = \"x\"\ncategory = \"z\"\n").is_ok() {
        return Err(String::from("aitem outside a to e was accepted"));
    }
    Ok(String::from(
        "canary OK: registered, unregistered, stale and fallen-baseline cases behave.",
    ))
}
