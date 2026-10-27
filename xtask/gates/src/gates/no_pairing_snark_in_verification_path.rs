//! No pairing-based SNARK sits on a Budlum verification path.
//!
//! # What is refused
//!
//! Groth16, KZG-based PLONK and any proof system over BN254 rest on pairings,
//! and a quantum adversary running Shor's algorithm breaks pairings. The
//! chain's own proofs are BudZero STARKs, which rest on a hash only. Two things
//! would let a pairing system back in without anyone deciding to:
//!
//! 1. **A dependency.** A crate that implements such a system, in any
//!    `Cargo.toml` of the tree or in any resolved `Cargo.lock`. The deny list
//!    below names the crate families; a manifest that renames one with
//!    `package = "..."` is caught by the real name.
//! 2. **A verifier arm.** `ProofSystem::Groth16` and `ProofSystem::Plonk` stay
//!    in the tree as external labels, because an outside chain can attest with
//!    such a system and the profile has to say so. A label is not a verifier:
//!    the identifiers may only appear in the file that defines the label. Code
//!    that matches on them elsewhere is the first step of a verifier.
//!
//! BLS12-381 is a pairing curve too, and it is deliberately not on the list:
//! it is the allowed finality peer of (b), always paired with an ML-DSA
//! quorum, and it is policed by the classical-use gate, not by this one.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Crates that implement a pairing-based proof system or the BN254 curve, in
/// the normalised spelling (lower case, `_` written as `-`).
const DENIED_CRATES: &[(&str, &str)] = &[
    ("ark-groth16", "Groth16"),
    ("ark-bn254", "the BN254 curve"),
    ("ark-circom", "Groth16 circuits"),
    ("circom-compat", "Groth16 circuits"),
    ("ark-poly-commit", "KZG polynomial commitments"),
    ("ark-marlin", "a KZG-based argument"),
    ("dusk-plonk", "KZG-based PLONK"),
    ("plonk", "KZG-based PLONK"),
    ("bellman", "Groth16"),
    ("bellman-ce", "Groth16"),
    ("bellperson", "Groth16"),
    ("groth16", "Groth16"),
    ("bn", "the BN254 curve"),
    ("bn254", "the BN254 curve"),
    ("substrate-bn", "the BN254 curve"),
    ("halo2curves", "the BN254 curve"),
    ("c-kzg", "KZG commitments"),
    ("kzg", "KZG commitments"),
    ("kzg-rs", "KZG commitments"),
    ("sp1-verifier", "Groth16 and PLONK verification"),
    ("risc0-groth16", "Groth16"),
];

/// The only source file allowed to name the external labels.
const LABEL_FILE: &str = "src/cross_domain/external/spec.rs";

/// Identifiers that are labels and never verifiers.
const LABELS: &[&str] = &["Groth16", "Plonk"];

/// Directories that carry no manifests or sources worth scanning.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cargo"];

/// A scan that finds fewer manifests than this looked at nothing.
const VACUITY_FLOOR: usize = 5;

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&path, out);
            }
        } else if kind.is_file() {
            out.push(path);
        }
    }
}

/// Product code: a `src` tree of the node, of a crate or of BudZero. The tools and
/// the gates under `xtask/` name the labels in their own deny lists and canaries.
fn is_product_source(rel: &str) -> bool {
    !rel.starts_with("xtask/") && (rel.starts_with("src/") || rel.contains("/src/"))
}

fn normalise(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

/// The text between the first pair of double quotes on a line.
fn quoted(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let len = line[start..].find('"')?;
    Some(&line[start..start + len])
}

/// The crate names a manifest or a lock file mentions as dependencies.
fn mentioned_crates(file_name: &str, text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if file_name == "Cargo.lock" {
            if let Some(rest) = line.strip_prefix("name") {
                if let Some(value) = rest.trim_start().strip_prefix('=').and_then(quoted) {
                    names.push(normalise(value));
                }
            }
            continue;
        }
        // `[dependencies.NAME]`, `[dev-dependencies.NAME]`, `[workspace.dependencies.NAME]`.
        if let Some(header) = line.strip_prefix('[') {
            let header = header.trim_end_matches(']');
            if let Some(pos) = header.find("dependencies.") {
                names.push(normalise(&header[pos + "dependencies.".len()..]));
            }
            continue;
        }
        // `NAME = ...` and `NAME.workspace = true`.
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().split('.').next().unwrap_or("");
            if !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                names.push(normalise(key));
            }
        }
        // `package = "NAME"` anywhere on the line renames the dependency.
        if let Some(pos) = line.find("package") {
            let rest = line[pos + "package".len()..].trim_start();
            if let Some(value) = rest.strip_prefix('=').and_then(quoted) {
                names.push(normalise(value));
            }
        }
    }
    names
}

/// Does `text` use `label` as an identifier (not as the front of a longer one,
/// such as `Plonky3`)?
fn uses_identifier(text: &str, label: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = text[from..].find(label) {
        let abs = from + pos;
        let before = text[..abs].chars().next_back();
        let after = text[abs + label.len()..].chars().next();
        let boundary_before = !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let boundary_after = !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if boundary_before && boundary_after {
            return true;
        }
        from = abs + label.len();
    }
    false
}

/// Strip `//` comments so a note about the labels is not a use of them.
fn code_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
    }
    out
}

fn scan(root: &Path) -> Result<(usize, Vec<String>), String> {
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut manifests = 0usize;
    let mut findings = Vec::new();
    for path in files {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if name == "Cargo.toml" || name == "Cargo.lock" {
            manifests += 1;
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for crate_name in mentioned_crates(&name, &text) {
                if let Some((_, what)) = DENIED_CRATES.iter().find(|(n, _)| *n == crate_name) {
                    findings.push(format!(
                        "{rel}: depends on `{crate_name}` ({what}); no pairing-based SNARK may sit \
                         on a Budlum verification path"
                    ));
                }
            }
        } else if path.extension().is_some_and(|e| e == "rs")
            && rel != LABEL_FILE
            && is_product_source(&rel)
        {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let code = code_only(&text);
            for label in LABELS {
                if uses_identifier(&code, label) {
                    findings.push(format!(
                        "{rel}: uses `{label}`, which is an external label that only {LABEL_FILE} \
                         may name; a verifier for it is a pairing-based SNARK on a verification path"
                    ));
                }
            }
        }
    }
    if manifests < VACUITY_FLOOR {
        return Err(format!(
            "only {manifests} manifests found under {}; the gate would look at nothing",
            root.display()
        ));
    }
    Ok((manifests, findings))
}

/// # Errors
///
/// A denied crate in a manifest or a lock file, a label identifier outside the
/// file that defines it, or a tree with too few manifests to mean anything.
pub fn run(root: &Path) -> Result<String, String> {
    let (manifests, findings) = scan(root)?;
    if findings.is_empty() {
        return Ok(format!(
            "No pairing-based SNARK on a verification path: {manifests} manifests scanned, {} denied crates.",
            DENIED_CRATES.len()
        ));
    }
    let mut msg = String::new();
    for finding in &findings {
        let _ = writeln!(msg, "FAIL: {finding}");
    }
    Err(msg)
}

fn fixture(root: &Path, files: &[(&str, &str)]) -> Result<(), String> {
    for i in 0..VACUITY_FLOOR {
        let dir = root.join(format!("pad{i}"));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"pad\"\n\n[dependencies]\np3-fri = \"=0.7.0\"\n",
        )
        .map_err(|e| e.to_string())?;
    }
    for (rel, text) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&path, text).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// # Errors
///
/// The first canary that misbehaves: a clean tree must pass, each way a
/// pairing system can enter must be caught, and Plonky3 must not be mistaken
/// for PLONK.
pub fn self_test() -> Result<String, String> {
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-pairing")?;
    let cases: &[(&str, &[(&str, &str)], bool)] = &[
        (
            "clean tree",
            &[(
                "src/lib.rs",
                "// Groth16 is mentioned only in a comment\nfn f() { let _plonky3 = 1; let _ = \"Plonky3\"; }\n",
            )],
            true,
        ),
        (
            "the label file may name the labels",
            &[(
                "src/cross_domain/external/spec.rs",
                "pub enum ProofSystem { Groth16, Plonk }\n",
            )],
            true,
        ),
        (
            "a dependency on a Groth16 crate",
            &[("verify/Cargo.toml", "[dependencies]\nark-groth16 = \"0.5\"\n")],
            false,
        ),
        (
            "a dependency under an underscore spelling",
            &[("verify/Cargo.toml", "[dependencies]\nark_bn254 = \"0.5\"\n")],
            false,
        ),
        (
            "a dependency table header",
            &[("verify/Cargo.toml", "[dependencies.bellman]\nversion = \"0.14\"\n")],
            false,
        ),
        (
            "a renamed dependency",
            &[(
                "verify/Cargo.toml",
                "[dependencies]\nharmless = { package = \"ark-groth16\", version = \"0.5\" }\n",
            )],
            false,
        ),
        (
            "a resolved lock entry",
            &[("verify/Cargo.lock", "[[package]]\nname = \"c-kzg\"\nversion = \"1.0.0\"\n")],
            false,
        ),
        (
            "a verifier arm outside the label file",
            &[(
                "src/verify.rs",
                "fn v(s: ProofSystem) -> bool { matches!(s, ProofSystem::Groth16) }\n",
            )],
            false,
        ),
    ];
    for (index, (label, files, should_pass)) in cases.iter().enumerate() {
        let dir = tmp.join(format!("case{index}"));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fixture(&dir, files)?;
        let passed = run(&dir).is_ok();
        if passed != *should_pass {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "canary `{label}`: expected the gate to {}, it did the opposite",
                if *should_pass { "pass" } else { "fail" }
            ));
        }
    }
    let empty = tmp.join("empty");
    fs::create_dir_all(&empty).map_err(|e| e.to_string())?;
    fs::write(empty.join("Cargo.toml"), "[package]\nname = \"x\"\n").map_err(|e| e.to_string())?;
    let vacuous = run(&empty).is_err();
    let _ = fs::remove_dir_all(&tmp);
    if !vacuous {
        return Err(
            "canary: a tree with one manifest passed; the vacuity floor is not working".into(),
        );
    }
    Ok(format!(
        "no-pairing-snark-in-verification-path self-test ok: {} cases",
        cases.len() + 1
    ))
}
