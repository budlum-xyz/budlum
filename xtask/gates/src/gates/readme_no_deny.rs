//! A module README must not deny a feature that the code ships.
//!
//! Ported from `scripts/check-readme-does-not-deny-shipped-code.sh`. For each
//! (readme, denial-regex, evidence, evidence-regex) pair, if the README
//! denies a concept and the code actually contains it, that is drift.

use std::fmt::Write as _;
use std::path::Path;

const PAIRS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "src/storage/README.md",
        "no parity shard concept",
        "src/storage/manifest.rs",
        "ShardKind::Parity",
        "`ShardRef` carries a `kind` and `ShardKind::Parity` exists. If parity \
         is present but unwired, say that; do not say the concept is absent.",
    ),
    (
        "src/storage/README.md",
        "redundancy is not erasure coding",
        "src/storage/erasure.rs",
        "pub fn encode_object",
        "`src/storage/erasure.rs` computes real Reed-Solomon parity. The \
         honest warning is that nothing calls it yet, not that redundancy is \
         replication.",
    ),
];

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| {
            let idx = l.find("//").unwrap_or(l.len());
            l[..idx].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Case-insensitive substring match (the shell regexes are simple phrases).
fn matches(text: &str, pat: &str) -> bool {
    let t = text.to_lowercase();
    let p = pat.to_lowercase();
    t.contains(&p)
}

/// # Errors
///
/// Returns a finding per drifted pair.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (readme_rel, denial_re, evidence_rel, evidence_re, advice) in PAIRS {
        let readme = root.join(readme_rel);
        let evidence = root.join(evidence_rel);
        if !readme.is_file() {
            problems.push(format!(
                "{readme_rel} is missing. If the module README moved, update this \
                 gate in the same commit so its claims stay watched."
            ));
            continue;
        }
        if !evidence.is_file() {
            checked += 1;
            continue;
        }
        checked += 1;
        let readme_text = std::fs::read_to_string(&readme).map_err(|e| e.to_string())?;
        let evidence_text = std::fs::read_to_string(&evidence).map_err(|e| e.to_string())?;
        let evidence_code = strip_comments(&evidence_text);
        let denies = matches(&readme_text, denial_re);
        let exists = matches(&evidence_code, evidence_re);
        if denies && exists {
            problems.push(format!(
                "{readme_rel} still states that a feature is absent, and \
                 {evidence_rel} contains it. {advice}"
            ));
        }
    }
    if checked == 0 {
        return Err(String::from("gate checked no pair"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "readme drift gate OK: {checked} claim/evidence pairs agree"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rdn")?;
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    let denies = "5. Redundancy is not erasure coding, it is replication. There is no parity shard concept.\n";
    let manifest = "pub enum ShardKind { Data, Parity }\n";
    let erasure = "pub fn encode_object() {}\n";
    std::fs::write(dir.join("src/storage/README.md"), denies).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/storage/manifest.rs"), manifest).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/storage/erasure.rs"), erasure).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a denying README passed"));
    }
    // Honest README: feature present but unwired.
    let honest = "5. Erasure coding exists, but no production path calls it yet.\n";
    std::fs::write(dir.join("src/storage/README.md"), honest).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an honest README was refused"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "readme-no-deny canary OK (a denial FAILs, honesty PASSes).",
    ))
}
