//! Lubot's tier story and its dataset hash have to stay checkable.
//!
//! Gate code: `K-AI-VERIFIABLE-INFERENCE-MESH`. A finding or a document that names this code resolves here.
//!
//! The invention text promises a ZK-checked inference path for Lubot. Two
//! things make that promise falsifiable today, and both are the surface a
//! prover would have to lie about: the served model name (a tier label the
//! model cannot invent for itself) and the dataset hash a proof is bound to.
//!
//! So the gate checks that `ModelTier` carries no multiplier label at all,
//! that the two naming tests are still present, that `served_model_name`
//! builds the name from the tier rather than returning a literal, and that
//! `lubot-data` still exposes `verify_sha256` for the provenance hash. A
//! fabricated "10x tier" or an unverified dataset entry is what this refuses.

use std::fmt::Write as _;
use std::path::Path;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("no {rel} at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

fn body_of(src: &str, name: &str) -> Option<String> {
    let at = src.find(&format!("fn {name}("))?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    let mut out = String::new();
    for ch in src[open..].chars() {
        out.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
            }
            _ => {}
        }
    }
    None
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let tier = read(root, "crates/lubot/crates/lubot-core/src/tier.rs")?;
    let data = read(root, "crates/lubot/crates/lubot-data/src/verify.rs").unwrap_or_default();
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let enum_at = tier.find("pub enum ModelTier").ok_or_else(|| {
        "no `pub enum ModelTier` in tier.rs; the tier is what the served name is derived from"
            .to_string()
    })?;
    let enum_end = tier[enum_at..]
        .find('}')
        .map_or(tier.len(), |i| enum_at + i);
    let enum_body = &tier[enum_at..enum_end];
    let variants: Vec<&str> = enum_body
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("///")
                && !l.starts_with("pub enum")
                && !l.ends_with('{')
        })
        .collect();
    if variants.is_empty() {
        problems.push(String::from(
            "`ModelTier` has no variants, so every served name is a guess.",
        ));
    } else {
        checked += 1;
    }
    for v in &variants {
        let label = v.trim_end_matches(',');
        if label.chars().any(|c| c.is_ascii_digit()) {
            problems.push(format!(
                "variant `{v}` names a number. Multiplier tier labels do not exist in Lubot: \
                 a `0.5x`/`10x` style label is a throughput promise the inference path cannot \
                 keep, and it is exactly the wording a marketing claim would add."
            ));
        }
    }
    for t in [
        "served_names_follow_tier_naming",
        "tier_names_contain_no_multiplier_labels",
    ] {
        if tier.contains(&format!("fn {t}")) {
            checked += 1;
        } else {
            problems.push(format!(
                "the test `{t}` is gone. It is the executable form of the naming rule; without \
                 it the rule is a comment."
            ));
        }
    }
    let served = body_of(&tier, "served_model_name").unwrap_or_default();
    if served.contains("\"lubot-") && served.contains("self") {
        checked += 1;
    } else {
        problems.push(
            "`served_model_name` no longer derives from `self`. A literal name means the API can \
             answer with a model the tier enum does not describe."
                .to_string(),
        );
    }
    if data.contains("pub fn verify_sha256") {
        checked += 1;
    } else {
        problems.push(
            "`lubot-data` no longer exposes `verify_sha256`. Provenance of a dataset entry is \
             the only claim about the data a proof can bind to; without it the manifest hash is \
             self-reported."
                .to_string(),
        );
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "Lubot inference surface OK: {checked} checks, {} tier variants with no numeric \
         label, both naming tests present, served names derived, dataset hash verified",
        variants.len()
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-lubot-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("crates/lubot/crates/lubot-core/src"))
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("crates/lubot/crates/lubot-data/src"))
        .map_err(|e| e.to_string())?;
    let good = "pub enum ModelTier {\n    /// Everyday use.\n    Light,\n    /// Highest capacity.\n    Normal,\n}\n\nimpl ModelTier {\n    pub fn served_model_name(self, version: &str) -> String {\n        format!(\"lubot-{}-{version}\", self.name())\n    }\n}\n\n#[cfg(test)]\nmod tests {\n    fn served_names_follow_tier_naming() {}\n    fn tier_names_contain_no_multiplier_labels() {}\n}\n";
    std::fs::write(dir.join("crates/lubot/crates/lubot-core/src/tier.rs"), good)
        .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("crates/lubot/crates/lubot-data/src/verify.rs"),
        "pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<(), DataError> { Ok(()) }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a contained tier file was refused"));
    }
    let bad = good.replace("    Normal,", "    Normal,\n    X10x,");
    std::fs::write(dir.join("crates/lubot/crates/lubot-core/src/tier.rs"), bad)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a `10x` tier label passed"));
    }
    std::fs::write(dir.join("crates/lubot/crates/lubot-core/src/tier.rs"), good)
        .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("crates/lubot/crates/lubot-data/src/verify.rs"),
        "// gone\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unverified dataset surface passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "Lubot canary OK (clean tiers PASS; a numeric tier label and a missing dataset \
         verifier each FAIL).",
    ))
}
