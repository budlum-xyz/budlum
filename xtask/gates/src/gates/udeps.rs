//! cargo-udeps unused-dependency ratchet.
//!
//! Ported from `scripts/check-udeps.sh`. Parses the tree-shaped output of
//! `cargo +nightly udeps --all-targets` into `<package>:<dep>` lines and
//! compares against `.github/udeps-baseline.txt`; a finding not on the
//! baseline fails (ratchet). A missing baseline file is an empty baseline,
//! not a reason to skip: the ratchet has never had a file, so the old SKIP
//! meant every unused dependency passed forever. To accept today's
//! findings, commit `.github/udeps-baseline.txt` from a green measurement.

use std::path::Path;

/// The line cargo-udeps prints when it finished and found nothing.
const CLEAN_SENTINEL: &str = "All deps seem to have been used.";

fn parse_udeps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pkg: Option<String> = None;
    for line in text.lines() {
        // A package line: "`budlum-core v0.1.0 (/path)"
        if let Some(rest) = line.trim_start().strip_prefix('`') {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() {
                pkg = Some(name);
                continue;
            }
        }
        // A dependency line: "├─── "chrono"" (or "└─── "group""). When a
        // package has more than one dependency group, the groups before the
        // last are drawn with a continuing rule: `│    ├─── "chrono"`. That
        // bar is not whitespace, so trimming did not reach the branch and
        // every dependency in a non-final group fell out of the parse.
        let t = line.trim_start().trim_start_matches(['│', ' ']);
        if let Some(rest) = t.strip_prefix("├─── ").or_else(|| t.strip_prefix("└─── "))
        {
            if let Some(dep) = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                if let Some(p) = &pkg {
                    out.push(format!("{p}:{dep}"));
                }
            }
        }
    }
    out
}

/// # Errors
///
/// Returns a finding when a parsed unused dependency is not in the baseline.
pub fn run(root: &Path, out: &Path) -> Result<String, String> {
    if !out.is_file() {
        return Err(format!(
            "the udeps output is missing/empty: {}",
            out.display()
        ));
    }
    let text = std::fs::read_to_string(out).map_err(|e| e.to_string())?;
    let found = parse_udeps(&text);
    if found.is_empty() {
        // An empty parse has two causes: the tool ran and found nothing, or
        // the tool never produced a report. Only the first is a pass. The
        // workflow pipes the tool's own stderr into this file, so a bootstrap
        // failure lands here as an "error:" line and used to read as clean.
        let lowered = text.to_ascii_lowercase();
        if lowered.starts_with("error:")
            || lowered.contains("\nerror:")
            || lowered.contains("failed to")
        {
            return Err(format!(
                "the cargo-udeps output could not be parsed; the scan is treated as\n\
                 incomplete and is not accepted as clean:\n{text}"
            ));
        }
        // A clean verdict needs the tool's own sentinel: an empty or
        // truncated file parses to zero findings too.
        if !text.contains(CLEAN_SENTINEL) {
            return Err(format!(
                "the cargo-udeps output has no findings and no `{CLEAN_SENTINEL}` line; \
                 the tool did not finish, so the scan is not accepted as clean:\n{text}"
            ));
        }
        return Ok(String::from("OK: no unused dependencies (parsed)."));
    }
    let baseline_path = root.join(".github/udeps-baseline.txt");
    // A missing file is an empty baseline: every finding fails.
    let bl = if baseline_path.is_file() {
        std::fs::read_to_string(&baseline_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };
    let baseline_set: std::collections::BTreeSet<&str> = bl.lines().collect();
    let mut fails: Vec<String> = Vec::new();
    for f in &found {
        if !baseline_set.contains(f.as_str()) {
            fails.push(format!(
                "FAIL: an unused dependency that is not in the baseline: {f}"
            ));
        }
    }
    if fails.is_empty() {
        Ok(format!(
            "OK: every finding is in the known baseline ({} of them).",
            found.len()
        ))
    } else {
        Err(fails.join("\n"))
    }
}

/// # Errors
///
/// Returns a finding when the parser misreads the real udeps tree format.
pub fn self_test() -> Result<String, String> {
    // Two dependency groups under one package: the first is drawn with the
    // continuing `│` rule, the last without it. Both must parse.
    let real = "info: Loading depinfo from \"x.d\"\nunused dependencies:\n`budlum-core v0.1.0 (/x/budlum)`\n├─── dependencies\n│    ├─── \"chrono\"\n│    └─── \"group\"\n└─── dev-dependencies\n     └─── \"tempfile\"\nNote: They might be false-positive.\n`bud-node v0.1.0 (/x/budzero/bud-node)`\n└─── dependencies\n     └─── \"serde_json\"\n";
    let parsed = parse_udeps(real);
    let expected = [
        "budlum-core:chrono",
        "budlum-core:group",
        "budlum-core:tempfile",
        "bud-node:serde_json",
    ];
    if parsed != expected {
        return Err(format!(
            "BOZUK PARSE: beklenen={expected:?} gelen={parsed:?}"
        ));
    }
    // A tool that died before producing a report must not read as clean. The
    // check runs through `run` so the canary measures the gate, not the
    // parser in isolation.
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-udeps")?;
    let broken = dir.join("bozuk.txt");
    std::fs::write(
        &broken,
        "error: no such command: `udeps`\n\nView all installed commands with `cargo --list`\n",
    )
    .map_err(|e| e.to_string())?;
    let broken_failed = run(&dir, &broken).is_err();
    let clean = dir.join("clean.txt");
    std::fs::write(
        &clean,
        "info: Loading depinfo from \"x.d\"\nAll deps seem to have been used.\n",
    )
    .map_err(|e| e.to_string())?;
    let clean_passed = run(&dir, &clean).is_ok();
    // An empty report is not a clean verdict.
    let empty = dir.join("empty.txt");
    std::fs::write(&empty, "").map_err(|e| e.to_string())?;
    let empty_failed = run(&dir, &empty).is_err();
    // A finding with no baseline file fails: the ratchet has no SKIP.
    let found = dir.join("found.txt");
    std::fs::write(
        &found,
        "unused dependencies:\n`a v0.1.0 (/x)`\n└─── dependencies\n     └─── \"left\"\n",
    )
    .map_err(|e| e.to_string())?;
    let found_failed = run(&dir, &found).is_err();
    // The same finding in a baseline passes.
    std::fs::create_dir_all(dir.join(".github")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(".github/udeps-baseline.txt"), "a:left\n")
        .map_err(|e| e.to_string())?;
    let baselined_passed = run(&dir, &found).is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    if !empty_failed {
        return Err(String::from(
            "canary: an empty udeps report was counted as clean",
        ));
    }
    if !found_failed {
        return Err(String::from(
            "canary: a finding with no baseline file passed (the ratchet skipped)",
        ));
    }
    if !baselined_passed {
        return Err(String::from(
            "canary: a finding that is in the baseline was refused",
        ));
    }
    if !broken_failed {
        return Err(String::from(
            "canary: broken udeps output was counted as clean (fail-open)",
        ));
    }
    if !clean_passed {
        return Err(String::from("canary: genuinely clean output was refused"));
    }
    Ok(String::from(
        "udeps canary OK: the tree was parsed; broken, empty and unbaselined output FAIL; clean and baselined output PASS.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tree() {
        let t = "`a v1.0`\n└─── dependencies\n     ├─── \"x\"\n     └─── \"y\"\n";
        assert_eq!(parse_udeps(t), vec!["a:x", "a:y"]);
    }

    #[test]
    fn ignores_notes() {
        let t =
            "Note: They might be false-positive.\n`b v1.0`\n└─── dependencies\n     └─── \"z\"\n";
        assert_eq!(parse_udeps(t), vec!["b:z"]);
    }
}
