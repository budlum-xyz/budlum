//! Every fuzz harness must be built by a `[[bin]]` and run by a workflow.
//!
//! Ported from `scripts/check-fuzz-targets-are-wired.sh`. A harness with no
//! `[[bin]]` entry cannot be built by cargo-fuzz; a built target no workflow
//! mentions fuzzes nothing on any schedule; a declared target with no harness
//! file is dead config.

use std::path::Path;

/// Parse `name = "..."` and `path = "fuzz_targets/<x>.rs"` from the fuzz
/// manifest.
fn parse_manifest(manifest_path: &Path) -> Result<(Vec<String>, Vec<String>), String> {
    let manifest_text = std::fs::read_to_string(manifest_path).map_err(|e| e.to_string())?;
    let mut declared: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for l in manifest_text.lines() {
        let t = l.trim_start();
        if let Some(rest) = t.strip_prefix("name") {
            if let Some(eq) = rest.find('=') {
                let v = rest[eq + 1..].trim().trim_matches('"');
                declared.push(v.to_string());
            }
        }
        if let Some(rest) = t.strip_prefix("path") {
            if let Some(eq) = rest.find('=') {
                let v = rest[eq + 1..].trim().trim_matches('"');
                if let Some(stem) = v
                    .strip_prefix("fuzz_targets/")
                    .and_then(|p| p.strip_suffix(".rs"))
                {
                    paths.push(stem.to_string());
                }
            }
        }
    }
    Ok((declared, paths))
}

/// # Errors
///
/// Returns a finding per unwired fuzz target, or a vacuity failure.
pub fn run(root: &Path) -> Result<String, String> {
    let targets_dir = root.join("fuzz/fuzz_targets");
    let manifest_path = root.join("fuzz/Cargo.toml");
    let workflows_dir = root.join(".github/workflows");
    if !targets_dir.is_dir() {
        return Err(format!(
            "no fuzz target directory at {}",
            targets_dir.display()
        ));
    }
    if !manifest_path.is_file() {
        return Err(format!("no manifest at {}", manifest_path.display()));
    }
    let mut harnesses: Vec<String> = Vec::new();
    let rd = std::fs::read_dir(&targets_dir).map_err(|e| e.to_string())?;
    for e in rd.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".rs") {
            harnesses.push(stem.to_string());
        }
    }
    harnesses.sort();
    if harnesses.is_empty() {
        return Err(String::from(
            "no .rs harnesses found; the gate would be vacuous",
        ));
    }
    let (declared, paths) = parse_manifest(&manifest_path)?;
    let mut workflow_text = String::new();
    if workflows_dir.is_dir() {
        let rd = std::fs::read_dir(&workflows_dir).map_err(|e| e.to_string())?;
        let mut files: Vec<String> = Vec::new();
        for e in rd.filter_map(Result::ok) {
            let n = e.file_name().to_string_lossy().to_string();
            let ext = e
                .path()
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "yml" || ext == "yaml" {
                files.push(n);
            }
        }
        files.sort();
        for f in files {
            if let Ok(t) = std::fs::read_to_string(workflows_dir.join(&f)) {
                workflow_text.push_str(&t);
            }
        }
    }
    if workflow_text.is_empty() {
        return Err(format!(
            "no workflow files under {}; gate would be vacuous",
            workflows_dir.display()
        ));
    }

    let mut problems: Vec<String> = Vec::new();
    for name in &harnesses {
        if !declared.contains(name) || !paths.contains(name) {
            problems.push(format!(
                "  {name}: harness exists but fuzz/Cargo.toml has no matching \
                 [[bin]] (name and path). cargo-fuzz cannot build it."
            ));
            continue;
        }
        // word-boundary mention in workflows
        let in_wf = workflow_text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .any(|tok| tok == name.as_str());
        if !in_wf {
            problems.push(format!(
                "  {name}: built but never run. No workflow mentions it, so it \
                 fuzzes nothing on any schedule."
            ));
        }
    }
    let harness_set: Vec<&String> = harnesses.iter().collect();
    let mut path_extra: Vec<&String> = paths.iter().filter(|p| !harness_set.contains(p)).collect();
    path_extra.sort();
    for name in path_extra {
        problems.push(format!(
            "  {name}: fuzz/Cargo.toml declares it, no such harness file."
        ));
    }

    if !problems.is_empty() {
        let mut msg = format!(
            "FAIL: {} fuzz target(s) are not fully wired:\n",
            problems.len()
        );
        for p in &problems {
            msg.push_str(p);
            msg.push('\n');
        }
        return Err(msg);
    }
    Ok(format!(
        "Fuzz wiring OK: {} harness(es), each with a [[bin]] entry \
         and at least one workflow that runs it.",
        harnesses.len()
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
        std::env::temp_dir().join(format!("budlum-gates-fuzz-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("fuzz/fuzz_targets"));
    let _ = std::fs::create_dir_all(dir.join(".github/workflows"));

    std::fs::write(dir.join("fuzz/fuzz_targets/abc.rs"), "fn main() {}\n")
        .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("fuzz/Cargo.toml"),
        "[[bin]]\nname = \"abc\"\npath = \"fuzz_targets/abc.rs\"\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join(".github/workflows/ci.yml"),
        "run: cargo fuzz run abc\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: correct wiring was refused"));
    }
    // Remove the workflow mention.
    std::fs::write(
        dir.join(".github/workflows/ci.yml"),
        "run: cargo fuzz run xyz\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: calismayan hedef gecti"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "fuzz-wiring kanaryasi OK (kablo PASS, calismayan FAIL).",
    ))
}
