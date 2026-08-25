//! Every name in a gate's `required_tests` must really be a `#[test]`.
//!
//! Ported from `scripts/check-required-tests-are-tests.sh`. A name in a
//! gate's `required_tests=(...)` list that carries no `#[test]` attribute is
//! a gate describing a test the tree does not have. Each name must appear
//! exactly once as a `#[test]`-annotated function, and exactly once as a
//! function definition at all, within the declared scope.

use std::fmt::Write as _;
use std::path::Path;

/// Collect `path:name` for every `#[test]`/`#[tokio::test]` function.
fn marked_tests(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let s = path.to_string_lossy();
                if !s.contains("/target") && !s.contains("/.git") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let lines: Vec<&str> = text.lines().collect();
                let mut pending = 0i32;
                for l in &lines {
                    if l.contains("#[test]") || l.contains("#[tokio::test]") {
                        pending = 5;
                        continue;
                    }
                    if pending > 0 {
                        if let Some(pos) = l.find("fn ") {
                            let after = &l[pos + 3..];
                            let name: String = after
                                .chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                .collect();
                            if !name.is_empty() {
                                out.push((rel.clone(), name));
                                pending = 0;
                                continue;
                            }
                        }
                        pending -= 1;
                    }
                }
            }
        }
    }
    out
}

/// Collect every `fn <name>` definition in the tree.
fn all_fns(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let s = path.to_string_lossy();
                if !s.contains("/target") && !s.contains("/.git") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for l in text.lines() {
                    if let Some(pos) = l.find("fn ") {
                        let after = &l[pos + 3..];
                        let name: String = after
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() {
                            out.push(name);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Parse `required_tests_scope="..."` and `required_tests=(...)` from a
/// shell gate script.
fn script_requirements(script: &std::path::Path) -> (String, Vec<String>) {
    let text = std::fs::read_to_string(script).unwrap_or_default();
    let mut scope = String::from(".*");
    for l in text.lines() {
        let t = l.trim_start();
        if let Some(rest) = t.strip_prefix("required_tests_scope=\"") {
            if let Some(end) = rest.find('"') {
                scope = rest[..end].to_string();
            }
        }
    }
    let mut names = Vec::new();
    let mut inside = false;
    for l in text.lines() {
        let t = l.trim_start();
        if t.starts_with("required_tests=(") {
            inside = true;
            continue;
        }
        if inside && t.starts_with(')') {
            inside = false;
            continue;
        }
        if inside {
            let name = t.split_whitespace().next().unwrap_or("");
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                names.push(name.to_string());
            }
        }
    }
    (scope, names)
}

/// # Errors
///
/// Returns a finding per required name that is not a real test.
pub fn run(root: &Path) -> Result<String, String> {
    let marked = marked_tests(root);
    if marked.is_empty() {
        return Err(format!(
            "no #[test] functions found under {} - wrong root?",
            root.display()
        ));
    }
    let fns = all_fns(root);

    let mut scripts_with_lists = 0usize;
    let mut total = 0usize;
    let mut missing_total: Vec<String> = Vec::new();

    let scripts_dir = root.join("ops/scripts");
    let Ok(rd) = std::fs::read_dir(&scripts_dir) else {
        return Err(format!("no scripts/ dir under {}", root.display()));
    };
    let mut scripts: Vec<std::path::PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("check-") && n.to_ascii_lowercase().ends_with(".sh"))
        })
        .collect();
    scripts.sort();

    for script in &scripts {
        let (scope, names) = script_requirements(script);
        if names.is_empty() {
            continue;
        }
        scripts_with_lists += 1;
        let scope_regex = format!("^({scope})(/|\\.rs$|$)");
        let mut missing: Vec<String> = Vec::new();
        for name in &names {
            total += 1;
            let test_matches = marked
                .iter()
                .filter(|(p, n)| {
                    n == name && {
                        let p = p.as_str();
                        // scope match: path matches scope pattern (simple prefix-or-regex)
                        let trimmed = scope.trim_start_matches('(').trim_end_matches(')');
                        p.contains(trimmed.trim_matches('*').trim_matches('/'))
                            || scope == ".*"
                            || scope_regex.contains(trimmed)
                    }
                })
                .count();
            let function_matches = fns.iter().filter(|n| *n == name).count();
            if test_matches != 1 || function_matches != 1 {
                missing.push(name.clone());
            }
        }
        if !missing.is_empty() {
            let sname = script
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let mut msg = format!("FAIL: {sname} requires tests that are not tests:\n");
            for m in &missing {
                writeln!(msg, "  - {m}").expect("writing to a String cannot fail");
            }
            missing_total.push(msg);
        }
    }

    if scripts_with_lists == 0 {
        // All required-test lists have migrated to Rust gates; nothing left
        // to check in shell.
        return Ok(String::from(
            "Required-test gate OK: no shell gate declares required_tests=() (all migrated to Rust).",
        ));
    }
    if !missing_total.is_empty() {
        let mut all = String::new();
        for m in &missing_total {
            all.push_str(m);
        }
        all.push_str(
            "\nA name in required_tests=() that carries no #[test] attribute is a\n\
             gate describing a test the tree does not have. Restore the attribute,\n\
             or remove the name and say why in the same commit.",
        );
        return Err(all);
    }
    Ok(format!(
        "Required-test gate OK: {total} required names across {scripts_with_lists} gate scripts all carry #[test]."
    ))
}

/// # Errors
///
/// Returns a finding when a required name that is not a test passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-rtt-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("ops/scripts"));
    let _ = std::fs::create_dir_all(dir.join("src"));

    std::fs::write(
        dir.join("ops/scripts/check-example-gate.sh"),
        "required_tests=(\n  a_real_test\n)\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/lib.rs"), "#[test]\nfn a_real_test() {}\n")
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct tree was refused"));
    }
    // Remove the #[test] attribute.
    std::fs::write(dir.join("src/lib.rs"), "fn a_real_test() {}\n").map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a name carrying no #[test] passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "required-tests canary OK: with a test it PASSes and without one it FAILs.",
    ))
}
