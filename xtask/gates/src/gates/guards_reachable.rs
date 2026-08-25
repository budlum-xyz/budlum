//! Every guard must be reachable from production code.
//!
//! Ported from `scripts/check-guards-are-reachable.sh`. A `pub fn
//! (check|verify|validate|require|enforce|assert|reject|refuse|deny|guard)_*`
//! that no production path calls is a comment. A module that declares itself
//! with a leading `//! WIRING: unwired - <reason>` is honestly exempt. The
//! unwired count is ratcheted against `.github/unwired-guards-baseline.txt`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

const BASELINE_FILE: &str = ".github/unwired-guards-baseline.txt";

const GUARD_PREFIXES: &[&str] = &[
    "check_",
    "verify_",
    "validate_",
    "require_",
    "enforce_",
    "assert_",
    "reject_",
    "refuse_",
    "deny_",
    "admit_",
    "guard_",
];

/// Collect production `.rs` files (tests excluded).
fn prod_files(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.join("src")];
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
                let n = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if !matches!(n.as_str(), ".git" | "target") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel.contains("/tests/") || rel.ends_with("_tests.rs") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.insert(rel, text);
                }
            }
        }
    }
    out
}

/// Remove `#[cfg(test)] mod ... { }` blocks, brace matched.
fn strip_test_mods(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    loop {
        let Some(at) = rest.find("#[cfg(test)]") else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at]);
        let Some(brace_rel) = rest[at..].find('{') else {
            return out;
        };
        let brace = at + brace_rel;
        if let Some(semi_rel) = rest[at..].find(';') {
            if semi_rel < brace_rel {
                rest = &rest[at + semi_rel + 1..];
                continue;
            }
        }
        let mut depth = 0i32;
        let mut j = brace;
        let b = rest.as_bytes();
        while j < b.len() {
            match b[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        rest = if j < rest.len() { &rest[j + 1..] } else { "" };
    }
}

/// Production code: test modules and doc comments removed.
fn code(text: &str) -> String {
    let mut out = String::new();
    for l in strip_test_mods(text).lines() {
        let t = l.trim_start();
        if t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn is_guard_fn(name: &str) -> bool {
    GUARD_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Leading module-doc `//! WIRING: unwired - <reason>` for the file itself.
fn has_file_level_unwired_marker(text: &str) -> bool {
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with("//!") {
            if stripped.starts_with("//! WIRING: unwired - ")
                || stripped.starts_with("//! WIRING: unwired-")
            {
                return true;
            }
            continue;
        }
        if !stripped.starts_with("//") && !stripped.starts_with('#') {
            break;
        }
    }
    false
}

/// Is `name(` called somewhere in `code`, other than at its own definition?
/// Line-based so byte slicing never lands inside a multibyte character.
fn is_called(name: &str, prod: &BTreeMap<String, String>) -> bool {
    let needle = format!("{name}(");
    for text in prod.values() {
        let c = code(text);
        for line in c.lines() {
            if !line.contains(&needle) {
                continue;
            }
            let t = line.trim_start();
            let def_here = t.starts_with("fn ")
                || t.starts_with("pub fn ")
                || t.starts_with("pub(crate) fn ")
                || t.starts_with("pub(super) fn ");
            if !def_here {
                return true;
            }
        }
    }
    false
}

/// # Errors
///
/// Returns a finding when the unwired count rose or the baseline is stale.
pub fn run(root: &Path) -> Result<String, String> {
    if !root.join("src").is_dir() {
        return Ok(String::from("0"));
    }
    let prod = prod_files(root);

    let mut guards: Vec<(String, String)> = Vec::new();
    for (path, text) in &prod {
        if has_file_level_unwired_marker(text) {
            continue;
        }
        let body = strip_test_mods(text);
        for line in body.lines() {
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix("pub ") else {
                continue;
            };
            let rest = rest.strip_prefix("async ").unwrap_or(rest);
            if let Some(rest) = rest.strip_prefix("fn ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if is_guard_fn(&name) {
                    guards.push((path.clone(), name));
                }
            }
        }
    }

    let mut unreached: Vec<(String, String)> = Vec::new();
    for (path, name) in &guards {
        if !is_called(name, &prod) {
            unreached.push((path.clone(), name.clone()));
        }
    }
    unreached.sort();

    let baseline_path = root.join(BASELINE_FILE);
    if !baseline_path.is_file() {
        return Err(format!("baseline missing: {}", baseline_path.display()));
    }
    let bl_text = std::fs::read_to_string(&baseline_path).map_err(|e| e.to_string())?;
    let baseline: usize = bl_text
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .ok_or_else(|| {
            format!(
                "no number in {}, gate would be vacuous",
                baseline_path.display()
            )
        })?
        .parse::<usize>()
        .map_err(|e| e.to_string())?;

    let count = unreached.len();
    if count > baseline {
        let mut msg = format!("unwired guards: {count} | baseline: {baseline}\n--- guards no production path reaches ---\n");
        for (p, n) in &unreached {
            writeln!(msg, "{p}\t{n}").expect("writing to a String cannot fail");
        }
        let _ = writeln!(
            msg,
            "FAIL: unwired guard count rose from {baseline} to {count}.\n  A refusal that nothing calls is a comment. Three defects of exactly this shape have already been found by hand, each correct and each never run. Either call the new guard from the path it was written for, or put it in a module whose doc says `WIRING: unwired - <reason>`."
        );
        return Err(msg);
    }
    if count < baseline {
        return Err(format!(
            "unwired guards: {count} | baseline: {baseline}\n\
             Baseline is now loose: {count} guards remain, the file says {baseline}.\n\
             Lower it in this pull request, or the gain is given back silently.\n\
             FAIL: baseline not tightened after wiring a guard up"
        ));
    }
    Ok(format!(
        "unwired guards: {count} | baseline: {baseline}\nOK: no new unreachable guards."
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-gr-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src"));
    let _ = std::fs::create_dir_all(dir.join(".github"));

    let guard = "pub fn check_thing_is_allowed(x: u8) -> Result<(), String> {\n    if x == 0 { return Err(\"no\".into()); }\n    Ok(())\n}\n";
    std::fs::write(dir.join("src/guarded.rs"), guard).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub mod guarded;\npub fn drive() {}\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(dir.join(BASELINE_FILE), "1\n").map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: uncalled guard sayilmadi"));
    }
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub mod guarded;\npub fn drive() { let _ = guarded::check_thing_is_allowed(1); }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a called guard was counted"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "guards-reachable canary OK: an uncalled guard is counted and a called one is not.",
    ))
}
