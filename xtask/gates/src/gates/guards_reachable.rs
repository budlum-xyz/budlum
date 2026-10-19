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

/// Is this path a test file? A `tests.rs` is a whole test module with no
/// inner attribute, so it is excluded like `*_tests.rs` and `tests/`.
fn is_test_file(rel: &str) -> bool {
    rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

/// The name of a `pub fn` header, with any visibility restriction and the
/// `async`, `const` and `unsafe` qualifiers.
fn pub_fn_name(line: &str) -> Option<String> {
    let mut rest = line.trim_start().strip_prefix("pub")?;
    if let Some(r) = rest.strip_prefix('(') {
        rest = &r[r.find(')')? + 1..];
    }
    let mut rest = rest.strip_prefix(' ')?.trim_start();
    loop {
        if let Some(r) = rest.strip_prefix("fn ") {
            rest = r;
            break;
        }
        rest = ["async ", "const ", "unsafe "]
            .iter()
            .find_map(|q| rest.strip_prefix(q))?;
    }
    Some(
        rest.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect(),
    )
}

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
                if is_test_file(&rel) {
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
pub(crate) fn strip_test_mods(text: &str) -> String {
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
/// Line-based so byte slicing never lands inside a multibyte character. Only
/// the line that defines *this* name is skipped: skipping every line that
/// starts with a function header hid the call in a one-line wrapper such as
/// `pub fn a() { check_b(1) }`, so a wired guard was counted as unwired.
fn is_called(name: &str, prod: &BTreeMap<String, String>) -> bool {
    let needle = format!("{name}(");
    let def = format!("fn {name}(");
    for text in prod.values() {
        // A module that declares itself unwired is not reached from the node,
        // so a call from it is no wiring.
        if has_file_level_unwired_marker(text) {
            continue;
        }
        let c = code(text);
        for line in c.lines() {
            if !line.contains(&needle) {
                continue;
            }
            if line.trim_start().contains(&def) {
                continue;
            }
            return true;
        }
    }
    false
}

/// # Errors
///
/// Returns a finding when the unwired count rose or the baseline is stale.
pub fn run(root: &Path) -> Result<String, String> {
    if !root.join("src").is_dir() {
        return Err(format!(
            "no src directory under {}: the gate would measure nothing",
            root.display()
        ));
    }
    let prod = prod_files(root);

    let mut guards: Vec<(String, String)> = Vec::new();
    for (path, text) in &prod {
        if has_file_level_unwired_marker(text) {
            continue;
        }
        let body = strip_test_mods(text);
        for line in body.lines() {
            if let Some(name) = pub_fn_name(line) {
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
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-gr")?;
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
    // The call sits on the same line as a function definition, which is the
    // shape the old predicate swallowed. The baseline is lowered to zero
    // before this phase, so the assertion is real: if a call site stops being
    // seen, the count rises over that zero and the canary fires.
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub mod guarded;\npub fn drive() { let _ = guarded::check_thing_is_allowed(1); }\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(dir.join(BASELINE_FILE), "0\n").map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a wired guard stayed in the count"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "guards-reachable canary OK: an uncalled guard is counted, a called one is not, and a call written on a definition line is not mistaken for a definition.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_qualifiers_and_tests_rs_are_handled() {
        assert_eq!(
            pub_fn_name("pub fn check_a(x: u8)").as_deref(),
            Some("check_a")
        );
        assert_eq!(
            pub_fn_name("pub(crate) fn check_b()").as_deref(),
            Some("check_b")
        );
        assert_eq!(
            pub_fn_name("    pub const fn check_c()").as_deref(),
            Some("check_c")
        );
        assert_eq!(
            pub_fn_name("pub unsafe fn check_d()").as_deref(),
            Some("check_d")
        );
        assert_eq!(
            pub_fn_name("pub async fn check_e()").as_deref(),
            Some("check_e")
        );
        assert_eq!(pub_fn_name("pub struct X;"), None);
        assert!(is_test_file("src/rpc/tests.rs"));
        assert!(!is_test_file("src/rpc/mod.rs"));
    }

    #[test]
    fn call_from_an_unwired_module_is_not_wiring() {
        let mut prod = BTreeMap::new();
        prod.insert(
            String::from("src/a.rs"),
            String::from("//! WIRING: unwired - x\nfn f() { check_it(1); }\n"),
        );
        prod.insert(
            String::from("src/b.rs"),
            String::from("pub fn check_it(x: u8) {}\n"),
        );
        assert!(!is_called("check_it", &prod));
    }
}
