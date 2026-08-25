//! A test that reads its own source must narrow before searching.
//!
//! Ported from `scripts/check-source-reading-tests-are-narrowed.sh`. When a
//! test does `include_str!("<its-own-file>")` and then searches the raw
//! binding, every string it looks for is also written in the assertion that
//! looks for it, so a positive assertion passes after the production code is
//! deleted. The test must split at `#[cfg(test)]`, bound a window, or
//! assemble the needle at runtime.

use std::fmt::Write as _;
use std::path::Path;

const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

/// `let <holder> = include_str!("<name>")` lines.
fn holders_in(src: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("include_str!(\"{name}\")");
    for line in src.lines() {
        if !line.contains(&needle) {
            continue;
        }
        let t = line.trim();
        let Some(rest) = t.strip_prefix("let ") else {
            continue;
        };
        let name_end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if name_end > 0 {
            out.push(rest[..name_end].to_string());
        }
    }
    out
}

/// `let <x> = <holder>.<...>` or `let <x> = &<holder>[...` - one hop narrowed.
fn narrowed_from(src: &str, holders: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for h in holders {
        let pat1 = format!("{h}.");
        let pat2 = format!("&{h}[");
        for line in src.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("let ") {
                let name_end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                let var = rest[..name_end].to_string();
                if var.is_empty() {
                    continue;
                }
                if rest[name_end..].contains(&pat1) || rest[name_end..].contains(&pat2) {
                    out.push(var);
                }
            }
        }
    }
    out
}

/// `holder.contains("<4+ chars>")` - a literal search against the raw file.
fn literal_searches(src: &str, holders: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for h in holders {
        let needle = format!("{h}.contains(\"");
        let mut rest = src;
        while let Some(pos) = rest.find(&needle) {
            let after = &rest[pos + needle.len()..];
            let lit_end = after.find('"').unwrap_or(after.len());
            let lit = &after[..lit_end];
            if lit.chars().count() >= 4 {
                out.push(lit.to_string());
            }
            rest = &after[lit_end + 1..];
        }
    }
    out
}

/// Does the file narrow before searching?
fn narrows(src: &str) -> bool {
    if src.contains("split_once(\"#[cfg(test)]\")") || src.contains("split(\"#[cfg(test)]\")") {
        return true;
    }
    // `&var[offset..(offset + N]` bounded window
    if src.lines().any(|l| {
        let t = l.trim();
        t.contains('[') && t.contains("..") && (t.contains(" + ") || t.contains('+'))
    }) {
        return true;
    }
    // needle assembled at runtime
    if src.contains("let ") && src.contains("format!(\"") && src.contains("{}") {
        return true;
    }
    if src.contains(".to_string() + \"") {
        return true;
    }
    false
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for scan_root in SCAN_ROOTS {
        let base = root.join(scan_root);
        if !base.is_dir() {
            continue;
        }
        let mut stack = vec![base];
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
                    if !matches!(n.as_str(), ".git" | "target" | "node_modules") {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let Ok(src) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if !src.contains(&format!("include_str!(\"{name}\")")) {
                        continue;
                    }
                    let mut holders = holders_in(&src, &name);
                    if holders.is_empty() {
                        continue;
                    }
                    checked += 1;
                    let narrowed_vars = narrowed_from(&src, &holders);
                    for nv in &narrowed_vars {
                        holders.retain(|h| h != nv);
                    }
                    let lit = literal_searches(&src, &holders);
                    if lit.is_empty() {
                        continue;
                    }
                    if !narrows(&src) || !lit.is_empty() {
                        let rel = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .to_string();
                        problems.push(format!(
                            "{rel} reads its own source with include_str! and searches it \
                             whole. Every string it looks for is also written in the \
                             assertion that looks for it, so a positive assertion passes \
                             after the production code is deleted. Split at `#[cfg(test)]`, \
                             bound a window around a `find` offset, or assemble the needle \
                             at runtime."
                        ));
                    }
                }
            }
        }
    }
    if checked == 0 {
        return Err(String::from(
            "gate found no self-reading test at all, so it measured nothing",
        ));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "source-reading test gate OK: {checked} files read their own source, \
         each narrowing before it searches"
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-sr-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src"));
    let _ = std::fs::create_dir_all(dir.join("budzero"));
    let _ = std::fs::create_dir_all(dir.join("wallet-core"));

    // Narrowed: split at the test marker before searching.
    let good = "#[test]\nfn reads_own_source() {\n    let src = include_str!(\"lib.rs\");\n    let prod = src.split_once(\"#[cfg(test)]\").unwrap().0;\n    assert!(prod.contains(\"fn production_fn\"));\n}\n";
    std::fs::write(dir.join("src/lib.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a narrowed test was rejected"));
    }
    // Not narrowed: searches the raw binding.
    let bad = "#[test]\nfn reads_own_source() {\n    let src = include_str!(\"lib.rs\");\n    assert!(src.contains(\"fn production_fn\"));\n}\n";
    std::fs::write(dir.join("src/lib.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: daraltilmamis test gecti"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "source-reading canary OK: a narrowed read PASSes and a raw search FAILs.",
    ))
}
