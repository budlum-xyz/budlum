//! A narrow test module must import every parent item its tests name.
//!
//! # The defect this exists for
//!
//! `src/cross_domain/bridge.rs` carries two test modules. One opens with
//! `use super::*`, the other with `use super::split_bridge_fee` - a
//! deliberately narrow import, which is good practice and also a trap: tests
//! appended to the file land in whichever module comes last, and a narrow
//! import does not bring the new function along. The code compiled, the
//! library compiled, `cargo check --lib` passed, and the failure only
//! appeared in CI as `cannot find function ... in this scope`.
//!
//! On this project's hardware the full test profile does not build (the
//! compiler is killed for memory), so `cargo check --lib` is the local
//! verification and it does not compile `#[cfg(test)]` bodies at all. That
//! makes this class of mistake invisible until CI - a slow feedback loop for
//! a mistake that takes one second to make.
//!
//! # What it checks
//!
//! For every test module that imports specific names from its parent rather
//! than glob-importing, every identifier the module calls that is defined at
//! the parent's top level must be among the imported names.
//!
//! # What it deliberately does not do
//!
//! It does not type-check, and it does not follow `use` paths beyond the
//! parent module. It answers one question - *can this test module see the
//! parent function it calls* - because that is the question that was missed.
//! A gate that tried to be a compiler would be a worse compiler.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Top-level `fn` names defined in `src`, outside any test module.
fn parent_functions(src: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in src.lines() {
        let t = line.trim_start();
        // Only column-0 items: nested `fn`s are not reachable as `super::x`.
        if !line.starts_with("pub fn ")
            && !line.starts_with("fn ")
            && !line.starts_with("pub(crate) fn ")
        {
            continue;
        }
        let after = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        let Some(rest) = after.strip_prefix("fn ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names
}

/// One test module: where it starts, and what it imported from `super`.
struct TestModule {
    name: String,
    line: usize,
    glob: bool,
    imported: BTreeSet<String>,
    body: String,
}

/// Split `src` into its `#[cfg(test)] mod ... { }` blocks.
fn test_modules(src: &str) -> Vec<TestModule> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        if lines[i].trim() != "#[cfg(test)]" {
            i += 1;
            continue;
        }
        let Some(header) = lines.get(i + 1) else {
            break;
        };
        let Some(rest) = header.trim_start().strip_prefix("mod ") else {
            i += 1;
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();

        // Body runs to the matching close brace at column 0.
        let start = i + 2;
        let mut end = lines.len();
        for (j, l) in lines.iter().enumerate().skip(start) {
            if *l == "}" {
                end = j;
                break;
            }
        }
        let body_lines = lines.get(start..end).unwrap_or_default();
        let body = body_lines.join("\n");

        let mut glob = false;
        let mut imported = BTreeSet::new();
        for l in body_lines {
            let t = l.trim();
            let Some(spec) = t.strip_prefix("use super::") else {
                continue;
            };
            let spec = spec.trim_end_matches(';');
            if spec == "*" {
                glob = true;
                continue;
            }
            let inner = spec.trim_start_matches('{').trim_end_matches('}');
            for part in inner.split(',') {
                let n = part.trim();
                if !n.is_empty() {
                    imported.insert(n.to_string());
                }
            }
        }
        out.push(TestModule {
            name,
            line: i + 2,
            glob,
            imported,
            body,
        });
        i = end.max(i + 1);
    }
    out
}

/// Names the body calls as bare functions: `name(`.
fn called_names(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let c = bytes[idx];
        if !(c.is_alphabetic() || c == '_') {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len() && (bytes[idx].is_alphanumeric() || bytes[idx] == '_') {
            idx += 1;
        }
        // A call is `name(`; a path segment `a::name(` belongs to that path.
        if bytes.get(idx) != Some(&'(') {
            continue;
        }
        if start >= 2 && bytes.get(start - 1) == Some(&':') {
            continue;
        }
        // `.method(` is a method call, not a free function.
        if start >= 1 && bytes.get(start - 1) == Some(&'.') {
            continue;
        }
        let name: String = bytes.get(start..idx).unwrap_or_default().iter().collect();
        out.insert(name);
        idx += 1;
    }
    out
}

fn check_file(path: &Path, findings: &mut Vec<String>) {
    let Ok(src) = fs::read_to_string(path) else {
        return;
    };
    if !src.contains("#[cfg(test)]") {
        return;
    }
    let parents = parent_functions(&src);
    for m in test_modules(&src) {
        if m.glob {
            continue;
        }
        // Functions the module defines itself are fine.
        let local = parent_functions(&m.body.replace("    ", ""));
        for called in called_names(&m.body) {
            if !parents.contains(&called) || m.imported.contains(&called) || local.contains(&called)
            {
                continue;
            }
            findings.push(format!(
                "  {}:{} mod {} calls `{}` but imports only {{{}}} from super. \
                 `cargo check --lib` does not compile test bodies, so this only \
                 fails in CI.",
                path.display(),
                m.line,
                m.name,
                called,
                m.imported.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
}

fn walk(dir: &Path, findings: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, findings);
        } else if path.extension().is_some_and(|e| e == "rs") {
            check_file(&path, findings);
        }
    }
}

/// # Errors
///
/// Returns the list of test modules that call a parent function they did not
/// import.
pub fn run(repo_root: &Path) -> Result<String, String> {
    let mut findings = Vec::new();
    let mut trees = 0usize;
    for root in ["src", "crates", "budzero"] {
        let p = repo_root.join(root);
        if p.exists() {
            trees += 1;
            walk(&p, &mut findings);
        }
    }
    if findings.is_empty() {
        return Ok(format!(
            "test module imports OK: {trees} tree(s) scanned, every narrow \
             `use super::{{..}}` covers the parent functions its tests call"
        ));
    }
    let mut msg = format!("{} test module(s):\n\n", findings.len());
    for f in findings {
        let _ = writeln!(msg, "{f}");
    }
    Err(msg)
}

/// # Errors
///
/// Returns an error when the gate's own detection does not behave.
pub fn self_test() -> Result<String, String> {
    let narrow = r"
pub fn helper() -> u8 { 1 }
pub fn other() -> u8 { 2 }

#[cfg(test)]
mod tests {
    use super::helper;

    #[test]
    fn t() {
        assert_eq!(helper(), 1);
        assert_eq!(other(), 2);
    }
}
";
    let parents = parent_functions(narrow);
    if !parents.contains("other") {
        return Err("parent scan missed a top-level fn".into());
    }
    let mods = test_modules(narrow);
    let m = mods.first().ok_or("no test module found")?;
    if m.glob {
        return Err("a narrow import was read as a glob".into());
    }
    if !m.imported.contains("helper") {
        return Err("the imported name was not read".into());
    }
    let called = called_names(&m.body);
    if !called.contains("other") {
        return Err("the uncovered call was not detected".into());
    }
    if !called.contains("helper") {
        return Err("the covered call was not detected".into());
    }

    // A glob import must silence it.
    let globbed = narrow.replace("use super::helper;", "use super::*;");
    let g = test_modules(&globbed);
    let gm = g.first().ok_or("no test module in glob variant")?;
    if !gm.glob {
        return Err("a glob import was not recognised".into());
    }

    // `a::b(` must not be read as a bare call to `b`.
    if called_names("let x = foo::bar();").contains("bar") {
        return Err("a path-qualified call was read as a bare call".into());
    }
    if called_names("x.len();").contains("len") {
        return Err("a method call was read as a free function".into());
    }
    Ok("self test OK: narrow imports flagged, globs and qualified paths not".into())
}
