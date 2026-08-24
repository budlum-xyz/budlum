//! A refusal must not leave a partial write behind.
//!
//! Ported from `scripts/check-refusals-do-not-mutate-first.sh`. A
//! `Result`-returning function that removes from a `self.` collection and can
//! still `return Err` afterwards must either put the value back (`.insert` on
//! the failing path), decide every refusal before the remove, or declare
//! `PARTIAL: allowed - <reason>` in its doc comment.

use std::fmt::Write as _;
use std::path::Path;

const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

/// Balanced brace body starting at `open` (index of `{`).
fn balanced(src: &str, open: usize) -> String {
    let mut depth = 0i32;
    let mut j = open;
    let b = src.as_bytes();
    while j < b.len() {
        match b[j] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open..=j].to_string();
                }
            }
            _ => {}
        }
        j += 1;
    }
    src[open..].to_string()
}

/// Remove `#[cfg(test)] mod ... { }` blocks, mirroring the shell gate's
/// `strip_test_mods`. When a `#[cfg(test)]` attribute is not followed by a
/// `mod`, it is left in place and the scan continues past it (the shell
/// regex skips it, it does not abort the whole strip).
fn strip_test_mods(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    loop {
        let m = rest.find("#[cfg(test)]");
        let Some(m) = m else {
            out.push_str(rest);
            return out;
        };
        // Find `mod <name> {`
        let after = &rest[m..];
        let Some(brace_rel) = after.find('{') else {
            out.push_str(rest);
            return out;
        };
        // Only treat as a test-mod if the attribute is followed by `mod`.
        let between = &after["#[cfg(test)]".len()..brace_rel];
        if !between.contains("mod") {
            out.push_str(&rest[..m + "#[cfg(test)]".len()]);
            rest = &rest[m + "#[cfg(test)]".len()..];
            continue;
        }
        let brace = m + brace_rel;
        let body = balanced(rest, brace);
        out.push_str(&rest[..m]);
        rest = &rest[m + body.len()..];
    }
}

/// Collect production `.rs` files under the scan roots.
fn collect_files(root: &Path) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
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
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if !matches!(name.as_str(), ".git" | "target" | "node_modules") {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if !is_test_path(&rel) {
                        files.push((path, rel));
                    }
                }
            }
        }
    }
    if files.is_empty() {
        return Err(format!(
            "no production .rs files found under {}",
            root.display()
        ));
    }
    Ok(files)
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

/// Doc comment lines immediately above `at`, mirroring the shell gate which
/// iterates `src[:at].splitlines()[:-1]` (the last line holds the tail of the
/// `fn` line itself and must not be inspected).
fn doc_above(src: &str, at: usize) -> String {
    let before = &src[..at];
    let lines: Vec<&str> = before.lines().collect();
    let mut doc: Vec<&str> = Vec::new();
    for line in lines[..lines.len().saturating_sub(1)].iter().rev() {
        let t = line.trim();
        if t.starts_with("///") || t.starts_with("//") {
            doc.push(t);
        } else if !t.starts_with('#') && !t.is_empty() {
            break;
        }
    }
    doc.reverse();
    doc.join("\n")
}

/// Does the `fn name(` line return `Result<`?
fn is_result_fn(line: &str) -> bool {
    let t = line.trim_start();
    if !t.starts_with("fn ") {
        return false;
    }
    t.contains("-> Result<")
}

/// The shell regex is `self\s*\.\s*\w+\s*\.\s*remove\(`: a `self` receiver
/// followed by exactly one identifier then `.remove(`. A local variable like
/// `map.remove(` (where `map` came from `self.inner.write()`) must NOT count,
/// so the match is the full `self.<word>.remove(` chain, not just any
/// `self.` in the window.
fn receiver_is_self(lines: &[&str], idx: usize) -> bool {
    let lo = idx.saturating_sub(2);
    let window: String = lines[lo..=idx]
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" ");
    let w = window.as_bytes();
    let mut i = 0;
    while i + 5 <= w.len() {
        // "self"
        if &w[i..i + 4] == b"self"
            && (i + 4 == w.len() || !w[i + 4].is_ascii_alphanumeric() && w[i + 4] != b'_')
        {
            // optional whitespace then '.'
            let mut j = i + 4;
            while j < w.len() && (w[j] == b' ' || w[j] == b'\t') {
                j += 1;
            }
            if j >= w.len() || w[j] != b'.' {
                i += 4;
                continue;
            }
            j += 1;
            while j < w.len() && (w[j] == b' ' || w[j] == b'\t') {
                j += 1;
            }
            // one identifier
            let id_start = j;
            while j < w.len() && (w[j].is_ascii_alphanumeric() || w[j] == b'_') {
                j += 1;
            }
            if j == id_start {
                i += 4;
                continue;
            }
            while j < w.len() && (w[j] == b' ' || w[j] == b'\t') {
                j += 1;
            }
            if j >= w.len() || w[j] != b'.' {
                i += 4;
                continue;
            }
            j += 1;
            while j < w.len() && (w[j] == b' ' || w[j] == b'\t') {
                j += 1;
            }
            // "remove("
            if w[j..].starts_with(b"remove(") {
                return true;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    false
}

/// # Errors
///
/// Returns a finding per offender, or a vacuity failure.
pub fn run(root: &Path) -> Result<String, String> {
    let files = collect_files(root)?;

    let mut problems: Vec<String> = Vec::new();
    let mut checked_fns = 0usize;

    for (path, rel) in &files {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {rel}: {e}"))?;
        let src = strip_test_mods(&raw);
        let mut rest = src.as_str();
        let mut offset = 0usize;
        while let Some(rel_pos) = rest.find("fn ") {
            let abs = offset + rel_pos;
            // Parse the fn signature until `{`.
            let after = &rest[rel_pos..];
            let Some(open_rel) = after.find('{') else {
                break;
            };
            let sig = &after[..open_rel];
            if !is_result_fn(sig) {
                rest = &after[open_rel + 1..];
                offset = abs + open_rel + 1;
                continue;
            }
            // Name.
            let name_start = sig.find("fn ").unwrap() + 3;
            let name: String = sig[name_start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let brace = abs + open_rel;
            let body = balanced(&src, brace);
            let lines: Vec<&str> = body.lines().collect();

            let removes: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(i, l)| {
                    !l.trim_start().starts_with("//")
                        && l.contains(".remove(")
                        && receiver_is_self(&lines, *i)
                })
                .map(|(i, _)| i)
                .collect();
            if removes.is_empty() {
                rest = &after[open_rel + 1..];
                offset = abs + open_rel + 1;
                continue;
            }
            checked_fns += 1;
            let first_remove = removes[0];
            let later_err: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(i, l)| {
                    *i > first_remove
                        && !l.trim_start().starts_with("//")
                        && l.contains("return Err(")
                })
                .map(|(i, _)| i)
                .collect();
            let guarded = |err_line: usize| -> bool {
                (first_remove + 1..err_line).any(|i| {
                    !lines[i].trim_start().starts_with("//") && lines[i].contains(".insert(")
                })
            };
            let unguarded: Vec<usize> =
                later_err.iter().copied().filter(|e| !guarded(*e)).collect();
            let restored = unguarded.is_empty();
            let declared = doc_above(&src, abs).contains("PARTIAL: allowed");

            if restored && !declared {
                // ok
            } else if declared && later_err.is_empty() {
                // declared but no later err: ok
            } else if !restored && !declared {
                let line_no = src[..brace].matches('\n').count() + 1 + first_remove + 1;
                problems.push(format!(
                    "{rel}:{line_no}: `{name}` removes from a `self.` collection and \
                     can still `return Err` afterwards, with nothing putting the value \
                     back. The caller is told the call failed while the entry is gone, \
                     and nothing rolls it back. Decide every refusal before the remove, \
                     restore it on the failing path, or write `PARTIAL: allowed - \
                     <reason>` in the function's doc."
                ));
            }
            rest = &after[open_rel + 1..];
            offset = abs + open_rel + 1;
        }
    }

    if checked_fns == 0 {
        return Err(String::from(
            "gate found no Result-returning fn that removes from a collection - \
             wrong root, or the pattern changed shape.",
        ));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "partial-write gate OK: {checked_fns} Result-returning fns remove from a \
         collection, each deciding its refusals first, restoring on failure, or \
         declaring why a partial write is allowed"
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
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-refusals-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(dir.join("src"));
    let _ = std::fs::create_dir_all(dir.join("budzero"));
    let _ = std::fs::create_dir_all(dir.join("wallet-core"));

    // Good: refusal before remove, or insert after.
    let good = "fn f(&mut self) -> Result<(), E> {\n    if !self.valid() { return Err(E::X); }\n    self.m.remove(&k);\n    Ok(())\n}\nfn g(&mut self) -> Result<(), E> {\n    let v = self.m.remove(&k)?;\n    let r = do_work()?;\n    self.m.insert(k, v);\n    Ok(())\n}\n";
    std::fs::write(dir.join("src/lib.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a good module was refused"));
    }

    // Bad: remove then Err with no insert.
    let bad = "fn f(&mut self) -> Result<(), E> {\n    self.m.remove(&k);\n    if !self.valid() { return Err(E::X); }\n    Ok(())\n}\n";
    std::fs::write(dir.join("src/lib.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: remove sonrasi Err gecti"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "refusals canary OK (good PASSes, a partial write FAILs).",
    ))
}
