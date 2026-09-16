//! A `.rs` file no `mod` declares is not code.
//!
//! Ported from `scripts/check-no-orphan-source-files.sh`.
//!
//! # The failure this closes
//!
//! `src/network/proto_bridge.rs` sat in the tree carrying a `pb` module with
//! imports and an `include!`, and nothing declared it: `mod proto_bridge;`
//! appeared in no file, so rustc never read it. Not compiled, not linted, not
//! covered, not counted. Its `pb` module was byte-identical to the one in
//! `proto_conversions.rs`, which is the copy the tree actually uses.
//!
//! An orphan file reads exactly like live code to a human: it has imports, it
//! appears in grep results, it shows up in a review diff. Worse, edits to it
//! are silent: a security fix applied to the wrong copy compiles fine and
//! changes nothing.
//!
//! # What is measured
//!
//! Every `.rs` file under `src/`, `budzero/` and `crates/wallet-core/` must be
//! reachable from a module declaration. Cargo auto-discovers `src/bin/*.rs`
//! and the `tests/`/`benches/`/`examples/` trees, so those are exempt, as are
//! crate roots (`lib.rs`, `main.rs`, `mod.rs`, `build.rs`).
//!
//! The port keeps every correction the shell version accumulated:
//!
//! * `mod child;` resolves against the lexical module path: `mod outer { mod
//!   inner; }` inside `src/lib.rs` names `src/outer/inner.rs`, not
//!   `src/inner.rs`.
//! * `#[path = "..."]` reaches an arbitrary file, relative to the declaring
//!   file's directory, matched by resolved concrete path rather than stem.
//! * Rust block comments nest, so a flat regex would stop at the first `*/`;
//!   a depth counter walks them instead.
//! * Raw strings (`r"..."`, `br"..."`) and normal strings and chars are
//!   blanked (preserving line structure) so braces and `mod` keywords inside
//!   them cannot perturb module scope tracking.
//!
//! # The second failure this closes
//!
//! Declaration is not reachability. The check above asks "does some file
//! declare this one", and `mod.rs` is exempt from being asked. So an entire
//! directory could sit unreachable from any crate root and stay invisible:
//! its `mod.rs` was exempt by name, and its siblings counted as declared
//! because that same unreachable `mod.rs` declared them. A ring of files
//! vouching for each other passes a per-file check.
//!
//! `src/account_abstraction/` was exactly this: five files, 493 lines,
//! declared in no crate root. It never compiled. Measured, not guessed:
//! invalid Rust was written into `threshold_mldsa.rs` and `cargo check --lib`
//! still passed. Inside it, three functions named like security checks could
//! not reject anything -- one compared the length of a fixed-size array
//! against its own length, a condition false at compile time.
//!
//! So the gate now also walks *from* the crate roots (`lib.rs`, `main.rs`,
//! `build.rs`, and the auto-discovered target directories) through `mod`
//! declarations, and reports any file the walk never arrives at. A file must
//! be both declared and reached.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

/// Roots holding shipped library code.
const SCAN_ROOTS: &[&str] = &["src", "budzero", "wallet-core"];

// ---------------------------------------------------------------------------
// Sanitizing: blank comments and literals so they cannot be read as code.
// ---------------------------------------------------------------------------

/// Blank line comments (`//` to end of line).
///
/// The shell version runs `//[^\n]*` over the raw text before any literal is
/// stripped, so a `//` inside a string is removed here too. That quirk is
/// kept for parity: what matters downstream is that braces and `mod` words
/// inside the commented region stop counting.
fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    out
}

/// Blank Rust block comments, which nest.
///
/// A flat non-greedy match stops at the first `*/` and leaves the tail of the
/// outer comment looking like executable code. A depth counter handles
/// `/* outer /* inner */ tail */`.
fn strip_block_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut depth = 0usize;
    let n = chars.len();
    while i < n {
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            depth += 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < n && chars[i] == '*' && chars[i + 1] == '/' {
            depth -= 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 {
            out.push(if chars[i] == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn blank_chars(chars: &[char]) -> String {
    chars
        .iter()
        .map(|&c| if c == '\n' { '\n' } else { ' ' })
        .collect()
}

/// Blank raw strings (`r"..."`, `br"..."`, `rb"..."` with `#` delimiters).
///
/// Delimiter-aware, so a quote inside the body does not end the string early.
fn strip_raw_strings(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let step = if (chars[i] == 'b' && i + 1 < n && chars[i + 1] == 'r')
            || (chars[i] == 'r' && i + 1 < n && chars[i + 1] == 'b')
        {
            2
        } else if chars[i] == 'r' {
            1
        } else {
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let mut j = i + step;
        let hash_start = j;
        while j < n && chars[j] == '#' {
            j += 1;
        }
        if j >= n || chars[j] != '"' {
            // Not a raw string after all: emit the first char and retry.
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let closing: String = std::iter::once('"')
            .chain(chars[hash_start..j].iter().copied())
            .collect();
        let closing_len = closing.chars().count();
        let mut end = None;
        let mut k = j + 1;
        while k + closing_len <= n {
            let cand: String = chars[k..k + closing_len].iter().collect();
            if cand == closing {
                end = Some(k);
                break;
            }
            k += 1;
        }
        let Some(end) = end else {
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let span_end = end + closing_len;
        out.push_str(&blank_chars(&chars[i..span_end]));
        i = span_end;
    }
    out
}

/// Blank normal string literals and char literals.
///
/// Mirrors `b?"(?:\\.|[^"\\])*"` for strings and `b?'(?:\\.|[^'\\])'` for
/// chars: a string holds any number of escaped or plain characters, a char
/// literal holds exactly one.
fn strip_quoted(text: &str, quote: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        let start = if c == quote || (c == 'b' && i + 1 < n && chars[i + 1] == quote) {
            Some(i)
        } else {
            None
        };
        let Some(start) = start else {
            out.push(c);
            i += 1;
            continue;
        };
        let content_start = start + 1 + usize::from(chars[start] == 'b');
        let mut ok = false;
        let mut close_at = 0usize;
        if quote == '\'' {
            if content_start < n {
                let item_end = if chars[content_start] == '\\' {
                    if content_start + 1 < n {
                        content_start + 2
                    } else {
                        content_start + 1
                    }
                } else {
                    content_start + 1
                };
                if item_end < n && chars[item_end] == '\'' {
                    ok = true;
                    close_at = item_end;
                }
            }
        } else {
            let mut j = content_start;
            while j < n {
                match chars[j] {
                    '\\' => {
                        if j + 1 < n {
                            j += 2;
                        } else {
                            break;
                        }
                    }
                    '"' => {
                        ok = true;
                        close_at = j;
                        break;
                    }
                    _ => j += 1,
                }
            }
        }
        if !ok {
            out.push(chars[start]);
            i = start + 1;
            continue;
        }
        out.push_str(&blank_chars(&chars[start..=close_at]));
        i = close_at + 1;
    }
    out
}

/// Blank comments and literals, preserving line structure.
fn sanitize(text: &str) -> String {
    let t = strip_line_comments(text);
    let t = strip_block_comments(&t);
    let t = strip_raw_strings(&t);
    let t = strip_quoted(&t, '"');
    strip_quoted(&t, '\'')
}

// ---------------------------------------------------------------------------
// Module declarations.
// ---------------------------------------------------------------------------

/// The identifier characters `[A-Za-z0-9_]+`.
fn match_name(rest: &str) -> Option<&str> {
    let end = rest
        .char_indices()
        .take_while(|&(_, c)| c.is_ascii_alphanumeric() || c == '_')
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    Some(&rest[..end])
}

/// Match `mod NAME;` (`inline` false) or `mod NAME {` (`inline` true),
/// mirroring `^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+NAME\s*[;{]`.
fn mod_decl_name(line: &str, inline: bool) -> Option<&str> {
    let rest = line.trim_start();
    let rest = if let Some(r) = rest.strip_prefix("pub") {
        // Optional `(...)`, then a required run of whitespace.
        let r = if let Some(inner) = r.strip_prefix('(') {
            let close = inner.find(')')?;
            &inner[close + 1..]
        } else {
            r
        };
        let ws = r.len() - r.trim_start().len();
        if ws == 0 {
            return None;
        }
        r.trim_start()
    } else {
        rest
    };
    let after_mod = rest.strip_prefix("mod")?;
    if after_mod.len() == after_mod.trim_start().len() {
        return None; // `mod` needs a following whitespace run
    }
    let after_mod = after_mod.trim_start();
    let name = match_name(after_mod)?;
    let tail = after_mod[name.len()..].trim_start();
    let wanted = if inline { '{' } else { ';' };
    if tail.starts_with(wanted) {
        Some(name)
    } else {
        None
    }
}

/// Yield `(scope, name)` for every `mod X;` declaration, tracking inline
/// `mod Y { ... }` scopes lexically so a declaration resolves against the
/// active module path.
fn iter_nested_mod_decls(text: &str) -> Vec<(Vec<String>, String)> {
    let sanitized = sanitize(text);
    let mut scope: Vec<Option<String>> = Vec::new();
    let mut out = Vec::new();
    for line in sanitized.split('\n') {
        let mut rest = line.trim_start();
        // A leading `}` closes the innermost open block scope.
        while rest.starts_with('}') {
            scope.pop();
            rest = rest[1..].trim_start();
        }
        let inline_name = mod_decl_name(line, true);
        let mut opens = rest.chars().filter(|&c| c == '{').count();
        if let Some(name) = inline_name {
            scope.push(Some(name.to_string()));
            // The inline `mod X {` brace is the module scope itself.
            opens = opens.saturating_sub(1);
        }
        if let Some(name) = mod_decl_name(line, false) {
            let sc: Vec<String> = scope.iter().flatten().cloned().collect();
            out.push((sc, name.to_string()));
        }
        // Balance braces that open later on the same line: non-module blocks
        // push a guard so their closing brace pops a guard, not a module
        // name.
        let closes = rest.chars().filter(|&c| c == '}').count();
        if opens > closes {
            for _ in 0..(opens - closes) {
                scope.push(None);
            }
        } else if closes > opens {
            for _ in 0..(closes - opens) {
                scope.pop();
            }
        }
    }
    out
}

/// Resolve `#[path = "..."]` targets out of a file's text.
///
/// Mirrors `#\[\s*path\s*=\s*"([^"]+)"\s*\]`, per line in practice.
fn path_attr_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let rest = line.trim_start();
        let Some(rest) = rest.strip_prefix("#[") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("path") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        let content = &rest[..end];
        let tail = rest[end + 1..].trim_start();
        if tail.starts_with(']') && !content.is_empty() {
            out.push(content.to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// File collection and path resolution.
// ---------------------------------------------------------------------------

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn walk(dir: &Path, root: &Path, files: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let Ok(p_kind) = e.file_type() else {
            continue;
        };
        let p = e.path();
        if p_kind.is_dir() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&p, root, files);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            files.push((p, rel));
        }
    }
}

/// Cargo discovers these without a `mod` declaration.
fn exempt(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts
        .last()
        .is_some_and(|b| matches!(*b, "lib.rs" | "main.rs" | "mod.rs" | "build.rs"))
    {
        return true;
    }
    // Cargo auto-discovers targets in these directories without any `mod`:
    // `<crate>/src/bin/*.rs` binaries, `<crate>/tests/*.rs` integration
    // tests, `<crate>/benches/*.rs` benchmarks, `<crate>/examples/*.rs`
    // examples. The first form sits under src/; the other three are siblings
    // of it.
    for i in 0..parts.len().saturating_sub(1) {
        let p = parts[i];
        if p == "bin" && i > 0 && parts[i - 1] == "src" {
            return true;
        }
        if matches!(p, "tests" | "benches" | "examples") {
            return true;
        }
    }
    false
}

/// A crate root: the compiler starts here without anyone declaring it.
///
/// `mod.rs` is deliberately absent. A `mod.rs` is only a root of its own
/// directory, and whether that directory is reached is the question being
/// asked; treating it as a root assumes the answer.
fn is_crate_root(rel: &str) -> bool {
    let Some(base) = rel.rsplit('/').next() else {
        return false;
    };
    if matches!(base, "lib.rs" | "main.rs" | "build.rs") {
        return true;
    }
    // Cargo builds these as targets in their own right.
    let parts: Vec<&str> = rel.split('/').collect();
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i] == "bin" && i > 0 && parts[i - 1] == "src" {
            return true;
        }
        if matches!(parts[i], "tests" | "benches" | "examples") {
            return true;
        }
    }
    false
}

/// Files reachable from the crate roots by following `mod` declarations.
///
/// Breadth-first from every root. `edges` maps a file to the files it
/// declares; a file absent from the result is one rustc never opens, however
/// many other files name it.
fn reachable_from_roots(
    files: &[(PathBuf, String)],
    edges: &BTreeMap<PathBuf, Vec<PathBuf>>,
) -> BTreeSet<PathBuf> {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();
    for (full, rel) in files {
        if is_crate_root(rel) {
            let n = normalize(full);
            if seen.insert(n.clone()) {
                queue.push(n);
            }
        }
    }
    while let Some(cur) = queue.pop() {
        let Some(children) = edges.get(&cur) else {
            continue;
        };
        for child in children {
            if seen.insert(child.clone()) {
                queue.push(child.clone());
            }
        }
    }
    seen
}

fn count_lines(p: &Path) -> usize {
    std::fs::read_to_string(p).map_or(0, |s| s.lines().count())
}

/// Resolve `mod X;` and `#[path]` declarations in one file to concrete paths.
fn declared_paths_for(text: &str, full: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = full.parent().unwrap_or_else(|| Path::new(""));
    let fname = full
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    for (scope, name) in iter_nested_mod_decls(text) {
        // `mod.rs`, `lib.rs` and `main.rs` are all crate roots: children
        // resolve next to them (`src/ast.rs`), while a child of a non-root
        // parent (`src/foo.rs`) resolves into a directory named after the
        // parent (`src/foo/child.rs`).
        let module_dir = if matches!(fname.as_str(), "mod.rs" | "lib.rs" | "main.rs") {
            join_scope(dir, &scope)
        } else {
            let stem = fname.rsplit_once('.').map_or(fname.as_str(), |(s, _)| s);
            join_scope(&dir.join(stem), &scope)
        };
        out.push(normalize(&module_dir.join(format!("{name}.rs"))));
        out.push(normalize(&module_dir.join(name).join("mod.rs")));
    }
    out
}

fn join_scope(dir: &Path, scope: &[String]) -> PathBuf {
    let mut out = dir.to_path_buf();
    for s in scope {
        out.push(s);
    }
    out
}

/// # Errors
///
/// `.rs` files that no `mod` declares, or a root that contains no `.rs` files
/// at all.
pub fn run(root: &Path) -> Result<String, String> {
    let src = root.join("src");
    if !src.is_dir() {
        return Err(format!(
            "no src directory at {} - wrong root?",
            src.display()
        ));
    }

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    let mut declared: BTreeSet<PathBuf> = BTreeSet::new();
    let mut path_targets: BTreeSet<PathBuf> = BTreeSet::new();

    for sub in SCAN_ROOTS {
        let base = root.join(sub);
        if !base.is_dir() {
            continue;
        }
        walk(&base, root, &mut files);
    }

    let mut edges: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

    for (full, _rel) in &files {
        let text = std::fs::read_to_string(full).unwrap_or_default();
        let from = normalize(full);
        for p in declared_paths_for(&text, full) {
            declared.insert(p.clone());
            edges.entry(from.clone()).or_default().push(p);
        }
        for target in path_attr_targets(&text) {
            let target_path =
                normalize(&full.parent().unwrap_or_else(|| Path::new("")).join(target));
            path_targets.insert(target_path.clone());
            edges.entry(from.clone()).or_default().push(target_path);
        }
    }

    if files.is_empty() {
        return Err(String::from(
            "FAIL: no .rs files found - wrong root, the gate would be vacuous",
        ));
    }

    let mut orphans: Vec<String> = Vec::new();
    for (full, rel) in &files {
        if exempt(rel) {
            continue;
        }
        let abs_path = normalize(full);
        if !declared.contains(&abs_path) && !path_targets.contains(&abs_path) {
            let lines = count_lines(full);
            orphans.push(format!("{rel}  ({lines} lines)"));
        }
    }

    // Second check: reachability from the crate roots. A file can be declared
    // by a sibling and still never be opened by rustc, if the declaring file
    // is itself unreachable. `mod.rs` is exempt above by name, which is what
    // let a whole unreachable directory hide behind its own `mod.rs`.
    let reachable = reachable_from_roots(&files, &edges);
    let mut unreachable: Vec<String> = Vec::new();
    for (full, rel) in &files {
        if exempt(rel) && !rel.ends_with("mod.rs") {
            continue;
        }
        let abs_path = normalize(full);
        if reachable.contains(&abs_path) {
            continue;
        }
        // Already named as an orphan; do not report the same file twice.
        if !declared.contains(&abs_path) && !path_targets.contains(&abs_path) && !exempt(rel) {
            continue;
        }
        let lines = count_lines(full);
        unreachable.push(format!("{rel}  ({lines} lines)"));
    }

    if !unreachable.is_empty() {
        let mut msg = String::from(
            "FAIL: these .rs files are not reachable from any crate root and are not compiled:\n",
        );
        for o in &unreachable {
            let _ = writeln!(msg, "  - {o}");
        }
        msg.push_str(
            "\nA `mod` somewhere declares them, but nothing declares that declarer, so rustc\n\
             never opens any of them. A ring of files declaring each other is still dead code:\n\
             not linted, not covered, not tested, while reading as live code in grep and review.\n\
             Declare the directory from a crate root or delete it.",
        );
        return Err(msg);
    }

    if !orphans.is_empty() {
        let mut msg =
            String::from("FAIL: these .rs files are declared by no `mod` and are not compiled:\n");
        for o in &orphans {
            let _ = writeln!(msg, "  - {o}");
        }
        msg.push_str(
            "\nrustc never reads them, so they are not linted, not covered and not tested,\n\
             while reading exactly like live code in grep and in review. Declare the module\n\
             or delete the file.",
        );
        return Err(msg);
    }

    Ok(format!(
        "Orphan-file gate OK: all {} .rs files are declared by a `mod` and reachable \
         from a crate root.",
        files.len()
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the ten canaries of the shell version.
// ---------------------------------------------------------------------------

/// Write a fixture tree, run the gate, check the verdict.
fn check_fixture(files: &[(&str, &str)], expect_ok: bool, label: &str) -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-orphan")?;
    for (rel, content) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
    }

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. The case that shipped: a file nothing declares.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod real;\n"),
            ("src/real.rs", "pub fn a() {}\n"),
            ("src/proto_bridge.rs", "pub fn ghost() {}\n"),
        ],
        false,
        "an undeclared file was accepted",
    )?;

    // 2. A tree where everything is declared must pass.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod real;\n"),
            ("src/real.rs", "pub fn a() {}\n"),
        ],
        true,
        "a fully declared tree was rejected",
    )?;

    // 3. `src/bin/*.rs` is auto-discovered by Cargo and must not be flagged.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod real;\n"),
            ("src/real.rs", "pub fn a() {}\n"),
            ("src/bin/tool.rs", "fn main() {}\n"),
        ],
        true,
        "src/bin/*.rs was flagged as an orphan",
    )?;

    // 4. A nested module declared from its parent must pass.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod deep;\n"),
            ("src/deep/mod.rs", "pub mod inner;\n"),
            ("src/deep/inner.rs", "pub fn a() {}\n"),
        ],
        true,
        "a nested declared module was flagged",
    )?;

    // 5. `#[path = "..."]` reaches a file that no plain `mod name;` names.
    check_fixture(
        &[
            ("src/lib.rs", "#[path = \"renamed.rs\"]\npub mod alias;\n"),
            ("src/renamed.rs", "pub fn a() {}\n"),
        ],
        true,
        "a #[path]-attached file was flagged as an orphan",
    )?;

    // 6. A missing src must fail rather than pass by default.
    check_fixture(&[], false, "a tree with no src was accepted")?;

    // 7. Inline nested modules resolve against the lexical module path:
    //    `mod outer { mod inner; }` names src/outer/inner.rs, so a bare
    //    src/inner.rs must stay an orphan.
    check_fixture(
        &[
            ("src/lib.rs", "mod outer {\n    mod inner;\n}\n"),
            ("src/inner.rs", "pub fn ghost() {}\n"),
        ],
        false,
        "an inline-nested declaration satisfied a file outside the lexical scope",
    )?;

    // 8. The same inline nesting with the file in the real location passes.
    check_fixture(
        &[
            ("src/lib.rs", "mod outer {\n    mod inner;\n}\n"),
            ("src/outer/inner.rs", "pub fn a() {}\n"),
        ],
        true,
        "an inline-nested module at its real path was flagged",
    )?;

    // 9. Nested Rust block comments must not perturb module scope tracking:
    //    a `}` inside `/* ... /* ... */ ... */` is comment text, not a scope
    //    close.
    check_fixture(
        &[
            (
                "src/lib.rs",
                "mod outer {\n    /* x /* y */ } */\n    mod inner;\n}\n",
            ),
            ("src/inner.rs", "pub fn ghost() {}\n"),
        ],
        false,
        "a nested block comment perturbed module scope tracking",
    )?;

    // 10. The same nesting with the file at the real path passes.
    check_fixture(
        &[
            (
                "src/lib.rs",
                "mod outer {\n    /* x /* y */ } */\n    mod inner;\n}\n",
            ),
            ("src/outer/inner.rs", "pub fn a() {}\n"),
        ],
        true,
        "a nested comment next to a real module declaration was flagged",
    )?;

    // 11. The blind spot itself: a directory nothing declares, whose `mod.rs`
    //     declares its own children. Every child is "declared", the `mod.rs`
    //     is exempt by name, and the whole directory is still dead code.
    //     This is `src/account_abstraction/` as it stood.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod real;\n"),
            ("src/real.rs", "pub fn a() {}\n"),
            ("src/ghost/mod.rs", "pub mod inner;\n"),
            ("src/ghost/inner.rs", "pub fn ghost() {}\n"),
        ],
        false,
        "an unreachable directory hid behind its own mod.rs",
    )?;

    // 12. The same directory, declared from the crate root, must pass.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod real;\npub mod ghost;\n"),
            ("src/real.rs", "pub fn a() {}\n"),
            ("src/ghost/mod.rs", "pub mod inner;\n"),
            ("src/ghost/inner.rs", "pub fn a() {}\n"),
        ],
        true,
        "a directory declared from the crate root was flagged",
    )?;

    // 13. Reachability must survive a chain, not just one hop.
    check_fixture(
        &[
            ("src/lib.rs", "pub mod a;\n"),
            ("src/a/mod.rs", "pub mod b;\n"),
            ("src/a/b/mod.rs", "pub mod c;\n"),
            ("src/a/b/c.rs", "pub fn a() {}\n"),
        ],
        true,
        "a three-deep declared chain was flagged",
    )?;

    Ok(String::from(
        "orphan-file gate self-test OK: undeclared file, missing src, \
         out-of-scope inline nesting, nested-comment scope perturbation and \
         a directory hiding behind its own mod.rs all rejected; declared, \
         nested, #[path], src/bin, inline-nested, comment-adjacent and \
         three-deep chained modules all pass.",
    ))
}
