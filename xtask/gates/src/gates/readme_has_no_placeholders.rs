//! Neither README may carry a template placeholder.
//!
//! Directive appendix A and B write their variable parts as `{{...}}` tokens and
//! say each one must be filled from its source: the toolchain from
//! `rust-toolchain.toml`, the test count from a CI run, the venue from the team
//! decision, the rehearsal numbers from the rehearsal record. A token that
//! survives into the tree is a page telling a reader that nobody filled it in.
//!
//! The gate is deliberately about the token and not about the value. Rule 0.5
//! of the directive forbids writing a number no run produced, so the honest
//! fill for a source that does not exist yet is a sentence, not a number. This
//! gate only refuses the token.

use std::fmt::Write as _;
use std::path::Path;

/// The two pages the directive requires to be placeholder free.
const PAGES: &[&str] = &["README.md", "README.tr.md"];

/// A page shorter than this is not a page; refusing it prevents a vacuous pass.
const MIN_LINES: usize = 100;

/// Every placeholder token in `text`, with its 1-based line number.
fn tokens(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find("{{") {
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                out.push((i + 1, rest[open..].to_string()));
                break;
            };
            out.push((i + 1, rest[open..open + 2 + close + 2].to_string()));
            rest = &after[close + 2..];
        }
    }
    out
}

fn check_page(root: &Path, name: &str) -> Result<usize, String> {
    let path = root.join(name);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
    let lines = text.lines().count();
    if lines < MIN_LINES {
        return Err(format!(
            "{name} has {lines} line(s), below the {MIN_LINES} this gate needs before an absence means anything"
        ));
    }
    let found = tokens(&text);
    if found.is_empty() {
        return Ok(lines);
    }
    let mut report = String::new();
    for (line, token) in &found {
        let _ = writeln!(report, "  {name}:{line}: {token}");
    }
    Err(report)
}

/// # Errors
///
/// Returns every surviving placeholder with its file and line.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = String::new();
    let mut lines = 0usize;
    for page in PAGES {
        match check_page(root, page) {
            Ok(n) => lines += n,
            Err(e) => problems.push_str(&e),
        }
    }
    if problems.is_empty() {
        Ok(format!(
            "OK: no placeholder token in either README ({lines} line(s) read)."
        ))
    } else {
        Err(format!(
            "FAIL: a placeholder survived into a page a reader sees. Fill it from its source, or write what is true while the source does not exist:\n{problems}"
        ))
    }
}

fn scratch_dir() -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum-readme-placeholders-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

fn page(body: &str) -> String {
    let mut s = String::new();
    for _ in 0..MIN_LINES {
        s.push_str("a line of the page\n");
    }
    s.push_str(body);
    s
}

/// # Errors
///
/// The self-test fails when a placeholder is accepted.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;

    std::fs::write(tmp.join("README.md"), page("no token here\n"))
        .map_err(|e| format!("cannot write README.md: {e}"))?;
    std::fs::write(tmp.join("README.tr.md"), page("burada da yok\n"))
        .map_err(|e| format!("cannot write README.tr.md: {e}"))?;
    if let Err(msg) = run(&tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("canary: a page without a token was rejected: {msg}"));
    }

    std::fs::write(
        tmp.join("README.md"),
        page("Rust {{toolchain:rust}} is pinned in rust-toolchain.toml.\n"),
    )
    .map_err(|e| format!("cannot write README.md: {e}"))?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a placeholder was accepted"));
    }

    // A half token is still a token: an unclosed `{{` means an edit went wrong.
    std::fs::write(tmp.join("README.md"), page("Genesis {{genesis:hash and time\n"))
        .map_err(|e| format!("cannot write README.md: {e}"))?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an unclosed token was accepted"));
    }

    // A stub page must not pass by having nothing to scan.
    std::fs::write(tmp.join("README.md"), "short\n")
        .map_err(|e| format!("cannot write short README.md: {e}"))?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a stub page was accepted"));
    }

    // A missing page must fail closed.
    std::fs::write(tmp.join("README.md"), page("no token here\n"))
        .map_err(|e| format!("cannot write README.md: {e}"))?;
    let _ = std::fs::remove_file(tmp.join("README.tr.md"));
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a missing page was accepted"));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "readme-has-no-placeholders self-test OK: a filled page passed and a token, an unclosed token, a stub page and a missing page were each caught.",
    ))
}
