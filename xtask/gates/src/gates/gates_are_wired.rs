//! Every `scripts/check-*.sh` still in the tree must actually run somewhere.
//!
//! Ported from `scripts/check-gates-are-wired.sh`.
//!
//! # The failure this closes
//!
//! A script in `scripts/` that no workflow invokes proves nothing about any
//! commit, but it still shows up when someone counts the gates. Four of them
//! had accumulated that way (`check-bloat.sh`, `check-kani.sh`,
//! `check-machete.sh`, `check-taplo.sh`, all added in one commit), and three
//! duplicated work that `extra-tooling.yml` was already doing properly with
//! pinned tool versions and real canaries.
//!
//! This gate closes the door behind them: a new `scripts/check-*.sh` has to be
//! referenced by a workflow, or CI fails and says so by name.
//!
//! # What counts as wired
//!
//! The shell version accumulated three corrections, and they are all kept:
//!
//! * Only executable workflow `run:` content counts. Metadata fields like
//!   workflow/job `name:` and regex metacharacters in a basename must not
//!   satisfy the gate, so the `run:` blocks (inline and folded `|`/`>`) are
//!   extracted and comments dropped.
//! * A mention inside a here-document body is data, not an invocation.
//! * A mention in an assignment or an argument to another script is not
//!   execution. A line counts only when its command position invokes an
//!   interpreter (`bash`/`sh`/`dash`/`zsh`) on the script path, and only the
//!   repository's own `scripts/<name>` (optionally under the CI `current/`
//!   checkout prefix used by semver.yml) satisfies the gate.

use std::path::Path;

/// The interpreters whose invocation of a script counts as execution.
const SHELLS: &[&str] = &["bash", "sh", "dash", "zsh"];

/// A line whose first non-space character is `#` is a comment.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// The first non-space character, as awk's `match($0, /[^ ]/) - 1`.
///
/// awk's `[^ ]` excludes only the literal space, so a tab counts as
/// non-space and its position is the line's indent.
fn first_non_space(line: &str) -> Option<usize> {
    line.find(|c: char| c != ' ')
}

/// Does this line start a folded `run: |` / `run: >` block?
///
/// Returns the block's indent (the position of the `-`, if any) so the body
/// lines can be told from the next key.
fn folded_run_start(line: &str) -> Option<usize> {
    let indent = first_non_space(line)?;
    let stripped = line.trim_start();
    let after_dash = stripped.strip_prefix('-').unwrap_or(stripped);
    let rest = after_dash.trim_start().strip_prefix("run:")?;
    let rest = rest.trim_start();
    let mut chars = rest.chars();
    if !matches!(chars.next(), Some('|' | '>')) {
        return None;
    }
    if chars.all(char::is_whitespace) {
        Some(indent)
    } else {
        None
    }
}

/// Does this line hold an inline `run: ...` command?
fn inline_run(line: &str) -> bool {
    let stripped = line.trim_start();
    let after_dash = stripped.strip_prefix('-').unwrap_or(stripped);
    after_dash.trim_start().starts_with("run:")
}

/// Collect every executable `run:` line out of the workflow files.
///
/// Mirrors the awk extractor of the shell version: comments are dropped,
/// folded block bodies are emitted until a line at or above the block's own
/// indent closes the block.
fn collect_run_content(workflows_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(workflows_dir) else {
        return out;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"))
        })
        .collect();
    files.sort();

    for path in files {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut in_run = false;
        let mut run_indent = 0usize;
        for line in src.lines() {
            if in_run {
                match first_non_space(line) {
                    None => continue, // blank: the block continues, nothing is emitted
                    Some(indent) => {
                        if indent <= run_indent {
                            in_run = false;
                            continue;
                        }
                        if !is_comment(line) {
                            out.push(line.to_string());
                        }
                    }
                }
                continue;
            }
            if is_comment(line) {
                continue;
            }
            if let Some(indent) = folded_run_start(line) {
                in_run = true;
                run_indent = indent;
                continue;
            }
            if inline_run(line) {
                out.push(line.to_string());
            }
        }
    }
    out
}

/// Minimal POSIX-ish word splitter, matching Python's `shlex.split`.
///
/// Returns `None` when quotes are unbalanced, which the shell version treated
/// as an unparsable line and skipped.
fn shlex_split(line: &str) -> Option<Vec<String>> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            '\'' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return None,
                    }
                }
            }
            '"' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\' | '$' | '`' | ' ')) => {
                                // shlex keeps these escapes inside double
                                // quotes: the escaped character is the token.
                                cur.push(c);
                            }
                            Some('\n') => {} // shlex: a line continuation is dropped
                            Some(other) => {
                                cur.push('\\');
                                cur.push(other);
                            }
                            None => return None,
                        },
                        Some(ch) => cur.push(ch),
                        None => return None,
                    }
                }
            }
            '\\' => {
                in_token = true;
                let ch = chars.next()?; // trailing backslash: shlex errors out
                cur.push(ch);
            }
            other => {
                in_token = true;
                cur.push(other);
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }
    Some(tokens)
}

/// Note here-document delimiters opened on this line.
///
/// The body of a here-document is data, not commands, so a script path
/// mentioned only there must not satisfy the gate. Mirrors the
/// `<<-?\s*(['"]?)([^\s'"]+)\1` extraction of the shell version.
fn note_heredocs(line: &str, delims: &mut Vec<String>) {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            let mut j = i + 2;
            if j < bytes.len() && bytes[j] == b'-' {
                j += 1;
            }
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r') {
                j += 1;
            }
            let quote = if j < bytes.len() && matches!(bytes[j], b'\'' | b'"') {
                let q = bytes[j];
                j += 1;
                Some(q)
            } else {
                None
            };
            let start = j;
            while j < bytes.len() {
                let b = bytes[j];
                let closes = match quote {
                    Some(q) => b == q || matches!(b, b' ' | b'\t' | b'\r'),
                    None => matches!(b, b' ' | b'\t' | b'\r' | b'\'' | b'"'),
                };
                if closes {
                    break;
                }
                j += 1;
            }
            if j > start {
                // Delimiters are ASCII here-doc markers, so a byte slice is a
                // character boundary.
                delims.push(line[start..j].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
}

/// The first token after `env`'s own assignments and options.
///
/// `env FAKE=./scripts/x bash ./scripts/y` must not mark `x` as executed.
fn unwrap_env(words: &[String]) -> Vec<String> {
    let mut idx = 1usize;
    while idx < words.len() {
        let token = words[idx].as_str();
        if token == "--" {
            return words[idx + 1..].to_vec();
        }
        if token == "-i" {
            idx += 1;
            continue;
        }
        if token == "-u" || token == "--unset" {
            idx += 2;
            continue;
        }
        if token.starts_with("-u") && token != "-u" {
            idx += 1;
            continue;
        }
        if token.contains('=') && !token.starts_with('-') {
            idx += 1;
            continue;
        }
        return words[idx..].to_vec();
    }
    Vec::new()
}

/// For `bash script args...`, the actual script file.
///
/// `bash -c "..."` executes a string, not a script file, so it yields no
/// target.
fn interpreter_target(words: &[String]) -> Option<String> {
    let mut idx = 1usize;
    while idx < words.len() {
        let token = words[idx].as_str();
        if token == "--" {
            idx += 1;
            break;
        }
        if token == "-c" {
            return None;
        }
        if token.starts_with('-') && token != "-" {
            idx += 1;
            continue;
        }
        break;
    }
    words.get(idx).cloned()
}

/// Is this word the repository's own `scripts/<name>`?
///
/// `./` prefixes are stripped (so `./scripts/x` counts), and the CI `current/`
/// checkout prefix used by semver.yml is accepted. A different directory such
/// as `./other/scripts/check-x.sh` must not satisfy the gate.
fn is_target(word: &str, name: &str) -> bool {
    let mut w = word;
    while let Some(rest) = w.strip_prefix("./") {
        w = rest;
    }
    let target = format!("ops/scripts/{name}");
    if w == target {
        return true;
    }
    if let Some(rest) = w.strip_prefix("current/") {
        return rest == target;
    }
    false
}

fn is_shell(first: &str) -> bool {
    if SHELLS.contains(&first) {
        return true;
    }
    let Some(rest) = first.strip_prefix("/usr/bin/") else {
        return false;
    };
    SHELLS.contains(&rest)
}

/// Does any run line invoke this script by name?
fn is_wired(run_content: &[String], name: &str) -> bool {
    let mut heredoc_delims: Vec<String> = Vec::new();
    for line in run_content {
        let stripped = line.trim();
        if !heredoc_delims.is_empty() {
            if stripped == heredoc_delims[0] {
                heredoc_delims.remove(0);
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        note_heredocs(line, &mut heredoc_delims);
        let Some(mut words) = shlex_split(line) else {
            continue;
        };
        // The extractor prints inline `- run: ...` lines verbatim, so drop
        // the YAML list dash and the `run:` keyword before looking at
        // command position.
        while matches!(words.first().map(String::as_str), Some("-" | "run:")) {
            words.remove(0);
        }
        if words.is_empty() {
            continue;
        }
        let first = words[0].clone();
        let first = if first == "env" {
            let unwrapped = unwrap_env(&words);
            let Some(first) = unwrapped.first().cloned() else {
                continue;
            };
            words = unwrapped;
            first
        } else {
            first
        };
        if !is_shell(&first) {
            continue;
        }
        if let Some(target) = interpreter_target(&words) {
            if is_target(&target, name) {
                return true;
            }
        }
    }
    false
}

/// # Errors
///
/// Scripts that no workflow invokes, or a root that contains no gate scripts
/// at all.
pub fn run(root: &Path) -> Result<String, String> {
    let workflows = root.join(".github/workflows");
    if !workflows.is_dir() {
        return Err(format!("no workflow directory at {}", workflows.display()));
    }

    let run_content = collect_run_content(&workflows);

    let scripts_dir = root.join("ops/scripts");
    let mut found_any = false;
    let mut unwired: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&scripts_dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| is_gate_script_name(n))
            .collect();
        names.sort();
        for name in names {
            found_any = true;
            if !is_wired(&run_content, &name) {
                unwired.push(name);
            }
        }
    }

    // Guard against the gate silently passing on an empty or misnamed tree:
    // a missing scripts directory means the wrong root, while a present but
    // empty one is the correct end state of the Rust migration.
    if !found_any {
        if !scripts_dir.is_dir() {
            return Err(format!(
                "no scripts directory at {} - wrong root?",
                scripts_dir.display()
            ));
        }
        return Ok(String::from(
            "Gate wiring OK: no scripts/check-*.sh remain - every gate is a Rust \
             module in xtask/gates.",
        ));
    }

    if !unwired.is_empty() {
        use std::fmt::Write as _;
        let mut msg = String::from("FAIL: these gate scripts are never invoked by any workflow:\n");
        for name in &unwired {
            let _ = writeln!(msg, "  - {name}");
        }
        msg.push_str(
            "Wire them into .github/workflows/, or delete them. A gate that does \
             not run is not a gate.",
        );
        return Err(msg);
    }

    let total = count_scripts(&scripts_dir);
    Ok(format!(
        "Gate wiring OK: all {total} scripts/check-*.sh are referenced by a workflow."
    ))
}

fn count_scripts(scripts_dir: &Path) -> usize {
    std::fs::read_dir(scripts_dir).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|e| is_gate_script_name(&e.file_name().to_string_lossy()))
            .count()
    })
}

/// Is this file name one of the gate scripts this gate polices?
fn is_gate_script_name(name: &str) -> bool {
    name.starts_with("check-")
        && std::path::Path::new(name)
            .extension()
            .is_some_and(|x| x == "sh")
}

/// Write a fixture tree, run the gate against it and check the verdict.
///
/// `expect_pass` flips the assertion: the orphan and here-document canaries
/// must FAIL, so a pass there is a broken gate.
fn check_fixture(
    script_names: &[&str],
    ci_yml: &str,
    expect_pass: bool,
    label: &str,
) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-wired-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("ops/scripts"));
    let _ = std::fs::create_dir_all(dir.join(".github/workflows"));
    for name in script_names {
        std::fs::write(
            dir.join("ops/scripts").join(name),
            "#!/usr/bin/env bash\ntrue\n",
        )
        .map_err(|e| e.to_string())?;
    }
    std::fs::write(dir.join(".github/workflows/ci.yml"), ci_yml).map_err(|e| e.to_string())?;

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_pass {
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
    // A tree where the only gate is wired must pass, otherwise the negative
    // case below would prove nothing.
    check_fixture(
        &["check-wired-example.sh"],
        "jobs:\n  example:\n    steps:\n      - run: bash ./ops/scripts/check-wired-example.sh\n",
        true,
        "self-test: correctly wired tree failed",
    )?;

    // Add a gate nothing references; the check must notice.
    check_fixture(
        &["check-wired-example.sh", "check-orphan-example.sh"],
        "jobs:\n  example:\n    steps:\n      - run: bash ./ops/scripts/check-wired-example.sh\n",
        false,
        "self-test: gate accepted a tree containing an unwired script",
    )?;

    // A script path mentioned only inside a here-document body is data, not
    // an invocation.
    check_fixture(
        &["check-heredoc-example.sh"],
        "jobs:\n  example:\n    steps:\n      - run: |\n          cat <<EOF\n          bash ./ops/scripts/check-heredoc-example.sh\n          EOF\n",
        false,
        "self-test: gate counted a here-document body as an invocation",
    )?;

    // The end state of the Rust migration: no shell gate left means nothing
    // left to wire, and the gate says so rather than calling it a wrong root.
    check_fixture(
        &[],
        "jobs:\n  example:\n    steps:\n      - run: echo hi\n",
        true,
        "self-test: a tree with no shell gates was rejected",
    )?;

    Ok(String::from(
        "Gate wiring self-test OK (wired PASS, orphan FAIL, heredoc FAIL, empty tree PASS).",
    ))
}
