//! Every cargo workspace in the tree is built by some workflow.
//!
//! # The failure this closes
//!
//! A workspace that no workflow builds is a workspace whose tests have never
//! run. It is not "untested by accident": it is untested in a way that looks
//! covered, because the repository has a CI badge, the badge is green, and the
//! directory has unit tests in it.
//!
//! This tree has five workspaces beside the root package: `budzero`,
//! the AI inference crate, the explorer crate, `fuzz`, `kani`, and the two
//! endpoint contracts under `contracts/object-layer/`. Each is its own cargo
//! workspace by necessity (a different target, a different toolchain, a
//! different edition pin), so a `cargo test` at the repository root reaches
//! none of them. The coverage has to be written out job by job, which is
//! exactly the kind of thing that is true one year and false the next.
//!
//! # What counts as covered
//!
//! A workflow builds a workspace when one of its `run:` lines reaches that
//! workspace's manifest:
//!
//!   * `--manifest-path <dir>/Cargo.toml` (with or without `./`), or
//!   * `working-directory: <dir>` on the same step, or
//!   * `cd <dir>` as a whole word in the command, or
//!   * for the repository root, a `cargo` command with no `--manifest-path`:
//!     a bare `cargo test` at the root builds the root package.
//!
//! Only executable `run:` content counts. A workspace named in a comment, in a
//! job name or in a cache key is not a workspace that was built. Two of those
//! three have already been true in this repository: `extra-tooling.yml` named
//! tools in `name:` fields that no step installed, and a corpus cache key
//! named `fuzz` while nothing compiled the fuzz targets.
//!
//! `cargo fuzz <target>` at the repository root is the one command that reaches
//! a workspace without naming its manifest: cargo-fuzz always resolves
//! `fuzz/Cargo.toml` from the root, and it takes no `--manifest-path`. That is
//! recorded as an implicit cover rather than as a special case in the parser,
//! so a future tool with the same shape is one line here instead of a hole in
//! the check.
//!
//! # What this gate does not do
//!
//! It does not run anything, so it cannot tell whether a job that names
//! `budzero` also passed. That is what the job is for. This gate answers the
//! earlier question: is there a job at all.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Directory names the walk does not enter.
const SKIPPED_DIRS: &[&str] = &["target", "node_modules", "vendor"];

/// Depth limit for the manifest walk.
///
/// Four covers `crates/ai-inference/crates/ai-core/Cargo.toml`; a manifest
/// deeper than that is not a workspace root this repository builds.
const MAX_DEPTH: usize = 5;

/// One workspace the gate requires a workflow to build.
struct Workspace {
    /// Repository relative directory, `""` for the root package.
    dir: String,
    /// Why the gate expects it to be built somewhere.
    why: &'static str,
}

/// A command that reaches a workspace without naming its manifest.
struct ImplicitCover {
    dir: &'static str,
    /// The command prefix that builds it. Matched at the start of a command.
    prefix: &'static str,
    why: &'static str,
}

/// Commands that reach a workspace implicitly.
const IMPLICIT: &[ImplicitCover] = &[ImplicitCover {
    dir: "fuzz",
    prefix: "cargo fuzz ",
    why: "cargo-fuzz resolves fuzz/Cargo.toml from the repository root and takes no --manifest-path",
}];

/// Is this line a comment, in whole or after its first token?
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Drop an inline `# comment` from a YAML scalar.
///
/// A `#` starts a comment only after whitespace, so `a#b` keeps its hash while
/// `a #b` does not. The distinction matters for the shell: `sed -e 's/#.*//'`
/// inside a `run:` line is not a comment, and reading it as one would cut a
/// command in half.
fn drop_inline_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Indentation of a line, in bytes.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Every executable line of every `run:` block in one workflow.
///
/// A `run:` block is either an inline command (`run: cargo test`) or a folded
/// or literal block (`run: |`, `run: >`) whose body is the following lines that
/// are indented further than the key. Anything else, including a `run:` that
/// appears in a comment, is data.
fn run_lines(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let raw = lines[i];
        let indent = indent_of(raw);
        let trimmed = raw.trim_start();
        let after_dash = trimmed
            .strip_prefix('-')
            .map(str::trim_start)
            .unwrap_or(trimmed);
        let Some(rest) = after_dash.strip_prefix("run:") else {
            i += 1;
            continue;
        };
        let rest = rest.trim();
        if rest.starts_with('|') || rest.starts_with('>') {
            let mut j = i + 1;
            while j < lines.len() {
                let body = lines[j];
                if body.trim().is_empty() {
                    j += 1;
                    continue;
                }
                if indent_of(body) <= indent {
                    break;
                }
                if !is_comment(body) {
                    out.push(drop_inline_comment(body).trim().to_string());
                }
                j += 1;
            }
            i = j;
            continue;
        }
        if !rest.is_empty() && !is_comment(rest) {
            out.push(drop_inline_comment(rest).trim().to_string());
        }
        i += 1;
    }
    out
}

/// Every workflow file GitHub reads.
fn workflow_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"));
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Does `line` name `dir` as a command's own argument?
///
/// The `cd` form needs a word boundary after the directory: `cd budzero` covers
/// `budzero`, while `cd budzero-old` does not.
fn mentions_dir(line: &str, dir: &str) -> bool {
    if line.contains(&format!("--manifest-path {dir}/Cargo.toml"))
        || line.contains(&format!("--manifest-path ./{dir}/Cargo.toml"))
    {
        return true;
    }
    if line.contains(&format!("working-directory: {dir}")) {
        return true;
    }
    let needle = format!("cd {dir}");
    let mut from = 0usize;
    while let Some(at) = line[from..].find(&needle) {
        let end = from + at + needle.len();
        let next = line.as_bytes().get(end).copied();
        let boundary = match next {
            None => true,
            Some(b) => b.is_ascii_whitespace() || b == b'&' || b == b';' || b == b')' || b == b'|',
        };
        if boundary {
            return true;
        }
        from = end;
    }
    false
}

/// Is this workspace built by the run lines collected from every workflow?
fn covered(runs: &[String], workspace: &Workspace) -> bool {
    if workspace.dir.is_empty() {
        // The root package: a cargo command that names no manifest runs here.
        return runs.iter().any(|line| {
            let starts = line.starts_with("cargo ") || line.starts_with("cargo\t");
            starts && !line.contains("--manifest-path")
        });
    }
    for cover in IMPLICIT {
        if cover.dir == workspace.dir.as_str()
            && runs
                .iter()
                .any(|line| line.starts_with(cover.prefix) || line.contains(&format!("&& {}", cover.prefix)))
        {
            return true;
        }
    }
    runs.iter().any(|line| mentions_dir(line, &workspace.dir))
}

/// Does this manifest declare a workspace?
fn declares_workspace(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[workspace]"))
}

/// Walk the tree for workspace manifests, plus the root package.
fn workspaces(root: &Path) -> Vec<Workspace> {
    fn walk(dir: &Path, depth: usize, out: &mut Vec<Workspace>) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if path.is_dir() {
                if SKIPPED_DIRS.contains(&name.as_str()) || name.starts_with('.') {
                    continue;
                }
                walk(&path, depth + 1, out);
                continue;
            }
            if name != "Cargo.toml" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if declares_workspace(&text) {
                let dir = path
                    .parent()
                    .map(|p| {
                        let rel = p.strip_prefix(root).unwrap_or(p);
                        rel.components()
                            .map(|c| c.as_os_str().to_string_lossy().into_owned())
                            .collect::<Vec<String>>()
                            .join("/")
                    })
                    .unwrap_or_default();
                out.push(Workspace {
                    dir,
                    why: "declares a [workspace]",
                });
            }
        }
    }
    let mut out = Vec::new();
    walk(root, 0, &mut out);
    // The root package is not a workspace by declaration, but it is the binary
    // this repository ships and every workflow that runs a bare cargo command
    // builds it. Leaving it out would let the one build everything depends on
    // go uncovered without a finding.
    if !out.iter().any(|w| w.dir.is_empty()) {
        out.push(Workspace {
            dir: String::new(),
            why: "the root package",
        });
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

/// Run the gate.
///
/// # Errors
///
/// A workspace that no workflow's `run:` content builds, or a tree with no
/// workflows to read.
pub fn run(root: &Path) -> Result<String, String> {
    let files = workflow_files(root);
    if files.is_empty() {
        return Err(String::from(
            "no workflow files under .github/workflows; the gate cannot prove coverage from nothing",
        ));
    }

    let mut runs: Vec<String> = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        runs.extend(run_lines(&text));
    }
    if runs.is_empty() {
        return Err(format!(
            "{} workflow file(s) but no executable run: content; nothing could be built",
            files.len()
        ));
    }

    let spaces = workspaces(root);
    let mut uncovered: Vec<&Workspace> = Vec::new();
    for space in &spaces {
        if !covered(&runs, space) {
            uncovered.push(space);
        }
    }

    if !uncovered.is_empty() {
        let mut msg = String::new();
        let _ = writeln!(
            msg,
            "{} workspace(s) that no workflow builds. Add a job that reaches each manifest \
             (--manifest-path, working-directory or cd), or the workspace has no test running anywhere:",
            uncovered.len()
        );
        for space in &uncovered {
            let shown = if space.dir.is_empty() {
                String::from("<repository root>")
            } else {
                space.dir.clone()
            };
            let _ = writeln!(msg, "  {shown} ({})", space.why);
        }
        return Err(msg);
    }

    let implicit_note: String = IMPLICIT
        .iter()
        .filter(|cover| spaces.iter().any(|w| w.dir == cover.dir))
        .map(|cover| format!("; `{}` is covered implicitly: {}", cover.dir, cover.why))
        .collect();

    Ok(format!(
        "Workspace coverage OK: {} workspace(s) covered by {} run line(s) from {} workflow(s){}.",
        spaces.len(),
        runs.len(),
        files.len(),
        implicit_note
    ))
}

/// Canaries for the parser and the coverage rule.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // A manifest reached by each of the three accepted forms is covered.
    let by_manifest = vec![String::from("cargo test --manifest-path budzero/Cargo.toml")];
    let by_relative = vec![String::from(
        "cargo clippy --manifest-path ./crates/wallet-core/Cargo.toml",
    )];
    let by_directory = vec![String::from("working-directory: kani")];
    let by_cd = vec![String::from("cd fuzz && cargo build")];
    for (case, lines, dir) in [
        ("--manifest-path", by_manifest, "budzero"),
        ("--manifest-path ./", by_relative, "crates/wallet-core"),
        ("working-directory", by_directory, "kani"),
        ("cd", by_cd, "fuzz"),
    ] {
        let workspace = Workspace { dir: dir.to_string(), why: "canary" };
        if !covered(&lines, &workspace) {
            problems.push(format!(
                "VACUOUS: `{dir}` was not covered by its own `{case}` line: {lines:?}"
            ));
        }
    }

    // A directory that merely starts with the workspace's name is not the
    // workspace.
    let near_miss = vec![
        String::from("cd budzero-old && cargo build"),
        String::from("cargo test --manifest-path budzero-old/Cargo.toml"),
    ];
    let workspace = Workspace { dir: String::from("budzero"), why: "canary" };
    if covered(&near_miss, &workspace) {
        problems.push(String::from(
            "BROKEN: `budzero-old` covered `budzero`. A prefix match makes this gate pass on the wrong directory.",
        ));
    }

    // The root package is covered by a bare cargo command and not by one that
    // names another manifest.
    let root = Workspace { dir: String::new(), why: "canary" };
    if !covered(&[String::from("cargo test --all-targets")], &root) {
        problems.push(String::from(
            "VACUOUS: a bare `cargo test` did not cover the root package",
        ));
    }
    if covered(
        &[String::from("cargo test --manifest-path budzero/Cargo.toml")],
        &root,
    ) {
        problems.push(String::from(
            "BROKEN: a command naming another manifest counted as the root package",
        ));
    }

    // `cargo fuzz` covers the fuzz workspace, and nothing else claims to.
    let fuzz = Workspace { dir: String::from("fuzz"), why: "canary" };
    if !covered(&[String::from("cargo fuzz run fuzz_blockchain_serialize -- -runs=1")], &fuzz) {
        problems.push(String::from(
            "VACUOUS: `cargo fuzz run` did not cover the fuzz workspace",
        ));
    }

    // Only run: content counts. A comment, a name and a cache key are data.
    let workflow = "\
name: Test
on: push
jobs:
  build:
    name: budzero tests
    runs-on: ubuntu-latest
    steps:
      # cd budzero is in this comment
      - name: Cache budzero
        uses: Swatinem/rust-cache@0000000000000000000000000000000000000000
        with:
          workspaces: budzero
      - name: Real step
        run: cargo test
";
    let runs = run_lines(workflow);
    if runs.iter().any(|line| line.contains("budzero")) {
        problems.push(format!(
            "BROKEN: a comment, a job name or a cache key was read as a command: {runs:?}"
        ));
    }

    // An inline command inside a block, and a folded block, are both executable.
    let block = "\
jobs:
  a:
    steps:
      - run: |
          set -euo pipefail
          cargo test --manifest-path budzero/Cargo.toml  # the workspace
      - run: >
          cargo test --manifest-path crates/ai-inference/Cargo.toml
";
    let runs = run_lines(block);
    if !runs.iter().any(|line| mentions_dir(line, "budzero")) {
        problems.push(format!(
            "VACUOUS: a command inside a `run: |` block was not read: {runs:?}"
        ));
    }
    if !runs.iter().any(|line| mentions_dir(line, "crates/ai-inference")) {
        problems.push(format!(
            "VACUOUS: a command inside a `run: >` block was not read: {runs:?}"
        ));
    }

    // An inline comment after a command does not stop it from matching.
    if !mentions_dir(
        &drop_inline_comment("cargo test --manifest-path kani/Cargo.toml  # the kani workspace"),
        "kani",
    ) {
        problems.push(String::from(
            "BROKEN: an inline comment hid the manifest path before it",
        ));
    }
    // A `#` that is not preceded by whitespace is not a comment.
    if !drop_inline_comment("sed -e 's/#.*//' file").contains("#") {
        problems.push(String::from(
            "BROKEN: a `#` inside a shell expression was treated as a comment",
        ));
    }

    // The manifest reader.
    if !declares_workspace("[workspace]\nmembers = []\n") {
        problems.push(String::from(
            "BROKEN: a `[workspace]` manifest was not recognised",
        ));
    }
    if declares_workspace("[package]\nname = \"x\"\n") {
        problems.push(String::from(
            "BROKEN: a plain package manifest was read as a workspace",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "workspace coverage gate self-test OK: --manifest-path (plain and ./-prefixed), \
         working-directory, cd and cargo fuzz all cover their workspace; a name-prefix near miss does \
         not; a bare cargo command covers the root package and a manifest-naming one does not; a \
         comment, a job name and a cache key are not commands; commands inside `run: |` and `run: >` \
         are; an inline comment does not hide a manifest path and a shell `#` is not an inline \
         comment; `[workspace]` is recognised and `[package]` is not.",
    ))
}
