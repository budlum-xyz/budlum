//! Every Cargo workspace is compiled by at least one workflow.
//!
//! Directive section 16.2 rule 3. A standalone workspace that no workflow
//! builds is a blind spot: its tests, lints and dependency graph drift
//! without a red check. This tree has been there twice. `crates/ai-inference`
//! stopped compiling while every job stayed green, and `bud/` - 103 modules -
//! was built by no CI job at all. Both were found by a person reading a
//! manifest, not by a check, which is why this gate exists.
//!
//! # What counts as coverage
//!
//! The gate discovers workspace roots from the manifests, then reads the
//! executable `run:` blocks of every workflow. A root is covered when a cargo
//! command that compiles reaches it:
//!
//! * `cargo build|test|check|clippy|run|bench|doc|kani|miri|mutants` under the
//!   step's `working-directory:`, or
//! * the same command with `--manifest-path` pointing inside the root, or
//! * `cargo fuzz` inside the root.
//!
//! These do not count: a comment, a `continue-on-error` or constant-false
//! step (a failing command there would not fail the job), `cargo fmt`,
//! `cargo metadata`, and a `cargo` verb that does not compile. A non-optional
//! path dependency of a compiled manifest does count, because cargo compiles
//! it with that manifest.
//!
//! # How the manifests are read
//!
//! Four facts per manifest: whether `[workspace]` and `[package]` exist, the
//! `members` array, a dependency's `optional` flag and a dependency's `path`.
//! The reader below is written out rather than added as a TOML dependency.
//! The gate crate decides what may enter the main branch and its dependency
//! set stays as narrow as the job allows - the same trade the release-profile
//! and clippy-extra gates state for their manifest and JSON readers. A
//! malformed manifest is a finding, not a silent default: "no members found"
//! and "no members declared" must not look the same to a gate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::gates::ci_workflow_guards::run_blocks;

/// The cargo verbs that compile something. `fmt`, `metadata`, `tree` and
/// `vendor` do not, and neither does a bare `cargo` subcommand this list does
/// not name.
const COMPILE_VERBS: &[&str] = &[
    "build", "test", "check", "clippy", "run", "fuzz", "bench", "kani", "mutants", "miri", "doc",
];

/// The dependency tables a path dependency may sit in.
const DEPENDENCY_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

/// Collapse `.` and `..` and drop empty components, as cargo does when it
/// resolves a path against a manifest directory.
fn normalize(relative: &str) -> String {
    let trimmed = relative.trim().trim_matches(['"', '\'']);
    let mut parts: Vec<&str> = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    if parts.is_empty() {
        String::from(".")
    } else {
        parts.join("/")
    }
}

/// Resolve `child` against `base`.
fn join_relative(base: &str, child: &str) -> String {
    let child = normalize(child);
    if base == "." {
        child
    } else if child == "." {
        base.to_string()
    } else {
        format!("{base}/{child}")
    }
}

/// Match one glob component against one path component (`*` and `?`).
fn component_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a `members` glob against a directory. A `**` component matches any
/// number of components.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[&str], t: &[&str]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(&"**") => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some(component) => {
                !t.is_empty() && component_match(component, t[0]) && go(&p[1..], &t[1..])
            }
        }
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let t: Vec<&str> = text.split('/').collect();
    go(&p, &t)
}

/// What the gate needs from one `Cargo.toml`.
#[derive(Debug, Default)]
struct Manifest {
    /// A `[workspace]` table is declared.
    workspace: bool,
    /// A `[package]` table is declared.
    package: bool,
    /// The workspace's `members` array, every entry normalized.
    members: Vec<String>,
    /// Paths of non-optional dependencies, normalized against the manifest's
    /// own directory.
    path_dependencies: Vec<String>,
}

/// Strip a `#` comment that is not inside a quoted string.
///
/// A manifest is data: a `#` inside a path or a description is part of the
/// value. The scan tracks quote state rather than splitting on the first `#`.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => return &line[..i],
                _ => {}
            },
        }
    }
    line
}

/// The string literals of a fragment, in order.
fn quoted(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut current = String::new();
    let mut escaped = false;
    for c in text.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    current.push(c);
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    out.push(std::mem::take(&mut current));
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    current.clear();
                }
            }
        }
    }
    out
}

/// The entries of the `members = [...]` array that starts at `start`.
///
/// The array may sit on one line, be spread over several lines, or list one
/// entry per line; all three forms appear in this tree, and a reader that
/// stops at the first newline reports a truncated member list.
fn members_of(text: &str, start: usize) -> Result<Vec<String>, String> {
    let rest = &text[start..];
    let Some(open) = rest.find('[') else {
        return Err(String::from("`members` is not an array"));
    };
    let mut depth = 0usize;
    let mut end = None;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else {
        return Err(String::from("`members` array is not closed"));
    };
    let entries = quoted(&rest[open..=end]);
    if entries.is_empty() {
        return Err(String::from("`members` names no entry"));
    }
    Ok(entries.iter().map(|m| normalize(m)).collect())
}

/// Which dependency table a header opens, if any.
///
/// Returns `Some("")` for a dependency table itself (`[dependencies]`,
/// `[target.'cfg(unix)'.dev-dependencies]`) and `Some(name)` for a single
/// dependency's own table (`[dependencies.serde]`), with a quoted name
/// unquoted (`[dependencies."serde-x"]`).
fn dependency_table_of(table: &str) -> Option<String> {
    for segment in DEPENDENCY_TABLES {
        if table == *segment {
            return Some(String::new());
        }
        if let Some(rest) = table.strip_prefix(&format!("{segment}.")) {
            return Some(rest.trim_matches('"').to_string());
        }
        // A target-scoped form: `[target.'cfg(unix)'.dependencies]` and
        // `[target.'cfg(unix)'.dependencies.serde]`.
        let scoped = format!(".{segment}");
        if let Some(index) = table.find(&scoped) {
            let rest = &table[index + scoped.len()..];
            if rest.is_empty() {
                return Some(String::new());
            }
            if let Some(name) = rest.strip_prefix('.') {
                return Some(name.trim_matches('"').to_string());
            }
        }
    }
    None
}

/// A dependency being read, as `(optional, path)`.
///
/// `optional` and `path` may be written in either order, and the entry is
/// only folded into the manifest once it is complete.
type Pending = (bool, Option<String>);

/// Fold a completed dependency into the manifest.
fn finish_dependency(pending: &mut Option<Pending>, dir: &str, out: &mut Manifest) {
    if let Some((optional, path)) = pending.take() {
        if !optional {
            if let Some(path) = path {
                out.path_dependencies.push(join_relative(dir, &path));
            }
        }
    }
}

/// Set `path` and `optional` on a dependency from one `key = value` line.
///
/// The key is matched exactly. An earlier version of this reader looked for
/// the substring `path`, which the opening brace of an inline table -
/// `{ path = ... }` - never matched, so it found no path dependency at all
/// and coverage silently stopped propagating along dependency edges.
fn apply_dependency_key(pending: &mut Pending, key: &str, value: &str) {
    match key {
        "path" => pending.1 = quoted(value).into_iter().next(),
        "optional" => pending.0 = value == "true",
        _ => {}
    }
}

/// Parse one line written as an inline table, returning `(optional, path)`.
fn parse_inline_table(body: &str) -> (bool, Option<String>) {
    let mut pending: Pending = (false, None);
    for part in body
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
    {
        if let Some((key, value)) = part.split_once('=') {
            apply_dependency_key(&mut pending, key.trim(), value.trim());
        }
    }
    pending
}

/// Read the facts the gate needs out of one manifest.
fn parse_manifest(text: &str, dir: &str) -> Result<Manifest, String> {
    let mut out = Manifest::default();
    let mut table = String::from("root");
    // The dependency table currently open: `[dependencies]`, a `[target...]`
    // form of it, or the dependency's own `[dependencies.name]` table.
    let mut dependency_key: Option<String> = None;
    let mut pending: Option<Pending> = None;
    let mut offset = 0usize;

    for raw in text.split_inclusive('\n') {
        let line_start = offset;
        offset += raw.len();
        let raw = raw.trim_end_matches(['\n', '\r']);
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            finish_dependency(&mut pending, dir, &mut out);
            table = header.trim().to_string();
            out.workspace |= table == "workspace";
            out.package |= table == "package";
            dependency_key = dependency_table_of(&table);
            continue;
        }
        if table == "workspace" && line.starts_with("members") {
            let skip = raw.len() - raw.trim_start().len();
            out.members.extend(members_of(text, line_start + skip)?);
            continue;
        }
        let Some(open_key) = dependency_key.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if open_key.is_empty() {
            // An entry of a dependency table: `name = "1"`, `name = { .. }`.
            finish_dependency(&mut pending, dir, &mut out);
            if value.starts_with('{') {
                let (optional, path) = parse_inline_table(value);
                if !optional {
                    if let Some(path) = path {
                        out.path_dependencies.push(join_relative(dir, &path));
                    }
                }
            } else {
                // A plain version requirement or a `workspace = true`
                // reference: no path, so start the entry anyway. The keys
                // that follow (`optional`, `path`) belong to it.
                pending = Some((false, None));
            }
            continue;
        }
        // Inside `[dependencies.name]`, every key belongs to that dependency.
        let slot = pending.get_or_insert((false, None));
        apply_dependency_key(slot, key, value);
    }
    finish_dependency(&mut pending, dir, &mut out);
    Ok(out)
}

/// Every `Cargo.toml` in the tree, keyed by its directory from the root.
fn collect_manifests(root: &Path) -> Result<BTreeMap<String, Manifest>, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Manifest>) -> Result<(), String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | "target" | "node_modules") {
                continue;
            }
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                walk(&path, root, out)?;
            } else if name == "Cargo.toml" {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let relative = path
                    .parent()
                    .and_then(|p| p.strip_prefix(root).ok())
                    .map_or_else(|| String::from("."), |p| normalize(&p.to_string_lossy()));
                let manifest = parse_manifest(&text, &relative)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                out.insert(relative, manifest);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

/// Is `dir` a member of the workspace declared at `workspace`?
fn is_member(manifests: &BTreeMap<String, Manifest>, workspace: &str, dir: &str) -> bool {
    let Some(value) = manifests.get(workspace) else {
        return false;
    };
    let relative = if workspace == "." {
        dir.to_string()
    } else {
        dir.strip_prefix(&format!("{workspace}/"))
            .unwrap_or(dir)
            .to_string()
    };
    value
        .members
        .iter()
        .any(|pattern| glob_match(pattern, &relative))
}

/// Every directory that is the root of its own cargo invocation: a declared
/// `[workspace]`, or a `[package]` that no enclosing workspace claims.
fn workspace_roots(manifests: &BTreeMap<String, Manifest>) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for (dir, value) in manifests {
        if value.workspace {
            roots.insert(dir.clone());
            continue;
        }
        if !value.package {
            continue;
        }
        let mut parent = Path::new(dir).parent();
        let mut owned = false;
        while let Some(ancestor) = parent {
            let ancestor_dir = normalize(&ancestor.to_string_lossy());
            if ancestor_dir != *dir
                && manifests
                    .get(&ancestor_dir)
                    .is_some_and(|v| v.workspace)
                && is_member(manifests, &ancestor_dir, dir)
            {
                owned = true;
                break;
            }
            parent = ancestor.parent();
        }
        if !owned {
            roots.insert(dir.clone());
        }
    }
    roots
}

/// The innermost workspace root that contains `dir`.
fn workspace_for_dir<'a>(dir: &str, roots: &'a BTreeSet<String>) -> Option<&'a str> {
    let dir = normalize(dir);
    roots
        .iter()
        .map(String::as_str)
        .filter(|root| *root == "." || dir == *root || dir.starts_with(&format!("{root}/")))
        .max_by_key(|root| root.len())
}

/// A compiling cargo command on one line of a `run:` block.
struct CargoCommand {
    verb: String,
    manifest: Option<String>,
}

/// Parse a line as a compiling cargo command, if it is one.
fn cargo_command(line: &str) -> Option<CargoCommand> {
    if line.trim_start().starts_with('#') {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let cargo = tokens.iter().position(|t| *t == "cargo")?;
    let mut rest = tokens[cargo + 1..].iter().copied().peekable();
    // A `+toolchain` argument selects the toolchain, not the subcommand.
    while rest.peek().is_some_and(|t| t.starts_with('+')) {
        rest.next();
    }
    let verb = rest.next()?.to_string();
    if !COMPILE_VERBS.contains(&verb.as_str()) && !verb.starts_with("build-") {
        return None;
    }
    let args: Vec<&str> = rest.collect();
    let mut manifest = None;
    for (i, token) in args.iter().enumerate() {
        if *token == "--manifest-path" {
            manifest = args.get(i + 1).map(|s| normalize(s));
        } else if let Some(value) = token.strip_prefix("--manifest-path=") {
            manifest = Some(normalize(value));
        }
    }
    Some(CargoCommand { verb, manifest })
}

/// The workspace roots a live workflow compiles, closure over path
/// dependencies included.
fn covered_workspaces(
    root: &Path,
    roots: &BTreeSet<String>,
    manifests: &BTreeMap<String, Manifest>,
) -> Result<BTreeSet<String>, String> {
    let workflows = root.join(".github/workflows");
    let entries = std::fs::read_dir(&workflows)
        .map_err(|e| format!("cannot read {}: {e}", workflows.display()))?;
    let mut covered = BTreeSet::new();
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    paths.sort();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for block in run_blocks(&text) {
            // A softened step cannot fail the job, so it proves nothing.
            if block.softened.is_some() {
                continue;
            }
            let working_directory = block.working_directory.as_deref().unwrap_or(".");
            for line in &block.lines {
                let Some(command) = cargo_command(line) else {
                    continue;
                };
                if let Some(manifest) = command.manifest {
                    let manifest_dir = Path::new(&manifest)
                        .parent()
                        .map_or_else(|| String::from("."), |p| normalize(&p.to_string_lossy()));
                    if let Some(workspace) = workspace_for_dir(&manifest_dir, roots) {
                        covered.insert(workspace.to_string());
                    }
                } else if command.verb == "fuzz" {
                    // `cargo fuzz` compiles the fuzz crate the subdirectory
                    // names, not the workspace it runs in.
                    let fuzz_dir = join_relative(working_directory, "fuzz");
                    if roots.contains(&fuzz_dir) {
                        covered.insert(fuzz_dir);
                    } else if let Some(workspace) = workspace_for_dir(working_directory, roots) {
                        covered.insert(workspace.to_string());
                    }
                } else if let Some(workspace) = workspace_for_dir(working_directory, roots) {
                    covered.insert(workspace.to_string());
                }
            }
        }
    }

    // A compiled manifest compiles its non-optional path dependencies too, so
    // coverage propagates along the dependency edges. Repeat until the set
    // stops growing: a chain of three workspaces must not need three passes.
    loop {
        let before = covered.len();
        let snapshot = covered.clone();
        for workspace in snapshot {
            for (dir, value) in manifests {
                if workspace_for_dir(dir, roots) != Some(workspace.as_str()) {
                    continue;
                }
                for dep in &value.path_dependencies {
                    if let Some(dependency_workspace) = workspace_for_dir(dep, roots) {
                        covered.insert(dependency_workspace.to_string());
                    }
                }
            }
        }
        if covered.len() == before {
            break;
        }
    }
    Ok(covered)
}

/// # Errors
///
/// Returns the workspace roots that no workflow compiles.
pub fn run(root: &Path) -> Result<String, String> {
    let manifests = collect_manifests(root)?;
    let roots = workspace_roots(&manifests);
    if roots.is_empty() {
        return Err(String::from("no Cargo workspace was discovered"));
    }
    let covered = covered_workspaces(root, &roots, &manifests)?;
    let missing: Vec<&str> = roots
        .iter()
        .filter(|root| !covered.contains(*root))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "workflows do not compile these Cargo workspaces: {}",
            missing.join(", ")
        ));
    }
    Ok(format!(
        "workflows_cover_every_workspace OK: {} workspace(s), every one compiled by a workflow",
        roots.len()
    ))
}

/// A root manifest whose dependency on `crates/a` makes that workspace
/// covered as soon as the root itself is.
const ROOT_MANIFEST: &str = "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\nmembers = [\"crates/*\"]\n\n[dependencies]\na = { path = \"crates/a\" }\n";

const MEMBER_MANIFEST: &str =
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

/// Write the workflow of a canary case, keeping the manifests as they are.
///
/// The manifest is written separately so a case can vary it; a fixture that
/// rewrote it every time would silently undo the previous case.
fn stage_workflow(root: &Path, workflow: &str) -> Result<(), String> {
    std::fs::create_dir_all(root.join(".github/workflows")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(root.join("crates/a")).map_err(|e| e.to_string())?;
    std::fs::write(root.join("crates/a/Cargo.toml"), MEMBER_MANIFEST)
        .map_err(|e| e.to_string())?;
    std::fs::write(root.join(".github/workflows/ci.yml"), workflow).map_err(|e| e.to_string())
}

/// Stage the default manifests and one workflow.
fn fixture(root: &Path, workflow: &str) -> Result<(), String> {
    std::fs::write(root.join("Cargo.toml"), ROOT_MANIFEST).map_err(|e| e.to_string())?;
    stage_workflow(root, workflow)
}

/// The canary. Every case names the hole it closes.
///
/// # Errors
///
/// Returns a finding when the gate does not behave as it promises.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-workspace-cover")?;
    let result = (|| {
        let good = "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test --workspace\n";
        fixture(&dir, good)?;
        run(&dir)?;

        fixture(
            &dir,
            "name: ci\non: [push]\njobs:\n  build:\n    steps:\n      - run: echo nothing\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an uncovered workspace passed"));
        }

        fixture(
            &dir,
            "name: ci\njobs:\n  build:\n    steps:\n      # cargo test --workspace\n      - run: echo comment\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a commented cargo command counted"));
        }

        fixture(
            &dir,
            "name: ci\njobs:\n  build:\n    steps:\n      - continue-on-error: true\n        run: cargo test --workspace\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a softened build counted"));
        }

        fixture(
            &dir,
            "name: ci\njobs:\n  build:\n    steps:\n      - run: cargo fmt --all\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: cargo fmt counted as a compile"));
        }

        // A `--manifest-path` names the workspace it points at, and the
        // workspace it points at is the covered one - not the directory the
        // step happens to run in.
        fixture(
            &dir,
            "name: ci\njobs:\n  build:\n    steps:\n      - run: cargo build --manifest-path crates/a/Cargo.toml\n",
        )?;
        if run(&dir).is_err() {
            return Err(String::from(
                "canary: a --manifest-path build must cover the root it names",
            ));
        }

        // Members spread over several lines are still members: the root owns
        // `crates/a`, so covering `crates/a` covers the member's workspace.
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\n[workspace]\nmembers = [\n  \"crates/a\",\n]\n",
        )
        .map_err(|e| e.to_string())?;
        stage_workflow(
            &dir,
            "name: ci\njobs:\n  build:\n    steps:\n      - run: cargo build --manifest-path crates/a/Cargo.toml\n",
        )?;
        if run(&dir).is_err() {
            return Err(String::from(
                "canary: a multi-line members array must still own its member",
            ));
        }

        // An unclosed members array is a finding, not an empty workspace.
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\n[workspace]\nmembers = [ \"crates/a\"\n",
        )
        .map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: an unclosed members array was read as a valid manifest",
            ));
        }
        Ok(String::from(
            "workflows_cover_every_workspace canary OK: path-dependency and multi-line coverage pass; missing, commented, softened, fmt-only and broken-manifest coverage fails",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    /// The injected canary, exercised through the test log too.
    #[test]
    fn workflows_cover_every_workspace_catches_injected_uncovered_workspace() {
        super::self_test().expect("workspace coverage canary");
    }

    #[test]
    fn manifest_reader_reads_the_four_facts() {
        let text = "[package]\nname = \"x\"\n\n[workspace]\nmembers = [\n  \"crates/*\",\n]\n\n[dependencies]\nplain = { path = \"../plain\" }\nskip = { path = \"../skip\", optional = true }\n\n[target.'cfg(unix)'.dependencies]\nunix = { path = \"../unix\" }\n";
        let parsed = super::parse_manifest(text, "crates/x").expect("manifest must parse");
        assert!(parsed.workspace);
        assert!(parsed.package);
        assert_eq!(parsed.members, vec![String::from("crates/*")]);
        assert_eq!(
            parsed.path_dependencies,
            vec![String::from("crates/plain"), String::from("crates/unix")],
            "an optional dependency is not compiled with the manifest"
        );
    }
}
