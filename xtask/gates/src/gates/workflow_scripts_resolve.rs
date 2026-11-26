//! A `run:` step that names a repository script must be able to find it.
//!
//! # The failure this closes
//!
//! Measured 2026-11-25 on `snapshot/144f40ec`: `Semver Check` was the only red
//! of eighteen runs, and its failing step was `Install protoc`, whose whole
//! body is
//!
//! ```text
//! run: python3 .github/scripts/install_protoc.py
//! ```
//!
//! The file exists. The step still died with
//!
//! ```text
//! python3: can't open file '/home/runner/work/budlum/budlum/.github/scripts/install_protoc.py'
//! ```
//!
//! because that job checks out into `path: current` and runs a second checkout
//! into `path: baseline`, so the workspace root holds no `.github/` tree at
//! all. Nothing in the repository asks the question the runner asks, which is
//! not "does this path exist somewhere" but "does it resolve from the directory
//! this step runs in".
//!
//! A workflow is data, so a broken path in it is not caught by the compiler,
//! by clippy, or by any of the gates that read the *content* of a step. It is
//! caught by the runner, once, half an hour in, looking like a product red.
//!
//! # What is checked
//!
//! For every workflow under `.github/workflows/` and every `run:` line that
//! invokes `python3 <path>` (or `bash <path>`, or the plain
//! `./<path>` form) with a path starting `.github/`, `scripts/` or `xtask/`,
//! the referenced file must exist **resolved against the directory the step
//! runs in**: the job's `defaults.run.working-directory`, else the workflow's,
//! else the repository root. A step declared `if: false` is still checked -
//! the intent is checked, not the execution.
//!
//! The gate does not try to model `cd` inside a script body or a path built by
//! variable expansion; a step that does that declares its own intent and is out
//! of scope, which is why the parse is limited to a literal first word after
//! the interpreter.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Roots a `run:` line may reference by literal path.
const SCRIPT_ROOTS: &[&str] = &[".github/", "scripts/", "xtask/"];

/// Interpreters whose first argument is a path we can resolve.
const INTERPRETERS: &[&str] = &["python3", "python", "bash", "sh"];

/// One `run:` line naming a repository script.
#[derive(Debug, PartialEq, Eq)]
pub struct ScriptRef {
    /// Workflow file, relative to the repository root.
    pub workflow: String,
    /// Step name, for the refusal.
    pub step: String,
    /// The referenced path as written.
    pub path: String,
    /// The directory the step runs in, relative to the repository root.
    pub working_directory: String,
    /// The subdirectory the job's checkout wrote the repository into, when the
    /// job uses `uses: actions/checkout` with `path: <dir>`. Empty means the
    /// checkout landed at the repository root.
    pub checkout_path: String,
    /// The directory the step runs in, expressed as a path inside the
    /// repository this gate is scanning.
    ///
    /// A checkout into `current/` puts a second copy of the repository at
    /// `current`, so `current` and `current/budzero` name the same tree as the
    /// root and `budzero`. The parser knows the job's checkout list and does
    /// that translation once, here, so the runner and the gate agree.
    pub step_dir_in_repo: String,
    /// Whether the workspace root holds the repository at all.
    ///
    /// False when the job checks out *only* into subdirectories: the runner's
    /// root then contains `current/` and `baseline/` and no `.github/`, so a
    /// root-relative path cannot resolve from anywhere the step could be
    /// running. This is the `Semver Check` layout, and modelling it is the
    /// whole point of the gate.
    pub root_holds_repository: bool,
}

impl ScriptRef {
    /// The directory the step actually runs in.
    ///
    /// `defaults.run.working-directory` wins. Without one, a job whose only
    /// checkout used `path: current` runs in `current`, because the workspace
    /// root holds no repository at all in that layout - which is exactly the
    /// 2026-11-25 `Semver Check` failure.
    fn effective_dir(&self) -> PathBuf {
        let wd = if self.working_directory.is_empty() || self.working_directory == "." {
            self.checkout_path.as_str()
        } else {
            self.working_directory.as_str()
        };
        let _ = self.root_holds_repository;
        if wd.is_empty() || wd == "." {
            PathBuf::new()
        } else {
            PathBuf::from(wd)
        }
    }

    /// Where the path is looked for, relative to the repository root.
    ///
    /// A checkout directory *is* a copy of the repository, so `current` names
    /// the root of that copy: the prefix is stripped and the remainder is
    /// resolved inside this tree. `current/budzero` resolves to `budzero`,
    /// which is the crate the step actually runs in.
    fn resolved(&self) -> PathBuf {
        PathBuf::from(&self.step_dir_in_repo).join(&self.path)
    }
}

/// Every literal script reference in `text`, a single workflow file.
///
/// `name` is the workflow's path relative to the repository root and is only
/// used to label findings.
pub fn script_refs(name: &str, text: &str) -> Vec<ScriptRef> {
    let mut out = Vec::new();
    // A hand-rolled scan rather than a YAML dependency: the shape needed here -
    // "which job am I in", "what is my working directory", "what does this run
    // line name" - is three indentation facts, and pulling a YAML parser into
    // the gate binary for them would add a dependency the gates deliberately
    // do not carry.
    let mut job: Option<String> = None;
    let mut job_wd: Option<String> = None;
    let mut workflow_wd: Option<String> = None;
    let mut step_name: String = String::new();
    let mut in_step = false;
    let mut current_wd: Option<String> = None;
    // Checkout directories seen in the current job. A job with exactly one
    // checkout into `path: <dir>` and no working directory runs inside `<dir>`.
    let mut job_checkouts: Vec<String> = Vec::new();
    // The checkout prefixes of the job, for the effective-directory model.
    let mut lookup: Vec<(String, String)> = Vec::new();
    let mut in_checkout = false;
    let mut checkout_path: Option<String> = None;

    let lines: Vec<&str> = text.lines().collect();
    for (idx, raw) in lines.iter().enumerate() {
        let line = raw.trim_end();
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }

        // A job header is two-space indented and ends in `:`.
        if indent == 2 && body.ends_with(':') && !body.starts_with('-') {
            job = Some(body.trim_end_matches(':').to_string());
            job_wd = None;
            in_step = false;
            job_checkouts.clear();
            lookup.clear();
        }
        // `defaults:` at job (4) or workflow (2) indentation opens a block whose
        // `working-directory:` is read below.
        if body.starts_with("working-directory:") {
            let value = body
                .trim_start_matches("working-directory:")
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            // Inside a step (`- name:`/`- run:` opened one) a
            // `working-directory:` belongs to that step; before the first step
            // of a job it belongs to the job. The indent alone cannot decide
            // this: `- name:` puts the step's keys at 8, and a job's
            // `defaults.run` keys also end up below 4.
            if in_step {
                current_wd = Some(value);
            } else if job.is_some() {
                job_wd = Some(value);
            } else {
                workflow_wd = Some(value);
            }
        }
        // A new step closes any checkout being read.
        if body.starts_with("- name:") || body.starts_with("- uses:") || body.starts_with("- run:")
        {
            if in_checkout {
                if let Some(p) = checkout_path.take() {
                    job_checkouts.push(p.clone());
                    lookup.push((String::new(), p));
                }
                in_checkout = false;
            }
        }
        // A checkout names itself either as `- uses: actions/checkout@...` (the
        // step's own first key) or as `uses: actions/checkout@...` after a
        // `- name:`. Both are read: the second is the form `semver.yml` uses,
        // and modelling only the first is why this gate missed that job.
        let bare = body.strip_prefix("- ").unwrap_or(body).trim_start();
        if bare.starts_with("uses:") && bare.contains("actions/checkout") {
            in_checkout = true;
            checkout_path = None;
        }
        // `with: path: <dir>` inside that step. A checkout without `path`
        // writes to the workspace root, recorded as the empty string.
        if in_checkout && body.starts_with("path:") {
            checkout_path = Some(
                body.trim_start_matches("path:")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
        }

        // A step begins at `- name:` or `- uses:` or `- run:`.
        if body.starts_with("- name:") {
            step_name = body
                .trim_start_matches("- name:")
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            in_step = true;
            current_wd = None;
        } else if body.starts_with("- run:") || body.starts_with("- uses:") {
            if step_name.is_empty() {
                step_name = format!("step {}", idx + 1);
            }
            in_step = true;
            current_wd = None;
        }
        if body.starts_with("- name:") {
            continue;
        }
        if !in_step {
            continue;
        }

        let command = if let Some(rest) = body.strip_prefix("- run:") {
            Some(rest.trim().to_string())
        } else if let Some(rest) = body.strip_prefix("run:") {
            Some(rest.trim().to_string())
        } else {
            None
        };
        let Some(command) = command else { continue };

        let wd = current_wd
            .clone()
            .or_else(|| job_wd.clone())
            .or_else(|| workflow_wd.clone())
            .unwrap_or_default();
        // A job whose checkouts all used `path: <dir>` has no repository at
        // the workspace root: with one such checkout that directory is where
        // the step runs, and with several a root-relative path resolves from
        // nowhere at all. Both cases are reported, because in both the fix is
        // the same one - say which directory the step runs in.
        let subdir_only =
            !job_checkouts.is_empty() && job_checkouts.iter().all(|c| !c.is_empty());
        let checkout = match job_checkouts.as_slice() {
            [only] if !only.is_empty() => only.clone(),
            _ => String::new(),
        };
        let raw_dir: String = {
            let candidate = if wd.is_empty() || wd == "." {
                checkout.clone()
            } else {
                wd.clone()
            };
            if candidate == "." {
                String::new()
            } else {
                candidate
            }
        };
        let step_dir_in_repo = in_repo_dir(&raw_dir, &job_checkouts);
        for path in paths_in(&command) {
            out.push(ScriptRef {
                workflow: name.to_string(),
                step: if step_name.is_empty() {
                    format!("step {}", idx + 1)
                } else {
                    step_name.clone()
                },
                path,
                working_directory: wd.clone(),
                checkout_path: checkout.clone(),
                step_dir_in_repo: step_dir_in_repo.clone(),
                root_holds_repository: !subdir_only,
            });
        }
        let _ = job.as_ref();
    }
    out
}

/// The step's directory, expressed as a path inside one copy of the repository.
///
/// `dir` is the runner-relative working directory (`current`, `current/budzero`,
/// or empty for the workspace root). Every checkout of the job into
/// `path: <prefix>` puts a fresh copy of the repository at `<prefix>`, so a
/// directory under a prefix is `<prefix>` stripped and the remainder appended
/// to the repository root. A directory that is under no prefix (the job has a
/// single root checkout) is already a path inside the repository.
fn in_repo_dir(dir: &str, checkouts: &[String]) -> String {
    if dir.is_empty() {
        return String::new();
    }
    let mut best: Option<(usize, String)> = None;
    for prefix in checkouts {
        if prefix.is_empty() {
            continue;
        }
        let hit = dir == prefix
            || dir
                .strip_prefix(prefix.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if !hit {
            continue;
        }
        let rest = dir.strip_prefix(prefix.as_str()).unwrap_or("");
        let rest = rest.trim_start_matches('/');
        // The longest matching prefix wins: `current` and `current/ops` both
        // name copies only if the job checked both out, and the deeper one is
        // the more specific reading.
        let better = best
            .as_ref()
            .map_or(true, |(len, _)| prefix.len() > *len);
        if better {
            best = Some((prefix.len(), rest.to_string()));
        }
    }
    best.map(|(_, rest)| rest).unwrap_or_else(|| dir.to_string())
}

/// The literal repository paths a single command line names.
fn paths_in(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in command.split("&&").flat_map(|s| s.split("||")) {
        let words: Vec<&str> = segment.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let mut candidate: Option<&str> = None;
        if INTERPRETERS.contains(&words[0]) {
            // `python3 <path>`; a `-c`, `-m` or flag first means no path.
            if let Some(w) = words.get(1) {
                if !w.starts_with('-') {
                    candidate = Some(w);
                }
            }
        } else if words[0].starts_with("./") {
            candidate = Some(words[0]);
        }
        if let Some(word) = candidate {
            let clean = word.trim_matches('"').trim_matches('\'');
            let clean = clean.strip_prefix("./").map_or(clean, |s| s);
            if SCRIPT_ROOTS.iter().any(|r| clean.starts_with(r))
                && (clean.ends_with(".py") || clean.ends_with(".sh") || clean.ends_with(".js"))
            {
                out.push(clean.to_string());
            }
        }
    }
    out
}

fn workflow_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(".github/workflows");
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| format!("the workflow directory could not be read ({}): {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("a workflow entry could not be read: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml")
            || path.extension().and_then(|e| e.to_str()) == Some("yaml")
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Run the gate over a repository root.
pub fn run(root: &Path) -> Result<String, String> {
    let files = workflow_files(root)?;
    if files.is_empty() {
        return Err(String::from(
            "no workflow files were found: a gate that scans nothing reports OK",
        ));
    }
    let mut findings = Vec::new();
    let mut checked = 0usize;
    for file in &files {
        let name = file
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| file.to_string_lossy().to_string());
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("{name} could not be read: {e}"))?;
        for reference in script_refs(&name, &text) {
            checked += 1;
            let resolved = reference.resolved();
            if !reference.root_holds_repository && reference.effective_dir().as_os_str().is_empty()
            {
                findings.push(format!(
                    "{} :: step `{}` runs `{}`, but the job checks out only into subdirectories, \
                     so the workspace root holds no `{}`; give the job a \
                     `defaults.run.working-directory` naming the checkout it works in",
                    reference.workflow,
                    reference.step,
                    reference.path,
                    reference.path
                ));
                continue;
            }
            if !root.join(&resolved).is_file() {
                findings.push(format!(
                    "{} :: step `{}` runs `{}` from `{}`, but `{}` does not exist",
                    reference.workflow,
                    reference.step,
                    reference.path,
                    {
                        let d = reference.effective_dir();
                        if d.as_os_str().is_empty() {
                            "<repo root>".to_string()
                        } else {
                            d.display().to_string()
                        }
                    },
                    resolved.display()
                ));
            }
        }
    }
    if !findings.is_empty() {
        let mut msg = String::from("workflow script paths that cannot resolve:\n");
        for f in &findings {
            let _ = writeln!(msg, "  - {f}");
        }
        let _ = write!(
            msg,
            "A step's path is resolved from the directory that step runs in, not from the \
             repository root: a job that checks out into a subdirectory must say so with \
             `defaults.run.working-directory`."
        );
        return Err(msg);
    }
    Ok(format!(
        "workflow script paths resolve: {checked} literal references across {} workflow file(s), \
         each found from the directory its step runs in",
        files.len()
    ))
}

/// Canaries: the gate must be able to fail.
pub fn self_test() -> Result<String, String> {
    // 1. A path that resolves from the repository root passes.
    let good = "name: w\njobs:\n  j:\n    steps:\n      - name: Install\n        run: python3 .github/scripts/install_protoc.py\n";
    let refs = script_refs(".github/workflows/w.yml", good);
    if refs.len() != 1 || refs[0].working_directory != "" {
        return Err(format!(
            "workflow-scripts-resolve self-test: the root-relative reference was not read: {refs:?}"
        ));
    }
    // 2. A job-level working directory is attached to the reference, which is
    //    how a subdirectory checkout is expressed.
    let job_wd = "name: w\njobs:\n  j:\n    defaults:\n      run:\n        working-directory: current\n    steps:\n      - name: Install\n        run: python3 .github/scripts/install_protoc.py\n";
    let refs = script_refs(".github/workflows/w.yml", job_wd);
    if refs.len() != 1 || refs[0].working_directory != "current" {
        return Err(format!(
            "workflow-scripts-resolve self-test: the job working directory was not read: {refs:?}"
        ));
    }
    // 3. A step-level working directory overrides the job's.
    let step_wd = "name: w\njobs:\n  j:\n    defaults:\n      run:\n        working-directory: current\n    steps:\n      - name: Install\n        working-directory: .\n        run: bash scripts/ci.sh\n";
    let refs = script_refs(".github/workflows/w.yml", step_wd);
    if refs.len() != 1 || refs[0].working_directory != "." {
        return Err(format!(
            "workflow-scripts-resolve self-test: the step working directory was not read: {refs:?}"
        ));
    }
    // 4. `&&` chains, `python3 -m` and `python3 -c` are read correctly: the
    //    first names a path, the other two name none.
    let chain = "name: w\njobs:\n  j:\n    steps:\n      - run: python3 -m pytest && python3 .github/scripts/install_protoc.py && bash scripts/a.sh\n      - run: python3 -c 'print(1)'\n";
    let refs = script_refs(".github/workflows/w.yml", chain);
    let paths: Vec<&str> = refs.iter().map(|r| r.path.as_str()).collect();
    if paths != vec![".github/scripts/install_protoc.py", "scripts/a.sh"] {
        return Err(format!(
            "workflow-scripts-resolve self-test: the chained-command parse is wrong: {paths:?}"
        ));
    }
    // 5. The two-checkout layout that broke `Semver Check`: a job whose only
    //    checkout wrote the repository into `current` runs inside `current`, so
    //    a root-relative path does not resolve from the workspace root.
    let two_checkouts = "name: w\njobs:\n  j:\n    steps:\n      - name: Checkout (current)\n        uses: actions/checkout@v7\n        with:\n          path: current\n      - name: Checkout (baseline)\n        uses: actions/checkout@v7\n        with:\n          path: baseline\n      - name: Install protoc\n        run: python3 .github/scripts/install_protoc.py\n";
    let refs = script_refs(".github/workflows/w.yml", two_checkouts);
    if refs.len() != 1 {
        return Err(format!(
            "workflow-scripts-resolve self-test: the checkout layout was not read: {refs:?}"
        ));
    }
    // Two checkouts and no working directory: the runner's own directory is
    // ambiguous, so the gate does not guess and does not resolve `current/...`
    // for the step. It still requires the job to say where it runs, which is
    // the only answer that cannot drift; the canary asserts the model is what
    // the docs say it is.
    if refs[0].checkout_path != "" {
        return Err(format!(
            "workflow-scripts-resolve self-test: a two-checkout job must not be given a single \
             checkout directory: {refs:?}"
        ));
    }
    let single_checkout = "name: w\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          path: current\n      - name: Install protoc\n        run: python3 .github/scripts/install_protoc.py\n";
    let refs = script_refs(".github/workflows/w.yml", single_checkout);
    if refs.len() != 1 || refs[0].checkout_path != "current" {
        return Err(format!(
            "workflow-scripts-resolve self-test: the single-checkout path was not read: {refs:?}"
        ));
    }
    // `current` is a copy of the repository, so the path resolves at the
    // repository root: the checkout prefix names a tree, not a subdirectory.
    if refs[0].resolved() != Path::new(".github/scripts/install_protoc.py") {
        return Err(format!(
            "workflow-scripts-resolve self-test: the checkout-relative resolution is wrong: {:?}",
            refs[0].resolved()
        ));
    }
    // A directory under the checkout (`current/budzero`) keeps that remainder,
    // because `budzero` is a real subdirectory of the checked-out copy.
    let nested = "name: w\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          path: current\n      - name: Build\n        working-directory: current/budzero\n        run: bash scripts/ci.sh\n";
    let refs = script_refs(".github/workflows/w.yml", nested);
    if refs.len() != 1 || refs[0].resolved() != Path::new("budzero/scripts/ci.sh") {
        return Err(format!(
            "workflow-scripts-resolve self-test: a nested checkout directory resolved to {:?}",
            refs.first().map(|r| r.resolved())
        ));
    }
    // 6. The shipped workflows all resolve. This is the canary that would have
    //    been red on 2026-11-25, and the one that keeps the semver job honest.
    let root = crate::repo_root();
    match run(&root) {
        Ok(_) => {}
        Err(e) => {
            return Err(format!(
                "workflow-scripts-resolve self-test: the shipped workflows do not resolve, which \
                 is the finding this gate exists for: {e}"
            ))
        }
    }
    Ok(String::from(
        "workflow-scripts-resolve self-test: root-relative, job-level, step-level, checkout-level, \
         chained and shipped references all resolve",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("workflow-scripts-resolve self-test");
    }
}
