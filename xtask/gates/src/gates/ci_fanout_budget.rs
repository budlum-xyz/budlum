//! One push may not queue more work than the shared runner pool can finish.
//!
//! # The failure this closes
//!
//! Every workflow that triggers on `pull_request` is queued again by every push
//! to a branch that heads an open pull request. Measured on the integration
//! branch on 2026-11-20: 30 such workflows declared 100 jobs between them, one
//! file alone declared 41, and the pool that has to run them is shared and
//! finite. Pushes arrived every three to four minutes, so each push cancelled
//! the run before it. In the 24 hours to 22:00 UTC the repository created 2333
//! runs and 450 of them ended `cancelled` against 86 that ended `success`; the
//! single check that branch protection requires was cancelled four times in
//! nineteen minutes and never reached a conclusion on the head commit, which
//! left the integration pull request permanently unmergeable.
//!
//! Nothing in the tree held the number down. Adding a job to a workflow, or a
//! `pull_request` trigger to a new one, is a one-line change that no gate read,
//! and the cost of that line is paid by every later push as queue depth. The
//! heavy batteries already carry a job-level condition that skips them for a
//! stacked pull request; the branch that heads the integration pull request is
//! exactly the one the condition does not skip, so the full battery re-queues on
//! every push to it.
//!
//! # What is checked
//!
//! Statically, from the workflow text alone:
//!
//! 1. Every workflow that triggers on `pull_request` is listed in
//!    `.github/ci-fanout-baseline.txt` with the number of jobs it declares. A
//!    workflow that is missing from the baseline fails by name: the fan-out of
//!    the pull-request path may not grow silently.
//! 2. No listed workflow may declare more jobs than its pinned count, and the
//!    pinned totals may not rise. The budget is a ratchet that moves down.
//! 3. A baseline entry whose workflow no longer triggers on `pull_request`, or
//!    whose file is gone, fails: a stale entry is a budget that no longer
//!    describes the tree, and it hides the room the next change will take.
//! 4. A job whose `strategy.matrix` cannot be counted from literal text - a
//!    `fromJSON` expression, an `include` or `exclude` list, an empty sequence -
//!    is counted as one job and recorded as opaque. Turning a countable matrix
//!    into an opaque one raises the opaque count and fails, because that is how
//!    a budget would be hidden rather than spent.
//!
//! A job-level `if:` is deliberately not read. The condition that skips the
//! heavy batteries is false for the integration pull request, so counting the
//! job is the honest number for the push that matters; a reader that discounted
//! conditional jobs would report a fan-out the pool never sees.
//!
//! The reader is line based, like its neighbours in this crate: what is needed
//! is the indentation structure of a known file shape, and this crate keeps its
//! dependency set narrow on purpose because it decides what reaches the
//! protected branch.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The pinned budget, relative to the repository root.
const BASELINE_REL: &str = ".github/ci-fanout-baseline.txt";

/// Where the workflow files live, relative to the repository root.
const WORKFLOWS_REL: &str = ".github/workflows";

/// The command that re-measures the budget, quoted in every finding that asks
/// for a re-measurement so the reader does not have to go looking for it.
const REMEASURE: &str = "cargo run --release --manifest-path xtask/gates/Cargo.toml -- \
                         ci-pull-request-fanout-is-budgeted --print-baseline";

/// What one workflow contributes to a single pull-request push.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Load {
    /// Path relative to the repository root, with forward slashes.
    path: String,
    /// Job keys the file declares.
    jobs: usize,
    /// Jobs with countable matrices multiplied out.
    fanout: usize,
    /// Jobs this reader cannot count from literal text: a matrix that is not
    /// literal, or a reusable call into another repository.
    opaque: usize,
    /// The names of those jobs, so a finding can point at the axis that hid.
    /// Not part of the baseline: names move without the budget moving.
    opaque_jobs: Vec<String>,
}

/// The pinned budget, as the baseline file states it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Budget {
    workflows: usize,
    jobs: usize,
    fanout: usize,
    opaque: usize,
    entries: BTreeMap<String, Load>,
}

/// Indentation of a line, in spaces. Tabs are not valid YAML indentation.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// True for a blank line or a line whose first non-space character is `#`.
fn is_skippable(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// True when the workflow runs on a pull request event.
///
/// Only the lines before `jobs:` are read. The block form (`pull_request:`
/// under `on:`), the list form (`- pull_request`) and the inline forms
/// (`on: pull_request`, `on: [push, pull_request]`) all count; a mention inside
/// a comment does not.
fn triggers_on_pull_request(src: &str) -> bool {
    for line in src.lines() {
        if indent_of(line) == 0 && line.trim_end() == "jobs:" {
            break;
        }
        if is_skippable(line) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("pull_request:")
            || trimmed.starts_with("pull_request_target:")
            || trimmed == "- pull_request"
            || trimmed == "- pull_request_target"
        {
            return true;
        }
        if indent_of(line) == 0 && trimmed.starts_with("on:") && trimmed.contains("pull_request") {
            return true;
        }
    }
    false
}

/// One job's own lines, without the key line that opens it.
struct JobBody {
    name: String,
    lines: Vec<String>,
}

/// The jobs a workflow declares, in file order.
///
/// A job key sits at the indentation of the first non-blank, non-comment line
/// under `jobs:`; every key at that indentation is a job. Keys deeper than that
/// belong to the job above them.
fn job_bodies(src: &str) -> Vec<JobBody> {
    let lines: Vec<&str> = src.lines().collect();
    let Some(jobs_at) = lines.iter().position(|line| line.trim_end() == "jobs:") else {
        return Vec::new();
    };
    let job_indent = lines[jobs_at + 1..]
        .iter()
        .find(|line| !is_skippable(line))
        .map_or(2, |line| indent_of(line));

    let mut bodies: Vec<JobBody> = Vec::new();
    for line in &lines[jobs_at + 1..] {
        if is_skippable(line) {
            if let Some(current) = bodies.last_mut() {
                current.lines.push(String::from(*line));
            }
            continue;
        }
        let indent = indent_of(line);
        if indent < job_indent {
            break;
        }
        let trimmed = line.trim();
        if indent == job_indent && trimmed.ends_with(':') && !trimmed.contains(' ') {
            bodies.push(JobBody {
                name: String::from(trimmed.trim_end_matches(':')),
                lines: Vec::new(),
            });
            continue;
        }
        if let Some(current) = bodies.last_mut() {
            current.lines.push(String::from(*line));
        }
    }
    bodies
}

/// The items of a literal flow sequence such as `[a, b, c]`.
///
/// Brackets and braces nest, so a comma only separates items at depth zero.
fn flow_items(value: &str) -> Option<Vec<String>> {
    let inner = value.trim();
    let body = inner.strip_prefix('[')?.strip_suffix(']')?;
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in body.chars() {
        match ch {
            '[' | '{' => {
                depth = depth.saturating_add(1);
                current.push(ch);
            }
            ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                items.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let tail = current.trim().to_string();
    if !tail.is_empty() {
        items.push(tail);
    }
    if items.is_empty() {
        return None;
    }
    Some(items)
}

/// True for a value this reader cannot resolve to a fixed number of entries.
fn is_expression(value: &str) -> bool {
    value.contains("${{") || value.contains("fromJSON")
}

/// How many runners one job occupies, and whether that number is countable.
///
/// Returns the matrix product when every axis is literal text, and marks the
/// job uncountable when the shape cannot be resolved without running GitHub's
/// own matrix expansion:
///
/// * `include:` on its own is countable - with no other axis it produces exactly
///   one job per entry, which is the shape the two-arch conformance and
///   double-compiling batteries use;
/// * `include:` next to another axis is not, because the entries merge into the
///   cross-product and can add combinations or extend existing ones;
/// * `exclude:` is not, because it removes combinations this reader would
///   otherwise count;
/// * an expression (`${{ }}`, `fromJSON`) or an empty sequence is not.
///
/// An uncountable job contributes one to the fan-out and one to the opaque
/// count, so `fanout` is a floor and `opaque` is what keeps the floor honest:
/// both are pinned, and neither may rise without a re-measurement. A job
/// without a matrix occupies one runner.
fn matrix_factor(job_lines: &[String]) -> (usize, bool) {
    let Some(strategy_at) = job_lines
        .iter()
        .position(|line| !is_skippable(line) && line.trim() == "strategy:")
    else {
        return (1, false);
    };
    let strategy_indent = indent_of(&job_lines[strategy_at]);
    let Some(offset) = job_lines[strategy_at + 1..].iter().position(|line| {
        !is_skippable(line) && indent_of(line) > strategy_indent && line.trim() == "matrix:"
    }) else {
        return (1, false);
    };
    let matrix_at = offset + strategy_at + 1;
    let matrix_indent = indent_of(&job_lines[matrix_at]);
    let axis_indent = matrix_indent + 2;

    // One pass over the matrix keys, because `include:` decides differently
    // depending on whether another axis sits beside it.
    let mut axes: Vec<(String, usize, bool)> = Vec::new();
    let mut index = matrix_at + 1;
    while index < job_lines.len() {
        let line = &job_lines[index];
        if is_skippable(line) {
            index += 1;
            continue;
        }
        if indent_of(line) <= matrix_indent {
            break;
        }
        if indent_of(line) != axis_indent {
            index += 1;
            continue;
        }
        let Some((name, value)) = line.trim().split_once(':') else {
            index += 1;
            continue;
        };
        let name = name.trim().to_string();
        let value = value.trim();
        let (entries, hidden, next) = axis_entries(job_lines, index, axis_indent, value);
        axes.push((name, entries, hidden));
        index = next;
    }
    if axes.is_empty() {
        return (1, false);
    }

    let include = axes.iter().find(|(name, _, _)| name == "include");
    let others = axes
        .iter()
        .filter(|(name, _, _)| name != "include" && name != "exclude")
        .count();
    if axes.iter().any(|(name, _, _)| name == "exclude") {
        return (1, true);
    }
    if let Some((_, entries, hidden)) = include {
        if others == 0 {
            return if *hidden {
                (1, true)
            } else {
                (*entries, false)
            };
        }
        return (1, true);
    }

    let mut factor = 1usize;
    for (_, entries, hidden) in &axes {
        if *hidden || *entries == 0 {
            return (1, true);
        }
        factor = factor.saturating_mul(*entries);
    }
    (factor, false)
}

/// The entry count of one matrix axis, starting at its key line.
///
/// Returns the count, whether the count is hidden, and the index of the first
/// line after the axis. A flow sequence may span lines (`shard_index: [` then
/// the numbers, then `]`), so the bracket depth decides where the axis ends.
fn axis_entries(
    job_lines: &[String],
    at: usize,
    axis_indent: usize,
    value: &str,
) -> (usize, bool, usize) {
    if !value.is_empty() {
        if value.starts_with('[') && !value.ends_with(']') {
            // Multi-line flow sequence: join until the bracket closes.
            let mut joined = String::from(value);
            let mut next = at + 1;
            while next < job_lines.len() && !joined.contains(']') {
                joined.push(' ');
                joined.push_str(job_lines[next].trim());
                next += 1;
            }
            if !joined.contains(']') {
                return (1, true, next);
            }
            return count_flow(&joined, next);
        }
        return count_flow(value, at + 1);
    }
    // Block sequence: count the `- item` lines that belong to this axis.
    let mut entries = 0usize;
    let mut hidden = false;
    let mut next = at + 1;
    while next < job_lines.len() {
        let entry = &job_lines[next];
        if is_skippable(entry) {
            next += 1;
            continue;
        }
        if indent_of(entry) <= axis_indent {
            break;
        }
        let text = entry.trim();
        if !text.starts_with("- ") && text != "-" {
            break;
        }
        if is_expression(text) {
            hidden = true;
        }
        entries += 1;
        // The fields of one entry sit deeper than its `- `, so skip them.
        next += 1;
        while next < job_lines.len() {
            let field = &job_lines[next];
            if is_skippable(field) || indent_of(field) == 0 {
                break;
            }
            let trimmed = field.trim();
            if indent_of(field) <= indent_of(entry) || trimmed.starts_with("- ") || trimmed == "-" {
                break;
            }
            if is_expression(trimmed) {
                hidden = true;
            }
            next += 1;
        }
    }
    if entries == 0 {
        return (0, true, next);
    }
    (entries, hidden, next)
}

/// Count the items of a flow sequence, or mark it hidden.
fn count_flow(value: &str, next: usize) -> (usize, bool, usize) {
    if is_expression(value) {
        return (1, true, next);
    }
    match flow_items(value) {
        Some(items) => {
            if items.iter().any(|item| is_expression(item)) {
                (1, true, next)
            } else {
                (items.len(), false, next)
            }
        }
        // A single literal value is one entry on this axis.
        None => (1, false, next),
    }
}

/// The target of a job-level `uses:`, which calls a reusable workflow.
///
/// A job's own keys sit at one indentation below the job key. The `- uses:` of
/// a step is deeper and carries a `- `, so it is never read as this.
fn job_reusable_call(lines: &[String]) -> Option<String> {
    let own_indent = lines
        .iter()
        .filter(|line| !is_skippable(line))
        .map(|line| indent_of(line))
        .min()?;
    for line in lines {
        if is_skippable(line) || indent_of(line) != own_indent {
            continue;
        }
        let Some(target) = line.trim().strip_prefix("uses:") else {
            continue;
        };
        let target = target.trim().trim_matches('"').trim_matches('\'');
        if !target.is_empty() {
            return Some(String::from(target));
        }
    }
    None
}

/// Where a job-level `uses:` target lives.
enum ReusableTarget {
    /// A workflow file in this tree, so its jobs can be read and counted.
    Local(String),
    /// Another repository's workflow, whose jobs this reader cannot see.
    Foreign(String),
}

/// A reusable call is local exactly when this reader can open its target: a
/// path under the workflows directory, with or without a leading `./`, in one
/// of the two extensions `workflow_files` collects. Anything else - another
/// repository, a pinned revision, an extension this reader would skip - is
/// foreign, and foreign is counted once and pinned as uncountable rather than
/// guessed at.
fn classify_reusable(target: &str) -> ReusableTarget {
    let cleaned = target.trim_start_matches("./");
    let readable = Path::new(cleaned)
        .extension()
        .is_some_and(|ext| ext == "yml" || ext == "yaml");
    if cleaned.starts_with(WORKFLOWS_REL) && readable {
        ReusableTarget::Local(String::from(cleaned))
    } else {
        ReusableTarget::Foreign(String::from(target))
    }
}

/// The fan-out one workflow contributes to a pull-request push.
///
/// A job that calls a reusable workflow holds no runner of its own: GitHub
/// queues the callee's jobs under this same push, so the callee's load is this
/// job's load and is measured here, recursively. `calling` is the chain of
/// workflows already being measured, so a circle is a finding rather than a
/// loop that never ends.
fn load_of(
    path: &str,
    src: &str,
    tree: &BTreeMap<String, String>,
    calling: &mut Vec<String>,
) -> Result<Load, String> {
    let bodies = job_bodies(src);
    let mut jobs = 0usize;
    let mut fanout = 0usize;
    let mut opaque = 0usize;
    let mut opaque_jobs: Vec<String> = Vec::new();
    for body in &bodies {
        match job_reusable_call(&body.lines)
            .as_deref()
            .map(classify_reusable)
        {
            Some(ReusableTarget::Foreign(target)) => {
                // The callee's jobs are queued by this push but live in another
                // repository, so they are counted once and pinned as
                // uncountable rather than taken as free capacity.
                jobs += 1;
                fanout += 1;
                opaque += 1;
                opaque_jobs.push(format!("{} calls {target}", body.name));
            }
            Some(ReusableTarget::Local(callee)) => {
                let Some(callee_src) = tree.get(&callee) else {
                    return Err(format!(
                        "{path}: job `{}` calls `{callee}`, which is not in this tree; a \
                         reusable call this reader cannot open is fan-out nobody has measured",
                        body.name
                    ));
                };
                if calling.contains(&callee) {
                    return Err(format!(
                        "{path}: job `{}` calls `{callee}`, which is already being measured in \
                         this chain ({}); reusable workflows may not call each other in a \
                         circle, and this reader will not loop to find out how deep it goes",
                        body.name,
                        calling.join(" -> ")
                    ));
                }
                calling.push(callee.clone());
                let sub = load_of(&callee, callee_src, tree, calling)?;
                calling.pop();
                jobs = jobs.saturating_add(sub.jobs);
                fanout = fanout.saturating_add(sub.fanout);
                opaque = opaque.saturating_add(sub.opaque);
                opaque_jobs.extend(
                    sub.opaque_jobs
                        .iter()
                        .map(|name| format!("{callee} {name}")),
                );
            }
            None => {
                let (factor, hidden) = matrix_factor(&body.lines);
                jobs += 1;
                fanout = fanout.saturating_add(factor);
                if hidden {
                    opaque += 1;
                    opaque_jobs.push(body.name.clone());
                }
            }
        }
    }
    Ok(Load {
        path: String::from(path),
        jobs,
        fanout,
        opaque,
        opaque_jobs,
    })
}

/// Every workflow file under `.github/workflows`, sorted by relative path.
fn workflow_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(WORKFLOWS_REL);
    let entries =
        fs::read_dir(&dir).map_err(|e| format!("{WORKFLOWS_REL} could not be read: {e}"))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{WORKFLOWS_REL} entry could not be read: {e}"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_yaml = path
            .extension()
            .is_some_and(|ext| ext == "yml" || ext == "yaml");
        if is_yaml {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Measure the pull-request fan-out of a tree.
///
/// Every workflow file is read first, including the ones that only answer
/// `workflow_call`, so that a reusable workflow cannot be a hideout for jobs
/// the pull-request path does queue.
fn measure(root: &Path) -> Result<Vec<Load>, String> {
    let mut tree: BTreeMap<String, String> = BTreeMap::new();
    for path in workflow_files(root)? {
        let relative = path
            .strip_prefix(root)
            .map_err(|e| format!("{} is not under the tree root: {e}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let src =
            fs::read_to_string(&path).map_err(|e| format!("{relative} could not be read: {e}"))?;
        tree.insert(relative, src);
    }
    let mut loads = Vec::new();
    for (relative, src) in &tree {
        if !triggers_on_pull_request(src) {
            continue;
        }
        let mut calling = vec![relative.clone()];
        loads.push(load_of(relative, src, &tree, &mut calling)?);
    }
    loads.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(loads)
}

fn sum(loads: &[Load], pick: fn(&Load) -> usize) -> usize {
    loads.iter().fold(0, |total, load| total + pick(load))
}

/// The baseline text for a measurement.
fn baseline_text(loads: &[Load]) -> String {
    let mut text = String::new();
    text.push_str("# Per-push fan-out of the pull-request CI path.\n");
    text.push_str("#\n");
    text.push_str("# Every workflow that triggers on `pull_request` is queued again by every\n");
    text.push_str("# push to a branch that heads an open pull request, and the runner pool\n");
    text.push_str("# those jobs share is finite. The totals below are a budget, not a report:\n");
    text.push_str("# they may fall, and they may only rise in the same change that\n");
    text.push_str("# re-measures them. A job whose matrix is not literal text is counted once\n");
    text.push_str("# and listed in `opaque`, so hiding a matrix behind an expression is a\n");
    text.push_str("# finding rather than free capacity. A job that calls a reusable workflow\n");
    text.push_str("# carries the callee's own jobs and runners, because GitHub queues the\n");
    text.push_str("# callee's work under the same push; a call into another repository cannot\n");
    text.push_str("# be read here, so it is counted once and listed in `opaque` too. A callee\n");
    text.push_str("# that is missing, or that calls back into its caller, is a finding.\n");
    text.push_str("#\n");
    text.push_str("# Re-measure in the same change that moves it:\n");
    text.push_str("#   ");
    text.push_str(REMEASURE);
    text.push('\n');
    let _ = writeln!(text, "workflows: {}", loads.len());
    let _ = writeln!(text, "jobs: {}", sum(loads, |load| load.jobs));
    let _ = writeln!(text, "fanout: {}", sum(loads, |load| load.fanout));
    let _ = writeln!(text, "opaque: {}", sum(loads, |load| load.opaque));
    for load in loads {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}",
            load.path, load.jobs, load.fanout, load.opaque
        );
    }
    text
}

/// Read a `key: number` header line.
fn header_value(text: &str, key: &str) -> Result<usize, String> {
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim() == key {
                return value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| format!("header `{key}` is not a number: {e}"));
            }
        }
    }
    Err(format!("header `{key}` is missing from {BASELINE_REL}"))
}

/// Parse the pinned budget.
fn parse_baseline(text: &str) -> Result<Budget, String> {
    let mut entries: BTreeMap<String, Load> = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line_number = number + 1;
        if is_skippable(line) {
            continue;
        }
        if line.contains(':') && !line.contains('\t') && !line.starts_with('.') {
            // One of the four header lines; anything else in this shape is a
            // malformed entry and must not be read as a header.
            let Some((key, value)) = line.split_once(':') else {
                return Err(format!(
                    "{BASELINE_REL}:{line_number}: malformed header line"
                ));
            };
            let key = key.trim();
            if !matches!(key, "workflows" | "jobs" | "fanout" | "opaque") {
                return Err(format!(
                    "{BASELINE_REL}:{line_number}: unknown header `{key}`"
                ));
            }
            value.trim().parse::<usize>().map_err(|e| {
                format!("{BASELINE_REL}:{line_number}: `{key}` is not a number: {e}")
            })?;
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err(format!(
                "{BASELINE_REL}:{line_number}: an entry is `<path>\\t<jobs>\\t<fanout>\\t<opaque>`, \
                 this line has {} tab-separated field(s)",
                fields.len()
            ));
        }
        let path = fields[0].trim();
        if !path.starts_with(WORKFLOWS_REL) {
            return Err(format!(
                "{BASELINE_REL}:{line_number}: `{path}` is not a workflow path"
            ));
        }
        let mut numbers = [0usize; 3];
        for (slot, field) in numbers.iter_mut().zip(fields[1..].iter()) {
            *slot = field.trim().parse::<usize>().map_err(|e| {
                format!(
                    "{BASELINE_REL}:{line_number}: `{path}` has a count that is not a number: {e}"
                )
            })?;
        }
        if entries.contains_key(path) {
            return Err(format!(
                "{BASELINE_REL}:{line_number}: `{path}` is pinned twice"
            ));
        }
        entries.insert(
            path.to_string(),
            Load {
                path: path.to_string(),
                jobs: numbers[0],
                fanout: numbers[1],
                opaque: numbers[2],
                // The baseline pins counts, not names; the names come from the
                // tree the gate is pointed at.
                opaque_jobs: Vec::new(),
            },
        );
    }

    let budget = Budget {
        workflows: header_value(text, "workflows")?,
        jobs: header_value(text, "jobs")?,
        fanout: header_value(text, "fanout")?,
        opaque: header_value(text, "opaque")?,
        entries,
    };

    // The header has to agree with the entries it summarises, or the ratchet
    // compares a total nobody can attribute to a file.
    let listed: Vec<Load> = budget.entries.values().cloned().collect();
    if budget.workflows != listed.len() {
        return Err(format!(
            "{BASELINE_REL}: the header pins {} workflow(s) but {} entry line(s) follow; \
             re-measure with `{REMEASURE}`",
            budget.workflows,
            listed.len()
        ));
    }
    for (label, pinned, measured) in [
        ("jobs", budget.jobs, sum(&listed, |load| load.jobs)),
        ("fanout", budget.fanout, sum(&listed, |load| load.fanout)),
        ("opaque", budget.opaque, sum(&listed, |load| load.opaque)),
    ] {
        if pinned != measured {
            return Err(format!(
                "{BASELINE_REL}: the header pins {label}={pinned} but the entries sum to \
                 {measured}; re-measure with `{REMEASURE}`"
            ));
        }
    }
    Ok(budget)
}

/// Compare a measurement against the pinned budget.
fn findings(loads: &[Load], budget: &Budget) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for load in loads {
        let Some(pinned) = budget.entries.get(&load.path) else {
            out.push(format!(
                "{} triggers on `pull_request` with {} job(s) but is absent from \
                 {BASELINE_REL}: the fan-out of the pull-request path may not grow silently; \
                 re-measure with `{REMEASURE}`",
                load.path, load.jobs
            ));
            continue;
        };
        if load.jobs > pinned.jobs {
            out.push(format!(
                "{} declares {} job(s) on the pull-request path, {} are pinned: a job added \
                 here is queued by every later push; re-measure with `{REMEASURE}` only if the \
                 work is meant to be permanent",
                load.path, load.jobs, pinned.jobs
            ));
        }
        if load.fanout > pinned.fanout {
            out.push(format!(
                "{} queues {} runner(s) on the pull-request path, {} are pinned: a matrix axis \
                 grew; re-measure with `{REMEASURE}`",
                load.path, load.fanout, pinned.fanout
            ));
        }
        if load.opaque > pinned.opaque {
            out.push(format!(
                "{} has {} job(s) this gate cannot count ({}), {} were pinned: an expression \
                 replaced literal text, or a reusable call reached outside this tree, either of \
                 which hides fan-out instead of budgeting it",
                load.path,
                load.opaque,
                load.opaque_jobs.join(", "),
                pinned.opaque
            ));
        }
    }
    let measured: BTreeMap<&str, &Load> = loads
        .iter()
        .map(|load| (load.path.as_str(), load))
        .collect();
    for path in budget.entries.keys() {
        if !measured.contains_key(path.as_str()) {
            out.push(format!(
                "{BASELINE_REL} pins `{path}` but that workflow no longer triggers on \
                 `pull_request` or no longer exists: a stale entry is budget the next change \
                 will spend without saying so; re-measure with `{REMEASURE}`"
            ));
        }
    }
    out
}

/// Rewrite the number of one header line, whatever it currently reads.
///
/// The canaries corrupt a baseline they did not write, so the number they
/// replace depends on the fixture's state; a literal `jobs: 3` would silently
/// corrupt nothing and the canary would pass for the wrong reason.
fn corrupt_header(text: &str, key: &str, replacement: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for line in text.lines() {
        if !done && !line.trim_start().starts_with('#') {
            if let Some((name, _)) = line.split_once(':') {
                if name.trim() == key {
                    let _ = writeln!(out, "{key}: {replacement}");
                    done = true;
                    continue;
                }
            }
        }
        let _ = writeln!(out, "{line}");
    }
    out
}

/// Read the budget and hold the tree to it.
fn check(root: &Path) -> Result<String, String> {
    let loads = measure(root)?;
    let path = root.join(BASELINE_REL);
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "{BASELINE_REL} could not be read ({e}); the pull-request fan-out has no budget, \
             so nothing holds it down. Emit one with `{REMEASURE}`"
        )
    })?;
    let budget = parse_baseline(&text)?;
    let found = findings(&loads, &budget);
    if !found.is_empty() {
        let mut message = format!(
            "pull-request fan-out is over budget ({} finding(s)):\n",
            found.len()
        );
        for finding in &found {
            let _ = writeln!(message, "  - {finding}");
        }
        let _ = writeln!(
            message,
            "measured: {} workflow(s), {} job(s), {} queued runner(s), {} job(s) this reader \
             cannot count; pinned: {}, {}, {}, {}",
            loads.len(),
            sum(&loads, |load| load.jobs),
            sum(&loads, |load| load.fanout),
            sum(&loads, |load| load.opaque),
            budget.workflows,
            budget.jobs,
            budget.fanout,
            budget.opaque
        );
        return Err(message);
    }
    Ok(format!(
        "ci-pull-request-fanout-is-budgeted OK: {} pull-request workflow(s) queue {} job(s) \
         ({} runner(s) at least, once countable matrices and reusable calls inside this tree are \
         multiplied out; {} job(s) this reader cannot count, so that runner figure is a floor) \
         against a pinned budget of {} job(s)",
        loads.len(),
        sum(&loads, |load| load.jobs),
        sum(&loads, |load| load.fanout),
        sum(&loads, |load| load.opaque),
        budget.jobs
    ))
}

/// Check the tree at `root`.
///
/// # Errors
///
/// Returns a finding when the workflow directory or the baseline cannot be
/// read, when the baseline is malformed or self-contradictory, and when the
/// tree's fan-out exceeds what the baseline pins.
pub fn run(root: &Path) -> Result<String, String> {
    run_args(root, &[])
}

/// Check the tree, or emit the baseline with `--print-baseline`.
///
/// # Errors
///
/// Returns a finding for an unknown argument, and otherwise whatever [`run`]
/// or the measurement returns.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        None => check(root),
        Some("--print-baseline") => Ok(baseline_text(&measure(root)?)),
        Some(other) => Err(format!(
            "unknown argument `{other}`; pass nothing for the budget check, or \
             `--print-baseline` to emit the pinned budget"
        )),
    }
}

/// Assert that an outcome which must be red actually is.
fn expect_red(label: &str, outcome: &Result<String, String>) -> Result<(), String> {
    if outcome.is_ok() {
        return Err(format!(
            "self-test: {label} passed and must fail; the gate cannot see this shape"
        ));
    }
    Ok(())
}

/// Assert that an outcome which must be green actually is.
fn expect_green(label: &str, outcome: &Result<String, String>) -> Result<(), String> {
    match outcome {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("self-test: {label} failed and must pass: {e}")),
    }
}

/// A light workflow: one job, no matrix.
const FIXTURE_LIGHT: &str = "name: Light\n\
on:\n  \
pull_request:\n\
permissions:\n  contents: read\n\
jobs:\n  \
lint:\n    \
name: Lint\n    \
runs-on: ubuntu-latest\n    \
steps:\n      - run: echo lint\n";

/// A heavy workflow: two jobs, one of them a two-entry literal matrix.
const FIXTURE_HEAVY: &str = "name: Heavy\n\
on:\n  \
pull_request:\n  \
schedule:\n    - cron: \"0 3 * * *\"\n\
permissions:\n  contents: read\n\
jobs:\n  \
build:\n    \
name: Build\n    \
runs-on: ubuntu-latest\n    \
strategy:\n      \
matrix:\n        \
os: [ubuntu-latest, macos-latest]\n    \
steps:\n      - run: echo build\n  \
prove:\n    \
name: Prove\n    \
runs-on: ubuntu-latest\n    \
steps:\n      - run: echo prove\n";

/// A workflow that only mentions the trigger inside a comment.
const FIXTURE_COMMENT_ONLY: &str = "name: Scheduled\n\
on:\n  \
# Not a pull_request trigger: this file runs on the schedule only.\n  \
schedule:\n    - cron: \"30 2 * * *\"\n\
jobs:\n  \
sweep:\n    \
runs-on: ubuntu-latest\n    \
steps:\n      - run: echo sweep\n";

/// Write the fixture tree and return its root.
fn fixture_tree(
    dir: &Path,
    heavy: &str,
    light: &str,
    extra: Option<(&str, &str)>,
) -> Result<(), String> {
    let workflows = dir.join(WORKFLOWS_REL);
    fs::create_dir_all(&workflows)
        .map_err(|e| format!("fixture tree could not be created: {e}"))?;
    fs::write(workflows.join("light.yml"), light)
        .map_err(|e| format!("fixture light.yml could not be written: {e}"))?;
    fs::write(workflows.join("heavy.yml"), heavy)
        .map_err(|e| format!("fixture heavy.yml could not be written: {e}"))?;
    fs::write(workflows.join("scheduled.yml"), FIXTURE_COMMENT_ONLY)
        .map_err(|e| format!("fixture scheduled.yml could not be written: {e}"))?;
    if let Some((name, body)) = extra {
        fs::write(workflows.join(name), body)
            .map_err(|e| format!("fixture {name} could not be written: {e}"))?;
    }
    Ok(())
}

/// Pin the budget the fixture tree actually measures.
fn pin_fixture(dir: &Path) -> Result<(), String> {
    let text = run_args(dir, &["--print-baseline"])?;
    fs::create_dir_all(dir.join(".github"))
        .map_err(|e| format!("fixture .github could not be created: {e}"))?;
    fs::write(dir.join(BASELINE_REL), text)
        .map_err(|e| format!("fixture baseline could not be written: {e}"))?;
    Ok(())
}

/// Measure one workflow source on its own, for the reader canaries.
///
/// These fixtures declare no reusable call, so the tree they are read against
/// is empty and the measurement cannot fail.
fn load_alone(path: &str, src: &str) -> Result<Load, String> {
    load_of(path, src, &BTreeMap::new(), &mut vec![String::from(path)])
}

/// Reader canaries: the trigger, the job count and the matrix product.
fn reader_suite() -> Result<(), String> {
    trigger_reader_suite()?;
    load_reader_suite()
}

/// Trigger canaries: every form of `pull_request` counts, prose does not.
fn trigger_reader_suite() -> Result<(), String> {
    if !triggers_on_pull_request(FIXTURE_LIGHT) {
        return Err(String::from(
            "self-test: a block-form `pull_request:` trigger was not read",
        ));
    }
    if !triggers_on_pull_request("on: [push, pull_request]\njobs:\n  a:\n    steps: []\n") {
        return Err(String::from(
            "self-test: an inline `on: [push, pull_request]` trigger was not read",
        ));
    }
    if !triggers_on_pull_request("on:\n  - pull_request\njobs:\n  a:\n    steps: []\n") {
        return Err(String::from(
            "self-test: a list-form `pull_request` trigger was not read",
        ));
    }
    if triggers_on_pull_request(FIXTURE_COMMENT_ONLY) {
        return Err(String::from(
            "self-test: a `pull_request` mention inside a comment was read as a trigger",
        ));
    }
    if triggers_on_pull_request("on:\n  push:\n    branches: [main]\njobs:\n  a:\n    steps: []\n")
    {
        return Err(String::from(
            "self-test: a push-only workflow was read as pull-request triggered",
        ));
    }
    Ok(())
}

/// Job and matrix canaries: the counts, the literal axes and the shapes that
/// hide a count behind an expression, an `include:` beside another axis or an
/// `exclude:`.
fn load_reader_suite() -> Result<(), String> {
    let light = load_alone(".github/workflows/light.yml", FIXTURE_LIGHT)?;
    if (light.jobs, light.fanout, light.opaque) != (1, 1, 0) {
        return Err(format!(
            "self-test: the light fixture measured jobs={} fanout={} opaque={}, expected 1/1/0",
            light.jobs, light.fanout, light.opaque
        ));
    }
    let heavy = load_alone(".github/workflows/heavy.yml", FIXTURE_HEAVY)?;
    if (heavy.jobs, heavy.fanout, heavy.opaque) != (2, 3, 0) {
        return Err(format!(
            "self-test: the heavy fixture measured jobs={} fanout={} opaque={}, expected 2/3/0 \
             (two jobs, one of them a two-entry literal matrix)",
            heavy.jobs, heavy.fanout, heavy.opaque
        ));
    }
    let block_sequence = FIXTURE_HEAVY.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os:\n          - ubuntu-latest\n          - macos-latest\n          - windows-latest",
    );
    let counted = load_alone(".github/workflows/heavy.yml", &block_sequence)?;
    if (counted.jobs, counted.fanout, counted.opaque) != (2, 4, 0) {
        return Err(format!(
            "self-test: a block-sequence matrix measured jobs={} fanout={} opaque={}, expected 2/4/0",
            counted.jobs, counted.fanout, counted.opaque
        ));
    }
    let expression = FIXTURE_HEAVY.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os: ${{ fromJSON(needs.plan.outputs.os) }}",
    );
    let hidden = load_alone(".github/workflows/heavy.yml", &expression)?;
    if (hidden.jobs, hidden.fanout, hidden.opaque) != (2, 2, 1) {
        return Err(format!(
            "self-test: an expression matrix measured jobs={} fanout={} opaque={}, expected 2/2/1 \
             (one job counted once and marked uncountable)",
            hidden.jobs, hidden.fanout, hidden.opaque
        ));
    }
    // `include:` beside another axis is not countable: the entries merge into
    // the cross-product.
    let include = FIXTURE_HEAVY.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os: [ubuntu-latest]\n        include:\n          - os: macos-latest",
    );
    if load_alone(".github/workflows/heavy.yml", &include)?.opaque != 1 {
        return Err(String::from(
            "self-test: a matrix mixing `include:` with another axis was counted instead of \
             marked uncountable",
        ));
    }
    // `include:` on its own is countable, and the shape the tree really carries
    // puts `fail-fast:` between `strategy:` and `matrix:`. An earlier reader
    // returned (1, false) here because it only looked at named axes, which
    // under-counted two two-arch batteries and reported `opaque: 0` for a tree
    // that has three include-only matrices.
    let include_only = "name: Two Arch\n\
on:\n  pull_request:\n\
jobs:\n  conformance:\n    \
if: ${{ github.event_name != 'pull_request' }}\n    \
name: Conformance (${{ matrix.arch }})\n    \
runs-on: ${{ matrix.runner }}\n    \
strategy:\n      fail-fast: false\n      \
matrix:\n        include:\n          - arch: x86_64\n            \
runner: ubuntu-24.04\n          - arch: aarch64\n            \
runner: ubuntu-24.04-arm\n    steps:\n      - run: echo prove\n";
    let counted_include = load_alone(".github/workflows/two-arch.yml", include_only)?;
    if (
        counted_include.jobs,
        counted_include.fanout,
        counted_include.opaque,
    ) != (1, 2, 0)
    {
        return Err(format!(
            "self-test: an include-only matrix measured jobs={} fanout={} opaque={}, expected \
             1/2/0 (two entries, no other axis)",
            counted_include.jobs, counted_include.fanout, counted_include.opaque
        ));
    }
    // `exclude:` removes combinations, so the count is not knowable here.
    let excluded = FIXTURE_HEAVY.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os: [ubuntu-latest, macos-latest]\n        exclude:\n          - os: macos-latest",
    );
    if load_alone(".github/workflows/heavy.yml", &excluded)?.opaque != 1 {
        return Err(String::from(
            "self-test: a matrix with an `exclude:` list was counted instead of marked uncountable",
        ));
    }
    // A flow sequence spread over lines still counts its items.
    let spread = FIXTURE_HEAVY.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os: [\n          ubuntu-latest,\n          macos-latest,\n          windows-latest,\n        ]",
    );
    let spread_load = load_alone(".github/workflows/heavy.yml", &spread)?;
    if (spread_load.fanout, spread_load.opaque) != (4, 0) {
        return Err(format!(
            "self-test: a multi-line flow sequence measured fanout={} opaque={}, expected 4/0",
            spread_load.fanout, spread_load.opaque
        ));
    }
    Ok(())
}

/// Budget canaries: growth, staleness, opacity and every corrupt baseline shape.
fn budget_suite() -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ci-fanout")?;
    fixture_tree(&dir, FIXTURE_HEAVY, FIXTURE_LIGHT, None)?;
    pin_fixture(&dir)?;
    expect_green("the correctly pinned fixture", &check(&dir))?;

    // A job added to an existing workflow, without re-measuring.
    let grown = FIXTURE_HEAVY.replace(
        "  prove:\n",
        "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo extra\n  prove:\n",
    );
    fixture_tree(&dir, &grown, FIXTURE_LIGHT, None)?;
    expect_red("a job added without re-measuring", &check(&dir))?;
    pin_fixture(&dir)?;
    expect_green("the same growth once re-measured", &check(&dir))?;

    // A countable matrix replaced by an expression: the fan-out hides.
    let hidden = grown.replace(
        "os: [ubuntu-latest, macos-latest]",
        "os: ${{ fromJSON(needs.plan.outputs.os) }}",
    );
    fixture_tree(&dir, &hidden, FIXTURE_LIGHT, None)?;
    expect_red("a literal matrix replaced by an expression", &check(&dir))?;

    // A new pull-request workflow that the baseline has never seen.
    fixture_tree(
        &dir,
        &hidden,
        FIXTURE_LIGHT,
        Some((
            "newcomer.yml",
            "name: New\non:\n  pull_request:\njobs:\n  one:\n    steps:\n      - run: echo one\n",
        )),
    )?;
    expect_red(
        "a new pull-request workflow absent from the baseline",
        &check(&dir),
    )?;

    // The trigger removed but the entry left behind: budget nobody spends.
    fixture_tree(
        &dir,
        &hidden.replace("  pull_request:\n", "  push:\n    branches: [main]\n"),
        FIXTURE_LIGHT,
        None,
    )?;
    expect_red("a stale baseline entry whose trigger is gone", &check(&dir))?;

    // Back to the pinned shape, then corrupt the baseline itself.
    fixture_tree(&dir, &grown, FIXTURE_LIGHT, None)?;
    pin_fixture(&dir)?;
    let good = fs::read_to_string(dir.join(BASELINE_REL))
        .map_err(|e| format!("self-test: the fixture baseline could not be read back: {e}"))?;

    fs::remove_file(dir.join(BASELINE_REL))
        .map_err(|e| format!("self-test: the fixture baseline could not be removed: {e}"))?;
    expect_red("a missing baseline", &check(&dir))?;
    fs::write(dir.join(BASELINE_REL), &good)
        .map_err(|e| format!("self-test: the fixture baseline could not be restored: {e}"))?;

    if corrupt_header(&good, "jobs", "three") == good {
        return Err(String::from(
            "self-test: the baseline corruptor changed nothing, so the canaries below would \
             pass for the wrong reason",
        ));
    }
    for (label, corrupt) in [
        (
            "an entry with the wrong field count",
            good.replace("light.yml\t1\t1\t0", "light.yml\t1\t1"),
        ),
        ("an unknown header key", good.replace("jobs:", "jobz:")),
        (
            "a non-numeric count",
            corrupt_header(&good, "jobs", "three"),
        ),
        (
            "a header that contradicts its entries",
            corrupt_header(&good, "jobs", "9999"),
        ),
        (
            "a workflow count that contradicts the entries",
            corrupt_header(&good, "workflows", "7"),
        ),
        (
            "an entry that is not a workflow path",
            good.replace(".github/workflows/light.yml", "src/lib.rs"),
        ),
    ] {
        fs::write(dir.join(BASELINE_REL), corrupt)
            .map_err(|e| format!("self-test: a corrupt baseline could not be written: {e}"))?;
        expect_red(label, &check(&dir))?;
    }
    fs::write(dir.join(BASELINE_REL), &good)
        .map_err(|e| format!("self-test: the fixture baseline could not be restored: {e}"))?;
    expect_green("the restored fixture", &check(&dir))?;
    Ok(())
}

/// A reusable workflow: it answers `workflow_call` only, and declares two jobs
/// that each spread over a three-entry literal matrix.
const FIXTURE_CALLEE: &str = "name: Deep\n\
on:\n  \
workflow_call:\n\
jobs:\n  \
first:\n    \
runs-on: ubuntu-latest\n    \
strategy:\n      \
matrix:\n        \
os: [a, b, c]\n    \
steps:\n      - run: echo first\n  \
second:\n    \
runs-on: ubuntu-latest\n    \
strategy:\n      \
matrix:\n        \
os: [a, b, c]\n    \
steps:\n      - run: echo second\n";

/// A pull-request workflow that calls the reusable one and also queues a job of
/// its own. A `uses:` job holds no runner, so this measures 3 jobs and 7
/// runners, not 2 and 2.
const FIXTURE_CALLER: &str = "name: Caller\n\
on:\n  \
pull_request:\n\
jobs:\n  \
deep:\n    \
uses: ./.github/workflows/deep.yml\n  \
plain:\n    \
runs-on: ubuntu-latest\n    \
steps:\n      - run: echo plain\n";

/// A pull-request workflow whose reusable call leaves this repository, so its
/// callee's jobs cannot be read here.
const FIXTURE_FOREIGN_CALLER: &str = "name: Foreign\n\
on:\n  \
pull_request:\n\
jobs:\n  \
borrowed:\n    \
uses: budlum-xyz/elsewhere/.github/workflows/deep.yml@v1\n";

/// Write a tree of workflow files, replacing whatever was there.
fn fixture_call_tree(dir: &Path, files: &[(&str, &str)]) -> Result<(), String> {
    let workflows = dir.join(WORKFLOWS_REL);
    let _ = fs::remove_dir_all(&workflows);
    fs::create_dir_all(&workflows)
        .map_err(|e| format!("fixture tree could not be created: {e}"))?;
    for (name, body) in files {
        fs::write(workflows.join(name), body)
            .map_err(|e| format!("fixture {name} could not be written: {e}"))?;
    }
    Ok(())
}

/// Measure one fixture tree the way `measure` does.
fn measure_call_tree(dir: &Path) -> Result<Load, String> {
    let loads = measure(dir)?;
    loads
        .into_iter()
        .find(|load| load.path == ".github/workflows/caller.yml")
        .ok_or_else(|| String::from("self-test: the caller workflow was not measured"))
}

/// Reusable-call canaries: a callee's jobs are this push's jobs, a call out of
/// the tree is uncountable, and a missing or circular callee is a finding.
fn reusable_suite() -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-fanout-calls")?;
    fixture_call_tree(
        &dir,
        &[("deep.yml", FIXTURE_CALLEE), ("caller.yml", FIXTURE_CALLER)],
    )?;

    // Reader: the callee's load is attributed to the caller.
    let load = measure_call_tree(&dir)?;
    if (load.jobs, load.fanout, load.opaque) != (3, 7, 0) {
        return Err(format!(
            "self-test: a job calling a reusable workflow with 2 jobs and 6 runners measured \
             {} job(s) and {} runner(s); the callee's fan-out is invisible to this reader",
            load.jobs, load.fanout
        ));
    }

    // Budget: honest pin is green, the callee growing under a stale pin is red.
    pin_fixture(&dir)?;
    expect_green("a correctly pinned reusable call", &check(&dir))?;
    let widened = FIXTURE_CALLEE.replace(
        "  second:\n",
        "  third:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo third\n  second:\n",
    );
    if widened == FIXTURE_CALLEE {
        return Err(String::from(
            "self-test: the callee-widening canary changed nothing, so the red expectation \
             below would pass for the wrong reason",
        ));
    }
    fixture_call_tree(
        &dir,
        &[("deep.yml", &widened), ("caller.yml", FIXTURE_CALLER)],
    )?;
    expect_red(
        "a reusable callee that grew under a stale pin",
        &check(&dir),
    )?;
    pin_fixture(&dir)?;
    expect_green("the same growth once re-measured", &check(&dir))?;

    // Reader: a step-level `- uses:` is not a reusable call.
    let stepped = "on:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
    let load = load_of(
        ".github/workflows/stepped.yml",
        stepped,
        &BTreeMap::new(),
        &mut vec![String::from(".github/workflows/stepped.yml")],
    )?;
    if (load.jobs, load.fanout, load.opaque) != (1, 1, 0) {
        return Err(format!(
            "self-test: a step-level `- uses:` was read as a reusable workflow call ({} job(s), \
             {} runner(s), {} uncountable)",
            load.jobs, load.fanout, load.opaque
        ));
    }

    // Reader: a call out of this tree is counted once and pinned as uncountable.
    fixture_call_tree(&dir, &[("caller.yml", FIXTURE_FOREIGN_CALLER)])?;
    let load = measure_call_tree(&dir)?;
    if load.opaque != 1 || load.fanout != 1 {
        return Err(format!(
            "self-test: a reusable call into another repository measured {} runner(s) and {} \
             uncountable job(s); it must be counted once and pinned, not taken as free capacity",
            load.fanout, load.opaque
        ));
    }
    if !load
        .opaque_jobs
        .iter()
        .any(|name| name.contains("budlum-xyz/elsewhere"))
    {
        return Err(String::from(
            "self-test: an uncountable reusable call did not name the repository it reaches",
        ));
    }

    // A callee that is not in the tree is a finding, not a guess: the
    // measurement itself refuses, so there is no budget to pin and no way for
    // the gate to fall back to counting the call as one cheap job.
    fixture_call_tree(&dir, &[("caller.yml", FIXTURE_CALLER)])?;
    expect_red(
        "a reusable call to a workflow that is not in the tree",
        &check(&dir),
    )?;
    expect_red(
        "emitting a budget for a tree with a missing callee",
        &run_args(&dir, &["--print-baseline"]),
    )?;

    // A circle is a finding, and the reader must not loop to find that out.
    let circle_a = "on:\n  pull_request:\njobs:\n  next:\n    uses: ./.github/workflows/b.yml\n";
    let circle_b = "on:\n  workflow_call:\njobs:\n  back:\n    uses: ./.github/workflows/a.yml\n";
    fixture_call_tree(&dir, &[("a.yml", circle_a), ("b.yml", circle_b)])?;
    expect_red(
        "reusable workflows that call each other in a circle",
        &check(&dir),
    )?;
    Ok(())
}

/// Prove the gate can fail, then that it passes on the shape it wants.
///
/// # Errors
///
/// Returns a finding when any canary disagrees with the rule it exercises.
pub fn self_test() -> Result<String, String> {
    reader_suite()?;
    budget_suite()?;
    reusable_suite()?;
    Ok(String::from(
        "ci-pull-request-fanout-is-budgeted self-test: the reader counts triggers, jobs, literal \
         matrices and reusable calls, and the budget refuses growth, staleness, hidden matrices, \
         a callee that is missing or circular, and every corrupt baseline shape",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_budget_self_test_passes() {
        let outcome = self_test();
        assert!(outcome.is_ok(), "self-test failed: {outcome:?}");
    }

    #[test]
    fn trigger_reader_is_not_fooled_by_a_comment() {
        assert!(triggers_on_pull_request(
            "on:\n  pull_request:\njobs:\n  a:\n    steps: []\n"
        ));
        assert!(!triggers_on_pull_request(
            "on:\n  # pull_request: mentioned in prose only\n  schedule:\n    - cron: \"0 0 * * *\"\njobs:\n  a:\n    steps: []\n"
        ));
    }

    #[test]
    fn flow_sequence_items_split_on_top_level_commas() {
        assert_eq!(
            flow_items("[a, b, c]"),
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(
            flow_items("[{a: 1, b: 2}, {a: 3, b: 4}]"),
            Some(vec!["{a: 1, b: 2}".to_string(), "{a: 3, b: 4}".to_string()])
        );
        assert_eq!(flow_items("[]"), None);
        assert_eq!(flow_items("ubuntu-latest"), None);
    }

    #[test]
    fn a_job_level_uses_is_a_reusable_call_and_a_step_level_one_is_not() {
        let job = vec![
            String::from("    uses: ./.github/workflows/deep.yml"),
            String::from("    with:"),
            String::from("      flag: true"),
        ];
        assert_eq!(
            job_reusable_call(&job).as_deref(),
            Some("./.github/workflows/deep.yml")
        );
        let stepped = vec![
            String::from("    runs-on: ubuntu-latest"),
            String::from("    steps:"),
            String::from("      - uses: actions/checkout@v4"),
        ];
        assert_eq!(job_reusable_call(&stepped), None);
    }

    #[test]
    fn a_reusable_target_inside_the_tree_is_local_and_anywhere_else_is_foreign() {
        assert!(matches!(
            classify_reusable("./.github/workflows/deep.yml"),
            ReusableTarget::Local(path) if path == ".github/workflows/deep.yml"
        ));
        assert!(matches!(
            classify_reusable(".github/workflows/deep.yaml"),
            ReusableTarget::Local(_)
        ));
        assert!(matches!(
            classify_reusable("budlum-xyz/elsewhere/.github/workflows/deep.yml@v1"),
            ReusableTarget::Foreign(_)
        ));
        // A local-looking path that carries a revision is not readable here.
        assert!(matches!(
            classify_reusable("./.github/workflows/deep.yml@branch"),
            ReusableTarget::Foreign(_)
        ));
    }

    #[test]
    fn an_expression_matrix_is_counted_once_and_marked() {
        let src = "on:\n  pull_request:\njobs:\n  a:\n    strategy:\n      matrix:\n        os: ${{ fromJSON(x) }}\n    steps:\n      - run: true\n";
        let load = load_of(
            ".github/workflows/a.yml",
            src,
            &BTreeMap::new(),
            &mut vec![String::from(".github/workflows/a.yml")],
        )
        .expect("a single workflow with no reusable call always measures");
        assert_eq!((load.jobs, load.fanout, load.opaque), (1, 1, 1));
    }
}
