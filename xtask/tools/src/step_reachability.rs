//! Read a workflow's step headers and say which steps can actually run.
//!
//! It replaces `ops/scripts/check-step-reachability.py`.
//!
//! CI here has learned the same lesson three times, from three different
//! steps: a job is a sequence, and a step that fails skips every later step
//! that does not carry `if: always()` or an equivalent guard. The fix is
//! written in `docs/CONTRIBUTING.md`: a red step must never stand between a
//! reader and another step's answer.
//!
//! That fix is expressed in `if:` expressions, and expressions are the one part
//! of a workflow that cannot be checked locally: the runner evaluates them.
//! A typo in a step id inside a guard fails open. `steps.nothere.outcome` is
//! not `'success'`, so the step is skipped, and a job with thirty skipped
//! gates looks like a job with thirty green ones. That is the gap this closes.
//!
//! Two hard findings, then a report:
//!
//! * a `steps.<id>` reference whose id no step in the same job declares;
//! * a guard that references an id declared later in the same job. Steps are
//!   evaluated in order, so the reference is null and the step is skipped.
//!
//! `--fail JOB:STEP` answers the question a red run asks: if this step fails,
//! which steps still run? It evaluates the guards with the subset of the
//! expression language the workflows here use (`always()`, `success()`,
//! `failure()`, `steps.<id>.outcome == '<x>'`, `!`, `&&`, `||`, parentheses).
//!
//! Only step headers are parsed (`id:`, `name:`, `if:`, `uses:`), at the
//! indentation Actions uses, so no YAML parser is needed. `run:` bodies are
//! ignored on purpose.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::report::{py_repr, Report};

const STEP_START: &str = "      - ";

/// One step header.
#[derive(Debug)]
struct Step {
    name: String,
    id: String,
    guard: Option<String>,
    raw: String,
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// `^  ([A-Za-z0-9_-]+):\s*$`
fn job_key(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    let end = rest.find(|c: char| !is_name_char(c))?;
    if end == 0 {
        return None;
    }
    let after = rest[end..].strip_prefix(':')?;
    after.trim().is_empty().then(|| &rest[..end])
}

/// Job id to (start, end) line indices, in file order, using the file's own
/// indentation. A repeated key keeps its first position and its last range.
fn jobs_of(text: &str) -> Vec<(String, (usize, usize))> {
    let lines: Vec<&str> = text.split('\n').collect();
    let keys: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| job_key(line).map(|name| (i, name)))
        .collect();
    let mut out: Vec<(String, (usize, usize))> = Vec::new();
    for (k, (i, name)) in keys.iter().enumerate() {
        let end = keys.get(k + 1).map_or(lines.len(), |next| next.0);
        match out.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = (*i, end),
            None => out.push(((*name).to_string(), (*i, end))),
        }
    }
    out
}

/// `^\s*<name>: (.*)$` on the first line of the block that has it.
fn field(block: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}: ");
    let value = block
        .split('\n')
        .find_map(|line| line.trim_start().strip_prefix(&prefix))?
        .trim();
    // YAML accepts a wholly quoted scalar; a value that merely ends with an
    // apostrophe (an expression like `... == 'success'`) must survive.
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > 1
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        let inner: String = chars[1..chars.len() - 1].iter().collect();
        return Some(inner.trim().to_string());
    }
    Some(value.to_string())
}

/// Header fields of every step in `job`, in file order.
fn steps_of(text: &str, job: &str) -> Result<Vec<Step>, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let (start, end) = jobs_of(text)
        .into_iter()
        .find(|(name, _)| name == job)
        .map(|(_, range)| range)
        .ok_or_else(|| format!("no job named {}", py_repr(job)))?;
    let idx: Vec<usize> = (start..end)
        .filter(|&i| lines[i].starts_with(STEP_START))
        .collect();
    let mut steps = Vec::new();
    for (k, &s) in idx.iter().enumerate() {
        let e = idx.get(k + 1).copied().unwrap_or(end);
        // The first line carries the key too, as `- name: X`, so it is
        // rewritten to the same shape as the rest of the block.
        let block = format!(
            "      {}\n{}",
            &lines[s][STEP_START.len()..],
            lines[s + 1..e].join("\n")
        );
        let name = field(&block, "name")
            .filter(|v| !v.is_empty())
            .or_else(|| field(&block, "uses").filter(|v| !v.is_empty()))
            .unwrap_or_default();
        steps.push(Step {
            name,
            id: field(&block, "id").unwrap_or_default(),
            guard: field(&block, "if").filter(|v| !v.is_empty()),
            raw: block,
        });
    }
    Ok(steps)
}

/// Split on `op` outside quotes and parentheses.
fn split_top(expr: &str, op: &str) -> Vec<String> {
    let chars: Vec<char> = expr.chars().collect();
    let op: Vec<char> = op.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_quote = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            in_quote = !in_quote;
        }
        if !in_quote && c == '(' {
            depth += 1;
        }
        if !in_quote && c == ')' {
            depth -= 1;
        }
        if !in_quote && depth == 0 && chars[i..].starts_with(&op) {
            out.push(std::mem::take(&mut cur));
            i += op.len();
            continue;
        }
        cur.push(c);
        i += 1;
    }
    out.push(cur);
    out.into_iter().filter(|x| !x.trim().is_empty()).collect()
}

/// `steps\.([A-Za-z0-9_-]+)\.outcome\s*==\s*'(\w+)'` over the whole text.
fn outcome_test(e: &str) -> Option<(&str, &str)> {
    let rest = e.strip_prefix("steps.")?;
    let end = rest.find(|c: char| !is_name_char(c))?;
    if end == 0 {
        return None;
    }
    let (id, rest) = rest.split_at(end);
    let rest = rest.strip_prefix(".outcome")?.trim_start();
    let rest = rest.strip_prefix("==")?.trim_start();
    let rest = rest.strip_prefix('\'')?.strip_suffix('\'')?;
    let word = !rest.is_empty() && rest.chars().all(|c| c.is_alphanumeric() || c == '_');
    word.then_some((id, rest))
}

/// Evaluate the guarded subset of the Actions expression language.
fn evaluate(expr: &str, ids: &HashMap<String, String>, failed: bool) -> Result<bool, String> {
    let e = expr.trim();
    if let Some(rest) = e.strip_prefix('!') {
        return Ok(!evaluate(rest, ids, failed)?);
    }
    for op in ["||", "&&"] {
        let parts = split_top(e, op);
        if parts.len() > 1 {
            let vals = parts
                .iter()
                .map(|x| evaluate(x, ids, failed))
                .collect::<Result<Vec<bool>, String>>()?;
            return Ok(if op == "&&" {
                vals.iter().all(|v| *v)
            } else {
                vals.iter().any(|v| *v)
            });
        }
    }
    if let Some(inner) = e.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        return evaluate(inner, ids, failed);
    }
    if let Some((id, want)) = outcome_test(e) {
        return Ok(ids.get(id).is_some_and(|got| got == want));
    }
    match e {
        "always()" => Ok(true),
        "success()" => Ok(!failed),
        "failure()" => Ok(failed),
        "cancelled()" => Ok(false),
        _ => Err(format!(
            "expression outside the supported subset: {}",
            py_repr(e)
        )),
    }
}

/// Every `steps.<id>.` reference in an expression, like `re.findall`.
fn step_refs(guard: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut at = 0;
    while let Some(found) = guard[at..].find("steps.") {
        let name_start = at + found + "steps.".len();
        let tail = &guard[name_start..];
        let len = tail.find(|c: char| !is_name_char(c)).unwrap_or(tail.len());
        if len > 0 && tail[len..].starts_with('.') {
            refs.push(tail[..len].to_string());
            at = name_start + len + 1;
        } else {
            at += found + 1;
        }
    }
    refs
}

/// Hard findings: dangling and forward `steps.<id>` references.
///
/// # Errors
///
/// Never in practice; kept as a `Result` so a malformed job table is loud.
pub fn check(text: &str, source: &str) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    for (job, _) in jobs_of(text) {
        let steps = steps_of(text, &job)?;
        let mut positions: HashMap<&str, usize> = HashMap::new();
        for (i, s) in steps.iter().enumerate() {
            if !s.id.is_empty() {
                positions.insert(&s.id, i);
            }
        }
        for (i, s) in steps.iter().enumerate() {
            let Some(guard) = &s.guard else { continue };
            for reference in step_refs(guard) {
                match positions.get(reference.as_str()) {
                    None => {
                        let shown = if s.name.is_empty() {
                            s.raw.split('\n').next().unwrap_or("")
                        } else {
                            &s.name
                        };
                        findings.push(format!(
                            "{source}: job {}, step {}: guard references `steps.{reference}`, \
                             which no step in this job declares - every step behind this guard is skipped",
                            py_repr(&job),
                            py_repr(shown),
                        ));
                    }
                    Some(&at) if at > i => findings.push(format!(
                        "{source}: job {}, step {}: guard references `steps.{reference}`, declared later in \
                         the same job - the reference is null at evaluation time, so the step \
                         is skipped",
                        py_repr(&job),
                        py_repr(&s.name),
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    Ok(findings)
}

/// One row of the `--fail` table: step name, verdict, outcome.
type Row = (String, &'static str, String);

/// Which steps run when `fail_step` in `fail_job` fails and the rest succeed.
///
/// # Errors
///
/// If the job does not exist in the text.
pub fn reachability(text: &str, fail_job: &str, fail_step: &str) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    let mut ids: HashMap<String, String> = HashMap::new();
    let mut failed = false;
    for s in steps_of(text, fail_job)? {
        let run = match &s.guard {
            Some(guard) => match evaluate(guard, &ids, failed) {
                Ok(v) => v,
                Err(message) => {
                    rows.push((s.name, "UNKNOWN", message));
                    continue;
                }
            },
            None => !failed,
        };
        let outcome = if s.name == fail_step {
            "failure"
        } else {
            "success"
        };
        if !s.id.is_empty() {
            ids.insert(s.id.clone(), outcome.to_string());
        }
        if outcome == "failure" {
            failed = true;
        }
        rows.push((
            s.name,
            if run { "run" } else { "SKIP" },
            outcome.to_string(),
        ));
    }
    Ok(rows)
}

const SELF_TEST_YAML: &str = "name: fixture
on: push
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - id: rust
        uses: dtolnay/rust-toolchain@x
      - name: Verdict
        run: cargo test
      - name: Guarded and reachable
        if: always() && steps.rust.outcome == 'success'
        run: cargo fmt --check
  dangling:
    runs-on: ubuntu-latest
    steps:
      - name: Guarded on nothing
        if: always() && steps.nothere.outcome == 'success'
        run: echo unreachable
  forward:
    runs-on: ubuntu-latest
    steps:
      - name: Runs before its guard's id exists
        if: always() && steps.later.outcome == 'success'
        run: echo skipped
      - id: later
        run: echo hi
  masked:
    runs-on: ubuntu-latest
    steps:
      - id: first
        name: First
        run: exit 1
      - name: Unguarded later verdict
        run: cargo test
      - name: Guarded later verdict
        if: always() && steps.first.outcome == 'success'
        run: echo skipped-too
";

/// The workflow files `*.yml` under `.github/workflows`, sorted, as
/// (name to show, path to read). Hidden files are skipped like a shell glob.
fn default_workflows(root: &Path) -> Vec<(String, PathBuf)> {
    let dir = root.join(".github").join("workflows");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| Path::new(n).extension().is_some_and(|x| x == "yml") && !n.starts_with('.'))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| (format!(".github/workflows/{n}"), dir.join(&n)))
        .collect()
}

fn expect(cond: bool, what: &str, out: &mut String) -> i32 {
    if cond {
        0
    } else {
        let _ = writeln!(out, "FAIL [step-reachability-self-test]: {what}");
        1
    }
}

fn self_test(root: &Path) -> Report {
    let mut out = String::new();
    let mut rc = 0;
    let text = SELF_TEST_YAML;
    let found = check(text, "fixture").unwrap_or_default();
    let joined = found.join("\n");
    rc |= expect(
        found.len() == 2,
        &format!(
            "expected exactly 2 findings, got {}:\n{joined}",
            found.len()
        ),
        &mut out,
    );
    rc |= expect(
        joined.contains("nothere"),
        "the dangling reference was not reported",
        &mut out,
    );
    rc |= expect(
        joined.contains("declared later"),
        "the forward reference was not reported",
        &mut out,
    );
    let rows = reachability(text, "masked", "First").unwrap_or_default();
    let skipped: Vec<&str> = rows
        .iter()
        .filter(|r| r.1 == "SKIP")
        .map(|r| r.0.as_str())
        .collect();
    rc |= expect(
        skipped == ["Unguarded later verdict", "Guarded later verdict"],
        &format!("a red first step must skip the unguarded step; got {skipped:?}"),
        &mut out,
    );
    let rows = reachability(text, "ok", "Verdict").unwrap_or_default();
    let ran: Vec<&str> = rows
        .iter()
        .filter(|r| r.1 == "run")
        .map(|r| r.0.as_str())
        .collect();
    rc |= expect(
        ran.contains(&"Guarded and reachable"),
        &format!(
            "a guard on a successful toolchain step must run even when an earlier step is red; ran={ran:?}"
        ),
        &mut out,
    );
    rc |= expect(
        evaluate("hash()", &HashMap::new(), false).is_err(),
        "an unsupported expression was accepted silently",
        &mut out,
    );
    let real = default_workflows(root);
    if !real.is_empty() {
        let mut n = 0;
        for (shown, path) in &real {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            n += check(&content, shown).map_or(1, |f| f.len());
        }
        rc |= expect(
            n == 0,
            &format!("{n} dangling/forward reference(s) in this repository"),
            &mut out,
        );
    }
    if rc == 0 {
        let _ = writeln!(
            out,
            "ok: step-reachability self-test (2 findings, 4 guard behaviours, {} real workflows)",
            real.len()
        );
    }
    Report::exit_with(out, rc)
}

/// The `--fail JOB:STEP` table.
fn fail_table(files: &[(String, PathBuf)], spec: &str) -> Report {
    let Some((job, step)) = spec.split_once(':') else {
        return Report::fail_with("usage: --fail JOB:STEP-NAME\n".to_string(), 2);
    };
    let mut text = String::new();
    for (_, path) in files {
        if let Ok(content) = std::fs::read_to_string(path) {
            if jobs_of(&content).iter().any(|(name, _)| name == job) {
                text.push_str(&content);
            }
        }
    }
    match reachability(&text, job, step) {
        Ok(rows) => {
            let mut out = String::new();
            for (name, verdict, outcome) in rows {
                let _ = writeln!(out, "{verdict:<4} {outcome:<9} {name}");
            }
            Report::ok(out)
        }
        Err(e) => Report::fail_with(format!("FAIL: {e}\n"), 1),
    }
}

/// Run the tool with its command line arguments.
#[must_use]
pub fn cli(args: &[&str], root: &Path) -> Report {
    if args.contains(&"--self-test") {
        return self_test(root);
    }
    let mut fail: Option<String> = None;
    let mut kept: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if let Some(value) = a.strip_prefix("--fail=") {
            fail = Some(value.to_string());
        } else if a == "--fail" {
            fail = it.next().map(|v| (*v).to_string());
        } else {
            kept.push(a);
        }
    }
    let files: Vec<(String, PathBuf)> = if kept.is_empty() {
        default_workflows(root)
    } else {
        kept.iter()
            .map(|a| ((*a).to_string(), PathBuf::from(a)))
            .collect()
    };
    if files.is_empty() {
        return Report::exit_with(
            "FAIL [step-reachability]: no workflow files found; a check that scans nothing passes nothing\n"
                .to_string(),
            1,
        );
    }
    if let Some(spec) = fail.filter(|s| !s.is_empty()) {
        return fail_table(&files, &spec);
    }
    let mut findings = Vec::new();
    for (shown, path) in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return Report::fail_with(
                    format!("FAIL: {} could not be read: {e}\n", path.display()),
                    1,
                );
            }
        };
        match check(&content, shown) {
            Ok(f) => findings.extend(f),
            Err(e) => return Report::fail_with(format!("FAIL: {e}\n"), 1),
        }
    }
    if findings.is_empty() {
        return Report::ok(format!(
            "ok: every steps.<id> guard resolves to an id declared earlier in its job ({} workflows)\n",
            files.len()
        ));
    }
    let mut out = String::new();
    for x in &findings {
        let _ = writeln!(out, "FAIL [step-reachability]: {x}");
    }
    let _ = writeln!(
        out,
        "{} finding(s) in {} workflow(s)",
        findings.len(),
        files.len()
    );
    Report::exit_with(out, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn the_fixture_has_exactly_the_two_silent_skip_findings() {
        let found = check(SELF_TEST_YAML, "fixture").expect("fixture parses");
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("job 'dangling', step 'Guarded on nothing'"));
        assert!(found[0].contains("`steps.nothere`"));
        assert!(found[1].contains("declared later"));
    }

    #[test]
    fn a_red_first_step_skips_the_unguarded_step() {
        let rows = reachability(SELF_TEST_YAML, "masked", "First").expect("job exists");
        let skipped: Vec<&str> = rows
            .iter()
            .filter(|r| r.1 == "SKIP")
            .map(|r| r.0.as_str())
            .collect();
        assert_eq!(
            skipped,
            ["Unguarded later verdict", "Guarded later verdict"]
        );
    }

    #[test]
    fn a_toolchain_guard_still_runs_behind_a_red_verdict() {
        let rows = reachability(SELF_TEST_YAML, "ok", "Verdict").expect("job exists");
        let guarded = rows.iter().find(|r| r.0 == "Guarded and reachable");
        assert_eq!(guarded.map(|r| r.1), Some("run"));
    }

    #[test]
    fn an_unknown_job_is_an_error() {
        assert!(reachability(SELF_TEST_YAML, "nope", "x").is_err());
    }

    #[test]
    fn expressions_follow_the_supported_subset() {
        let none = ids(&[]);
        let done = ids(&[("a", "success"), ("b", "failure")]);
        assert_eq!(evaluate("always()", &none, true), Ok(true));
        assert_eq!(evaluate("success()", &none, true), Ok(false));
        assert_eq!(evaluate("failure()", &none, true), Ok(true));
        assert_eq!(evaluate("cancelled()", &none, true), Ok(false));
        assert_eq!(evaluate("!failure()", &none, false), Ok(true));
        assert_eq!(
            evaluate("steps.a.outcome == 'success'", &done, false),
            Ok(true)
        );
        assert_eq!(
            evaluate("steps.b.outcome=='success'", &done, false),
            Ok(false)
        );
        assert_eq!(
            evaluate("steps.zzz.outcome == 'success'", &done, false),
            Ok(false)
        );
        assert_eq!(
            evaluate(
                "always() && (steps.a.outcome == 'success' || steps.b.outcome == 'success')",
                &done,
                true
            ),
            Ok(true)
        );
        assert_eq!(
            evaluate("always() && steps.b.outcome == 'success'", &done, true),
            Ok(false)
        );
    }

    #[test]
    fn an_unsupported_expression_is_refused_with_its_text() {
        let err = evaluate("hash()", &ids(&[]), false).expect_err("not in the subset");
        assert_eq!(err, "expression outside the supported subset: 'hash()'");
    }

    #[test]
    fn splitting_ignores_quotes_and_parentheses() {
        assert_eq!(split_top("a && (b && c)", "&&"), ["a ", " (b && c)"]);
        assert_eq!(
            split_top("x == 'a && b' && y", "&&"),
            ["x == 'a && b' ", " y"]
        );
        assert_eq!(split_top("only", "&&"), ["only"]);
    }

    #[test]
    fn step_references_are_found_like_findall() {
        assert_eq!(
            step_refs("steps.a.outcome == 'x' && steps.b-2.conclusion"),
            ["a", "b-2"]
        );
        assert!(step_refs("steps.nodot").is_empty());
    }

    #[test]
    fn quoted_guards_keep_an_inner_apostrophe() {
        assert_eq!(
            field("      if: \"always()\"", "if").as_deref(),
            Some("always()")
        );
        assert_eq!(
            field("      if: steps.a.outcome == 'success'", "if").as_deref(),
            Some("steps.a.outcome == 'success'")
        );
    }

    #[test]
    fn job_keys_need_two_spaces_and_a_bare_name() {
        assert_eq!(job_key("  build:"), Some("build"));
        assert_eq!(job_key("  build-2:  "), Some("build-2"));
        assert_eq!(job_key("    build:"), None);
        assert_eq!(job_key("  build: x"), None);
        assert_eq!(job_key("jobs:"), None);
    }

    #[test]
    fn the_name_falls_back_to_uses_and_then_to_empty() {
        let steps = steps_of(SELF_TEST_YAML, "ok").expect("job exists");
        assert_eq!(steps[0].name, "dtolnay/rust-toolchain@x");
        assert_eq!(steps[0].id, "rust");
        assert_eq!(steps[1].name, "Verdict");
        assert_eq!(steps[1].guard, None);
    }

    #[test]
    fn the_real_workflows_have_no_dangling_references() {
        let root = crate::repo_root();
        let files = default_workflows(&root);
        assert!(!files.is_empty(), "no workflow files found");
        for (shown, path) in files {
            let text = std::fs::read_to_string(path).expect("workflow readable");
            let found = check(&text, &shown).expect("workflow parses");
            assert!(found.is_empty(), "{found:?}");
        }
    }
}
