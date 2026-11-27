//! The pull-request branches that must never have a run cancelled are the
//! branches the repository actually delivers into, and no other.
//!
//! # The failure this closes
//!
//! Forty workflows carry a `concurrency.cancel-in-progress` expression whose
//! whole job is to exempt the integration head: a pull request into that branch
//! is the one place a complete CI verdict is required, and a push to its head
//! arrives faster than the suite runs. The exemption reads, in every one of
//! them,
//!
//! ```text
//! github.base_ref != 'testnet' && github.base_ref != 'ortak-teslim'
//! ```
//!
//! `ortak-teslim` was retired on 2026-11-22 (`CEO-1010`: `ajan/*` ->
//! `ortak-teslim` -> `testnet` -> `main`). The branch that heads the delivery
//! pull request today is `testnet-50`. But `testnet-50 != 'testnet'`, so every
//! `base_ref` comparison against `testnet` and `ortak-teslim` is **true** for a
//! pull request into `testnet-50`, and the exemption the expressions exist for
//! never fires on the branch they exist for. The measured symptom is in the
//! CI record: a delivery head whose 108 checks are green while the branch
//! cannot be merged because the required run is cancelled on the next push.
//!
//! # What is checked
//!
//! The set of branches a `cancel-in-progress` expression compares `base_ref`
//! against is derived, not listed: it is read from the same file that already
//! names the delivery path (`.github/ci-fanout-baseline.txt`, the
//! `delivery_branches` key), so a change of delivery branch is one edit in one
//! place and this gate follows it. Then, for every workflow that declares a
//! `cancel-in-progress` expression which mentions `github.base_ref`:
//!
//! 1. every delivery branch must be compared, by name, with `!=` - an
//!    expression that exempts a branch the repository no longer delivers into
//!    is not enough;
//! 2. no `base_ref` comparison may name `testnet` as if it were the delivery
//!    head when the delivery head is a *different* branch: a prefix match on a
//!    retired name is the exact defect being closed, so a comparison whose
//!    literal is a proper prefix of a delivery branch is reported;
//! 3. an expression that mentions `base_ref` but compares no branch at all is a
//!    finding: it reads as an exemption and exempts nothing.
//!
//! Comment lines are dropped before the scan, so a exemption that survives only
//! as a YAML comment does not count, and the self-test proves each of these
//! cases red on a tampered copy.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The file that names the delivery branches, relative to the repository root.
const DELIVERY_FILE_REL: &str = ".github/delivery-branches.txt";

/// A branch name after trimming quotes and whitespace.
fn clean(name: &str) -> &str {
    name.trim().trim_matches(|c| c == '\'' || c == '"')
}

/// The delivery branches named by the baseline file.
///
/// # Errors
///
/// Returns the reason the baseline cannot be read or carries no
/// `delivery_branches` entry. An empty set would make every check below vacuous,
/// so it is an error rather than a pass.
pub(crate) fn delivery_branches(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join(DELIVERY_FILE_REL);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("ci-concurrency-scope: cannot read {}: {e}", path.display()))?;
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = clean(line);
        if !name.is_empty() && !found.iter().any(|f| f == name) {
            found.push(name.to_string());
        }
    }
    if found.is_empty() {
        return Err(format!(
            "ci-concurrency-scope: {DELIVERY_FILE_REL} names no delivery branch; \
             the delivery branches must be named, not assumed"
        ));
    }
    Ok(found)
}

/// One `cancel-in-progress` line, with the file and line number it came from.
#[derive(Debug)]
pub(crate) struct Exemption {
    pub(crate) file: String,
    pub(crate) line_no: usize,
    pub(crate) expr: String,
}

/// The `cancel-in-progress` expressions in a workflow text, comments dropped.
pub(crate) fn exemptions(file: &str, text: &str) -> Vec<Exemption> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let bare = raw.trim_start();
        if bare.starts_with('#') {
            continue;
        }
        let Some(rest) = bare.strip_prefix("cancel-in-progress:") else {
            continue;
        };
        out.push(Exemption {
            file: file.to_string(),
            line_no: idx + 1,
            expr: rest.trim().to_string(),
        });
    }
    out
}

/// Every branch literal that an expression compares `github.base_ref` to.
///
/// The comparison may be written `github.base_ref != 'x'` or `'x' ==
/// github.base_ref`; both spellings appear in real workflow files, so both are
/// read. Operators other than `!=` and `==` are not read: an expression that
/// compares with `contains` or a regex satisfies nothing here, and saying so is
/// the point.
fn base_ref_literals(expr: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let tokens: Vec<&str> = expr
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '{' || c == '}')
        .filter(|t| !t.is_empty())
        .collect();
    for (i, tok) in tokens.iter().enumerate() {
        // `github.base_ref != 'x'`: the reference is on the left.
        let next = tokens.get(i + 1).copied().unwrap_or("");
        if *tok == "github.base_ref" && (next == "!=" || next == "==") {
            if let Some(rhs) = tokens.get(i + 2) {
                out.push((next.to_string(), clean(rhs).to_string()));
            }
            continue;
        }
        // `'x' == github.base_ref`: the literal is on the left and the
        // reference two tokens to the right. Both spellings occur in the tree,
        // and missing one is how a guard that exempts nothing would be read as
        // an exemption.
        if (next == "!=" || next == "==") && tokens.get(i + 2).copied() == Some("github.base_ref") {
            out.push((next.to_string(), clean(tok).to_string()));
        }
    }
    out
}

/// The findings for one workflow text.
pub(crate) fn check_text(text: &str, label: &str, delivery: &[String]) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    for ex in exemptions(label, text) {
        if !ex.expr.contains("github.base_ref") {
            // `cancel-in-progress: false`, or a guard that keys on the ref
            // rather than the base. Nothing to scope.
            continue;
        }
        let literals = base_ref_literals(&ex.expr);
        if literals.is_empty() {
            findings.push(format!(
                "{}:{}: `cancel-in-progress` reads `github.base_ref` but compares no branch; \
                 an expression that cannot exempt anything still reads as an exemption",
                ex.file, ex.line_no
            ));
            continue;
        }
        let compared: Vec<&str> = literals.iter().map(|(_, b)| b.as_str()).collect();
        for want in delivery {
            let exempted = literals.iter().any(|(op, b)| op == "!=" && b == want);
            if !exempted {
                findings.push(format!(
                    "{}:{}: the delivery branch `{want}` is not exempted from cancellation \
                     (compared: {}); a push to that head cancels the verdict the branch exists to produce",
                    ex.file,
                    ex.line_no,
                    compared.join(", ")
                ));
            }
        }
        for (_, b) in &literals {
            if delivery.iter().any(|d| d == b) {
                continue;
            }
            if let Some(owner) = delivery.iter().find(|d| d.starts_with(&format!("{b}-"))) {
                findings.push(format!(
                    "{}:{}: `{b}` is a retired name of the delivery branch `{owner}`; \
                     `{b} != '{b}'` does not match `{owner}`, so this comparison never fires for it",
                    ex.file, ex.line_no
                ));
            }
        }
    }
    findings
}

fn workflow_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join(".github/workflows");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("ci-concurrency-scope: cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    files.sort();
    Ok(files)
}

/// Run the gate against a repository root.
///
/// # Errors
///
/// Returns every finding, plus the reason the tree could not be read.
pub fn run(root: &Path) -> Result<String, String> {
    let delivery = delivery_branches(root)?;
    let mut findings: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for path in workflow_files(root)? {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("ci-concurrency-scope: cannot read {}: {e}", path.display()))?;
        let label = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        scanned += 1;
        findings.extend(check_text(&text, &label, &delivery));
    }
    if !findings.is_empty() {
        return Err(format!(
            "ci-concurrency-scope: {} finding(s) in the cancellation exemptions:\n  {}",
            findings.len(),
            findings.join("\n  ")
        ));
    }
    Ok(format!(
        "ci-concurrency-scope: {scanned} workflow(s) read; every `cancel-in-progress` guard that \
         keys on `github.base_ref` exempts the delivery branch(es) {}",
        delivery.join(", ")
    ))
}

fn fixture(delivery: &[String]) -> String {
    let mut guard = String::from("github.ref != 'refs/heads/main'");
    for b in delivery {
        let _ = write!(guard, " && github.base_ref != '{b}'");
    }
    guard
}

/// Self-test: a good tree passes and every tamper this gate exists to catch is
/// refused. Each case is a real shape found in `.github/workflows`.
///
/// # Errors
///
/// Returns the case that behaved against its expectation, so a gate that has
/// gone blind cannot report success.
pub fn self_test() -> Result<String, String> {
    let delivery: Vec<String> = vec!["testnet-50".to_string()];
    let good = format!(
        "name: ci\non: [push]\nconcurrency:\n  group: ci-${{{{ github.ref }}}}\n  \
         cancel-in-progress: ${{{{ {} }}}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      \
         - name: x\n        run: echo hi\n",
        fixture(&delivery)
    );
    let ok = check_text(&good, "fixture", &delivery);
    if !ok.is_empty() {
        return Err(format!(
            "ci-concurrency-scope self-test: a correct guard was refused: {}",
            ok.join("; ")
        ));
    }

    // 1. The retired-branch guard, verbatim from 36 workflow files.
    let stale = "name: ci\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: \
                 ${{ github.ref != 'refs/heads/main' && github.base_ref != 'testnet' && \
                 github.base_ref != 'ortak-teslim' }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n";
    let f = check_text(stale, "fixture", &delivery);
    if f.is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: the retired `testnet`/`ortak-teslim` guard passed",
        ));
    }
    // 2. No branch compared at all.
    let empty = "name: ci\nconcurrency:\n  group: ci\n  cancel-in-progress: \
                 ${{ github.base_ref != '' }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n";
    if check_text(empty, "fixture", &delivery).is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: an empty comparison passed",
        ));
    }
    // 3. Exemption present only as a comment.
    let commented = format!(
        "name: ci\nconcurrency:\n  group: ci\n  # cancel-in-progress: ${{{{ {} }}}}\n  \
         cancel-in-progress: ${{{{ github.base_ref != 'testnet' }}}}\njobs:\n  j:\n    \
         runs-on: ubuntu-latest\n",
        fixture(&delivery)
    );
    if check_text(&commented, "fixture", &delivery).is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: a commented-out exemption was counted",
        ));
    }
    // 4. The reversed comparison spelling is read rather than missed.
    let reversed = "name: ci\nconcurrency:\n  group: ci\n  cancel-in-progress: \
                    ${{ 'testnet-50' == github.base_ref }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n";
    if check_text(reversed, "fixture", &delivery).is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: the reversed comparison spelling was not read",
        ));
    }
    // 5. A second delivery branch is not satisfied by the first.
    let two: Vec<String> = vec!["testnet-50".to_string(), "garden-2".to_string()];
    let one_of_two = "name: ci\nconcurrency:\n  group: ci\n  cancel-in-progress: \
                      ${{ github.base_ref != 'testnet-50' }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n";
    if check_text(one_of_two, "fixture", &two).is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: a second delivery branch was not required",
        ));
    }
    // 6. A guard that keys on `github.ref` alone carries no base_ref claim and
    //    is out of scope, not a failure.
    let ref_only = "name: ci\nconcurrency:\n  group: ci\n  cancel-in-progress: \
                    ${{ github.ref != 'refs/heads/main' }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n";
    if !check_text(ref_only, "fixture", &delivery).is_empty() {
        return Err(String::from(
            "ci-concurrency-scope self-test: a ref-only guard was refused",
        ));
    }
    Ok(String::from(
        "ci-concurrency-scope self-test: stale branch names, empty comparisons, commented \
         exemptions, reversed operands, a missing second delivery branch and ref-only guards \
         all behave",
    ))
}

#[cfg(test)]
mod tests {
    use super::{base_ref_literals, delivery_branches, exemptions};

    #[test]
    fn self_test_passes() {
        super::self_test().expect("ci-concurrency-scope self-test");
    }

    #[test]
    fn both_operand_orders_are_read() {
        let a = base_ref_literals("github.base_ref != 'x' && 'y' == github.base_ref");
        assert_eq!(
            a,
            vec![
                ("!=".to_string(), "x".to_string()),
                ("==".to_string(), "y".to_string())
            ]
        );
    }

    #[test]
    fn comment_lines_are_not_exemptions() {
        let text = "# cancel-in-progress: false\n  cancel-in-progress: ${{ true }}\n";
        let found = exemptions("f.yml", text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_no, 2);
    }

    #[test]
    fn the_repository_baseline_names_its_delivery_branches() {
        // Run against the real tree, not a fixture.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repository root above xtask/gates")
            .to_path_buf();
        let delivery = delivery_branches(&root).expect("delivery branches are named");
        assert!(
            !delivery.is_empty(),
            "an empty delivery set makes every exemption check vacuous"
        );
    }
}
