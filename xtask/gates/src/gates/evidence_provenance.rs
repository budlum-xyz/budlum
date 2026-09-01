//! A slashing report may only move stake once the consensus layer has
//! verified it.
//!
//! Ported from `scripts/check-evidence-provenance-is-checked.sh`.
//!
//! # The failure this closes
//!
//! `SlashingReport` carries a `provenance` field with two values.
//! `ConsensusVerified` means the local consensus engine checked the
//! signatures or the quorum. `Unverified` means the report arrived from
//! outside, through the permissionless `slash-evidence-submit` endpoint, and
//! nobody has checked anything yet. `is_actionable` refuses the second, and
//! that refusal is what keeps the permissionless endpoint safe without a
//! whitelist.
//!
//! The risk is direct: an externally submitted report passes structural
//! validation, and a path that validates shape and then slashes would cut a
//! validator's stake on a claim nobody verified.
//!
//! # What is checked
//!
//! 1. `is_actionable` still refuses `Unverified` and still runs the
//!    structural check.
//! 2. `slash_from_report`, the entry point that takes a typed report, calls
//!    it.
//! 3. The bare `slash` may only be reached from the paths that already sit
//!    behind consensus; a new caller is named.
//! 4. Some test in the tree constructs a report with
//!    `ProofProvenance::Unverified`, so the refusal is asserted by
//!    something.

use std::fmt::Write as _;
use std::path::Path;

/// Python `\s`.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

/// Blank line comments (`//` to end of line).
fn strip_comments(text: &str) -> String {
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

/// Brace-matched body of the item whose header is `pub fn NAME\s*\(`.
///
/// Matching braces survives both `#[cfg(test)]` sections below the function
/// and nested blocks.
fn body_of<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("pub fn {name}");
    let mut from = 0usize;
    while let Some(pos) = text[from..].find(&header) {
        let abs = from + pos;
        let rest = &text[abs + header.len()..];
        if !skip_py_ws(rest).starts_with('(') {
            from = abs + 1;
            continue;
        }
        // The opening brace is the first `{` at or after the header.
        let open_rel = text[abs + header.len()..].find('{')?;
        let i = abs + header.len() + open_rel;
        let mut depth = 0usize;
        for (off, c) in text[i..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[i..i + off + c.len_utf8()]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
    None
}

/// Does this production text contain `.slash(` or `.slash_role_only(`?
fn has_slash_call(prod: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = prod[from..].find(".slash") {
        let abs = from + pos;
        let mut rest = &prod[abs + ".slash".len()..];
        if rest.starts_with("_role_only") {
            rest = &rest["_role_only".len()..];
        }
        if skip_py_ws(rest).starts_with('(') {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn walk_rs(dir: &std::path::Path, root: &Path, out: &mut Vec<(std::path::PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(p_kind) = e.file_type() else {
            continue;
        };
        let p = e.path();
        if p_kind.is_dir() {
            walk_rs(&p, root, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            out.push((p, rel));
        }
    }
}

/// Every `.rs` file under `src/`, with its path relative to the root.
fn src_rs_files(root: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    walk_rs(&root.join("src"), root, &mut out);
    out
}

/// Production files under `src/` (outside the allowed and test trees) whose
/// text calls the bare `slash`.
fn unexpected_slash_callers(root: &Path) -> Vec<String> {
    let allowed = [
        "src/core/account.rs",
        "src/execution/executor.rs",
        "src/registry/permissionless.rs",
    ];
    let mut unexpected: Vec<String> = Vec::new();
    for (full, rel) in src_rs_files(root) {
        // `/tests/` covers the test tree; `_tests.rs` covers test modules
        // that live next to the code they exercise.
        if allowed.contains(&rel.as_str()) || rel.contains("/tests/") || rel.ends_with("_tests.rs")
        {
            continue;
        }
        let text = strip_comments(&std::fs::read_to_string(&full).unwrap_or_default());
        let prod = text.split("#[cfg(test)]").next().unwrap_or(&text);
        if has_slash_call(prod) {
            unexpected.push(rel);
        }
    }
    unexpected.sort();
    unexpected
}

/// Does any `.rs` file under `src/` hold both `ProofProvenance::Unverified`
/// and a `#[test]`?
fn has_unverified_test(root: &Path) -> bool {
    src_rs_files(root).iter().any(|(full, _rel)| {
        let text = std::fs::read_to_string(full).unwrap_or_default();
        text.contains("ProofProvenance::Unverified") && text.contains("#[test]")
    })
}

/// # Errors
///
/// Missing sources, a provenance check that is gone or hollow, a new caller
/// of the bare `slash`, or no test asserting the refusal.
pub fn run(root: &Path) -> Result<String, String> {
    let evidence = root.join("src/registry/evidence.rs");
    let registry = root.join("src/registry/permissionless.rs");

    for path in [&evidence, &registry] {
        if !path.is_file() {
            return Err(format!(
                "FAIL: expected source file missing: {}",
                path.display()
            ));
        }
    }

    let ev_code = strip_comments(&std::fs::read_to_string(&evidence).unwrap_or_default());
    let reg_raw = std::fs::read_to_string(&registry).unwrap_or_default();
    let reg_code = strip_comments(&reg_raw);
    let reg_prod = reg_code.split("#[cfg(test)]").next().unwrap_or(&reg_code);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    // 1. The check itself must still refuse unverified reports.
    checked += 1;
    let actionable = body_of(&ev_code, "is_actionable");
    if let Some(body) = actionable {
        checked += 1;
        if !body.contains("Unverified") {
            problems.push(String::from(
                "`is_actionable` no longer mentions `Unverified`, so it does not \
                 distinguish a consensus-verified report from one anybody can \
                 submit. The provenance field then decides nothing.",
            ));
        }
        checked += 1;
        if !body.contains("Err(") {
            problems.push(String::from(
                "`is_actionable` never returns an error. A check that accepts \
                 every report satisfies every call-site test and protects \
                 nothing.",
            ));
        }
        checked += 1;
        if !body.contains("validate_shape") {
            problems.push(String::from(
                "`is_actionable` no longer runs the structural check, so a \
                 malformed report that happens to be consensus-verified would \
                 pass.",
            ));
        }
    } else {
        problems.push(String::from(
            "`SlashingReport::is_actionable` is gone. It is the only thing \
             standing between an externally submitted claim and a validator's \
             stake.",
        ));
    }

    // 2. The typed entry point must call it.
    checked += 1;
    if let Some(body) = body_of(reg_prod, "slash_from_report") {
        checked += 1;
        if !body.contains("is_actionable") {
            problems.push(String::from(
                "`slash_from_report` does not call `is_actionable`. It takes a \
                 report, so it can see the provenance field, and skipping the \
                 check is exactly the hole the field exists to close.",
            ));
        }
    } else {
        problems.push(String::from(
            "`slash_from_report` is gone. Evidence then has no entry point that \
             reads its provenance.",
        ));
    }

    // 3. The bare `slash` may only be reached from paths that already sit
    //    behind consensus.
    checked += 1;
    let unexpected = unexpected_slash_callers(root);
    if !unexpected.is_empty() {
        problems.push(format!(
            "a new caller reaches the bare `slash` without going through \
             `slash_from_report`: {}. The bare form takes a condition and \
             trusts it, which is right only where consensus already decided. \
             If this path carries a `SlashingReport`, it should use \
             `slash_from_report` so the provenance is read.",
            unexpected.join(", ")
        ));
    }

    // 4. The refusal must be asserted by a real test somewhere in the tree.
    checked += 1;
    if !has_unverified_test(root) {
        problems.push(String::from(
            "no test constructs a report with `ProofProvenance::Unverified`. The \
             refusal is then asserted by nothing.",
        ));
    }

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "evidence provenance gate OK: {checked} checks, unverified reports cannot move stake"
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the eight canaries of the shell version.
// ---------------------------------------------------------------------------

const ACTIONABLE_GOOD: &str = "    pub fn is_actionable(&self) -> Result<(), EvidenceError> {\n\
        self.validate_shape()?;\n\
        match self.provenance {\n\
            ProofProvenance::ConsensusVerified => Ok(()),\n\
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),\n\
        }\n\
    }\n";
const ACTIONABLE_ALWAYS_OK: &str =
    "    pub fn is_actionable(&self) -> Result<(), EvidenceError> {\n\
        self.validate_shape()?;\n\
        Ok(())\n\
    }\n";
const ACTIONABLE_NO_SHAPE: &str =
    "    pub fn is_actionable(&self) -> Result<(), EvidenceError> {\n\
        match self.provenance {\n\
            ProofProvenance::ConsensusVerified => Ok(()),\n\
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),\n\
        }\n\
    }\n";
const FROM_REPORT_GOOD: &str = "    pub fn slash_from_report(&mut self, report: &SlashingReport) -> Result<Option<SlashOutcome>, EvidenceError> {\n\
        report.is_actionable()?;\n\
        let condition = report.condition();\n\
        let ratio = self.params.slash_ratio(condition);\n\
        self.slash(report.offender, report.role, condition, ratio).ok();\n\
        Ok(None)\n\
    }\n";
const FROM_REPORT_SKIPS: &str = "    pub fn slash_from_report(&mut self, report: &SlashingReport) -> Result<Option<SlashOutcome>, EvidenceError> {\n\
        let condition = report.condition();\n\
        let ratio = self.params.slash_ratio(condition);\n\
        self.slash(report.offender, report.role, condition, ratio).ok();\n\
        Ok(None)\n\
    }\n";
const TESTS_PRESENT: &str = "\n\
#[cfg(test)]\n\
mod tests {\n\
    use super::*;\n\
    #[test]\n\
    fn unverified_is_refused() {\n\
        let r = report_with(ProofProvenance::Unverified);\n\
        assert!(r.is_actionable().is_err());\n\
    }\n\
}\n";

/// Write one fixture tree and return its directory.
fn build_fixture(
    check_mode: &str,
    call_mode: &str,
    caller_mode: &str,
    test_mode: &str,
) -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-evidence-{}-{nanos}",
        std::process::id()
    ));
    for sub in ["src/registry", "src/core", "src/execution", "src/rpc"] {
        let _ = std::fs::create_dir_all(dir.join(sub));
    }

    let actionable = match check_mode {
        "gone" => "",
        "always_ok" => ACTIONABLE_ALWAYS_OK,
        "no_shape" => ACTIONABLE_NO_SHAPE,
        _ => ACTIONABLE_GOOD,
    };
    let tests = if test_mode == "present" {
        TESTS_PRESENT
    } else {
        ""
    };
    std::fs::write(
        dir.join("src/registry/evidence.rs"),
        format!("impl SlashingReport {{\n{actionable}}}\n{tests}"),
    )
    .map_err(|e| e.to_string())?;

    let from_report = match call_mode {
        "gone" => "",
        "skips" => FROM_REPORT_SKIPS,
        _ => FROM_REPORT_GOOD,
    };
    std::fs::write(
        dir.join("src/registry/permissionless.rs"),
        format!(
            "impl PermissionlessRegistry {{\n{from_report}\n    pub fn slash(&mut self, a: Address, r: RoleId, c: SlashingCondition, s: u64) -> Result<SlashOutcome, RegistryError> {{ todo!() }}\n}}\n"
        ),
    )
    .map_err(|e| e.to_string())?;

    // The two allowed callers always exist.
    std::fs::write(
        dir.join("src/core/account.rs"),
        "fn mirror(&mut self) { let _ = self.registry.slash(a, r, c, s); }\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/execution/executor.rs"),
        "fn ai_inference(&mut self) { let _ = self.registry.slash_role_only(a, r, c, s); }\n",
    )
    .map_err(|e| e.to_string())?;

    // A third caller appears when the fixture asks for one.
    let rpc = if caller_mode == "extra" {
        "async fn submit(&self) { let _ = self.registry.slash(a, r, c, s); }\n"
    } else {
        "async fn submit(&self) { let _ = self.registry.slash_from_report(&report); }\n"
    };
    std::fs::write(dir.join("src/rpc/server.rs"), rpc).map_err(|e| e.to_string())?;

    Ok(dir)
}

fn expect_finding(dir: &std::path::Path, label: &str, expect_ok: bool) -> Result<(), String> {
    let result = run(dir);
    let _ = std::fs::remove_dir_all(dir);
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
    // 1. The corrected shape must pass, or every canary below proves nothing.
    let dir = build_fixture("ok", "ok", "ok", "present")?;
    expect_finding(&dir, "the corrected tree was rejected", true)?;

    // 2. The check disappears.
    let dir = build_fixture("gone", "ok", "ok", "present")?;
    expect_finding(&dir, "a missing is_actionable", false)?;

    // 3. The subtle one: `is_actionable` still exists, still runs the
    //    structural check, and accepts every provenance.
    let dir = build_fixture("always_ok", "ok", "ok", "present")?;
    expect_finding(&dir, "a check that accepts unverified reports", false)?;

    // 4. Provenance is read, structure is not.
    let dir = build_fixture("no_shape", "ok", "ok", "present")?;
    expect_finding(&dir, "a check that skips structural validation", false)?;

    // 5. The typed entry point disappears.
    let dir = build_fixture("ok", "gone", "ok", "present")?;
    expect_finding(&dir, "a missing slash_from_report", false)?;

    // 6. The typed entry point stops calling the check.
    let dir = build_fixture("ok", "skips", "ok", "present")?;
    expect_finding(
        &dir,
        "an entry point that skips the provenance check",
        false,
    )?;

    // 7. A third caller routes around the typed path.
    let dir = build_fixture("ok", "ok", "extra", "present")?;
    expect_finding(&dir, "a new caller reaching the bare slash", false)?;

    // 8. Nothing asserts the refusal.
    let dir = build_fixture("ok", "ok", "ok", "absent")?;
    expect_finding(&dir, "a missing regression test", false)?;

    Ok(String::from(
        "evidence provenance gate self-test OK: 7 canaries",
    ))
}
