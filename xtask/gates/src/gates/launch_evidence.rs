//! Fail closed when the launch ledger has no per-gate and per-finding evidence.
//!
//! This is a *presence and shape* check, not a substitute for independently
//! verifying CI artifacts, source-to-production wiring, or reviewer approval.
//! A source file, a named test, or a fixture with hand-entered results is not
//! evidence that its test passed on the closing commit.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

const TLG: &str = "docs/audit/TLG_REPORT.md";
const LIVE: &str = "docs/audit/LIVE_STATUS.md";
const FINDINGS: &str = "docs/audit/FINDINGS.md";
const MAX_EXAMPLES: usize = 12;

fn rows(
    text: &str,
    kind: &str,
    count: usize,
    columns: usize,
) -> Result<BTreeMap<usize, Vec<String>>, String> {
    let mut result = BTreeMap::new();
    for (line_no, line) in text.lines().enumerate() {
        let Some(value) = line.strip_prefix("| ") else {
            continue;
        };
        let Some((id, _)) = value.split_once(" |") else {
            continue;
        };
        let Some(digits) = id.strip_prefix(kind).and_then(|s| s.strip_prefix('-')) else {
            continue;
        };
        if digits.len() != if kind == "TLG" { 2 } else { 3 }
            || !digits.bytes().all(|c| c.is_ascii_digit())
        {
            return Err(format!(
                "{kind} malformed identifier at line {}: {id}",
                line_no + 1
            ));
        }
        let number: usize = digits
            .parse()
            .map_err(|_| format!("{kind} invalid ID: {id}"))?;
        if !(1..=count).contains(&number) {
            return Err(format!(
                "{kind} out-of-range ID at line {}: {id}",
                line_no + 1
            ));
        }
        let fields: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|s| s.trim().to_string())
            .collect();
        if fields.len() != columns {
            return Err(format!(
                "{kind}-{number:03} has {} columns, expected {columns}",
                fields.len()
            ));
        }
        if result.insert(number, fields).is_some() {
            return Err(format!("duplicate {kind}-{number:03}"));
        }
    }
    for number in 1..=count {
        if !result.contains_key(&number) {
            return Err(format!(
                "missing {kind}-{number:03}; a partial ledger is not proof"
            ));
        }
    }
    Ok(result)
}

fn hex_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

fn token<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split(|c: char| c.is_ascii_whitespace() || c == ';' || c == '`')
        .find_map(|part| part.strip_prefix(key).filter(|v| !v.is_empty()))
}

fn run_number(text: &str) -> bool {
    token(text, "ci=").is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
}

fn cited_file(root: &Path, text: &str) -> bool {
    let Some((path, line)) = text.rsplit_once(':') else {
        return false;
    };
    let Ok(number) = line.parse::<usize>() else {
        return false;
    };
    let mut parts = path.split('/');
    let allowed = matches!(
        parts.next(),
        Some(
            "src"
                | "crates"
                | "bud"
                | "budzero"
                | "execution"
                | "mobile"
                | "contracts"
                | "ops"
                | "config"
                | "xtask"
        )
    );
    if number == 0
        || !allowed
        || path.contains("..")
        || path.contains(' ')
        || path.split('/').any(|p| {
            matches!(
                p,
                "tests" | "test" | "fixtures" | "fuzz" | "benches" | "examples" | "target"
            )
        })
    {
        return false;
    }
    let file = root.join(path);
    file.is_file()
        && std::fs::read_to_string(file).is_ok_and(|source| number <= source.lines().count())
}

fn proof_record(root: &Path, path: &str) -> bool {
    path.starts_with("docs/audit/evidence/") && !path.contains("..") && root.join(path).is_file()
}

/// A profile helper and a named test do not close the direct settlement API.
fn binding_direct_guard(source: &str) -> bool {
    let Some(start) = source.find(concat!("pub fn execute_gr", "aft_tx(")) else {
        return false;
    };
    let body = &source[start..];
    let Some(end) = body.find("match tx {") else {
        return false;
    };
    let preflight = &body[..end];
    let Some(guard) = preflight.find("if !app_binding_enabled_for_chain_id(ctx.chain_id)") else {
        return false;
    };
    preflight[guard..].contains("return Err(")
}

fn binding_guard(root: &Path) -> Result<(), String> {
    let path = concat!("src/settlement/gr", "aft.rs");
    let code = std::fs::read_to_string(root.join(path))
        .map_err(|e| format!("{path}: cannot inspect settlement door: {e}"))?;
    let production = super::capability_modules_are_wired::code_only(&code);
    if !binding_direct_guard(&production) {
        return Err(String::from("app-binding direct settlement door lacks a testnet chain-ID refusal: settlement app-binding module::execute_app_binding_tx_or_legacy must call app_binding_enabled_for_chain_id(ctx.chain_id) before match tx. A devnet-only profile helper or an unexecuted test is insufficient."));
    }
    Ok(())
}

fn audit(root: &Path, tlg: &str, live: &str, findings: &str) -> Result<String, String> {
    let tlg_rows = rows(tlg, "TLG", 27, 4)?;
    let live_rows = rows(live, "BLG", 267, 7)?;
    let finding_rows = rows(findings, "BLG", 267, 8)?;
    let mut missing = Vec::new();
    for (id, row) in &tlg_rows {
        // Section 18 requires a SHA, CI run or rehearsal record, and reviewer.
        let evidence = &row[1];
        if row[3] != "Green"
            || !token(evidence, "sha=").is_some_and(hex_sha)
            || !(run_number(evidence)
                || token(evidence, "record=").is_some_and(|p| proof_record(root, p)))
            || token(evidence, "reviewer=").is_none()
        {
            missing.push(format!(
                "TLG-{id:02}: no green verdict with SHA, CI run/record and reviewer"
            ));
        }
    }
    for (id, row) in &live_rows {
        let finding = &finding_rows[id];
        let status = row[4].as_str();
        let close_status = finding[1].as_str();
        if status != close_status
            || !matches!(status, "Closed" | "Removed" | "Invalid" | "Feature closed")
        {
            missing.push(format!(
                "BLG-{id:03}: status unknown, unsupported, or inconsistent"
            ));
            continue;
        }
        let source = &row[6];
        let removal = status == "Removed" && token(&finding[3], "removed=").is_some();
        if !removal && !cited_file(root, source) {
            missing.push(format!(
                "BLG-{id:03}: no current production file:line evidence"
            ));
        }
        let test = &row[5];
        if test.is_empty() || test.contains("Not recorded") || test.contains("Not collected") {
            missing.push(format!("BLG-{id:03}: no reproduction test/result"));
        }
        if finding[2].contains("Not recorded")
            || finding[3].contains("Not recorded")
            || !hex_sha(&finding[4])
            || !run_number(&format!("ci={}", finding[5]))
            || finding[7].is_empty()
            || finding[7].contains("Not recorded")
        {
            missing.push(format!(
                "BLG-{id:03}: no closure proof, merged SHA, CI run and reviewer"
            ));
        }
        if status == "Feature closed" && !finding[6].contains("_is_closed_on_testnet") {
            missing.push(format!(
                "BLG-{id:03}: no explicit testnet feature refusal test"
            ));
        }
        if status == "Removed" && !finding[3].contains("no-legacy-storage") {
            missing.push(format!("BLG-{id:03}: no removal gate evidence"));
        }
    }
    if !missing.is_empty() {
        let examples = missing
            .iter()
            .take(MAX_EXAMPLES)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ");
        return Err(format!(
            "Launch evidence incomplete: {} gap(s) across 27 TLG and 267 BLG rows. First gaps:\n  {examples}\nDo not claim testnet readiness from source-only tests or fixture values.",
            missing.len()
        ));
    }
    Ok(String::from("Launch evidence metadata complete; verify CI runs, rehearsals and reviewer approvals independently before marking TLG green."))
}

/// Check the on-disk evidence ledgers and `app_binding` guard.
///
/// # Errors
///
/// Reports missing or unsupported evidence, malformed identifiers, or absent files.
pub fn run(root: &Path) -> Result<String, String> {
    let read = |name: &str| {
        std::fs::read_to_string(root.join(name))
            .map_err(|e| format!("{name}: evidence file missing or unreadable: {e}"))
    };
    let ledger_result = audit(root, &read(TLG)?, &read(LIVE)?, &read(FINDINGS)?);
    let guard_result = binding_guard(root);
    match (ledger_result, guard_result) {
        (Err(ledger), Err(guard)) => Err(format!("{ledger}\n{guard}")),
        (Err(ledger), Ok(())) => Err(ledger),
        (Ok(_), Err(guard)) => Err(guard),
        (Ok(complete), Ok(())) => Ok(complete),
    }
}

/// Run `launch-evidence` with optional CLI arguments (`--require-complete`).
///
/// In `--all` (`args` empty), checks the direct `app_binding` settlement guard
/// and verifies structural schema/row integrity across the 27 TLG and 267 BLG
/// rows without requiring pre-CI SHAs or reviewer sign-off. Passing
/// `--require-complete` enforces the full release readiness audit.
///
/// # Errors
///
/// Reports missing/malformed ledger files, an unwired `app_binding` guard, or
/// incomplete evidence when `--require-complete` is set.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    if args.contains(&"--require-complete") {
        return run(root);
    }
    let read = |name: &str| {
        std::fs::read_to_string(root.join(name))
            .map_err(|e| format!("{name}: evidence file missing or unreadable: {e}"))
    };
    let tlg_rows = rows(&read(TLG)?, "TLG", 27, 4)?;
    let live_rows = rows(&read(LIVE)?, "BLG", 267, 7)?;
    let finding_rows = rows(&read(FINDINGS)?, "BLG", 267, 8)?;
    binding_guard(root)?;
    let n_tlg = tlg_rows.len();
    let n_blg = live_rows.len().min(finding_rows.len());
    Ok(format!(
        "launch-evidence schema & guard OK \
         ({n_tlg} TLG rows, {n_blg} BLG rows; pass `--require-complete` for sign-off)"
    ))
}

/// Inject missing and misleading evidence to prove this gate can fail.
///
/// # Errors
///
/// Reports if any injected absence or source-only claim was accepted.
pub fn self_test() -> Result<String, String> {
    let mut tlg = String::new();
    let mut live = String::new();
    let mut findings = String::new();
    for n in 1..=27 {
        let _ = writeln!(tlg, "| TLG-{n:02} | source only | gap | Unverified |");
    }
    for n in 1..=267 {
        let _ = writeln!(live, "| BLG-{n:03} | directive | High | WP-01 | Unknown / unverified | Not recorded | Not collected |");
        let _ = writeln!(findings, "| BLG-{n:03} | Unknown / unverified | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded | Not recorded |");
    }
    let root = Path::new(".");
    let err = audit(root, &tlg, &live, &findings)
        .err()
        .ok_or("missing evidence passed")?;
    if !err.contains("TLG-01") || !err.contains("294 gap(s) across 27 TLG and 267 BLG rows") {
        return Err(String::from(
            "source-only/unknown evidence was not rejected for both ledgers",
        ));
    }
    if rows(&tlg.replacen("| TLG-01", "| TLG-02", 1), "TLG", 27, 4).is_ok()
        || rows(&live.replacen("| BLG-001", "| BLG-002", 1), "BLG", 267, 7).is_ok()
        || rows(
            &findings.replacen(" | Not recorded |", " | Not recorded | extra |", 1),
            "BLG",
            267,
            8,
        )
        .is_ok()
    {
        return Err(String::from("duplicate or malformed evidence rows passed"));
    }
    let good = concat!(
        "pub fn execute_gr",
        "aft_tx(ctx: C, tx: T) -> R { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } match tx { _ => Ok(()) } }"
    );
    let bad = concat!(
        "pub fn execute_gr",
        "aft_tx(ctx: C, tx: T) -> R { // app_binding_enabled_for_chain_id(ctx.chain_id) return Err(..);\n match tx { _ => Ok(()) } }"
    );
    let inverted = good.replace(
        "if !app_binding_enabled_for_chain_id",
        "if app_binding_enabled_for_chain_id",
    );
    if !binding_direct_guard(&super::capability_modules_are_wired::code_only(good))
        || binding_direct_guard(&super::capability_modules_are_wired::code_only(bad))
        || binding_direct_guard(&super::capability_modules_are_wired::code_only(&inverted))
    {
        return Err(String::from(
            "app-binding direct-gate comment canary failed",
        ));
    }
    Ok(String::from(
        "launch-evidence canary OK: missing proof, duplicate rows and unwired app-binding guard refused",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn launch_evidence_rejects_source_only_and_missing_proof() {
        super::self_test().unwrap();
    }

    #[test]
    fn launch_evidence_rejects_fake_sha_and_missing_source() {
        use super::*;
        assert!(!hex_sha("f37e5c4d"));
        assert!(!cited_file(Path::new("."), "tests/rehearsal/main.rs:1"));
        assert!(!cited_file(
            Path::new("."),
            "src/tests/privacy_ai_execution.rs:1"
        ));
        assert!(!proof_record(Path::new("."), "tests/rehearsal/main.rs"));
        assert!(!run_number("ci=not-run"));
    }

    #[test]
    fn launch_evidence_requires_direct_binding_preflight_not_comment_or_profile_helper() {
        use super::*;
        let good = concat!(
            "pub fn execute_gr",
            "aft_tx(ctx: C, tx: T) -> R { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } match tx { _ => Ok(()) } }"
        );
        assert!(binding_direct_guard(
            &super::super::capability_modules_are_wired::code_only(good)
        ));
        let comment = concat!(
            "pub fn execute_gr",
            "aft_tx(ctx: C, tx: T) -> R { // app_binding_enabled_for_chain_id(ctx.chain_id) return Err(...);\n match tx { _ => Ok(()) } }"
        );
        assert!(!binding_direct_guard(
            &super::super::capability_modules_are_wired::code_only(comment)
        ));
        assert!(!binding_direct_guard(concat!(
            "pub fn app_binding_enabled_for_chain_id() {} pub fn execute_gr",
            "aft_tx(ctx: C, tx: T) -> R { match tx { _ => Ok(()) } }"
        )));
    }
}
