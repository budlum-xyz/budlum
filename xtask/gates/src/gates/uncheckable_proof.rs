//! The storage challenge verifier is either enforcing real proofs or contained.
//!
//! `storage_challenge_proofs_are_checkable` has two honest states.
//!
//! 1. `true`. Every answer is verified through `DefaultAdapter::verify` against
//!    the deal's storage root. No `!flag => Ok(())` bypass exists, an answer
//!    that carries no proof returns `Err`, and a proof that fails to verify
//!    slashes.
//! 2. `false`. The witness proves a responder-supplied Merkle path and is not
//!    tied to the stored shard bytes, so it is not evidence about possession.
//!    The verifier is then contained: the verification match takes an
//!    administrative arm that returns only `Ok(())`, and the one door that pays
//!    for an answer (`record_proven_read`) is guarded by the same flag. An
//!    unbound proof neither pays nor slashes.
//!
//! A flag that says `true` without the real verification is a defect, and so is
//! a flag that says `false` next to a paying door that ignores it. A flag that
//! is neither a bare `true` nor a bare `false` hides which state holds and also
//! fails. Flipping the flag to `true` makes the gate demand the first state in
//! full, so the flag cannot be raised without the shard-bound witness behind it.

use std::fmt::Write as _;
use std::path::Path;

use super::rust_literals;

const FLAG: &str = "storage_challenge_proofs_are_checkable";

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/domain/storage_deal.rs");
    if !f.is_file() {
        return Err(format!("no storage_deal.rs at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(rust_literals::scrub(&src))
}

fn has_fn(code: &str, name: &str) -> bool {
    rust_literals::has_live_test(code, name)
}

/// What the body of `fn <flag>()` is.
#[derive(Debug, PartialEq, Eq)]
enum Flag {
    Missing,
    True,
    False,
    Computed,
}

fn flag_state(code: &str, flag: &str) -> Flag {
    let needle = format!("fn {flag}()");
    let Some(at) = code.find(&needle) else {
        return Flag::Missing;
    };
    let Some(open_rel) = code[at..].find('{') else {
        return Flag::Missing;
    };
    let open = at + open_rel;
    match block_at(code, open) {
        Some("true") => Flag::True,
        Some("false") => Flag::False,
        Some(_) => Flag::Computed,
        None => Flag::Missing,
    }
}

/// The trimmed text between the brace at `open` and its match.
fn block_at(code: &str, open: usize) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(code[open + 1..open + i].trim());
                }
            }
            _ => {}
        }
    }
    None
}

/// The trimmed body of the first block that follows `needle`.
fn block_after<'a>(code: &'a str, needle: &str) -> Option<&'a str> {
    let at = code.find(needle)?;
    let open = at + code[at..].find('{')?;
    block_at(code, open)
}

/// The code before the first `mod tests`. A call inside a test module is an
/// exercise of the door, not a door.
fn production(code: &str) -> &str {
    code.split("mod tests").next().unwrap_or(code)
}

/// Offsets of every call `.record_proven_read(` (the definition is `fn ...`).
fn call_sites(code: &str) -> Vec<usize> {
    code.match_indices(".record_proven_read(")
        .map(|(at, _)| at)
        .collect()
}

/// The condition of the `if` that directly precedes `at`: the text between that
/// `if` and its opening brace. The paying door must sit under an `if` whose
/// condition names the flag, so an unrelated mention of the flag earlier in the
/// function does not count as a guard.
fn enclosing_condition(code: &str, at: usize) -> Option<&str> {
    let head = &code[..at];
    let mut from = head.len();
    while let Some(i) = head[..from].rfind("if ") {
        let before = head[..i].chars().next_back();
        if before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_')) {
            let rest = &head[i + 3..];
            let end = rest.find('{').unwrap_or(rest.len());
            return Some(&rest[..end]);
        }
        from = i;
    }
    None
}

/// State 1: the flag is `true`, so the real verification must be intact.
fn check_verified(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    if code.contains(&format!("if !Self::{FLAG}() => Ok(())")) {
        problems.push(format!(
            "a `!Self::{FLAG}() => Ok(())` bypass remains in the verification match."
        ));
    } else {
        *checked += 1;
    }
    if code.contains("(Some(_), None) => Err(") {
        *checked += 1;
    } else {
        problems.push("the no-proof arm no longer returns `Err`.".to_string());
    }
    for (name, why) in [
        (
            "an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable",
            "verifies both honest STARK acceptance and forged-proof slashing",
        ),
        (
            "the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof",
            "the boundary: an answer with no proof must still slash",
        ),
    ] {
        if has_fn(code, name) {
            *checked += 1;
        } else {
            problems.push(format!("the test `{name}` is gone. It holds {why}."));
        }
    }
}

/// State 2: the flag is `false`, so every consumer of the answer is contained.
fn check_contained(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    match block_after(code, &format!("if !Self::{FLAG}()")) {
        None => problems.push(format!(
            "the verification match has no `if !Self::{FLAG}()` containment arm."
        )),
        Some("Ok(())") => *checked += 1,
        Some(_) => problems.push(format!(
            "the `if !Self::{FLAG}()` arm must be exactly `Ok(())`: it may not slash, \
             verify or pay on evidence that is not bound to the shard bytes."
        )),
    }

    let prod = production(code);
    let calls = call_sites(prod);
    if calls.is_empty() {
        problems.push(
            "no `record_proven_read` call remains, so the paying door can no longer be checked; \
             update this gate with the door that replaced it."
                .to_string(),
        );
    }
    let guard = format!("Self::{FLAG}()");
    for at in calls {
        if enclosing_condition(prod, at).is_some_and(|condition| condition.contains(&guard)) {
            *checked += 1;
        } else {
            problems.push(format!(
                "a `record_proven_read` call does not sit under an `if` that names `{guard}`: \
                 an unbound answer would earn a proven-read credit."
            ));
        }
    }

    for (name, why) in [
        (
            "an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable",
            "an answer that carries a proof does not slash and earns no credit",
        ),
        (
            "an_unbound_answer_without_proof_is_resolved_without_slash_or_credit",
            "an answer without a proof resolves the challenge and earns no credit",
        ),
        (
            "self_opened_or_unverifiable_challenge_never_credits_proven_read",
            "an unverifiable challenge never credits a proven read",
        ),
    ] {
        if has_fn(code, name) {
            *checked += 1;
        } else {
            problems.push(format!("the test `{name}` is gone. It holds {why}."));
        }
    }
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let regime = match flag_state(&code, FLAG) {
        Flag::Missing => {
            problems.push(format!(
                "`{FLAG}` is missing or is no longer a plain boolean function."
            ));
            None
        }
        Flag::Computed => {
            problems.push(format!(
                "`{FLAG}` must be a bare `true` or a bare `false`. A computed value hides \
                 which state holds."
            ));
            None
        }
        Flag::True => {
            checked += 1;
            check_verified(&code, &mut problems, &mut checked);
            Some("proofs are enforced")
        }
        Flag::False => {
            checked += 1;
            check_contained(&code, &mut problems, &mut checked);
            Some("proofs are contained")
        }
    };

    if code.contains("DefaultAdapter::verify") {
        checked += 1;
    } else {
        problems.push(
            "`DefaultAdapter::verify` is missing from storage challenge verification.".to_string(),
        );
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "uncheckable-proof check OK: {checked} checks, {}",
        regime.unwrap_or("no state")
    ))
}

const TEST_CARRYING: &str = "#[test]\nfn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {}\n";
const TEST_MISSING_SLASHES: &str =
    "#[test]\nfn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {}\n";
const TEST_NO_PROOF_RESOLVES: &str =
    "#[test]\nfn an_unbound_answer_without_proof_is_resolved_without_slash_or_credit() {}\n";
const TEST_NO_CREDIT: &str =
    "#[test]\nfn self_opened_or_unverifiable_challenge_never_credits_proven_read() {}\n";

fn fixture_verified() -> String {
    format!(
        "pub(crate) fn {FLAG}() -> bool {{\n    true\n}}\n\
         fn f() {{\n    match (a, b) {{\n\
         (Some(r), Some(p)) => Self::verify_answer_challenge_zk_proof(&c, &r, &h, p),\n\
         (Some(_), None) => Err(StorageError::InvalidMerkleProof(m)),\n\
         (None, _) => Ok(()),\n    }}\n    DefaultAdapter::verify(&e, &i, &p);\n}}\n\
         {TEST_CARRYING}{TEST_MISSING_SLASHES}"
    )
}

fn fixture_contained() -> String {
    format!(
        "pub(crate) fn {FLAG}() -> bool {{\n    false\n}}\n\
         fn answer() {{\n\
         let verification = if !Self::{FLAG}() {{\n        Ok(())\n    }} else {{\n\
         match (root, proof) {{\n\
         (Some(r), Some(p)) => Self::verify_answer_challenge_zk_proof(&c, &r, &h, p),\n\
         (Some(_), None) => Err(StorageError::InvalidMerkleProof(m)),\n\
         (None, _) => Ok(()),\n        }}\n    }};\n\
         if answered && opener != operator && Self::{FLAG}() {{\n\
         self.record_proven_read(id, epoch);\n    }}\n\
         DefaultAdapter::verify(&e, &i, &p);\n}}\n\
         {TEST_CARRYING}{TEST_NO_PROOF_RESOLVES}{TEST_NO_CREDIT}"
    )
}

fn check_fixture(dir: &Path, label: &str, src: &str, must_pass: bool) -> Result<(), String> {
    std::fs::write(dir.join("src/domain/storage_deal.rs"), src).map_err(|e| e.to_string())?;
    match (must_pass, run(dir).is_ok()) {
        (true, false) => Err(format!("canary: {label} was refused")),
        (false, true) => Err(format!("canary: {label} passed")),
        _ => Ok(()),
    }
}

fn run_fixtures(dir: &Path) -> Result<(), String> {
    let verified = fixture_verified();
    let contained = fixture_contained();

    check_fixture(dir, "a verified tree", &verified, true)?;
    check_fixture(dir, "a contained tree", &contained, true)?;

    // State 1 defects.
    check_fixture(
        dir,
        "a raised flag with a bypass",
        &verified.replace(
            "(None, _) => Ok(()),",
            &format!("(None, _) if !Self::{FLAG}() => Ok(()),"),
        ),
        false,
    )?;
    check_fixture(
        dir,
        "a raised flag whose no-proof arm no longer errs",
        &verified.replace("(Some(_), None) => Err(", "(Some(_), None) => Ok(("),
        false,
    )?;
    check_fixture(
        dir,
        "a raised flag without the missing-proof test",
        &verified.replace(TEST_MISSING_SLASHES, ""),
        false,
    )?;

    // State 2 defects.
    check_fixture(
        dir,
        "a contained tree whose flag is computed",
        &contained.replace("    false\n}", "    chain_flag()\n}"),
        false,
    )?;
    check_fixture(
        dir,
        "a contained tree with an unguarded paying door",
        &contained.replace(
            &format!("if answered && opener != operator && Self::{FLAG}() {{"),
            "if answered && opener != operator {",
        ),
        false,
    )?;
    check_fixture(
        dir,
        "a contained tree whose arm can slash",
        &contained.replace(
            &format!("if !Self::{FLAG}() {{\n        Ok(())\n    }}"),
            &format!(
                "if !Self::{FLAG}() {{\n        Err(StorageError::InvalidMerkleProof(m))\n    }}"
            ),
        ),
        false,
    )?;
    check_fixture(
        dir,
        "a contained tree without the no-proof test",
        &contained.replace(TEST_NO_PROOF_RESOLVES, ""),
        false,
    )?;
    check_fixture(
        dir,
        "a contained tree without the no-credit test",
        &contained.replace(TEST_NO_CREDIT, ""),
        false,
    )?;
    check_fixture(
        dir,
        "a tree with no flag at all",
        &contained.replace(FLAG, "something_else"),
        false,
    )?;
    Ok(())
}

/// # Errors
///
/// Returns a finding when a defect fixture passes or a good fixture is refused.
pub fn self_test() -> Result<String, String> {
    let dir = rust_literals::exclusive_scratch_dir("budlum-gates-uncheck")?;
    let _ = std::fs::create_dir_all(dir.join("src/domain"));
    let outcome = run_fixtures(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    outcome?;
    Ok(String::from(
        "uncheckable-proof canary OK (enforced and contained states PASS; nine defect fixtures FAIL).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bare_true_or_false_body_names_a_state() {
        let f = FLAG;
        let active = format!("fn {f}() -> bool {{\n    true\n}}\n");
        assert_eq!(flag_state(&active, f), Flag::True);
        let one_line = format!("fn {f}() -> bool {{ true }}\n");
        assert_eq!(flag_state(&one_line, f), Flag::True);
        let disabled = format!("fn {f}() -> bool {{\n    false\n}}\n");
        assert_eq!(flag_state(&disabled, f), Flag::False);
        let computed = format!("fn {f}() -> bool {{\n    feature_on()\n}}\n");
        assert_eq!(flag_state(&computed, f), Flag::Computed);
        assert_eq!(flag_state("fn other() {}", f), Flag::Missing);
    }

    #[test]
    fn calls_inside_a_test_module_are_not_doors() {
        let code = "fn f() { self.record_proven_read(1); }\nmod tests { fn t() { reg.record_proven_read(2); } }\n";
        assert_eq!(call_sites(production(code)).len(), 1);
    }

    #[test]
    fn only_the_condition_directly_above_a_call_is_a_guard() {
        let guarded = "if a && Self::flag() {\n    self.pay();\n}";
        let at = guarded.find("self.pay").unwrap_or(0);
        assert!(enclosing_condition(guarded, at).is_some_and(|c| c.contains("Self::flag()")));
        // The flag is named earlier in the function, under a different `if`.
        let unrelated = "if !Self::flag() {\n    Ok(())\n}\nif a && b {\n    self.pay();\n}";
        let at = unrelated.find("self.pay").unwrap_or(0);
        assert!(enclosing_condition(unrelated, at).is_some_and(|c| !c.contains("Self::flag()")));
        // `elif`-like identifiers are not the keyword.
        assert_eq!(enclosing_condition("let notif = 1; self.pay();", 14), None);
    }

    #[test]
    fn a_call_site_is_not_the_definition() {
        let code = "fn record_proven_read(&mut self) {}\nfn f() { self.record_proven_read(1); }\n";
        assert_eq!(call_sites(code).len(), 1);
    }
}
