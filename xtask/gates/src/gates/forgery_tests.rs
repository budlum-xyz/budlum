//! Required forgery tests must exist and be real `#[test]`s that assert a
//! refusal.
//!
//! Ported from `scripts/check-forgery-tests-are-named.sh`. Each required name
//! must appear as a `#[test] fn`, and its body (following helper calls) must
//! assert a refusal.

use std::fmt::Write as _;
use std::path::Path;

const REQUIRED: &[&str] = &[
    "rejects_a_forged_difference",
    "rejects_a_forged_product",
    "rejects_a_forged_quotient_when_dividing_by_zero",
    "rejects_a_comparison_read_from_a_wrapped_bit_string",
    "rejects_a_load_that_denies_touching_memory",
    "rejects_a_pop_that_invents_a_value",
    "rejects_a_return_to_an_address_never_pushed",
    "rejects_a_jump_past_the_end_of_the_program",
    "rejects_a_row_relabelled_as_a_different_opcode",
    "rejects_a_swapped_source_register",
    "rejects_a_write_to_the_zero_register",
    "rejects_a_register_that_changes_value_without_a_write",
    "rejects_an_assert_that_claims_zero_is_non_zero",
    "rejects_an_invented_starting_register",
    "rejects_an_opcode_column_that_disagrees_with_the_program",
    "rejects_a_redirected_storage_slot",
    "rejects_a_shifted_event_digest",
    "rejects_tampered_bitwise_and_result",
    "rejects_tampered_comparison_result",
    "rejects_tampered_event_digest",
    "rejects_tampered_poseidon_sbox",
    "rejects_tampered_storage_write_result",
    "rejects_a_proof_claiming_an_impossible_degree",
];

fn collect_sources(root: &Path) -> String {
    let mut blob = String::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.join("budzero")];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let n = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if !matches!(n.as_str(), ".git" | "target") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    blob.push_str(&text);
                    blob.push('\n');
                }
            }
        }
    }
    blob
}

/// Brace-matched body of `fn <name>`.
fn body_of(blob: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let start = blob.find(&needle)?;
    let rest = &blob[start + needle.len()..];
    let open = rest.find('{')? + start + needle.len();
    // The scan starts after the opening brace, which `depth` already
    // counts. Starting on it counted the brace twice, so the body's own
    // `}` never brought the depth back to zero, the scan ran to the end of
    // the blob and returned `None`, and the caller took `None` as "skip":
    // no required test's body was ever checked for a refusal.
    let mut depth = 1i32;
    let mut i = open + 1;
    let b = blob.as_bytes();
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(blob[open..i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Drop comments, string literals and char literals, so an assertion named
/// in a message or a comment does not count as an assertion made.
///
/// A `'` opens a char literal only when one closes it within a few bytes
/// (`'x'`, `'\n'`); otherwise it is a lifetime or an apostrophe in a
/// comment. Taking every `'` as a quote let the apostrophe in a comment
/// such as `the row's successor` swallow the code that followed it, up to
/// the next apostrophe, and with it the `is_err()` the check was looking
/// for.
fn strip_strings(text: &str) -> String {
    let mut out = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'"' {
            out.push('"');
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else if b[i] == b'\'' {
            let close = (i + 2..=(i + 4).min(b.len().saturating_sub(1)))
                .find(|&j| b[j] == b'\'' && !(b[j - 1] == b'\\' && j == i + 2));
            out.push('\'');
            i = close.map_or(i + 1, |j| j + 1);
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let blob = collect_sources(root);
    if blob.is_empty() {
        return Err(format!("no .rs sources under {}/budzero", root.display()));
    }
    let mut problems: Vec<String> = Vec::new();

    for name in REQUIRED {
        // `#[test] fn <name>(`
        let is_test = blob.contains("#[test]") && blob.contains(&format!("fn {name}("));
        // check attribute precedes the fn
        let test_before_fn = blob
            .find(&format!("fn {name}("))
            .is_some_and(|fn_pos| blob[..fn_pos].rfind("#[test]").is_some());
        if is_test && test_before_fn {
            continue;
        }
        if blob.contains(&format!("fn {name}(")) {
            problems.push(format!(
                "`{name}` exists but is not a `#[test]`-annotated function."
            ));
        } else {
            problems.push(format!("`{name}` is missing."));
        }
    }

    // Each required test's body must assert a refusal (directly or via the
    // shared helper).
    let helper = "prove_fails_after_tamper";
    for name in REQUIRED {
        let Some(body) = body_of(&blob, name) else {
            continue;
        };
        let body = strip_strings(&body);
        let delegates = body.contains(helper);
        let asserts_failure = body.contains("is_err()")
            || body.contains("expect_err")
            || body.contains("unwrap_err")
            || body.contains("Err(VerifyError::");
        let rejects_at_vm =
            body.contains("assert_eq!(vm.registers") || body.contains("assert!(!receipt.success");
        if !delegates && !asserts_failure && !rejects_at_vm {
            problems.push(format!(
                "`{name}` builds a forgery and never asserts the proof is \
                 refused. A test that tampers and then expects success is \
                 coverage on paper."
            ));
        }
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "forgery-names gate OK: {} required forgery tests are real and assert a refusal",
        REQUIRED.len()
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-ft-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let mut good = String::new();
    for n in REQUIRED {
        writeln!(
            good,
            "#[test]\nfn {n}() {{\n    assert!(prove_fails_after_tamper());\n}}"
        )
        .expect("writing to a String cannot fail");
    }
    good.push_str("fn prove_fails_after_tamper() -> bool { true }\n");
    std::fs::write(dir.join("budzero/bud-proof/src/lib.rs"), &good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: correct tests were refused"));
    }
    // Remove #[test] from one.
    let bad = good.replace(
        "#[test]\nfn rejects_a_forged_difference()",
        "fn rejects_a_forged_difference()",
    );
    std::fs::write(dir.join("budzero/bud-proof/src/lib.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a name carrying no #[test] passed"));
    }
    // A test that tampers and then asserts success is coverage on paper:
    // its body has to be read, and read to its own closing brace, or this
    // check is a no-op. It was one, for as long as the body scan started on
    // the opening brace and never returned a body.
    let paper = good.replace(
        "fn rejects_a_forged_difference() {\n    assert!(prove_fails_after_tamper());\n}",
        "fn rejects_a_forged_difference() {\n    let r = tamper();\n    assert!(r.is_ok());\n}",
    );
    assert_ne!(paper, good, "the fixture must contain the rewritten test");
    std::fs::write(dir.join("budzero/bud-proof/src/lib.rs"), paper).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a required test that asserts success after tampering passed",
        ));
    }
    // An apostrophe in a comment is not a quote. One before the assertion
    // used to open a "char literal" that ran to the next apostrophe and hid
    // the `is_err()` behind it.
    let apostrophe = good.replace(
        "fn rejects_a_forged_difference() {\n    assert!(prove_fails_after_tamper());\n}",
        "fn rejects_a_forged_difference() {\n    // the row's successor\n    let r = tamper();\n    \
         assert!(r.is_err());\n    let _ = 'x';\n}",
    );
    std::fs::write(dir.join("budzero/bud-proof/src/lib.rs"), apostrophe)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: an apostrophe in a comment hid the refusal assertion that followed it",
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "forgery-tests canary OK: with a test it PASSes, without one it FAILs, and a test \
         asserting success after tampering FAILs.",
    ))
}
