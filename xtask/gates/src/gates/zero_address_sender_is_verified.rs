//! Zero-address genesis bypass gate.
//!
//! A HIGH finding was fixed (CWE-306):
//! `validate_transaction_with_context` used to return `Ok(())` for every
//! `tx.from == Address::zero()`, so a zero-address wallet skipped all
//! validation. The fix admits only the canonical genesis transaction, which
//! `tx.verify()` accepts, and rejects everything else.
//!
//! Mutation testing showed that NO gate protected this fix: removing
//! the `tx.verify()` check did not fail any required check, and no test
//! pinned the path. This gate closes both gaps.

use std::path::Path;

fn account_path(root: &Path) -> std::path::PathBuf {
    root.join("src/core/account.rs")
}

/// Strip Rust comments and string literals (preserving line structure) so
/// comment-bait or dead text cannot satisfy the gate (CWE-697).
fn strip_rust_noise(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes[pos..].starts_with(b"//") {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                out.push(' ');
                pos += 1;
            }
            continue;
        }
        if bytes[pos..].starts_with(b"/*") {
            // Rust block comments nest (`/* outer /* inner */ tail */`); a
            // flat scan stops at the first `*/` and leaves the tail looking
            // like live code. Track depth instead (CWE-697).
            out.push(' ');
            out.push(' ');
            pos += 2;
            let mut depth = 1usize;
            while pos < bytes.len() && depth > 0 {
                if bytes[pos..].starts_with(b"/*") {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    pos += 2;
                    continue;
                }
                if bytes[pos..].starts_with(b"*/") {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    pos += 2;
                    continue;
                }
                out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                pos += 1;
            }
            continue;
        }
        if bytes[pos] == b'r' || bytes[pos] == b'b' {
            let mut scan = pos;
            if bytes[scan] == b'b' {
                scan += 1;
            }
            if scan < bytes.len() && bytes[scan] == b'r' {
                scan += 1;
                let mut hash_count = 0usize;
                while scan < bytes.len() && bytes[scan] == b'#' {
                    hash_count += 1;
                    scan += 1;
                }
                if scan < bytes.len() && bytes[scan] == b'"' {
                    let mut end = scan + 1;
                    while end < bytes.len() {
                        if bytes[end] == b'"' {
                            let mut hashes = 0usize;
                            let mut cursor = end + 1;
                            while cursor < bytes.len()
                                && bytes[cursor] == b'#'
                                && hashes < hash_count
                            {
                                hashes += 1;
                                cursor += 1;
                            }
                            if hashes == hash_count {
                                break;
                            }
                        }
                        end += 1;
                    }
                    let mut blank_to = if end < bytes.len() {
                        end + 1 + hash_count
                    } else {
                        bytes.len()
                    };
                    if blank_to > bytes.len() {
                        blank_to = bytes.len();
                    }
                    while pos < blank_to {
                        out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                        pos += 1;
                    }
                    continue;
                }
            }
        }
        if bytes[pos] == b'"' {
            out.push(' ');
            pos += 1;
            while pos < bytes.len() && bytes[pos] != b'"' {
                if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
                    pos += 2;
                    continue;
                }
                out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                pos += 1;
            }
            if pos < bytes.len() {
                out.push(' ');
                pos += 1;
            }
            continue;
        }
        out.push(bytes[pos] as char);
        pos += 1;
    }
    out
}

fn collect(root: &Path) -> Result<String, String> {
    let p = account_path(root);
    std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

/// True if `text` contains any unit-`Ok` success form: `Ok(())`, a path
/// `::Ok(())`, or a typed `Ok::<T, E>(())` variant, whitespace-tolerant.
/// Literal matching misses typed or spaced forms (CWE-697).
fn ok_success_in(text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    // A unit-Ok used as a collection item (`vec![Ok(())]`, `[Ok(())]`) is not
    // a control-flow success (CWE-697: nested-item).
    if compact.contains("![Ok(())") || compact.contains("[Ok(()),") {
        return false;
    }
    compact.contains("Ok(())")
        || compact.contains("::Ok(())")
        || (compact.contains("Ok::<") && compact.contains(">(())"))
        || (compact.contains("::Ok::<") && compact.contains(">(())"))
}

/// Does the code after the positive `tx.verify()` block fail closed? Only a
/// leading `return Err(` / `Err(` counts. Anything else - a helper call, a
/// tail `true`, a tail `Ok` - is an unguarded success path that reopens the
/// zero-address bypass even when a decoy `Ok(())` sits inside the verified
/// branch (CWE-697).
fn fail_closes_after_verify(text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.starts_with("returnErr(") || compact.starts_with("Err(")
}
fn judge(src: &str) -> Vec<String> {
    let mut problems = Vec::new();

    if !src.contains("zero-address sender is only valid for the canonical genesis transaction") {
        problems.push(String::from(
            "account.rs no longer rejects non-genesis zero-address senders. The CWE-306 bypass is protected only by this rejection.",
        ));
    }

    let clean = strip_rust_noise(src);
    let function_start = clean.find("pub fn validate_transaction_with_context(");
    let zero_guard = function_start.and_then(|fstart| {
        let frest = &clean[fstart..];
        let body_start = frest.find('{')?;
        let body = &frest[body_start..];
        let mut depth = 0i32;
        let mut end = body.len();
        for (i, ch) in body.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let fblock = &body[..end];
        let zero_start = fblock.find("if tx.from == Address::zero() {")?;
        let rest = &fblock[zero_start..];
        let mut depth = 0i32;
        let mut end = rest.len();
        for (i, ch) in rest.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        Some(&rest[..end])
    });
    if let Some(block) = zero_guard {
        // The zero-address success must be nested INSIDE the
        // `if tx.verify() { .. }` block. Any `Ok(())` (with or without
        // `return`) outside that block, including after a failed verify
        // (`if !tx.verify() { return Ok(()); }`) or as a tail expression
        // (`if tx.verify() { Ok(()) }`), is an unguarded success
        // (CWE-697).
        // Success is any `Ok` expression whose payload is the unit type:
        // `Ok(())`, `Ok::<(), String>(())`, `Ok::<_, _>(())`, etc. A literal
        // `Ok(())` match misses the typed forms (CWE-697).
        // Whitespace-compact unit-success detection covers `Ok(())`,
        // `Ok :: <(), String> (())`, `::Ok(())` etc. (CWE-697).
        let has_ok_success = ok_success_in(block);
        let guarded_success = block.find("if tx.verify() {").is_some_and(|verify_start| {
            let verify_rest = &block[verify_start..];
            let mut verify_depth = 0i32;
            let mut verify_end = verify_rest.len();
            for (i, ch) in verify_rest.char_indices() {
                match ch {
                    '{' => verify_depth += 1,
                    '}' => {
                        verify_depth -= 1;
                        if verify_depth == 0 {
                            verify_end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let verify_block = &verify_rest[..verify_end];
            // A success inside a closure (`|| { Ok(()) }`) or helper within
            // the verify block does not guard the outer path; exclude it
            // (CWE-697: nested helper decoys).
            let verify_no_closure = !verify_block.contains("||") && !verify_block.contains("| ");
            let ok_in_verify = verify_no_closure && ok_success_in(verify_block);
            let ok_before = ok_success_in(&block[..verify_start]);
            let after = &verify_rest[verify_end..];
            // The tail must fail closed. A success after the verified branch
            // - whether an `Ok(())`, a helper call, or a bare tail `true` -
            // reopens the bypass even when a decoy `Ok(())` sits inside the
            // branch; only `return Err(` / `Err(` is a real close
            // (CWE-697). An `Ok(())` after the verify block is likewise
            // rejected.
            let after_fails_closed = fail_closes_after_verify(after);
            let ok_after = ok_success_in(after);
            ok_in_verify && !ok_before && !ok_after && after_fails_closed
        });
        if has_ok_success && !guarded_success {
            problems.push(String::from(
                "account.rs has regressed to an unguarded zero-address success. Ok(()) must be nested inside the positive tx.verify() branch; a failed-verify or tail success reopens the CWE-306 bypass.",
            ));
        }
    } else {
        problems.push(String::from(
            "account.rs has no zero-address branch inside validate_transaction_with_context; the CWE-306 guard is missing.",
        ));
    }

    let has_test = src
        .lines()
        .zip(src.lines().skip(1))
        .any(|(a, b)| a.trim() == "#[test]" && b.contains("zero_address_non_genesis_rejected"));
    if !has_test {
        problems.push(String::from(
            "no #[test] pinning the zero-address validation path was found. Keep test_zero_address_non_genesis_rejected in account.rs.",
        ));
    }

    problems
}

pub fn run(root: &Path) -> Result<String, String> {
    let src = collect(root)?;
    let problems = judge(&src);
    if problems.is_empty() {
        return Ok(String::from(
            "zero-address gate OK: non-genesis zero-address senders are rejected and a test pins the path.",
        ));
    }
    Err(problems.join("\n"))
}

pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();

    let good = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            return Ok(());\n        }\n        return Err(\"zero-address sender is only valid for the canonical genesis transaction\".into());\n    }\n}\n#[test]\nfn zero_address_non_genesis_rejected() {}\n";
    if !judge(good).is_empty() {
        problems.push(String::from(
            "BROKEN: the protected form was reported as missing.",
        ));
    }

    let bad = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        return Ok(());\n    }\n}\n";
    let finds = judge(bad);
    if !finds
        .iter()
        .any(|p| p.contains("effectively unguarded") || p.contains("unguarded zero-address"))
    {
        problems.push(String::from(
            "VACUOUS: the unguarded zero-address bypass was accepted.",
        ));
    }

    let dead = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        let _unused = tx.verify();\n        return Ok(());\n    }\n}\n";
    if !judge(dead)
        .iter()
        .any(|p| p.contains("effectively unguarded") || p.contains("unguarded zero-address"))
    {
        problems.push(String::from(
            "VACUOUS: a dead tx.verify() plus unconditional zero-address success was accepted.",
        ));
    }

    let misnested = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() { }\n        return Ok(());\n    }\n}\n";
    if !judge(misnested).iter().any(|p| p.contains("nested inside")) {
        problems.push(String::from(
            "VACUOUS: a misnested tx.verify() branch was accepted.",
        ));
    }

    // A decoy `Ok(())` inside the verified branch with a tail success after
    // it must fail (CWE-697).
    let decoy_tail = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            Ok::<_, _>(())\n        }\n        true\n    }\n}\n";
    if !judge(decoy_tail)
        .iter()
        .any(|p| p.contains("unguarded zero-address"))
    {
        problems.push(String::from(
            "VACUOUS: a decoy Ok inside the verified branch plus a tail success was accepted.",
        ));
    }

    // A helper-call success after the verified branch must fail too
    // (CWE-697).
    let decoy_helper = "pub fn validate_transaction_with_context(\n        &self,\n        tx: &Transaction,\n    ) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            return Ok(());\n        }\n        self.accept_zero_address()\n    }\n}\n";
    if !judge(decoy_helper)
        .iter()
        .any(|p| p.contains("unguarded zero-address"))
    {
        problems.push(String::from(
            "VACUOUS: a helper success after the verified branch was accepted.",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "zero-address gate self-test OK: the protected form passes, the unguarded bypass fails.",
    ))
}
