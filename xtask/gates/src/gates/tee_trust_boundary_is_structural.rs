//! TEE trust-boundary gate.
//!
//! An earlier fix hardened `sign_with_privacy` against self-attested software
//! runtimes (security review, MEDIUM/HIGH, CWE-347): the runtime returns only a raw
//! hardware quote (`TeeQuoter::quote`) and the wallet verifies it with a
//! verifier it owns (`TeeQuoteVerifier`) before trusting any field. The
//! runtime never supplies parsed attestation fields, so a self-attesting
//! software runtime cannot fabricate an attestation by echoing fields back.
//!
//! Mutation testing showed that NO gate protects this split: reverting
//! to a runtime-supplied `attest()` would not fail any required check. This
//! gate name-locks the structural split.

use std::path::Path;

fn tee_files(root: &Path) -> Vec<std::path::PathBuf> {
    vec![
        root.join("crates/wallet-core/src/lib.rs"),
        root.join("crates/wallet-core/src/tee.rs"),
    ]
}

/// Strip Rust comments, ordinary strings and raw strings (preserving line
/// structure) so dead text cannot satisfy the gate (CWE-697).
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

fn read_all(root: &Path) -> Result<String, String> {
    let mut out = String::new();
    for p in tee_files(root) {
        let s =
            std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        out.push_str(&s);
        out.push('\n');
    }
    Ok(out)
}

/// Judge the current tree.
/// `sign_with_privacy` must take the verifier AND call it inside its own
/// body; a call elsewhere in the file does not count (CWE-697: tee.rs
/// test helpers already call `verify_quote`).
/// Does the attestation predicate at `needle` appear in a guard that returns
/// an error from `sign_with_privacy`?
///
/// Only a top-level `return Err(..)` in the guard body fails the outer
/// function closed. A `return Err` nested inside a closure passed as an
/// argument (`move |_| { return Err(..); }`), a named closure binding
/// (`let f = || { return Err(..); }`) or a nested block
/// (`if false { return Err(..); }`) is a decoy that leaves the outer
/// attestation check fail-open (CWE-697). Track
/// brace depth line by line and accept only a depth-0 `return Err`.
fn has_rejecting_guard(body: &str, needle: &str) -> bool {
    body.find(needle).is_some_and(|guard_start| {
        let guard = &body[guard_start..];
        match guard.find('{') {
            Some(open) => {
                let mut depth = 0usize;
                let mut guarded = false;
                for (idx, ch) in guard[open..].char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                let guard_body = &guard[open + 1..open + idx];
                                let mut nested_depth = 0usize;
                                let mut top_level_return_err = false;
                                for line in guard_body.lines() {
                                    let trimmed = line.trim();
                                    if nested_depth == 0
                                        && (trimmed.starts_with("return Err(")
                                            || trimmed.starts_with("return Err ("))
                                    {
                                        top_level_return_err = true;
                                        break;
                                    }
                                    for c in trimmed.chars() {
                                        match c {
                                            '{' => nested_depth += 1,
                                            '}' => {
                                                nested_depth = nested_depth.saturating_sub(1);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                // Hardening kept from the
                                // bulgular branch: a closure/nested-fn decoy
                                // (`||`, `| `, `fn `) or a nested conditional
                                // (a `return Err` appearing after a nested
                                // `if` opener) must not satisfy the
                                // rejecting-guard check even if the line walk
                                // above could be fooled by brace layout.
                                let closure_decoy = guard_body.contains("||")
                                    || guard_body.contains("| ")
                                    || guard_body.contains("fn ");
                                let first_err = guard_body.find("return Err");
                                let first_if = guard_body.find("if ");
                                let nested_conditional = match (first_err, first_if) {
                                    (Some(e), Some(f)) => f < e,
                                    _ => false,
                                };
                                guarded =
                                    top_level_return_err && !closure_decoy && !nested_conditional;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                guarded
            }
            None => false,
        }
    })
}

fn check_live_verifier_call(src: &str, problems: &mut Vec<String>) {
    // Strip comments and string/raw-string literals first so a decoy
    // `sign_with_privacy` inside dead text cannot anchor the check
    // (CWE-697). Anchor to the `impl Wallet { .. }` block so an earlier live
    // helper with the same signature cannot steal the anchor (CWE-697), and
    // require the attestation RESULT to be used, so an
    // inert `verify_quote` call that does not drive the decision is rejected.
    let clean = strip_rust_noise(src);
    let sign_with_privacy_block = clean.find("impl Wallet {").and_then(|impl_start| {
        let impl_src = &clean[impl_start..];
        let impl_open = impl_src.find('{')?;
        let mut impl_depth = 0usize;
        let mut impl_end = None;
        for (idx, ch) in impl_src[impl_open..].char_indices() {
            match ch {
                '{' => impl_depth += 1,
                '}' => {
                    impl_depth = impl_depth.saturating_sub(1);
                    if impl_depth == 0 {
                        impl_end = Some(impl_open + idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        let wallet_impl = &impl_src[..=impl_end?];
        let method_start = wallet_impl.find("pub fn sign_with_privacy(")?;
        let body = &wallet_impl[method_start..];
        let open = body.find('{')?;
        let mut depth = 0usize;
        for (idx, ch) in body[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(&body[..=open + idx]);
                    }
                }
                _ => {}
            }
        }
        None
    });
    let live_verifier_call = match sign_with_privacy_block {
        Some(body) => {
            // Each attestation predicate must appear in a fail-closed guard
            // that returns an error from sign_with_privacy. Presence alone is
            // insufficient: `let measurement_ok = attestation.verify_measurement(..)`
            // still leaves an unconditional success path (CWE-697:
            // fail-open branches).
            let measurement_gates_flow =
                has_rejecting_guard(body, "if !attestation.verify_measurement(");
            let backend_gates_flow = has_rejecting_guard(body, "if attestation.backend !=");
            let report_gates_flow =
                has_rejecting_guard(body, "if !attestation.verify_report_data(");
            body.contains("verifier: &dyn TeeQuoteVerifier")
                && (body.contains("let attestation = verifier.verify_quote(&quote)")
                    || body.contains("let attestation=verifier.verify_quote(&quote)"))
                && measurement_gates_flow
                && backend_gates_flow
                && report_gates_flow
        }
        None => false,
    };
    if !live_verifier_call {
        problems.push(String::from(
            "sign_with_privacy no longer enforces the wallet-owned quote verification step before trusting attestation fields. The attestation result must be produced by verifier.verify_quote and actually used (measurement, backend, report_data checks); without it the runtime can reclaim attestation control.",
        ));
    }
}

fn judge(src: &str) -> Vec<String> {
    let mut problems = Vec::new();

    // 1. The runtime side must be a quote source, not an attestation source.
    if !src.contains("trait TeeQuoter: TeeRuntime") {
        problems.push(String::from(
            "wallet-core no longer has a `TeeQuoter` trait. The runtime must produce only \\
             a raw quote; letting it produce parsed attestation fields reopens the \\
             self-attestation bypass (CWE-347).",
        ));
    }
    if src.contains("trait TeeAttester")
        || src.contains("runtime: &dyn TeeAttester")
        || src.contains(".attest(")
    {
        problems.push(String::from(
            "wallet-core still references a runtime-supplied `attest` path. Attestation must come from a wallet-owned verifier over a raw quote.",
        ));
    }
    // Rename-resistant and multi-line-signature resistant (CWE-697):
    // a method returning `Result<TeeAttestation>` outside the wallet-owned
    // verifier is a self-attestation path under any name. Normalize
    // whitespace first so a return type split across lines is still caught.
    let normalized = src.split_whitespace().collect::<Vec<_>>().join(" ");
    // The wallet-owned verifier trait's own body: a `verify_quote` inside it
    // is the ONE allowed producer of a parsed attestation.
    let verifier_block = normalized.find("trait TeeQuoteVerifier").and_then(|start| {
        normalized[start..]
            .find('}')
            .map(|end| &normalized[start..=start + end])
    });
    if normalized.contains("-> Result<TeeAttestation")
        || normalized.contains("-> Result< TeeAttestation")
    {
        for signature in normalized.split("fn ").skip(1) {
            // Cut the signature at the first `;` or `{` so it ends at the
            // method declaration, not at whatever follows it in the file.
            let sig_cut = signature
                .find(';')
                .or_else(|| signature.find('{'))
                .unwrap_or(signature.len());
            let full_signature = format!("fn {}", &signature[..sig_cut]);
            // A method is safe only if its declaration sits inside the
            // wallet-owned `trait TeeQuoteVerifier { .. }` body. The bare
            // name `verify_quote` is not a pass: a runtime-owned trait may
            // reuse that name and the gate must still reject it
            // (CWE-697). Impls of the verifier trait carry the trait's full
            // method body in the same block, so a block-level match covers
            // them: we accept the signature if it appears anywhere inside
            // `trait TeeQuoteVerifier { .. }` (which spans its impls only
            // when they are written inline in that block; separate `impl
            // TeeQuoteVerifier for X` blocks are matched by checking the
            // normalized text between the trait and the next top-level
            // keyword).
            // A method is safe if its declaration sits inside the wallet-owned
            // `trait TeeQuoteVerifier { .. }` body OR inside an
            // `impl TeeQuoteVerifier for .. { .. }` block. A bare `verify_quote`
            // name under any OTHER trait is a runtime-owned attestation path
            // and must be rejected (CWE-697).
            let in_trait = verifier_block.is_some_and(|block| block.contains(&full_signature));
            let in_impl = normalized
                .split("impl TeeQuoteVerifier for")
                .skip(1)
                .any(|chunk| {
                    let open = chunk.find('{');
                    let close = chunk.find('}').unwrap_or(chunk.len());
                    if let Some(o) = open {
                        let body = &chunk[o..=close.min(chunk.len().saturating_sub(1))];
                        body.contains(&full_signature)
                    } else {
                        false
                    }
                });
            let allowed_verifier_method = in_trait || in_impl;
            if (signature.contains("-> Result<TeeAttestation")
                || signature.contains("-> Result< TeeAttestation"))
                && !allowed_verifier_method
            {
                problems.push(String::from(
                    "wallet-core has a method returning Result<TeeAttestation> outside the wallet-owned TeeQuoteVerifier. Under any name this is a runtime-supplied attestation path and reopens the self-attestation bypass.",
                ));
                break;
            }
        }
    }

    // 2. The verifier side must be wallet-owned and fail closed.
    if !src.contains("trait TeeQuoteVerifier") {
        problems.push(String::from(
            "wallet-core no longer has a `TeeQuoteVerifier` trait. Without a wallet-owned \\
             verifier, the runtime is the only source of attestation and can self-attest.",
        ));
    }
    if !src.contains("UnavailableTeeQuoteVerifier") {
        problems.push(String::from(
            "wallet-core no longer fails closed when no hardware root is linked. \\
             `UnavailableTeeQuoteVerifier` must reject every quote.",
        ));
    }

    check_live_verifier_call(src, &mut problems);

    problems
}

/// # Errors
///
/// Returns the trust-boundary protections that are missing.
pub fn run(root: &Path) -> Result<String, String> {
    let src = read_all(root)?;
    let problems = judge(&src);
    if problems.is_empty() {
        return Ok(String::from(
            "TEE trust-boundary gate OK: runtime produces raw quotes, wallet verifies \\
             them, and signing fails closed without an enrolled measurement.",
        ));
    }
    Err(problems.join("\n"))
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();

    let good = "\
trait TeeQuoter: TeeRuntime { fn quote(&self, d: [u8; 32]) -> Result<Vec<u8>, WalletError>; }
trait TeeQuoteVerifier { fn verify_quote(&self, q: &[u8]) -> Result<TeeAttestation, WalletError>; }
pub struct UnavailableTeeQuoteVerifier;
impl Wallet {
    pub fn sign_with_privacy(&self, message: &[u8], runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable(\"x\".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable(\"x\".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable(\"x\".into())); }
        Ok([0u8; 64])
    }
}
";
    if !judge(good).is_empty() {
        problems.push(String::from(
            "BROKEN: the trust-boundary split was reported as missing.",
        ));
    }

    let bad = "\
trait TeeAttester: TeeRuntime { fn attest(&self, d: [u8; 32]) -> Result<TeeAttestation, WalletError>; }
pub fn sign_with_privacy(&self, message: &[u8], runtime: &dyn TeeAttester) -> Result<[u8; 64], WalletError> {}
";
    let finds = judge(bad);
    if !finds
        .iter()
        .any(|p| p.contains("TeeQuoteVerifier") || p.contains("runtime-supplied"))
    {
        problems.push(String::from(
            "VACUOUS: a runtime-attestation tree was accepted.",
        ));
    }

    let renamed = "\ntrait RuntimeClaims { fn get_attestation(&self, d: [u8; 32]) -> Result<TeeAttestation, WalletError>; }\npub fn sign_with_privacy(&self, runtime: &dyn RuntimeClaims) -> Result<[u8; 64], WalletError> {}\n";
    if !judge(renamed)
        .iter()
        .any(|p| p.contains("Result<TeeAttestation"))
    {
        problems.push(String::from(
            "VACUOUS: a renamed runtime-attestation API was accepted.",
        ));
    }

    let renamed_multiline = "\ntrait TeeQuoter: TeeRuntime { fn quote(&self, d: [u8; 32]) -> Result<Vec<u8>, WalletError>; }\ntrait TeeQuoteVerifier { fn verify_quote(&self, q: &[u8]) -> Result<TeeAttestation, WalletError>; }\npub struct UnavailableTeeQuoteVerifier;\ntrait RuntimeClaims {\n    fn get_attestation(&self, d: [u8; 32]) -> Result<\n        TeeAttestation,\n        WalletError,\n    >;\n}\npub fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, claims: &dyn RuntimeClaims, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { let _ = (runtime, claims, verifier); }\n";
    if !judge(renamed_multiline)
        .iter()
        .any(|p| p.contains("Result<TeeAttestation") || p.contains("runtime-supplied"))
    {
        problems.push(String::from(
            "VACUOUS: a renamed runtime-attestation API with a multi-line Result signature was accepted.",
        ));
    }

    let runtime_verify_quote = "\ntrait TeeQuoter: TeeRuntime { fn quote(&self, d: [u8; 32]) -> Result<Vec<u8>, WalletError>; }\ntrait TeeQuoteVerifier { fn verify_quote(&self, q: &[u8]) -> Result<TeeAttestation, WalletError>; }\npub struct UnavailableTeeQuoteVerifier;\nimpl TeeQuoteVerifier for UnavailableTeeQuoteVerifier { fn verify_quote(&self, _q: &[u8]) -> Result<TeeAttestation, WalletError> { Err(WalletError::TeeUnavailable(\"x\".into())) } }\ntrait RuntimeClaims: TeeRuntime { fn verify_quote(&self, d: [u8; 32]) -> Result<TeeAttestation, WalletError>; }\npub fn sign_with_privacy(&self, runtime: &dyn RuntimeClaims, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { let _ = (runtime, verifier); }\n";
    if !judge(runtime_verify_quote)
        .iter()
        .any(|p| p.contains("Result<TeeAttestation") || p.contains("runtime-supplied"))
    {
        problems.push(String::from(
            "VACUOUS: a runtime-owned verify_quote method was accepted.",
        ));
    }

    // A decoy `sign_with_privacy` inside a comment before the live one must
    // not anchor the verifier-call check (CWE-697).
    let decoy = "/* fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { let quote = runtime.quote([0u8; 32]).unwrap(); let attestation = verifier.verify_quote(&quote).unwrap(); let _ = attestation; } */\npub fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { Ok([0u8; 64]) }\n";
    let mut decoy_problems = Vec::new();
    check_live_verifier_call(decoy, &mut decoy_problems);
    if decoy_problems.is_empty() {
        problems.push(String::from(
            "VACUOUS: a decoy sign_with_privacy in a comment anchored the verifier-call check.",
        ));
    }

    // A `return Err` nested inside a closure argument or inner block must not
    // satisfy the rejecting-guard check: the outer attestation check would
    // stay fail-open (CWE-697).
    let closure_decoy = "\nimpl Wallet {\n    pub fn sign_with_privacy(&self, message: &[u8], runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {\n        let quote = runtime.quote([0u8; 32]).unwrap();\n        let attestation = verifier.verify_quote(&quote).unwrap();\n        if !attestation.verify_measurement(&[0u8; 32]) { let _d = move || { return Err(WalletError::TeeUnavailable(\"x\".into())); }; }\n        if attestation.backend != TeeBackendKind::ClientSgx { if false { return Err(WalletError::TeeUnavailable(\"x\".into())); } }\n        if !attestation.verify_report_data(&[0u8; 32]) { let _d = || { return Err(WalletError::TeeUnavailable(\"x\".into())); }; }\n        Ok([0u8; 64])\n    }\n}\n";
    let mut closure_problems = Vec::new();
    check_live_verifier_call(closure_decoy, &mut closure_problems);
    if closure_problems.is_empty() {
        problems.push(String::from(
            "VACUOUS: nested-closure/nested-block return Err decoys satisfied the rejecting-guard check.",
        ));
    }

    // A raw-string decoy before the live function must not anchor the check.
    let raw_decoy = "let _d = r#\"pub fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { let quote = runtime.quote([0u8; 32]).unwrap(); let attestation = verifier.verify_quote(&quote).unwrap(); let _ = attestation; }\"#;\npub fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> { Ok([0u8; 64]) }\n";
    let mut raw_decoy_problems = Vec::new();
    check_live_verifier_call(raw_decoy, &mut raw_decoy_problems);
    if raw_decoy_problems.is_empty() {
        problems.push(String::from(
            "VACUOUS: a raw-string decoy sign_with_privacy anchored the verifier-call check.",
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "TEE trust-boundary gate self-test OK: the split passes, the runtime-attestation \\
         regression fails.",
    ))
}
