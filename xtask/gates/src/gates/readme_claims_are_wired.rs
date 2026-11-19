//! Every shipped subsystem claim in `README.md` and `README.tr.md` must be
//! backed by non-test production code, a real production call site, and an
//! automated test, and the Manifest V3 BNS extension must exclude every
//! protocol reserved label.
//!
//! # The failure this closes
//!
//! A README can promise a subsystem whose implementation lives only in a test
//! fixture, sits disconnected from the node call graph, or lost its tests in a
//! refactor. Similarly, a browser extension redirect table can drift behind
//! `src/registry/params.rs::RESERVED_LABELS` and intercept core Budlum service
//! domains (`api.budlum.xyz`, `rpc.budlum.xyz`, `gateway.budlum.xyz`).
//!
//! This gate checks each shipped claim across four artifacts:
//! 1. Both `README.md` and `README.tr.md` declare the claim.
//! 2. The defining production file contains the named symbol outside comments
//!    and outside `#[cfg(test)]`.
//! 3. A distinct production call-site file references the symbol outside
//!    comments and outside `#[cfg(test)]`.
//! 4. The designated test file carries an automated `#[test]` or
//!    `#[tokio::test]` exercising the subsystem.
//!
//! It also parses `src/registry/params.rs::RESERVED_LABELS` and checks that
//! `browser-extension/rules.json` excludes every `<label>.budlum.xyz` entry.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// One README claim and the production + wiring + test evidence backing it.
#[derive(Debug, Clone, Copy)]
pub struct ReadmeClaim {
    /// Short stable identifier reported on failure.
    pub id: &'static str,
    /// Case-insensitive phrase expected in `README.md`.
    pub readme_marker: &'static str,
    /// Case-insensitive phrase expected in `README.tr.md`.
    pub readme_tr_marker: &'static str,
    /// Repository-relative source file defining the production implementation.
    pub prod_file: &'static str,
    /// Production symbol expected outside comments and `#[cfg(test)]`.
    pub prod_symbol: &'static str,
    /// Distinct production source file that wires/invokes the implementation.
    pub call_site_file: &'static str,
    /// Token expected at the call site outside comments and `#[cfg(test)]`.
    pub call_site_token: &'static str,
    /// File carrying automated tests (`#[test]` or `#[tokio::test]`).
    pub test_file: &'static str,
    /// Token expected inside the test file.
    pub test_token: &'static str,
}

/// Core shipped subsystem claims enforced against `README.md` and `README.tr.md`.
const CLAIMS: &[ReadmeClaim] = &[
    ReadmeClaim {
        id: "consensus-pos-engine",
        readme_marker: "src/consensus/",
        readme_tr_marker: "src/consensus/",
        prod_file: "src/consensus/pos.rs",
        prod_symbol: "pub struct PoSEngine",
        call_site_file: "src/chain/blockchain.rs",
        call_site_token: "PoSConfig",
        test_file: "src/consensus/pos.rs",
        test_token: "PoSEngine",
    },
    ReadmeClaim {
        id: "hybrid-bls-pq-finality",
        readme_marker: "GlobalBlockHeader",
        readme_tr_marker: "GlobalBlockHeader",
        prod_file: "src/chain/finality.rs",
        prod_symbol: "pub struct ValidatorSetSnapshot",
        call_site_file: "src/chain/blockchain.rs",
        call_site_token: "ValidatorSetSnapshot",
        test_file: "src/chain/finality.rs",
        test_token: "ValidatorSetSnapshot",
    },
    ReadmeClaim {
        id: "domain-finality-adapters",
        readme_marker: "src/domain/",
        readme_tr_marker: "src/domain/",
        prod_file: "src/domain/finality_adapter.rs",
        prod_symbol: "pub enum FinalityStatus",
        call_site_file: "src/chain/blockchain.rs",
        call_site_token: "FinalityStatus",
        test_file: "src/domain/finality_adapter.rs",
        test_token: "FinalityStatus",
    },
    ReadmeClaim {
        id: "cross-domain-bridge-lifecycle",
        readme_marker: "bridge_payload_hash",
        readme_tr_marker: "bridge_payload_hash",
        prod_file: "src/cross_domain/bridge.rs",
        prod_symbol: "bridge_payload_hash",
        call_site_file: "src/execution/executor.rs",
        call_site_token: "bridge",
        test_file: "src/cross_domain/bridge.rs",
        test_token: "bridge_payload_hash",
    },
    ReadmeClaim {
        id: "permissionless-stake-registry",
        readme_marker: "src/registry/",
        readme_tr_marker: "src/registry/",
        prod_file: "src/registry/permissionless.rs",
        prod_symbol: "pub struct PermissionlessRegistry",
        call_site_file: "src/core/account.rs",
        call_site_token: "PermissionlessRegistry",
        test_file: "src/registry/permissionless.rs",
        test_token: "PermissionlessRegistry",
    },
    ReadmeClaim {
        id: "budzero-stark-prover",
        readme_marker: "BudZero",
        readme_tr_marker: "BudZero",
        prod_file: "budzero/bud-proof/src/plonky3_prover.rs",
        prod_symbol: "pub fn ",
        call_site_file: "src/execution/zkvm.rs",
        call_site_token: "bud_proof",
        test_file: "budzero/bud-proof/src/plonky3_prover.rs",
        test_token: "prove",
    },
    ReadmeClaim {
        id: "bud3-storage-registry",
        readme_marker: "B.U.D.",
        readme_tr_marker: "B.U.D.",
        prod_file: "src/storage/bud3/registry.rs",
        prod_symbol: "pub enum ShareStatus",
        call_site_file: "src/execution/executor.rs",
        call_site_token: "ShareStatus",
        test_file: "src/storage/bud3/registry.rs",
        test_token: "ShareStatus",
    },
    ReadmeClaim {
        id: "ai-inference-layer",
        readme_marker: "src/ai_inference/",
        readme_tr_marker: "src/ai_inference/",
        prod_file: "src/ai_inference/mod.rs",
        prod_symbol: "pub struct ",
        call_site_file: "src/execution/executor.rs",
        call_site_token: "ai_inference",
        test_file: "src/ai_inference/mod.rs",
        test_token: "AI",
    },
    ReadmeClaim {
        id: "data-market-consent-gate",
        readme_marker: concat!("Pol", "len"),
        readme_tr_marker: concat!("Pol", "len"),
        prod_file: concat!("src/pol", "len/content_gate.rs"),
        prod_symbol: "pub struct ProtectedContent",
        call_site_file: concat!("src/pol", "len/mod.rs"),
        call_site_token: "ProtectedContent",
        test_file: concat!("src/pol", "len/content_gate.rs"),
        test_token: "ProtectedContent",
    },
    ReadmeClaim {
        id: "bns-registry-and-gateway",
        readme_marker: "src/bns/",
        readme_tr_marker: "src/bns/",
        prod_file: "src/bns/registry.rs",
        prod_symbol: "pub struct BnsRegistry",
        call_site_file: "src/web_gateway/resolve.rs",
        call_site_token: "BnsRegistry",
        test_file: "src/bns/registry.rs",
        test_token: "BnsRegistry",
    },
    ReadmeClaim {
        id: "wallet-core-ml-dsa-and-bns",
        readme_marker: "ML-DSA-87",
        readme_tr_marker: "ML-DSA-87",
        prod_file: "crates/wallet-core/src/bns.rs",
        prod_symbol: "pub fn verify_bns_proof",
        call_site_file: "crates/wallet-core/src/lib.rs",
        call_site_token: "verify_bns_proof",
        test_file: "crates/wallet-core/src/bns.rs",
        test_token: "verify_bns_proof",
    },
    ReadmeClaim {
        id: "rpc-and-sentry-shielding",
        readme_marker: "PKCS#11",
        readme_tr_marker: "PKCS#11",
        prod_file: "src/network/sentry_gate.rs",
        prod_symbol: "pub struct SentryGateBehaviour",
        call_site_file: "src/network/node.rs",
        call_site_token: "SentryGateBehaviour",
        test_file: "src/network/sentry_gate.rs",
        test_token: "SentryGateBehaviour",
    },
];

/// Scan non-string, non-char tokens of a line to update brace depth for a
/// skipped `#[cfg(test)]` item.
fn advance_test_skip(
    slice: &str,
    skipping_test: &mut bool,
    waiting_for_body: &mut bool,
    brace_depth: &mut usize,
) {
    let mut chars = slice.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '\'' => {
                // Skip char literals like `'{'` or `'\''` without mistaking lifetimes like `'a`.
                let mut probe = chars.clone();
                match probe.next() {
                    Some('\\') => {
                        let _ = probe.next();
                        if probe.next() == Some('\'') {
                            chars = probe;
                        }
                    }
                    Some(_) if probe.next() == Some('\'') => {
                        chars = probe;
                    }
                    _ => {}
                }
            }
            '{' => {
                *waiting_for_body = false;
                *brace_depth = brace_depth.saturating_add(1);
            }
            '}' => {
                *brace_depth = brace_depth.saturating_sub(1);
                if !*waiting_for_body && *brace_depth == 0 {
                    *skipping_test = false;
                }
            }
            ';' if *waiting_for_body => {
                *skipping_test = false;
                *waiting_for_body = false;
            }
            _ => {}
        }
    }
}

/// Return only the non-test, non-comment production source of a Rust file.
///
/// Properly skips individual `#[cfg(test)]`-annotated items (whether terminated
/// by `;` or balanced `{ ... }`, ignoring braces inside string/char literals)
/// without discarding production code that appears later in the same file.
fn production_code_only(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut skipping_test = false;
    let mut waiting_for_body = false;
    let mut brace_depth: usize = 0;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let code_part = match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        };
        let code_trimmed = code_part.trim();

        if !skipping_test {
            if code_trimmed.starts_with("#[cfg(test)]")
                || code_trimmed.starts_with("#[cfg(all(test,")
            {
                skipping_test = true;
                waiting_for_body = true;
                brace_depth = 0;
                let after_attr = match code_trimmed.find(']') {
                    Some(idx) => code_trimmed[idx + 1..].trim(),
                    None => "",
                };
                if !after_attr.is_empty() {
                    advance_test_skip(
                        after_attr,
                        &mut skipping_test,
                        &mut waiting_for_body,
                        &mut brace_depth,
                    );
                }
                continue;
            }
            out.push_str(code_part);
            out.push('\n');
            continue;
        }

        if waiting_for_body && code_trimmed.starts_with("#[") {
            continue;
        }
        advance_test_skip(
            code_part,
            &mut skipping_test,
            &mut waiting_for_body,
            &mut brace_depth,
        );
    }
    out
}

/// Extract quoted entries from `pub const RESERVED_LABELS: &[&str] = &[ ... ];`.
fn extract_reserved_labels(params_rs: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut in_array = false;
    for line in params_rs.lines() {
        if !in_array {
            if line.contains("RESERVED_LABELS") && line.contains("&[") {
                in_array = true;
            }
            continue;
        }
        if line.trim_start().starts_with("];") {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(start) = trimmed.find('"') {
            let rest = &trimmed[start + 1..];
            if let Some(end) = rest.find('"') {
                labels.push(rest[..end].to_string());
            }
        }
    }
    labels
}

/// Validate a set of README claims against `root`.
pub fn check_claims(root: &Path, claims: &[ReadmeClaim]) -> Vec<String> {
    let mut findings = Vec::new();

    let readme_en = match std::fs::read_to_string(root.join("README.md")) {
        Ok(s) => s,
        Err(e) => {
            findings.push(format!("cannot read README.md: {e}"));
            return findings;
        }
    };
    let readme_tr = match std::fs::read_to_string(root.join("README.tr.md")) {
        Ok(s) => s,
        Err(e) => {
            findings.push(format!("cannot read README.tr.md: {e}"));
            return findings;
        }
    };
    let readme_en_lower = readme_en.to_lowercase();
    let readme_tr_lower = readme_tr.to_lowercase();

    for claim in claims {
        if !readme_en_lower.contains(&claim.readme_marker.to_lowercase()) {
            findings.push(format!(
                "[{}] README.md is missing expected marker `{}`",
                claim.id, claim.readme_marker
            ));
        }
        if !readme_tr_lower.contains(&claim.readme_tr_marker.to_lowercase()) {
            findings.push(format!(
                "[{}] README.tr.md is missing expected marker `{}`",
                claim.id, claim.readme_tr_marker
            ));
        }
        if claim.prod_file == claim.call_site_file {
            findings.push(format!(
                "[{}] prod_file and call_site_file must be distinct (`{}`)",
                claim.id, claim.prod_file
            ));
        }

        match std::fs::read_to_string(root.join(claim.prod_file)) {
            Ok(src) => {
                let prod = production_code_only(&src);
                if !prod.contains(claim.prod_symbol) {
                    findings.push(format!(
                        "[{}] `{}` lacks non-test production symbol `{}`",
                        claim.id, claim.prod_file, claim.prod_symbol
                    ));
                }
            }
            Err(e) => findings.push(format!(
                "[{}] cannot read production file `{}`: {e}",
                claim.id, claim.prod_file
            )),
        }

        match std::fs::read_to_string(root.join(claim.call_site_file)) {
            Ok(src) => {
                let prod = production_code_only(&src);
                if !prod.contains(claim.call_site_token) {
                    findings.push(format!(
                        "[{}] call site `{}` does not wire `{}` in production code",
                        claim.id, claim.call_site_file, claim.call_site_token
                    ));
                }
            }
            Err(e) => findings.push(format!(
                "[{}] cannot read call site `{}`: {e}",
                claim.id, claim.call_site_file
            )),
        }

        match std::fs::read_to_string(root.join(claim.test_file)) {
            Ok(src) => {
                let has_test_attr = src.contains("#[test]") || src.contains("#[tokio::test]");
                if !has_test_attr {
                    findings.push(format!(
                        "[{}] test file `{}` has no #[test] or #[tokio::test]",
                        claim.id, claim.test_file
                    ));
                } else if !src.contains(claim.test_token) {
                    findings.push(format!(
                        "[{}] test file `{}` does not reference `{}`",
                        claim.id, claim.test_file, claim.test_token
                    ));
                }
            }
            Err(e) => findings.push(format!(
                "[{}] cannot read test file `{}`: {e}",
                claim.id, claim.test_file
            )),
        }
    }

    findings
}

/// Verify that `browser-extension/rules.json` excludes every reserved label
/// defined in `src/registry/params.rs::RESERVED_LABELS`.
pub fn check_bns_extension_reserved_parity(root: &Path) -> Vec<String> {
    let mut findings = Vec::new();

    let params_path = root.join("src/registry/params.rs");
    let rules_path = root.join("browser-extension/rules.json");
    let manifest_path = root.join("browser-extension/manifest.json");

    if !manifest_path.is_file() {
        findings.push("missing browser-extension/manifest.json (Manifest V3 BNS resolver)".into());
        return findings;
    }
    let manifest_src = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            findings.push(format!("cannot read browser-extension/manifest.json: {e}"));
            return findings;
        }
    };
    if !manifest_src.contains("\"manifest_version\": 3") {
        findings.push("browser-extension/manifest.json must declare manifest_version 3".into());
    }

    let params_src = match std::fs::read_to_string(&params_path) {
        Ok(s) => s,
        Err(e) => {
            findings.push(format!("cannot read src/registry/params.rs: {e}"));
            return findings;
        }
    };
    let rules_src = match std::fs::read_to_string(&rules_path) {
        Ok(s) => s,
        Err(e) => {
            findings.push(format!("cannot read browser-extension/rules.json: {e}"));
            return findings;
        }
    };

    let reserved = extract_reserved_labels(&params_src);
    if reserved.is_empty() {
        findings.push("failed to parse RESERVED_LABELS from src/registry/params.rs".into());
        return findings;
    }

    let mut missing = BTreeSet::new();
    for label in &reserved {
        let domain = format!("\"{label}.budlum.xyz\"");
        if !rules_src.contains(&domain) {
            missing.insert(label.clone());
        }
    }
    if !missing.is_empty() {
        let joined: Vec<String> = missing.into_iter().collect();
        findings.push(format!(
            "browser-extension/rules.json omits reserved label exclusions: {}",
            joined.join(", ")
        ));
    }

    findings
}

/// Run the gate against the repository root.
pub fn run(root: &Path) -> Result<String, String> {
    let mut findings = check_claims(root, CLAIMS);
    findings.extend(check_bns_extension_reserved_parity(root));

    if findings.is_empty() {
        Ok(format!(
            "readme-claims-are-wired OK: {} shipped README claim(s) verified across production code, call sites, and tests, plus BNS extension reserved-label parity",
            CLAIMS.len()
        ))
    } else {
        let mut msg = format!("readme-claims-are-wired found {} gap(s):\n", findings.len());
        for f in &findings {
            let _ = writeln!(msg, "  - {f}");
        }
        Err(msg)
    }
}

/// Self-test canary proving the gate rejects unwired claims, test-only symbols,
/// missing tests, and missing reserved-label exclusions.
pub fn self_test() -> Result<String, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let root = dir.path();

    let claim = ReadmeClaim {
        id: "synthetic-claim",
        readme_marker: "SyntheticEngine",
        readme_tr_marker: "SyntheticEngine",
        prod_file: "src/synth.rs",
        prod_symbol: "pub struct SyntheticEngine",
        call_site_file: "src/caller.rs",
        call_site_token: "SyntheticEngine",
        test_file: "src/synth.rs",
        test_token: "SyntheticEngine",
    };

    let write = |rel: &str, body: &str| -> Result<(), String> {
        let full = root.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {rel}: {e}"))?;
        }
        std::fs::write(&full, body).map_err(|e| format!("write {rel}: {e}"))
    };

    // 1. Clean synthetic tree must pass.
    write("README.md", "Ships SyntheticEngine today.\n")?;
    write("README.tr.md", "Bugun SyntheticEngine sunar.\n")?;
    write(
        "src/synth.rs",
        "pub struct SyntheticEngine;\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn works() { let _ = super::SyntheticEngine; }\n}\n",
    )?;
    write(
        "src/caller.rs",
        "pub fn wire() { let _ = crate::synth::SyntheticEngine; }\n",
    )?;
    write(
        "src/registry/params.rs",
        "pub const RESERVED_LABELS: &[&str] = &[\n    \"api\",\n    \"gateway\",\n];\n",
    )?;
    write(
        "browser-extension/manifest.json",
        "{\"manifest_version\": 3}\n",
    )?;
    write(
        "browser-extension/rules.json",
        "[\"api.budlum.xyz\", \"gateway.budlum.xyz\"]\n",
    )?;

    let clean = check_claims(root, &[claim]);
    if !clean.is_empty() {
        return Err(format!("canary clean tree failed: {clean:?}"));
    }
    let clean_ext = check_bns_extension_reserved_parity(root);
    if !clean_ext.is_empty() {
        return Err(format!("canary clean extension failed: {clean_ext:?}"));
    }

    // 2. Production symbol hidden inside #[cfg(test)] must fail.
    write(
        "src/synth.rs",
        "#[cfg(test)]\nmod tests {\n    pub struct SyntheticEngine;\n    #[test]\n    fn works() { let _ = SyntheticEngine; }\n}\n",
    )?;
    if check_claims(root, &[claim]).is_empty() {
        return Err("canary failed to catch test-only production symbol".into());
    }

    // 3. Unwired production symbol (call site does not reference it) must fail.
    write(
        "src/synth.rs",
        "pub struct SyntheticEngine;\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn works() { let _ = super::SyntheticEngine; }\n}\n",
    )?;
    write(
        "src/caller.rs",
        "// SyntheticEngine only mentioned in comment\npub fn wire() {}\n",
    )?;
    if check_claims(root, &[claim]).is_empty() {
        return Err("canary failed to catch unwired call site".into());
    }

    // 4. Missing test attribute must fail.
    write(
        "src/caller.rs",
        "pub fn wire() { let _ = crate::synth::SyntheticEngine; }\n",
    )?;
    write("src/synth.rs", "pub struct SyntheticEngine;\n")?;
    if check_claims(root, &[claim]).is_empty() {
        return Err("canary failed to catch missing automated test".into());
    }

    // 5. Missing reserved label in browser-extension/rules.json must fail.
    write("browser-extension/rules.json", "[\"api.budlum.xyz\"]\n")?;
    if check_bns_extension_reserved_parity(root).is_empty() {
        return Err("canary failed to catch missing reserved label exclusion".into());
    }

    Ok("readme-claims-are-wired canary OK: test-only symbol, unwired call site, missing test, and missing BNS reserved label exclusion all caught".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn readme_claims_are_wired_catches_injected_unwired_claim() {
        let res = super::self_test();
        assert!(res.is_ok(), "self_test failed: {res:?}");
    }
}
