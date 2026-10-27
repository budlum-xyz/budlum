//! Every ML-DSA and SLH-DSA signature and verification carries a context.
//!
//! FIPS 204 and FIPS 205 fold a context string into the signed message. The
//! gives every signing surface its own string (`src/crypto/ctx.rs`),
//! so a signature made for one surface does not verify on another even when
//! the payload bytes are equal. That only works if no call site passes an empty
//! context, and none invents a string outside the registry.
//!
//! This gate reads production Rust under `src/` and `crates/wallet-core` and
//! fails on two things:
//!
//! * a call to a context-taking function whose context argument is an empty
//!   literal (`b""`, `&[]`, `""`, `Vec::new()`) or any literal at all: the
//!   argument must name a constant of the registry, or a variable that holds
//!   one;
//! * a call to a signing or verification primitive of the libraries
//!   (`verify_with_context`, `sign_randomized`, `sign_deterministic`,
//!   `try_sign_with_context`, `try_verify_with_context`, `sign_internal`)
//!   outside the facade `src/crypto/pq.rs`, where the context rule is enforced
//!   once.
//!
//! Test code is out of scope: tests pass a context to prove what the facade
//! refuses.

use std::fmt::Write as _;
use std::path::Path;

/// Roots holding shipped code.
const SCAN_ROOTS: &[&str] = &["src", "crates/wallet-core/src"];

/// The one file allowed to call the library primitives.
const FACADE: &str = "src/crypto/pq.rs";

/// The mounted copies of the facade in the wallet are the same file.
const MOUNT_FILE: &str = "crates/wallet-core/src/crypto.rs";

/// `(callee, index of the context argument)`.
const CTX_CALLS: &[(&str, usize)] = &[
    ("verify_ml_dsa_87_signature(", 0),
    ("PqKeyPair::verify(", 1),
    ("pq::verify(", 3),
    ("pq::verify_in(", 4),
    ("pq::ml_dsa_sign(", 3),
    ("pq::slh_dsa_sign(", 3),
    ("pq::verify_ml_dsa_single(", 4),
    ("composite::verify(", 1),
    ("composite::verify_in(", 2),
    ("message_representative(", 1),
    (".sign_in(", 1),
    (".sign_for(", 0),
    ("Wallet::verify_for(", 1),
];

/// Library primitives that must stay behind the facade.
const LIBRARY_PRIMITIVES: &[&str] = &[
    ".verify_with_context(",
    ".sign_randomized(",
    ".sign_deterministic(",
    ".try_sign_with_context(",
    ".try_verify_with_context(",
    ".sign_internal(",
];

/// Whether an argument is a literal rather than a name.
fn is_literal(arg: &str) -> bool {
    let a = arg.trim();
    a.starts_with("b\"")
        || a.starts_with('"')
        || a.starts_with("&b\"")
        || a.starts_with("&[")
        || a.starts_with("Vec::new()")
        || a.starts_with("&Vec::new()")
        || a.starts_with("&[]")
}

/// The findings of one source text, as `line: reason`.
#[must_use]
pub fn findings_of(rel: &str, text: &str) -> Vec<String> {
    let clean = super::pq_scan::blank_comments(text);
    let mut out = Vec::new();
    for (callee, ctx_index) in CTX_CALLS {
        for at in super::pq_scan::find_all(&clean, callee) {
            // The callee must start at a token boundary: `x.pq::verify(` is fine,
            // `my_pq::verify(` is another function.
            let before = clean.get(..at).and_then(|s| s.chars().next_back());
            if !callee.starts_with('.')
                && before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let Some(args) = super::pq_scan::call_args(&clean, at) else {
                continue;
            };
            if let Some(arg) = args.get(*ctx_index) {
                if is_literal(arg) {
                    out.push(format!(
                        "{}: `{}` is given the literal context `{arg}`; pass a constant of crypto::ctx",
                        super::pq_scan::line_of(&clean, at),
                        callee.trim_end_matches('(')
                    ));
                }
            }
        }
    }
    if rel != FACADE && rel != MOUNT_FILE {
        for primitive in LIBRARY_PRIMITIVES {
            for at in super::pq_scan::find_all(&clean, primitive) {
                out.push(format!(
                    "{}: `{}` is a library primitive; sign and verify through crypto::pq",
                    super::pq_scan::line_of(&clean, at),
                    primitive.trim_matches(|c| c == '.' || c == '(')
                ));
            }
        }
    }
    out
}

/// Run the gate.
///
/// # Errors
///
/// Any empty or literal context, or a library primitive outside the facade.
pub fn run(root: &Path) -> Result<String, String> {
    let files = super::pq_scan::rust_files(root, SCAN_ROOTS);
    if files.len() < 100 {
        return Err(format!(
            "only {} source files found under the scan roots; the gate would be vacuous",
            files.len()
        ));
    }
    let mut report = String::new();
    let mut count = 0usize;
    for (rel, path) in &files {
        let Some(text) = super::pq_scan::production_text(path) else {
            continue;
        };
        for finding in findings_of(rel, &text) {
            count += 1;
            let _ = writeln!(report, "  {rel}:{finding}");
        }
    }
    if count == 0 {
        Ok(format!(
            "Every PQ call is bound to a context: {} files scanned.",
            files.len()
        ))
    } else {
        Err(format!(
            "{count} PQ call(s) lack a bound context:\n{report}\n  Use a constant from \
             src/crypto/ctx.rs and call through crypto::pq."
        ))
    }
}

/// Canaries.
///
/// # Errors
///
/// A canary that does not behave as stated.
pub fn self_test() -> Result<String, String> {
    let bad = [
        "fn f() { verify_ml_dsa_87_signature(b\"\", &m, &s, &k) }",
        "fn f() { pq::verify(scheme, &pk, &msg, &[], &sig) }",
        "fn f() { PqKeyPair::verify(&pk, \"\", &m, &s) }",
        "fn f() { kp.sign_for(b\"tx\", &m) }",
        "fn f() { vk.verify_with_context(&m, ctx, &s) }",
        "fn f() { sk.sign_randomized(&m, ctx, &mut rng) }",
    ];
    for source in bad {
        if findings_of("src/x.rs", source).is_empty() {
            return Err(format!("a bad call was missed: {source:?}"));
        }
    }
    let good = [
        "fn f() { verify_ml_dsa_87_signature(crate::crypto::ctx::TX_V5, &m, &s, &k) }",
        "fn f() { pq::verify(scheme, &pk, &msg, ctx, &sig) }",
        "fn f() { PqKeyPair::verify(&pk, ctx::QC_V2, &m, &s) }",
        "fn f() { kp.sign_for(ctx, &m) }",
        "// pq::verify(a, b, c, b\"\", e)\nfn f() {}",
        "fn f() { my_pq::verify(a, b, c, b\"\", e) }",
    ];
    for source in good {
        let found = findings_of("src/x.rs", source);
        if !found.is_empty() {
            return Err(format!("a clean call was flagged: {source:?} -> {found:?}"));
        }
    }
    if findings_of(FACADE, "fn f() { vk.verify_with_context(&m, ctx, &s) }")
        .iter()
        .any(|f| f.contains("library primitive"))
    {
        return Err(String::from("the facade itself was flagged"));
    }
    Ok(String::from(
        "canary OK: empty and literal contexts and library primitives are caught outside the facade.",
    ))
}
