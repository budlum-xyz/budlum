//! `bud3_custody_proofs`: the custody proof path verifies against the stored
//! symbol root, and nothing accepts a proof on the holder's word.
//!
//! §6.11.2 and WP-20 items 5-6. A custody proof is the only thing standing
//! between "this validator says it holds the bytes" and "this validator holds
//! the bytes". The failure modes are specific and each has a place in the code
//! where it would appear:
//!
//!   * **the proof is not checked at all** - `submit_proofs` stores what it is
//!     given and marks a pass;
//!   * **the proof is checked against a root the holder supplied** - the
//!     attacker supplies both the symbol and the root and the check is circular;
//!   * **a bad proof in a batch leaves the good ones applied** - a holder
//!     answers some audits, gets caught on one, and the batch is still counted;
//!   * **a proof outside its window is accepted** - a holder replays last
//!     epoch's proof forever;
//!   * **the audit draw is not the registry's** - two nodes draw different
//!     challenges from the same seed, and every audit fails on half of them.
//!
//! The gate asserts the shape of the verification in `registry.rs` and
//! `custody.rs`: the calls that have to be there, and the absence of the
//! shortcuts that would make a proof meaningless.

use std::fmt::Write as _;
use std::path::Path;

/// A call that must exist in the custody path.
struct Required {
    file: &'static str,
    call: &'static str,
    why: &'static str,
}

/// The calls the verification depends on.
const REQUIRED: &[Required] = &[
    Required {
        file: "src/storage/bud3/custody.rs",
        call: "pub fn verify(",
        why: "the proof has no verifier, so `submit_proofs` can only trust it",
    },
    Required {
        file: "src/storage/bud3/custody.rs",
        call: "pub fn prove(",
        why: "holders have no way to produce the proof the verifier checks",
    },
    Required {
        file: "src/storage/bud3/custody.rs",
        call: "pub fn symbol_root(",
        why: "the root the proof is checked against would have no definition",
    },
    Required {
        file: "src/storage/bud3/custody.rs",
        call: "pub fn audit_for(",
        why: "the challenge is not derived from the seed, so two nodes draw \
              different audits",
    },
    Required {
        file: "src/storage/bud3/registry.rs",
        call: "proof\n                .verify(&audit, &ctx)",
        why: "`submit_proofs` does not verify the proof it is given",
    },
    Required {
        file: "src/storage/bud3/registry.rs",
        call: "let root = obj.roots.get(share.root).ok_or(RegistryError::BadProof)?;",
        why: "the verification context would come from somewhere other than the \
              stored symbol root - a root the holder supplies makes the check circular",
    },
    Required {
        file: "src/storage/bud3/registry.rs",
        call: "if hits.contains(&(*key, idx)) {",
        why: "one proof could be counted twice in a batch",
    },
    Required {
        file: "src/storage/bud3/registry.rs",
        call: "consecutive_misses = 0;",
        why: "a pass would not clear the loss counter, so a holder that missed \
              twice and then answered would still lose the share",
    },
    Required {
        file: "src/storage/bud3/registry.rs",
        call: "s.open_audit.is_some_and(|(_, last)| last < epoch)",
        why: "an audit window would never close and a missed audit would never be \
              recorded",
    },
];

/// A shortcut whose presence means the check is not real.
struct Forbidden {
    file: &'static str,
    text: &'static str,
    why: &'static str,
}

/// The shortcuts.
const FORBIDDEN: &[Forbidden] = &[
    Forbidden {
        file: "src/storage/bud3/registry.rs",
        text: "symbol_root: proof.symbol_root",
        why: "the verification context is taken from the proof itself",
    },
    Forbidden {
        file: "src/storage/bud3/custody.rs",
        text: "// TODO",
        why: "a verifier with a TODO is a verifier that does not verify everything",
    },
];

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The verification as it has to be shaped.
fn check(root: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for required in REQUIRED {
        match read(root, required.file) {
            Err(_) => found.push(format!(
                "  {}: {} is missing entirely -- {}",
                required.file, required.call, required.why
            )),
            Ok(text) => {
                if !text.contains(required.call) {
                    found.push(format!(
                        "  {}: `{}` is gone -- {}",
                        required.file,
                        required.call.replace('\n', " ").trim(),
                        required.why
                    ));
                }
            }
        }
    }
    for forbidden in FORBIDDEN {
        if let Ok(text) = read(root, forbidden.file) {
            if text.contains(forbidden.text) {
                found.push(format!(
                    "  {}: carries `{}` -- {}",
                    forbidden.file, forbidden.text, forbidden.why
                ));
            }
        }
    }
    Ok(found)
}

/// Run the gate.
///
/// # Errors
///
/// The findings, one per line.
pub fn run(root: &Path) -> Result<String, String> {
    let found = check(root)?;
    if found.is_empty() {
        return Ok(format!(
            "bud3 custody proofs OK: {} verification call(s) present, no shortcut",
            REQUIRED.len()
        ));
    }
    let mut out = String::new();
    for line in &found {
        let _ = writeln!(out, "{line}");
    }
    Err(format!(
        "FAIL: the B.U.D. 3.0 custody proof path (§6.11.2) is not verification:\n{out}  \
         A custody proof that is not checked against the stored symbol root proves \
         nothing, and the audit rewards it earns are paid for storage nobody holds."
    ))
}

/// The canary: a removed verifier, a circular root and a TODO each fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-custody")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        let body = |skip: Option<&str>| -> String {
            let mut text = String::new();
            for r in REQUIRED {
                if Some(r.call) != skip {
                    text.push_str(r.call);
                    text.push('\n');
                }
            }
            text
        };
        for file in ["src/storage/bud3/custody.rs", "src/storage/bud3/registry.rs"] {
            let mut text = String::new();
            for r in REQUIRED.iter().filter(|r| r.file == file) {
                text.push_str(r.call);
                text.push('\n');
            }
            put(file, &text)?;
        }
        run(&dir).map_err(|e| format!("canary: a correct custody path failed: {e}"))?;

        // A removed verifier.
        put(
            "src/storage/bud3/custody.rs",
            &body(Some("pub fn verify(")),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a missing verifier passed"));
        }
        // A circular root.
        put(
            "src/storage/bud3/custody.rs",
            &body(None).replace("pub fn verify(", "pub fn verify("),
        )?;
        let mut registry = body(None);
        registry.push_str("symbol_root: proof.symbol_root\n");
        put("src/storage/bud3/registry.rs", &registry)?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a proof-supplied symbol root passed",
            ));
        }
        // A TODO in the verifier.
        let mut custody = body(None);
        custody.push_str("// TODO\n");
        put("src/storage/bud3/custody.rs", &custody)?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a TODO in the verifier passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-custody-proofs canary OK: a missing verifier, a circular root \
         and a TODO each failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_custody_proofs_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }

    #[test]
    fn the_tree_verifies() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the gate crate lives two levels below the root");
        assert!(super::run(root).is_ok(), "{:?}", super::run(root));
    }
}
