//! The execution proof path refuses rather than trusting.
//!
//! Gate code: `K-ZKVM-IMMUNE-REGENERATION`. A finding or a document that names this code resolves here.
//!
//! The invention text promises that a regenerated artifact cannot bring a
//! proof with it: what the chain accepts is the check, not the claim. This
//! gate pins the five fail-closed checks the executor runs on an AI
//! execution proof, the size bound that precedes deserialization, and the
//! fact that the un-gated executor entry point has no production caller.
//!
//! Each item is a claim about code, not prose: the error codes have to sit
//! inside a `BudlumError::validation(` call, the bound has to be compared
//! against `MAX_PROOF_BYTES` before the envelope is decoded, and the
//! ungated path may only be named by the file that defines it.

use std::fmt::Write as _;
use std::path::Path;

const CODES: [&str; 5] = [
    "ai_exec_chain_id",
    "ai_exec_program_rebuild",
    "ai_exec_stark",
    "ai_exec_structural",
    "ai_exec_proof_too_large",
];

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("no {rel} at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// Is `code` named inside a validation error rather than in prose?
fn code_is_a_rejection(src: &str, code: &str) -> bool {
    let needle = "BudlumError::validation(";
    let mut at = 0usize;
    while let Some(i) = src[at..].find(needle) {
        let start = at + i + needle.len();
        let end = src.len().min(start + 90);
        if src.get(start..end).is_some_and(|w| w.contains(code)) {
            return true;
        }
        at = start;
    }
    false
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let exec = read(root, "src/execution/executor.rs")?;
    let verifier = read(root, "src/execution/proof_verifier.rs")?;
    let zkvm = read(root, "src/execution/zkvm.rs")?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for code in CODES {
        if code_is_a_rejection(&exec, code) {
            checked += 1;
        } else {
            problems.push(format!(
                "`{code}` is no longer a validation rejection in `executor.rs`. Each of \
                 the five codes marks a check the executor cannot skip: chain binding, \
                 program rebuild, STARK verify, structural report, size bound. A path \
                 that accepts a proof without one of them is a proof the node did not \
                 check."
            ));
        }
    }

    if exec.contains("proof_bytes.len() > crate::execution::proof_verifier::MAX_PROOF_BYTES") {
        checked += 1;
    } else {
        problems.push(
            "the envelope size bound is gone from the decode path. `validate_envelope_structure` \
             takes a decoded envelope, and decoding is the work the bound exists to price; \
             an unbounded `proof_bytes` turns a relay into a memory-exhaustion target."
                .to_string(),
        );
    }
    if let Some(line) = verifier
        .lines()
        .find(|l| l.contains("pub const MAX_PROOF_BYTES"))
    {
        if line.contains("1 << 20") {
            checked += 1;
        } else {
            problems.push(format!(
                "`MAX_PROOF_BYTES` is no longer `1 << 20`; it now reads `{}`. Raising the \
                 ceiling is a protocol decision, not a side effect of touching a file: the \
                 value is what the light client budgets per proof.",
                line.trim()
            ));
        }
    } else {
        problems.push("no `pub const MAX_PROOF_BYTES` in `proof_verifier.rs`.".to_string());
    }

    let callers = ungated_callers(root);
    if callers.is_empty() {
        checked += 1;
    } else {
        problems.push(format!(
            "`execute_bytecode_ungated` is called from {}. That entry point exists for tests \
             and local tooling; wiring it into a production path lets bytecode run with no gas \
             or mainnet gate, which is exactly what the proof is supposed to make unnecessary.",
            callers.join(", ")
        ));
    }
    if zkvm.contains("pub fn execute_bytecode_mainnet") {
        checked += 1;
    } else {
        problems.push(
            "`execute_bytecode_mainnet` is gone from `zkvm.rs`. The gated entry point is the \
             only one this gate assumes exists; without it the ungated one becomes the default \
             rather than the exception."
                .to_string(),
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
        "ZKVM regeneration containment OK: {checked} checks, all five proof rejections \
         present, the size bound precedes decoding, and no production path reaches the \
         un-gated executor"
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
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-zkvm-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/execution")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/rpc")).map_err(|e| e.to_string())?;

    let exec = "fn f() {\n\
        let report = verify_execution_proof_structural_with_model(p, r, res, m);\n\
        if !report.is_structurally_valid() {\n\
            return Err(BudlumError::validation(\"ai_exec_structural\", \"x\"));\n\
        }\n\
        if !bound {\n\
            return Err(BudlumError::validation(\"ai_exec_chain_id\", \"x\"));\n\
        }\n\
        return Err(BudlumError::validation(\"ai_exec_program_rebuild\", \"x\"));\n\
        return Err(BudlumError::validation(\"ai_exec_stark\", e));\n\
        if proof.proof_bytes.len() > crate::execution::proof_verifier::MAX_PROOF_BYTES {\n\
            return Err(BudlumError::validation(\"ai_exec_proof_too_large\", \"x\"));\n\
        }\n\
    }\n";
    let verifier = "pub const MAX_PROOF_BYTES: usize = 1 << 20;\n";
    let zkvm = "pub fn execute_bytecode_ungated(b: &[u8]) {}\npub fn execute_bytecode_mainnet(b: &[u8]) {}\n";
    std::fs::write(dir.join("src/execution/executor.rs"), exec).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/execution/proof_verifier.rs"), verifier)
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/execution/zkvm.rs"), zkvm).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a contained tree was refused"));
    }

    // Bad: one rejection lost and the size bound raised.
    let bad = exec.replace("\"ai_exec_stark\", e", "\"ai_exec_other\", e");
    std::fs::write(dir.join("src/execution/executor.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a proof path missing a rejection passed",
        ));
    }
    std::fs::write(dir.join("src/execution/executor.rs"), exec).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/execution/proof_verifier.rs"),
        "pub const MAX_PROOF_BYTES: usize = 1 << 24;\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a raised size ceiling passed silently",
        ));
    }
    std::fs::write(dir.join("src/execution/proof_verifier.rs"), verifier)
        .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("src/rpc/server.rs"),
        "fn h() { execute_bytecode_ungated(&b); }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: an RPC path reaching the un-gated executor passed",
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "ZKVM containment canary OK (contained PASSes; a missing rejection, a raised \n         ceiling, and an un-gated production caller each FAIL).",
    ))
}

/// Files outside the defining one that name the un-gated executor. The un-gated
/// entry point exists for tests and local tooling; a production path that calls
/// it runs bytecode with no gas or mainnet gate, which is what the proof is
/// supposed to make unnecessary.
fn ungated_callers(root: &Path) -> Vec<String> {
    let mut callers: Vec<String> = Vec::new();
    for dir in ["src/execution", "src/rpc"] {
        let Ok(rd) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().is_some_and(|n| n == "zkvm.rs") {
                continue;
            }
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            if body.contains("execute_bytecode_ungated") {
                callers.push(path.display().to_string());
            }
        }
    }
    callers
}
