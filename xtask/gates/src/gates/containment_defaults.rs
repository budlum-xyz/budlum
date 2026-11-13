//! Containment defaults check for `budzero`.
//!
//! `MainnetActivation` in `bud-isa` now enables both AIR-backed `VerifyMerkle`
//! (64-depth 30-round Poseidon path verification) and `VerifyInference`
//! (30-round Poseidon inference commitment digest) under
//! `MainnetActivation::default()`, while `bud-vm` decodes against
//! `MainnetActivation::default()` and `src/execution/zkvm.rs` keeps mainnet
//! execution mode enabled.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

fn strip_line_comments(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(at) => &l[..at],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Check `isa_code`, `vm_code`, `zkvm_code` for active containment defaults.
pub fn check(isa_code: &str, vm_code: &str, zkvm_code: &str) -> Result<String, String> {
    let default_start = isa_code.find("impl Default for MainnetActivation");
    let Some(start) = default_start else {
        return Err(String::from(
            "MainnetActivation no longer has a Default impl - the canonical activation defaults are the containment boundary",
        ));
    };
    let tail = &isa_code[start..];
    let body_end = tail.find("\nimpl ").unwrap_or(tail.len());
    let default_body = &tail[..body_end];

    let mut missing = Vec::new();
    for flag in ["verify_merkle_enabled", "verify_inference_enabled"] {
        let on = format!("{flag}: true");
        let off = format!("{flag}: false");
        if !default_body.contains(&on) {
            missing.push(format!(
                "MainnetActivation::default() must enable {flag} (AIR-backed verification is active)."
            ));
        }
        if default_body.contains(&off) {
            missing.push(format!(
                "MainnetActivation::default() disables {flag} somewhere in the impl."
            ));
        }
    }

    if !vm_code.contains("MainnetActivation::default()") {
        missing.push(String::from(
            "bud-vm no longer decodes against MainnetActivation::default().",
        ));
    }
    if vm_code.contains("MainnetActivation::full()") {
        missing.push(String::from(
            "bud-vm decodes against MainnetActivation::full() instead of MainnetActivation::default().",
        ));
    }
    if zkvm_code.contains("with_mainnet_mode(") && zkvm_code.contains("false)") {
        // Test helpers may construct non-mainnet VMs, so check production path.
        if let Some(exec_idx) = zkvm_code.find("pub fn execute_bytecode_mainnet") {
            let fn_slice = &zkvm_code[exec_idx..zkvm_code.len().min(exec_idx + 1200)];
            if !fn_slice.contains("with_mainnet_mode") || fn_slice.contains("false") {
                missing.push(String::from(
                    "execute_bytecode_mainnet does not invoke Vm::with_mainnet_mode(..., true).",
                ));
            }
        }
    }

    if !missing.is_empty() {
        let mut msg = String::new();
        for m in &missing {
            let _ = writeln!(msg, "  - {m}");
        }
        return Err(format!("Containment default check failed:\n{msg}"));
    }

    Ok(String::from(
        "OK: MainnetActivation::default() enables VerifyMerkle & VerifyInference, and bud-vm reads default().",
    ))
}

/// # Errors
///
/// Missing source files or a regression in `MainnetActivation` / `bud-vm` decode defaults.
pub fn run(root: &Path) -> Result<String, String> {
    let isa_path = root.join("budzero/bud-isa/src/lib.rs");
    let vm_path = root.join("budzero/bud-vm/src/lib.rs");
    let zkvm_path = root.join("src/execution/zkvm.rs");

    let isa_code = strip_line_comments(
        &fs::read_to_string(&isa_path).map_err(|e| format!("{}: {e}", isa_path.display()))?,
    );
    let vm_code = strip_line_comments(
        &fs::read_to_string(&vm_path).map_err(|e| format!("{}: {e}", vm_path.display()))?,
    );
    let zkvm_code = strip_line_comments(
        &fs::read_to_string(&zkvm_path).map_err(|e| format!("{}: {e}", zkvm_path.display()))?,
    );

    check(&isa_code, &vm_code, &zkvm_code)
}

/// In-memory self-test verifying pass and fail-closed rejection cases.
///
/// # Errors
///
/// Returns an error if the canary check stops distinguishing valid defaults from closed/mismatched ones.
pub fn self_test() -> Result<String, String> {
    let good_isa = "pub struct MainnetActivation {}\nimpl Default for MainnetActivation {\n    fn default() -> Self {\n        Self {\n            verify_merkle_enabled: true,\n            verify_inference_enabled: true,\n        }\n    }\n}\n";
    let good_vm = "fn decode() { MainnetActivation::default(); }\n";
    let good_zkvm =
        "pub fn execute_bytecode_mainnet() { Vm::with_mainnet_mode(1024, 100, true); }\n";
    if check(good_isa, good_vm, good_zkvm).is_err() {
        return Err(String::from("canary: active default fixture failed"));
    }

    let closed_isa = "pub struct MainnetActivation {}\nimpl Default for MainnetActivation {\n    fn default() -> Self {\n        Self {\n            verify_merkle_enabled: false,\n            verify_inference_enabled: true,\n        }\n    }\n}\n";
    if check(closed_isa, good_vm, good_zkvm).is_ok() {
        return Err(String::from("canary: closed VerifyMerkle flag passed"));
    }

    let full_vm = "fn decode() { MainnetActivation::full(); }\n";
    if check(good_isa, full_vm, good_zkvm).is_ok() {
        return Err(String::from(
            "canary: MainnetActivation::full() call passed",
        ));
    }

    Ok(String::from(
        "canary OK: active defaults -> PASS, closed/full override -> FAIL.",
    ))
}
