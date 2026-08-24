//! Staged-rollout defaults are the containment boundary.
//!
//! Ported from `scripts/check-containment-defaults.sh`. `MainnetActivation`
//! must default `verify_merkle_enabled` and `verify_inference_enabled` to
//! `false`, the VM must decode against `MainnetActivation::default()` (never
//! `full()`), and the execution layer must consult the activated feature
//! flags rather than hard-coded behavior.

use std::path::Path;

fn code_of(path: &Path) -> Result<String, String> {
    if !path.is_file() {
        return Err(format!("expected source file missing: {}", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n"))
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let isa = root.join("budzero/bud-isa/src/lib.rs");
    let vm = root.join("budzero/bud-vm/src/lib.rs");
    let exec = root.join("src/execution/zkvm.rs");
    let isa_code = code_of(&isa)?;
    let vm_code = code_of(&vm)?;
    let exec_code = code_of(&exec)?;

    // 1. Default impl exists and closes both flags.
    let default_start = isa_code.find("impl Default for MainnetActivation");
    let default_block = default_start.map(|s| {
        let rest = &isa_code[s..];
        let end = rest.find('}').unwrap_or(rest.len());
        &rest[..=end]
    });
    let Some(default_block) = default_block else {
        return Err(String::from(
            "MainnetActivation no longer has a Default impl - the staged-rollout defaults are the containment boundary",
        ));
    };
    for flag in ["verify_merkle_enabled", "verify_inference_enabled"] {
        if !default_block
            .lines()
            .any(|l| l.trim().starts_with(&format!("{flag}:")) && l.trim().contains("false"))
        {
            return Err(format!(
                "MainnetActivation::default() no longer closes {flag}.\n  \
                 VerifyMerkle is gated because its path verification is unfinished;\n  \
                 VerifyInference because there is no verification circuit behind it and it\n  \
                 returns a hard-coded zero. Opening either is a consensus-visible decision\n  \
                 that belongs in the commit that makes it, with the verification to match."
            ));
        }
    }

    // 2. The VM decodes against default(), not full().
    if !vm_code.contains("MainnetActivation::default()") {
        return Err(String::from(
            "bud-vm no longer decodes against MainnetActivation::default().\n  Whatever it uses instead is what the gate actually is.",
        ));
    }
    if vm_code.contains("MainnetActivation::full()") {
        return Err(String::from(
            "bud-vm decodes against MainnetActivation::full(), which sets every\n  \
             staged-rollout flag true and makes default() dead code. This is the exact\n  \
             state the gate was in when VerifyMerkle and VerifyInference were both open\n  \
             on mainnet.",
        ));
    }

    // 3. The execution layer consults the activated flags.
    if !exec_code.contains("verify_merkle_enabled") && !exec_code.contains("merkle_enabled") {
        return Err(String::from(
            "the execution layer no longer consults the VerifyMerkle activation flag.\n  \
             The containment boundary only holds if the gated opcode is refused at run time.",
        ));
    }

    Ok(String::from(
        "Containment-defaults gate OK: staged-rollout flags closed, VM decodes against default(), execution consults the flags.",
    ))
}

/// # Errors
///
/// Returns a finding when an opened flag passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-contain-{}-{nanos}",
        std::process::id()
    ));
    for sub in ["budzero/bud-isa/src", "budzero/bud-vm/src", "src/execution"] {
        std::fs::create_dir_all(dir.join(sub)).map_err(|e| e.to_string())?;
    }
    let good_isa = "pub struct MainnetActivation {}\nimpl Default for MainnetActivation {\n    fn default() -> Self {\n        Self {\n            verify_merkle_enabled: false,\n            verify_inference_enabled: false,\n        }\n    }\n}\n";
    let good_vm = "fn decode() { MainnetActivation::default(); }\n";
    let good_exec = "if activation.verify_merkle_enabled {}\n";
    std::fs::write(dir.join("budzero/bud-isa/src/lib.rs"), good_isa).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/bud-vm/src/lib.rs"), good_vm).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/execution/zkvm.rs"), good_exec).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a module with the flag off was refused",
        ));
    }
    // Open one flag.
    let open_isa = good_isa.replace(
        "verify_merkle_enabled: false",
        "verify_merkle_enabled: true",
    );
    std::fs::write(dir.join("budzero/bud-isa/src/lib.rs"), open_isa).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an on VerifyMerkle flag passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "containment canary OK (off PASSes, on FAILs).",
    ))
}
