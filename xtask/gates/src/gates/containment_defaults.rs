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
    // Literals and comments (line and block) are blanked: a `/* .. */` that
    // names the call, or a `//` inside a string, must not change what is read.
    Ok(super::rust_literals::scrub(&text))
}

/// The text of the first brace-balanced block that starts at or after `from`.
fn balanced_block(text: &str, from: usize) -> Option<&str> {
    let open = text[from..].find('{')? + from;
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Does `execute_bytecode` hand `true` as the mainnet flag to the inner runner?
fn has_gated_entry(exec_code: &str) -> bool {
    let compact: String = exec_code.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("execute_bytecode_inner(bytecode,gas_limit,true,ctx)")
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
    // Production text only: a unit test that mentions the flag is no consultation.
    let exec_code = super::capability_modules_are_wired::strip_test_mods(&code_of(&exec)?);

    // 1. Default impl exists and closes both flags.
    let default_start = isa_code.find("impl Default for MainnetActivation");
    // The whole impl, balanced: lines after the first `}` are read too, and an
    // impl with no closing brace is a finding, not a panic.
    let default_block = default_start.and_then(|s| balanced_block(&isa_code, s));
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
        if default_block
            .lines()
            .any(|l| l.contains(flag) && l.contains("true"))
        {
            return Err(format!(
                "MainnetActivation::default() sets {flag} to true somewhere in the impl."
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

    // 3. The execution layer runs contract bytecode in the gated mode. The flag
    // itself is read inside the VM; what the executor owns is passing `true`
    // for mainnet mode on the transaction path.
    if !exec_code.contains("Vm::with_mainnet_mode(") || !has_gated_entry(&exec_code) {
        return Err(String::from(
            "the execution layer no longer runs contract bytecode in mainnet (gated) mode.\n  \
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
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-contain")?;
    for sub in ["budzero/bud-isa/src", "budzero/bud-vm/src", "src/execution"] {
        std::fs::create_dir_all(dir.join(sub)).map_err(|e| e.to_string())?;
    }
    let good_isa = "pub struct MainnetActivation {}\nimpl Default for MainnetActivation {\n    fn default() -> Self {\n        Self {\n            verify_merkle_enabled: false,\n            verify_inference_enabled: false,\n        }\n    }\n}\n";
    let good_vm = "fn decode() { MainnetActivation::default(); }\n";
    let good_exec = "fn execute_bytecode() { Self::execute_bytecode_inner(bytecode, gas_limit, true, ctx) }\nfn inner() { Vm::with_mainnet_mode(1, 2, mainnet); }\n#[cfg(test)]\nmod tests { fn t() { assert!(!d.verify_merkle_enabled); } }\n";
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gated_entry_needs_true_in_production_text() {
        assert!(has_gated_entry(
            "x(bytecode,\n gas_limit, true, ctx)"
                .replace("x", "execute_bytecode_inner")
                .as_str()
        ));
        assert!(!has_gated_entry(
            "execute_bytecode_inner(bytecode, gas_limit, false, ctx)"
        ));
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;

    #[test]
    fn balanced_block_reads_the_whole_impl_and_never_panics() {
        let t = "impl X { fn d() -> S { S { a: false } } fn e() { s.a = true; } } tail";
        let b = balanced_block(t, 0).unwrap();
        assert!(b.ends_with("} }") && b.contains("s.a = true"));
        assert!(balanced_block("impl X { fn d() {", 0).is_none());
        assert!(balanced_block("no brace", 0).is_none());
    }
}
