//! Cross-EE deploy immutability, canonical pointer verification, foreign-caller
//! domain separation, `UER-1` Merkle domain tags, and fail-closed legacy CLI
//! consensus parsing must remain intact in production code.
//!
//! # Why this gate exists
//!
//! Five high-impact execution and configuration invariants protect consensus
//! state across the unified execution layer:
//!
//! 1. Unprivileged deployment paths across `EVM`, `WASM`, `SVM`, `Move`,
//!    `BudZero`, and expansion environments must refuse `POINTER_BYTECODE_PREFIX`
//!    (`is_pointer_bytecode_prefixed`) and must refuse overwriting an already
//!    deployed contract, while runtime pointer dispatchers (`evm_ee.rs`,
//!    `wasm_ee.rs`, `svm_ee.rs`, `move_ee.rs`) must verify pointer descriptors
//!    through `verify_canonical_pointer_bytecode` instead of raw fail-open
//!    `decode_pointer_bytecode`.
//! 2. `BudZeroEe` caller propagation (`src/execution/budzero_ee/mod.rs`) must
//!    bind `(caller.ee, caller.id)` under `"BDLM_UEL_FOREIGN_CALLER_V1"` rather
//!    than truncating 62-byte WASM or 20-byte EVM identities to 32 raw bytes.
//! 3. `MoveEe` `0x1::randomness` (`src/execution/coordinator/move_ee.rs`) must
//!    bind `call.tx_hash` under `"BDLM_MOVE_RANDOMNESS_V1"`, and `UER-1`
//!    (`src/execution/uer.rs`) must keep distinct domain tags for receipt,
//!    leaf, binary interior node, and odd-leaf promotion (`CVE-2012-2459`).
//! 4. `NodeConfig::apply_legacy_config` (`src/cli/commands.rs`) must fail
//!    closed on unrecognized `consensus` strings rather than mapping `_ => None`.

use std::fs;
use std::path::{Path, PathBuf};

const EE_POINTER_DISPATCHERS: &[&str] = &[
    "src/execution/coordinator/evm_ee.rs",
    "src/execution/coordinator/wasm_ee.rs",
    "src/execution/coordinator/svm_ee.rs",
    "src/execution/coordinator/move_ee.rs",
];

const EE_DEPLOY_GUARDS: &[&str] = &[
    "src/execution/coordinator/evm_ee.rs",
    "src/execution/coordinator/wasm_ee.rs",
    "src/execution/coordinator/svm_ee.rs",
    "src/execution/coordinator/move_ee.rs",
    "src/execution/coordinator/expansion_ee.rs",
    "src/execution/budzero_ee/mod.rs",
];

/// Strip `#[cfg(test)] mod ... { ... }` blocks so test helpers cannot satisfy
/// or trip production source invariants.
fn strip_test_mods(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("#[cfg(test)]") {
        let start = i + rel;
        out.push_str(&src[i..start]);
        let after_attr = start + "#[cfg(test)]".len();
        let trimmed = src[after_attr..].trim_start();
        let ws_len = src[after_attr..].len() - trimmed.len();
        if trimmed.starts_with("mod ") || trimmed.starts_with("pub mod ") {
            let mod_pos = after_attr + ws_len;
            if let Some(open_rel) = src[mod_pos..].find('{') {
                let open_at = mod_pos + open_rel;
                let bytes = src.as_bytes();
                let mut depth = 0usize;
                let mut j = open_at;
                while j < bytes.len() {
                    if bytes[j] == b'{' {
                        depth += 1;
                    } else if bytes[j] == b'}' {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        out.push_str("#[cfg(test)]");
        i = after_attr;
    }
    out.push_str(&src[i..]);
    out
}

fn read_prod(root: &Path, rel: &str) -> Result<String, String> {
    let full = root.join(rel);
    let raw = fs::read_to_string(&full).map_err(|e| format!("cannot read {rel}: {e}"))?;
    Ok(strip_test_mods(&raw))
}

fn check_pointer_and_deploy_guards(
    root: &Path,
    checked: &mut usize,
    errors: &mut Vec<String>,
) {
    match read_prod(root, "src/execution/coordinator/assets/mod.rs") {
        Ok(assets_src) => {
            *checked += 1;
            if !assets_src.contains("pub fn verify_canonical_pointer_bytecode")
                || !assets_src.contains("derive_pointer_address")
                || !assets_src.contains("derive_uel_asset_id")
            {
                errors.push(String::from(
                    "src/execution/coordinator/assets/mod.rs: missing canonical pointer verifier \
                     binding both derive_uel_asset_id and derive_pointer_address",
                ));
            }
        }
        Err(e) => errors.push(e),
    }

    for &rel in EE_DEPLOY_GUARDS {
        match read_prod(root, rel) {
            Ok(prod) => {
                *checked += 1;
                if !prod.contains("is_pointer_bytecode_prefixed") {
                    errors.push(format!(
                        "{rel}: user deploy path must reject reserved pointer prefix via \
                         is_pointer_bytecode_prefixed"
                    ));
                }
            }
            Err(e) => errors.push(e),
        }
    }

    for &rel in EE_POINTER_DISPATCHERS {
        match read_prod(root, rel) {
            Ok(prod) => {
                *checked += 1;
                if !prod.contains("verify_canonical_pointer_bytecode") {
                    errors.push(format!(
                        "{rel}: runtime pointer dispatch must call verify_canonical_pointer_bytecode"
                    ));
                }
                if prod.contains("decode_pointer_bytecode(") {
                    errors.push(format!(
                        "{rel}: raw fail-open decode_pointer_bytecode(...) is forbidden in EE \
                         runtime/deploy paths; use verify_canonical_pointer_bytecode or \
                         is_pointer_bytecode_prefixed"
                    ));
                }
            }
            Err(e) => errors.push(e),
        }
    }
}

fn check_caller_randomness_uer_and_cli(
    root: &Path,
    checked: &mut usize,
    errors: &mut Vec<String>,
) {
    match read_prod(root, "src/execution/budzero_ee/mod.rs") {
        Ok(bz_src) => {
            *checked += 1;
            if !bz_src.contains("\"BDLM_UEL_FOREIGN_CALLER_V1\"") {
                errors.push(String::from(
                    "src/execution/budzero_ee/mod.rs: missing BDLM_UEL_FOREIGN_CALLER_V1 \
                     domain-separated caller derivation",
                ));
            }
            if bz_src.contains("caller_id.len().min(32)") {
                errors.push(String::from(
                    "src/execution/budzero_ee/mod.rs: truncating caller_id[..32] collides \
                     foreign and 62-byte bech32 callers",
                ));
            }
        }
        Err(e) => errors.push(e),
    }

    match read_prod(root, "src/execution/coordinator/move_ee.rs") {
        Ok(move_src) => {
            *checked += 1;
            if !move_src.contains("\"BDLM_MOVE_RANDOMNESS_V1\"")
                || !move_src.contains("call.tx_hash")
            {
                errors.push(String::from(
                    "src/execution/coordinator/move_ee.rs: 0x1::randomness must bind \
                     call.tx_hash under BDLM_MOVE_RANDOMNESS_V1",
                ));
            }
        }
        Err(e) => errors.push(e),
    }

    match read_prod(root, "src/execution/uer.rs") {
        Ok(uer_src) => {
            *checked += 1;
            for tag in [
                "\"BDLM_UER_RECEIPT_V1\"",
                "\"BDLM_UER_LEAF_V1\"",
                "\"BDLM_UER_NODE_V1\"",
                "\"BDLM_UER_ODD_PROMOTE_V1\"",
            ] {
                if !uer_src.contains(tag) {
                    errors.push(format!(
                        "src/execution/uer.rs: missing distinct UER-1 domain tag {tag}"
                    ));
                }
            }
        }
        Err(e) => errors.push(e),
    }

    match read_prod(root, "src/cli/commands.rs") {
        Ok(cli_src) => {
            *checked += 1;
            if let Some(pos) = cli_src.find("fn apply_legacy_config") {
                let window_end = (pos + 1_200).min(cli_src.len());
                let body = &cli_src[pos..window_end];
                if body.contains("_ => None") || !body.contains("process::exit(1)") {
                    errors.push(String::from(
                        "src/cli/commands.rs: apply_legacy_config must fail closed with \
                         process::exit(1) on invalid consensus instead of mapping _ => None",
                    ));
                }
            } else {
                errors.push(String::from(
                    "src/cli/commands.rs: missing apply_legacy_config definition",
                ));
            }
        }
        Err(e) => errors.push(e),
    }
}

fn check_root(root: &Path) -> Result<usize, Vec<String>> {
    let mut errors = Vec::new();
    let mut checked = 0usize;
    check_pointer_and_deploy_guards(root, &mut checked, &mut errors);
    check_caller_randomness_uer_and_cli(root, &mut checked, &mut errors);
    if errors.is_empty() {
        Ok(checked)
    } else {
        Err(errors)
    }
}

/// # Errors
///
/// Returns every violated self-interrogation invariant across the workspace.
pub fn run(root: &Path) -> Result<String, String> {
    match check_root(root) {
        Ok(checked) => Ok(format!(
            "self-interrogation invariants OK across {checked} production module checks"
        )),
        Err(errors) => Err(errors.join("\n")),
    }
}

fn write_fixture_file(base: &Path, rel: &str, content: &str) -> Result<(), String> {
    let full = base.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&full, content).map_err(|e| format!("write {}: {e}", full.display()))
}

fn build_valid_fixture(base: &Path) -> Result<(), String> {
    write_fixture_file(
        base,
        "src/execution/coordinator/assets/mod.rs",
        "pub fn is_pointer_bytecode_prefixed(c: &[u8]) -> bool { !c.is_empty() }\n\
         pub fn verify_canonical_pointer_bytecode() { let _ = (derive_uel_asset_id, derive_pointer_address); }\n",
    )?;
    for &rel in &[
        "src/execution/coordinator/evm_ee.rs",
        "src/execution/coordinator/wasm_ee.rs",
        "src/execution/coordinator/svm_ee.rs",
    ] {
        write_fixture_file(
            base,
            rel,
            "fn guard() { is_pointer_bytecode_prefixed(&[]); verify_canonical_pointer_bytecode(); }\n",
        )?;
    }
    write_fixture_file(
        base,
        "src/execution/coordinator/move_ee.rs",
        "fn guard(call: &Call) {\n\
             is_pointer_bytecode_prefixed(&[]);\n\
             verify_canonical_pointer_bytecode();\n\
             let _ = (\"BDLM_MOVE_RANDOMNESS_V1\", call.tx_hash);\n\
         }\n",
    )?;
    write_fixture_file(
        base,
        "src/execution/coordinator/expansion_ee.rs",
        "fn guard() { is_pointer_bytecode_prefixed(&[]); }\n",
    )?;
    write_fixture_file(
        base,
        "src/execution/budzero_ee/mod.rs",
        "fn apply() { is_pointer_bytecode_prefixed(&[]); let _ = \"BDLM_UEL_FOREIGN_CALLER_V1\"; }\n",
    )?;
    write_fixture_file(
        base,
        "src/execution/uer.rs",
        "const TAGS: &[&[u8]] = &[\n\
             b\"BDLM_UER_RECEIPT_V1\",\n\
             b\"BDLM_UER_LEAF_V1\",\n\
             b\"BDLM_UER_NODE_V1\",\n\
             b\"BDLM_UER_ODD_PROMOTE_V1\",\n\
         ];\n",
    )?;
    write_fixture_file(
        base,
        "src/cli/commands.rs",
        "fn apply_legacy_config() { std::process::exit(1); }\n",
    )
}

fn scratch_dir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir().join(format!(
        "budlum-self-interrogation-{}",
        std::process::id()
    ));
    for idx in 0..64u32 {
        let cand = base.with_extension(format!("run{idx}"));
        if !cand.exists() {
            fs::create_dir_all(&cand).map_err(|e| format!("create scratch dir: {e}"))?;
            return Ok(cand);
        }
    }
    Err(String::from("unable to allocate scratch dir for self_interrogation self_test"))
}

/// # Errors
///
/// Returns an error if the positive fixture fails or any negative mutation passes.
pub fn self_test() -> Result<String, String> {
    let dir = scratch_dir()?;
    let result = (|| -> Result<String, String> {
        build_valid_fixture(&dir)?;
        check_root(&dir).map_err(|e| format!("valid fixture rejected: {}", e.join("; ")))?;

        // Negative 1: fail-open decode_pointer_bytecode reintroduced in WASM EE.
        build_valid_fixture(&dir)?;
        write_fixture_file(
            &dir,
            "src/execution/coordinator/wasm_ee.rs",
            "fn bad() { is_pointer_bytecode_prefixed(&[]); verify_canonical_pointer_bytecode(); decode_pointer_bytecode(&[]); }\n",
        )?;
        if check_root(&dir).is_ok() {
            return Err(String::from("canary 1 failed: accepted decode_pointer_bytecode in wasm_ee.rs"));
        }

        // Negative 2: BudZeroEe truncates caller_id[..32].
        build_valid_fixture(&dir)?;
        write_fixture_file(
            &dir,
            "src/execution/budzero_ee/mod.rs",
            "fn bad(caller_id: &[u8]) { is_pointer_bytecode_prefixed(&[]); let _ = caller_id.len().min(32); }\n",
        )?;
        if check_root(&dir).is_ok() {
            return Err(String::from("canary 2 failed: accepted truncated caller_id in budzero_ee"));
        }

        // Negative 3: UER-1 missing odd-leaf promotion tag.
        build_valid_fixture(&dir)?;
        write_fixture_file(
            &dir,
            "src/execution/uer.rs",
            "const TAGS: &[&[u8]] = &[b\"BDLM_UER_RECEIPT_V1\", b\"BDLM_UER_LEAF_V1\", b\"BDLM_UER_NODE_V1\"];\n",
        )?;
        if check_root(&dir).is_ok() {
            return Err(String::from("canary 3 failed: accepted UER-1 without BDLM_UER_ODD_PROMOTE_V1"));
        }

        // Negative 4: Legacy CLI maps unknown consensus to None.
        build_valid_fixture(&dir)?;
        write_fixture_file(
            &dir,
            "src/cli/commands.rs",
            "fn apply_legacy_config(s: &str) { let _ = match s { \"pos\" => Some(1), _ => None }; }\n",
        )?;
        if check_root(&dir).is_ok() {
            return Err(String::from("canary 4 failed: accepted fail-open _ => None in apply_legacy_config"));
        }

        Ok(String::from(
            "self-interrogation-invariants self-test OK: valid fixture passed and 4 negative \
             canaries (pointer spoofing, foreign-caller truncation, UER odd-leaf tag omission, \
             and legacy CLI consensus fallback) were refused.",
        ))
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}
