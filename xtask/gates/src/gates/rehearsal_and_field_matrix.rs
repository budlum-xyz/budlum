//! Static gate: ceremony rehearsal topology, T-1..T-7 drill evaluator, Mobile
//! device matrix, and UEL execution limits (`WP-46`, `WP-37`, `WP-35`).

use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("cannot read `{rel}`: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn check(root: &Path) -> Result<String, String> {
    let genesis_txt = read_rel(root, "config/rehearsal-genesis.json")?;
    let genesis: serde_json::Value = serde_json::from_str(&genesis_txt)
        .map_err(|e| format!("`config/rehearsal-genesis.json` invalid JSON: {e}"))?;
    let validators = genesis
        .get("validators")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| String::from("`config/rehearsal-genesis.json` missing `validators` array"))?;
    if validators.len() < 8 {
        return Err(format!(
            "`config/rehearsal-genesis.json` has {} validators; at least 8 Full validators are required",
            validators.len()
        ));
    }

    let topo_txt = read_rel(root, "ops/rehearsal/topology.toml")?;
    for required in [
        "full_validators = 8",
        "relay_nodes = 4",
        "upload_gateways = 2",
        "android_phone_validators = 20",
        "simulated_mobile_validators = 1000",
        "steady_state_secs = 259200",
    ] {
        if !topo_txt.contains(required) {
            return Err(format!(
                "`ops/rehearsal/topology.toml` missing required floor `{required}`"
            ));
        }
    }

    let reh_prod = strip_cfg_test(&read_rel(root, "src/registry/rehearsal.rs")?).to_string();
    for needle in [
        "MIN_REHEARSAL_FULL_VALIDATORS",
        "verify_rehearsal_topology",
        "evaluate_rehearsal_drills",
        "analyze_mobile_field_logs",
    ] {
        if !reh_prod.contains(needle) {
            return Err(format!(
                "`src/registry/rehearsal.rs` missing required symbol `{needle}`"
            ));
        }
    }

    for doc in [
        "docs/rehearsal/DRILLS.md",
        "docs/rehearsal/RESULTS.md",
        "docs/MOBILE_DEVICE_MATRIX.md",
        "docs/EXECUTION_LIMITS.md",
    ] {
        let body = read_rel(root, doc)?;
        if body.trim().is_empty() {
            return Err(format!("`{doc}` is empty"));
        }
    }

    Ok(String::from(
        "rehearsal-and-field-matrix OK: 8-Full rehearsal genesis, topology floors, T-1..T-7 drill evaluator, mobile device matrix, and execution limits verified.",
    ))
}

/// Run the gate against `root`.
///
/// # Errors
///
/// Returns an error string when any rehearsal or device-matrix invariant fails.
pub fn run(root: &Path) -> Result<String, String> {
    check(root)
}

/// Run positive and negative synthetic canary checks.
///
/// # Errors
///
/// Returns an error string if the positive fixture fails or any negative fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rehearsal")?;
    let res = (|| -> Result<String, String> {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_genesis = r#"{"validators":[1,2,3,4,5,6,7,8]}"#;
        let clean_topo = "full_validators = 8\nrelay_nodes = 4\nupload_gateways = 2\nandroid_phone_validators = 20\nsimulated_mobile_validators = 1000\nsteady_state_secs = 259200\n";
        let clean_reh = "pub const MIN_REHEARSAL_FULL_VALIDATORS: usize = 8;\npub fn verify_rehearsal_topology() {}\npub fn evaluate_rehearsal_drills() {}\npub fn analyze_mobile_field_logs() {}\n";

        put("config/rehearsal-genesis.json", clean_genesis)?;
        put("ops/rehearsal/topology.toml", clean_topo)?;
        put("src/registry/rehearsal.rs", clean_reh)?;
        put("docs/rehearsal/DRILLS.md", "# Drills\n")?;
        put("docs/rehearsal/RESULTS.md", "# Results\n")?;
        put("docs/MOBILE_DEVICE_MATRIX.md", "# Matrix\n")?;
        put("docs/EXECUTION_LIMITS.md", "# Limits\n")?;

        check(&dir).map_err(|e| format!("clean canary failed: {e}"))?;

        // Negative canary 1: fewer than 8 Full validators in rehearsal genesis must fail.
        put("config/rehearsal-genesis.json", r#"{"validators":[1,2,3,4,5,6,7]}"#)?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "canary failed: 7-validator rehearsal genesis passed",
            ));
        }
        put("config/rehearsal-genesis.json", clean_genesis)?;

        // Negative canary 2: missing mobile field log analyzer must fail.
        put("src/registry/rehearsal.rs", "pub const MIN_REHEARSAL_FULL_VALIDATORS: usize = 8;\n")?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "canary failed: rehearsal.rs without analyze_mobile_field_logs passed",
            ));
        }

        Ok(String::from(
            "rehearsal-and-field-matrix canary OK: positive tree passed; 2 negative fixtures rejected.",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}
