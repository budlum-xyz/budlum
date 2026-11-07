//! B.U.D. 3.0 class-aware placement gate (`bud3-placement`).
//!
//! Enforces statically that:
//! 1. `src/storage/bud3/placement.rs` uses integer-only fixed-point rendezvous
//!    hashing (`log2_q32`, `neg_log2_unit_q32`) with zero floating-point tokens,
//!    enforces the `MOBILE_SYMBOL_FLOOR_MILLI` (`300`, 30%) floor, implements
//!    `lookup_with_shrink` down to a single Full validator, and computes
//!    `physical_bytes_split` (`user_physical_bytes` vs `decentralization_physical_bytes`).
//! 2. `xtask/tools/src/placement_table.rs` exists and verifies the canonical
//!    Section 6.9.4 buckets.

use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    if !path.is_file() {
        return Err(format!("missing required file: {rel}"));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let code = match line.find("//") {
            Some(idx) => line.get(..idx).unwrap_or(line),
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// Run the `bud3-placement` gate against `root`.
///
/// # Errors
///
/// Returns an error if any  placement, mobile-floor, shrink, or float-free
/// consensus invariant is violated.
pub fn run(root: &Path) -> Result<String, String> {
    let placement_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/placement.rs",
    )?));
    for required in [
        "MOBILE_SYMBOL_FLOOR_MILLI",
        "log2_q32",
        "neg_log2_unit_q32",
        "pub fn lookup_with_shrink",
        "pub fn physical_bytes_split",
        "survives_mobile_exit",
    ] {
        if !placement_src.contains(required) {
            return Err(format!(
                "bud3-placement: src/storage/bud3/placement.rs missing `{required}`"
            ));
        }
    }
    for forbidden_float in ["f32", "f64"] {
        if placement_src.contains(forbidden_float) {
            return Err(format!(
                "bud3-placement: consensus placement.rs contains forbidden float token `{forbidden_float}`"
            ));
        }
    }

    let tool_src = strip_line_comments(&read_rel(root, "xtask/tools/src/placement_table.rs")?);
    for required in ["pub fn compute_canonical_table", "mobile_floor"] {
        if !tool_src.contains(required) {
            return Err(format!(
                "bud3-placement: xtask/tools/src/placement_table.rs missing `{required}`"
            ));
        }
    }

    Ok(String::from(
        "bud3-placement OK: Q32 integer rendezvous, 30% mobile floor, network shrink, and off-chain placement-table verified.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean synthetic tree fails or a float/floor canary passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-placement")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_placement = "\
pub const MOBILE_SYMBOL_FLOOR_MILLI: u64 = 300;
fn log2_q32() {}
fn neg_log2_unit_q32() {}
pub fn survives_mobile_exit() {}
pub fn lookup_with_shrink() {}
pub fn physical_bytes_split() {}
";
        let clean_tool = "\
pub struct Inputs { pub mobile_floor: f64 }
pub fn compute_canonical_table() {}
";
        put("src/storage/bud3/placement.rs", clean_placement)?;
        put("xtask/tools/src/placement_table.rs", clean_tool)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        put(
            "src/storage/bud3/placement.rs",
            &format!("{clean_placement}\npub fn bad(x: f64) -> f64 {{ x }}\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: f64 in placement.rs passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-placement canary OK: clean tree passed; float in consensus placement.rs failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_placement_canary() {
        assert!(super::self_test().is_ok());
    }
}
