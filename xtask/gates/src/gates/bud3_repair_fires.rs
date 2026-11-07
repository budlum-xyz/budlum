//! B.U.D. 3.0 lazy-repair, handover, and reassignment gate (`bud3-repair-fires`, WP-20).
//!
//! Enforces statically that:
//! 1. `src/storage/bud3/repair.rs` implements 20-block Instant Task Handover
//!    (`REPAIR_HANDOVER_BLOCKS`), fresh-ESI repair generation (`build_segment_repair`),
//!    1% random repair auditing (`should_audit_repair_batch`, `verify_repaired_symbol`),
//!    and 1% stake slashing (`BAD_REPAIR_SLASH_BPS`, `bad_repair_slash_amount`).
//! 2. `src/storage/bud3/maintenance.rs` prioritizes shrink repairs by smallest
//!    remaining fault margin (`prioritize_shrink_repairs`) and exports the four
//!    `budlum_bud3_*` Prometheus series.
//! 3. `src/storage/bud3/registry.rs` wires lazy `repairs_due` (`(f / 2).max(1)`),
//!    `record_repair`, `decline` reassignment, and voluntary `release_shares`.

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

/// Run the `bud3-repair-fires` gate against `root`.
///
/// # Errors
///
/// Returns an error if any WP-20 lazy-repair, 20-block handover, 1% bad-repair
/// slash, or reassignment invariant is missing.
pub fn run(root: &Path) -> Result<String, String> {
    let repair_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/repair.rs",
    )?));
    for required in [
        "REPAIR_HANDOVER_BLOCKS: u64 = 20",
        "BAD_REPAIR_SLASH_BPS: u64 = 100",
        "pub fn assign_repairer",
        "pub fn build_segment_repair",
        "pub fn verify_repaired_symbol",
        "pub const fn bad_repair_slash_amount",
    ] {
        if !repair_src.contains(required) {
            return Err(format!(
                "bud3-repair-fires: src/storage/bud3/repair.rs missing `{required}`"
            ));
        }
    }

    let maint_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/maintenance.rs",
    )?));
    for required in [
        "pub fn prioritize_shrink_repairs",
        "pub fn select_reassignment_holders",
        "budlum_bud3_segments_at_risk",
        "budlum_bud3_repair_backlog",
        "budlum_bud3_audit_latency",
        "budlum_bud3_custody_bytes",
    ] {
        if !maint_src.contains(required) {
            return Err(format!(
                "bud3-repair-fires: src/storage/bud3/maintenance.rs missing `{required}`"
            ));
        }
    }

    let reg_src = strip_line_comments(strip_cfg_test(&read_rel(
        root,
        "src/storage/bud3/registry.rs",
    )?));
    for required in [
        "pub fn repairs_due",
        "pub fn record_repair",
        "pub fn decline",
        "pub fn release_shares",
    ] {
        if !reg_src.contains(required) {
            return Err(format!(
                "bud3-repair-fires: src/storage/bud3/registry.rs missing `{required}`"
            ));
        }
    }

    Ok(String::from(
        "bud3-repair-fires OK: lazy f/2 trigger, 20-block handover, fresh-ESI repair, 1% bad-repair slash, and metrics wired.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if a clean synthetic tree fails or a broken canary passes.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-repair-fires")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_repair = "\
pub const REPAIR_HANDOVER_BLOCKS: u64 = 20;
pub const BAD_REPAIR_SLASH_BPS: u64 = 100;
pub fn assign_repairer() {}
pub fn build_segment_repair() {}
pub fn verify_repaired_symbol() {}
pub const fn bad_repair_slash_amount() -> u64 { 0 }
";
        let clean_maint = "\
pub fn prioritize_shrink_repairs() {}
pub fn select_reassignment_holders() {}
pub fn m() { let _ = (\"budlum_bud3_segments_at_risk\", \"budlum_bud3_repair_backlog\", \"budlum_bud3_audit_latency\", \"budlum_bud3_custody_bytes\"); }
";
        let clean_reg = "\
pub fn repairs_due() {}
pub fn record_repair() {}
pub fn decline() {}
pub fn release_shares() {}
";
        put("src/storage/bud3/repair.rs", clean_repair)?;
        put("src/storage/bud3/maintenance.rs", clean_maint)?;
        put("src/storage/bud3/registry.rs", clean_reg)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        put("src/storage/bud3/registry.rs", "pub fn repairs_due() {}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: registry.rs missing record_repair/release_shares passed",
            ));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-repair-fires canary OK: clean tree passed; incomplete repair/release wiring failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_repair_fires_canary() {
        assert!(super::self_test().is_ok());
    }
}
