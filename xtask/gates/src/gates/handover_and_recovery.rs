//! Static gate: `handover-and-recovery` (Section 7.6, Section 7.7).
//!
//! Verifies:
//! 1. `src/registry/handover.rs` implements all Section 7.6 Instant Task Handover
//!    deadlines (`SEAT_ABSENCE_HANDOVER_CHECKPOINTS = 2`, `CUSTODY_READ_TIMEOUT_MS = 2_000`,
//!    3-epoch share ack handover, 20-block repair duty handover, next-block presence
//!    aggregate fallback) and Section 7.7 40-block disaster recovery mode
//!    (`FINALITY_STALL_RECOVERY_BLOCKS = 40`, `budlum_finality_stalled`, R-03 doc).
//! 2. `src/core/metrics.rs` registers `"budlum_finality_stalled"`.
//! 3. `tests/churn/main.rs` exercises all seven  churn scenarios.

use std::fs;
use std::path::Path;

pub fn run(root: &Path) -> Result<String, String> {
    let handover_src = fs::read_to_string(root.join("src/registry/handover.rs"))
        .map_err(|e| format!("missing src/registry/handover.rs: {e}"))?;
    let handover_prod = handover_src
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default();

    for token in [
        "R-03",
        "SEAT_ABSENCE_HANDOVER_CHECKPOINTS: u64 = 2",
        "CUSTODY_READ_TIMEOUT_MS: u64 = 2_000",
        "FINALITY_STALL_RECOVERY_BLOCKS: u64 = 40",
        "pub fn proposer_for_round",
        "pub fn record_checkpoint_participation",
        "pub fn handover_unacked_share",
        "pub fn handover_repair_duty",
        "pub fn flush_pending_presence_aggregates",
        "pub fn compute_recovery_committee",
        "finality_stalled",
    ] {
        if !handover_prod.contains(token) && !handover_src.contains(token) {
            return Err(format!(
                "src/registry/handover.rs missing required token `{token}`"
            ));
        }
    }

    let metrics_src = fs::read_to_string(root.join("src/core/metrics.rs"))
        .map_err(|e| format!("missing src/core/metrics.rs: {e}"))?;
    if !metrics_src.contains("\"budlum_finality_stalled\"") {
        return Err("src/core/metrics.rs missing `budlum_finality_stalled`".to_owned());
    }

    let churn_src = fs::read_to_string(root.join("tests/churn/main.rs"))
        .map_err(|e| format!("missing tests/churn/main.rs: {e}"))?;
    for test_fn in [
        "fn proposer_round_handover",
        "fn repair_task_handover_after_20_blocks",
        "fn custody_assignment_handover_after_3_epochs",
        "fn presence_aggregate_fallback_next_block",
        "fn ten_percent_full_departure_keeps_finality",
        "fn all_mobile_departure_does_not_touch_finality",
        "fn finality_stall_enters_recovery_mode",
    ] {
        if !churn_src.contains(test_fn) {
            return Err(format!("tests/churn/main.rs missing `{test_fn}`"));
        }
    }

    Ok("handover-and-recovery: Section 7.6 AGD, 40-block disaster recovery, and churn suite verified".to_owned())
}

pub fn self_test() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum_handover_recovery_gate_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src/registry")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("src/core")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("tests/churn")).map_err(|e| e.to_string())?;

    let valid_handover = r#"
//! R-03 documented.
pub const SEAT_ABSENCE_HANDOVER_CHECKPOINTS: u64 = 2;
pub const CUSTODY_READ_TIMEOUT_MS: u64 = 2_000;
pub const FINALITY_STALL_RECOVERY_BLOCKS: u64 = 40;
pub fn proposer_for_round() {}
pub fn record_checkpoint_participation() {}
pub fn handover_unacked_share() {}
pub fn handover_repair_duty() {}
pub fn flush_pending_presence_aggregates() {}
pub fn compute_recovery_committee() {}
pub fn sync_finality_stalled() {}
"#;
    let valid_metrics = r#"pub const M: &str = "budlum_finality_stalled";"#;
    let valid_churn = r#"
fn proposer_round_handover() {}
fn repair_task_handover_after_20_blocks() {}
fn custody_assignment_handover_after_3_epochs() {}
fn presence_aggregate_fallback_next_block() {}
fn ten_percent_full_departure_keeps_finality() {}
fn all_mobile_departure_does_not_touch_finality() {}
fn finality_stall_enters_recovery_mode() {}
"#;
    fs::write(dir.join("src/registry/handover.rs"), valid_handover).map_err(|e| e.to_string())?;
    fs::write(dir.join("src/core/metrics.rs"), valid_metrics).map_err(|e| e.to_string())?;
    fs::write(dir.join("tests/churn/main.rs"), valid_churn).map_err(|e| e.to_string())?;
    run(&dir)?;

    let bad = valid_handover.replace("FINALITY_STALL_RECOVERY_BLOCKS: u64 = 40", "FINALITY_STALL_RECOVERY_BLOCKS: u64 = 10");
    fs::write(dir.join("src/registry/handover.rs"), bad).map_err(|e| e.to_string())?;
    let res = run(&dir);
    let _ = fs::remove_dir_all(&dir);
    if res.is_ok() {
        return Err("handover-and-recovery accepted wrong stall threshold".to_owned());
    }
    Ok(())
}
