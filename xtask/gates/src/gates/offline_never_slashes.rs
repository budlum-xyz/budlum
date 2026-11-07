//! Static gate: `offline-never-slashes` (directive section 7.8, section 11.7, WP-13).
//!
//! Enforces invariant V-4 (closing BLG-251):
//! 1. `src/validators/presence.rs` implements `PresenceSignal`, `PresenceAggregate`,
//!    `PresenceTracker::verify_aggregate`, `PresenceTracker::advance_window`,
//!    `PresenceTracker::request_resume`, `PresenceTracker::activate_due_resumes`,
//!    and `PRESENCE_DOUBLE_SIGN_BPS: u64 = 100`, while `advance_window` never
//!    touches stake or calls `slash_from_report` / `consensus_liveness`.
//! 2. `src/registry/liveness.rs` exposes `record_suspension_epoch`, `request_resume`,
//!    and `activate_due_resumes`, and never calls `consensus_liveness`.

use std::fs;
use std::path::Path;

pub fn run(root: &Path) -> Result<String, String> {
    let presence_path = root.join("src/validators/presence.rs");
    let presence_src = fs::read_to_string(&presence_path)
        .map_err(|e| format!("missing src/validators/presence.rs: {e}"))?;
    let presence_prod = presence_src
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default();

    for token in [
        "PRESENCE_DOUBLE_SIGN_BPS: u64 = 100",
        "pub struct PresenceSignal",
        "pub struct PresenceAggregate",
        "pub fn verify_aggregate",
        "pub fn advance_window",
        "pub fn request_resume",
        "pub fn activate_due_resumes",
    ] {
        if !presence_prod.contains(token) {
            return Err(format!(
                "src/validators/presence.rs missing required token `{token}`"
            ));
        }
    }

    if let Some((_, after)) = presence_prod.split_once("pub fn advance_window") {
        let body = after
            .split("pub fn request_resume")
            .next()
            .unwrap_or_default();
        for forbidden in ["slash_from_report", "consensus_liveness", "stake"] {
            if body.contains(forbidden) {
                return Err(format!(
                    "invariant V-4 violation: `advance_window` references `{forbidden}`"
                ));
            }
        }
    }

    let liveness_path = root.join("src/registry/liveness.rs");
    let liveness_src = fs::read_to_string(&liveness_path)
        .map_err(|e| format!("missing src/registry/liveness.rs: {e}"))?;
    let liveness_prod = liveness_src
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default();
    for token in [
        "pub fn record_suspension_epoch",
        "pub fn request_resume",
        "pub fn activate_due_resumes",
    ] {
        if !liveness_prod.contains(token) {
            return Err(format!(
                "src/registry/liveness.rs missing required non-slashing suspension token `{token}`"
            ));
        }
    }
    if liveness_prod.contains("consensus_liveness") {
        return Err(String::from(
            "invariant V-4 violation: src/registry/liveness.rs emits consensus_liveness",
        ));
    }

    Ok(String::from(
        "offline-never-slashes OK: single-pairing presence aggregate and non-slashing V-4 suspension verified",
    ))
}

pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-offline-noslash")?;
    let res = (|| -> Result<(), String> {
        fs::create_dir_all(dir.join("src/validators")).map_err(|e| e.to_string())?;
        fs::create_dir_all(dir.join("src/registry")).map_err(|e| e.to_string())?;

        let valid_presence = "\
pub const PRESENCE_DOUBLE_SIGN_BPS: u64 = 100;\n\
pub struct PresenceSignal;\n\
pub struct PresenceAggregate;\n\
pub struct PresenceTracker;\n\
impl PresenceTracker {\n\
    pub fn verify_aggregate(&self) {}\n\
    pub fn advance_window(&mut self) { let _suspended = true; }\n\
    pub fn request_resume(&mut self) {}\n\
    pub fn activate_due_resumes(&mut self) {}\n\
}\n";
        let valid_liveness = "\
pub struct LivenessTracker;\n\
impl LivenessTracker {\n\
    pub fn record_suspension_epoch(&mut self) {}\n\
    pub fn request_resume(&mut self) {}\n\
    pub fn activate_due_resumes(&mut self) {}\n\
}\n";
        fs::write(dir.join("src/validators/presence.rs"), valid_presence)
            .map_err(|e| e.to_string())?;
        fs::write(dir.join("src/registry/liveness.rs"), valid_liveness)
            .map_err(|e| e.to_string())?;
        run(&dir)?;

        let bad = valid_presence.replace("let _suspended = true;", "let _ = slash_from_report;");
        fs::write(dir.join("src/validators/presence.rs"), bad).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: offline-never-slashes accepted slashing inside advance_window",
            ));
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&dir);
    res?;
    Ok(String::from(
        "offline-never-slashes canary OK: slashing inside advance_window was refused",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn offline_never_slashes_catches_injected_slashing_in_suspension() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
