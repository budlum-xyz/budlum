//! Static gate: `offline-never-slashes` (Section 7.8, Section 11.7,).
//!
//! Enforces invariant V-4 (closing):
//! 1. `src/registry/presence.rs` implements `PresenceSignal`, `PresenceAggregate`
//!    single-pairing BLS verification (`verify_single_pairing`), `hours_to_epochs`,
//!    `apply_resume_validator` (1-epoch delay), and 1% presence double-sign slash
//!    (`PRESENCE_DOUBLE_SIGN_SLASH_PPM = 10_000`), while `advance_epoch` suspends
//!    offline validators without reducing `stake_atoms`.
//! 2. `src/registry/liveness.rs` exposes `SuspensionNotice` and
//!    `record_suspension_epoch` with `stake_slashed_atoms: 0`.

use std::fs;
use std::path::Path;

pub fn run(root: &Path) -> Result<String, String> {
    let presence_path = root.join("src/registry/presence.rs");
    let presence_src = fs::read_to_string(&presence_path)
        .map_err(|e| format!("missing src/registry/presence.rs: {e}"))?;
    let presence_prod = presence_src
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default();

    for token in [
        "\"/budlum/presence/1\"",
        "BDLM_PRESENCE_V1",
        "PRESENCE_DOUBLE_SIGN_SLASH_PPM: u64 = 10_000",
        "pub fn hours_to_epochs",
        "pub struct PresenceSignal",
        "pub struct PresenceAggregate",
        "pub fn verify_single_pairing",
        "pub fn advance_epoch",
        "pub fn apply_resume_validator",
        "pub fn slash_double_sign",
    ] {
        if !presence_prod.contains(token) {
            return Err(format!(
                "src/registry/presence.rs missing required token `{token}`"
            ));
        }
    }

    // Ensure `advance_epoch` never mutates `stake_atoms`.
    if let Some((_, after)) = presence_prod.split_once("pub fn advance_epoch") {
        let body = after
            .split("pub fn apply_resume_validator")
            .next()
            .unwrap_or_default();
        if body.contains("stake_atoms") {
            return Err(
                "invariant V-4 violation: `advance_epoch` touches `stake_atoms` on offline suspension"
                    .to_owned(),
            );
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
        "pub struct SuspensionNotice",
        "pub fn record_suspension_epoch",
        "stake_slashed_atoms: 0",
    ] {
        if !liveness_prod.contains(token) {
            return Err(format!(
                "src/registry/liveness.rs missing required non-slashing suspension token `{token}`"
            ));
        }
    }

    Ok(
        "offline-never-slashes: single-pairing presence aggregate and non-slashing V-4 suspension verified"
            .to_owned(),
    )
}

pub fn self_test() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum_offline_never_slashes_gate_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src/registry")).map_err(|e| e.to_string())?;

    let valid_presence = r#"
pub const TOPIC: &str = "/budlum/presence/1";
pub const TAG: &str = "BDLM_PRESENCE_V1";
pub const PRESENCE_DOUBLE_SIGN_SLASH_PPM: u64 = 10_000;
pub fn hours_to_epochs() {}
pub struct PresenceSignal;
pub struct PresenceAggregate;
impl PresenceAggregate { pub fn verify_single_pairing(&self) {} }
pub struct PresenceTracker;
impl PresenceTracker {
    pub fn advance_epoch(&mut self) { let _suspended = true; }
    pub fn apply_resume_validator(&mut self) {}
    pub fn slash_double_sign(&mut self) {}
}
"#;
    let valid_liveness = r#"
pub struct SuspensionNotice { pub stake_slashed_atoms: u64 }
pub fn record_suspension_epoch() -> SuspensionNotice {
    SuspensionNotice { stake_slashed_atoms: 0 }
}
"#;
    fs::write(dir.join("src/registry/presence.rs"), valid_presence).map_err(|e| e.to_string())?;
    fs::write(dir.join("src/registry/liveness.rs"), valid_liveness).map_err(|e| e.to_string())?;
    run(&dir)?;

    // Negative canary: touching `stake_atoms` inside `advance_epoch` must fail!
    let bad_presence = valid_presence.replace(
        "let _suspended = true;",
        "let stake_atoms = 0;",
    );
    fs::write(dir.join("src/registry/presence.rs"), bad_presence).map_err(|e| e.to_string())?;
    let res = run(&dir);
    let _ = fs::remove_dir_all(&dir);
    if res.is_ok() {
        return Err("offline-never-slashes accepted stake mutation in advance_epoch".to_owned());
    }
    Ok(())
}
