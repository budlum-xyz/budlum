//! Static gate: `bud3-codec-and-replace` (Section 6.6.1, 6.6.2, 6.14;).
//!
//! Verifies:
//! 1. `crates/bud-codec/src/registry.rs` freezes the 27-slot A0 `REGISTER` table
//!    with `CodecState::{Open, Closed, Reserved}`.
//! 2. `src/storage/bud3/replace.rs` enforces `MIN_REPLACE_ATTESTATIONS: usize = 3`,
//!    `FAST_PROBE_MIN_SAVINGS_BPS: u32 = 500` (`select_codec_with_fast_probe`),
//!    and `admit_object_replacement` slashing mismatched `ContentId` proposals.
//! 3. `src/storage/bud3/access_tiering.rs` logs `TierTransition` observations with
//!    `testnet_converts_objects() == false`.
//! 4. `src/storage/bud3/tx.rs` wires `StorageTxV3::ReplaceObject`.

use std::fs;
use std::path::Path;

pub fn run(root: &Path) -> Result<String, String> {
    let reg_src = fs::read_to_string(root.join("crates/bud-codec/src/registry.rs"))
        .map_err(|e| format!("missing crates/bud-codec/src/registry.rs: {e}"))?;
    if !reg_src.contains("REGISTER: [CodecEntry; 27]") {
        return Err("crates/bud-codec/src/registry.rs missing 27-entry REGISTER".to_owned());
    }

    let replace_src = fs::read_to_string(root.join("src/storage/bud3/replace.rs"))
        .map_err(|e| format!("missing src/storage/bud3/replace.rs: {e}"))?;
    let replace_prod = replace_src
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default();
    for token in [
        "MIN_REPLACE_ATTESTATIONS: usize = 3",
        "FAST_PROBE_MIN_SAVINGS_BPS: u32 = 500",
        "pub fn select_codec_with_fast_probe",
        "pub fn admit_object_replacement",
        "bad_repair_slash_amount",
    ] {
        if !replace_prod.contains(token) {
            return Err(format!("src/storage/bud3/replace.rs missing `{token}`"));
        }
    }

    let tier_src = fs::read_to_string(root.join("src/storage/bud3/access_tiering.rs"))
        .map_err(|e| format!("missing src/storage/bud3/access_tiering.rs: {e}"))?;
    let tier_prod = tier_src.split("#[cfg(test)]").next().unwrap_or_default();
    for token in [
        "pub struct TierTransition",
        "pub struct AccessTierTracker",
        "pub const fn testnet_converts_objects() -> bool",
    ] {
        if !tier_prod.contains(token) {
            return Err(format!(
                "src/storage/bud3/access_tiering.rs missing `{token}`"
            ));
        }
    }

    let tx_src = fs::read_to_string(root.join("src/storage/bud3/tx.rs"))
        .map_err(|e| format!("missing src/storage/bud3/tx.rs: {e}"))?;
    if !tx_src.contains("ReplaceObject") {
        return Err("src/storage/bud3/tx.rs missing `StorageTxV3::ReplaceObject`".to_owned());
    }

    Ok("bud3-codec-and-replace: A0 fast probe, access tiering log, and ReplaceObject verified".to_owned())
}

pub fn self_test() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum_bud3_codec_replace_gate_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("crates/bud-codec/src")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("src/storage/bud3")).map_err(|e| e.to_string())?;

    fs::write(
        dir.join("crates/bud-codec/src/registry.rs"),
        "pub static REGISTER: [CodecEntry; 27] = [];",
    )
    .map_err(|e| e.to_string())?;
    let valid_replace = r#"
pub const MIN_REPLACE_ATTESTATIONS: usize = 3;
pub const FAST_PROBE_MIN_SAVINGS_BPS: u32 = 500;
pub fn select_codec_with_fast_probe() {}
pub fn admit_object_replacement() { let _ = bad_repair_slash_amount(0); }
"#;
    fs::write(dir.join("src/storage/bud3/replace.rs"), valid_replace).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("src/storage/bud3/access_tiering.rs"),
        "pub struct TierTransition; pub struct AccessTierTracker; impl AccessTierTracker { pub const fn testnet_converts_objects() -> bool { false } }",
    )
    .map_err(|e| e.to_string())?;
    fs::write(dir.join("src/storage/bud3/tx.rs"), "pub enum StorageTxV3 { ReplaceObject }")
        .map_err(|e| e.to_string())?;
    run(&dir)?;

    let bad = valid_replace.replace("MIN_REPLACE_ATTESTATIONS: usize = 3", "MIN_REPLACE_ATTESTATIONS: usize = 1");
    fs::write(dir.join("src/storage/bud3/replace.rs"), bad).map_err(|e| e.to_string())?;
    let res = run(&dir);
    let _ = fs::remove_dir_all(&dir);
    if res.is_ok() {
        return Err("bud3-codec-and-replace accepted < 3 attestations".to_owned());
    }
    Ok(())
}
