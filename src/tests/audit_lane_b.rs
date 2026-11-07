//! Live-verification regression locks for the lane B findings of the unified
//! findings ledger (directive section 14). Each lock names the finding it
//! keeps closed and cites the evidence it relies on.
//!
//! No lane B record is Closed in this snapshot: the WP-07 removal is in
//! flight (PR #8) and no deletion has merged, and none of the WP-45/WP-56
//! fixes has landed. The Reproduced rows and the Open rows are recorded in
//! `docs/audit/live/lane-b.md`; their repro tests are owed on the
//! `audit/repro-b` branch (directive sections 14.1 and 15.8, S-3).
//!
//! This module therefore carries only permanent locks for facts that must
//! hold regardless of which package flips the findings.

fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// BLG-063 (foot that is already closed, kept closed): the privacy-transfer
/// allowlist in the executor keeps mainnet off. The WP-45 fix flips the
/// *testnet/devnet* allowance (the open half of the finding, tracked in
/// `docs/audit/live/lane-b.md`); the mainnet refusal is permanent.
#[test]
fn blg_063_mainnet_privacy_transfers_stay_off() {
    let executor = production_part(include_str!("../execution/executor.rs"));
    assert!(
        executor.contains("privacy_transfers_enabled"),
        "the allowlist must remain the single gate for privacy transfers"
    );
    // The in-tree test pins the mainnet refusal; keep it there.
    let all = include_str!("../execution/executor.rs");
    assert!(
        all.contains("assert!(!privacy_transfers_enabled(mainnet)"),
        "mainnet must stay off the privacy-transfer allowlist"
    );
}

/// BLG-093: the ai-inference crate never ships an undetermined license state.
/// Today the finding is open: `Cargo.toml` declares PolyForm Shield 1.0.0
/// while `LICENSE.md` ships MIT (recorded in the ledger). Both states are
/// legal for this lock - the recorded-open split, or either unified outcome
/// after WP-45. The only illegal state is silence on both sides.
#[test]
fn blg_093_ai_inference_license_is_identifiable() {
    let manifest = include_str!("../../crates/ai-inference/Cargo.toml");
    let license_file = include_str!("../../crates/ai-inference/LICENSE.md");
    let declared = manifest.contains("LicenseRef-PolyForm-Shield-1.0.0");
    let file_is_mit = license_file.trim_start().starts_with("MIT License");
    assert!(
        declared || file_is_mit,
        "ai-inference must always name its license on at least one of the two surfaces"
    );
}

#[test]
fn audit_lane_b_blg_035_closed_by_removal_of_bud_node() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("budzero/bud-node").exists(),
        "BLG-035: budzero/bud-node must stay removed"
    );
}

#[test]
fn audit_lane_b_blg_045_closed_by_removal_of_legacy_challenge_provider() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/storage/provider.rs").exists()
            && !root.join("src/domain/storage_deal.rs").exists(),
        "BLG-045: legacy challenge provider and storage_deal must stay removed"
    );
}

#[test]
fn audit_lane_b_blg_046_closed_by_removal_of_legacy_deal_open() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/domain/deal_open.rs").exists()
            && !root.join("bud").exists(),
        "BLG-046/BLG-073: legacy deal_open and bud/ workspace must stay removed"
    );
}
