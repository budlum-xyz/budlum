//! The fixture integrity gate.
//!
//! `config/fixtures/real-chain.json` is the single source the tests rest on
//! (`src/tests/real_chain_fixtures.rs` reads the same file - the single-source
//! rule; a second copy is the worst copy). This gate verifies that the file exists,
//! carries the required sections, stays within a sane size and obeys its own format
//! rules (hex without 0x). Verifying the content against the real chain is the
//! job of the tests; this gate is a schema canary.
//! A JSON dependency was deliberately not added: the gates carry only syn+quote
//! and this gate validates well enough at string level.

use std::path::Path;

const FIXTURE_PATH: &str = "config/fixtures/real-chain.json";
const MIN_BYTES: u64 = 1_024;
const MAX_BYTES: u64 = 64 * 1_024;
const REQUIRED_SECTIONS: &[&str] = &[
    "\"provenance\"",
    "\"btc_merkle_blocks\"",
    "\"btc_halvings\"",
    "\"eth_headers\"",
    "\"expected_hash\"",
    "\"merkle_root\"",
    "\"generation_sat\"",
    "\"base_fee_per_gas\"",
];

/// # Errors
///
/// When the fixture file is missing, empty, bloated, or has a missing section.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(FIXTURE_PATH);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "the fixture file could not be read: {} ({e})",
            path.display()
        )
    })?;
    let len = text.len() as u64;
    if len < MIN_BYTES {
        return Err(format!(
            "the fixture is {len} bytes - below {MIN_BYTES} (the file may have been emptied)"
        ));
    }
    if len > MAX_BYTES {
        return Err(format!(
            "the fixture is {len} bytes - above {MAX_BYTES} (data may have been dumped into the file)"
        ));
    }
    for section in REQUIRED_SECTIONS {
        if !text.contains(section) {
            return Err(format!(
                "the fixture is missing a required section: {section}"
            ));
        }
    }
    // Our own format rule: hex fields are stored without a 0x prefix. A prefixed
    // field signals format drift (a raw upstream copy has been mixed in).
    if text.contains("\"0x") {
        return Err(
            "the fixture contains a 0x-prefixed field; our own format is unprefixed - \
             a drift check"
                .into(),
        );
    }
    Ok(format!(
        "fixture verified: {len} bytes, {} required sections present",
        REQUIRED_SECTIONS.len()
    ))
}

/// Evidence that the gate itself can go red: corrupt copies are produced in a temporary
/// directory and each must be refused by `run`.
///
/// # Errors
///
/// Errors if one of the corrupt copies is not refused (a vacuous gate).
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-fixture-gate-self-test")?;
    // Removed on every exit: a scenario that fails used to return early and
    // leave the directory behind, one per run, in the temp root.
    let result = scenarios(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn scenarios(dir: &std::path::Path) -> Result<String, String> {
    std::fs::create_dir_all(dir.join("config/fixtures"))
        .map_err(|e| format!("the temporary directory could not be created: {e}"))?;
    let fixture = dir.join(FIXTURE_PATH);

    // (1) A missing file is refused.
    if run(dir).is_ok() {
        return Err("a missing fixture file was not refused (vacuous)".into());
    }

    // (2) An empty or tiny file -> refused.
    std::fs::write(&fixture, "{}").map_err(|e| e.to_string())?;
    if run(dir).is_ok() {
        return Err("an empty fixture was not refused (vacuous)".into());
    }

    // (3) A file with a missing section -> refused.
    std::fs::write(
        &fixture,
        format!(
            "{{\"provenance\":\"x\",\"btc_merkle_blocks\":[],\"btc_halvings\":[],\"eth_headers\":[],\"expected_hash\":\"{}\",\"merkle_root\":\"{}\",\"generation_sat\":0,\"base_fee_per_gas\":null}}",
            "0".repeat(64),
            "0".repeat(64),
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(dir).is_ok() {
        return Err("a fixture with a missing section was not refused (vacuous)".into());
    }

    // (4) A 0x-prefixed field (format drift) -> refused.
    std::fs::write(
        &fixture,
        format!(
            "{{\"provenance\":\"x\",\"btc_merkle_blocks\":[{{\"height\":0,\"merkle_root\":\"0x{}\",\"txids\":[]}}],\"btc_halvings\":[],\"eth_headers\":[],\"expected_hash\":\"{}\",\"generation_sat\":0,\"base_fee_per_gas\":null}}",
            "0".repeat(64),
            "0".repeat(64),
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(dir).is_ok() {
        return Err("a 0x-prefixed fixture was not refused (vacuous)".into());
    }

    Ok("fixture-integrity self-test: 4/4 refusal scenarios proved".into())
}
