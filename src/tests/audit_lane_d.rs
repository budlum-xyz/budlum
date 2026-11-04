//! Lane D live-verification regression tests (WP-01 to WP-04).
//!
//! Only "previously fixed" findings live here: each test is green and stays
//! permanent (directive section 14.1 rule 7). Repro tests for findings that are
//! still open live on the `audit/repro-d` branch and do not merge.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Text of a repository file; a missing file fails the test with its path.
fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Source of a production file with its `#[cfg(test)]` tail cut off.
fn production_of(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap_or(src)
}

/// The text from `start` up to (not including) the next `end` marker.
fn between<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let from = src
        .find(start)
        .unwrap_or_else(|| panic!("marker not found: {start}"));
    let rest = &src[from..];
    let to = rest[start.len()..]
        .find(end)
        .map_or(rest.len(), |i| i + start.len());
    &rest[..to]
}

/// BLG-117 (fixed parts): the wallet Poseidon is the shared note-packing
/// permutation, the recipient tag is a full field element, and the recovery
/// proposal digest binds chain id and account nonce.
#[test]
fn audit_lane_d_blg_117_poseidon_tag_and_recovery_digest_are_fixed() {
    let privacy = read_repo("crates/wallet-core/src/privacy_crypto.rs");
    assert!(privacy.contains("use budlum_note_packing::poseidon;"));
    assert!(privacy.contains("poseidon::permute(state)[0]"));
    assert!(privacy.contains("assert_eq!(poseidon::FULL_ROUNDS, 8);"));
    let transfer = read_repo("crates/wallet-core/src/privacy_transfer.rs");
    assert!(transfer.contains("pub recipient_tag: u64,"));
    assert!(!transfer.contains("recipient_tag: i32"));
    let lib = read_repo("crates/wallet-core/src/lib.rs");
    let digest = between(&lib, "pub fn digest(&self) -> [u8; 32] {", "\n    }\n");
    assert!(digest.contains("hasher.update(self.chain_id.to_be_bytes());"));
    assert!(digest.contains("hasher.update(self.account_nonce.to_be_bytes());"));
}

/// BLG-150 (fixed part): the default prevote and precommit signatures are
/// domain-separated from the block signature.
#[test]
fn audit_lane_d_blg_150_vote_signatures_are_domain_separated_from_block() {
    let src = read_repo("src/crypto/signer.rs");
    assert!(src.contains("b\"BDLM_PREVOTE_ED25519_V1\""));
    assert!(src.contains("b\"BDLM_PRECOMMIT_ED25519_V1\""));
}
