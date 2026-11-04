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

/// BLG-012: the coverage ratchet reads `totals.lines.percent`, not the first
/// file's percentage, and refuses a non-finite baseline.
#[test]
fn audit_lane_d_blg_012_coverage_gate_reads_the_total_and_refuses_nan() {
    let src = read_repo("xtask/gates/src/gates/coverage.rs");
    let prod = production_of(&src);
    assert!(prod.contains(".get(\"totals\")"));
    assert!(prod.contains("is_finite()"));
    assert!(src.contains("fn the_total_is_read_not_the_first_file"));
}

/// BLG-016: no lock file pins a crate below the patched version of the
/// advisories seen on 2026-11-04 (rustls, quinn-proto, rustls-webpki,
/// webpki-roots, ctutils). Versions are compared numerically.
#[test]
fn audit_lane_d_blg_016_lockfiles_do_not_pin_known_vulnerable_versions() {
    fn ver(s: &str) -> Vec<u64> {
        s.split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }
    let floors: &[(&str, &str)] = &[
        ("rustls", "0.23.46"),
        ("quinn-proto", "0.11.18"),
        ("rustls-webpki", "0.103.16"),
        ("webpki-roots", "1.0.10"),
        ("ctutils", "0.4.4"),
    ];
    fn find(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                if name != "target" && name != ".git" && name != "node_modules" {
                    find(&p, out);
                }
            } else if name == "Cargo.lock" {
                out.push(p);
            }
        }
    }
    let mut locks = Vec::new();
    find(&repo_root(), &mut locks);
    assert!(locks.len() >= 12, "expected the 12 tracked lock files");
    for lock in locks {
        let text = std::fs::read_to_string(&lock).unwrap();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let Some(name) = line.strip_prefix("name = \"").and_then(|r| r.strip_suffix('"')) else {
                continue;
            };
            let Some(version) = lines
                .next()
                .and_then(|l| l.strip_prefix("version = \""))
                .and_then(|r| r.strip_suffix('"'))
            else {
                continue;
            };
            for (krate, floor) in floors {
                if name == *krate && ver(version)[..2] == ver(floor)[..2] {
                    assert!(
                        ver(version) >= ver(floor),
                        "{}: {krate} {version} is below the patched {floor}",
                        lock.display()
                    );
                }
            }
        }
    }
}
