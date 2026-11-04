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

/// BLG-029: the forwarded client address is the rightmost `X-Forwarded-For`
/// entry, honoured only from a trusted proxy.
#[test]
fn audit_lane_d_blg_029_forwarded_for_uses_the_rightmost_entry() {
    let src = read_repo("src/rpc/server.rs");
    let body = between(&src, "fn extract_client_ip<B>", "\n}\n");
    assert!(body.contains(".split(',').next_back()"));
    assert!(!body.contains(".split(',').next()"));
    assert!(body.contains("request_came_from_trusted_proxy(config, req)"));
}

/// BLG-068: budscan refuses a resolver-supplied `storage_root` the registry
/// does not hold, requires the explicit `bud://` mark for a content id, and
/// refuses bidi-override and path-traversal spellings.
#[test]
fn audit_lane_d_blg_068_budscan_does_not_badge_unproven_roots() {
    let bns = read_repo("crates/budscan/src/bns_proof.rs");
    assert!(bns.contains("fn a_storage_root_the_registry_does_not_hold_is_refused"));
    assert!(bns.contains("e.storage_root == resolved.storage_root"));
    let query = read_repo("crates/budscan/src/query.rs");
    assert!(query.contains("fn explicit_prefixes_remove_the_ambiguity"));
    assert!(query.contains("fn a_bidi_override_is_refused_not_displayed"));
    assert!(query.contains("fn path_traversal_never_becomes_a_name"));
}

/// BLG-121: budscan checks the 48-byte Arweave data root, refuses a truncated
/// root, treats an expired name as bound to nothing, and keeps patch paths
/// inside their tree.
#[test]
fn audit_lane_d_blg_121_budscan_arweave_expiry_and_patch_paths() {
    let arweave = read_repo("crates/budscan/src/arweave.rs");
    assert!(arweave.contains("pub fn data_root(data: &[u8]) -> [u8; 48]"));
    assert!(arweave.contains("fn a_truncated_expected_root_is_rejected_not_verified"));
    let bns = read_repo("crates/budscan/src/bns_proof.rs");
    assert!(bns.contains("if entry.expires_at <= current_epoch"));
    assert!(bns.contains("an expired name binds to no content"));
    let patch = read_repo("crates/budscan/src/patchset.rs");
    assert!(patch.contains("segment == \"..\""));
}

/// BLG-010: the PKCS#11 key label is part of the key search at connect time,
/// and several keys are never guessed between.
#[test]
fn audit_lane_d_blg_010_pkcs11_label_is_applied_before_the_key_is_bound() {
    let src = read_repo("src/crypto/pkcs11.rs");
    let connect = between(&src, "fn connect(", "fn extract_ed25519_public_key");
    let extract = connect
        .find("extract_ed25519_public_key(&session, key_label.as_deref())")
        .expect("connect must search the public key with the label");
    let binding = connect
        .find("verify_key_binding(&session, key_label.as_deref()")
        .expect("connect must prove the key binding with the label");
    assert!(extract < binding);
    assert!(src.contains("fn require_single_key"));
    assert!(src.contains("refusing to guess, set an explicit key label"));
}

/// BLG-011: the shipped systemd unit supplies the RPC key variable and closes
/// core dumps instead of opening them.
#[test]
fn audit_lane_d_blg_011_service_unit_sets_rpc_key_and_closes_core_dumps() {
    let unit = read_repo("ops/budlum-core.service");
    assert!(unit.contains("LimitCORE=0"));
    assert!(!unit.contains("LimitCORE=infinity"));
    assert!(unit.contains("Environment=BUDLUM_RPC_API_KEY_ENV=BUDLUM_RPC_API_KEY"));
    assert!(unit.contains("EnvironmentFile=/etc/budlum/rpc.env"));
}

/// BLG-013: `--all-features` is a valid composition (no `compile_error!`) and
/// CI holds it with a must-build canary.
#[test]
fn audit_lane_d_blg_013_all_features_is_a_buildable_composition() {
    fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, hits);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                if text.contains(concat!("compile", "_error!")) {
                    hits.push(p.display().to_string());
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(&repo_root().join("src"), &mut hits);
    assert!(hits.is_empty(), "feature-exclusion macros found: {hits:?}");
    let ci = read_repo(".github/workflows/ci.yml");
    assert!(ci.contains("Feature canary - --all-features MUST BUILD"));
    assert!(ci.contains("cargo check --all-features"));
}

/// BLG-014: the backup drill fails on a non-zero `--check-db` exit code, not
/// only on output text.
#[test]
fn audit_lane_d_blg_014_backup_drill_checks_the_exit_status() {
    let src = read_repo("xtask/tools/src/backup_drill.rs");
    let prod = production_of(&src);
    assert!(prod.contains("\"--check-db\""));
    assert!(prod.contains("!check.status.success()"));
    assert!(prod.contains("!status.success()"));
}

/// BLG-015: every standalone Rust package has its unit tests run by CI.
#[test]
fn audit_lane_d_blg_015_ci_runs_every_standalone_package_test_suite() {
    let ci = read_repo(".github/workflows/ci.yml");
    for pkg in [
        "crates/ai-inference",
        "crates/bpqs",
        "crates/budscan",
        "crates/note-packing",
        "crates/wallet-core",
        "xtask/tools",
    ] {
        assert!(
            ci.contains(&format!("cargo test --manifest-path {pkg}/Cargo.toml"))
                || ci.contains(&format!("cargo test --release --manifest-path {pkg}/Cargo.toml")),
            "CI does not run the unit tests of {pkg}"
        );
    }
}

/// BLG-026 (fixed parts): no empty `assert!(true)` gate test remains in the
/// wallet crate, and the V3 wallet uses a 24-word phrase and an
/// NFKD-normalised password.
#[test]
fn audit_lane_d_blg_026_no_vacuous_gate_test_and_v3_wallet_is_24_words() {
    for rel in ["crates/wallet-core/src/lib.rs", "crates/wallet-core/src/wallet_v3.rs"] {
        assert!(!read_repo(rel).contains("assert!(true"));
    }
    let v3 = read_repo("crates/wallet-core/src/wallet_v3.rs");
    assert!(v3.contains("24 words (256 bits of entropy)"));
    assert!(v3.contains("InvalidEntropy"));
    assert!(read_repo("crates/wallet-core/Cargo.toml").contains("NFKD normalized"));
}
