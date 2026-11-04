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

/// BLG-013: `--all-features` is a valid composition (no feature-exclusion
/// macro anywhere in src/) and CI holds it with a must-build canary.
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

/// BULGU-011: the CORS layer never reflects request headers; allowed headers
/// are a fixed list, an empty origin list emits nothing, and credentials are
/// never allowed.
#[test]
fn audit_lane_d_bulgu_011_cors_does_not_reflect_request_headers() {
    let src = read_repo("src/rpc/server.rs");
    let prod = production_of(&src);
    assert!(!prod.contains("access-control-request-headers"));
    assert!(!prod.contains("access-control-allow-credentials"));
    assert!(prod.contains("HeaderValue::from_static(\"content-type, x-api-key, authorization\")"));
    assert!(prod.contains("if config.cors_origins.is_empty() {\n        return CorsOutcome::NotApplicable;"));
}

/// TEST-GAP-02: Kani carries a harness family for each of the four targets
/// SECURITY.md names.
#[test]
fn audit_lane_d_test_gap_02_kani_covers_the_four_security_md_targets() {
    let kani = read_repo("kani/src/lib.rs");
    for harness in [
        "fn penalty_never_exceeds_stake",
        "fn merkle_sibling_index_is_in_bounds",
        "fn classify_pq_signature_len",
        "fn bitmap_cannot_vote_more_stake_than_the_set_holds",
    ] {
        assert!(kani.contains(harness), "missing {harness}");
    }
    assert!(read_repo("docs/SECURITY.md").contains(
        "bond arithmetic, QC Merkle paths, PQ signature length classification, finality bitmap accounting"
    ));
}

/// BLG-030: the development credit paths refuse every chain id except devnet
/// (testnet included), and out-of-block RPC writers are operator-only refusals.
#[test]
fn audit_lane_d_blg_030_testnet_development_credit_is_refused() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::core::chain_config::Network;
    use std::sync::Arc;
    let addr = Address::from_hex(&"01".repeat(32)).unwrap();
    let testnet = Network::Testnet.chain_id().value();
    let genesis = crate::chain::genesis::GenesisConfig::new(testnet);
    let mut bc =
        Blockchain::new_with_genesis(Arc::new(PoWEngine::new(0)), None, testnet, None, Some(genesis));
    assert!(bc.fund_development_account(&addr).is_err());
    assert!(bc.credit_development_account(&addr, 5).is_err());
    let devnet = Network::Devnet.chain_id().value();
    let mut dev = Blockchain::new(Arc::new(PoWEngine::new(0)), None, devnet, None);
    assert!(dev.fund_development_account(&addr).is_ok());

    let table = read_repo("src/rpc/method_class.rs");
    for method in [
        "bud_registerExternalDomain",
        "bud_submitExternalEvidence",
        "bud_readmitExternalDomain",
        "bud_scheduleExternalFork",
        "bud_slashExternalProver",
        "bud_bondExternalProver",
        "bud_setExternalQuorumPolicy",
    ] {
        assert!(
            table.contains(&format!("row(\"{method}\", Operator, Refused)")),
            "{method} must be an operator-only refusal"
        );
    }
}

/// BLG-098 (fixed part): the clap-skipped RPC fields are restored to the secure
/// defaults before any file or environment overlay.
#[test]
fn audit_lane_d_blg_098_secure_rpc_defaults_survive_clap_skip() {
    let cfg = crate::cli::commands::NodeConfig::default();
    assert!(cfg.rpc_auth_required);
    assert_eq!(cfg.rpc_allowed_ips, vec!["127.0.0.1".to_string(), "::1".to_string()]);
    let src = read_repo("src/cli/commands.rs");
    let load = between(&src, "pub fn load_with_file(&mut self) {", "if let Some(path)");
    assert!(load.contains("self.apply_secure_rpc_defaults();"));
}

/// BLG-099: the API-key comparison walks the expected value in full; equal keys
/// match, any difference or length mismatch refuses.
#[test]
fn audit_lane_d_blg_099_constant_time_compare_has_no_self_comparison() {
    use crate::rpc::server::constant_time_eq_str as eq;
    assert!(eq("secret-key", "secret-key"));
    assert!(!eq("secret-kex", "secret-key"));
    assert!(!eq("secret", "secret-key"));
    assert!(!eq("secret-key-and-more", "secret-key"));
    assert!(!eq("", "secret-key"));
    assert!(eq("", ""));
    let src = read_repo("src/rpc/server.rs");
    let body = between(&src, "pub fn constant_time_eq_str", "\n}\n");
    assert!(!body.contains("a_b.ct_eq(a_b)"));
    assert!(!body.contains("b_b.ct_eq(b_b)"));
}

/// BLG-200 (fixed part): `BlsKeypair::from_bytes` refuses the zero secret and a
/// malformed encoding, and finality refuses an identity public key.
#[test]
fn audit_lane_d_blg_200_bls_from_bytes_refuses_zero_secret() {
    assert!(crate::crypto::primitives::BlsKeypair::from_bytes(&[0u8; 32 + 96]).is_err());
    assert!(crate::crypto::primitives::BlsKeypair::from_bytes(&[1u8; 5]).is_err());
    let finality = read_repo("src/chain/finality.rs");
    assert!(finality.contains("BLS public key is identity or not in the prime-order subgroup"));
}
