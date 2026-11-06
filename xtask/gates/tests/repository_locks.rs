//! Each test pins one finding of the CI, gate and supply-chain
//! family to the repository state, so the fix cannot silently regress.
//!
//! The tests read repository files only. They live in the gate crate so they
//! build in seconds, apart from the node crate's test target.

use std::path::{Path, PathBuf};

/// The repository root; `BUDLUM_ROOT` points the tests at a staged copy (the
/// same switch the gate binary has), which is how a test is shown red against
/// the tree as it was before its fix.
fn root() -> PathBuf {
    std::env::var_os("BUDLUM_ROOT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Every standalone workspace that ships a binary pins the release
/// hardening pair (`overflow-checks = true`, `panic = "abort"`).
#[test]
fn standalone_workspaces_pin_release_hardening() {
    let mut missing = Vec::new();
    for manifest in [
        "kani/Cargo.toml",
        "xtask/gates/Cargo.toml",
        "xtask/release/Cargo.toml",
        "xtask/tools/Cargo.toml",
        "crates/bpqs/Cargo.toml",
        "crates/note-packing/Cargo.toml",
    ] {
        let text = read(manifest);
        let table = text
            .split("[profile.release]")
            .nth(1)
            .map_or("", |t| t.split("\n[").next().unwrap_or(t));
        if !(table.contains("overflow-checks = true") && table.contains("panic = \"abort\"")) {
            missing.push(manifest);
        }
    }
    assert!(
        missing.is_empty(),
        "no release hardening pins in {missing:?}"
    );
}

/// The tool sources carry no leftover Turkish messages.
#[test]
fn tool_sources_have_no_turkish_messages() {
    let mut hits = Vec::new();
    for file in [
        "xtask/tools/src/prepush.rs",
        "xtask/tools/src/seed_corpus.rs",
    ] {
        let text = read(file);
        for word in ["bulunamadi", "Varsayilan", "cikti dizini"] {
            if text.contains(word) {
                hits.push(format!("{file}: {word}"));
            }
        }
    }
    assert!(hits.is_empty(), "Turkish left in tools: {hits:?}");
}

/// No workflow names the deleted `fix/architecture-tip-adlari` branch,
/// and Dependabot covers every tracked `Cargo.lock` directory.
#[test]
fn workflows_and_dependabot_are_current() {
    let dir = root().join(".github/workflows");
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{e}"))
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if std::path::Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yml"))
            && std::fs::read_to_string(entry.path())
                .is_ok_and(|t| t.contains("fix/architecture-tip-adlari"))
        {
            stale.push(name);
        }
    }
    stale.sort();
    assert!(
        stale.is_empty(),
        "workflows naming the deleted branch: {stale:?}"
    );

    let dependabot = read(".github/dependabot.yml");
    for lock_dir in [
        "/bud",
        "/budzero",
        "/fuzz",
        "/crates/ai-inference",
        "/crates/bpqs",
        "/crates/budscan",
        "/crates/note-packing",
        "/crates/wallet-core",
        "/xtask/gates",
        "/xtask/release",
        "/xtask/tools",
    ] {
        assert!(
            dependabot.contains(&format!("\"{lock_dir}\"")),
            "dependabot.yml does not cover {lock_dir}"
        );
    }
}

/// The throughput benchmarks do not clamp sizes and times to
/// `u32::MAX`, which silently capped any larger measurement.
#[test]
fn micro_benches_do_not_clamp_to_u32_max() {
    for file in [
        "benches/micro/ratio_rayon.rs",
        "benches/micro/erasure_rows.rs",
    ] {
        let text = read(file);
        for clamp in [
            "u32::try_from(bytes)",
            "u32::try_from(serial.as_micros())",
            "u32::try_from(pool.as_micros())",
        ] {
            assert!(!text.contains(clamp), "{file} clamps with `{clamp}`");
        }
    }
}

/// The kani workspace carries a `Cargo.lock`, so `--locked` resolves
/// and the lock-freshness step in CI sees it.
#[test]
fn kani_workspace_has_a_lockfile() {
    let lock = read("kani/Cargo.lock");
    assert!(lock.contains("name = \"budlum-kani\""));
}

/// The indexer binary has an explicit `[[bin]]` entry.
#[test]
fn indexer_binary_is_registered() {
    let manifest = read("Cargo.toml");
    assert!(
        manifest.contains("name = \"budlum-indexer\"\npath = \"src/bin/budlum-indexer.rs\""),
        "no explicit [[bin]] for budlum-indexer"
    );
}

#[test]
fn external_planning_directive_and_wrapper_stay_outside_repository() {
    let ignore = read(".gitignore");
    for name in ["THE_BUDLUM_DIREKTIF.md", "arena_claude.py"] {
        assert!(
            !root().join(name).exists(),
            "non-English external file must stay outside the repository tree: {name}"
        );
        assert!(
            ignore.contains(&format!("/{name}")),
            ".gitignore must keep /{name} out of git status"
        );
    }
}

#[test]
fn required_fee_is_classified_as_a_read() {
    let gate = read("xtask/gates/src/gates/no_out_of_block_consensus_writes.rs");
    let names = gate
        .split("const READ_NAMES: &[&str] = &[")
        .nth(1)
        .and_then(|t| t.split("];").next())
        .unwrap_or_default();
    assert!(
        names.contains("\"required_fee\""),
        "required_fee must be listed in READ_NAMES"
    );
}

#[test]
fn base_tree_bud3_and_lockfile_regressions_stay_closed() {
    let filter = read("src/storage/bud3/dedup_index.rs");
    assert!(filter.contains("bits.div_ceil(64)"));
    assert!(!filter.contains("((bits + 63) / 64)"));
    assert!(filter.contains("lanes.iter_mut().zip(digest.chunks_exact(8))"));
    assert!(!filter.contains("lanes[i] = v"));

    let http = read("src/bin/support/http.rs");
    assert!(http.contains("octets.get_mut(8..)"));

    let registry = read("src/storage/bud3/registry.rs");
    assert!(registry.contains("impl serde::Serialize for Bud3Registry"));
    assert!(registry.contains("probe.mark_unseen(holder)"));

    for lock in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let body = read(lock);
        assert!(
            body.contains("name = \"bud-codec\""),
            "{lock} must lock bud-codec"
        );
    }

    let osv = read(".github/workflows/osv-scanner.yml");
    for lock in [
        "crates/bud-codec/Cargo.lock",
        "crates/uel-abi/Cargo.lock",
        "kani/Cargo.lock",
    ] {
        assert!(
            osv.contains(&format!("--lockfile={lock}")),
            "osv-scanner.yml must scan {lock}"
        );
    }
}
