//! WP-42 closures: each test pins one finding of the CI, gate and supply-chain
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

/// BLG-085: every standalone workspace that ships a binary pins the release
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

/// BLG-086: the tool sources carry no leftover Turkish messages.
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
