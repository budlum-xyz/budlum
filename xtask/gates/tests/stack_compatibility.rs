//! Regression locks for the open-PR stack compatibility work.
//!
//! These tests read repository files only. They pin the gate wiring and the
//! audit result so the pre-merge syntax check cannot be removed, and the
//! mechanical audit cannot quietly start skipping PR heads.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    std::env::var_os("BUDLUM_ROOT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The gate is a real registered gate, not a file nobody runs.
#[test]
fn rust_syntax_gate_is_wired() {
    let main = read("xtask/gates/src/main.rs");
    assert!(
        main.contains("pub mod rust_syntax_is_parseable;"),
        "the gate module is not declared"
    );
    assert!(
        main.contains("name: \"rust-syntax-is-parseable\"")
            && main.contains("gates::rust_syntax_is_parseable::self_test"),
        "the gate is not in the --all registry with its canary"
    );
    let gate = read("xtask/gates/src/gates/rust_syntax_is_parseable.rs");
    assert!(gate.contains("pub fn run("), "the gate has no run");
    assert!(
        gate.contains("pub fn self_test(") && gate.contains("canary"),
        "the gate has no self-test canaries"
    );
}

/// The live compatibility audit saw every head, found the broken branches,
/// and the integrated tree has no syntax findings.
#[test]
fn compatibility_audit_covers_the_live_stack() {
    let text = read("docs/audit/STACK_COMPATIBILITY_DATA_2026-11-06.json");
    let data: serde_json::Value =
        serde_json::from_str(&text).expect("the audit data is valid JSON");
    let open = data["open_prs"].as_u64().expect("open_prs");
    let seen = data["heads_seen"].as_u64().expect("heads_seen");
    assert_eq!(open, seen, "some PR heads were skipped by the audit");
    assert_eq!(
        data["heads_missing"].as_array().map(Vec::len),
        Some(0),
        "the audit reports missing heads"
    );
    let broken = data["branches_with_syntax_errors"]
        .as_array()
        .expect("branches_with_syntax_errors");
    let numbers: Vec<u64> = broken
        .iter()
        .filter_map(|b| b["pr"].as_u64())
        .collect();
    for expected in [8u64, 9, 55] {
        assert!(
            numbers.contains(&expected),
            "PR #{expected} is missing from the broken-branch list: {numbers:?}"
        );
    }
    assert_eq!(
        data["integrated_tree_syntax_errors"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "the integrated tree has syntax findings"
    );
}

/// The audit tool and its local replica are both present and both name the
/// grammar they use. A tree-sitter parse cannot be replaced by a grep.
#[test]
fn audit_tool_and_replica_are_present() {
    let tool = read("ops/scripts/stack_compatibility_audit.py");
    assert!(
        tool.contains("tree_sitter") && tool.contains("PARSER.parse"),
        "the audit tool does not parse with the Rust grammar"
    );
    let replica = read("ops/scripts/rust_syntax_gate_replica.py");
    assert!(
        replica.contains("--self-test") && replica.contains("def findings("),
        "the gate replica is not self-tested"
    );
}
