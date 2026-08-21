//! Required named tests: node classification.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "node_mode_maps_roles",
    "node_archive_rejects_pruning",
    "node_archive_requires_backups",
    "node_full_pruning_requires_finalized_snapshot_retention",
    "node_full_pruning_requires_nonzero_retention",
    "node_prune_decision_distinguishes_full_and_archive",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Node classification")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Node classification")
}
