//! Required exact named tests: the Garden infrastructure acceptance suite.
//!
//! The tests live in `tests/garden/garden_acceptance.rs` and drive real
//! `budlum-core` nodes in separate processes. The cargo test log must
//! contain the full line `test <name> ... ok` for every name below, so a
//! test that was renamed, deleted or filtered out fails the gate instead of
//! shrinking the acceptance suite silently.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "garden_invite_same_record",
    "garden_invite_any_validator",
    "garden_invite_rejected",
    "garden_invite_size",
    "garden_invite_host_moves",
    "garden_invite_while_frozen",
    "garden_every_validator_works",
    "garden_storage_all_parts",
    "garden_storage_shrink",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "garden-acceptance")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "garden-acceptance")
}
