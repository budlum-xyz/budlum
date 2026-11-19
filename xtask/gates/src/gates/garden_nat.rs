//! Required exact named test: Garden behind real address translation.
//!
//! The test lives in `tests/garden/garden_nat.rs` and runs real
//! `budlum-core` nodes in network namespaces. The cargo test log must
//! contain the full line `test <name> ... ok`, so a test that was renamed,
//! deleted or filtered out fails the gate instead of passing with nothing
//! run.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &["garden_join_behind_real_nat"];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "garden-nat")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "garden-nat")
}
