//! Required exact named tests: bns.
//!
//! Ported from scripts/check-*.sh. The cargo test log must contain the full
//! line `test tests::bns::<name> ... ok` for every name, so a substring (e.g.
//! `invariant_1` matching `invariant_10`) cannot satisfy the gate. The names
//! span two module roots (`tests::bns::tests` and `tests::bns_expanded`), so
//! they are carried here as full test paths.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "tests::bns::tests::test_bns_registration_and_resolution",
    "tests::bns::tests::test_bns_expiration",
    "tests::bns_expanded::test_bns_cost_scaling",
    "tests::bns_expanded::test_bns_renewal",
    "tests::bns_expanded::test_bns_subdomains_owner_only",
    "tests::bns_expanded::test_bns_invalid_names",
    "tests::bns_expanded::test_bns_transfer",
    "tests::bns_expanded::test_bns_full_resolve_with_storage",
    "tests::bns_expanded::bns_lifecycle_doors_reject_zero_duration_and_zero_owner",
    "tests::bns_expanded::bns_renew_and_transfer_execute_through_consensus_doors",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "bns")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "bns")
}
