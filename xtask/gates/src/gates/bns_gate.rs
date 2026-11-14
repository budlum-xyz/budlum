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
    // B12-B16: the governance price door, the expiry index, the metrics that
    // observe them, and the root property the Merkle tree rests on.
    "tests::bns_expanded::bns_base_cost_bounds_and_tenfold_step_are_enforced",
    "tests::bns_expanded::bns_base_cost_change_does_not_touch_existing_registrations",
    "tests::bns_expanded::bns_expiry_index_reclaims_the_earliest_expired_name_without_a_scan",
    "tests::bns_expanded::bns_expiry_index_tracks_renewal_prune_and_rebuild",
    "tests::bns_expanded::bns_expiry_index_is_not_committed_to_the_root",
    "tests::bns_expanded::bns_metrics_export_one_counter_per_type_and_the_named_gauges",
    "tests::bns_expanded::bns_root_is_independent_of_insertion_order",
    "tests::bns_expanded::bns_absence_proof_boundaries_must_be_adjacent_positions",
    "tests::bns_expanded::bns_set_content_refuses_unknown_content_and_binds_a_registered_object",
    "wallet::identity_profile::tests::a_swapped_address_under_a_valid_bns_proof_is_not_verified",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "bns")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "bns")
}
