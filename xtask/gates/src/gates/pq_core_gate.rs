//! Required named tests: the post-quantum core.
//!
//! The cargo test log of the PQ core job must show every name followed by
//! `ok`. The list carries the vector replays (NIST ACVP, Wycheproof, the
//! explicit bug vectors), the differential test between the two ML-DSA
//! libraries, the scheme registry, the context table, the composite signature
//! and the wiping tests. A vector set that is not replayed by a named test here
//! is not a required vector set (`tests/vectors/pq/README.md`).

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "pq_vectors_acvp_mldsa_keygen",
    "pq_vectors_acvp_mldsa_siggen",
    "pq_vectors_acvp_mldsa_sigver",
    "pq_vectors_wycheproof_mldsa",
    "pq_vectors_acvp_slhdsa_keygen",
    "pq_vectors_acvp_slhdsa_sigver",
    "pq_vectors_acvp_slhdsa_siggen",
    "pq_vectors_bug_control_signature_verifies",
    "pq_vectors_bug_duplicate_hint_index",
    "pq_vectors_bug_decreasing_hint_indices",
    "pq_vectors_bug_noncanonical_hint_padding",
    "pq_vectors_bug_hint_counts_not_monotonic_or_over_omega",
    "pq_vectors_bug_infinity_norm_bound",
    "pq_vectors_bug_wrong_lengths",
    "pq_vectors_bug_context_longer_than_255_bytes",
    "pq_vectors_bug_an_empty_context_is_refused_by_the_facade",
    "pq_vectors_differential_random_inputs",
    "pq_vectors_disagreement_is_counted_and_invalid",
    "pq_vectors_verdict_digest",
    "scheme_table_is_sorted_and_unique",
    "scheme_table_matches_the_spec_sizes",
    "pq_scheme_name_is_derived_from_the_registry",
    "genesis_statuses_follow_section_6_5",
    "unknown_and_disabled_schemes_do_not_verify",
    "the_ladder_has_no_shortcuts",
    "governance_may_only_activate",
    "an_emergency_suite_opens_in_two_steps_of_its_own",
    "ctx_strings_are_unique_ascii_and_short",
    "ctx_is_registered_accepts_only_the_registry",
    "ml_dsa_round_trips_through_both_verifiers",
    "the_two_ml_dsa_libraries_sign_identically",
    "a_wrong_context_message_or_key_is_rejected",
    "an_empty_or_long_context_is_refused",
    "unknown_reserved_and_wrong_length_inputs_are_refused",
    "a_disabled_scheme_is_refused_by_the_chain_registry",
    "a_split_verdict_is_invalid_and_counted",
    "slh_dsa_128s_round_trips_and_binds_the_context",
    "slh_dsa_refuses_a_wrong_seed_length",
    "composite_round_trips_for_both_active_suites",
    "composite_encodings_round_trip_and_have_fixed_length",
    "composite_rejects_a_missing_component",
    "composite_rejects_a_swapped_component",
    "composite_rejects_a_changed_context",
    "composite_rejects_a_changed_suite",
    "composite_rejects_reuse_from_another_domain",
    "composite_rejects_a_weak_ed25519_key",
    "composite_respects_the_scheme_registry",
    "composite_known_answer_pins_the_representative",
    "composite_slh_dsa_emergency_suite_round_trips_once_activated",
    "zeroize_every_secret_holder_wipes_on_drop",
    "zeroize_wrapper_wipes_before_the_value_is_released",
    "pq_verifier_disagreement_is_exported",
];

/// Check a cargo test log.
///
/// # Errors
///
/// A required test missing from the log, or a missing log.
pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "pq-core")
}

/// Canary: a complete log passes, a log without the first name fails.
///
/// # Errors
///
/// A canary that does not behave as stated.
pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "pq-core")
}
