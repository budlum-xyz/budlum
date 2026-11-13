//! Required exact named tests: gateway (B14).
//!
//! The gateway is the only part of the stack that turns a name into bytes a
//! browser executes, so its rules are gated by name rather than by module
//! coverage. Three of the four names below are the tests that would fail if a
//! rule were deleted:
//!
//! - `a_response_never_carries_a_cookie`: origin isolation. A cookie set here
//!   is scoped to the suffix, not to the name.
//! - `a_site_may_narrow_the_policy_but_not_widen_it`: the CSP floor.
//! - `traversal_and_malformed_paths_are_refused_before_any_lookup`: the
//!   manifest is the only place a path is interpreted.
//! - `a_tampered_proof_is_a_502_and_never_a_page`: the gateway serves nothing
//!   that did not fold to a root the light client verified.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "gateway::policy::tests::a_response_never_carries_a_cookie",
    "gateway::policy::tests::a_site_may_narrow_the_policy_but_not_widen_it",
    "gateway::manifest::tests::traversal_and_malformed_paths_are_refused_before_any_lookup",
    "gateway::resolve::tests::a_tampered_proof_is_a_502_and_never_a_page",
    "gateway::resolve::tests::a_proof_checked_against_a_root_the_node_chose_would_be_no_proof",
    "gateway::host::tests::the_bare_suffix_and_reserved_labels_go_to_budlum_not_to_bns",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "gateway")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "gateway")
}
