//! Required exact named tests: gateway (B14).
//!
//! The gateway is the only part of the stack that turns a name into bytes a
//! browser executes, so its rules are gated by name rather than by module
//! coverage. The names below are the tests that would fail if a rule were
//! deleted, among them:
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
    "web_gateway::policy::tests::a_response_never_carries_a_cookie",
    "web_gateway::policy::tests::a_site_may_narrow_the_policy_but_not_widen_it",
    "web_gateway::manifest::tests::traversal_and_malformed_paths_are_refused_before_any_lookup",
    "web_gateway::resolve::tests::a_tampered_proof_is_a_502_and_never_a_page",
    "web_gateway::resolve::tests::a_proof_checked_against_a_root_the_node_chose_would_be_no_proof",
    "web_gateway::host::tests::the_bare_suffix_and_reserved_labels_go_to_budlum_not_to_bns",
    // What a visitor is answered when the name is not there to serve: an
    // expired record and a proven absence are a 404, a subdomain never falls
    // back to its parent, and one prover alone is not agreement.
    "web_gateway::resolve::tests::an_expired_record_is_a_404_even_with_a_perfect_proof",
    "web_gateway::resolve::tests::a_name_between_two_names_proves_absent_and_is_a_404",
    "web_gateway::resolve::tests::a_subdomain_serves_its_own_content_and_never_the_parent",
    "web_gateway::resolve::tests::provers_must_agree_and_an_empty_set_is_not_agreement",
    // The process binary (`src/bin/budlum-gateway.rs`) has its own four tests,
    // and they are not named here on purpose. `required_tests` resolves every
    // name to the file that must carry it, and a binary target's tests run
    // under the crate name, so the resolution would fail on a correct tree.
    // The binary is covered by `cargo test` on its own target instead.
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "gateway")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "gateway")
}
