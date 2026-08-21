//! Required named tests: fork-choice.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "pow_picks_highest_cumulative_work",
    "pos_picks_highest_vote_weight",
    "bft_conflicting_qc_is_rejected",
    "poa_requires_authority_quorum",
    "lifecycle_transitions_are_explicit",
    "mixed_domain_candidates_rejected",
    "domain_lifecycle_requires_freeze_before_retire",
    "retired_domain_is_terminal",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Fork-choice")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Fork-choice")
}
