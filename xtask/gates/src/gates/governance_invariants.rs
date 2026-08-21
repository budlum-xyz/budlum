//! Required named tests: governance invariant.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "governance_rejects_non_whitelisted_parameter_proposal",
    "governance_rejects_invalid_parameter_value",
    "governance_sets_parameter_activation_timelock",
    "governance_records_vote_weight_snapshot",
    "governance_stake_transfer_cannot_double_count_vote_weight",
    "governance_parameter_update_waits_for_activation_epoch",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Governance invariant")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Governance invariant")
}
