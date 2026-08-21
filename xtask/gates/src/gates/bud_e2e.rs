//! Required exact named tests: `bud_e2e`.
//!
//! Ported from scripts/check-*.sh. The cargo test log must contain the full
//! line `test tests::bud_e2e::<name> ... ok` for every name, so a substring (e.g.
//! `invariant_1` matching `invariant_10`) cannot satisfy the gate.

use std::path::Path;

const TESTS: &[&str] = &[
    "tests::bud_e2e::invariant_1_no_whitelist_for_deal_or_challenge",
    "tests::bud_e2e::invariant_2_no_admin_pause_freeze_hook",
    "tests::bud_e2e::invariant_3_any_account_can_challenge_any_deal",
    "tests::bud_e2e::invariant_4_any_account_meeting_bond_can_open_deal",
    "tests::bud_e2e::invariant_5_opener_bond_must_be_positive",
    "tests::bud_e2e::invariant_6_slash_only_via_missed_deadline",
    "tests::bud_e2e::invariant_7_slashed_deal_rejects_new_challenges",
    "tests::bud_e2e::invariant_8_deal_requires_shard_to_be_in_manifest",
    "tests::bud_e2e::invariant_9_manifest_id_is_deterministic_across_nodes",
    "tests::bud_e2e::e2e_three_actor_manifest_to_challenge_flow",
    "tests::bud_e2e::e2e_missed_challenge_slashes_only_the_target_deal",
    "tests::bud_e2e::e2e_malicious_operator_cached_range_misses_entropy_selected_challenge",
    "tests::bud_e2e::e2e_deal_queries_return_replica_set",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "bud_e2e")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "bud_e2e")
}
