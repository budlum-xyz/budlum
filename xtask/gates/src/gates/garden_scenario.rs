//! Required exact named tests: the Garden acceptance scenario.
//!
//! The scenario lives in `tests/garden/garden_scenario.rs` and drives real
//! `budlum-core` nodes in separate processes. The cargo test log must
//! contain the full line `test <name> ... ok` for every name below, so a
//! step that was renamed, deleted or filtered out fails the gate instead of
//! shrinking the scenario silently. One name stands for one acceptance step.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "garden_step_01_host_creates_a_garden_with_invite_and_qr",
    "garden_step_02_five_validators_join_with_the_invite",
    "garden_step_03_validators_share_messages_and_posts",
    "garden_step_04_image_resolves_on_another_node_with_equal_content_id",
    "garden_step_05_participant_queries_the_path_of_a_message",
    "garden_step_06_sudden_departure_keeps_chain_and_content",
    "garden_step_07_finality_is_visible_on_budlum_as_active",
    "garden_step_08_host_leaves_and_the_garden_freezes_readable",
    "garden_step_09_host_returns_and_the_garden_runs_again",
    "garden_step_10_everyone_leaves_and_no_data_stays_on_disk",
    "garden_step_11_a_new_garden_is_created",
    "garden_is_closed_on_testnet",
    "garden_join_behind_nat",
    "garden_host_silence_freezes_and_its_return_resumes",
    "garden_validator_leaves_and_returns_while_the_garden_runs",
    "garden_rpc_is_refused_on_the_public_listener",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "garden-scenario")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "garden-scenario")
}
