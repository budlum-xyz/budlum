//! Required named tests: wallet-core.
//!
//! Ported from scripts/check-wallet-core-gate.sh, a member of the "required
//! named tests" family. The cargo test log must show every name followed by
//! `ok`.

use std::path::Path;

const TESTS: &[&str] = &[
    "entropy_size_preserves_mnemonic_word_count",
    "wallet_generate_rejects_placeholder_entropy_in_production",
    "mnemonic_checksum_validation_rejects_invalid",
    "binding_capabilities_do_not_claim_a_wiring_that_is_absent",
    "binding_export_redacts_seed_and_counts_words",
    "binding_uniffi_feature_stub_exports_capabilities",
    "binding_wasm_feature_stub_exports_capabilities",
    "multisig_policy_validates_threshold",
    "multisig_requires_distinct_valid_owner_signatures",
    "multisig_rejects_wrong_message_or_non_owner",
    "multisig_accepts_all_two_of_three_combinations",
    "multisig_enforces_three_of_five_combinations",
    "social_recovery_policy_validates_threshold_and_timelock",
    "social_recovery_requires_distinct_guardian_signatures",
    "social_recovery_rejects_non_guardian_or_wrong_digest",
    "social_recovery_rotates_compromised_guardian",
    "social_recovery_removal_preserves_threshold_safety",
    "recovery_proposal_sets_timelock_and_addresses",
    "recovery_proposal_digest_binds_target_and_timelock",
    "recovery_proposal_requires_quorum_and_timelock",
    "recovery_proposal_rejects_same_owner_or_overflow",
    "d2_privacy_config_defaults_off",
    "d2_privacy_config_user_opt_in_client_first",
    "d2_privacy_config_server_backend_fallback",
    "d2_note_privacy_only_keeps_tee_off",
    "d2_view_key_derive_export_roundtrip",
    "d2_view_key_rotation_changes_key",
    "d2_view_key_rejects_malformed_hex",
    "d2_wallet_defaults_privacy_off",
    "d2_wallet_private_transfer_requires_note_privacy",
    "d2_wallet_private_transfer_1in_1out_signs",
    "d2_wallet_private_transfer_with_change",
    "d2_wallet_tee_enabled_fail_closed_without_runtime",
    "d2_wallet_tee_ready_mock_allows_sign",
    "d2_wallet_tee_requires_enrolled_measurement",
    "d2_wallet_tee_rejects_foreign_measurement",
    "d2_wallet_tee_rejects_wrong_backend",
    "d2_wallet_tee_rejects_forged_quote",
    "d2_wallet_view_key_bound_to_seed",
    "d2_wallet_overspend_rejected",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "wallet-core")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "wallet-core")
}
