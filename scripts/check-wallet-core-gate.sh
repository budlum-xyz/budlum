#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  entropy_size_preserves_mnemonic_word_count
  wallet_generate_rejects_placeholder_entropy_in_production
  mnemonic_checksum_validation_rejects_invalid
  binding_capabilities_include_mobile_and_browser_stubs
  binding_export_redacts_seed_and_counts_words
  binding_uniffi_feature_stub_exports_capabilities
  binding_wasm_feature_stub_exports_capabilities
  multisig_policy_validates_threshold
  multisig_requires_distinct_valid_owner_signatures
  multisig_rejects_wrong_message_or_non_owner
  multisig_accepts_all_two_of_three_combinations
  multisig_enforces_three_of_five_combinations
  social_recovery_policy_validates_threshold_and_timelock
  social_recovery_requires_distinct_guardian_signatures
  social_recovery_rejects_non_guardian_or_wrong_digest
  social_recovery_rotates_compromised_guardian
  social_recovery_removal_preserves_threshold_safety
  recovery_proposal_sets_timelock_and_addresses
  recovery_proposal_digest_binds_target_and_timelock
  recovery_proposal_requires_quorum_and_timelock
  recovery_proposal_rejects_same_owner_or_overflow
  d2_privacy_config_defaults_off
  d2_privacy_config_user_opt_in_client_first
  d2_privacy_config_server_backend_fallback
  d2_note_privacy_only_keeps_tee_off
  d2_view_key_derive_export_roundtrip
  d2_view_key_rotation_changes_key
  d2_view_key_rejects_malformed_hex
  d2_wallet_defaults_privacy_off
  d2_wallet_private_transfer_requires_note_privacy
  d2_wallet_private_transfer_1in_1out_signs
  d2_wallet_private_transfer_with_change
  d2_wallet_tee_enabled_fail_closed_without_runtime
  d2_wallet_tee_ready_mock_allows_sign
  d2_wallet_view_key_bound_to_seed
  d2_wallet_overspend_rejected
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

self_test() {
  local tmp
  tmp="$(mktemp)"
  trap "rm -f '$tmp' '$tmp.bad'" EXIT
  for name in "${required_tests[@]}"; do
    printf 'test tests::%s ... ok\n' "$name" >> "$tmp"
  done
  bash "$0" "$tmp" >/dev/null
  grep -v "${required_tests[0]}" "$tmp" > "$tmp.bad" || true
  if bash "$0" "$tmp.bad" >/dev/null 2>&1; then
    fail "self-test expected missing test to fail"
  fi
  echo "Wallet Core gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required wallet-core test did not run/pass: $name"
  done
  echo "Wallet Core gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
