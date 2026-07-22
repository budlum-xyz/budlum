#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_14_entropy_size_preserves_mnemonic_word_count
  phase11_14_wallet_generate_rejects_placeholder_entropy_in_production
  phase11_14_mnemonic_checksum_validation_rejects_invalid
  phase11_14_binding_capabilities_include_mobile_and_browser_stubs
  phase11_14_binding_export_redacts_seed_and_counts_words
  phase11_14_binding_uniffi_feature_stub_exports_capabilities
  phase11_14_binding_wasm_feature_stub_exports_capabilities
  phase11_14_multisig_policy_validates_threshold
  phase11_14_multisig_requires_distinct_valid_owner_signatures
  phase11_14_multisig_rejects_wrong_message_or_non_owner
  phase11_14_multisig_accepts_all_two_of_three_combinations
  phase11_14_multisig_enforces_three_of_five_combinations
  phase11_14_social_recovery_policy_validates_threshold_and_timelock
  phase11_14_social_recovery_requires_distinct_guardian_signatures
  phase11_14_social_recovery_rejects_non_guardian_or_wrong_digest
  phase11_14_social_recovery_rotates_compromised_guardian
  phase11_14_social_recovery_removal_preserves_threshold_safety
  phase11_14_recovery_proposal_sets_timelock_and_addresses
  phase11_14_recovery_proposal_digest_binds_target_and_timelock
  phase11_14_recovery_proposal_requires_quorum_and_timelock
  phase11_14_recovery_proposal_rejects_same_owner_or_overflow
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
