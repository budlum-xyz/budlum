#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_16_governance_rejects_non_whitelisted_parameter_proposal
  phase11_16_governance_rejects_invalid_parameter_value
  phase11_16_governance_sets_parameter_activation_timelock
  phase11_16_governance_records_vote_weight_snapshot
  phase11_16_governance_stake_transfer_cannot_double_count_vote_weight
  phase11_16_governance_parameter_update_waits_for_activation_epoch
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
    printf 'test %s ... ok\n' "$name" >> "$tmp"
  done
  bash "$0" "$tmp" >/dev/null
  grep -v "${required_tests[0]}" "$tmp" > "$tmp.bad" || true
  if bash "$0" "$tmp.bad" >/dev/null 2>&1; then
    fail "self-test expected missing test to fail"
  fi
  echo "Governance invariant gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required governance invariant test did not run/pass: $name"
  done
  echo "Governance invariant gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
