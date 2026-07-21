#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_8_base_fee_increase_is_bounded
  phase11_8_base_fee_decrease_is_bounded
  phase11_8_max_fee_below_base_fee_rejected
  phase11_8_effective_tip_cannot_exceed_priority_or_cap
  phase11_8_legacy_fee_maps_to_zero_tip
  phase11_8_reward_pool_default_schedule_valid
  phase11_8_reward_pool_conserves_budget
  phase11_8_reward_pool_rounding_remainder_deterministic
  phase11_8_total_bud_committed_counts_stake_and_unbonding
  phase11_8_supply_capacity_remaining_uses_committed_denominator
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

self_test() {
  local tmp
  tmp="$(mktemp)"
  trap "rm -f '$tmp'" EXIT
  for name in "${required_tests[@]}"; do
    printf 'test %s ... ok\n' "$name" >> "$tmp"
  done
  "$0" "$tmp" >/dev/null
  grep -v "${required_tests[0]}" "$tmp" > "$tmp.bad"
  if "$0" "$tmp.bad" >/dev/null 2>&1; then
    fail "self-test expected missing test to fail"
  fi
  echo "Economy invariant gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required economy invariant test did not run/pass: $name"
  done
  echo "Economy invariant gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
