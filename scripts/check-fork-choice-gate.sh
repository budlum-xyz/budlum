#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  pow_picks_highest_cumulative_work
  pos_picks_highest_vote_weight
  bft_conflicting_qc_is_rejected
  poa_requires_authority_quorum
  lifecycle_transitions_are_explicit
  mixed_domain_candidates_rejected
  domain_lifecycle_requires_freeze_before_retire
  retired_domain_is_terminal
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
  grep -v "${required_tests[0]}" "$tmp" > "$tmp.bad"
  if bash "$0" "$tmp.bad" >/dev/null 2>&1; then
    fail "self-test expected missing test to fail"
  fi
  echo "Fork-choice gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required fork-choice test did not run/pass: $name"
  done
  echo "Fork-choice gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
