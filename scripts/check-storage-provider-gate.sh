#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  task11_10_storage_provider_put_get_roundtrip
  task11_10_storage_provider_rejects_invalid_range
  task11_10_storage_provider_prove_settle_roundtrip
  task11_10_storage_provider_rejects_forged_proof_range_hash
  task11_10_lifecycle_happy_path_settled
  task11_10_lifecycle_challenge_can_miss_or_slash
  task11_10_lifecycle_rejects_skip_open_to_settled
  task11_10_lifecycle_terminal_states_are_final
  task11_10_registry_lifecycle_projection_tracks_challenge_and_slash
  task11_10_registry_lifecycle_projection_tracks_expiry
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
  echo "StorageProvider gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required storage provider test did not run/pass: $name"
  done
  echo "StorageProvider gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
