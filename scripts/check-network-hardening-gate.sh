#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_12_rate_limit_exhaustion_uses_dedicated_penalty
  phase11_12_repeated_rate_limit_exhaustion_bans_peer
  h5_eclipse_subnet_bound_rejects_fifth_peer
  h5_eclipse_disconnect_frees_subnet_slot
  h5_eclipse_peer_accounting_is_idempotent
  h5_3_rpc_auth_required_by_default
  h5_5_max_message_size_rejected
  h5_1_eclipse_bound_still_active
  h5_6_multinode_smoke_artifacts_present
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
  "$0" "$tmp" >/dev/null
  grep -v "${required_tests[0]}" "$tmp" > "$tmp.bad" || true
  if "$0" "$tmp.bad" >/dev/null 2>&1; then
    fail "self-test expected missing test to fail"
  fi
  echo "Network hardening gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required network hardening test did not run/pass: $name"
  done
  echo "Network hardening gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
