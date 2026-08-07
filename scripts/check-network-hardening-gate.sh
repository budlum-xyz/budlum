#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  rate_limit_exhaustion_uses_dedicated_penalty
  repeated_rate_limit_exhaustion_bans_peer
  peer_rate_limit_security_profile
  eclipse_subnet_bound_rejects_fifth_peer
  eclipse_disconnect_frees_subnet_slot
  eclipse_peer_accounting_is_idempotent
  rpc_auth_required_by_default
  max_message_size_rejected
  eclipse_bound_still_active
  multinode_smoke_artifacts_present
  chaos_network_partition_isolates_groups
  chaos_byzantine_block_rejected
  chaos_eclipse_single_peer_isolation
  chaos_sybil_subnet_bound_rejects_excess
  chaos_ban_ttl_allows_reconnect_after_expiry
  chaos_reputation_fuzz_decay
  outbound_subnet_diversity_rejects_excess
  reputation_score_clamped_under_repeated_penalties
  h5_score_map_ceiling_holds_on_every_entry_point
  h5_score_map_ceiling_is_load_bearing
  h5_ceiling_refuses_rather_than_evicting_a_ban
  h5_tracked_peer_still_scored_when_map_is_full
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
