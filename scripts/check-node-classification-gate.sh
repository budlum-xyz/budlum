#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_10_node_mode_maps_roles
  phase11_10_node_archive_rejects_pruning
  phase11_10_node_archive_requires_backups
  phase11_10_node_full_pruning_requires_finalized_snapshot_retention
  phase11_10_node_full_pruning_requires_nonzero_retention
  phase11_10_node_prune_decision_distinguishes_full_and_archive
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
  echo "Node classification gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required node classification test did not run/pass: $name"
  done
  echo "Node classification gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
