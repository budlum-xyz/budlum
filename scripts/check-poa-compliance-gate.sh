#!/usr/bin/env bash
set -euo pipefail

required_tests=(
  phase11_18_poa_compliance_rejects_permissionless_screening
  phase11_18_poa_compliance_screening_updates_status
  phase11_18_poa_compliance_requires_admin_for_freeze
  phase11_18_poa_compliance_freeze_is_poa_only
  phase11_18_poa_compliance_audit_log_is_append_only
  phase11_18_poa_compliance_rejects_zero_evidence_hashes
  phase11_18_poa_compliance_records_travel_rule_metadata_hash
  phase11_18_poa_compliance_rejects_permissionless_travel_rule_metadata
  phase11_18_poa_compliance_exports_audit_csv
  phase11_18_poa_compliance_exports_audit_json
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
  echo "PoA compliance gate self-test OK"
}

check_log() {
  local log="$1"
  [[ -f "$log" ]] || fail "test log missing: $log"
  for name in "${required_tests[@]}"; do
    grep -Eq "test .*${name} .*ok|${name}.*ok" "$log" \
      || fail "required PoA compliance test did not run/pass: $name"
  done
  echo "PoA compliance gate OK: ${#required_tests[@]} named tests observed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  [[ $# -eq 1 ]] || fail "usage: $0 <cargo-test-log> | --self-test"
  check_log "$1"
fi
