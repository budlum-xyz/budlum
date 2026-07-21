#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

check_contains() {
  local file="$1"
  local needle="$2"
  grep -Fq "$needle" "$file" || fail "missing marker in $file: $needle"
}

check_root() {
  local root="$1"
  [[ -f "$root/docs/THREAT_MODEL.md" ]] || fail "missing docs/THREAT_MODEL.md"
  [[ -f "$root/docs/audit_prep/README.md" ]] || fail "missing docs/audit_prep/README.md"
  [[ -f "$root/docs/VALIDATOR_KEY_MANAGEMENT.md" ]] || fail "missing docs/VALIDATOR_KEY_MANAGEMENT.md"
  [[ -f "$root/docs/MAINNET_LOCKDOWN_CHECKLIST.md" ]] || fail "missing docs/MAINNET_LOCKDOWN_CHECKLIST.md"
  [[ -f "$root/docs/audit_prep/MAINNET_READINESS_REVIEW.md" ]] || fail "missing docs/audit_prep/MAINNET_READINESS_REVIEW.md"
  [[ -f "$root/docs/operations/PRODUCTION_RUNBOOK.md" ]] || fail "missing docs/operations/PRODUCTION_RUNBOOK.md"
  [[ -f "$root/docs/operations/HSM_BLS_PQ_POLICY.md" ]] || fail "missing docs/operations/HSM_BLS_PQ_POLICY.md"
  [[ -f "$root/docs/audit_prep/CI_STABILITY_WINDOW.md" ]] || fail "missing docs/audit_prep/CI_STABILITY_WINDOW.md"

  check_contains "$root/docs/THREAT_MODEL.md" "Threat Model v2"
  check_contains "$root/docs/THREAT_MODEL.md" "Phase 11.20 Mitigation Closure Matrix"
  check_contains "$root/docs/THREAT_MODEL.md" "Residual Risk Register"
  check_contains "$root/docs/audit_prep/README.md" "Phase 11.20 Audit Prep Index"
  check_contains "$root/docs/audit_prep/README.md" "threat model v2"
  check_contains "$root/docs/audit_prep/README.md" "Evidence map"
  check_contains "$root/docs/audit_prep/README.md" "Known limits"
  check_contains "$root/docs/VALIDATOR_KEY_MANAGEMENT.md" "YubiHSM 2"
  check_contains "$root/docs/VALIDATOR_KEY_MANAGEMENT.md" "PKCS#11"
  check_contains "$root/docs/VALIDATOR_KEY_MANAGEMENT.md" "Key rotation"
  check_contains "$root/docs/VALIDATOR_KEY_MANAGEMENT.md" "Backup and loss scenario"
  check_contains "$root/docs/MAINNET_LOCKDOWN_CHECKLIST.md" "Mainnet Lockdown Checklist"
  check_contains "$root/docs/MAINNET_LOCKDOWN_CHECKLIST.md" "7 consecutive days green"
  check_contains "$root/docs/MAINNET_LOCKDOWN_CHECKLIST.md" "Waiver policy"
  check_contains "$root/docs/audit_prep/MAINNET_READINESS_REVIEW.md" "Mainnet Readiness Review"
  check_contains "$root/docs/audit_prep/MAINNET_READINESS_REVIEW.md" "MR-1..MR-10 review ledger"
  check_contains "$root/docs/audit_prep/MAINNET_READINESS_REVIEW.md" "Required sign-offs before launch lock"
  check_contains "$root/docs/audit_prep/CI_STABILITY_WINDOW.md" "CI Stability Window"
  check_contains "$root/docs/audit_prep/CI_STABILITY_WINDOW.md" "7 günlük launch-lock stabilite penceresi"
  check_contains "$root/docs/operations/HSM_CEREMONY_REHEARSAL.md" "HSM Ceremony Rehearsal"
  check_contains "$root/docs/operations/HSM_CEREMONY_REHEARSAL.md" "Mock geçmez kanıtı"
  check_contains "$root/docs/MAINNET_READINESS.md" "Phase 11.20 Snapshot"
  check_contains "$root/docs/MAINNET_READINESS.md" "28/28 success"
  echo "Audit prep gate OK"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  mkdir -p "$tmp/docs/audit_prep" "$tmp/docs/operations"
  cat > "$tmp/docs/THREAT_MODEL.md" <<'DOC'
# Threat Model v2
## Phase 11.20 Mitigation Closure Matrix
## Residual Risk Register
DOC
  cat > "$tmp/docs/audit_prep/README.md" <<'DOC'
# Phase 11.20 Audit Prep Index
threat model v2
## Evidence map
## Known limits
DOC
  cat > "$tmp/docs/VALIDATOR_KEY_MANAGEMENT.md" <<'DOC'
# Validator Key Management
YubiHSM 2
PKCS#11
Key rotation
Backup and loss scenario
DOC
  cat > "$tmp/docs/MAINNET_LOCKDOWN_CHECKLIST.md" <<'DOC'
# Mainnet Lockdown Checklist
7 consecutive days green
Waiver policy
DOC
  cat > "$tmp/docs/audit_prep/MAINNET_READINESS_REVIEW.md" <<'DOC'
# Mainnet Readiness Review
## MR-1..MR-10 review ledger
## Required sign-offs before launch lock
DOC
  printf 'runbook\n' > "$tmp/docs/operations/PRODUCTION_RUNBOOK.md"
  printf 'hsm policy\n' > "$tmp/docs/operations/HSM_BLS_PQ_POLICY.md"
  printf '# CI Stability Window\n7 günlük launch-lock stabilite penceresi\n' > "$tmp/docs/audit_prep/CI_STABILITY_WINDOW.md"
  printf '# HSM Ceremony Rehearsal\nMock geçmez kanıtı\n' > "$tmp/docs/operations/HSM_CEREMONY_REHEARSAL.md"
  printf '# Mainnet Readiness\nPhase 11.20 Snapshot\n28/28 success\n' > "$tmp/docs/MAINNET_READINESS.md"
  check_root "$tmp" >/dev/null
  rm "$tmp/docs/VALIDATOR_KEY_MANAGEMENT.md"
  if ( check_root "$tmp" ) >/dev/null 2>&1; then
    fail "self-test expected missing key-management doc to fail"
  fi
  echo "Audit prep gate self-test OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  root="${1:-.}"
  check_root "$root"
fi
