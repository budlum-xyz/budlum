#!/usr/bin/env bash
# ============================================================================
# Check-storage-proof-production-boundary.sh
# Verify storage proof production boundary.
#
# Production storage challenge paths must require a real ProofEnvelope.
# Test-mock-proof must only be accepted via cfg!(test) guard.
# A proof that fails to verify must cost the operator its bond, not merely
# return an error that leaves the challenge open for another attempt.
#
# Run with --self-test to prove the checks can fail (see the canary below).
# A gate that cannot fail is not a gate.
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Every check reads one file, so the checks can run against a scratch copy
# during the self-test.
run_checks() {
  local root="$1"
  local src="$root/src/domain/storage_deal.rs"
  local actor="$root/src/chain/chain_actor.rs"

  # 1. Production verify_answer_challenge_zk_proof must exist
  grep -q "verify_answer_challenge_zk_proof" "$src" 2>/dev/null ||
    fail "verify_answer_challenge_zk_proof not found in storage_deal.rs"

  # 2. DefaultAdapter::verify (STARK verification) must be called
  grep -q "DefaultAdapter::verify" "$src" 2>/dev/null ||
    fail "DefaultAdapter::verify not found in storage_deal.rs"

  # 3. proof_bytes field must exist in RetrievalResponse
  grep -q "proof_bytes" "$src" 2>/dev/null ||
    fail "proof_bytes field not found in storage_deal.rs"

  # 4. Production code must reject test-mock-proof when cfg!(test) is false
  #    The cfg!(test) guard ensures test-mock-proof only works in test builds
  grep -q 'cfg!(test) && proof_bytes == b"test-mock-proof"' "$src" 2>/dev/null ||
    fail "cfg!(test) guard for test-mock-proof not found - production may accept mock proofs"

  # 5. storage_root must be checked (mandatory proof when storage_root exists)
  grep -qE "storage_root.*proof_bytes|proof_bytes.*storage_root|storage_root.is_some" "$src" 2>/dev/null ||
    fail "storage_root + proof_bytes binding not found"

  # 6. A failed verification must produce `Mismatched`, not a bare error.
  #
  #    `ChallengeOutcome::Mismatched` was declared with a doc comment saying
  #    the operator bond is slashed, and produced nowhere in the tree. The
  #    verification failure returned `Err`, which left nothing in `results`,
  #    moved no bond, and let the operator answer wrongly again, so a wrong
  #    answer was strictly cheaper than silence, since only silence reached
  #    `finalize_missed_challenge`. Both directions are checked, because a
  #    recorded slash that never burns is not a slash.
  grep -q "ChallengeOutcome::Mismatched" "$src" 2>/dev/null ||
    fail "storage_deal.rs never produces ChallengeOutcome::Mismatched - a wrong answer costs the operator nothing"

  grep -qE "\\bapply_storage_bond_slash\\b" "$actor" 2>/dev/null ||
    fail "chain_actor.rs does not burn the bond for a Mismatched answer - the slash is recorded but never applied"
}

# --------------------------------------------------------------------------
# Canary: the checks above are only worth running if they can fail. Build a
# scratch tree that violates check 6 and confirm the gate rejects it.
# --------------------------------------------------------------------------
self_test() {
  local root="${BUDLUM_ROOT:-.}"
  # Not `local`: the EXIT trap fires after the function scope is gone.
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"

  mkdir -p "$tmp/src/domain" "$tmp/src/chain"
  cp "$root/src/domain/storage_deal.rs" "$tmp/src/domain/storage_deal.rs"
  cp "$root/src/chain/chain_actor.rs" "$tmp/src/chain/chain_actor.rs"

  # The unmodified copy must pass, otherwise the canary proves nothing about
  # the real tree.
  if ! (run_checks "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not reproduce a passing run on an unmodified copy" >&2
    exit 1
  fi

  # Remove the Mismatched production and confirm the gate notices.
  sed -i 's/ChallengeOutcome::Mismatched/ChallengeOutcome::Answered/g' "$tmp/src/domain/storage_deal.rs"
  if (run_checks "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate accepted a tree that never produces Mismatched (vacuous gate)" >&2
    exit 1
  fi

  # Restore, then remove the burn and confirm that is caught too.
  cp "$root/src/domain/storage_deal.rs" "$tmp/src/domain/storage_deal.rs"
  sed -i 's/apply_storage_bond_slash/canary_removed_the_burn/g' "$tmp/src/chain/chain_actor.rs"
  if (run_checks "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate accepted a tree where the Mismatched slash never burns (vacuous gate)" >&2
    exit 1
  fi

  echo "Storage proof boundary gate self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

run_checks "${1:-.}"
echo "Storage proof production boundary OK: STARK verification mandatory, test-mock-proof only in cfg!(test), a failed proof slashes the operator bond."
