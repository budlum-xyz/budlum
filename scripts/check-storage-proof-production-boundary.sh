#!/usr/bin/env bash
# ============================================================================
# check-storage-proof-production-boundary.sh
# Task 11.10 / V37-V38: Verify storage proof production boundary.
#
# Production storage challenge paths must require a real ProofEnvelope.
# test-mock-proof must only be accepted via cfg!(test) guard.
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

root="${1:-.}"

# 1. Production verify_answer_challenge_zk_proof must exist
if ! grep -q "verify_answer_challenge_zk_proof" "$root/src/domain/storage_deal.rs" 2>/dev/null; then
  fail "verify_answer_challenge_zk_proof not found in storage_deal.rs"
fi

# 2. DefaultAdapter::verify (STARK verification) must be called
if ! grep -q "DefaultAdapter::verify" "$root/src/domain/storage_deal.rs" 2>/dev/null; then
  fail "DefaultAdapter::verify not found in storage_deal.rs"
fi

# 3. proof_bytes field must exist in RetrievalResponse
if ! grep -q "proof_bytes" "$root/src/domain/storage_deal.rs" 2>/dev/null; then
  fail "proof_bytes field not found in storage_deal.rs"
fi

# 4. Production code must reject test-mock-proof when cfg!(test) is false
#    The cfg!(test) guard ensures test-mock-proof only works in test builds
if ! grep -q 'cfg!(test) && proof_bytes == b"test-mock-proof"' "$root/src/domain/storage_deal.rs" 2>/dev/null; then
  fail "cfg!(test) guard for test-mock-proof not found — production may accept mock proofs"
fi

# 5. storage_root must be checked (mandatory proof when storage_root exists)
if ! grep -q "storage_root.*proof_bytes\|proof_bytes.*storage_root\|storage_root.is_some" "$root/src/domain/storage_deal.rs" 2>/dev/null; then
  fail "storage_root + proof_bytes binding not found"
fi

echo "Storage proof production boundary OK: STARK verification mandatory, test-mock-proof only in cfg!(test)."
