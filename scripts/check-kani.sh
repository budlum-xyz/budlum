#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--self-test" ]; then
  echo "kani self-test OK (mock)"
  exit 0
fi
echo "kani check stub - real harnesses in src/crypto/kani.rs"
# Cargo kani --harness verify_pop 2>&1 | tail -20 || true
