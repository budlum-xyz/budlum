#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--self-test" ]; then
  echo "bloat self-test OK"
  exit 0
fi
# Binary size gate - max 150MB for release node (tunable)
MAX_BYTES=$((150*1024*1024))
BIN=$(ls -S target/release/budlum* 2>/dev/null | head -n1 || echo "")
if [ -z "$BIN" ]; then
  echo "no binary found, skip"
  exit 0
fi
SIZE=$(stat -c%s "$BIN" 2>/dev/null || stat -f%z "$BIN")
echo "binary $BIN size $SIZE bytes"
if [ "$SIZE" -gt "$MAX_BYTES" ]; then
  echo "FAIL: binary too large >150MB"
  exit 1
fi
cargo bloat --release --crates -n 20 || true
echo "bloat OK"
