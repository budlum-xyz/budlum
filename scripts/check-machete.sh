#!/usr/bin/env bash
set -euo pipefail
# Kanarya pattern
if [ "${1:-}" = "--self-test" ]; then
  echo "machete self-test OK"
  exit 0
fi
cargo machete --with-metadata
echo "cargo machete clean"
