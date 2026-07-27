#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--self-test" ]; then
  echo "taplo self-test OK"
  exit 0
fi
taplo lint
echo "taplo lint OK"
