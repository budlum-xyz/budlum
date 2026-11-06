#!/usr/bin/env bash
# WP-46 drill T-7 (TLG-20): general RPC load test.
# Pass: rate limiting engages; 429 ratio measured and recorded.
# Evidence: docs/rehearsal/T-7.md.
set -euo pipefail
echo "T-7: general RPC load test"
echo "PASS requires: 429 responses under overload AND measured 429 ratio recorded"
