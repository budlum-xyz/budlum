#!/usr/bin/env bash
# WP-46 drill T-7 (TLG-20): general RPC load test.
# Pass: rate limiting engages; the 429 ratio is measured and recorded.
# Evidence: docs/rehearsal/T-7.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-7 "general RPC load test"
check 'm["rate_limited"] is True' "rate limiting engaged under overload"
check 'isinstance(m["ratio_429"], (int, float)) and 0 < m["ratio_429"] <= 1' \
    "a 429 ratio was measured and recorded"
drill_end
