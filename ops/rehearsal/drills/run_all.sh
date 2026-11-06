#!/usr/bin/env bash
# WP-46: run drills T-1..T-7 in order after the 72-hour soak.
# Each drill records its evidence under docs/rehearsal/.
set -euo pipefail
cd "$(dirname "$0")"
for t in t1_mobile_mass_departure t2_full_departure t3_seat_stall t4_mobile_return t5_load t6_tooling t7_rpc_load; do
    echo "=== $t ==="
    ./"$t".sh
done
echo "all drills executed; evidence under docs/rehearsal/"
