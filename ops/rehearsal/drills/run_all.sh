#!/usr/bin/env bash
# WP-46: run drills T-1..T-7, in order, after the 72-hour soak.
# Each drill needs its own measurement file (REHEARSAL_EVIDENCE). A drill that
# has no measurement exits 2 and is reported as NOT RUN; it is never counted as
# a pass, and the run keeps going so one missing file does not hide the rest.
set -uo pipefail
cd "$(dirname "$0")"

drills="t1_mobile_mass_departure t2_full_departure t3_seat_stall t4_mobile_return t5_load t6_tooling t7_rpc_load"
passed=0
failed=0
not_run=0
summary=""

for t in $drills; do
    echo "=== $t ==="
    ./"$t".sh
    case $? in
        0) passed=$((passed + 1)); summary="$summary$t PASS"$'\n' ;;
        2) not_run=$((not_run + 1)); summary="$summary$t NOT RUN (no measurement)"$'\n' ;;
        *) failed=$((failed + 1)); summary="$summary$t FAIL"$'\n' ;;
    esac
done

printf '%s' "$summary"
echo "drills: $passed passed, $failed failed, $not_run not run"
if [ "$failed" -ne 0 ] || [ "$not_run" -ne 0 ]; then
    echo "T-1..T-7 are not all evidenced; the rehearsal is not complete (directive 17.1)." >&2
    exit 1
fi
echo "all seven drills passed with measurements under docs/rehearsal/"
