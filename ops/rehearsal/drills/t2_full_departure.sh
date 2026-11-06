#!/usr/bin/env bash
# WP-46 drill T-2: stop 10% of Full validators at once (at least one).
# Pass (TLG-08): finality delayed by at most 2 checkpoint intervals and seats
# hand over within at most 3. Evidence: docs/rehearsal/T-2.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-2 "10% of Full validators stop at once"
check 'm["finality_delay_checkpoints"] <= 2' "finality delayed by at most 2 checkpoints"
check 'm["seat_handover_checkpoints"] <= 3' "seats handed over within 3 checkpoints"
drill_end
