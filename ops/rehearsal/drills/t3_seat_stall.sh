#!/usr/bin/env bash
# WP-46 drill T-3: halt more than one third of active seats for 50 blocks.
# Pass: budlum_finality_stalled fires; finality resumes when seats return.
# Evidence: docs/rehearsal/T-3.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-3 "more than one third of active seats halted for 50 blocks"
check 'm["blocks_halted"] >= 50' "the halt lasted at least 50 blocks"
check 'm["alert_fired"] is True' "budlum_finality_stalled fired"
check 'm["finality_resumed"] is True' "finality resumed after the seats returned"
drill_end
