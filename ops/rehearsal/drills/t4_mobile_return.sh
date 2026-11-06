#!/usr/bin/env bash
# WP-46 drill T-4: Mobile validators return after T-1.
# Pass: ResumeValidator effective after one epoch; repair completes.
# Evidence: docs/rehearsal/T-4.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-4 "Mobile validators return"
check 'm["resume_effective_epochs"] <= 1' "ResumeValidator took effect within one epoch"
check 'm["repair_completed"] is True' "repair completed"
drill_end
