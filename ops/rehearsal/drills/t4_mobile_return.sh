#!/usr/bin/env bash
# WP-46 drill T-4: Mobile validators return after T-1.
# Pass: ResumeValidator is effective after one epoch; repair completes.
# Evidence: docs/rehearsal/T-4.md.
set -euo pipefail
echo "T-4: Mobile validators return"
echo "PASS requires: ResumeValidator effective after one epoch AND repair completes"
