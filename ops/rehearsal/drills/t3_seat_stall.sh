#!/usr/bin/env bash
# WP-46 drill T-3: halt more than one third of active seats for 50 blocks.
# Pass: budlum_finality_stalled alert fires; finality resumes when seats return.
# Evidence: docs/rehearsal/T-3.md.
set -euo pipefail
echo "T-3: halting >1/3 of active seats for 50 blocks"
echo "PASS requires: budlum_finality_stalled alert fires AND finality resumes after seats return"
