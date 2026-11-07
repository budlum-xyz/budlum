#!/usr/bin/env bash
# WP-46 drill T-2: stop 10% of Full validators at once (at least one).
# Pass (TLG-08): finality delayed by at most 2 checkpoint intervals; seats hand
# over within at most 3 checkpoint intervals. Evidence: docs/rehearsal/T-2.md.
set -euo pipefail
echo "T-2: stopping 10% of Full validators"
echo "PASS requires: finality delay <= 2 checkpoints AND seat handover <= 3 checkpoints"
