#!/usr/bin/env bash
# WP-46 drill T-1: stop ALL Mobile validators at once (directive 1.3.4, TLG-07).
# Pass: finality delay unchanged, no object lost, reads continue from Full.
# Evidence goes to docs/rehearsal/T-1.md (metric output, log summary, timeline).
set -euo pipefail
echo "T-1: stopping all Mobile validators (simulated + phones)"
# ops hook: stop simulated mobile validators and instruct phones to pause.
echo "measure finality delay before/after; verify reads from Full class"
echo "PASS requires: finality delay unchanged AND zero object loss (checksum audit)"
