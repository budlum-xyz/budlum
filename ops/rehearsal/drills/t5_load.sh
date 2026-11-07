#!/usr/bin/env bash
# WP-46 drill T-5: load >= 100 GiB total, 10 000 small objects, concurrent views.
# Pass: uploads and views succeed under load. Evidence: docs/rehearsal/T-5.md.
set -euo pipefail
echo "T-5: 100 GiB / 10k-object load with concurrent views"
echo "PASS requires: upload+view success under load; throughput recorded"
