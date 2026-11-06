#!/usr/bin/env bash
# WP-46 drill T-5: load of at least 100 GiB, 10 000 small objects, concurrent
# views. Pass: uploads and views succeed under load; throughput recorded.
# Evidence: docs/rehearsal/T-5.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-5 "100 GiB / 10 000-object load with concurrent views"
check 'm["total_gib"] >= 100' "the load carried at least 100 GiB"
check 'm["object_count"] >= 10000' "at least 10 000 objects were stored"
# The card says uploads and views succeed; 0.999 tolerates a single retried
# request out of a thousand and nothing more.
check 'm["upload_success_ratio"] >= 0.999' "uploads succeeded under load"
check 'm["view_success_ratio"] >= 0.999' "concurrent views succeeded under load"
drill_end
