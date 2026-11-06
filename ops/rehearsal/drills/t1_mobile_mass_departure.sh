#!/usr/bin/env bash
# WP-46 drill T-1: stop ALL Mobile validators at once (directive 1.3.4, TLG-07).
# Pass: finality delay unchanged, no object lost, reads continue from Full.
# Evidence: docs/rehearsal/T-1.md (written from REHEARSAL_EVIDENCE).
source "$(dirname "$0")/lib.sh"
drill_begin T-1 "all Mobile validators stop at once"
check 'm["finality_delay_after_ms"] <= m["finality_delay_before_ms"]' \
    "finality delay did not grow when every Mobile validator stopped"
check 'm["objects_lost"] == 0' "no object was lost (checksum audit)"
check 'm["full_class_reads_ok"] is True' "reads continued from the Full class"
drill_end
