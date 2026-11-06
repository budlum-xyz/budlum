#!/usr/bin/env bash
# WP-46 drill support (directive 12.5, 17.1).
#
# A drill does not decide its own success from a print statement. It reads the
# measurement file produced during the soak, applies the pass criteria from the
# card, and writes the evidence page. Without a measurement it exits 2 and
# writes nothing: an absent measurement is not a pass (directive 0.3 item 5,
# 15.5 item 10).
#
# Usage from a drill:
#   source "$(dirname "$0")/lib.sh"
#   drill_begin T-1 "<title>"
#   check 'm["objects_lost"] == 0' "no object was lost"
#   drill_end
#
# Environment:
#   REHEARSAL_EVIDENCE   measurement JSON for this drill (required)
#   REHEARSAL_RPC        public RPC URL; when set, liveness is probed first
#   REHEARSAL_OUT        evidence directory (default: docs/rehearsal)
set -euo pipefail

DRILL=""
OUT_DIR="${REHEARSAL_OUT:-docs/rehearsal}"
OUT_FILE=""
STATUS=0

fail() {
    echo "${DRILL:-drill}: $*" >&2
    exit 1
}

drill_begin() {
    DRILL="${1:?drill name}"
    local title="${2:-$1}"
    OUT_FILE="$OUT_DIR/$DRILL.md"

    if [ -n "${REHEARSAL_RPC:-}" ]; then
        command -v curl >/dev/null || fail "curl is required to probe \$REHEARSAL_RPC"
        local body='{"jsonrpc":"2.0","method":"bud_netListening","params":[],"id":1}'
        curl -s -o /dev/null --max-time 5 -H 'Content-Type: application/json' \
            -d "$body" "$REHEARSAL_RPC" ||
            fail "RPC $REHEARSAL_RPC did not answer; measurements cannot be trusted"
    fi

    local evidence="${REHEARSAL_EVIDENCE:-}"
    if [ -z "$evidence" ]; then
        cat >&2 <<EOF
$DRILL: no measurement supplied, so this drill cannot pass.
  Set REHEARSAL_EVIDENCE=<file.json> with the fields this drill checks and
  re-run. Nothing was written to $OUT_FILE.
EOF
        exit 2
    fi
    [ -f "$evidence" ] || fail "measurement file $evidence does not exist"

    mkdir -p "$OUT_DIR"
    {
        echo "# $DRILL — $title"
        echo
        echo "Measurement: \`$evidence\` (SHA-256 below)."
        echo "Recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
        echo '```json'
        cat "$evidence"
        echo '```'
        echo
        echo '```'
        sha256sum "$evidence"
        echo '```'
        echo
        echo "## Criteria"
    } > "$OUT_FILE"
    echo "=== $DRILL: $title ==="
}

# evaluate <python expression over m> — exit 0 when true, 1 when false,
# 2 when the measurement is unusable (missing field, not JSON).
evaluate() {
    python3 - "${REHEARSAL_EVIDENCE:?}" "$1" <<'PY'
import json, sys
path, expression = sys.argv[1], sys.argv[2]
try:
    m = json.load(open(path))
except (OSError, ValueError):
    raise SystemExit(2)
try:
    ok = bool(eval(expression, {"__builtins__": {}}, {"m": m}))  # noqa: S307 - literals from this file only
except (KeyError, TypeError):
    raise SystemExit(2)
raise SystemExit(0 if ok else 1)
PY
}

check() {
    local expression="$1" explanation="$2" verdict
    if evaluate "$expression"; then
        echo "PASS $DRILL: $explanation"
        echo "- PASS: $explanation" >> "$OUT_FILE"
    else
        verdict=$?
        if [ "$verdict" -eq 2 ]; then
            echo "FAIL $DRILL: the measurement cannot answer: $explanation" >&2
            echo "- FAIL (measurement unusable): $explanation" >> "$OUT_FILE"
        else
            echo "FAIL $DRILL: $explanation" >&2
            echo "- FAIL: $explanation" >> "$OUT_FILE"
        fi
        STATUS=1
    fi
}

drill_end() {
    if [ "$STATUS" -eq 0 ]; then
        echo "**Verdict: PASS**" >> "$OUT_FILE"
        echo "$DRILL: PASS"
    else
        echo "**Verdict: FAIL**" >> "$OUT_FILE"
        echo "$DRILL: FAIL — evidence is in $OUT_FILE" >&2
    fi
    exit "$STATUS"
}
