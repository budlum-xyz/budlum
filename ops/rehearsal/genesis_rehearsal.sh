#!/usr/bin/env bash
# WP-46 ceremony rehearsal (directive 12.5, 17.2.2): build the rehearsal
# genesis from at least 8 Full validator public registration records and
# record the genesis digest. Usage:
#   genesis_rehearsal.sh <registrations-dir> [out-dir]
# Each registration file is the public record produced by `bud validator init`
# on the operator's own machine (JSON with at least "class": "Full" and the
# public keys). Private keys never enter this script.
set -euo pipefail

REG_DIR="${1:?usage: genesis_rehearsal.sh <registrations-dir> [out-dir]}"
OUT_DIR="${2:-docs/rehearsal}"
MIN_FULL=8

count_full=0
validators_json=""
for f in "$REG_DIR"/*.json; do
    [ -e "$f" ] || { echo "no registration files in $REG_DIR" >&2; exit 2; }
    class=$(python3 -c "import json,sys; print(json.load(open('$f')).get('class',''))")
    if [ "$class" = "Full" ]; then
        count_full=$((count_full + 1))
        validators_json="${validators_json}$(cat "$f"),"
    fi
done

if [ "$count_full" -lt "$MIN_FULL" ]; then
    echo "ceremony rehearsal needs at least $MIN_FULL Full validators, got $count_full" >&2
    exit 1
fi

validators_json="[${validators_json%,}]"
mkdir -p "$OUT_DIR"
python3 - "$validators_json" "$OUT_DIR/rehearsal-genesis.json" << 'PY'
import json, sys
validators = json.loads(sys.argv[1])
tpl = json.load(open("config/rehearsal-genesis.json"))
tpl["validators"] = validators
tpl["ceremony_status"] = "rehearsal"
tpl["ceremony_note"] = (
    "Rehearsal genesis produced by ops/rehearsal/genesis_rehearsal.sh from "
    f"{len(validators)} Full validator public records. Throwaway network; "
    "chain id 45261 (KR-34)."
)
json.dump(tpl, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY

sha256sum "$OUT_DIR/rehearsal-genesis.json" | tee "$OUT_DIR/rehearsal-genesis.sha256"
echo "rehearsal genesis written to $OUT_DIR/rehearsal-genesis.json ($count_full Full validators)"
