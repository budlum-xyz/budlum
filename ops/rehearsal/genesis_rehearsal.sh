#!/usr/bin/env bash
# WP-46 ceremony rehearsal (directive 12.5, 17.2.2).
#
# Input: a directory of public operator records, one JSON file per operator,
# exactly as `bud validator init --record-out` writes them on the operator's
# own machine (`validator`, `registration`, optional `moniker`).
#
# This script validates the inputs and then hands the assembly to the checked
# ceremony (`bud genesis assemble`). It never merges records into the template
# itself: a genesis written here must be the one a node accepts, and only the
# ceremony code can guarantee that. It republishes only the public fields, so
# nothing else in an input file can reach the output.
#
# Usage:
#   genesis_rehearsal.sh <registrations-dir> [out-dir] [-- extra bud arguments]
#
# Environment:
#   MIN_FULL             minimum distinct valid operator records (default 8)
#   REHEARSAL_CLASSES    optional JSON map {"<validator address>": "Full"|"Mobile"};
#                        when set, the Full count is enforced from it. The record
#                        itself carries no class, so an unset map only proves
#                        "at least N valid operators", never "N Full".
#   BUD                  ceremony binary (default: bud)
set -euo pipefail

REG_DIR="${1:?usage: genesis_rehearsal.sh <registrations-dir> [out-dir] [-- bud args]}"
shift 1
OUT_DIR="${1:-docs/rehearsal}"
[ $# -gt 0 ] && shift
MIN_FULL="${MIN_FULL:-8}"
EXTRA=()
if [ "${1:-}" = "--" ]; then
    shift
    EXTRA=("$@")
fi

[ -d "$REG_DIR" ] || { echo "no such directory: $REG_DIR" >&2; exit 2; }
mkdir -p "$OUT_DIR"

python3 - "$REG_DIR" "$MIN_FULL" "${REHEARSAL_CLASSES:-}" <<'PY'
import json, sys
from pathlib import Path

reg_dir, minimum, classes_path = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
classes = {}
if classes_path:
    try:
        classes = json.loads(Path(classes_path).read_text())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REHEARSAL_CLASSES is not a readable JSON map: {exc}")

records, seen, problems = [], set(), []
for path in sorted(reg_dir.glob("*.json")):
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        problems.append(f"{path.name}: not JSON ({exc})")
        continue
    if not isinstance(record, dict):
        problems.append(f"{path.name}: not a JSON object")
        continue
    validator, registration = record.get("validator"), record.get("registration")
    if not isinstance(validator, str) or not validator:
        problems.append(f"{path.name}: no public validator address")
        continue
    if not isinstance(registration, dict) or not registration:
        problems.append(f"{path.name}: no public consensus-key registration")
        continue
    if validator in seen:
        problems.append(f"{path.name}: duplicate validator {validator}")
        continue
    seen.add(validator)
    records.append((validator, record))

if problems:
    sys.stderr.write("\n".join(problems) + "\n")
    raise SystemExit(f"refusing the rehearsal genesis: {len(problems)} invalid record(s)")

if len(records) < minimum:
    raise SystemExit(
        f"ceremony rehearsal needs at least {minimum} distinct valid operator "
        f"records, got {len(records)}"
    )

full = [v for v, _ in records if classes.get(v) == "Full"] if classes else []
if classes:
    unknown = [v for v, _ in records if v not in classes]
    if unknown:
        raise SystemExit(
            "REHEARSAL_CLASSES has no class for: " + ", ".join(unknown)
        )
    if len(full) < minimum:
        raise SystemExit(
            f"ceremony rehearsal needs at least {minimum} Full validators, "
            f"got {len(full)}"
        )
else:
    sys.stderr.write(
        "note: the operator record carries no validator class and "
        "REHEARSAL_CLASSES is unset, so the Full/Mobile split is NOT verified; "
        f"this run only proves {len(records)} valid operators.\n"
    )

print(f"{len(records)} valid operator records"
      + (f", {len(full)} of them Full" if classes else ""))
PY

"${BUD:-bud}" genesis assemble --network testnet \
    --operators "$REG_DIR" --out "$OUT_DIR/rehearsal-genesis.json" "${EXTRA[@]}"
sha256sum "$OUT_DIR/rehearsal-genesis.json" | tee "$OUT_DIR/rehearsal-genesis.sha256"
echo "rehearsal genesis written to $OUT_DIR/rehearsal-genesis.json"
