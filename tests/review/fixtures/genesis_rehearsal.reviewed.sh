#!/usr/bin/env bash
# WP-46 ceremony rehearsal (directive 12.5, 17.2.2). Validates the public
# operator records and hands the assembly to the checked ceremony in `bud`;
# it never merges records itself and never republishes their contents.
#   genesis_rehearsal.sh <registrations-dir> [out-dir] [-- extra bud args]
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

mkdir -p "$OUT_DIR"
python3 - "$REG_DIR" "$MIN_FULL" "$OUT_DIR/validated.json" <<'PY'
import json, sys
from pathlib import Path

reg_dir, minimum, out = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
records, seen, problems = [], set(), []
for path in sorted(reg_dir.glob("*.json")):
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        problems.append(f"{path.name}: not JSON ({exc})")
        continue
    if not isinstance(record, dict):
        problems.append(f"{path.name}: not an object")
        continue
    validator, registration = record.get("validator"), record.get("registration")
    if not isinstance(validator, str) or not validator:
        problems.append(f"{path.name}: no validator address")
        continue
    if not isinstance(registration, dict) or not registration:
        problems.append(f"{path.name}: no public consensus-key registration")
        continue
    if validator in seen:
        problems.append(f"{path.name}: duplicate validator {validator}")
        continue
    seen.add(validator)
    # Only the public fields leave this step; everything else in the input
    # file (including anything secret) is dropped, never republished.
    records.append({"validator": validator, "registration": registration,
                    "moniker": str(record.get("moniker", ""))})
if problems:
    sys.stderr.write("\n".join(problems) + "\n")
    raise SystemExit(f"refusing the rehearsal: {len(problems)} invalid record(s)")
if len(records) < minimum:
    raise SystemExit(f"ceremony rehearsal needs at least {minimum} valid operator records, got {len(records)}")
out.write_text(json.dumps({"operators": records}, indent=2, sort_keys=True))
PY

"${BUD:-bud}" genesis assemble --network testnet \
    --operators "$REG_DIR" --out "$OUT_DIR/rehearsal-genesis.json" "${EXTRA[@]}"
sha256sum "$OUT_DIR/rehearsal-genesis.json" | tee "$OUT_DIR/rehearsal-genesis.sha256"
