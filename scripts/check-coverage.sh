#!/usr/bin/env bash
# ============================================================================
# check-coverage.sh —  ratchet kapısı (kullanıcı kararı Q-7b1(a))
#
# Line coverage'ı .github/coverage-baseline.txt eşiğiyle karşılaştırır.
# Ratchet kuralı: baseline yalnız BİLİNÇLİ PR ile yükselir (sprint başına +%2
# hedef; %90 tavan = ADIM8.5 hedefi). Baseline'ı DÜŞÜRMEK CI gevşetme ihlalidir.
#
# Baseline kanıtı (2026-07-17, yerel, `ca668f8` üstü worktree):
#   cargo llvm-cov nextest --lib → lines 64.15% (14493/22594), functions 54.89%,
#   531/531 test PASS (60.46s). Eşik bu kanıtın altına yuvarlandı: 64.00.
#
# Kullanım:
#   bash scripts/check-coverage.sh <cov.json>   # kapı
#   bash scripts/check-coverage.sh --self-test  # vacuous-gate kanaryası
# ============================================================================
set -euo pipefail

BASELINE_FILE="$(cd "$(dirname "$0")/.." && pwd)/.github/coverage-baseline.txt"
BASELINE=$(grep -E '^[0-9]+(\.[0-9]+)?$' "$BASELINE_FILE" | head -1)
[ -n "$BASELINE" ] || { echo "FAIL: baseline dosyası okunamadı ($BASELINE_FILE)"; exit 1; }

gate() {
  local json="$1"
  [ -s "$json" ] || { echo "FAIL: coverage JSON yok/boş: $json"; exit 1; }
  python3 - "$json" "$BASELINE" <<'PYEOF'
import json, sys
path, baseline = sys.argv[1], float(sys.argv[2])
try:
    d = json.load(open(path))
    t = d["data"][0]["totals"]
    actual = float(t["lines"]["percent"])
except Exception as e:
    print(f"FAIL: coverage JSON parse edilemedi: {e}")
    raise SystemExit(1)
L = t["lines"]
print(f"lines: {L['covered']}/{L['count']} = {actual:.2f}%  |  baseline: {baseline:.2f}%")
if actual + 1e-9 < baseline:
    print(f"FAIL: coverage %{actual:.2f} baseline'ın (%{baseline:.2f}) ALTINDA — regresyon kapısı.")
    raise SystemExit(1)
print("OK: coverage baseline üstünde (ratchet sağlam).")
PYEOF
}

if [ "${1:-}" = "--self-test" ]; then
  # Kanarya: düşük JSON FAIL, yüksek JSON PASS olmak zorunda — yoksa kapı vacuous.
  tmp=$(mktemp -d)
  python3 - "$tmp" <<'PYEOF'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1])
def fake(pct):
    return {"type": "coverage", "data": [{"totals": {
        "lines": {"count": 100, "covered": int(pct), "percent": float(pct)},
        "functions": {"count": 0, "covered": 0, "percent": 0.0},
        "regions": {"count": 0, "covered": 0, "percent": 0.0}}}]}
(base / "low.json").write_text(json.dumps(fake(0.0)))
(base / "high.json").write_text(json.dumps(fake(100.0)))
PYEOF
  if gate "$tmp/low.json" >/dev/null 2>&1; then
    echo "VACUOUS GATE: %0 coverage baseline'ı (%$BASELINE) geçti!"; exit 1
  fi
  if ! gate "$tmp/high.json" >/dev/null 2>&1; then
    echo "BOZUK KAPI: %100 coverage reddedildi!"; exit 1
  fi
  echo "kanarya OK: düşük coverage FAIL, yüksek coverage PASS (kapı vacuous değil)."
  exit 0
fi

[ $# -ge 1 ] || { echo "kullanım: $0 <cov.json> | --self-test"; exit 1; }
gate "$1"
