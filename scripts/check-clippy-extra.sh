#!/usr/bin/env bash
# ============================================================================
# check-clippy-extra.sh — G2: clippy pedantic+nursery izleme-ratchet kapısı
# (ADIM8 §3.3 izleme modu + kullanıcının ratchet tercihiyle güçlendirilmiş:
#  sayı ARTARSA fail — düşmesi serbest, yeni baseline bilinçli PR'la düşürülür)
#
# Baseline kanıtı (2026-07-17, yerel, `98b0fd9` worktree):
#   cargo clippy --all-targets -- -W pedantic -W nursery → 191 uyarı, 20 lint
#   (en yüksek: uninlined_format_args 106, cast_precision_loss 14, cast_sign_loss 10)
#
# Kullanım:
#   bash scripts/check-clippy-extra.sh <clippy-json>   # kapı
#   bash scripts/check-clippy-extra.sh --self-test     # vacuous-gate kanaryası
# ============================================================================
set -euo pipefail

BASELINE_FILE="$(cd "$(dirname "$0")/.." && pwd)/.github/clippy-extra-baseline.txt"
BASELINE=$(grep -E '^[0-9]+$' "$BASELINE_FILE" | head -1)
[ -n "$BASELINE" ] || { echo "FAIL: baseline okunamadı ($BASELINE_FILE)"; exit 1; }

count_json() {
  python3 - "$1" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get('reason') == 'compiler-message':
        m = d['message']
        if m.get('level') == 'warning' and (m.get('code') or {}).get('code', '').startswith('clippy::'):
            n += 1
print(n)
PY
}

gate() {
  local json="$1"
  [ -s "$json" ] || { echo "FAIL: clippy JSON yok/boş: $json"; return 1; }
  local n
  n=$(count_json "$json")
  echo "clippy-extra: $n | baseline: $BASELINE"
  if [ "$n" -gt "$BASELINE" ]; then
    echo "FAIL: pedantic/nursery uyarı sayısı baseline'ı aştı (+$((n-BASELINE))) — yeni uyarı ratchet'e takıldı."
    return 1
  fi
  echo "OK: pedantic/nursery baseline altında/eşit (ratchet sağlam)."
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  python3 - "$tmp" <<'PY'
import json, pathlib, sys
base = pathlib.Path(sys.argv[1])
def msg(n, path):
    lines = [json.dumps({"reason": "compiler-message", "message": {
        "level": "warning", "code": {"code": "clippy::selftest_lint"}, "rendered": ""}})
        for _ in range(n)]
    path.write_text("\n".join(lines))
msg(2, base / "few.json")
msg(999999, base / "many.json")
PY
  if gate "$tmp/many.json" >/dev/null 2>&1; then
    echo "VACUOUS GATE: 999999 uyarı baseline'ı ($BASELINE) geçti!"; exit 1
  fi
  if ! gate "$tmp/few.json" >/dev/null 2>&1; then
    echo "BOZUK KAPI: 2 uyarı reddedildi!"; exit 1
  fi
  echo "kanarya OK: aşan FAIL, düşük PASS (kapı vacuous değil)."
  exit 0
fi

[ $# -ge 1 ] || { echo "kullanım: $0 <clippy-json> | --self-test"; exit 1; }
gate "$1"
