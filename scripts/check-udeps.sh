#!/usr/bin/env bash
# ============================================================================
# check-udeps.sh — G3 (ADIM8 §3.3): cargo-udeps kullanılmayan-bağımlılık kapısı
#
# `cargo +nightly udeps --all-targets` çıktısındaki GERÇEK formatı parse eder:
#   unused dependencies:
#   `budlum-core v0.1.0 (/path)`
#   └─── dependencies
#        ├─── "chrono"
#        └─── "group"
# Her bulgu "<paket>:<dep>" biçimine indirgenir ve .github/udeps-baseline.txt
# (izin verilenler, doc-test/YALANCI-pozitif notlarıyla) ile karşılaştırılır.
# Baseline'da OLMAYAN bulgu = FAIL (ratchet: yeni kullanılmayan dep eklenemez).
# Baseline dosyası yoksa SKIP (adım 1 ölçüm modu — vacuous-gate YOK).
#
# Kullanım:
#   bash scripts/check-udeps.sh <udeps-cikti>   # kapı
#   bash scripts/check-udeps.sh --self-test     # kanarya (gerçek formatla)
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="$ROOT/.github/udeps-baseline.txt"

parse() {
  # stdout: "paket:dep" satırları (gerçek udeps ağaç çıktısından)
  python3 - "$1" << 'PYEOF'
import re, sys
pkg = None
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.match(r"^`([a-zA-Z0-9_-]+) v[0-9]", line)
    if m:
        pkg = m.group(1)
        continue
    m = re.match(r"^\s+[├└]───\s+\"([^\"]+)\"", line)
    if m and pkg:
        print(f"{pkg}:{m.group(1)}")
PYEOF
}

gate() {
  local out="$1"
  [ -s "$out" ] || { echo "FAIL: udeps çıktısı yok/boş: $out"; return 1; }
  local found
  found=$(parse "$out")
  if [ -z "$found" ]; then
    echo "OK: kullanılmayan bağımlılık yok (parse edilmiş)."
    return 0
  fi
  if [ ! -f "$BASELINE" ]; then
    echo "SKIP: $BASELINE yok — ilk ölçüm (adım 1); bulgular:"
    echo "$found"
    return 0
  fi
  local fail=0 line
  while IFS= read -r line; do
    if ! grep -qxF "$line" "$BASELINE"; then
      echo "FAIL: baseline'da olmayan kullanılmayan bağımlılık: $line"
      fail=1
    fi
  done <<< "$found"
  if [ "$fail" -eq 0 ]; then
    echo "OK: tüm bulgular bilinen baseline'da ($(echo "$found" | wc -l) adet)."
    return 0
  fi
  return 1
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  # GERÇEK udeps çıktısı biçimi (e937a1c CI kanıtı)
  cat > "$tmp/real.txt" << 'T'
info: Loading depinfo from "x.d"
unused dependencies:
`budlum-core v0.1.0 (/x/budlum)`
└─── dependencies
     ├─── "chrono"
     └─── "group"
Note: They might be false-positive.
`bud-node v0.1.0 (/x/budzero/bud-node)`
└─── dependencies
     └─── "serde_json"
T
  p=$(parse "$tmp/real.txt")
  exp=$'budlum-core:chrono\nbudlum-core:group\nbud-node:serde_json'
  [ "$p" = "$exp" ] || { echo "BOZUK PARSE: beklenen=[$exp] gelen=[$p]"; exit 1; }
  printf 'budlum-core:chrono\nbudlum-core:group\nbud-node:serde_json\n' > "$tmp/base.txt"
  cp "$tmp/base.txt" "$ROOT/.github/udeps-baseline.txt"
  code=0
  gate "$tmp/real.txt" >/dev/null 2>&1 || code=$?
  [ "$code" -eq 0 ] || { echo "BOZUK KAPI: tam baseline reddedildi!"; rm -f "$ROOT/.github/udeps-baseline.txt"; exit 1; }
  printf 'budlum-core:chrono\n' > "$ROOT/.github/udeps-baseline.txt"
  code=0
  gate "$tmp/real.txt" >/dev/null 2>&1 || code=$?
  [ "$code" -eq 1 ] || { echo "VACUOUS GATE: eksik baseline (bud-node:serde_json) geçti!"; rm -f "$ROOT/.github/udeps-baseline.txt"; exit 1; }
  echo "all used" > "$tmp/temiz.txt"
  printf 'anything:goes\n' > "$ROOT/.github/udeps-baseline.txt"
  gate "$tmp/temiz.txt" >/dev/null 2>&1 || { echo "BOZUK KAPI: temiz çıktı reddedildi!"; rm -f "$ROOT/.github/udeps-baseline.txt"; exit 1; }
  rm -f "$ROOT/.github/udeps-baseline.txt"
  echo "kanarya OK: gerçek-format parse doğru; eksik-baseline FAIL, tam PASS, temiz PASS."
  exit 0
fi
[ $# -ge 1 ] || { echo "kullanım: $0 <udeps-cikti> | --self-test"; exit 1; }
gate "$1"
