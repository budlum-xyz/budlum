#!/usr/bin/env bash
# ============================================================================
# check-geiger.sh — G11 (ADIM8.5 §2): cargo-geiger unsafe görünürlük raporu
#
# cargo geiger --all-targets çıktısını alır. First-party crate'lerde
# (budlum-core, bud-*) unsafe kullanımı SIFIR beklenir — src/lib.rs
# `#![forbid(unsafe_code)]` bunu derleme zamanında ZATEN kilitler (bu kapı
# ikinci, bağımsız kanıt katmanıdır). Üçüncü-taraf bağımlılıklar BİLGİ
# amaçlı basılır (gate'e girmez — her dep update'i farklı unsafe taşır;
# ratchet kırılgan olur, dürüst scoping).
#
# Kullanım:
#   bash scripts/check-geiger.sh <geiger-cikti>   # kapı (first-party 0)
#   bash scripts/check-geiger.sh --self-test      # kanarya
# ============================================================================
set -euo pipefail

gate() {
  local out="$1"
  [ -s "$out" ] || { echo "FAIL: geiger çıktısı yok/boş: $out"; return 1; }
  # First-party satırları: 'budlum-core' veya 'bud-' ile başlayanlar; Unsafe
  # kullanım sütunu: "0/..." dışında bir değer = FAIL.
  local fp_bad
  fp_bad=$(grep -E '^(budlum-core|bud-)' "$out" | grep -vE '\b0/[0-9]+' || true)
  if [ -n "$fp_bad" ]; then
    echo "FAIL: first-party crate'te sıfır-olmayan unsafe kullanımı (G1 forbid ile çelişir — sahte rapor olabilir!):"
    echo "$fp_bad"
    return 1
  fi
  local total
  total=$(grep -cE '^[a-z]' "$out" || true)
  echo "OK: first-party unsafe kullanımı = 0 (G1 forbid ile tutarlı). $total satır inceleme (deps bilgi amaçlı):"
  grep -E '^[a-z]' "$out" | head -20 || true
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  cat > "$tmp/temiz.txt" << 'T'
budlum-core 0/120
bud-proof 0/44
ring 17/8920
sled 3/1200
T
  cat > "$tmp/kirli.txt" << 'T'
budlum-core 2/120
ring 17/8920
T
  code=0
  gate "$tmp/kirli.txt" >/dev/null 2>&1 || code=$?
  [ "$code" -eq 1 ] || { echo "VACUOUS GATE: first-party unsafe (2) geçti!"; exit 1; }
  gate "$tmp/temiz.txt" >/dev/null 2>&1 || { echo "BOZUK KAPI: temiz çıktı reddedildi!"; exit 1; }
  echo "kanarya OK: first-party unsafe FAIL, deps-unsafe PASS (bilgi), temiz PASS."
  exit 0
fi
[ $# -ge 1 ] || { echo "kullanım: $0 <geiger-cikti> | --self-test"; exit 1; }
gate "$1"
