#!/usr/bin/env bash
# ============================================================================
# check-bns-gate.sh — Phase 10 Bölüm 4: BNS test isim kanaryası
#
# `cargo test --lib bns` çıktısını alır ve 8 BNS testinin HER BİRİNİN
# isim-isim "... ok" göründüğünü doğrular (scripts/check-bud-e2e.sh deseni).
#
# Neden gerekli (vacuous-gate koruması): bir test silinir/yeniden adlandırılırsa
# `cargo test` yine yeşil kalabilir (daha az test geçer). Bu kapı, BNS suite'in
# BİREBİR isimleriyle koştuğunu kilitler (modül-bazlı denetim — toplam sayı
# üzerinden değil).
#
# Kullanım:
#   bash scripts/check-bns-gate.sh <test-cikti-dosyasi>   # kapı
#   bash scripts/check-bns-gate.sh --self-test            # kanarya (vacuous değil kanıtı)
# ============================================================================
set -euo pipefail

# Phase 10 Bölüm 4 zorunlu listesi — 8 BNS testi (birebir isim kilidi)
EXPECTED=(
  "test_bns_registration_and_resolution"
  "test_bns_expiration"
  "test_bns_cost_scaling"
  "test_bns_renewal"
  "test_bns_subdomains_owner_only"
  "test_bns_invalid_names"
  "test_bns_transfer"
  "test_bns_full_resolve_with_storage"
)

gate() {
  local out="$1"
  [ -s "$out" ] || { echo "FAIL: test ciktisi yok/bos: $out"; return 1; }
  local missing=0 name
  for name in "${EXPECTED[@]}"; do
    # Birebir yol + "ok" sonlanmasi — alt-dize eslesmesi engelli:
    if ! grep -Eq "^test ${name} \.\.\. ok$" "$out"; then
      echo "FAIL: beklenen test ciktida yok veya ok degil: $name"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "FAIL: bns isim kanaryasi — zorunlu 8 testten en az biri eksik/kirik."
    return 1
  fi
  echo "OK: bns 8 zorunlu test isim-isim ok."
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  # 1) TAM cikti → PASS
  {
    for name in "${EXPECTED[@]}"; do
      echo "test ${name} ... ok"
    done
  } > "$tmp/full.txt"
  # 2) test_bns_expiration EKSIK → FAIL olmali (vacuous degil)
  {
    for name in "${EXPECTED[@]}"; do
      [ "$name" = "test_bns_expiration" ] && continue
      echo "test ${name} ... ok"
    done
  } > "$tmp/missing.txt"
  # 3) test_bns_transfer FAILED → FAIL olmali
  {
    for name in "${EXPECTED[@]}"; do
      if [ "$name" = "test_bns_transfer" ]; then
        echo "test ${name} ... FAILED"
      else
        echo "test ${name} ... ok"
      fi
    done
  } > "$tmp/failed.txt"
  ok=0
  gate "$tmp/full.txt" >/dev/null || { echo "BOZUK KAPI: tam cikti reddedildi!"; ok=1; }
  if gate "$tmp/missing.txt" >/dev/null 2>&1; then
    echo "VACUOUS GATE: eksik test gecti!"; ok=1
  fi
  if gate "$tmp/failed.txt" >/dev/null 2>&1; then
    echo "VACUOUS GATE: FAILED satiri gecti!"; ok=1
  fi
  [ "$ok" -eq 0 ] || exit 1
  echo "kanarya OK: tam→PASS, eksik/FAILED→FAIL (kapi vacuous degil)."
  exit 0
fi

[ $# -ge 1 ] || { echo "kullanim: $0 <test-cikti-dosyasi> | --self-test"; exit 1; }
gate "$1"
