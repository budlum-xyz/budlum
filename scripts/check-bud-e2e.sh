#!/usr/bin/env bash
# ============================================================================
# check-bud-e2e.sh — G14 (ADIM8.5 §4): bud_e2e invariant isim kanaryası
#
# `cargo test --lib bud_e2e` çıktısını alır ve 9 invariant + 3 e2e testinin
# HER BİRİNİN isim-isim "... ok" göründüğünü doğrular.
#
# Neden gerekli (vacuous-gate koruması): biri bir invariant'ı silersek ya da
# yeniden adlandırırsa `cargo test` yine yeşil kalabilir (daha az test geçer).
# Bu kapı, talimattaki 9 invariant'ın BİREBİR isimleriyle koştuğunu kilitler.
#
# Kullanım:
#   bash scripts/check-bud-e2e.sh <test-cikti-dosyasi>   # kapı
#   bash scripts/check-bud-e2e.sh --self-test            # kanarya (vacuous değil kanıtı)
# ============================================================================
set -euo pipefail

# ADIM8.5 §4 zorunlu listesi — 9 invariant + 3 e2e akış (birebir isim kilidi)
EXPECTED=(
  "invariant_1_no_whitelist_for_deal_or_challenge"
  "invariant_2_no_admin_pause_freeze_hook"
  "invariant_3_any_account_can_challenge_any_deal"
  "invariant_4_any_account_meeting_bond_can_open_deal"
  "invariant_5_opener_bond_must_be_positive"
  "invariant_6_slash_only_via_missed_deadline"
  "invariant_7_slashed_deal_rejects_new_challenges"
  "invariant_8_deal_requires_shard_to_be_in_manifest"
  "invariant_9_manifest_id_is_deterministic_across_nodes"
  "e2e_three_actor_manifest_to_challenge_flow"
  "e2e_missed_challenge_slashes_only_the_target_deal"
  "e2e_deal_queries_return_replica_set"
)

gate() {
  local out="$1"
  [ -s "$out" ] || { echo "FAIL: test çıktısı yok/boş: $out"; return 1; }
  local missing=0 name
  for name in "${EXPECTED[@]}"; do
    # Birebir isim + "ok" — alt-dize eşleşmesi (ör. invariant_1 → invariant_10) engelli:
    if ! grep -Eq "test tests::bud_e2e::${name} \.\.\. ok$" "$out"; then
      echo "FAIL: beklenen test çıktıda yok veya ok değil: $name"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "FAIL: bud_e2e isim kanaryası — zorunlu 12 testten en az biri eksik/kırık."
    return 1
  fi
  echo "OK: bud_e2e 12 zorunlu test (9 invariant + 3 e2e) isim-isim ok."
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  # 1) TAM çıktı → PASS
  {
    for name in "${EXPECTED[@]}"; do
      echo "test tests::bud_e2e::${name} ... ok"
    done
  } > "$tmp/full.txt"
  # 2) invariant_5 EKSİK → FAIL olmalı (vacuous değil)
  {
    for name in "${EXPECTED[@]}"; do
      [ "$name" = "invariant_5_opener_bond_must_be_positive" ] && continue
      echo "test tests::bud_e2e::${name} ... ok"
    done
  } > "$tmp/missing.txt"
  # 3) invariant_3 FAILED → FAIL olmalı
  {
    for name in "${EXPECTED[@]}"; do
      if [ "$name" = "invariant_3_any_account_can_challenge_any_deal" ]; then
        echo "test tests::bud_e2e::${name} ... FAILED"
      else
        echo "test tests::bud_e2e::${name} ... ok"
      fi
    done
  } > "$tmp/failed.txt"
  ok=0
  gate "$tmp/full.txt" >/dev/null || { echo "BOZUK KAPI: tam çıktı reddedildi!"; ok=1; }
  if gate "$tmp/missing.txt" >/dev/null 2>&1; then
    echo "VACUOUS GATE: eksik invariant geçti!"; ok=1
  fi
  if gate "$tmp/failed.txt" >/dev/null 2>&1; then
    echo "VACUOUS GATE: FAILED satırı geçti!"; ok=1
  fi
  [ "$ok" -eq 0 ] || exit 1
  echo "kanarya OK: tam→PASS, eksik/FAILED→FAIL (kapı vacuous değil)."
  exit 0
fi

[ $# -ge 1 ] || { echo "kullanım: $0 <test-cikti-dosyasi> | --self-test"; exit 1; }
gate "$1"
