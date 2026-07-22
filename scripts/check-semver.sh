#!/usr/bin/env bash
# ============================================================================
# check-semver.sh — ADIM-1 (ARENA2, 2026-07-21) Madde 5 sertleştirmesi:
# cargo-semver-checks public API breakage GATE.
#
# Geçmiş: `.github/workflows/semver.yml` her adımda `continue-on-error: true`
# idi ve crates.io base'i olmadığı için `check-release` anlamlı çalışamıyordu.
# Bugün: iki-checkout (current vs baseline) + `--baseline-root`, kapı FAIL
# verebilir (CI tek hakem; sahte-yeşil yasak).
#
# Politika:
#   * cargo-semver-checks exit 0 → PASS (public API kırılması yok).
#   * exit != 0 (kırılma raporu VEYA altyapı hatası) →
#     `.github/semver-exceptions.txt` içinde yorum-olmayan en az bir satır
#     varsa PASS-İSTİSNA (kanıtlı kabul — her satır gerekçe taşır, kullanıcı
#     onayı gerekir; deny.toml [advisories] ignore disipliniyle aynı ruh),
#     yoksa FAIL.
#
# Kullanım:
#   bash scripts/check-semver.sh --self-test                 # kanarya (statik)
#   bash scripts/check-semver.sh <current-root> <baseline-root>  # gate
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

self_test() {
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  # 1) Script kendisi sözdizimsel olarak geçerli mi?
  bash -n "$repo_root/scripts/check-semver.sh" || fail "self-test: bash -n broke"
  # 2) Exceptions dosyası mevcut ve başlığı taşıyor mu?
  local exc="$repo_root/.github/semver-exceptions.txt"
  [[ -f "$exc" ]] || fail "self-test: missing .github/semver-exceptions.txt"
  grep -Fq "SEMVER EXCEPTIONS" "$exc" || fail "self-test: exceptions header missing"
  grep -Fiq "kullanıcı onayı" "$exc" || fail "self-test: exceptions policy line missing"
  # 3) Gate fonksiyonları tanımlı mı?
  grep -Fq "semver_checks_gate" "$repo_root/scripts/check-semver.sh" \
    || fail "self-test: gate function missing"
  # 4) Sınıflandırma kanaryası: INFRA kilidi mevcut mu (crash≠kırılma — istisna
  #    yalnız kırılma raporuna uygulanabilir; altyapı çökmesi maskelenemez).
  grep -Fq "SEMVER_INFRA_PATTERN" "$repo_root/scripts/check-semver.sh" \
    || fail "self-test: infra/crash classification missing"
}

semver_checks_gate() {
  # Mutlak yola kanonikleştir: gate alt kabuğu `cd "$current"` yapar; göreli
  # baseline yolu (ör. ./baseline) cd sonrası çözümsüz kalır → CI'da
  # "path './baseline' is not a directory or a manifest" (ilk koşu, kök neden).
  local current baseline
  current="$(cd "$1" 2>/dev/null && pwd)" || fail "current root yok: $1"
  baseline="$(cd "$2" 2>/dev/null && pwd)" || fail "baseline root yok: $2"
  [[ -f "$current/Cargo.toml" ]] || fail "current root without Cargo.toml: $current"
  [[ -f "$baseline/Cargo.toml" ]] || fail "baseline root without Cargo.toml: $baseline"
  command -v cargo-semver-checks >/dev/null 2>&1 \
    || fail "cargo-semver-checks not installed (cargo install cargo-semver-checks --locked)"

  local exc="$current/.github/semver-exceptions.txt"
  [[ -f "$exc" ]] || exc="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/semver-exceptions.txt"

  local out
  out="$(mktemp)"
  local status=0
  (
    cd "$current"
    # Renkli çıktı sınıflandırma regex'lerini bozar (ANSI kaçışları "error:"
    # kelimesini böler); kapı her ortamda plaintext rapor üzerinden karar verir.
    # --default-features (kök-neden, 2026-07-21 CI kanıtı + lokal tam repro):
    # cargo-semver-checks default'ta ~--all-features heuristiğiyle rustdoc
    # üretir; budlum-core'da `pq-dilithium`+`pq-ml-dsa` mutually-exclusive
    # (src/crypto/primitives.rs compile_error!) olduğundan heuristic doc
    # derlemesini exit 101 "could not document" ile öldürüyordu. Gate,
    # projenin gerçek build'ini temsil eden crate-defined default setiyle koşar.
    CARGO_TERM_COLOR=never \
      cargo semver-checks check-release -p budlum-core --baseline-root "$baseline" --default-features
  ) >"$out" 2>&1 || status=$?
  # Güvenlik ağı: env'in etkisiz kaldığı senaryo için ANSI strip idempotent'tir.
  sed -i 's/\x1b\[[0-9;]*[A-Za-z]//g' "$out"
  sed -n '1,240p' "$out"

  if [ "$status" -eq 0 ]; then
    echo "SEMVER GATE: PASS — public API kırılması yok (budlum-core vs baseline)."
    rm -f "$out"
    return 0
  fi

  echo "::warning::cargo-semver-checks kırılma/hata raporladı (exit=$status)."
  # SINIFLANDIRMA (v2, ARENA2 2026-07-21): exit 101 iki TAMAMEN farklı
  # sınıftan gelir — (a) breakage raporu ("--- failure <lint>" +
  # "requires new major/minor version"), (b) altyapı hatası (rustdoc-json
  # crash, cargo-doc/metadata başarısızlığı, E45xx derleme hatası).
  # İstisnaların anlamı "(b-c) bilinen kırılmayı gerekçesiyle kabul"
  # olduğundan maskelenmesi KABUL EDİLEMEZ şey altyapı crash'idir:
  # crash = "kırılma olup olmadığı BİLİNEMEZ" (kanıt yok), sahte-yeşil olur.
  # Bu yüzden INFRA sınıfında istisna listesi DEVRE DIŞI — kapı fail-closed.
  local SEMVER_INFRA_PATTERN='^error: running cargo-(doc|metadata)|error\[E[0-9]+\]|^error: could not (compile|document)|^error: failed to build rustdoc|failed to parse lock file|no matching package|^error: no such command'
  if grep -Eq "$SEMVER_INFRA_PATTERN" "$out"; then
    echo "SEMVER GATE: FAIL — araç ALTYAPI hatasıyla sonuçsuz kaldı (crash≠kırılma; istisna uygulanamaz)." >&2
    echo "İstisna mekanizması yalnızca gerçek kırılma raporlarına uygulanır." >&2
    rm -f "$out"
    return 1
  fi
  if ! grep -Eq '^--- (failure|warning)|requires new (major|minor) version' "$out"; then
    echo "SEMVER GATE: FAIL — çıktı ne kırılma raporu ne bilinen altyapı hatası (fail-closed sınıflandırma)." >&2
    rm -f "$out"
    return 1
  fi
  if [ -f "$exc" ] && grep -vqE '^[[:space:]]*(#|$)' "$exc"; then
    echo "SEMVER GATE: PASS-İSTİSNA — .github/semver-exceptions.txt gerekçeli kabul içeriyor:"
    grep -vE '^[[:space:]]*(#|$)' "$exc" | sed 's/^/  ISTISNA: /'
    rm -f "$out"
    return 0
  fi

  echo "SEMVER GATE: FAIL — public API kırılması istisnasız." >&2
  echo "Seçenekler: (a) kırılmayı geri al, (b) MAJOR/MINOR niyetliyse ve kullanıcı" >&2
  echo "onaylıysa .github/semver-exceptions.txt'e gerekçeli satır ekle." >&2
  rm -f "$out"
  return 1
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

semver_checks_gate "${1:?usage: check-semver.sh <current-root> <baseline-root>}" \
  "${2:?usage: check-semver.sh <current-root> <baseline-root>}"
