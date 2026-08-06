#!/usr/bin/env bash
# ============================================================================
# Check-semver.sh - sertleştirme (2026-07-21):
# Cargo-semver-checks public API breakage GATE.
#
# Geçmiş: `.github/workflows/semver.yml` her adımda `continue-on-error: true`
# Idi ve crates.io base'i olmadığı için `check-release` anlamlı çalışamıyordu.
# Bugün: iki-checkout (current vs baseline) + `--baseline-root`, kapı FAIL
# Verebilir (CI tek hakem; sahte-yeşil yasak).
#
# Politika:
#   * cargo-semver-checks exit 0 → PASS (public API kırılması yok).
#   * exit != 0 (kırılma raporu VEYA altyapı hatası) →
#     `.github/semver-exceptions.txt` içinde yorum-olmayan en az bir satır
#     Varsa PASS-İSTİSNA (kanıtlı kabul - her satır gerekçe taşır, kullanıcı
#     Onayı gerekir; .quality/deny.toml [advisories] ignore disipliniyle aynı ruh),
#     Yoksa FAIL.
#
# Kullanım:
#   Bash scripts/check-semver.sh --self-test # kanarya (statik)
#   Bash scripts/check-semver.sh <current-root> <baseline-root>  # gate
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

  # 3) Sınıflandırmayı GERÇEKTEN çalıştır.
  #
  # Bu bölüm eskiden kaynakta "SEMVER_INFRA_PATTERN geçiyor mu" diye dize
  # arıyordu. Bir deseni yanlış yazmaya karşı hiçbir koruma vermez: desen
  # hiç çalıştırılmıyordu. Kanarya, kapının FAIL EDEBİLDİĞİNİ kanıtlamalı.
  local tmp
  tmp="$(mktemp -d)"
  local report="$tmp/report" empty_exc="$tmp/none" filled_exc="$tmp/some"
  : > "$empty_exc"
  printf '# yorum\n\n' >> "$empty_exc"
  printf 'BDLM-1: bilinecek kirilma, kullanici onayli\n' > "$filled_exc"

  # 3a) Altyapı crash'i: istisna dosyası DOLU olsa bile reddedilmeli.
  #     Maskelenmesi kabul edilemez olan sınıf budur; crash "kırılma yok"
  #     demek değil, "bilinemiyor" demektir.
  #
  #     Her crash örneği, YANINDA gerçek bir kırılma raporu ile birlikte
  #     verilir. Sebep ölçüldü: crash tek başına verilirse, INFRA deseninden
  #     düşse bile "ne rapor ne crash" kolu (3c) onu yakalar ve kanarya
  #     yine geçer. Yani desen silinse fark edilmezdi. Rapor satırı eklemek
  #     3c'yi devre dışı bırakır ve testi TAM OLARAK INFRA desenine bağlar:
  #     desen eşleşmezse istisna uygulanır ve PASS olur, kanarya kırılır.
  local infra_cases=(
    'error: could not document `budlum-core`'
    'error[E0432]: unresolved import'
    'error: running cargo-metadata failed'
    'error: failed to build rustdoc'
    'error: no such command: `semver-checks`'
  )
  local case_line
  for case_line in "${infra_cases[@]}"; do
    {
      printf '%s\n' "$case_line"
      printf -- '--- failure struct_missing: pub struct removed\n'
    } > "$report"
    if classify_semver_report "$report" "$filled_exc" >/dev/null 2>&1; then
      rm -rf "$tmp"
      fail "self-test: altyapı hatası istisnayla maskelendi: $case_line"
    fi
  done

  # 3c) Tanınmayan çıktı: ne rapor ne bilinen crash -> fail-closed.
  printf 'beklenmedik bir sey\n' > "$report"
  if classify_semver_report "$report" "$empty_exc" >/dev/null 2>&1; then
    rm -rf "$tmp"
    fail "self-test: sınıflandırılamayan çıktı geçirildi (fail-closed değil)"
  fi

  # 3d) Gerçek kırılma, istisnasız -> reddedilmeli.
  printf -- '--- failure struct_missing: pub struct removed\n' > "$report"
  if classify_semver_report "$report" "$empty_exc" >/dev/null 2>&1; then
    rm -rf "$tmp"
    fail "self-test: istisnasız kırılma geçirildi"
  fi

  # 3e) Gerçek kırılma + gerekçeli istisna -> geçmeli. Bu olmadan kapı
  #     "her şeyi reddet" olurdu ve yukarıdaki dördü de bedavaya geçerdi.
  printf -- '--- failure struct_missing: pub struct removed\n' > "$report"
  if ! classify_semver_report "$report" "$filled_exc" >/dev/null 2>&1; then
    rm -rf "$tmp"
    fail "self-test: gerekçeli istisna kabul edilmedi (kapı her şeyi reddediyor)"
  fi

  rm -rf "$tmp"
  echo "kanarya OK: crash maskelenmiyor, tanınmayan çıktı fail-closed, kırılma"
  echo "  istisnasız FAIL / gerekçeli istisnayla PASS (kapı vacuous değil)."
}

semver_checks_gate() {
  # Mutlak yola kanonikleştir: gate alt kabuğu `cd "$current"` yapar; göreli
  # Baseline yolu (ör. ./baseline) cd sonrası çözümsüz kalır → CI'da
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
    # Kelimesini böler); kapı her ortamda plaintext rapor üzerinden karar verir.
    # --default-features (kök-neden, 2026-07-21 CI kanıtı + lokal tam repro):
    # Cargo-semver-checks default'ta ~--all-features heuristiğiyle rustdoc
    # Üretir; budlum-core'da `pq-dilithium`+`pq-ml-dsa` mutually-exclusive
    # (src/crypto/primitives.rs compile_error!) olduğundan heuristic doc
    # Derlemesini exit 101 "could not document" ile öldürüyordu. Gate,
    # Projenin gerçek build'ini temsil eden crate-defined default setiyle koşar.
    CARGO_TERM_COLOR=never \
      cargo semver-checks check-release -p budlum-core --baseline-root "$baseline" --default-features
  ) >"$out" 2>&1 || status=$?
  # Güvenlik ağı: env'in etkisiz kaldığı senaryo için ANSI strip idempotent'tir.
  sed -i 's/\x1b\[[0-9;]*[A-Za-z]//g' "$out"
  sed -n '1,240p' "$out"

  if [ "$status" -eq 0 ]; then
    echo "SEMVER GATE: PASS - public API kırılması yok (budlum-core vs baseline)."
    rm -f "$out"
    return 0
  fi

  echo "::warning::cargo-semver-checks kırılma/hata raporladı (exit=$status)."
  # SINIFLANDIRMA (v2, 2026-07-21): exit 101 iki TAMAMEN farklı
  # Sınıftan gelir - (a) breakage raporu ("--- failure <lint>" +
  # "requires new major/minor version"), (b) altyapı hatası (rustdoc-json
  # Crash, cargo-doc/metadata başarısızlığı, E45xx derleme hatası).
  classify_semver_report "$out" "$exc"
  local verdict=$?
  rm -f "$out"
  return $verdict
}

# Sınıflandırma: rapor dosyası + istisna dosyası -> karar.
#
# Gate gövdesinden AYRILDI çünkü kanaryası bunu çalıştırabilsin. Eskiden bu
# mantık `semver_checks_gate` içine gömülüydü ve `--self-test` yalnızca kendi
# kaynağında dize arıyordu: "SEMVER_INFRA_PATTERN geçiyor mu". Bu, deseni
# YANLIŞ yazmaya karşı hiçbir koruma vermez, çünkü desenin kendisi hiç
# çalıştırılmıyordu. Bir kanarya, kapının fail edebildiğini KANITLAMALI;
# kaynakta bir kelime aramak kanıt değildir.
#
# 0 = geç, 1 = reddet.
classify_semver_report() {
  local out="$1" exc="$2"

  # İstisnaların anlamı "(b-c) bilinen kırılmayı gerekçesiyle kabul"
  # Olduğundan maskelenmesi KABUL EDİLEMEZ şey altyapı crash'idir:
  # Crash = "kırılma olup olmadığı BİLİNEMEZ" (kanıt yok), sahte-yeşil olur.
  # Bu yüzden INFRA sınıfında istisna listesi DEVRE DIŞI, kapı fail-closed.
  local SEMVER_INFRA_PATTERN='^error: running cargo-(doc|metadata)|error\[E[0-9]+\]|^error: could not (compile|document)|^error: failed to build rustdoc|failed to parse lock file|no matching package|^error: no such command'
  if grep -Eq "$SEMVER_INFRA_PATTERN" "$out"; then
    echo "SEMVER GATE: FAIL - araç ALTYAPI hatasıyla sonuçsuz kaldı (crash≠kırılma; istisna uygulanamaz)." >&2
    echo "İstisna mekanizması yalnızca gerçek kırılma raporlarına uygulanır." >&2
    return 1
  fi
  if ! grep -Eq '^--- (failure|warning)|requires new (major|minor) version' "$out"; then
    echo "SEMVER GATE: FAIL - çıktı ne kırılma raporu ne bilinen altyapı hatası (fail-closed sınıflandırma)." >&2
    return 1
  fi
  if [ -f "$exc" ] && grep -vqE '^[[:space:]]*(#|$)' "$exc"; then
    echo "SEMVER GATE: PASS-İSTİSNA - .github/semver-exceptions.txt gerekçeli kabul içeriyor:"
    grep -vE '^[[:space:]]*(#|$)' "$exc" | sed 's/^/  ISTISNA: /'
    return 0
  fi

  echo "SEMVER GATE: FAIL - public API kırılması istisnasız." >&2
  echo "Seçenekler: (a) kırılmayı geri al, (b) MAJOR/MINOR niyetliyse ve kullanıcı" >&2
  echo "onaylıysa .github/semver-exceptions.txt'e gerekçeli satır ekle." >&2
  return 1
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

semver_checks_gate "${1:?usage: check-semver.sh <current-root> <baseline-root>}" \
  "${2:?usage: check-semver.sh <current-root> <baseline-root>}"
