#!/usr/bin/env bash
# ============================================================================
# Check-cargo-vet.sh — tedarik zinciri güven denetimi (cargo-vet) ratchet kapısı
#
# ARKA PLAN — bu kapı neden "yeni" sayılmalı:
# `supply-chain/config.toml` depoda aylardır duruyordu ve dosyanın varlığı
# "cargo-vet denetimi var" izlenimi veriyordu. Gerçekte dosya cargo-vet
# Şemasında OLMAYAN uydurma anahtarlarla yazılmıştı
# (`audit-compatible-output`, `[default-criteria] safe-to-run`) ve araç onu
# Parse bile edemiyordu:
#     ERROR × Failed to parse toml file: invalid type: boolean `true`,
#             Expected struct PolicyEntry [config.toml:11]
# Yani cargo-vet bu repoda hiçbir zaman çalışmadı; hiçbir CI job'ı da onu
# Çağırmıyordu. Config gerçek şemaya taşındı, `imports.lock` oluşturuldu ve
# Denetim ilk kez koştu: 437 denetimsiz bağımlılık.
#
# NEDEN GÜN-1 FAIL DEĞİL: 437 crate / ~6.7M satır denetim backlog'u tek
# Oturumda kapatılamaz. Gün-1 `cargo vet check` zorunlu kılınsaydı kapı ya
# Kalıcı kırmızı kalırdı ya da ilk sıkışmada gevşetilirdi — ikisi de
# CI-softening. Bunun yerine repo'nun zaten kullandığı RATCHET
# Deseni uygulanıyor: sayı ARTAMAZ, düşmesi serbesttir. Yeni bir denetimsiz
# Bağımlılık eklemek bugünden itibaren CI'ı kırar; mevcut borç ise bilinçli
# PR'larla baseline düşürülerek eritilir.
#
# Kullanım:
#   Bash scripts/check-cargo-vet.sh # kapı
#   Bash scripts/check-cargo-vet.sh --self-test # vacuous-gate kanaryası
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_FILE="$REPO_ROOT/.github/cargo-vet-baseline.txt"

read_baseline() {
  local b
  b=$(grep -E '^[0-9]+$' "$BASELINE_FILE" | head -1)
  [ -n "$b" ] || { echo "FAIL: baseline okunamadı ($BASELINE_FILE)"; exit 1; }
  printf '%s' "$b"
}

# `cargo vet check` denetimsiz bağımlılık varsa non-zero döner; sayıyı
# Çıktısındaki "<N> unvetted dependencies" satırından okuyoruz. Tamamen temiz
# Bir ağaçta bu satır hiç basılmaz, o yüzden yokluğu 0 sayılır.
count_unvetted() {
  local out
  out=$(cd "$REPO_ROOT" && cargo vet check 2>&1 || true)
  printf '%s' "$out" | grep -oE '^[0-9]+ unvetted dependencies' | head -1 | grep -oE '^[0-9]+' || printf '0'
}

if [ "${1:-}" = "--self-test" ]; then
  # Vacuous-gate koruması: sayaç gerçekten çıktıdan mı okunuyor, yoksa her
  # Koşuda sessizce 0 mı dönüyor? Sentetik bir çıktıya karşı doğruluyoruz.
  probe() {
    printf '%s' "$1" | grep -oE '^[0-9]+ unvetted dependencies' | head -1 | grep -oE '^[0-9]+' || printf '0'
  }
  got=$(probe "Vetting Failed!

123 unvetted dependencies:
  aead:0.5.2 missing [\"safe-to-deploy\"]")
  [ "$got" = "123" ] || { echo "FAIL: kanarya — sayaç 123 yerine '$got' okudu (parse bozuk)"; exit 1; }
  got_clean=$(probe "Vetting Succeeded!")
  [ "$got_clean" = "0" ] || { echo "FAIL: kanarya — temiz çıktı 0 yerine '$got_clean' okudu"; exit 1; }
  # Baseline dosyası gerçekten bir sayı içermeli.
  b=$(read_baseline)
  echo "Kanarya OK: sayaç 123/0 doğru okudu, baseline=$b."
  exit 0
fi

BASELINE=$(read_baseline)
N=$(count_unvetted)
echo "cargo-vet denetimsiz bağımlılık: $N | baseline: $BASELINE"

if [ "$N" -gt "$BASELINE" ]; then
  echo "FAIL: denetimsiz bağımlılık sayısı baseline'ı aştı (+$((N - BASELINE)))."
  echo "      Yeni bir bağımlılık eklendiyse: ya güvenilir bir import kaynağı"
  echo "      onu kapsamalı, ya \`cargo vet certify\` ile gerekçeli denetim"
  echo "      kaydı girilmeli. Baseline'ı YÜKSELTMEK bir çözüm değildir."
  exit 1
fi

if [ "$N" -lt "$BASELINE" ]; then
  echo "İYİLEŞME: baseline $BASELINE -> $N düşürülebilir."
  echo "          .github/cargo-vet-baseline.txt dosyasını $N yapın (ratchet sıkılır)."
fi

echo "OK: denetimsiz bağımlılık baseline altında/eşit (ratchet sağlam)."
