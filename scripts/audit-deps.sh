#!/usr/bin/env bash
# Scripts/audit-deps.sh - Rust dependency audit
#
# Bu script `cargo audit` aracını çalıştırır ve bilinen güvenlik
# Açıklarına karşı bağımlılıkları kontrol eder. ch12 §3.7 mainnet
# Blocker kapsamında.
#
# Kullanım:
#   ./scripts/audit-deps.sh
#
# Çıktı: stdout + `target/audit/DEPENDENCY_AUDIT.md` raporu.
# Kabul kriteri: hiçbir "unmaintained" warning'i dışında CVE olmamalı.
# "unmaintained" warning'leri ayrıca gözden geçirilir (false positive
# Olabilir; CI warning olarak raporlanır, fail etmez).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[audit-deps] Budlum Core dependency audit başlatılıyor..."

# 1. cargo audit yükle (yoksa)
if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "[audit-deps] cargo-audit yükleniyor..."
    cargo install --locked cargo-audit
fi

# 2. Her iki lockfile'ı da tara (root + budzero)
ROOT_AUDIT_JSON="$(mktemp)"
BUDZERO_AUDIT_JSON="$(mktemp)"
ROOT_RAW_OUT="$(mktemp)"
BUDZERO_RAW_OUT="$(mktemp)"
trap 'rm -f "$ROOT_AUDIT_JSON" "$BUDZERO_AUDIT_JSON" "$ROOT_RAW_OUT" "$BUDZERO_RAW_OUT"' EXIT

cargo audit --file Cargo.lock --json > "$ROOT_AUDIT_JSON" || ROOT_AUDIT_EXIT=$?
ROOT_AUDIT_EXIT="${ROOT_AUDIT_EXIT:-0}"

cargo audit --file budzero/Cargo.lock --json > "$BUDZERO_AUDIT_JSON" || BUDZERO_AUDIT_EXIT=$?
BUDZERO_AUDIT_EXIT="${BUDZERO_AUDIT_EXIT:-0}"

if [ "$ROOT_AUDIT_EXIT" -ne 0 ]; then
    AUDIT_EXIT="$ROOT_AUDIT_EXIT"
elif [ "$BUDZERO_AUDIT_EXIT" -ne 0 ]; then
    AUDIT_EXIT="$BUDZERO_AUDIT_EXIT"
else
    AUDIT_EXIT=0
fi

# 3. Raporu yaz
REPORT="$REPO_ROOT/target/audit/DEPENDENCY_AUDIT.md"
mkdir -p "$(dirname "$REPORT")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cargo audit --file Cargo.lock --deny warnings > "$ROOT_RAW_OUT" 2>&1 || true
cargo audit --file budzero/Cargo.lock --deny warnings > "$BUDZERO_RAW_OUT" 2>&1 || true

# Bulgular CI log'una BASILIR.
#
# Onceden basilmiyordu: `--json` gecici bir dosyaya, ham cikti da
# `target/audit/DEPENDENCY_AUDIT.md`'ye gidiyordu ve o raporu hicbir workflow
# artefakt olarak yuklemiyordu. Sonuc: is calisiyor, yesil doniyor ve tek bir
# danisma adi log'da gorunmuyordu.
#
# Bu bos bir titizlik degil. `.quality/deny.toml` `unmaintained = "none"`
# tutuyor ve bu kararin TEK gerekcesi soyle yazili: "Uyari gorunurlugu
# kaybolmuyor: CI dependency-audit job'indaki cargo audit her kosuda
# unmaintained uyarilarini raporlar." Raporlamiyordu.
#
# Ornek: RUSTSEC-2024-0380 (`pqcrypto-dilithium`, mainnet varsayilan PQ imza
# yolu). Karar verilmis ve `.quality/osv-scanner.toml`'da gerekcesiyle
# kayitli -- ama cargo audit tarafinda hicbir kosuda gorunmedi. Iki tarayici
# ayni agaci tariyor ve yalniz birinin sonucu okunabiliyordu.
echo ""
echo "──────── cargo audit - root Cargo.lock ────────"
cat "$ROOT_RAW_OUT"
echo "──────── cargo audit - budzero/Cargo.lock ────────"
cat "$BUDZERO_RAW_OUT"
echo "──────────────────────────────────────────────────"
echo ""

# Danisma kimliklerini ozetle: log'u okuyan biri hangi uyarilarin bilindigini
# tek bakista gorsun.
ADVISORIES="$(grep -hoE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$ROOT_RAW_OUT" "$BUDZERO_RAW_OUT" | sort -u || true)"
if [ -n "$ADVISORIES" ]; then
    echo "[audit-deps] Bu agacta gorulen danismalar:"
    printf '  - %s\n' $ADVISORIES
else
    echo "[audit-deps] Hicbir danisma bulunmadi."
fi
echo ""

{
    echo "# Dependency Audit Raporu"
    echo ""
    echo "**Oluşturulma:** $TIMESTAMP"
    echo "**Araç:** cargo-audit (https://github.com/rustsec/rustsec)"
    echo "**Repo:** lubosruler/budlum @ \`$(git rev-parse --short HEAD)\`"
    echo ""
    echo "## Özet"
    echo ""
    if [ "$AUDIT_EXIT" -eq 0 ]; then
        echo "- ✅ Bilinen güvenlik açığı **YOK** (root + budzero lockfile)."
    else
        echo "- ⚠️ cargo-audit exit code: $AUDIT_EXIT (genelde unmaintained warning)."
    fi
    echo "- Root lockfile exit code: $ROOT_AUDIT_EXIT"
    echo "- BudZero lockfile exit code: $BUDZERO_AUDIT_EXIT"
    echo ""
    echo "## Ham çıktı - root Cargo.lock"
    echo ""
    echo "\`\`\`"
    head -50 "$ROOT_RAW_OUT" || true
    echo "\`\`\`"
    echo ""
    echo "## Ham çıktı - budzero/Cargo.lock"
    echo ""
    echo "\`\`\`"
    head -50 "$BUDZERO_RAW_OUT" || true
    echo "\`\`\`"
    echo ""
    echo "## Kabul kriteri"
    echo ""
    echo "CI'da \`dependency-audit\` job'ı bu scripti çalıştırır. **Bilinen"
    echo "güvenlik açığı (CVE) tespit edilirse job fail eder.** Unmaintained"
    echo "warning'leri warning olarak raporlanır (fail etmez). Root ve BudZero"
    echo "lockfile'ları birlikte denetlenir."
    echo ""
    echo "Bu rapor  kapsamında otomatik üretilir."
} > "$REPORT"

echo "[audit-deps] Rapor: $REPORT"
echo "[audit-deps] Bitti."

# Exit code'u koru (CI için)
exit "$AUDIT_EXIT"
