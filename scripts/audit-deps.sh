#!/usr/bin/env bash
# scripts/audit-deps.sh — Rust dependency audit (Task 0.40 §1.7)
#
# Bu script `cargo audit` aracını çalıştırır ve bilinen güvenlik
# açıklarına karşı bağımlılıkları kontrol eder. ch12 §3.7 mainnet
# blocker kapsamında.
#
# Kullanım:
#   ./scripts/audit-deps.sh
#
# Çıktı: stdout + `docs/operations/DEPENDENCY_AUDIT.md` raporu.
# Kabul kriteri: hiçbir "unmaintained" warning'i dışında CVE olmamalı.
# "unmaintained" warning'leri ayrıca gözden geçirilir (false positive
# olabilir; CI warning olarak raporlanır, fail etmez).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[audit-deps] Budlum Core dependency audit başlatılıyor..."

# 1. cargo audit yükle (yoksa)
if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "[audit-deps] cargo-audit yükleniyor..."
    cargo install --locked cargo-audit
fi

# 2. JSON çıktısı al
AUDIT_JSON="$(mktemp)"
trap 'rm -f "$AUDIT_JSON"' EXIT
cargo audit --json > "$AUDIT_JSON" || AUDIT_EXIT=$?
AUDIT_EXIT="${AUDIT_EXIT:-0}"

# 3. Raporu yaz
REPORT="$REPO_ROOT/docs/operations/DEPENDENCY_AUDIT.md"
mkdir -p "$(dirname "$REPORT")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

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
        echo "- ✅ Bilinen güvenlik açığı **YOK**."
    else
        echo "- ⚠️ cargo-audit exit code: $AUDIT_EXIT (genelde unmaintained warning)."
    fi
    echo ""
    echo "## Ham çıktı"
    echo ""
    echo "\`\`\`"
    # Not: çıktıyı doğrudan `| head`e vermek EPIPE'de cargo-audit'i abort
    # ettirebiliyor (CI'da "core dumped" gürültüsü). Önce dosyaya yaz.
    RAW_OUT="$(mktemp)"
    cargo audit --deny warnings > "$RAW_OUT" 2>&1 || true
    head -50 "$RAW_OUT" || true
    rm -f "$RAW_OUT"
    echo "\`\`\`"
    echo ""
    echo "## Kabul kriteri"
    echo ""
    echo "CI'da \`dependency-audit\` job'ı bu scripti çalıştırır. **Bilinen"
    echo "güvenlik açığı (CVE) tespit edilirse job fail eder.** Unmaintained"
    echo "warning'leri warning olarak raporlanır (fail etmez)."
    echo ""
    echo "Bu rapor Task 0.40 §1.7 kapsamında otomatik üretilir."
} > "$REPORT"

echo "[audit-deps] Rapor: $REPORT"
echo "[audit-deps] Bitti."

# exit code'u koru (CI için)
exit "$AUDIT_EXIT"
