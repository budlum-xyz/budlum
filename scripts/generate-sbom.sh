#!/usr/bin/env bash
# scripts/generate-sbom.sh — Rust SBOM üretici (Phase 0.40 §1.7)
#
# Bu script CycloneDX formatında SBOM (Software Bill of Materials)
# üretir. ch12 §3.7 mainnet blocker kapsamında; harici audit
# firması için zorunlu teslim kalemi.
#
# Kullanım:
#   ./scripts/generate-sbom.sh
#
# Çıktı: `sbom.cdx.json` (repo root) + `docs/operations/SBOM.md` özeti.
# Format: CycloneDX 1.5 (JSON).
# Kabul kriteri: SBOM dosyası oluşturulabiliyor + JSON parse oluyor.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[generate-sbom] SBOM üretimi başlatılıyor..."

# 1. cargo-cyclonedx yükle (yoksa)
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "[generate-sbom] cargo-cyclonedx yükleniyor..."
    cargo install --locked cargo-cyclonedx
fi

# 2. SBOM üret
SBOM_FILE="$REPO_ROOT/sbom.cdx.json"
# Debug: cargo-cyclonedx çıktısını yakala
CYCLONEDX_OUT=$(cargo cyclonedx --format json 2>&1) || {
    echo "[generate-sbom] cargo cyclonedx HATA (exit=$?): $CYCLONEDX_OUT"
    exit 1
}
echo "[generate-sbom] cargo cyclonedx çıktısı: ${CYCLONEDX_OUT:0:200}"
echo "[generate-sbom] Dizindeki dosyalar:"
ls -la *.json *.xml 2>/dev/null || echo "(hiç .json/.xml yok)"
echo "[generate-sbom] target/cy* altında:"
ls target/cyclonedx/ 2>/dev/null || echo "(target/cyclonedx yok)"
find . -maxdepth 1 -name "*.json" -o -name "*.xml" 2>/dev/null
if [ -f bom.json ]; then
    mv bom.json "$SBOM_FILE"
elif [ -f bom.xml ]; then
    echo "[generate-sbom] bom.xml bulundu (format json istenmişti!)"
    exit 1
else
    echo "[generate-sbom] HATA: bom.json bulunamadı."
    exit 1
fi

# 3. JSON validasyon
if ! python3 -c "import json; json.load(open('$SBOM_FILE'))" 2>/dev/null; then
    echo "[generate-sbom] HATA: SBOM JSON parse edilemedi."
    exit 1
fi

# 4. Boyut ve bileşen sayısı
SBOM_SIZE="$(stat -c%s "$SBOM_FILE" 2>/dev/null || stat -f%z "$SBOM_FILE" 2>/dev/null || echo "?")"
COMPONENT_COUNT="$(python3 -c "import json; print(len(json.load(open('$SBOM_FILE')).get('components', [])))" 2>/dev/null || echo "?")"

# 5. Rapor
DOC="$REPO_ROOT/docs/operations/SBOM.md"
mkdir -p "$(dirname "$DOC")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

{
    echo "# SBOM (Software Bill of Materials)"
    echo ""
    echo "**Oluşturulma:** $TIMESTAMP"
    echo "**Araç:** cargo-cyclonedx (https://github.com/CycloneDX/cyclonedx-rust-cargo)"
    echo "**Format:** CycloneDX 1.5 (JSON)"
    echo "**Repo:** lubosruler/budlum @ \`$(git rev-parse --short HEAD)\`"
    echo ""
    echo "## Özet"
    echo ""
    echo "- **SBOM dosyası:** \`sbom.cdx.json\` (boyut: $SBOM_SIZE byte)"
    echo "- **Bileşen sayısı:** $COMPONENT_COUNT"
    echo ""
    echo "## Kullanım"
    echo ""
    echo "Harici audit firması \`sbom.cdx.json\` dosyasını doğrudan kullanabilir."
    echo "Format: CycloneDX 1.5 JSON, tüm transitive bağımlılıkları içerir."
    echo ""
    echo "## Yenileme"
    echo ""
    echo "\`\`\`bash"
    echo "./scripts/generate-sbom.sh"
    echo "\`\`\`"
    echo ""
    echo "Bu rapor Phase 0.40 §1.7 kapsamında otomatik üretilir."
} > "$DOC"

echo "[generate-sbom] SBOM: $SBOM_FILE ($SBOM_SIZE byte, $COMPONENT_COUNT bileşen)"
echo "[generate-sbom] Rapor: $DOC"
echo "[generate-sbom] Bitti."
