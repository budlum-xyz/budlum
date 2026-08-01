#!/usr/bin/env bash
# Scripts/generate-sbom.sh - Rust SBOM üretici
#
# Bu script CycloneDX formatında SBOM (Software Bill of Materials)
# Üretir. ch12 §3.7 mainnet blocker kapsamında; harici audit
# Firması için zorunlu teslim kalemi.
#
# Kullanım:
#   ./scripts/generate-sbom.sh
#
# Çıktı: `sbom.cdx.json` (repo root) + `target/audit/SBOM.md` özeti.
# Format: CycloneDX 1.5 (JSON).
# Kabul kriteri: SBOM dosyası oluşturulabiliyor + JSON parse oluyor.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[generate-sbom] SBOM üretimi başlatılıyor..."

# 1. cargo-cyclonedx yükle (yoksa veya sürüm pinli değilse).
# Sürüm pinli: CLI bayrakları sürümler arası değişebiliyor (run #728:
# `--output-file` kaldırılmıştı), kapının deterministik kalması için pin ZORUNLU.
# (PR #13 fix'inden taşıma - triyaj bakiyesi.)
CYCLONEDX_VERSION="0.5.9"
if ! command -v cargo-cyclonedx >/dev/null 2>&1 \
    || ! cargo cyclonedx --version 2>/dev/null | grep -q "$CYCLONEDX_VERSION"; then
    echo "[generate-sbom] cargo-cyclonedx $CYCLONEDX_VERSION (pinli) yükleniyor..."
    cargo install --locked cargo-cyclonedx --version "$CYCLONEDX_VERSION"
fi

# 2. SBOM üret
SBOM_FILE="$REPO_ROOT/sbom.cdx.json"
cargo cyclonedx --format json
# Cargo-cyclonedx writes <package-name>.cdx.json (e.g. budlum-core.cdx.json)
SBOM_TMP=$(ls -t *.cdx.json 2>/dev/null | head -1)
if [ -n "$SBOM_TMP" ] && [ -f "$SBOM_TMP" ]; then
    mv "$SBOM_TMP" "$SBOM_FILE"
else
    echo "[generate-sbom] HATA: .cdx.json dosyası bulunamadı."
    ls -la *.json *.xml 2>/dev/null || true
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
DOC="$REPO_ROOT/target/audit/SBOM.md"
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
    echo "Bu rapor  kapsamında otomatik üretilir."
} > "$DOC"

echo "[generate-sbom] SBOM: $SBOM_FILE ($SBOM_SIZE byte, $COMPONENT_COUNT bileşen)"
echo "[generate-sbom] Rapor: $DOC"
echo "[generate-sbom] Bitti."
