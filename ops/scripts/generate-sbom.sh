#!/usr/bin/env bash
# ops/scripts/generate-sbom.sh - Rust SBOM generator
#
# This script produces an SBOM (Software Bill of Materials) in CycloneDX
# format. It sits inside the ch12 section 3.7 mainnet blocker scope; a
# mandatory deliverable for the external audit firm.
#
# Usage:
#   ./scripts/generate-sbom.sh
#
# Output: `sbom.cdx.json` (repo root) plus the `target/audit/SBOM.md` summary.
# Format: CycloneDX 1.5 (JSON).
# Acceptance criterion: the SBOM file can be created and the JSON parses.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "[generate-sbom] starting SBOM generation..."

# 1. install cargo-cyclonedx (if absent or the version is not pinned).
# The version is pinned: CLI flags can change between releases (run #728:
# `--output-file` had been removed); the pin is REQUIRED for the gate to stay deterministic.
# (Carried over from the previous fix - the triage balance.)
CYCLONEDX_VERSION="0.5.9"
if ! command -v cargo-cyclonedx >/dev/null 2>&1 \
    || ! cargo cyclonedx --version 2>/dev/null | grep -q "$CYCLONEDX_VERSION"; then
    echo "[generate-sbom] installing cargo-cyclonedx $CYCLONEDX_VERSION (pinned)..."
    cargo install --locked cargo-cyclonedx --version "$CYCLONEDX_VERSION"
fi

# 2. produce the SBOM
SBOM_FILE="$REPO_ROOT/sbom.cdx.json"
# cargo-cyclonedx writes <package-name>.cdx.json next to the manifest. The
# root manifest is the single package `budlum-core`, so that name is the
# artifact of this run; a stale file from an earlier run must not stand in
# for it, which is why it is removed first and named explicitly afterwards.
SBOM_TMP="$REPO_ROOT/budlum-core.cdx.json"
rm -f "$SBOM_TMP"
cargo cyclonedx --format json
if [ ! -f "$SBOM_TMP" ]; then
    echo "[generate-sbom] ERROR: cargo-cyclonedx did not write $SBOM_TMP."
    ls -la ./*.cdx.json 2>/dev/null || true
    exit 1
fi
mv "$SBOM_TMP" "$SBOM_FILE"

# 3. JSON validation
if ! python3 -c "import json; json.load(open('$SBOM_FILE'))" 2>/dev/null; then
    echo "[generate-sbom] ERROR: the SBOM is not parseable JSON."
    exit 1
fi

# 4. size and component count
SBOM_SIZE="$(stat -c%s "$SBOM_FILE" 2>/dev/null || stat -f%z "$SBOM_FILE" 2>/dev/null || echo "?")"
COMPONENT_COUNT="$(python3 -c "import json; print(len(json.load(open('$SBOM_FILE')).get('components', [])))" 2>/dev/null || echo "?")"

# 5. Report
DOC="$REPO_ROOT/target/audit/SBOM.md"
mkdir -p "$(dirname "$DOC")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

{
    echo "# SBOM (Software Bill of Materials)"
    echo ""
    echo "**Generated:** $TIMESTAMP"
    echo "**Tool:** cargo-cyclonedx (https://github.com/CycloneDX/cyclonedx-rust-cargo)"
    echo "**Format:** CycloneDX 1.5 (JSON)"
    echo "**Repo:** budlum-xyz/budlum @ \`$(git rev-parse --short HEAD)\`"
    echo ""
    echo "## Summary"
    echo ""
    echo "- **SBOM file:** \`sbom.cdx.json\` (size: $SBOM_SIZE bytes)"
    echo "- **Component count:** $COMPONENT_COUNT"
    echo ""
    echo "## Usage"
    echo ""
    echo "The external audit firm can use \`sbom.cdx.json\` directly."
    echo "Format: CycloneDX 1.5 JSON, it includes every transitive dependency."
    echo ""
    echo "## Regeneration"
    echo ""
    echo "\`\`\`bash"
    echo "./scripts/generate-sbom.sh"
    echo "\`\`\`"
    echo ""
    echo "This report is generated automatically."
} > "$DOC"

echo "[generate-sbom] SBOM: $SBOM_FILE ($SBOM_SIZE bytes, $COMPONENT_COUNT components)"
echo "[generate-sbom] report: $DOC"
echo "[generate-sbom] done."
