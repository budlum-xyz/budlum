#!/usr/bin/env bash
# ============================================================================
# check-actionlint.sh —  workflow lint kapısı (vacuous-gate kanaryalı)
# Kullanım:
#   bash scripts/check-actionlint.sh             # tüm workflow'ları lint'le
#   bash scripts/check-actionlint.sh --self-test # kanarya: bozuk workflow FAIL kanıtı
# ============================================================================
set -euo pipefail
BIN="${ACTIONLINT_BIN:-actionlint}"

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  # Bilerek bozuk: (1) geçersiz event adı, (2) tanımsız context alanı
  cat > "$tmp/badan-workflow.yml" <<'YML'
name: badan-bozuk
on: [pushh]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.boyle_alan_yok_xyz }}"
YML
  if "$BIN" "$tmp/badan-workflow.yml" >/dev/null 2>&1; then
    echo "VACUOUS GATE: bozuk workflow actionlint'ten geçti!"; exit 1
  fi
  echo "kanarya OK: bozuk workflow reddedildi (kapı vacuous değil)."
  exit 0
fi

"$BIN" .github/workflows/*.yml
echo "actionlint temiz."
