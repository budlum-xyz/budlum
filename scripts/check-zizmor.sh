#!/usr/bin/env bash
# ============================================================================
# check-zizmor.sh — G27 (ADIM8.5 §10): GitHub Actions statik güvenlik analizi
#
# zizmor v1.27.0 — sürüm + sha256 pinli indirme (hadolint/gitleaks deseni).
# Politika: repo workflow'larında 0 bulgu (düzeltmeler gerçek, bastırmalar
# satır-içi gerekçeli `# zizmor: ignore[...]` marker'lı).
#
# Kullanım:
#   ZIZMOR_BIN=/path/zizmor bash scripts/check-zizmor.sh             # lint
#   ZIZMOR_BIN=/path/zizmor bash scripts/check-zizmor.sh --self-test # kanarya
#   (ZIZMOR_BIN yoksa pinli sürüm+sha256 ile /tmp'ye indirilir)
# ============================================================================
set -euo pipefail

VERSION="1.27.0"
SHA256="277f2bd8fd37cf60c42ab7afca6faa884e65440fa31e02b44bdaae60f62a358f"

BIN="${ZIZMOR_BIN:-}"
if [ -z "$BIN" ]; then
  tgz="/tmp/zizmor-${VERSION}.tar.gz"
  curl --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --retry-delay 2 \
    -sSfL -o "$tgz" \
    "https://github.com/zizmorcore/zizmor/releases/download/v${VERSION}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
  echo "${SHA256}  ${tgz}" | sha256sum -c - >/dev/null
  tar xzf "$tgz" -C /tmp zizmor
  chmod +x /tmp/zizmor
  BIN="/tmp/zizmor"
fi

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  # Kasitli TEHLIKELI: pull_request_target + PR head checkout (kritik bulgu uretmeli)
  cat > "$tmp/tehlikeli.yml" <<'YML'
name: badan-tehlikeli
on: pull_request_target
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
YML
  # Temiz örnek → bulgu üretmemeli
  cat > "$tmp/temiz.yml" <<'YML'
name: badan-temiz
on: push
permissions:
  contents: read
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      - run: echo temiz
YML
  if "$BIN" "$tmp/tehlikeli.yml" >/dev/null 2>&1; then
    echo "VACUOUS GATE: pull_request_target+head-checkout zizmor'dan gecti!"; exit 1
  fi
  if ! "$BIN" "$tmp/temiz.yml" >/dev/null 2>&1; then
    echo "BOZUK KAPI: temiz workflow reddedildi!"; exit 1
  fi
  echo "kanarya OK: tehlikeli→FAIL, temiz→PASS (kapı vacuous degil)."
  exit 0
fi

"$BIN" .github/workflows/
echo "zizmor temiz."
