#!/usr/bin/env bash
# Module-level coverage report ( S10 /  C6).
# Usage: bash scripts/coverage-report.sh
# CI'da çalıştırılır; consensus/cross_domain/crypto modül bazında % raporlar.
set -euo pipefail

echo "=== Budlum Coverage Report ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

if command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "--- Per-file coverage (top 20 by lines) ---"
    cargo llvm-cov nextest --lib --text 2>&1 \
        | grep -E "^src/" \
        | sort -t$'\t' -k2 -rn \
        | head -20
    echo ""
    echo "--- Summary ---"
    cargo llvm-cov nextest --lib --summary-only 2>&1 | tail -3
    echo ""
    echo "--- Module breakdown ---"
    for mod in consensus cross_domain crypto execution chain network storage ai; do
        pct=$(cargo llvm-cov nextest --lib --text 2>&1 \
              | grep "^src/$mod/" \
              | awk '{s+=$3; c+=$4} END {if(s>0) printf "%.1f", c*100/s; else print "N/A"}')
        echo "  src/$mod/: ${pct}%"
    done
else
    echo "cargo-llvm-cov not installed. Install: cargo install cargo-llvm-cov"
    echo ""
    echo "Coverage baseline:"
    cat .github/coverage-baseline.txt 2>/dev/null || echo "(baseline not found)"
fi
