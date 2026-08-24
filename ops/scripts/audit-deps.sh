#!/usr/bin/env bash
# ops/scripts/audit-deps.sh - Rust dependency audit
#
# This script runs `cargo audit` and checks the dependencies against
# known security holes. It sits inside the ch12 section 3.7 mainnet
# blocker scope.
#
# Usage:
#   ./scripts/audit-deps.sh
#
# Output: stdout plus the `target/audit/DEPENDENCY_AUDIT.md` report.
# Acceptance criterion: no CVE other than "unmaintained" warnings.
# "unmaintained" warnings are reviewed separately (they may be false
# positives; CI reports them as warnings, it does not fail).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "[audit-deps] starting the Budlum Core dependency audit..."

# 1. install cargo audit (if absent)
if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "[audit-deps] installing cargo-audit..."
    cargo install --locked cargo-audit
fi

# 2. scan both lockfiles (root + budzero)
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

# 3. write the report
REPORT="$REPO_ROOT/target/audit/DEPENDENCY_AUDIT.md"
mkdir -p "$(dirname "$REPORT")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cargo audit --file Cargo.lock --deny warnings > "$ROOT_RAW_OUT" 2>&1 || true
cargo audit --file budzero/Cargo.lock --deny warnings > "$BUDZERO_RAW_OUT" 2>&1 || true

# The findings ARE PRINTED into the CI log.
#
# Previously they were not: `--json` went to a temporary file and the raw output
# to `target/audit/DEPENDENCY_AUDIT.md`, and no workflow uploaded that report
# as an artifact. Result: the job runs, comes back green and not a single
# advisory name appears in the log.
#
# This is not empty pedantry. `.quality/deny.toml` holds `unmaintained = "none"`
# and the ONLY justification for that decision is written as: "warning visibility
# is not lost: the cargo audit in the CI dependency-audit job reports unmaintained
# warnings on every run." It was not reporting them.
#
# Example: RUSTSEC-2024-0380 (`pqcrypto-dilithium`, the mainnet default PQ signature
# path). The decision was made and is recorded with its reason in
# `.quality/osv-scanner.toml` -- but it never appeared on the cargo audit side in any
# run. Two scanners read the same tree and only one result was readable.
echo ""
echo "──────── cargo audit - root Cargo.lock ────────"
cat "$ROOT_RAW_OUT"
echo "──────── cargo audit - budzero/Cargo.lock ────────"
cat "$BUDZERO_RAW_OUT"
echo "──────────────────────────────────────────────────"
echo ""

# Summarise the advisory identifiers: whoever reads the log should see at a glance
# which warnings are known.
ADVISORIES="$(grep -hoE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$ROOT_RAW_OUT" "$BUDZERO_RAW_OUT" | sort -u || true)"
if [ -n "$ADVISORIES" ]; then
    echo "[audit-deps] advisories seen in this tree:"
    printf '  - %s\n' $ADVISORIES
else
    echo "[audit-deps] no advisory was found."
fi
echo ""

{
    echo "# Dependency Audit Report"
    echo ""
    echo "**Generated:** $TIMESTAMP"
    echo "**Tool:** cargo-audit (https://github.com/rustsec/rustsec)"
    echo "**Repo:** budlum-xyz/budlum @ \`$(git rev-parse --short HEAD)\`"
    echo ""
    echo "## Summary"
    echo ""
    if [ "$AUDIT_EXIT" -eq 0 ]; then
        echo "- OK **NO** known security hole (root + budzero lockfile)."
    else
        echo "- WARNING cargo-audit exit code: $AUDIT_EXIT (usually an unmaintained warning)."
    fi
    echo "- Root lockfile exit code: $ROOT_AUDIT_EXIT"
    echo "- BudZero lockfile exit code: $BUDZERO_AUDIT_EXIT"
    echo ""
    echo "## Raw output - root Cargo.lock"
    echo ""
    echo "\`\`\`"
    head -50 "$ROOT_RAW_OUT" || true
    echo "\`\`\`"
    echo ""
    echo "## Raw output - budzero/Cargo.lock"
    echo ""
    echo "\`\`\`"
    head -50 "$BUDZERO_RAW_OUT" || true
    echo "\`\`\`"
    echo ""
    echo "## Acceptance criterion"
    echo ""
    echo "The \`dependency-audit\` job in CI runs this script. **If a known"
    echo "security hole (CVE) is detected the job fails.** Unmaintained"
    echo "warnings are reported as warnings (they do not fail). The root and BudZero"
    echo "lockfiles are checked together."
    echo ""
    echo "This report is generated automatically."
} > "$REPORT"

echo "[audit-deps] report: $REPORT"
echo "[audit-deps] done."

# Preserve the exit code (for CI)
exit "$AUDIT_EXIT"
