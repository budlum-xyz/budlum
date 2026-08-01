#!/usr/bin/env bash
# ============================================================================
# check-kani.sh - model-checking gate for bond arithmetic.
#
# A script with this name existed before and was deleted, for a good reason:
# it printed a stub message, pointed at a `src/crypto/kani.rs` that was not in
# the tree, no workflow ran it, and there were no `#[kani::proof]` harnesses
# anywhere. It counted as a gate while proving nothing. SECURITY.md recorded
# that removal and listed model checking as open work.
#
# This is the replacement. It runs real harnesses (`kani/src/lib.rs`), it is
# invoked by `.github/workflows/extra-tooling.yml`, and it fails when a proof
# fails.
#
# The gate checks two things, because either alone can pass while the property
# is unverified:
#
#   1. `cargo kani` reports VERIFICATION:- SUCCESSFUL and no failures.
#   2. The number of harnesses it actually ran matches the number declared in
#      the source. A proof that silently stops being compiled - a stray
#      `cfg`, a renamed module, a harness filtered out by a `--harness` flag
#      that no longer matches - would otherwise leave the gate green with
#      nothing behind it. This is the same failure the deleted script had.
#
# Usage:
#   bash scripts/check-kani.sh <kani-output-log>   # gate
#   bash scripts/check-kani.sh --self-test         # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PROOFS_FILE="$ROOT/kani/src/lib.rs"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Number of `#[kani::proof]` attributes in the source. This is the count the
# run has to match. Indented, because the harnesses sit inside a `cfg(kani)`
# module.
declared_harnesses() {
  [ -f "$PROOFS_FILE" ] || fail "harness file missing: $PROOFS_FILE"
  grep -c '#\[kani::proof\]' "$PROOFS_FILE"
}

gate() {
  local log="$1"
  [ -s "$log" ] || fail "kani output missing or empty: $log"

  # Any individual failure fails the gate, whatever the summary says.
  if grep -qE '^VERIFICATION:- FAILED' "$log"; then
    echo "--- failing checks ---" >&2
    grep -E 'Failed Checks|VERIFICATION:- FAILED' "$log" >&2 || true
    fail "a Kani proof failed"
  fi

  local successful
  successful=$(grep -cE '^VERIFICATION:- SUCCESSFUL' "$log" || true)
  [ "$successful" -gt 0 ] || fail "no successful verification in output - did Kani run at all?"

  local declared
  declared=$(declared_harnesses)
  [ "$declared" -gt 0 ] || fail "no #[kani::proof] harnesses declared"

  if [ "$successful" -ne "$declared" ]; then
    fail "Kani verified $successful harness(es) but $declared are declared in \
kani/src/lib.rs - a proof stopped running without anyone noticing"
  fi

  echo "Kani gate OK: $successful/$declared harnesses verified."
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  declared=$(declared_harnesses)

  # 1. A failing proof must fail the gate.
  {
    echo "Checking harness penalty_never_exceeds_stake..."
    echo "VERIFICATION:- FAILED"
  } > "$tmp/failed.log"
  if ( gate "$tmp/failed.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a FAILED verification was accepted!" >&2
    exit 1
  fi

  # 2. Empty output must fail - the case where Kani never ran.
  : > "$tmp/empty.log"
  if ( gate "$tmp/empty.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: empty Kani output was accepted!" >&2
    exit 1
  fi

  # 3. Fewer harnesses than declared must fail, even though every one that ran
  #    succeeded. This is the specific way the previous script was hollow.
  : > "$tmp/short.log"
  echo "VERIFICATION:- SUCCESSFUL" > "$tmp/short.log"
  if [ "$declared" -gt 1 ] && ( gate "$tmp/short.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: $declared declared but 1 verified was accepted!" >&2
    exit 1
  fi

  # 4. A full, clean run must pass, or the gate rejects everything.
  : > "$tmp/ok.log"
  for _ in $(seq 1 "$declared"); do
    echo "VERIFICATION:- SUCCESSFUL" >> "$tmp/ok.log"
  done
  if ! ( gate "$tmp/ok.log" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a clean run of all $declared harnesses was rejected!" >&2
    exit 1
  fi

  echo "kani gate self-test OK: failure, empty output and a short run all rejected; a full run passes."
  exit 0
fi

[ $# -ge 1 ] || { echo "usage: $0 <kani-output-log> | --self-test"; exit 1; }
gate "$1"
