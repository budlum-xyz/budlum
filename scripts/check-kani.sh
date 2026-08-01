#!/usr/bin/env bash
# ============================================================================
# check-kani.sh, model-checking gate for bond arithmetic.
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
#      the source. A proof that silently stops being compiled, a stray
#      `cfg`, a renamed module, a harness filtered out by a `--harness` flag
#      that no longer matches, would otherwise leave the gate green with
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

# Number of `#[kani::proof]` attributes in the source, minus the ones marked
# `// SLOW:`. This is the count a pull-request run has to match.
#
# The split exists because three harnesses relate two `penalty_for` results to
# each other, and a solver cannot close a comparison of two symbolic 128-bit
# products inside a CI budget. That was measured per harness rather than
# guessed: one clamped call is proved in under a second, two related calls
# time out, and splitting the asserts does not help because `stake * SCALE`
# over a symbolic 64-bit stake is itself the wall.
#
# The marker is counted rather than a list of names being kept here, so a
# harness cannot be quietly excluded by renaming it: the count has to come out
# right either way. `BUDLUM_KANI_SCOPE=all` restores the full count for the
# scheduled run.
declared_harnesses() {
  [ -f "$PROOFS_FILE" ] || fail "harness file missing: $PROOFS_FILE"
  local total slow
  total=$(grep -c '#\[kani::proof\]' "$PROOFS_FILE")
  slow=$(grep -c '^\s*// SLOW:' "$PROOFS_FILE" || true)
  if [ "${BUDLUM_KANI_SCOPE:-fast}" = "all" ]; then
    printf '%s' "$total"
    return 0
  fi
  # A marker that does not sit above a `#[kani::proof]` would shrink the
  # expected count without excluding anything, which is the vacuous direction.
  local marked_proofs
  marked_proofs=$(grep -A1 '^\s*// SLOW:' "$PROOFS_FILE" | grep -c '#\[kani::proof\]' || true)
  if [ "$slow" -ne "$marked_proofs" ]; then
    fail "$slow SLOW markers but $marked_proofs of them sit above a #[kani::proof]; \
a stray marker would lower the expected count without excluding a harness"
  fi
  printf '%s' "$((total - slow))"
}

# The harness names, split by the `// SLOW:` marker.
#
# Kani 0.67 has `--harness` (repeatable, and exact with `--exact`) but no
# `--exclude-harness`, so the workflow selects the fast ones by name rather
# than excluding the slow ones. Verified against the 0.67.0 source rather than
# assumed: binding a gate to a flag that does not exist would leave it running
# everything and timing out exactly as before.
#
# The scan walks forward from each marker to the next `fn`, because a doc
# comment can sit between the two: a fixed `-A3` window found two of the three
# and silently dropped the third, which is the failure this comment exists to
# stop recurring.
harness_names() {
  local want="$1"   # fast | slow
  python3 - "$PROOFS_FILE" "$want" <<'PY_INNER'
import re
import sys

path, want = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().split("\n")

marked = False
out = []
for line in lines:
    s = line.strip()
    if s.startswith("// SLOW:"):
        marked = True
        continue
    m = re.match(r"fn ([a-z0-9_]+)\(", s)
    if m:
        # Only functions that carry a proof attribute count, and the attribute
        # sits above the doc comment, so it is tracked separately.
        out.append((m.group(1), marked))
        marked = False
        continue
    # A blank line or a closing brace ends the run of attributes and docs that
    # a marker can apply to. Doc comments and attributes do not.
    if s and not s.startswith(("///", "//!", "//", "#[")):
        marked = False

# Reduce to harnesses only: a name is a harness when `#[kani::proof]` appears
# above it, which is checked by rescanning with the attribute in view.
text = "\n".join(lines)
harnesses = set()
for m in re.finditer(r"#\[kani::proof\][^}]*?fn ([a-z0-9_]+)\(", text, re.S):
    harnesses.add(m.group(1))

for name, slow in out:
    if name not in harnesses:
        continue
    if (want == "slow") == slow:
        print(name)
PY_INNER
}

slow_harness_names() {
  harness_names slow
}

# The module path a fully-qualified harness name would need.
#
# Not used by the workflow any more: `--exact` was tried, rejected a bare name
# and rejected `budlum_kani::proofs::x` too, and the 0.67.0 source shows why.
# It compares against `mangled_name`, which carries the module but not the
# crate, so `proofs::x` is the form it wants. Binding a gate to Kani internal
# naming is a bad trade, so the workflow filters on the bare name instead and
# relies on the harness count for exactness.
#
# Kept because the next person will try `--exact` too, and this answers it.
harness_module_path() {
  local crate module
  crate=$(grep -m1 '^name = ' "$(dirname "$PROOFS_FILE")/../Cargo.toml" \
    | sed 's/name = "//; s/"//' | tr '-' '_')
  module=$(grep -oE '^(pub )?mod [a-z_]+ \{' "$PROOFS_FILE" | head -1 \
    | sed 's/^pub //; s/^mod //; s/ {//')
  [ -n "$crate" ] || fail "could not read the crate name from kani/Cargo.toml"
  [ -n "$module" ] || fail "could not find the module the harnesses live in"
  printf '%s::%s' "$crate" "$module"
}

fast_harness_names() {
  harness_names fast
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

# The workflow asks for the exclusion list rather than repeating it, so the
# two cannot drift apart.
if [ "${1:-}" = "--slow-names" ]; then
  slow_harness_names
  exit 0
fi

if [ "${1:-}" = "--fast-names" ]; then
  fast_harness_names
  exit 0
fi

if [ "${1:-}" = "--module-path" ]; then
  harness_module_path
  exit 0
fi

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

  # 2. Empty output must fail, the case where Kani never ran.
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

  # 5. The fast/slow split must not become a way to exclude a harness quietly.
  #    A `// SLOW:` marker that does not sit above a `#[kani::proof]` lowers the
  #    expected count while excluding nothing, so it has to be rejected.
  stray="$tmp/stray.rs"
  {
    echo "    // SLOW: not above a proof at all"
    echo "    fn helper() {}"
    echo "    #[kani::proof]"
    echo "    fn a() {}"
    echo "    #[kani::proof]"
    echo "    fn b() {}"
  } > "$stray"
  if ( PROOFS_FILE="$stray" declared_harnesses ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a stray SLOW marker was accepted; it would lower the \
expected count without excluding a harness!" >&2
    exit 1
  fi

  # 6. A well-formed split must produce total-minus-slow, and `all` must
  #    produce the total. If these ever coincide the split is doing nothing.
  split="$tmp/split.rs"
  {
    echo "    #[kani::proof]"
    echo "    fn fast_one() {}"
    echo "    #[kani::proof]"
    echo "    fn fast_two() {}"
    echo "    // SLOW: measured, does not close in CI budget"
    echo "    #[kani::proof]"
    echo "    fn slow_one() {}"
  } > "$split"
  fast_n="$( PROOFS_FILE="$split" declared_harnesses )"
  all_n="$( PROOFS_FILE="$split" BUDLUM_KANI_SCOPE=all declared_harnesses )"
  [ "$fast_n" = "2" ] || { echo "BROKEN GATE: fast count was $fast_n, expected 2" >&2; exit 1; }
  [ "$all_n" = "3" ] || { echo "BROKEN GATE: all count was $all_n, expected 3" >&2; exit 1; }

  # 7. The workflow needs the slow names to exclude them, and a rename must
  #    show up here rather than silently dropping an exclusion.
  names="$( PROOFS_FILE="$split" slow_harness_names | paste -sd, - )"
  [ "$names" = "slow_one" ] \
    || { echo "BROKEN GATE: slow names came out as '$names', expected 'slow_one'" >&2; exit 1; }

  echo "kani gate self-test OK: failure, empty output and a short run all rejected; a full run passes; the fast/slow split counts 2/3 and names its exclusions."
  exit 0
fi

[ $# -ge 1 ] || { echo "usage: $0 <kani-output-log> | --self-test"; exit 1; }
gate "$1"
