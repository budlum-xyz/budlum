#!/usr/bin/env bash
# ============================================================================
# check-badges-are-current.sh, README badges must match what CI measured.
#
# The test badge is written by a CI step that pushes to `main`. That push has
# been rejected on every run since branch protection was enabled:
#
#   remote: error: GH006: Protected branch update failed for refs/heads/main.
#   ! [remote rejected] HEAD -> main (protected branch hook declined)
#   ##[warning]Rozet 1773 olmali ama push 3/3 denemede reddedildi.
#
# The step emits a warning and then exits 0, so the job stays green and nobody
# notices. The badge said 1542 while the suite had grown to 1773 - a 231-test
# gap, advertised on the front page of the repository.
#
# A warning that nothing reads is not a signal. This gate turns the mismatch
# into a failure on the pull request that causes it, where the author can fix
# it in the same commit. The number then arrives through the normal review
# path instead of a privileged push, which is also why the push channel can be
# retired: it needed an admin PAT to bypass the protection that exists for
# good reasons.
#
# Usage:
#   bash scripts/check-badges-are-current.sh <cargo-test-log>   # gate
#   bash scripts/check-badges-are-current.sh --self-test        # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
README="$ROOT/README.md"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# The count the badge currently advertises.
badge_count() {
  [ -f "$README" ] || fail "README missing: $README"
  # `head -1` on the *number* too: `tests-1542%20lib` contains two digit runs
  # (1542 and the 20 of %20), and taking both would produce "1542\n20".
  grep -oE 'tests-[0-9]+%20lib' "$README" | head -1 | grep -oE '[0-9]+' | head -1 || true
}

# The count the test run actually produced. Takes the LAST `N passed`, which is
# the summary line; earlier matches come from individual test binaries.
measured_count() {
  local log="$1"
  grep -oE '[0-9]+ passed' "$log" | tail -1 | grep -oE '^[0-9]+' || true
}

gate() {
  local log="$1"
  [ -s "$log" ] || fail "test log missing or empty: $log"

  # A badge derived from a failing run would be worse than a stale one.
  if grep -qE '[1-9][0-9]* failed' "$log"; then
    fail "test log records failures; refusing to compare badge against a red run"
  fi

  local measured badge
  measured="$(measured_count "$log")"
  [ -n "$measured" ] || fail "could not parse a test count from $log - gate would be vacuous"

  badge="$(badge_count)"
  [ -n "$badge" ] || fail "no tests-N%20lib badge found in README.md"

  if [ "$badge" != "$measured" ]; then
    fail "README test badge says $badge, this run measured $measured.
  Update the badge in README.md in this pull request:
      [![Tests](https://img.shields.io/badge/tests-${measured}%20lib-blue)](https://github.com/budlum-xyz/budlum)"
  fi

  echo "Badge gate OK: README advertises $badge tests, run measured $measured."
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  real_badge="$(badge_count)"
  [ -n "$real_badge" ] || fail "self-test needs a badge in README.md"

  # 1. A count that disagrees with the badge must fail. This is the case the
  #    gate exists for, and the one the push channel silently tolerated.
  printf 'test result: ok. %s passed; 0 failed; 1 ignored\n' "$((real_badge + 1))" > "$tmp/drifted.log"
  if ( gate "$tmp/drifted.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a badge one test behind was accepted!" >&2
    exit 1
  fi

  # 2. A log with failures must fail, even if the count matches.
  printf 'test result: FAILED. %s passed; 2 failed; 0 ignored\n' "$real_badge" > "$tmp/red.log"
  if ( gate "$tmp/red.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a badge compared against a failing run was accepted!" >&2
    exit 1
  fi

  # 3. Empty output must fail, the case where the test step never ran.
  : > "$tmp/empty.log"
  if ( gate "$tmp/empty.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: empty test output was accepted!" >&2
    exit 1
  fi

  # 4. A log with no parseable count must fail rather than pass by default.
  echo "warning: something unrelated" > "$tmp/garbage.log"
  if ( gate "$tmp/garbage.log" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unparsable log was accepted!" >&2
    exit 1
  fi

  # 5. The matching case must pass, or the gate rejects every pull request.
  printf 'test result: ok. %s passed; 0 failed; 1 ignored\n' "$real_badge" > "$tmp/match.log"
  if ! ( gate "$tmp/match.log" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a badge that matches the run was rejected!" >&2
    exit 1
  fi

  echo "badge gate self-test OK: drift, red runs, empty and unparsable logs all rejected; a match passes."
  exit 0
fi

[ $# -ge 1 ] || { echo "usage: $0 <cargo-test-log> | --self-test"; exit 1; }
gate "$1"
