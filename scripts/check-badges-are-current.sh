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
# The test count was only one of four badges, and it was the only one checked.
# The other three were wrong in ways nobody would notice by looking at them:
#
#   1. The CI badge carried no `branch=`/`event=` filter. GitHub falls back to
#      "the most recent run across all branches" whenever the default branch
#      has no run yet, so a green front page could be reporting a topic branch.
#      Worse, the run it names is the pull_request run, which builds a merge
#      commit that exists on neither branch. The badge now pins
#      `branch=main&event=push`, so it reports the code that is actually on
#      `main`, and the link resolves to the same filtered query rather than to
#      an unfiltered run list that shows something else.
#   2. The Rust badge hardcoded a version string next to a link to
#      `rust-toolchain.toml`. The link invites the reader to verify, and until
#      now nothing did: the two could drift apart in either direction and CI
#      stayed green.
#   3. The License badge hardcoded `Apache-2.0` while `Cargo.toml` carries the
#      SPDX id that tooling actually consumes. A badge saying one thing and a
#      manifest saying another is the sort of mismatch that only surfaces in a
#      legal review.
#
# So this gate now checks every badge on the page against the file it points
# at, and refuses a badge whose link does not lead to that evidence.
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

# ---------------------------------------------------------------------------
# The three badges that assert a fact about a file in this repository.
# Each is compared against that file, not against a remembered value.
# ---------------------------------------------------------------------------

# The CI badge must name the branch and the event it reports, or GitHub is
# free to answer with a run from somewhere else.
check_ci_badge() {
  local line
  line="$(grep -F 'actions/workflows/ci.yml/badge.svg' "$README" | head -1 || true)"
  [ -n "$line" ] || fail "no CI badge found in README.md"

  case "$line" in
    *'badge.svg?branch=main&event=push'*) ;;
    *)
      fail "the CI badge does not pin branch and event.
  Without \`?branch=main&event=push\` GitHub reports the newest run on ANY
  branch when main has none, and otherwise reports the pull_request run,
  which builds a merge commit that is on no branch. Use:
      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml/badge.svg?branch=main&event=push"
      ;;
  esac

  # The link has to lead to the same filtered view the image claims, or a
  # reader who clicks to verify is shown a different set of runs.
  case "$line" in
    *'ci.yml?query=branch%3Amain+event%3Apush'*) ;;
    *)
      fail "the CI badge image is filtered but its link is not.
  Point the link at the same query the image reports:
      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush"
      ;;
  esac
}

# The Rust badge must equal the channel in rust-toolchain.toml, which is the
# file it links to.
check_rust_badge() {
  local toolchain badge
  toolchain="$ROOT/rust-toolchain.toml"
  [ -f "$toolchain" ] || fail "rust-toolchain.toml missing: $toolchain"

  badge="$(grep -oE 'badge/rust-[0-9]+\.[0-9]+\.[0-9]+-' "$README" | head -1 \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
  [ -n "$badge" ] || fail "no rust-VERSION badge found in README.md"

  local pinned
  pinned="$(grep -oE '^[[:space:]]*channel[[:space:]]*=[[:space:]]*"[^"]+"' "$toolchain" \
    | head -1 | grep -oE '"[^"]+"' | tr -d '"' || true)"
  [ -n "$pinned" ] || fail "could not read the channel from rust-toolchain.toml - gate would be vacuous"

  [ "$badge" = "$pinned" ] || fail "README rust badge says $badge, rust-toolchain.toml pins $pinned"
}

# The License badge must equal the SPDX id in Cargo.toml, which is what
# tooling reads, and the link must lead to the licence text.
check_license_badge() {
  local manifest badge declared link
  manifest="$ROOT/Cargo.toml"
  [ -f "$manifest" ] || fail "Cargo.toml missing: $manifest"

  # `Apache--2.0` in a shields.io path is an escaped `Apache-2.0`.
  badge="$(grep -oE 'badge/license-[A-Za-z0-9.+-]+-blue' "$README" | head -1 \
    | sed -E 's|badge/license-||; s|-blue$||; s|--|@@|g; s|-| |g; s|@@|-|g' || true)"
  [ -n "$badge" ] || fail "no license badge found in README.md"

  declared="$(grep -oE '^license[[:space:]]*=[[:space:]]*"[^"]+"' "$manifest" \
    | head -1 | grep -oE '"[^"]+"' | tr -d '"' || true)"
  [ -n "$declared" ] || fail "Cargo.toml declares no license - gate would be vacuous"

  [ "$badge" = "$declared" ] || fail "README license badge says '$badge', Cargo.toml declares '$declared'"

  link="$(grep -F 'badge/license-' "$README" | head -1 || true)"
  case "$link" in
    *'](LICENSE.md)'*) ;;
    *) fail "the license badge does not link to LICENSE.md" ;;
  esac
  [ -f "$ROOT/LICENSE.md" ] || fail "the license badge links to LICENSE.md, which does not exist"
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
      [![Tests](https://img.shields.io/badge/tests-${measured}%20lib-blue)](https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush)"
  fi

  check_ci_badge
  check_rust_badge
  check_license_badge

  echo "Badge gate OK: README advertises $badge tests, run measured $measured;"
  echo "  CI badge pins branch=main&event=push, rust badge matches rust-toolchain.toml,"
  echo "  license badge matches Cargo.toml and links to LICENSE.md."
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

  # ------------------------------------------------------------------
  # Canaries for the three badges the count gate never looked at. Each
  # runs the real check against a README that has exactly one thing
  # wrong, so a check that stopped looking is caught here rather than
  # being trusted forever.
  #
  # `README` and `ROOT` are re-pointed at a copy, so the canary damages
  # a throwaway file and never the tree.
  # ------------------------------------------------------------------
  real_root="$ROOT"
  real_readme="$README"

  with_broken_readme() {
    # $1 = sed program that breaks one badge, $2 = check function name.
    local edit="$1" check="$2" work
    work="$tmp/tree"
    rm -rf "$work"
    mkdir -p "$work"
    cp "$real_readme" "$work/README.md"
    cp "$real_root/rust-toolchain.toml" "$work/rust-toolchain.toml"
    cp "$real_root/Cargo.toml" "$work/Cargo.toml"
    cp "$real_root/LICENSE.md" "$work/LICENSE.md"
    sed -i "$edit" "$work/README.md"
    ROOT="$work" README="$work/README.md"
    local rc=0
    ( "$check" ) >/dev/null 2>&1 || rc=1
    ROOT="$real_root" README="$real_readme"
    return $rc
  }

  # 6. A CI badge with no branch/event filter must fail: that is the badge
  #    that can report a run from a branch nobody is looking at.
  if with_broken_readme 's|badge.svg?branch=main&event=push|badge.svg|' check_ci_badge; then
    echo "VACUOUS GATE: an unfiltered CI badge was accepted!" >&2
    exit 1
  fi

  # 7. A filtered image whose link is unfiltered must fail: clicking to
  #    verify would show a different set of runs than the image reports.
  if with_broken_readme 's|ci.yml?query=branch%3Amain+event%3Apush|ci.yml|' check_ci_badge; then
    echo "VACUOUS GATE: a CI badge linking somewhere else was accepted!" >&2
    exit 1
  fi

  # 8. A rust badge that disagrees with rust-toolchain.toml must fail.
  if with_broken_readme 's|badge/rust-[0-9.]*-orange|badge/rust-9.9.9-orange|' check_rust_badge; then
    echo "VACUOUS GATE: a rust badge that contradicts rust-toolchain.toml was accepted!" >&2
    exit 1
  fi

  # 9. A license badge that disagrees with Cargo.toml must fail.
  if with_broken_readme 's|badge/license-[A-Za-z0-9.+-]*-blue|badge/license-MIT-blue|' check_license_badge; then
    echo "VACUOUS GATE: a license badge that contradicts Cargo.toml was accepted!" >&2
    exit 1
  fi

  # 10. A license badge pointing at no licence text must fail.
  if with_broken_readme 's|](LICENSE.md)|](docs)|' check_license_badge; then
    echo "VACUOUS GATE: a license badge not linking to LICENSE.md was accepted!" >&2
    exit 1
  fi

  # 11. The three checks must PASS against the real README, or the gate
  #     rejects every pull request for reasons unrelated to its diff.
  check_ci_badge      || { echo "BROKEN GATE: the real CI badge was rejected!" >&2; exit 1; }
  check_rust_badge    || { echo "BROKEN GATE: the real rust badge was rejected!" >&2; exit 1; }
  check_license_badge || { echo "BROKEN GATE: the real license badge was rejected!" >&2; exit 1; }

  echo "badge gate self-test OK: drift, red runs, empty and unparsable logs all rejected;"
  echo "  an unfiltered CI badge, a mislinked CI badge, a stale rust version, a wrong"
  echo "  licence id and a licence badge with no text behind it are all rejected too;"
  echo "  the README as committed passes every one."
  exit 0
fi

[ $# -ge 1 ] || { echo "usage: $0 <cargo-test-log> | --self-test"; exit 1; }
gate "$1"
