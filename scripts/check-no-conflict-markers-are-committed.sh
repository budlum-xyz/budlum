#!/usr/bin/env bash
# ============================================================================
# check-no-conflict-markers-are-committed.sh
#
# A merge that was resolved by hand can leave `<<<<<<<`, `=======` and
# `>>>>>>>` in a file, and nothing here noticed. Measured: `main` carried
# three of them in README.md for two merges, advertised on the front page of
# the repository, while all 62 checks stayed green.
#
# Why no existing gate caught it: `check-badges-are-current.sh` reads the
# badge number with a regex that matched the line *inside* the conflict
# block, so the badge looked correct and the markers around it were never
# examined. rustfmt would have caught it in a `.rs` file; nothing reads
# Markdown.
#
# The check is deliberately whole-tree rather than diff-scoped. A marker that
# survives one merge survives every later one, so scoping to the current
# change would let an old marker sit forever.
#
# Usage:
#   bash scripts/check-no-conflict-markers-are-committed.sh              # gate
#   bash scripts/check-no-conflict-markers-are-committed.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# A conflict marker is these seven bytes at the start of a line. The trailing
# space on the open and close markers matters: `<<<<<<<` with no space is a
# legitimate thing to write in prose about merge conflicts, which this file
# itself does above, and matching it would make the gate fail on its own
# documentation.
scan() {
  local dir="$1"
  grep -rnE '^(<<<<<<< |>>>>>>> |={7}$)' "$dir" \
    --exclude-dir=.git \
    --exclude-dir=target \
    --exclude="check-no-conflict-markers-are-committed.sh" \
    2>/dev/null || true
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  canaries=0

  # Canary 1: the exact shape found on main.
  mkdir -p "$tmp/c1"
  printf '%s\n' '<<<<<<< HEAD' '[badge A]' '=======' '>>>>>>> abc1234 (msg)' > "$tmp/c1/README.md"
  [ -n "$(scan "$tmp/c1")" ] || fail "canary 1: the marker set found on main was not detected"
  canaries=$((canaries + 1))

  # Canary 2: open marker alone, the half a truncated resolution leaves.
  mkdir -p "$tmp/c2"
  printf '%s\n' 'text' '<<<<<<< ours' 'more' > "$tmp/c2/a.rs"
  [ -n "$(scan "$tmp/c2")" ] || fail "canary 2: a lone open marker was not detected"
  canaries=$((canaries + 1))

  # Canary 3: close marker alone.
  mkdir -p "$tmp/c3"
  printf '%s\n' 'text' '>>>>>>> theirs' > "$tmp/c3/b.yml"
  [ -n "$(scan "$tmp/c3")" ] || fail "canary 3: a lone close marker was not detected"
  canaries=$((canaries + 1))

  # Canary 4: the bare separator, which is the one a human reader skips over.
  mkdir -p "$tmp/c4"
  printf '%s\n' 'text' '=======' 'more' > "$tmp/c4/c.md"
  [ -n "$(scan "$tmp/c4")" ] || fail "canary 4: a bare seven-equals separator was not detected"
  canaries=$((canaries + 1))

  # Canary 5: a Markdown setext heading underline is six or more equals and is
  # NOT a conflict. This is the false positive that would make the gate
  # unusable, so it is pinned.
  mkdir -p "$tmp/c5"
  printf '%s\n' 'A heading' '=========' 'body' > "$tmp/c5/d.md"
  [ -z "$(scan "$tmp/c5")" ] || fail "canary 5: a nine-equals setext heading must not be flagged"
  canaries=$((canaries + 1))

  # Canary 6: prose about merge markers, written without the trailing space,
  # must stay legal or this file's own header would fail the gate.
  mkdir -p "$tmp/c6"
  printf '%s\n' 'we look for <<<<<<< and >>>>>>> in files' > "$tmp/c6/e.md"
  [ -z "$(scan "$tmp/c6")" ] || fail "canary 6: prose mentioning markers must not be flagged"
  canaries=$((canaries + 1))

  # Canary 7: a clean tree returns nothing, so the gate is not passing by
  # matching everything.
  mkdir -p "$tmp/c7"
  printf '%s\n' 'ordinary line' 'another' > "$tmp/c7/f.rs"
  [ -z "$(scan "$tmp/c7")" ] || fail "canary 7: a clean tree must produce no findings"
  canaries=$((canaries + 1))

  echo "conflict marker gate self-test OK: $canaries canaries"
  exit 0
fi

found="$(scan "$ROOT")"
if [ -n "$found" ]; then
  echo "$found" >&2
  fail "conflict markers are committed; a merge was left half-resolved"
fi
echo "OK: no conflict markers in the tree"
