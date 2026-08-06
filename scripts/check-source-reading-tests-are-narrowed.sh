#!/usr/bin/env bash
# ============================================================================
# check-source-reading-tests-are-narrowed.sh
#
# A test that reads its own file must not be satisfied by its own text.
#
# Why this gate exists.
#
# Several pins in this tree assert things about the call graph by reading
# source with `include_str!`, because "nothing calls this" is not observable
# from behaviour. That is a legitimate technique and it has found real
# defects. It has one failure mode, and the tree has hit it twice.
#
# `include_str!("thisfile.rs")` reads the whole file, test module included.
# The string being searched for is usually written twice: once in the code,
# once in the assertion that looks for it. Searched whole-file, the assertion
# finds its own text, so:
#
#   * a positive assertion (`contains(X)`) passes even after X is deleted
#     from production, which is the exact change it exists to catch;
#   * a negative assertion (`!contains(X)`) fails immediately and for the
#     wrong reason, which is how this was first noticed: CI rejected
#     `the_peer_cap_is_not_decided_a_second_time_in_this_file` because the
#     needle `max_peers: if mobile_mode` appeared in the assertion itself.
#
# The first is worse. A test that fails loudly gets fixed within the hour; a
# pin that passes on the strength of its own source is a pin that has been
# switched off and still reports green.
#
# What the gate checks.
#
# Every file containing `include_str!("<its own name>")` must narrow before
# it searches: either by splitting at `#[cfg(test)]`, by bounding a window
# around a `find(...)` offset, or by assembling the needle at runtime so it
# cannot appear verbatim in its own source.
#
# Known limits. This measures the presence of a narrowing technique, not that
# the narrowing is correct: a test could split at `#[cfg(test)]` and then
# search the unsplit string anyway. That would be caught by review, not here.
# The two files this gate was written against both do the narrowing properly.
#
# Usage:
#   bash scripts/check-source-reading-tests-are-narrowed.sh              # gate
#   bash scripts/check-source-reading-tests-are-narrowed.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

scan() {
  python3 - "$1" <<'PY'
import os, re, sys

root = sys.argv[1]
problems = []
checked = 0

for scan_root in ("src", "budzero", "wallet-core"):
    base = os.path.join(root, scan_root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            src = open(path, encoding="utf-8", errors="replace").read()
            if f'include_str!("{name}")' not in src:
                continue
            # Which binding holds the file contents. Only searches against
            # *that* can be satisfied by the assertion's own text.
            holders = set(
                re.findall(rf'let (\w+) = include_str!\("{re.escape(name)}"\)', src)
            )
            if not holders:
                continue

            # Measured: the file reads itself, whatever it does next. Counting
            # only the accusable ones would let the gate go hollow the moment
            # every finding is fixed, which is exactly when it still needs to
            # be watching.
            checked += 1

            # Follow one hop of derivation. A test that does
            # `let prod = src.split_once(...)` and then searches `prod` has
            # narrowed, and `prod` must not be treated as the raw file.
            narrowed_from = set()
            for holder in list(holders):
                narrowed_from.update(
                    re.findall(rf'let (\w+) = {re.escape(holder)}\s*\n?\s*\.', src)
                )
                narrowed_from.update(
                    re.findall(rf'let (\w+) = &?{re.escape(holder)}\[', src)
                )
            holders -= narrowed_from

            # A `contains` on anything else is a different question. Measured:
            # `registry/params.rs` calls `doc.contains("governance-tunable")`
            # on a doc comment it assembled and `err.contains(...)` on an
            # error message, neither of which is the file's own source.
            literal_searches = [
                needle
                for holder in holders
                for needle in re.findall(
                    # Exactly this binding: `\w*` here would let `adapter_src`
                    # match `adapter_prod` and hide the very defect the gate
                    # is for. Measured by reverting the fix and watching the
                    # gate stay green.
                    rf'(?<![a-zA-Z0-9_]){re.escape(holder)}\.contains\("([^"]{{4,}})"\)',
                    src,
                )
            ]
            if not literal_searches:
                continue

            # Reaching here means a search against the RAW file binding
            # survived, and `literal_searches` names it. Asking "does this
            # file contain a narrowing technique somewhere" would answer yes
            # for a file that narrows in one assertion and not in the next,
            # which is the shape `adapter.rs` actually had: measured by
            # reverting the fix and watching the gate stay green.
            #
            # Does it narrow before searching? Kept as a separate signal so
            # the failure message can tell a file that narrows nowhere from
            # one that narrows inconsistently.
            narrowed = (
                'split_once("#[cfg(test)]")' in src
                or 'split("#[cfg(test)]")' in src
                # a bounded window around a located offset
                or re.search(r"&\w+\[\w+\.\.\(?\w+\s*\+\s*\d+", src) is not None
                # needle assembled at runtime
                or re.search(r'let \w+ = format!\("[^"]*\{\}', src) is not None
                or re.search(r'"\w+"\.to_string\(\) \+ "', src) is not None
            )
            if not narrowed or literal_searches:
                problems.append(
                    f"{os.path.relpath(path, root)} reads its own source with "
                    "include_str! and searches it whole. Every string it looks "
                    "for is also written in the assertion that looks for it, so "
                    "a positive assertion passes after the production code is "
                    "deleted. Split at `#[cfg(test)]`, bound a window around a "
                    "`find` offset, or assemble the needle at runtime."
                )

if checked == 0:
    print("FAIL: gate found no self-reading test at all, so it measured nothing",
          file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"source-reading test gate OK: {checked} files read their own source, "
      "each narrowing before it searches")
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  canaries=0

  mk() {
    rm -rf "$tmp/case"; mkdir -p "$tmp/case/src"
    printf '%s\n' "$1" > "$tmp/case/src/probe.rs"
  }

  # 1. The bug: reads itself, searches whole-file. Must be caught.
  mk 'pub fn thing() {}
#[cfg(test)]
mod t {
    #[test]
    fn pinned() {
        let src = include_str!("probe.rs");
        assert!(src.contains("pub fn thing"));
    }
}'
  if ( scan "$tmp/case" ) >/dev/null 2>&1; then
    fail "canary 1: a whole-file self-search was accepted"
  fi
  canaries=$((canaries + 1))

  # 2. Narrowed by splitting at #[cfg(test)]. The searches are against the
  #    narrowed binding, so there is no raw-file search left to measure and
  #    a tree of only this file reports "measured nothing" (exit 2). What
  #    matters is that it is not ACCUSED, which is exit 1.
  mk 'pub fn thing() {}
#[cfg(test)]
mod t {
    #[test]
    fn pinned() {
        let src = include_str!("probe.rs");
        let prod = src.split_once("#[cfg(test)]").map(|(a, _)| a).unwrap();
        assert!(prod.contains("pub fn thing"));
    }
}'
  rc=0
  ( scan "$tmp/case" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] || fail "canary 2: a correctly narrowed test was accused"
  canaries=$((canaries + 1))

  # 3. Narrowed by a bounded window around a located offset. Same shape.
  mk 'pub fn thing() {}
#[cfg(test)]
mod t {
    #[test]
    fn pinned() {
        let src = include_str!("probe.rs");
        let at = src.find("pub fn thing").unwrap();
        let body = &src[at..(at + 400).min(src.len())];
        assert!(body.contains("thing"));
    }
}'
  rc=0
  ( scan "$tmp/case" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] || fail "canary 3: a windowed test was accused"
  canaries=$((canaries + 1))

  # 4. A runtime-assembled needle cannot appear verbatim in its own source,
  #    so there is nothing for it to collide with. The gate has no fixed
  #    string to measure either, so it skips the file: exit 2 on a tree
  #    containing only this one, which is "measured nothing", not "passed".
  mk 'pub fn thing() {}
#[cfg(test)]
mod t {
    #[test]
    fn pinned() {
        let src = include_str!("probe.rs");
        let needle = format!("pub fn {}", "thing");
        assert!(src.contains(&needle));
    }
}'
  rc=0
  ( scan "$tmp/case" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] || fail "canary 4: a runtime-assembled needle was accused"
  canaries=$((canaries + 1))

  # 5. A tree with no self-reading test must exit 2, not pass. A gate that
  #    silently measures nothing is worse than one that is absent.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty/src"
  printf '%s\n' 'pub fn thing() {}' > "$tmp/empty/src/probe.rs"
  rc=0
  ( scan "$tmp/empty" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] || fail "canary 5: measuring nothing exited $rc, expected 2"
  canaries=$((canaries + 1))

  # 6. A test that reads its own source but searches no fixed string cannot
  #    collide with its own text, and must not be accused. Measured:
  #    `registry/params.rs` iterates every `pub` field and its doc comment,
  #    which is a legitimate use with no needle to find.
  rm -rf "$tmp/iter"; mkdir -p "$tmp/iter/src"
  printf '%s\n' 'pub fn thing() {}
#[cfg(test)]
mod t {
    #[test]
    fn every_field_is_documented() {
        let src = include_str!("probe.rs");
        let mut seen = 0;
        for line in src.lines() {
            if line.trim().starts_with("pub ") {
                seen += 1;
            }
        }
        assert!(seen > 0);
    }
}' > "$tmp/iter/src/probe.rs"
  rc=0
  ( scan "$tmp/iter" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] \
    || fail "canary 6: a needle-free self-reading test was accused"
  canaries=$((canaries + 1))

  # 6. The tree as committed must pass.
  scan "$ROOT" >/dev/null || fail "the committed tree does not pass its own gate"
  canaries=$((canaries + 1))

  echo "source-reading test gate self-test OK: $canaries canaries."
  exit 0
fi

scan "$ROOT"
