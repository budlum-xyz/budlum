#!/usr/bin/env bash
# ============================================================================
# check-guards-are-reachable.sh, a refusal nothing calls is a comment.
#
# Three defects of the same shape have now been found by hand, and each was
# correct code that never ran:
#
#   * `objects_needing_repair` computed the repair band and no sweep read it,
#     so the effective repair window was unbounded while every published
#     durability figure assumed one that existed.
#   * `validate_mainnet_disk_policy` refused plaintext BLS and post-quantum
#     keys on mainnet, and no load path called it.
#   * `check_content_may_be_public` refused to let paid content register in
#     the public deduplicated class. Its doc comment said "called on the
#     declaration path". Nothing called it, so paid content registered as
#     plaintext, and a plaintext ContentId is the hash of the bytes: anyone
#     holding a candidate file could confirm it was the listed asset.
#
# All three passed review, passed their own tests, and passed CI. What they
# have in common is not a bug in the logic but a missing edge in the call
# graph, and nothing in this repository was looking for that.
#
# This gate counts them. Every `pub fn` whose name begins check/verify/
# validate/require/enforce/assert/reject/refuse/deny/guard is a refusal by
# its own naming, and a refusal reachable only from tests protects the tests.
#
# It is a ratchet rather than a wall. Twenty exist today; that is the
# baseline, and it may only go down. Wiring one up, or moving it into a
# module that honestly declares `WIRING: unwired`, lowers the number. Adding
# a twenty-first fails the run that adds it, which is the moment it costs
# nothing to fix.
#
# Deliberately not a hard zero. Twenty modules cannot be wired in one change
# without a diff nobody can review, and a gate that demands that gets turned
# off. A number that can only fall gets paid down.
#
# Usage:
#   bash scripts/check-guards-are-reachable.sh              # gate
#   bash scripts/check-guards-are-reachable.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
BASELINE_FILE="$ROOT/.github/unwired-guards-baseline.txt"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Count guards that no production file calls, in a tree rooted at $1.
#
# Printed one per line as `path\tname` so the gate can name them, with the
# count on the last line.
scan() {
  python3 - "$1" <<'PY'
import os, re, sys

root = sys.argv[1]
src = os.path.join(root, "src")
if not os.path.isdir(src):
    print("0")
    sys.exit(0)

prod = {}
for base, dirs, files in os.walk(src):
    dirs[:] = [d for d in dirs if d not in (".git", "target")]
    for fn in files:
        if not fn.endswith(".rs"):
            continue
        p = os.path.join(base, fn)
        # Test files are not production callers. A guard called only from
        # `src/tests/` is exactly the case this gate exists to count.
        if f"{os.sep}tests{os.sep}" in p or p.endswith("_tests.rs"):
            continue
        prod[p] = open(p, encoding="utf-8", errors="replace").read()


def code(text):
    """Production code with test modules and doc comments removed.

    Doc comments are dropped because a doc link naming a function is not a
    call: measured, `derived.rs` mentioning `generated::GeneratorId` in prose
    was enough to make a different gate report that module as wired.
    """
    text = text.split("#[cfg(test)]")[0]
    return re.sub(r"^[ \t]*//[/!].*$", "", text, flags=re.MULTILINE)


GUARD = re.compile(
    r"\bpub (?:async )?fn ((?:check|verify|validate|require|enforce|assert"
    r"|reject|refuse|deny|guard)_[a-z0-9_]+)"
)

unreached = []
for path, text in prod.items():
    body = text.split("#[cfg(test)]")[0]
    # A module that declares itself unwired is already honest about this.
    if "WIRING: unwired" in text:
        continue
    for m in GUARD.finditer(body):
        name = m.group(1)
        call = re.compile(r"(?<![a-zA-Z0-9_])" + re.escape(name) + r"\s*\(")
        decl = re.compile(r"\bfn\s+" + re.escape(name) + r"\s*[(<]")
        reached = False
        for other, otext in prod.items():
            c = code(otext)
            for hit in call.finditer(c):
                # The definition itself is not a call to itself.
                if not decl.search(c, max(0, hit.start() - 16), hit.end()):
                    reached = True
                    break
            if reached:
                break
        if not reached:
            unreached.append((os.path.relpath(path, root), name))

for path, name in sorted(unreached):
    print(f"{path}\t{name}")
print(len(unreached))
PY
}

count_of() { scan "$1" | tail -1; }

gate() {
  [ -f "$BASELINE_FILE" ] || fail "baseline missing: $BASELINE_FILE"
  local baseline
  baseline="$(grep -E '^[0-9]+$' "$BASELINE_FILE" | head -1)"
  [ -n "$baseline" ] || fail "no number in $BASELINE_FILE, gate would be vacuous"

  local output count
  output="$(scan "$ROOT")"
  count="$(tail -1 <<<"$output")"

  echo "unwired guards: $count | baseline: $baseline"

  if [ "$count" -gt "$baseline" ]; then
    echo "--- guards no production path reaches ---" >&2
    sed '$d' <<<"$output" >&2
    fail "unwired guard count rose from $baseline to $count.
  A refusal that nothing calls is a comment. Three defects of exactly this
  shape have already been found by hand, each correct and each never run.
  Either call the new guard from the path it was written for, or put it in a
  module whose doc says \`WIRING: unwired - <reason>\`."
  fi

  if [ "$count" -lt "$baseline" ]; then
    echo "Baseline is now loose: $count guards remain, the file says $baseline."
    echo "Lower it in this pull request, or the gain is given back silently."
    fail "baseline not tightened after wiring a guard up"
  fi

  echo "OK: no new unreachable guards."
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  canaries=0

  mk() {
    local dir="$1" body="$2" caller="$3"
    rm -rf "$dir"
    mkdir -p "$dir/src" "$dir/.github"
    printf '%s\n' "$body" > "$dir/src/guarded.rs"
    printf '%s\n' "$caller" > "$dir/src/lib.rs"
    printf '0\n' > "$dir/.github/unwired-guards-baseline.txt"
  }

  GUARD_FN='pub fn check_thing_is_allowed(x: u8) -> Result<(), String> {
    if x == 0 { return Err("no".into()); }
    Ok(())
}'
  CALLS='pub mod guarded;
pub fn drive() { let _ = guarded::check_thing_is_allowed(1); }'
  SILENT='pub mod guarded;
pub fn drive() {}'
  MARKED='//! WIRING: unwired - kept until the caller lands.
pub fn check_thing_is_allowed(x: u8) -> Result<(), String> {
    if x == 0 { return Err("no".into()); }
    Ok(())
}'
  DOC_ONLY='pub mod guarded;
/// See [`guarded::check_thing_is_allowed`] for the rule this mirrors.
pub fn drive() {}'

  # 1. A guard nothing calls must be counted. The case the gate exists for.
  mk "$tmp/silent" "$GUARD_FN" "$SILENT"
  [ "$(count_of "$tmp/silent")" = "1" ] \
    || fail "canary 1: an uncalled guard was not counted"
  canaries=$((canaries + 1))

  # 2. A guard that is called must not be counted, or the gate is a ban on
  #    naming a function `check_`.
  mk "$tmp/wired" "$GUARD_FN" "$CALLS"
  [ "$(count_of "$tmp/wired")" = "0" ] \
    || fail "canary 2: a guard that is genuinely called was counted"
  canaries=$((canaries + 1))

  # 3. A module that declares itself unwired is already honest, and must not
  #    be counted twice.
  mk "$tmp/marked" "$MARKED" "$SILENT"
  [ "$(count_of "$tmp/marked")" = "0" ] \
    || fail "canary 3: an honestly declared unwired module was counted"
  canaries=$((canaries + 1))

  # 4. A doc comment mentioning the guard is not a call. Measured on this
  #    tree: prose in a neighbouring module was enough to make a different
  #    gate report an unwired module as wired.
  mk "$tmp/doc" "$GUARD_FN" "$DOC_ONLY"
  [ "$(count_of "$tmp/doc")" = "1" ] \
    || fail "canary 4: a doc-comment mention was counted as a call"
  canaries=$((canaries + 1))

  # 5. A call from a test file is not a production call.
  mk "$tmp/testonly" "$GUARD_FN" "$SILENT"
  mkdir -p "$tmp/testonly/src/tests"
  printf '%s\n' 'fn t() { let _ = crate::guarded::check_thing_is_allowed(1); }' \
    > "$tmp/testonly/src/tests/mod.rs"
  [ "$(count_of "$tmp/testonly")" = "1" ] \
    || fail "canary 5: a test-only caller was treated as production"
  canaries=$((canaries + 1))

  # 6. The ratchet must fail upward. A baseline of 0 against a tree with one
  #    unreached guard has to be a failure, not a warning.
  mk "$tmp/rise" "$GUARD_FN" "$SILENT"
  if ( BUDLUM_ROOT="$tmp/rise" \
       BASELINE_FILE="$tmp/rise/.github/unwired-guards-baseline.txt" \
       bash "$0" ) >/dev/null 2>&1; then
    fail "canary 6: a rise above the baseline was accepted"
  fi
  canaries=$((canaries + 1))

  # 7. And it must fail downward too, so a gain is written down instead of
  #    being silently available to spend later.
  mk "$tmp/fall" "$GUARD_FN" "$CALLS"
  printf '3\n' > "$tmp/fall/.github/unwired-guards-baseline.txt"
  if ( BUDLUM_ROOT="$tmp/fall" \
       BASELINE_FILE="$tmp/fall/.github/unwired-guards-baseline.txt" \
       bash "$0" ) >/dev/null 2>&1; then
    fail "canary 7: a stale, too-loose baseline was accepted"
  fi
  canaries=$((canaries + 1))

  # 8. The tree as committed must pass.
  gate >/dev/null || fail "the committed tree does not match its own baseline"
  canaries=$((canaries + 1))

  echo "guard reachability gate self-test OK: $canaries canaries."
  echo "  An uncalled guard is counted, a called one is not, an honest unwired"
  echo "  marker is respected, prose and test-only callers do not count, and the"
  echo "  ratchet fails in both directions."
  exit 0
fi

gate
