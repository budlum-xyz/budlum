#!/usr/bin/env bash
# ============================================================================
# check-slash-expression-has-one-home.sh
#
# The fixed-point slash penalty must be computed by a named function, never
# spelled out at a call site.
#
# B35: the expression
#
#     ((stake as u128 * ratio as u128) / FIXED_POINT_SCALE as u128) as u64
#
# was written out at five places across two workspaces, and the narrowing was
# not spelled the same way in all of them. `as u64` truncates; the Kani mirror
# used `try_from().expect()`, which panics. At `stake = u64::MAX` and
# `ratio = FIXED_POINT_SCALE + 1` the quotient is wider than 64 bits, so the
# production copies wrapped to about 1.8e13 against a bond of about 1.8e19: a
# 100.0001% slash left 99.9999% of the stake in place.
#
# `RegistryParams::validate` rejects a ratio above the ceiling, so the wrap was
# not reachable through governance. That is containment, and containment is
# exactly what this gate is protecting: the guard was one layer, the mirror
# test compared the copies only over ratios where they agree, and nothing
# stopped a sixth copy from landing in front of a path without that guard.
#
# Two homes exist on purpose, because `budzero/verifier-registry` does not
# depend on `budlum-core`:
#
#     src/core/chain_config.rs                    slash_penalty
#     budzero/verifier-registry/src/params.rs     slash_penalty
#
# Their bodies are compared here, so the copy cannot drift.
#
# Usage:
#   bash scripts/check-slash-expression-has-one-home.sh              # gate
#   bash scripts/check-slash-expression-has-one-home.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]

# The two files allowed to contain the expression, because each is a body of
# the canonical function for its workspace.
HOMES = {
    "src/core/chain_config.rs",
    "budzero/verifier-registry/src/params.rs",
}

# `stake * ratio / SCALE`, narrowed to a `u64`, where one operand is a stake
# or a bond. Deliberately loose on whitespace, because one of the five real
# copies was line-wrapped and a single-line regex missed it.
#
# Scoped to the slash path on purpose. The same fixed-point shape appears in
# `tokenomics::metabolic_burn` and `annual_burn_amount`, and those wrap too,
# but a wrapped burn cannot exceed the fee it is taken from, so it is a
# different finding with a different argument and is tracked as B36 rather
# than swept in here. A gate that flags every fixed-point multiply would be
# asking reviewers to silence it, which is how a gate stops meaning anything.
EXPR = re.compile(
    r"(?:stake|bond)[^;]{0,60}?u128[^;]{0,80}?\*[^;]{0,120}?u128"
    r"[^;]{0,120}?/[^;]{0,80}?FIXED_POINT_SCALE[^;]{0,40}?\)\s*as\s+u64",
    re.S | re.I,
)

SKIP_DIRS = {".git", "target", "node_modules", ".cargo"}

offenders = []
scanned = 0
homes_seen = set()

for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for name in sorted(filenames):
        if not name.endswith(".rs"):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        if rel in HOMES:
            homes_seen.add(rel)
            continue
        for m in EXPR.finditer(text):
            start = text.rfind("\n", 0, m.start()) + 1
            line_no = text.count("\n", 0, m.start()) + 1
            line = text[start : text.find("\n", m.start())]
            stripped = line.strip()
            # A comment quoting the old expression is documentation, and this
            # gate is about code. `kani/src/lib.rs` explains the bug by
            # showing it.
            if stripped.startswith(("//", "///", "//!", "*")):
                continue
            offenders.append(f"  {rel}:{line_no}: {stripped[:96]}")

if scanned < 50:
    print(f"FAIL: only {scanned} .rs files scanned under {root}; gate would be vacuous",
          file=sys.stderr)
    sys.exit(2)

if offenders:
    print(f"FAIL: the slash expression is written out at {len(offenders)} place(s) "
          "outside its two homes:", file=sys.stderr)
    for o in offenders:
        print(o, file=sys.stderr)
    print("", file=sys.stderr)
    print("  Call `slash_penalty` instead. It clamps to the bond, which the", file=sys.stderr)
    print("  bare expression does not: a ratio above FIXED_POINT_SCALE makes", file=sys.stderr)
    print("  the quotient exceed u64 and `as u64` wraps it to a fraction of", file=sys.stderr)
    print("  the stake. See B35.", file=sys.stderr)
    sys.exit(1)

print(f"Slash expression OK: {scanned} .rs files scanned, "
      f"{len(homes_seen)} canonical home(s) found, no inline copies.")
PY
}

# The two `slash_penalty` bodies must agree. Compared with comments and
# whitespace removed, because the two files document different things around
# the same arithmetic.
compare_homes() {
  local root="$1"
  python3 - "$root" <<'PY'
import re
import sys

root = sys.argv[1]
HOMES = [
    "src/core/chain_config.rs",
    "budzero/verifier-registry/src/params.rs",
]

def body(path):
    text = open(path, encoding="utf-8").read()
    at = text.find("pub fn slash_penalty")
    if at < 0:
        return None
    brace = text.index("{", at)
    depth = 0
    i = brace
    while True:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    src = text[brace : i + 1]
    src = re.sub(r"//[^\n]*", "", src)
    return re.sub(r"\s+", "", src)

bodies = {}
for rel in HOMES:
    b = body(f"{root}/{rel}")
    if b is None:
        print(f"FAIL: no `pub fn slash_penalty` in {rel}", file=sys.stderr)
        sys.exit(1)
    bodies[rel] = b

first, second = HOMES
if bodies[first] != bodies[second]:
    print("FAIL: the two slash_penalty bodies have drifted apart.", file=sys.stderr)
    print(f"  {first}:\n    {bodies[first][:200]}", file=sys.stderr)
    print(f"  {second}:\n    {bodies[second][:200]}", file=sys.stderr)
    sys.exit(1)

# A body that does not clamp would pass the identity check while losing the
# property, so the shape is checked too.
if "u128::from(u64::MAX)" not in bodies[first] or "returnstake" not in bodies[first]:
    print("FAIL: slash_penalty no longer clamps; the identity check would be "
          "comparing two copies of the bug.", file=sys.stderr)
    sys.exit(1)

print("Both slash_penalty bodies agree and both still clamp.")
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  build_clean() {
    local d="$1"
    mkdir -p "$d/src/core" "$d/budzero/verifier-registry/src"
    for i in $(seq 1 60); do
      printf 'fn f%s() -> u64 { 1 }\n' "$i" > "$d/src/core/f$i.rs"
    done
    local fn='pub fn slash_penalty(stake: u64, r: u64) -> u64 {
    let quotient = (u128::from(stake) * u128::from(r)) / u128::from(FIXED_POINT_SCALE);
    if quotient > u128::from(u64::MAX) {
        return stake;
    }
    let narrow = quotient as u64;
    if narrow > stake { stake } else { narrow }
}'
    printf 'pub const FIXED_POINT_SCALE: u64 = 1_000_000;\n%s\n' "$fn" \
      > "$d/src/core/chain_config.rs"
    printf 'pub const FIXED_POINT_SCALE: u64 = 1_000_000;\n%s\n' "$fn" \
      > "$d/budzero/verifier-registry/src/params.rs"
  }

  build_clean "$tmp/clean"
  out="$(scan "$tmp/clean" 2>&1)" || fail "canary: a clean tree was rejected: $out"
  case "$out" in
    *"no inline copies"*) ;;
    *) fail "canary: clean tree passed with an unexpected message: $out" ;;
  esac
  compare_homes "$tmp/clean" >/dev/null 2>&1 \
    || fail "canary: two identical clamped bodies were reported as drifted"

  # 1. An inline copy anywhere else must be caught.
  rm -rf "$tmp/inline"; build_clean "$tmp/inline"
  cat > "$tmp/inline/src/core/offender.rs" <<'RS'
fn slash(stake: u64, ratio: u64) -> u64 {
    ((stake as u128 * ratio as u128) / FIXED_POINT_SCALE as u128) as u64
}
RS
  if scan "$tmp/inline" >/dev/null 2>&1; then
    fail "canary: an inline copy of the slash expression was not detected"
  fi

  # 2. The same copy split across lines, which is how one of the five real
  #    ones was written and how a regex anchored to a single line misses it.
  rm -rf "$tmp/wrapped"; build_clean "$tmp/wrapped"
  cat > "$tmp/wrapped/src/core/offender.rs" <<'RS'
fn slash(stake: u64, ratio: u64) -> u64 {
    let penalty = ((stake as u128 * ratio as u128)
        / FIXED_POINT_SCALE as u128) as u64;
    penalty
}
RS
  if scan "$tmp/wrapped" >/dev/null 2>&1; then
    fail "canary: a line-wrapped inline copy was not detected"
  fi

  # 3. A comment quoting the expression must NOT be flagged, or the gate
  #    forbids explaining the bug it exists to prevent.
  rm -rf "$tmp/comment"; build_clean "$tmp/comment"
  cat > "$tmp/comment/src/core/doc.rs" <<'RS'
/// The old form was
/// ((stake as u128 * ratio as u128) / FIXED_POINT_SCALE as u128) as u64
/// and it wrapped.
fn documented() -> u64 { 0 }
RS
  scan "$tmp/comment" >/dev/null 2>&1 \
    || fail "canary: a comment quoting the expression was wrongly rejected"

  # 4. Drift between the two homes must be caught.
  rm -rf "$tmp/drift"; build_clean "$tmp/drift"
  printf 'pub const FIXED_POINT_SCALE: u64 = 1_000_000;\npub fn slash_penalty(stake: u64, r: u64) -> u64 {\n    let quotient = (u128::from(stake) * u128::from(r)) / u128::from(FIXED_POINT_SCALE);\n    if quotient > u128::from(u64::MAX) {\n        return stake;\n    }\n    quotient as u64\n}\n' \
    > "$tmp/drift/budzero/verifier-registry/src/params.rs"
  if compare_homes "$tmp/drift" >/dev/null 2>&1; then
    fail "canary: two different slash_penalty bodies were accepted as equal"
  fi

  # 5. Two identical but UNCLAMPED bodies must be caught. Without this the
  #    identity check would happily compare two copies of the bug.
  rm -rf "$tmp/unclamped"; build_clean "$tmp/unclamped"
  local_unclamped='pub fn slash_penalty(stake: u64, r: u64) -> u64 {
    ((u128::from(stake) * u128::from(r)) / u128::from(FIXED_POINT_SCALE)) as u64
}'
  for f in src/core/chain_config.rs budzero/verifier-registry/src/params.rs; do
    printf 'pub const FIXED_POINT_SCALE: u64 = 1_000_000;\n%s\n' "$local_unclamped" \
      > "$tmp/unclamped/$f"
  done
  if compare_homes "$tmp/unclamped" >/dev/null 2>&1; then
    fail "canary: two identical unclamped bodies were accepted"
  fi

  # 6. Vacuity floor.
  mkdir -p "$tmp/empty"
  printf 'fn a() {}\n' > "$tmp/empty/only.rs"
  if scan "$tmp/empty" >/dev/null 2>&1; then
    fail "canary: a near-empty tree passed; the vacuity floor is not working"
  fi

  echo "Self-test OK: inline copy, wrapped copy, drift, unclamped pair and an empty tree all rejected; a comment and a clean tree pass."
  exit 0
fi

scan "$ROOT"
compare_homes "$ROOT"
