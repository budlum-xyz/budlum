#!/usr/bin/env bash
# ============================================================================
# check-accumulators-pin-their-first-row.sh
#
# A column built by a transition rule must have its first row pinned.
#
# Why this gate exists.
#
# `COL_EVENT_DIGEST_0` accumulates the `rs1` of every `Log` row. Two things
# constrained it: a transition,
#
#   digest[i+1] - digest[i] - is_log[i+1] * rs1[i+1] == 0
#
# and a last-row comparison against `public_inputs[40]`. The transition fixes
# the difference between consecutive rows and says nothing about where the
# sequence starts, so the whole run slides: a prover writes `D` on the first
# row, every relative step still holds because each one is relative, and the
# last row carries `D + sum(logged values)`. The public input then states an
# event digest for events the program never emitted, with `D` free.
#
# The field is not decorative. `storage_deal.rs` packs its entire replay
# context into it, deal and challenge and responder and epoch and chain,
# specifically so one shard proof cannot answer a different challenge. A prover
# choosing the starting value is a prover choosing that context.
#
# Every other accumulator in the AIR already pinned its first row: both image
# folds, `clk`, `pc`, and all three LogUp running sums. This one was the
# exception. A rule that holds for six columns and not the seventh is not a
# rule anyone remembers, so it is checked instead.
#
# What the gate checks.
#
# For each accumulator column below, the AIR must contain both:
#
#   * a `when_transition` constraint mentioning it, which is what makes it an
#     accumulator rather than a plain witness, and
#   * a `when_first_row` constraint mentioning it.
#
# The list is explicit. Discovering "every column used in a transition" would
# sweep in the continuity rules for the register and memory tables, where the
# first row is deliberately unconstrained because the table may start mid-run.
# What is listed here is the narrow class: columns that accumulate a value
# forward and are then read out against a public input.
#
# Usage:
#   bash scripts/check-accumulators-pin-their-first-row.sh              # gate
#   bash scripts/check-accumulators-pin-their-first-row.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
air = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_air.rs")

if not os.path.isfile(air):
    print(f"FAIL: no AIR at {air}", file=sys.stderr)
    sys.exit(2)

src = open(air, encoding="utf-8").read()
code = re.sub(r"//[^\n]*", "", src)

# Columns that accumulate forward and are read out against a public input.
# Each entry is (column, what it accumulates, what a free start would let a
# prover claim).
ACCUMULATORS = [
    (
        "COL_EVENT_DIGEST_0",
        "the rs1 of every Log row",
        "an event digest for events the program never emitted, which is the "
        "replay context storage challenges are bound by",
    ),
    (
        "COL_MEM_INIT_ACC",
        "the committed initial memory image",
        "a starting memory image the host never provided",
    ),
    (
        "COL_REG_INIT_ACC",
        "the committed initial register file",
        "a starting register file the host never provided",
    ),
    (
        "COL_GAS_USED",
        "the running gas total",
        "a gas figure that does not match the work done",
    ),
]

problems = []
checked = 0

# Split the AIR into `builder.<gate>()...;` statements so a constraint's gate
# and its operands are read together rather than by line proximity.
statements = re.findall(r"builder\s*\.[^;]*;", code, re.DOTALL)


def names_for(column):
    """The column plus every local the AIR reads it into.

    Constraints are written against locals, not against `cur[COL_...]`
    directly: the event digest is read into `cur_event_0` and `nxt_event_0`
    before it is used. A gate that only looked for the column name would find
    the declarations and none of the constraints, and would then report
    "not an accumulator" for every column in the list, which is the shape of
    a gate that fails loudly instead of checking anything.
    """
    found = {column}
    for m in re.finditer(
        rf"let\s+(\w+)\s*(?::[^=]+)?=\s*(?:cur|nxt)\[\s*{re.escape(column)}\s*\]", code
    ):
        found.add(m.group(1))
    return found


def mentions(statement, column):
    return any(re.search(rf"\b{re.escape(n)}\b", statement) for n in names_for(column))

for column, accumulates, risk in ACCUMULATORS:
    if column not in src:
        problems.append(
            f"{column} is gone from the AIR. If the accumulator was removed the "
            f"entry here should go with it, in the same commit, with the reason."
        )
        continue

    checked += 1

    in_transition = any(
        "when_transition" in st and mentions(st, column) for st in statements
    )
    in_first_row = any(
        "when_first_row" in st and mentions(st, column) for st in statements
    )

    if not in_transition:
        # Not an accumulator any more, or renamed. Either way the entry is
        # stale and saying so is better than passing quietly.
        problems.append(
            f"{column} appears in no `when_transition` constraint, so this gate "
            f"cannot confirm it is still an accumulator. If it stopped being "
            f"one, remove it from the list in the same commit."
        )
        continue

    if not in_first_row:
        problems.append(
            f"{column} accumulates {accumulates} across a transition but its "
            f"first row is not pinned. A transition constrains differences "
            f"between rows and never the starting point, so the whole sequence "
            f"slides and a prover can claim {risk}."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"accumulator gate OK: {checked} accumulators, every first row pinned")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src"
    printf '%s\n' "$body" >"$dir/budzero/bud-proof/src/plonky3_air.rs"
  }

  GOOD='pub const COL_EVENT_DIGEST_0: usize = 696;
pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_zero(nxt[COL_EVENT_DIGEST_0] - cur[COL_EVENT_DIGEST_0]);
        builder.when_first_row().assert_zero(cur[COL_EVENT_DIGEST_0]);
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_MEM_INIT_ACC], zero.clone());
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'

  # 1. The corrected shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected AIR was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: the event digest accumulates with no starting point.
  mk "$tmp/sliding" 'pub const COL_EVENT_DIGEST_0: usize = 696;
pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_zero(nxt[COL_EVENT_DIGEST_0] - cur[COL_EVENT_DIGEST_0]);
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_MEM_INIT_ACC], zero.clone());
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'
  if ( scan "$tmp/sliding" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an accumulator with no first-row constraint was accepted!" >&2
    exit 1
  fi

  # 3. The same hole in one of the image folds. All four are covered, not just
  #    the one that happened to be wrong.
  mk "$tmp/memhole" 'pub const COL_EVENT_DIGEST_0: usize = 696;
pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_zero(nxt[COL_EVENT_DIGEST_0] - cur[COL_EVENT_DIGEST_0]);
        builder.when_first_row().assert_zero(cur[COL_EVENT_DIGEST_0]);
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'
  if ( scan "$tmp/memhole" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unpinned memory image fold was accepted!" >&2
    exit 1
  fi

  # 4. A first-row constraint on a *different* column must not count for this
  #    one. Matching by line proximity rather than by statement is the way a
  #    gate like this goes vacuous.
  mk "$tmp/wrongcol" 'pub const COL_EVENT_DIGEST_0: usize = 696;
pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_zero(nxt[COL_EVENT_DIGEST_0] - cur[COL_EVENT_DIGEST_0]);
        builder.when_first_row().assert_zero(cur[COL_CLK]);
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_MEM_INIT_ACC], zero.clone());
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'
  if ( scan "$tmp/wrongcol" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a first-row constraint on another column was counted!" >&2
    exit 1
  fi

  # 5. A comment naming the column is not a constraint.
  mk "$tmp/comment" 'pub const COL_EVENT_DIGEST_0: usize = 696;
pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_zero(nxt[COL_EVENT_DIGEST_0] - cur[COL_EVENT_DIGEST_0]);
        // builder.when_first_row().assert_zero(cur[COL_EVENT_DIGEST_0]);
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_MEM_INIT_ACC], zero.clone());
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'
  if ( scan "$tmp/comment" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a commented-out constraint was accepted!" >&2
    exit 1
  fi

  # 6. A deleted column must fail rather than pass for having nothing to check.
  mk "$tmp/gone" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
pub const COL_GAS_USED: usize = 57;
        builder.when_transition().assert_eq(nxt[COL_MEM_INIT_ACC], cur[COL_MEM_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_MEM_INIT_ACC], zero.clone());
        builder.when_transition().assert_eq(nxt[COL_REG_INIT_ACC], cur[COL_REG_INIT_ACC]);
        builder.when_first_row().assert_eq(cur[COL_REG_INIT_ACC], zero.clone());
        builder.when_transition().assert_zero(nxt[COL_GAS_USED] - cur[COL_GAS_USED]);
        builder.when_first_row().assert_zero(cur[COL_GAS_USED]);'
  if ( scan "$tmp/gone" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing accumulator column was accepted!" >&2
    exit 1
  fi

  # 7. A missing AIR must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no AIR was accepted!" >&2
    exit 1
  fi

  echo "accumulator gate self-test OK: an unpinned event digest, an unpinned image fold, a first-row constraint on another column, a commented-out constraint, a deleted column and a missing AIR are all rejected; the pinned tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
