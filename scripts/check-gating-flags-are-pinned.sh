#!/usr/bin/env bash
# ============================================================================
# check-gating-flags-are-pinned.sh
#
# A witness column that gates a constraint must itself be pinned down.
#
# Why this gate exists.
#
# `COL_REG_SAME` is a flag meaning "the next row of the register table is
# about the same register". It gates the two constraints that give the table
# its meaning: that a register keeps its value between a write and the next
# read, and that consecutive rows for one register agree on the index. Both
# were written as
#
#   r_active * nr_active * r_same * (...)
#
# so setting `r_same = 0` switched them off. Nothing anywhere said when that
# was allowed. There was no booleanity constraint on the column, no constraint
# on the `1 - r_same` side, and the LogUp argument never reads it, so the
# honest value was whatever the prover chose to write. Writing zero on the row
# before a read removed the requirement that the read return the value that
# had been written, and register values are the inputs to every arithmetic
# constraint in the machine.
#
# The memory table has the identical shape and was never vulnerable, which is
# exactly why this was easy to miss. There, `m_same = 0` is a claim that the
# next row is a different address, and a separate constraint then forces the
# first read of a new address to return zero. Claiming it costs the prover the
# value it wanted to invent. Registers have no first-touch rule, so the
# counterpart was never written.
#
# What the gate checks.
#
# For each flag column listed below, the AIR must contain evidence that the
# flag is constrained rather than merely used, in at least one of these forms:
#
#   * a booleanity assertion on it, and
#   * either a constraint on the negated side (`one - flag`), or an equality
#     tying the flag to something derived (`assert_eq(flag, ...)`).
#
# Booleanity alone is not enough and is the trap this gate is named for: a
# boolean flag that only ever appears as a multiplier can still be set to zero
# for free. The column has to cost something when it lies.
#
# The list is explicit rather than discovered. A regex that tried to find
# "every column used as a multiplier inside assert_zero" would sweep in every
# selector and every activity flag, most of which are pinned by other means
# (selectors by the opcode binding, activity flags by LogUp multiplicity), and
# a gate that fires on correct code gets switched off. What is listed here is
# the narrow class this bug came from: same-ness flags comparing a row to its
# neighbour.
#
# Usage:
#   bash scripts/check-gating-flags-are-pinned.sh              # gate
#   bash scripts/check-gating-flags-are-pinned.sh --self-test  # canary
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
air = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_air.rs")

if not os.path.isfile(air):
    print(f"FAIL: no AIR at {air}", file=sys.stderr)
    sys.exit(2)

src = open(air, encoding="utf-8").read()

# The flags this gate is responsible for, and the local binding each one is
# read into. Both spellings matter: the column name proves the flag still
# exists, the local name is what the constraints are written in terms of.
FLAGS = [
    ("COL_REG_SAME", "r_same"),
    ("COL_MEM_SAME", "m_same"),
]

problems = []
checked = 0

for column, local in FLAGS:
    if column not in src:
        problems.append(
            f"{column} is gone from the AIR. If the flag was removed the entry "
            f"here should go with it, in the same commit, with the reason."
        )
        continue

    # Confirm the local name is actually bound to this column, otherwise the
    # evidence below would be about some unrelated identifier.
    bind = re.search(
        rf"let\s+{re.escape(local)}\s*:\s*AB::Expr\s*=\s*cur\[{re.escape(column)}\]", src
    )
    if not bind:
        problems.append(
            f"{column} is not read into `{local}` the way this gate expects, so "
            f"it cannot tell what is constraining it. Update the gate together "
            f"with the rename."
        )
        continue

    checked += 1

    # Evidence 1: booleanity.
    boolean = re.search(rf"assert_bool\(\s*{re.escape(local)}\b", src) is not None

    # Evidence 2: the flag costs something when it is zero. Either a constraint
    # written against the negated side, or an equality pinning it to a value
    # the prover does not choose freely.
    negated = re.search(
        rf"\(\s*one\.clone\(\)\s*-\s*{re.escape(local)}\.clone\(\)\s*\)", src
    ) is not None
    pinned = re.search(
        rf"assert_eq\(\s*{re.escape(local)}\.clone\(\)\s*,", src
    ) is not None

    if not boolean and not (negated or pinned):
        problems.append(
            f"{column} gates constraints but nothing pins it: no booleanity, no "
            f"constraint on the `1 - {local}` side, and no equality binding it. "
            f"A prover can set it to zero for free and switch off whatever it "
            f"gates."
        )
    elif not (negated or pinned):
        problems.append(
            f"{column} is boolean but costs nothing when it is zero. Booleanity "
            f"only says the flag is 0 or 1, not that 0 is a lie the prover has "
            f"to pay for. Add a constraint on the `1 - {local}` side, or pin the "
            f"flag to the condition it claims with an inverse witness."
        )
    elif not boolean:
        problems.append(
            f"{column} has a counterpart constraint but no booleanity, so it can "
            f"take a field value that is neither 0 nor 1 and satisfy both sides "
            f"at once."
        )

if checked == 0:
    print(
        "FAIL: none of the listed gating flags could be checked - the gate is "
        "vacuous",
        file=sys.stderr,
    )
    sys.exit(1)

if problems:
    print("FAIL: these gating flags are not pinned:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "\nA flag that switches a constraint off is part of the constraint. If the\n"
        "prover picks its value, the prover picks whether the rule applies.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"Gating-flag gate OK: all {checked} same-ness flags are boolean and pinned.")
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  mk() {
    local dir="$1"
    local body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src"
    printf '%s\n' "$body" > "$dir/budzero/bud-proof/src/plonky3_air.rs"
  }

  # A tree where both flags are boolean and pinned.
  local good
  good='pub const COL_REG_SAME: usize = 28;
pub const COL_MEM_SAME: usize = 54;
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        builder.assert_bool(r_same.clone());
        builder.when_transition().assert_eq(r_same.clone(), one.clone() - reg_diff_z);
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.assert_bool(m_same.clone());
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'

  # 1. A correct tree must pass, or the gate is failing for its own reasons.
  mk "$tmp/good" "$good"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a tree with both flags pinned was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 2. The shape that shipped: used as a multiplier, nothing else. No
  #    booleanity, no counterpart.
  mk "$tmp/free" 'pub const COL_REG_SAME: usize = 28;
pub const COL_MEM_SAME: usize = 54;
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        builder.when_transition().assert_zero(
            r_active.clone() * nr_active.clone() * r_same.clone() * (nr_val - r_val),
        );
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.assert_bool(m_same.clone());
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'
  if ( scan "$tmp/free" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a gating flag with no booleanity and no counterpart was accepted!" >&2
    exit 1
  fi

  # 3. Boolean but free. This is the subtle one: booleanity reads like the
  #    column is handled, and it is not.
  mk "$tmp/boolonly" 'pub const COL_REG_SAME: usize = 28;
pub const COL_MEM_SAME: usize = 54;
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        builder.assert_bool(r_same.clone());
        builder.when_transition().assert_zero(
            r_active.clone() * nr_active.clone() * r_same.clone() * (nr_val - r_val),
        );
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.assert_bool(m_same.clone());
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'
  if ( scan "$tmp/boolonly" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a boolean flag with no cost for being zero was accepted!" >&2
    exit 1
  fi

  # 4. Counterpart present but no booleanity: the flag can be a field element
  #    that is neither 0 nor 1.
  mk "$tmp/nobool" 'pub const COL_REG_SAME: usize = 28;
pub const COL_MEM_SAME: usize = 54;
        let r_same: AB::Expr = cur[COL_REG_SAME].into();
        builder.when_transition().assert_eq(r_same.clone(), one.clone() - reg_diff_z);
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'
  if ( scan "$tmp/nobool" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a flag with a counterpart but no booleanity was accepted!" >&2
    exit 1
  fi

  # 5. A deleted flag must fail rather than pass for having nothing to check.
  mk "$tmp/gone" 'pub const COL_MEM_SAME: usize = 54;
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.assert_bool(m_same.clone());
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'
  if ( scan "$tmp/gone" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing flag column was accepted!" >&2
    exit 1
  fi

  # 6. A renamed local must fail loudly rather than silently checking nothing.
  mk "$tmp/renamed" 'pub const COL_REG_SAME: usize = 28;
pub const COL_MEM_SAME: usize = 54;
        let reg_is_same: AB::Expr = cur[COL_REG_SAME].into();
        builder.assert_bool(reg_is_same.clone());
        let m_same: AB::Expr = cur[COL_MEM_SAME].into();
        builder.assert_bool(m_same.clone());
        builder.when_transition().assert_zero(
            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),
        );'
  if ( scan "$tmp/renamed" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a renamed local was accepted without checking anything!" >&2
    exit 1
  fi

  # 7. A missing AIR must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no AIR was accepted!" >&2
    exit 1
  fi

  echo "gating-flag gate self-test OK: an unconstrained flag, a boolean-but-free flag, a flag with no booleanity, a deleted column, a renamed local and a missing AIR are all rejected; a properly pinned tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
