#!/usr/bin/env bash
# ============================================================================
# check-cross-table-checks-use-last-row.sh
#
# A constraint that reads a side table must fire on the last row, not on the
# last CPU row.
#
# Why this gate exists.
#
# The AIR packs several tables into one matrix. The CPU table has one row per
# executed step. The register table has one row per register event, three per
# step. The memory table has one row per memory event. They share a row index
# and nothing keeps them the same length.
#
# "The last CPU row" is written `when(is_halt).when(cpu_active)`, and it is the
# right place for anything built out of CPU columns: gas, exit code, the final
# state root. It is the wrong place for anything built out of a side table,
# because that table may still be mid-fold when the CPU side reaches its Halt.
#
# This already happened once. The register image accumulator was checked on the
# last CPU row, and since one step contributes three register events the
# register table outruns the CPU table on every program. Four honest proofs
# stopped verifying and CI caught it as `d2_proves_nullifier_check_invalid_secret`
# plus three `proves_verify_merkle_valid_*`. The fix was `when_last_row`.
#
# The memory image accumulator had the identical shape and did not fail,
# because no opcode currently produces two memory events in one step: four
# opcodes set `memory_addr` on their step and six push an extra event from the
# stack or storage buffers, and the two sets do not intersect. So `n_mem` is at
# most `n_cpu` and the fold happens to be finished in time. That is a fact
# about today's opcode table, not something the AIR states, and the first
# opcode that pairs a memory access with a stack push breaks it silently, in a
# constraint nobody was editing.
#
# What the gate checks.
#
# For each accumulator column that belongs to a side table, the constraint
# binding it to a public input must use `when_last_row`, and must not be gated
# on `is_halt` or `cpu_active`. The columns are listed explicitly: a regex that
# tried to discover "every column not in the CPU block" would sweep in the
# selectors and the decode columns, which are CPU columns and are correctly
# checked on the last CPU row.
#
# The gate deliberately does not ban `when(is_halt)` outright. Most of its uses
# are correct and banning them would train the next reader to route around the
# gate.
#
# Usage:
#   bash scripts/check-cross-table-checks-use-last-row.sh              # gate
#   bash scripts/check-cross-table-checks-use-last-row.sh --self-test  # canary
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

# Accumulator columns that live on a side table. Each is folded across that
# table's rows, so the finished value is only guaranteed on the very last row
# of the matrix.
SIDE_TABLE_ACCUMULATORS = [
    ("COL_MEM_INIT_ACC", "the memory table"),
    ("COL_REG_INIT_ACC", "the register table"),
]

problems = []
checked = 0

for column, table in SIDE_TABLE_ACCUMULATORS:
    if column not in src:
        problems.append(
            f"{column} is gone from the AIR. If the accumulator was removed the "
            f"entry here should go with it, in the same commit, with the reason."
        )
        continue

    # Find the block that binds this accumulator to a public input. The
    # binding reads the column into a local and compares it against
    # `public_inputs[..]`, so look for the brace-delimited block containing
    # both.
    blocks = []
    for m in re.finditer(rf"\{{[^{{}}]*{re.escape(column)}[^{{}}]*\}}", src, re.DOTALL):
        body = m.group(0)
        if "public_inputs" in body:
            blocks.append((m.start(), body))

    if not blocks:
        problems.append(
            f"{column} is never compared against a public input, so the "
            f"accumulator is folded and then dropped. Either it binds "
            f"something or it should not exist."
        )
        continue

    for start, body in blocks:
        checked += 1
        line = src[:start].count("\n") + 1
        code = re.sub(r"//[^\n]*", "", body)

        if "when_last_row" not in code:
            problems.append(
                f"AIR line ~{line}: the binding for {column} does not use "
                f"`when_last_row`. {column.split('_')[1].lower()} lives on "
                f"{table}, whose length is not the CPU table's, so the fold "
                f"may still be running when the CPU side halts."
            )

        for gate in ("is_halt", "cpu_active"):
            if re.search(rf"\.when\(\s*{gate}", code):
                problems.append(
                    f"AIR line ~{line}: the binding for {column} is gated on "
                    f"`{gate}`, which names the last *CPU* row. {column} is "
                    f"folded across {table}; when that table is longer the "
                    f"accumulator is mid-fold there and honest proofs fail. "
                    f"This is what happened to the register image."
                )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(
    f"cross-table checks OK: {checked} side-table bindings, all on the last row"
)
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

  GOOD='pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'

  # 1. The corrected shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected AIR was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: the memory binding gated on the last CPU row.
  mk "$tmp/halted" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder
                .when(is_halt.clone())
                .when(cpu_active.clone())
                .assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/halted" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a side-table accumulator checked on the last CPU row was accepted!" >&2
    exit 1
  fi

  # 3. The register half regressing the same way. Both columns are covered,
  #    not just the one that happened to be wrong.
  mk "$tmp/regressed" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder
                .when(is_halt.clone())
                .assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/regressed" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: the register accumulator gated on is_halt was accepted!" >&2
    exit 1
  fi

  # 4. Belt and braces is still wrong: `when_last_row` present but the CPU
  #    gate left on top of it narrows the check to rows that are both.
  mk "$tmp/both" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let expected = public_inputs[10].into();
            builder
                .when_last_row()
                .when(cpu_active.clone())
                .assert_eq(acc_last, expected);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/both" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a last-row check narrowed by a CPU gate was accepted!" >&2
    exit 1
  fi

  # 5. An accumulator folded and never bound to anything is not a pass.
  mk "$tmp/unbound" 'pub const COL_MEM_INIT_ACC: usize = 731;
pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc: AB::Expr = cur[COL_MEM_INIT_ACC].into();
            let nacc: AB::Expr = nxt[COL_MEM_INIT_ACC].into();
            builder.when_transition().assert_eq(nacc, acc);
        }
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
  if ( scan "$tmp/unbound" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an accumulator bound to nothing was accepted!" >&2
    exit 1
  fi

  # 6. A deleted column must fail rather than pass for having nothing to check.
  mk "$tmp/gone" 'pub const COL_REG_INIT_ACC: usize = 736;
        {
            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();
            let expected = public_inputs[12].into();
            builder.when_last_row().assert_eq(acc_last, expected);
        }'
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

  echo "cross-table gate self-test OK: a memory accumulator on the last CPU row, a register accumulator on is_halt, a last-row check narrowed by a CPU gate, an unbound accumulator, a deleted column and a missing AIR are all rejected; the corrected tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
