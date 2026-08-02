#!/usr/bin/env bash
# ============================================================================
# check-logup-multipliers-are-boolean.sh
#
# A LogUp activity flag must be boolean. An index column is not a flag.
#
# Why this gate exists.
#
# The memory argument decides, per CPU row, whether that row demands a memory
# entry. `Load rd, r0, imm` is the machine's load-immediate and touches no
# memory; every other `Load` and every `Store` reads or writes the word at
# `rs1_val + imm`. The AIR separated the two with
#
#   is_real_mem_op = (is_load + is_store) * rs1_idx
#
# and `rs1_idx` is a register number, not a flag. On `Store r0, r7, r2` the
# demand side is scaled by seven while the memory table supplies the row once.
# The prover mirrored the same line as an honest boolean, so the two sides
# disagreed for every base register except `r1`.
#
# Both halves are broken and they fail in opposite directions. Completeness:
# any correct program whose pointer lives outside `r1` has no valid proof at
# all, and every test in the tree happened to pick `r1`, which is why nothing
# caught it. Soundness: the multiplier is a prover-supplied field element that
# multiplies into a running sum, so what the argument enforces depends on a
# value the prover chose, and "it currently comes out unsatisfiable" is not a
# constraint.
#
# What the gate checks.
#
# In the LogUp section of the AIR, no `is_*` activity term may be formed by
# multiplying with a raw index column. Index columns are named below: they end
# in `_IDX` and hold register numbers, not flags. A boolean derived from one
# through an inverse witness (`rs1_idx * rs1_idx_inv`) is exactly the right
# construction and is what the fix uses, so the gate looks for the raw column
# name rather than banning the concept.
#
# The prover mirror is checked too. A correct AIR paired with a prover that
# builds the same flag from a Rust comparison is the shape that hid this for
# as long as it did: both sides looked reasonable in isolation and only the
# product disagreed. The mirror has to read the same witness column.
#
# Usage:
#   bash scripts/check-logup-multipliers-are-boolean.sh              # gate
#   bash scripts/check-logup-multipliers-are-boolean.sh --self-test  # canary
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
prover = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_prover.rs")

for path, what in ((air, "AIR"), (prover, "prover")):
    if not os.path.isfile(path):
        print(f"FAIL: no {what} at {path}", file=sys.stderr)
        sys.exit(2)

air_src = open(air, encoding="utf-8").read()
prover_src = open(prover, encoding="utf-8").read()

# Columns that hold a register number. Multiplying an activity term by one of
# these scales the LogUp demand side by the register index.
INDEX_LOCALS = ["rs1_idx", "rs2_idx", "rd_idx", "reg_idx"]

# The activity terms the memory and register arguments are built from. Each
# entry is (local name, the file it must be boolean in).
ACTIVITY_TERMS = [
    "is_real_mem_op",
    "is_stack_op",
    "is_storage_op",
    "is_any_mem_op",
]

problems = []
checked = 0

for term in ACTIVITY_TERMS:
    for src, what in ((air_src, "AIR"), (prover_src, "prover")):
        # Find the definition, allowing the expression to run over lines.
        m = re.search(
            rf"let\s+{re.escape(term)}\s*(?::[^=]+)?=\s*(.*?);",
            src,
            re.DOTALL,
        )
        if not m:
            problems.append(
                f"{what}: `{term}` is gone or spelled differently, so this gate "
                f"cannot tell what the memory argument multiplies by. Update the "
                f"gate in the same commit as the rename."
            )
            continue

        checked += 1
        body = m.group(1)
        # Strip comments; a comment naming a column is not a multiplication.
        body = re.sub(r"//[^\n]*", "", body)

        for idx in INDEX_LOCALS:
            # `rs1_idx_z` and `rs1_idx_inv` are the safe derivations, so match
            # the bare local only.
            if re.search(rf"\b{re.escape(idx)}\b(?!_)", body):
                problems.append(
                    f"{what}: `{term}` is built by multiplying with `{idx}`, "
                    f"which holds a register number rather than a flag. The "
                    f"LogUp demand side is then scaled by the register index "
                    f"while the table supplies the row once, so honest programs "
                    f"using any register but r1 have no valid proof. Derive a "
                    f"boolean through an inverse witness instead: "
                    f"`{idx} * {idx}_inv`, asserted boolean, with "
                    f"`{idx} * (1 - z) == 0`."
                )

# The boolean derived from an index must actually be pinned, otherwise the
# witness is free and the flag can be switched off on a row that does address
# memory.
for idx in INDEX_LOCALS:
    inv = f"{idx}_inv"
    if inv not in air_src:
        continue
    z = re.search(rf"let\s+{re.escape(idx)}_z\s*(?::[^=]+)?=\s*[^;]*{re.escape(inv)}", air_src)
    if not z:
        problems.append(
            f"AIR: `{inv}` exists but no `{idx}_z` is derived from it, so the "
            f"witness is carried and never used."
        )
        continue
    checked += 1
    if not re.search(rf"assert_bool\(\s*{re.escape(idx)}_z", air_src):
        problems.append(
            f"AIR: `{idx}_z` is not asserted boolean, so the inverse witness "
            f"can take a value that is neither 0 nor 1."
        )
    # The other half: a non-zero index must force z = 1, otherwise a prover
    # writes zero for the inverse and switches the row off the bus.
    if not re.search(
        rf"assert_zero\(\s*{re.escape(idx)}\.clone\(\)\s*\*\s*\(\s*one\.clone\(\)\s*-\s*{re.escape(idx)}_z",
        air_src,
    ):
        problems.append(
            f"AIR: nothing forces `{idx}_z = 1` when `{idx}` is non-zero, so a "
            f"prover can write zero for `{inv}` and take a row that does "
            f"address memory off the demand side of the argument."
        )

    # The prover has to read the same column, not recompute the decision.
    col = f"COL_{idx.upper()}_INV"
    if col in air_src and col not in prover_src:
        problems.append(
            f"prover: `{col}` is declared in the AIR but the prover never reads "
            f"it, so the two sides are deciding the same flag independently. "
            f"That is the shape the original bug hid in."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"logup multipliers OK: {checked} checks, no activity flag scaled by a register index")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" air_body="$2" prover_body="$3"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src"
    printf '%s\n' "$air_body" >"$dir/budzero/bud-proof/src/plonky3_air.rs"
    printf '%s\n' "$prover_body" >"$dir/budzero/bud-proof/src/plonky3_prover.rs"
  }

  GOOD_AIR='pub const COL_RS1_IDX_INV: usize = 737;
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
        builder.assert_bool(rs1_idx_z.clone());
        builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z.clone()));
        let is_real_mem_op = (is_load.clone() + is_store.clone()) * rs1_idx_z;
        let is_stack_op = is_push.clone() + is_pop.clone();
        let is_storage_op = is_sread.clone() + is_swrite.clone();
        let is_any_mem_op = is_real_mem_op.clone() + is_stack_op.clone() + is_storage_op.clone();'
  GOOD_PROVER='            let rs1_idx_z = rs1_idx * row[COL_RS1_IDX_INV];
            let is_real_mem_op = (is_load + is_store) * rs1_idx_z;
            let is_stack_op = is_push + is_pop;
            let is_storage_op = is_sread + is_swrite;
            let is_any_mem_op = is_real_mem_op + is_stack_op + is_storage_op;'

  # 1. The fixed shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD_AIR" "$GOOD_PROVER"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected AIR and prover were rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: the AIR multiplies by the raw register index.
  mk "$tmp/rawindex" 'pub const COL_RS1_IDX_INV: usize = 737;
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
        builder.assert_bool(rs1_idx_z.clone());
        builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z.clone()));
        let is_real_mem_op = (is_load.clone() + is_store.clone()) * rs1_idx.clone();
        let is_stack_op = is_push.clone() + is_pop.clone();
        let is_storage_op = is_sread.clone() + is_swrite.clone();
        let is_any_mem_op = is_real_mem_op.clone() + is_stack_op.clone() + is_storage_op.clone();' "$GOOD_PROVER"
  if ( scan "$tmp/rawindex" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an activity flag scaled by a raw register index was accepted!" >&2
    exit 1
  fi

  # 3. The prover mirror doing it instead. Half a fix is the harder bug.
  mk "$tmp/proverraw" "$GOOD_AIR" '            let is_real_mem_op = (is_load + is_store) * rs1_idx;
            let is_stack_op = is_push + is_pop;
            let is_storage_op = is_sread + is_swrite;
            let is_any_mem_op = is_real_mem_op + is_stack_op + is_storage_op;'
  if ( scan "$tmp/proverraw" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a prover mirror scaled by a register index was accepted!" >&2
    exit 1
  fi

  # 4. Booleanity missing: the inverse witness can be any field element.
  mk "$tmp/nobool" 'pub const COL_RS1_IDX_INV: usize = 737;
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
        builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z.clone()));
        let is_real_mem_op = (is_load.clone() + is_store.clone()) * rs1_idx_z;
        let is_stack_op = is_push.clone() + is_pop.clone();
        let is_storage_op = is_sread.clone() + is_swrite.clone();
        let is_any_mem_op = is_real_mem_op.clone() + is_stack_op.clone() + is_storage_op.clone();' "$GOOD_PROVER"
  if ( scan "$tmp/nobool" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unpinned inverse witness was accepted!" >&2
    exit 1
  fi

  # 5. The costly half missing: a prover writes zero for the inverse and takes
  #    a row that does address memory off the bus.
  mk "$tmp/nocost" 'pub const COL_RS1_IDX_INV: usize = 737;
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
        builder.assert_bool(rs1_idx_z.clone());
        let is_real_mem_op = (is_load.clone() + is_store.clone()) * rs1_idx_z;
        let is_stack_op = is_push.clone() + is_pop.clone();
        let is_storage_op = is_sread.clone() + is_swrite.clone();
        let is_any_mem_op = is_real_mem_op.clone() + is_stack_op.clone() + is_storage_op.clone();' "$GOOD_PROVER"
  if ( scan "$tmp/nocost" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a free inverse witness with no cost for lying was accepted!" >&2
    exit 1
  fi

  # 6. The prover ignoring the column the AIR reads. Two independent decisions
  #    about one flag is exactly how the original divergence survived.
  mk "$tmp/nomirror" "$GOOD_AIR" '            let is_real_mem_op = (is_load + is_store)
                * if rs1_index != Goldilocks::ZERO { Goldilocks::ONE } else { Goldilocks::ZERO };
            let is_stack_op = is_push + is_pop;
            let is_storage_op = is_sread + is_swrite;
            let is_any_mem_op = is_real_mem_op + is_stack_op + is_storage_op;'
  if ( scan "$tmp/nomirror" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a prover that recomputes the flag instead of reading the witness was accepted!" >&2
    exit 1
  fi

  # 7. A renamed activity term must fail loudly rather than check nothing.
  mk "$tmp/renamed" 'pub const COL_RS1_IDX_INV: usize = 737;
        let rs1_idx: AB::Expr = cur[COL_RS1_IDX].into();
        let rs1_idx_inv: AB::Expr = cur[COL_RS1_IDX_INV].into();
        let rs1_idx_z = rs1_idx.clone() * rs1_idx_inv;
        builder.assert_bool(rs1_idx_z.clone());
        builder.assert_zero(rs1_idx.clone() * (one.clone() - rs1_idx_z.clone()));
        let is_memory_op = (is_load.clone() + is_store.clone()) * rs1_idx.clone();' "$GOOD_PROVER"
  if ( scan "$tmp/renamed" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a renamed activity term was accepted without checking anything!" >&2
    exit 1
  fi

  # 8. A missing AIR must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no AIR was accepted!" >&2
    exit 1
  fi

  echo "logup multiplier gate self-test OK: a raw index in the AIR, a raw index in the prover, a missing booleanity, a free witness, an unmirrored flag, a renamed term and a missing AIR are all rejected; the corrected tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
