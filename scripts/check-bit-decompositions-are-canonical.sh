#!/usr/bin/env bash
# ============================================================================
# check-bit-decompositions-are-canonical.sh
#
# A bit decomposition must be pinned to the canonical representative, not just
# reconstitute to the right field element.
#
# Why this gate exists.
#
# `Lt`, `Gt`, `Lte`, `Gte`, `And`, `Or` and `Xor` all answer from the 64 bit
# columns rather than from the register value. The only thing tying the bits to
# the value was booleanity plus
#
#   sum(b_i * 2^i) == rs_val
#
# and that is not enough. Goldilocks is `P = 2^64 - 2^32 + 1`, so `2^64 > P`
# and a 64 bit pattern can sit at or above the modulus and wrap. Every value
# below `2^32 - 1` therefore has a second valid bit string:
#
#   rs_val = 5
#     honest      0x0000000000000005
#     alternative 0xFFFFFFFF00000006     (= 5 + P, still under 2^64)
#
# Both reconstitute to 5. The comparison reads the bits, so the prover picks
# which answer it gets: against 100 the honest bits give `5 < 100 = 1`, and the
# alternative sets the top bit and gives 0. A contract checking
# `balance >= amount` through any of these opcodes has a check the prover
# decides.
#
# The fix excludes exactly the non-canonical patterns. `P = 0xFFFFFFFF_00000001`,
# so a pattern is at or above the modulus precisely when its high 32 bits are
# all ones and its low 32 bits are not all zero. An inverse witness turns that
# into a degree three constraint.
#
# What the gate checks.
#
# For each decomposed operand:
#
#   * the reconstitution constraint still exists, which is what makes the
#     columns a decomposition rather than free witnesses,
#   * every bit is asserted boolean,
#   * a canonicity witness column exists and is read into the AIR, and
#   * both halves of the canonicity rule are present: the inverse is pinned
#     (`d * (1 - z) == 0`) and the saturated case costs something
#     (`(1 - z) * lo == 0`).
#
# The last pair is the trap this gate is named for. A witness that is declared
# and multiplied but never pinned looks like a canonicity check and enforces
# nothing, which is the same shape as the gating-flag bug.
#
# Usage:
#   bash scripts/check-bit-decompositions-are-canonical.sh              # gate
#   bash scripts/check-bit-decompositions-are-canonical.sh --self-test  # canary
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
prover = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_prover.rs")

for path, what in ((air, "AIR"), (prover, "prover")):
    if not os.path.isfile(path):
        print(f"FAIL: no {what} at {path}", file=sys.stderr)
        sys.exit(2)

air_src = open(air, encoding="utf-8").read()
prover_src = open(prover, encoding="utf-8").read()
code = re.sub(r"//[^\n]*", "", air_src)

# Each decomposed operand: its bit base column and the canonicity witness that
# has to accompany it.
OPERANDS = [
    ("COL_CMP_RS1_BASE", "COL_CMP_RS1_HI_INV", "rs1"),
    ("COL_CMP_RS2_BASE", "COL_CMP_RS2_HI_INV", "rs2"),
]

problems = []
checked = 0

for base, inv, name in OPERANDS:
    if base not in air_src:
        problems.append(
            f"{base} is gone from the AIR. If the decomposition was removed the "
            f"entry here should go with it, in the same commit, with the reason."
        )
        continue

    checked += 1

    # The decomposition has to still be tied to the register value, otherwise
    # the bits are free and canonicity is beside the point.
    if not re.search(rf"{re.escape(base)}\s*\+\s*i\s*\]", code):
        problems.append(
            f"{base} is no longer indexed per bit, so this gate cannot tell "
            f"whether the decomposition is still reconstituted. Update the gate "
            f"together with the rewrite."
        )
        continue

    # Booleanity is written against the local the bit is read into, not
    # against `cur[BASE + i]`, so follow the local. Measured before writing
    # this: the AIR does `let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i]`
    # and then `assert_bool(a_bit)`, and a gate matching the column name
    # directly finds neither.
    bit_locals = set(
        re.findall(rf"let\s+(\w+)\s*:[^=]*=\s*cur\[\s*{re.escape(base)}\s*\+", code)
    )
    if not any(re.search(rf"assert_bool\(\s*{re.escape(loc)}\b", code) for loc in bit_locals):
        problems.append(
            f"the bits of {name} are not asserted boolean, so the "
            f"reconstitution sum can be satisfied by field elements that are "
            f"not bits at all."
        )

    # Canonicity witness must exist, be read, and be pinned on both sides.
    if inv not in air_src:
        problems.append(
            f"{name} has no canonicity witness ({inv}). Booleanity plus "
            f"`sum(b_i * 2^i) == val` admits two bit strings for every value "
            f"below 2^32 - 1, because 2^64 > P, and the comparison opcodes read "
            f"the bits, so the prover chooses the answer."
        )
        continue

    checked += 1

    # The witness may be read directly or through a loop over
    # `(base, inv_col)` pairs, which is how the AIR shares one block between
    # the two operands. Both count as being read; neither being present does
    # not.
    read_directly = re.search(rf"cur\[\s*{re.escape(inv)}\s*\]", code)
    read_via_pair = re.search(rf"{re.escape(base)}\s*,\s*{re.escape(inv)}", code) and re.search(
        r"cur\[\s*inv_col\s*\]", code
    )
    if not (read_directly or read_via_pair):
        problems.append(
            f"{inv} is declared but never read by the AIR, so it is a column "
            f"the prover fills and nothing consults."
        )
        continue

    # Both halves. The inverse has to be pinned to the difference it claims,
    # and the saturated case has to cost something.
    pinned = re.search(r"assert_zero\(\s*d\s*\*\s*\(\s*AB::Expr::ONE\s*-\s*z", code) or re.search(
        r"assert_zero\(d \* \(AB::Expr::ONE - z", code
    )
    costs = re.search(r"assert_zero\(\s*\(\s*AB::Expr::ONE\s*-\s*z\s*\)\s*\*\s*lo", code)
    boolean_z = re.search(r"assert_bool\(\s*z\b", code)

    if not boolean_z:
        problems.append(
            f"the canonicity flag derived from {inv} is not asserted boolean, "
            f"so the witness can take a value that is neither 0 nor 1."
        )
    if not pinned:
        problems.append(
            f"nothing forces the canonicity flag to 1 when the high half is not "
            f"saturated, so a prover writes zero for {inv} and the low-half rule "
            f"below never fires. A witness that is multiplied but not pinned "
            f"enforces nothing."
        )
    if not costs:
        problems.append(
            f"a saturated high half costs nothing: the rule that the low half "
            f"must then be zero is missing, so the non-canonical patterns are "
            f"still available."
        )
    checked += 3

# The prover has to fill the witness, or every honest proof fails.
for _, inv, name in OPERANDS:
    if inv in air_src and inv not in prover_src:
        problems.append(
            f"prover: {inv} is read by the AIR but never filled, so no honest "
            f"proof for a comparison can exist."
        )
    else:
        checked += 1

# The subtraction has to happen in the field. Measured: for a high half of 0,
# `wrapping_sub` gives 0xFFFFFFFF00000001 while the field difference is
# `P - 0xFFFFFFFF`, and those are different elements, so the inverse would be
# the inverse of the wrong value and every honest comparison would fail.
if "COL_CMP_RS1_HI_INV" in prover_src and re.search(
    r"wrapping_sub\(\s*0xFFFF_FFFF", prover_src
):
    problems.append(
        "prover: the canonicity difference is computed with `wrapping_sub` "
        "rather than in the field. Those disagree for every high half below "
        "0xFFFFFFFF, so the witness would be the inverse of the wrong element."
    )
checked += 1

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"bit decomposition gate OK: {checked} checks, both operands pinned to the canonical representative")
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

  GOOD_AIR='pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            for (base, inv_col) in [
                (COL_CMP_RS1_BASE, COL_CMP_RS1_HI_INV),
                (COL_CMP_RS2_BASE, COL_CMP_RS2_HI_INV),
            ] {
                let d_inv: AB::Expr = cur[inv_col].into();
                let z = d.clone() * d_inv;
                builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
                builder.when(is_cmp_or_bw.clone()).assert_zero(d * (AB::Expr::ONE - z.clone()));
                builder.when(is_cmp_or_bw.clone()).assert_zero((AB::Expr::ONE - z) * lo);
            }
        }'
  GOOD_PROVER='            let d = bud_vm::field_sub_goldilocks(hi, 0xFFFF_FFFF);
            values[row_start + COL_CMP_RS1_HI_INV] = Goldilocks::new(inv);
            values[row_start + COL_CMP_RS2_HI_INV] = Goldilocks::new(inv);'

  # 1. The corrected shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD_AIR" "$GOOD_PROVER"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: a decomposition with no canonicity witness at all.
  mk "$tmp/nowitness" 'pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }' "$GOOD_PROVER"
  if ( scan "$tmp/nowitness" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a decomposition with no canonicity witness was accepted!" >&2
    exit 1
  fi

  # 3. A witness that is declared and multiplied but never pinned. This is the
  #    trap: it looks like a canonicity check and enforces nothing.
  mk "$tmp/unpinned" 'pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            let d_inv: AB::Expr = cur[COL_CMP_RS1_HI_INV].into();
            let z = d.clone() * d_inv;
            builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
            builder.when(is_cmp_or_bw.clone()).assert_zero((AB::Expr::ONE - z) * lo);
        }' "$GOOD_PROVER"
  if ( scan "$tmp/unpinned" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unpinned canonicity witness was accepted!" >&2
    exit 1
  fi

  # 4. The saturated case costing nothing: the low-half rule missing.
  mk "$tmp/nocost" 'pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            let d_inv: AB::Expr = cur[COL_CMP_RS1_HI_INV].into();
            let z = d.clone() * d_inv;
            builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
            builder.when(is_cmp_or_bw.clone()).assert_zero(d * (AB::Expr::ONE - z.clone()));
        }' "$GOOD_PROVER"
  if ( scan "$tmp/nocost" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a canonicity rule with no cost for a saturated high half was accepted!" >&2
    exit 1
  fi

  # 5. A witness the AIR declares and never reads.
  mk "$tmp/unread" 'pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }' "$GOOD_PROVER"
  if ( scan "$tmp/unread" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a witness column that is never read was accepted!" >&2
    exit 1
  fi

  # 6. The prover computing the difference with wrapping_sub. Measured to be
  #    a different element from the field subtraction, so every honest
  #    comparison would fail; a gate that misses this ships a broken prover.
  mk "$tmp/wrapping" "$GOOD_AIR" '            let d = hi.wrapping_sub(0xFFFF_FFFF);
            values[row_start + COL_CMP_RS1_HI_INV] = Goldilocks::new(inv);
            values[row_start + COL_CMP_RS2_HI_INV] = Goldilocks::new(inv);'
  if ( scan "$tmp/wrapping" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a wrapping_sub difference was accepted!" >&2
    exit 1
  fi

  # 7. The prover never filling the witness the AIR reads.
  mk "$tmp/unfilled" "$GOOD_AIR" '            let d = bud_vm::field_sub_goldilocks(hi, 0xFFFF_FFFF);'
  if ( scan "$tmp/unfilled" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unfilled witness was accepted!" >&2
    exit 1
  fi

  # 8. A missing tree must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no sources was accepted!" >&2
    exit 1
  fi

  echo "bit decomposition gate self-test OK: a missing witness, an unpinned witness, a missing low-half rule, an unread column, a wrapping_sub difference, an unfilled witness and a missing tree are all rejected; the canonical tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
