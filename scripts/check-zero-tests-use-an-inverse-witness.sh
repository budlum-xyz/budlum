#!/usr/bin/env bash
# ============================================================================
# check-zero-tests-use-an-inverse-witness.sh
#
# An opcode whose VM rule is "is this value zero" must be constrained with an
# inverse witness, not with a direct comparison against a constant.
#
# Why this gate exists.
#
# `Assert` halts the VM only when its condition is zero, so every non-zero
# value passes. The AIR asked for `assert_one(rs1_val)`, which demands exactly
# 1. The two rules agree on `0` and `1` and disagree on everything else.
#
# Nothing caught it because every test fed the opcode a comparison result, and
# `Eq`, `Lt` and their neighbours only ever produce `0` or `1`. The rules are
# identical on that set. BudL's `constrain(...)` lowers straight to `Assert`,
# so `constrain(flags & MASK)` was a contract the VM ran and no prover could
# prove.
#
# The direction is completeness rather than soundness, which is why it lasted:
# a stricter AIR rejects correct programs instead of accepting false ones, and
# that reads as broken tooling rather than as an attack.
#
# A field element has no order and no bits, so "non-zero" is not something a
# constraint can say directly. It needs a witness:
#
#   z = v * v_inv        asserted boolean
#   v * (1 - z) == 0     a non-zero v forces z = 1
#
# after which `z` is exactly "v is non-zero" and can be used like any flag.
#
# What the gate checks.
#
# Every opcode whose VM body tests a source register against zero is listed
# below with the witness column the AIR must use for it. For each one:
#
#   * the VM must still perform that zero test, otherwise the entry is stale,
#   * the AIR must read the named witness column, and
#   * the AIR must not constrain that opcode's source register directly
#     against a constant, which is the shape the bug had.
#
# The list is explicit rather than discovered. Reading the VM to decide which
# opcodes "should" have a witness would need the gate to understand the VM,
# and a gate that guesses is a gate that gets switched off.
#
# Usage:
#   bash scripts/check-zero-tests-use-an-inverse-witness.sh              # gate
#   bash scripts/check-zero-tests-use-an-inverse-witness.sh --self-test  # canary
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
vm = os.path.join(root, "budzero", "bud-vm", "src", "lib.rs")
air = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_air.rs")

for path, what in ((vm, "VM"), (air, "AIR")):
    if not os.path.isfile(path):
        print(f"FAIL: no {what} at {path}", file=sys.stderr)
        sys.exit(2)

vm_src = open(vm, encoding="utf-8").read()
air_src = open(air, encoding="utf-8").read()
air_code = re.sub(r"//[^\n]*", "", air_src)

# (opcode, the register its VM rule tests, the witness column the AIR must use)
ZERO_TESTS = [
    ("Assert", "src1_val", "COL_ASSERT_INV"),
    ("Div", "src2_val", "COL_DIV_INV"),
    ("Inv", "src1_val", "COL_INV_ZERO"),
    ("Jnz", "src1_val", "COL_JNZ_COND_INV"),
    ("Not", "src1_val", "COL_INV_ZERO"),
]


def vm_body(name):
    m = re.search(rf"Opcode::{name} => \{{", vm_src)
    if not m:
        return None
    start, depth, i = m.end(), 1, m.end()
    while i < len(vm_src) and depth:
        if vm_src[i] == "{":
            depth += 1
        elif vm_src[i] == "}":
            depth -= 1
        i += 1
    return vm_src[start:i]


problems = []
checked = 0

for opcode, reg, witness in ZERO_TESTS:
    body = vm_body(opcode)
    if body is None:
        problems.append(
            f"the VM has no `Opcode::{opcode}` arm this gate can read. If the "
            f"opcode was removed the entry here should go with it, in the same "
            f"commit."
        )
        continue

    checked += 1

    if not re.search(rf"{re.escape(reg)}\s*(==|!=)\s*0", re.sub(r"//[^\n]*", "", body)):
        problems.append(
            f"the VM's `{opcode}` no longer tests `{reg}` against zero, so this "
            f"entry describes a rule that is gone. Update the gate together "
            f"with the semantics."
        )
        continue

    checked += 1

    if witness not in air_src:
        problems.append(
            f"`{opcode}` tests `{reg}` against zero in the VM and the AIR has no "
            f"`{witness}`. A field element has no order, so non-zero cannot be "
            f"stated directly; without a witness the AIR is enforcing some "
            f"other rule, and the two only have to agree on the values the "
            f"tests happen to use."
        )
        continue

    checked += 1

    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", opcode).lower()
    # The VM calls it `src1_val` and the AIR calls it `rs1_val`. Measured
    # while writing this gate: matching the VM's spelling against the AIR
    # found nothing and the gate passed a tree with the bug still in it, so
    # the translation is not optional.
    air_reg = reg.replace("src", "rs")
    # The bug's exact shape: the opcode's own register compared straight to a
    # constant instead of going through the witness.
    direct = re.search(
        rf"\.when\(is_{snake}[^)]*\)\s*\.assert_one\(\s*{re.escape(air_reg)}",
        air_code,
    )
    if direct:
        problems.append(
            f"`{opcode}` constrains `{reg}` directly with `assert_one`, which "
            f"demands exactly 1 where the VM only refuses zero. Those agree on "
            f"0 and 1 and nowhere else, and comparison results are 0 or 1, so "
            f"tests will not show the difference. Route it through "
            f"`{witness}`."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"zero-test gate OK: {checked} checks, every zero test goes through a witness")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" vm_body="$2" air_body="$3"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-vm/src" "$dir/budzero/bud-proof/src"
    printf '%s\n' "$vm_body" >"$dir/budzero/bud-vm/src/lib.rs"
    printf '%s\n' "$air_body" >"$dir/budzero/bud-proof/src/plonky3_air.rs"
  }

  GOOD_VM='            Opcode::Assert => {
                if src1_val == 0 { return Err(VmError::AssertionFailed); }
            }
            Opcode::Div => {
                let result = if src2_val != 0 { 1 } else { 0 };
            }
            Opcode::Inv => {
                let result = if src1_val != 0 { 1 } else { 0 };
            }
            Opcode::Jnz => {
                let taken = src1_val != 0;
            }
            Opcode::Not => {
                let result = if src1_val == 0 { 1 } else { 0 };
            }'
  GOOD_AIR='pub const COL_ASSERT_INV: usize = 740;
pub const COL_DIV_INV: usize = 58;
pub const COL_INV_ZERO: usize = 60;
pub const COL_JNZ_COND_INV: usize = 62;
        let assert_inv: AB::Expr = cur[COL_ASSERT_INV].into();
        let assert_z = rs1_val.clone() * assert_inv;
        builder.when(is_assert.clone()).assert_bool(assert_z.clone());
        builder.when(is_assert).assert_one(assert_z);'

  # 1. The corrected shape must pass, otherwise the gate is unusable.
  mk "$tmp/good" "$GOOD_VM" "$GOOD_AIR"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: the register compared straight to one.
  mk "$tmp/direct" "$GOOD_VM" 'pub const COL_ASSERT_INV: usize = 740;
pub const COL_DIV_INV: usize = 58;
pub const COL_INV_ZERO: usize = 60;
pub const COL_JNZ_COND_INV: usize = 62;
        builder.when(is_assert).assert_one(rs1_val.clone());'
  if ( scan "$tmp/direct" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a direct assert_one on the register was accepted!" >&2
    exit 1
  fi

  # 3. The witness column removed entirely.
  mk "$tmp/nowitness" "$GOOD_VM" 'pub const COL_DIV_INV: usize = 58;
pub const COL_INV_ZERO: usize = 60;
pub const COL_JNZ_COND_INV: usize = 62;
        let assert_z = rs1_val.clone();
        builder.when(is_assert).assert_one(assert_z);'
  if ( scan "$tmp/nowitness" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing witness column was accepted!" >&2
    exit 1
  fi

  # 4. A different opcode's witness going missing. All five are covered, not
  #    just the one that happened to be wrong.
  mk "$tmp/jnzgone" "$GOOD_VM" 'pub const COL_ASSERT_INV: usize = 740;
pub const COL_DIV_INV: usize = 58;
pub const COL_INV_ZERO: usize = 60;
        let assert_inv: AB::Expr = cur[COL_ASSERT_INV].into();
        let assert_z = rs1_val.clone() * assert_inv;
        builder.when(is_assert).assert_one(assert_z);'
  if ( scan "$tmp/jnzgone" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing Jnz witness was accepted!" >&2
    exit 1
  fi

  # 5. The VM losing the zero test makes the entry stale, and a stale entry
  #    must be loud rather than quietly passing.
  mk "$tmp/stale" '            Opcode::Assert => {
                let _ = src1_val;
            }
            Opcode::Div => {
                let result = if src2_val != 0 { 1 } else { 0 };
            }
            Opcode::Inv => {
                let result = if src1_val != 0 { 1 } else { 0 };
            }
            Opcode::Jnz => {
                let taken = src1_val != 0;
            }
            Opcode::Not => {
                let result = if src1_val == 0 { 1 } else { 0 };
            }' "$GOOD_AIR"
  if ( scan "$tmp/stale" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a stale entry was accepted!" >&2
    exit 1
  fi

  # 6. A comment describing the zero test is not the zero test.
  mk "$tmp/comment" '            Opcode::Assert => {
                // if src1_val == 0 { return Err(VmError::AssertionFailed); }
                let _ = src1_val;
            }
            Opcode::Div => {
                let result = if src2_val != 0 { 1 } else { 0 };
            }
            Opcode::Inv => {
                let result = if src1_val != 0 { 1 } else { 0 };
            }
            Opcode::Jnz => {
                let taken = src1_val != 0;
            }
            Opcode::Not => {
                let result = if src1_val == 0 { 1 } else { 0 };
            }' "$GOOD_AIR"
  if ( scan "$tmp/comment" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a commented-out zero test was accepted!" >&2
    exit 1
  fi

  # 7. A missing tree must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no sources was accepted!" >&2
    exit 1
  fi

  echo "zero-test gate self-test OK: a direct assert_one, a missing witness, a missing witness for another opcode, a stale entry, a commented-out zero test and a missing tree are all rejected; the witnessed tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
