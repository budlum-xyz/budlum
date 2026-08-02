#!/usr/bin/env bash
# ============================================================================
# check-air-selectors-are-opcode-bound.sh
#
# Every `COL_IS_<OP>` selector in the AIR must appear in the selector to opcode
# binding sum, and every opcode in the ISA must have a selector.
#
# Why this gate exists.
#
# Per opcode rules in the AIR are all written as
# `builder.when(is_<op>).assert_...`, so a rule is only evaluated on rows where
# its selector is set. Two constraints governed the selectors: booleanity, and
# an exclusivity sum forcing exactly one of them to be 1 on every CPU row.
# Neither says *which* selector has to be the one that is set.
#
# Six selectors had a hand written binding to their opcode, each added when the
# opcode it guards was audited. The other twenty nine had none. That let a
# prover take an honest `Assert` row, clear `is_assert`, set `is_mul`, and have
# the row check `rd == rs1 * rs2` instead of `rs1 == 1`. On an Assert row
# rd and rs2 are both zero, so the multiplication identity reads `0 == x * 0`
# and holds for any value. The assertion was never evaluated, gas was identical,
# exclusivity still summed to one, and no LogUp argument looked at which
# selector it had been.
#
# The AIR now binds all thirty five in one sum. This gate is what keeps the
# thirty sixth from being added unbound: the exclusivity constraint will happily
# accept a new selector that no term of the sum mentions, so nothing in the
# build would fail, and the new opcode would be forgeable from the day it
# lands.
#
# The gate also checks the reverse direction. An ISA opcode with no selector at
# all is not covered by the exclusivity sum either, so a row carrying it could
# only be represented by lying about the selector, and the binding would then
# be unsatisfiable rather than absent. Either way it is a hole, so both
# directions fail.
#
# Usage:
#   bash scripts/check-air-selectors-are-opcode-bound.sh              # gate
#   bash scripts/check-air-selectors-are-opcode-bound.sh --self-test  # canary
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
isa = os.path.join(root, "budzero", "bud-isa", "src", "lib.rs")

if not os.path.isfile(air):
    print(f"FAIL: no AIR at {air}", file=sys.stderr)
    sys.exit(2)
if not os.path.isfile(isa):
    print(f"FAIL: no ISA at {isa}", file=sys.stderr)
    sys.exit(2)

air_src = open(air, encoding="utf-8").read()
isa_src = open(isa, encoding="utf-8").read()

# The ISA is the source of truth for which opcodes exist and what they encode
# to. Read the discriminants off the enum rather than a hand kept list here,
# so adding an opcode cannot silently leave this gate behind.
opcodes = {}
for name, value in re.findall(r"^\s{4}(\w+)\s*=\s*(0x[0-9A-Fa-f]+)\s*,", isa_src, re.M):
    opcodes[name] = int(value, 16)

if not opcodes:
    print("FAIL: no opcodes parsed out of the ISA - the gate would be vacuous",
          file=sys.stderr)
    sys.exit(1)

# Selector columns declared in the AIR.
selectors = dict(
    (name, int(idx))
    for name, idx in re.findall(r"pub const COL_IS_(\w+): usize = (\d+)", air_src)
)

if not selectors:
    print("FAIL: no COL_IS_* selectors found in the AIR - the gate would be vacuous",
          file=sys.stderr)
    sys.exit(1)

# The binding sum. Each term is `is_<op>.clone() * (opcode_here.clone() - op(0xNN))`.
bound = {}
for sel, value in re.findall(
    r"is_(\w+)\.clone\(\)\s*\*\s*\(opcode_here\.clone\(\)\s*-\s*op\((0x[0-9A-Fa-f]+)\)\)",
    air_src,
):
    bound[sel.upper()] = int(value, 16)

if not bound:
    print("FAIL: the selector to opcode binding sum was not found in the AIR.\n"
          "      Either it was removed, or it was rewritten in a shape this gate\n"
          "      cannot read. Both need looking at: with no binding, any row can\n"
          "      be relabelled as any other opcode.",
          file=sys.stderr)
    sys.exit(1)

problems = []

# Direction 1: every selector must be bound, and bound to the right value.
#
# `COL_IS_<X>` maps to the ISA name by removing underscores and comparing case
# insensitively, which is how the tree already spells them: SUM_CONSERVATION is
# SumConservation, VERIFY_MERKLE is VerifyMerkle.
def isa_name_for(selector_name):
    flat = selector_name.replace("_", "").lower()
    for name in opcodes:
        if name.lower() == flat:
            return name
    return None

for sel in sorted(selectors):
    isa_name = isa_name_for(sel)
    if isa_name is None:
        problems.append(
            f"selector COL_IS_{sel} matches no opcode in the ISA - either the "
            f"opcode was removed and the column is dead, or it is misspelled"
        )
        continue
    if sel not in bound:
        problems.append(
            f"selector COL_IS_{sel} (opcode {isa_name} = "
            f"0x{opcodes[isa_name]:02X}) is not in the binding sum - a row "
            f"carrying any other opcode could set it"
        )
        continue
    if bound[sel] != opcodes[isa_name]:
        problems.append(
            f"selector COL_IS_{sel} is bound to 0x{bound[sel]:02X} but "
            f"{isa_name} encodes to 0x{opcodes[isa_name]:02X}"
        )

# Direction 2: every opcode must have a selector.
selector_isa_names = set(
    n for n in (isa_name_for(s) for s in selectors) if n is not None
)
for name in sorted(opcodes):
    if name not in selector_isa_names:
        problems.append(
            f"opcode {name} = 0x{opcodes[name]:02X} has no COL_IS_* selector - "
            f"a row carrying it is outside the exclusivity sum"
        )

if problems:
    print("FAIL: the AIR's selector to opcode binding is incomplete:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "\nEvery per opcode rule runs under `builder.when(is_<op>)`. A selector "
        "that\nnothing pins to an opcode lets a prover choose which rules apply "
        "to a row.",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"AIR selector binding OK: all {len(selectors)} selectors are bound to "
    f"their opcode, and all {len(opcodes)} opcodes have a selector."
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  mk() {
    local dir="$1"
    local air_body="$2"
    local isa_body="$3"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src" "$dir/budzero/bud-isa/src"
    printf '%s\n' "$air_body" > "$dir/budzero/bud-proof/src/plonky3_air.rs"
    printf '%s\n' "$isa_body" > "$dir/budzero/bud-isa/src/lib.rs"
  }

  local good_isa
  good_isa='pub enum Opcode {
    Halt = 0x00,
    Add = 0x01,
    Mul = 0x03,
}'

  local good_air
  good_air='pub const COL_IS_HALT: usize = 19;
pub const COL_IS_ADD: usize = 11;
pub const COL_IS_MUL: usize = 13;
        let selector_opcode_binding = is_halt.clone() * (opcode_here.clone() - op(0x00))
            + is_add.clone() * (opcode_here.clone() - op(0x01))
            + is_mul.clone() * (opcode_here.clone() - op(0x03));'

  # 1. A fully bound tree passes. Without this the gate could be failing for
  #    reasons that have nothing to do with what it claims to check.
  mk "$tmp/good" "$good_air" "$good_isa"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a correctly bound AIR was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 2. The shape that shipped: a selector with no term in the sum. This is the
  #    exact hole that let an Assert row be relabelled as a Mul.
  mk "$tmp/unbound" 'pub const COL_IS_HALT: usize = 19;
pub const COL_IS_ADD: usize = 11;
pub const COL_IS_MUL: usize = 13;
        let selector_opcode_binding = is_halt.clone() * (opcode_here.clone() - op(0x00))
            + is_add.clone() * (opcode_here.clone() - op(0x01));' "$good_isa"
  if ( scan "$tmp/unbound" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a selector missing from the binding sum was accepted!" >&2
    exit 1
  fi

  # 3. A selector bound to the wrong opcode. Worse than unbound, because it
  #    reads as covered.
  mk "$tmp/wrong" 'pub const COL_IS_HALT: usize = 19;
pub const COL_IS_ADD: usize = 11;
pub const COL_IS_MUL: usize = 13;
        let selector_opcode_binding = is_halt.clone() * (opcode_here.clone() - op(0x00))
            + is_add.clone() * (opcode_here.clone() - op(0x01))
            + is_mul.clone() * (opcode_here.clone() - op(0x02));' "$good_isa"
  if ( scan "$tmp/wrong" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a selector bound to the wrong opcode was accepted!" >&2
    exit 1
  fi

  # 4. A new ISA opcode with no selector at all.
  mk "$tmp/noselector" "$good_air" 'pub enum Opcode {
    Halt = 0x00,
    Add = 0x01,
    Mul = 0x03,
    Sub = 0x02,
}'
  if ( scan "$tmp/noselector" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an opcode with no selector was accepted!" >&2
    exit 1
  fi

  # 5. The binding sum deleted outright must fail, not pass for having nothing
  #    to disagree with.
  mk "$tmp/nosum" 'pub const COL_IS_HALT: usize = 19;
pub const COL_IS_ADD: usize = 11;
pub const COL_IS_MUL: usize = 13;' "$good_isa"
  if ( scan "$tmp/nosum" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an AIR with no binding sum at all was accepted!" >&2
    exit 1
  fi

  # 6. No selectors at all must fail rather than pass by having no offenders.
  mk "$tmp/nosel" 'pub const TRACE_WIDTH: usize = 733;' "$good_isa"
  if ( scan "$tmp/nosel" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an AIR with no selectors at all was accepted!" >&2
    exit 1
  fi

  # 7. No opcodes at all must fail too.
  mk "$tmp/noop" "$good_air" 'pub struct Nothing;'
  if ( scan "$tmp/noop" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an ISA with no opcodes at all was accepted!" >&2
    exit 1
  fi

  # 8. Missing files must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no AIR was accepted!" >&2
    exit 1
  fi

  echo "AIR selector binding gate self-test OK: an unbound selector, a selector bound to the wrong opcode, an opcode with no selector, a deleted binding sum, an AIR with no selectors, an ISA with no opcodes and a missing tree are all rejected; a fully bound AIR passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
