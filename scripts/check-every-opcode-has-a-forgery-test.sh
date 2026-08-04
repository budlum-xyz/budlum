#!/usr/bin/env bash
# ============================================================================
# check-every-opcode-has-a-forgery-test.sh
#
# Every opcode the AIR constrains must have a test that forges it and watches
# the proof stop closing.
#
# Why this gate exists.
#
# A constraint with no forgery test is a constraint nobody has watched fail.
# It compiles, it is covered by a green suite, and the only thing anyone knows
# about it is that honest execution passes. Honest execution passing is not
# evidence: a constraint deleted entirely also lets honest execution pass.
#
# Coverage was measured per opcode, by walking every `rejects_*` test body for
# the `Opcode::` variants it actually builds. Measured before this gate: 30
# opcodes, 20 covered, 10 with no forgery test at all. Those ten were `Inv`,
# `Not`, `Eq`, `Neq`, `Gt`, `Lte`, `Gte`, `Jmp`, `Jnz` and `Syscall`, each with
# constraints in the AIR and nothing attacking them.
#
# Why the measurement walks bodies and not names.
#
# Names lie. `rejects_tampered_comparison_result` sounds like it covers the
# comparison family; it builds `Opcode::Lt` and nothing else. Counting by name
# reported six comparison opcodes as covered when one was. This gate reads
# what each test constructs, which is the only reading that cannot be gamed by
# renaming a function.
#
# The three shapes this refuses:
#
#   1. An opcode gains an AIR constraint and no forgery test. That is the
#      original finding and the reason for the gate.
#   2. A forgery test stops asserting failure. A test that builds the opcode
#      and expects success is coverage on paper and nothing underneath, which
#      is why the helper it delegates to is checked as well.
#   3. The helper itself stops asserting failure. Every test that goes through
#      `prove_fails_after_tamper` inherits its assertion, so hollowing out the
#      helper hollows out all of them at once while every name survives.
#
# What this gate does not check: that each forgery is the *strongest* one
# available for that opcode, or that the tamper reaches the specific constraint
# the opcode's soundness rests on. It checks that something forges the opcode
# and the proof refuses it.
#
# Usage:
#   bash scripts/check-every-opcode-has-a-forgery-test.sh
#   bash scripts/check-every-opcode-has-a-forgery-test.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
isa = os.path.join(root, "budzero", "bud-isa", "src", "lib.rs")
prover = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_prover.rs")

for path in (isa, prover):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
        sys.exit(2)


def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def body_after(text, start):
    """Brace-matched body beginning at the first `{` at or after `start`."""
    i = text.index("{", start)
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
        j += 1
    return None


isa_src = strip_comments(open(isa, encoding="utf-8").read())
prover_src = open(prover, encoding="utf-8").read()

problems = []
checked = 0

# The opcode set comes from the ISA, not a hand-kept list here. A new opcode
# is then covered by this gate the moment it is defined, which is the point:
# a list maintained in the gate would need updating by the same commit that
# adds the opcode, and that is exactly the commit that would forget.
checked += 1
m = re.search(r"pub enum Opcode\s*\{(.*?)\n\}", isa_src, re.S)
if not m:
    print("FAIL: cannot find `Opcode` in the ISA to enumerate", file=sys.stderr)
    sys.exit(2)
opcodes = re.findall(r"^\s*([A-Z]\w*)\s*=", m.group(1), re.M)
if len(opcodes) < 10:
    print(
        f"FAIL: only {len(opcodes)} opcodes parsed from the ISA, which is too "
        "few to be the real set; the enum shape changed and this gate is "
        "reading it wrong",
        file=sys.stderr,
    )
    sys.exit(2)

# Every `rejects_*` test, with its body.
tests = {}
for m in re.finditer(r"fn (rejects_\w+)\s*\(\s*\)\s*\{", prover_src):
    body = body_after(prover_src, m.end() - 1)
    if body is not None:
        tests[m.group(1)] = body

checked += 1
if not tests:
    problems.append(
        "no `rejects_*` tests found at all. Every AIR constraint is then "
        "unwatched: honest execution passing is not evidence, because a "
        "deleted constraint also lets honest execution pass."
    )

# 1. Coverage, measured by what each test builds rather than what it is named.
checked += 1
uncovered = []
for op in opcodes:
    needle_a = f"Opcode::{op},"
    needle_b = f"Opcode::{op})"
    if not any(needle_a in b or needle_b in b for b in tests.values()):
        uncovered.append(op)
if uncovered:
    problems.append(
        f"{len(uncovered)} opcode(s) have no forgery test: "
        f"{', '.join(uncovered)}. A constraint nobody has watched fail is a "
        "constraint nobody has tested."
    )

# 2. Each forgery test must assert a failure, directly or through the helper.
checked += 1
helper = "prove_fails_after_tamper"
for name, body in sorted(tests.items()):
    delegates = helper in body
    # A refusal can be spelled several ways and all of them are real:
    # `is_err()`, an `expect_err`, or a `matches!(.., Err(Variant))` that
    # names which error. The last one is the strongest of the three, because
    # it pins *why* the proof was refused rather than only that it was.
    asserts_failure = (
        "is_err()" in body
        or "expect_err" in body
        or "unwrap_err" in body
        or re.search(r"Err\(VerifyError::", body) is not None
    )
    # A test can also assert a refusal that happens *before* proving: the VM
    # itself rejects the input, so the proof it produces is over an honest
    # trace and correctly verifies. `rejects_verify_merkle_with_incorrect_root`
    # is that shape, and it is not weaker, it locks a different door. The
    # marker is an assertion about the VM's own answer.
    rejects_at_the_vm = (
        "assert_eq!(vm.registers" in body or "assert!(!receipt.success" in body
    )
    if not delegates and not asserts_failure and not rejects_at_the_vm:
        problems.append(
            f"`{name}` builds a forgery and never asserts the proof is "
            "refused. A test that tampers and then expects success is "
            "coverage on paper."
        )

# 3. The helper every test leans on must still assert failure. Hollowing it
#    out hollows out all of them while every test name survives.
checked += 1
h = re.search(r"fn " + helper + r"\s*\(", prover_src)
if h is None:
    if any(helper in b for b in tests.values()):
        problems.append(
            f"tests delegate to `{helper}` and it does not exist."
        )
else:
    checked += 1
    hbody = body_after(prover_src, h.end() - 1)
    if hbody is None or "is_err()" not in hbody:
        problems.append(
            f"`{helper}` no longer asserts that verification fails. Every "
            "test delegating to it inherits that, so the whole forgery suite "
            "would pass against a proof system that accepts tampered traces."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"opcode forgery gate OK: {checked} checks, {len(opcodes)} opcodes, "
    f"{len(tests)} forgery tests, every opcode attacked"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  expect_finding() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "GATE IS VACUOUS: $what passed!" >&2
      return 1
    fi
    if [ "$rc" -ne 1 ]; then
      echo "GATE IS BROKEN: $what exited $rc, which is not a finding." >&2
      return 1
    fi
  }

  # Fixtures are written by python: bodies contain `#[test]`, and bash treats
  # `[` as a glob inside `${var//pattern/...}`, so a substitution would
  # silently do nothing and leave the canary asserting against an unmodified
  # tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root, cover_mode, assert_mode, helper_mode = sys.argv[1:5]
for sub in ("budzero/bud-isa/src", "budzero/bud-proof/src"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

# Ten opcodes is enough to be a real set and small enough to read.
ops = ["Halt", "Add", "Sub", "Mul", "Div", "Inv", "Not", "Eq", "Jmp", "Syscall"]
enum = "pub enum Opcode {\n" + "".join(
    f"    {o} = 0x{i:02X},\n" for i, o in enumerate(ops)
) + "}\n"
open(os.path.join(root, "budzero/bud-isa/src/lib.rs"), "w").write(enum)

if helper_mode == "hollow":
    helper = """    fn prove_fails_after_tamper(program: Vec<u64>, setup: impl FnOnce(&mut Vm), tamper: impl FnOnce(&mut Vec<Step>)) {
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(res.is_ok());
    }
"""
elif helper_mode == "gone":
    helper = ""
else:
    helper = """    fn prove_fails_after_tamper(program: Vec<u64>, setup: impl FnOnce(&mut Vm), tamper: impl FnOnce(&mut Vec<Step>)) {
        let res = Plonky3Adapter::verify(&envelope, &pi, &program);
        assert!(res.is_err(), "Expected verification to FAIL");
    }
"""

covered = ops if cover_mode == "all" else ops[:-3]
body = ""
for i, o in enumerate(covered):
    # The last test is the one whose assertion mode varies.
    last = i == len(covered) - 1
    if assert_mode == "weak" and last:
        body += (
            "    #[test]\n"
            f"    fn rejects_a_forged_{o.lower()}() {{\n"
            f"        let program = vec![inst(Opcode::{o}, 1, 2, 3, 0)];\n"
            "        let res = Plonky3Adapter::verify(&envelope, &pi, &program);\n"
            "        assert!(res.is_ok());\n"
            "    }\n"
        )
    else:
        body += (
            "    #[test]\n"
            f"    fn rejects_a_forged_{o.lower()}() {{\n"
            f"        let program = vec![inst(Opcode::{o}, 1, 2, 3, 0), inst(Opcode::Halt, 0, 0, 0, 0)];\n"
            "        prove_fails_after_tamper(program, |_| {}, |trace| {\n"
            "            trace[0].dst_val = 0;\n"
            "        });\n"
            "    }\n"
        )

open(os.path.join(root, "budzero/bud-proof/src/plonky3_prover.rs"), "w").write(
    "#[cfg(test)]\nmod tests {\n" + helper + body + "}\n"
)
PYB
  }

  # 1. The corrected shape must pass, or every canary below proves nothing.
  build "$tmp/good" all strong strong
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    return 1
  fi

  # 2. The original finding: opcodes with constraints and no forgery test.
  build "$tmp/uncovered" partial strong strong
  expect_finding "$tmp/uncovered" "opcodes with no forgery test" || return 1

  # 3. A test that builds the opcode and expects the proof to succeed. Name
  #    based counting calls this covered.
  build "$tmp/weak" all weak strong
  expect_finding "$tmp/weak" "a forgery test that expects success" || return 1

  # 4. The subtle one: the shared helper stops asserting failure. Every test
  #    name survives, every opcode still looks covered, and the whole suite
  #    passes against a proof system that accepts tampered traces.
  build "$tmp/hollow" all strong hollow
  expect_finding "$tmp/hollow" "a helper that no longer asserts failure" || return 1

  # 5. Tests delegate to a helper that does not exist.
  build "$tmp/nohelper" all strong gone
  expect_finding "$tmp/nohelper" "tests delegating to a missing helper" || return 1

  echo "opcode forgery gate self-test OK: 4 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
