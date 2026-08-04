#!/usr/bin/env bash
# ============================================================================
# check-forgery-tests-are-named.sh
#
# The proof-forgery tests are the only evidence the AIR constrains anything.
#
# Why this gate exists.
#
# `cargo test --workspace` going green says every test that ran passed. It says
# nothing about which tests exist. A forgery test deleted in a refactor, or
# renamed while someone reshuffled a module, takes its coverage with it and
# leaves the suite just as green as before. The tests listed here are the ones
# that tamper with a trace and require the verifier to refuse it; each is the
# only thing standing between a closed soundness finding and its return.
#
# The list is deliberately explicit rather than a pattern like `rejects_*`. A
# pattern counts whatever happens to match it, so replacing a hard test with an
# easy one keeps the count and loses the coverage.
#
# A test may assert the refusal through a helper. Three of the entries here
# call `prove_fails_after_tamper`, which builds the trace, applies the
# tampering and requires `verify` to return an error; the test body itself
# contains no `is_err`. Reading only the immediate body reported all three as
# toothless, which was a false alarm on genuinely strict tests, and a gate that
# cries wolf gets muted. The check therefore follows calls into local helpers,
# to a bounded depth, and treats a refusal asserted anywhere along that chain
# as the test's own.
#
# `rejects_a_jump_past_the_end_of_the_program` is the reason this gate was
# written. Nothing in the AIR bounds `COL_PC`: the jump constraint is
# `next_pc = pc + imm` and no constraint says the result addresses a real
# instruction. What refuses an out-of-range jump is the Program CTL, in a
# different constraint, which never mentions jumps. SP1 Hypercube shipped the
# neighbouring bug (JALR without the specified `& ~1`) and Polygon zkEVM
# shipped the severe one (arbitrary ROM jump, mintable balance). Our defence
# holds, and it holds indirectly, which is exactly the kind that gets optimised
# away by someone who cannot see what it was load-bearing for.
#
# Usage:
#   bash scripts/check-forgery-tests-are-named.sh              # gate
#   bash scripts/check-forgery-tests-are-named.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# Each entry is a test that tampers with an honest trace and requires the
# verifier to refuse the result.
required_tests=(
  rejects_a_forged_difference
  rejects_a_forged_product
  rejects_a_forged_quotient_when_dividing_by_zero
  rejects_a_comparison_read_from_a_wrapped_bit_string
  rejects_a_load_that_denies_touching_memory
  rejects_a_pop_that_invents_a_value
  rejects_a_return_to_an_address_never_pushed
  rejects_a_jump_past_the_end_of_the_program
  rejects_a_row_relabelled_as_a_different_opcode
  rejects_a_swapped_source_register
  rejects_a_write_to_the_zero_register
  rejects_a_register_that_changes_value_without_a_write
  rejects_an_assert_that_claims_zero_is_non_zero
  rejects_an_invented_starting_register
  rejects_an_opcode_column_that_disagrees_with_the_program
  rejects_a_redirected_storage_slot
  rejects_a_shifted_event_digest
  rejects_tampered_bitwise_and_result
  rejects_tampered_comparison_result
  rejects_tampered_event_digest
  rejects_tampered_poseidon_sbox
  rejects_tampered_storage_write_result
  rejects_a_proof_claiming_an_impossible_degree
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" "${required_tests[@]}" <<'PY'
import os
import re
import sys

root = sys.argv[1]
required = sys.argv[2:]

sources = []
for base in (os.path.join(root, "budzero"),):
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target")]
        for name in filenames:
            if name.endswith(".rs"):
                sources.append(os.path.join(dirpath, name))

if not sources:
    print(f"FAIL: no .rs sources under {root}/budzero", file=sys.stderr)
    sys.exit(2)

blob = ""
for path in sources:
    try:
        blob += open(path, encoding="utf-8", errors="ignore").read() + "\n"
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

missing = []
not_a_test = []
for name in required:
    # The attribute has to be there. A `#[test]` quietly moved onto the wrong
    # function is how an economy invariant went untested once already.
    if re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + re.escape(name) + r"\s*\(", blob):
        continue
    if re.search(r"\bfn\s+" + re.escape(name) + r"\s*\(", blob):
        not_a_test.append(name)
    else:
        missing.append(name)

# A forgery test that no longer requires a refusal proves nothing. The
# assertion may live in a helper the test calls rather than in its own body, so
# follow those calls rather than reporting a strict test as toothless.
REFUSAL = re.compile(r"is_err\(\)|unwrap_err\(\)|expect_err\(|should_panic")


def body_of(fn_name):
    """Brace-matched body of `fn fn_name`, or None."""
    m = re.search(r"\bfn\s+" + re.escape(fn_name) + r"\s*(?:<[^>]*>)?\s*\(", blob)
    if not m:
        return None
    try:
        i = blob.index("{", m.end() - 1)
    except ValueError:
        return None
    depth, j, start = 0, i, None
    while j < len(blob):
        if blob[j] == "{":
            depth += 1
            if start is None:
                start = j
        elif blob[j] == "}":
            depth -= 1
            if depth == 0:
                return blob[start : j + 1]
        j += 1
    return None


def asserts_refusal(fn_name, depth=0, seen=None):
    """True when this function, or a helper it calls, requires an error.

    Depth is bounded at two hops: one for the usual test-to-helper call and one
    for a helper built on another. Deeper than that the chain is no longer
    something a reader would follow either, and an unbounded walk would happily
    reach an unrelated function that happens to assert an error.
    """
    seen = seen or set()
    if fn_name in seen or depth > 2:
        return False
    seen.add(fn_name)
    body = body_of(fn_name)
    if body is None:
        return False
    if REFUSAL.search(body):
        return True
    for callee in set(re.findall(r"\b([a-z_][a-z0-9_]{4,})\s*\(", body)):
        if callee in seen:
            continue
        if body_of(callee) is not None and asserts_refusal(callee, depth + 1, seen):
            return True
    return False


toothless = [
    name
    for name in required
    if body_of(name) is not None and not asserts_refusal(name)
]

problems = []
if missing:
    problems.append(
        "these forgery tests do not exist: "
        + ", ".join(sorted(missing))
        + ". Each was the only evidence that a specific tampering is refused; "
        "`cargo test` stays green without them."
    )
if not_a_test:
    problems.append(
        "these exist as functions but carry no `#[test]`: "
        + ", ".join(sorted(not_a_test))
        + ". A function nothing runs is not coverage."
    )
if toothless:
    problems.append(
        "these no longer assert a refusal: "
        + ", ".join(sorted(toothless))
        + ". A forgery test that does not require an error passes whether the "
        "constraint holds or not. If the assertion lives in a helper, the "
        "helper has to be reachable from the test by a direct call."
    )

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"forgery test gate OK: {len(required)} named tamper tests present and asserting")
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

  # Fixtures are written by python: `#[test]` contains `[`, which bash expands
  # as a glob inside `${var//pattern/...}`, so a substitution there silently
  # does nothing and the canary asserts against an unmodified fixture.
  build() {
    python3 - "$1" "$2" "${required_tests[@]}" <<'PYB'
import os
import sys

root, mode = sys.argv[1], sys.argv[2]
names = sys.argv[3:]
os.makedirs(os.path.join(root, "budzero", "src"), exist_ok=True)

out = []
for i, n in enumerate(names):
    if mode == "missing" and i == 0:
        continue
    if mode == "not_a_test" and i == 0:
        out.append("fn %s() { assert!(v().is_err()); }" % n)
        continue
    if mode == "toothless" and i == 0:
        out.append("#[test]\nfn %s() { assert!(v().is_ok()); }" % n)
        continue
    if mode == "via_helper" and i == 0:
        # The real shape: the test tampers and delegates, and the refusal is
        # asserted one call away. Reading only this body finds no `is_err`.
        out.append("#[test]\nfn %s() { prove_fails_after_tamper(p, t); }" % n)
        continue
    if mode == "helper_toothless" and i == 0:
        out.append("#[test]\nfn %s() { prove_succeeds_after_tamper(p, t); }" % n)
        continue
    out.append("#[test]\nfn %s() { assert!(v().is_err()); }" % n)

if mode == "via_helper":
    out.append(
        "fn prove_fails_after_tamper(p: u8, t: u8) {\n"
        "    let res = verify(p, t);\n"
        "    assert!(res.is_err(), \"tampering must be refused\");\n}"
    )
if mode == "helper_toothless":
    out.append(
        "fn prove_succeeds_after_tamper(p: u8, t: u8) {\n"
        "    let res = verify(p, t);\n"
        "    assert!(res.is_ok());\n}"
    )
open(os.path.join(root, "budzero", "src", "lib.rs"), "w").write("\n".join(out) + "\n")
PYB
  }

  # 1. Every test present, each asserting a refusal: must pass.
  build "$tmp/good" good
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a complete set of forgery tests was rejected!" >&2
    return 1
  fi

  # 2. One test deleted, which is what a refactor does silently.
  build "$tmp/missing" missing
  expect_finding "$tmp/missing" "a deleted forgery test" || return 1

  # 3. `#[test]` dropped: the function survives, the coverage does not.
  build "$tmp/nottest" not_a_test
  expect_finding "$tmp/nottest" "a forgery test with no #[test]" || return 1

  # 4. The assertion inverted to `is_ok`, so the test passes either way.
  build "$tmp/toothless" toothless
  expect_finding "$tmp/toothless" "a forgery test asserting success" || return 1

  # 5. The assertion lives one call away, in a helper. This is the real shape
  #    of three entries on the list, and reading only the test body reported
  #    all three as toothless: a false alarm on genuinely strict tests. A gate
  #    that cries wolf gets muted, and a muted gate protects nothing.
  build "$tmp/helper" via_helper
  if ! ( scan "$tmp/helper" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a test whose refusal is asserted in a helper it calls" >&2
    echo "was reported as toothless." >&2
    return 1
  fi

  # 6. Following the call must not become a way to pass without asserting
  #    anything. A helper that requires success is still toothless, however
  #    many hops away it sits.
  build "$tmp/helper_bad" helper_toothless
  expect_finding "$tmp/helper_bad" "a helper that asserts success, not refusal" \
    || return 1

  echo "forgery test gate self-test OK: 6 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
